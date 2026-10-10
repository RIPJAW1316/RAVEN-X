from collections import Counter
from datetime import datetime, timezone
from collections.abc import Mapping
from ...domain.compliance import *
from ...domain.endpoint import EndpointId, EndpointStatus
from ...domain.security import AuthorizationAction, AuthorizationRequest, AuthorizationResource, PrincipalType


class ComplianceControlEvaluator:
    def __init__(self, *, max_age_hours=24, clock=None):
        if max_age_hours <= 0: raise ValueError("evidence age must be positive")
        self.max_age = max_age_hours * 3600; self.clock = clock or (lambda: datetime.now(timezone.utc))

    def evaluate(self, control, endpoint, assessments):
        now = self.clock(); endpoint_id = str(endpoint.endpoint_id)
        if control.applicability_platform and str(endpoint.platform.name).casefold() != control.applicability_platform.casefold():
            return ControlEvaluation(control.control_id, ComplianceStatus.NOT_APPLICABLE, ComplianceReason.ENDPOINT_NOT_APPLICABLE, now, endpoint_id, capability=control.capability)
        if control.capability is ComplianceEvaluationCapability.UNSUPPORTED:
            return ControlEvaluation(control.control_id, ComplianceStatus.UNKNOWN, ComplianceReason.CONTROL_UNSUPPORTED, now, endpoint_id, capability=control.capability)
        ordered = sorted(tuple(assessments or ()), key=lambda x: _time(getattr(x, "completed_at", None) or getattr(x, "created_at", None)), reverse=True)
        source = next((a for a in ordered if _status(a) in {"completed", "failed", "cancelled"}), None)
        if source is None:
            return ControlEvaluation(control.control_id, ComplianceStatus.UNKNOWN, ComplianceReason.SCANNER_NOT_RUN, now, endpoint_id, capability=control.capability)
        source_id = str(getattr(source, "assessment_id", "")); observed_ids=[]
        relevant = []
        for requirement in control.evidence_requirements:
            execution = [x for x in _scanner_results(source) if str(x.get("scanner_id")) == requirement.scanner_id]
            findings = [x for x in _findings(source) if _matches(x, requirement)]
            if findings:
                observed_ids.extend(str(x.get("occurrence_id") or x.get("finding_id") or "") for x in findings)
                relevant.append(("violation", requirement, findings, execution))
            elif not execution:
                relevant.append(("missing", requirement, (), ()))
            elif str(execution[-1].get("status", "")).lower() == "failed":
                relevant.append(("failed", requirement, (), execution))
            else:
                relevant.append(("absence", requirement, (), execution))
        stamp = _time(getattr(source, "completed_at", None) or getattr(source, "created_at", None)); age=max(0,(now-stamp).total_seconds())
        if age > self.max_age: return ControlEvaluation(control.control_id, ComplianceStatus.UNKNOWN, ComplianceReason.STALE_EVIDENCE, now, endpoint_id, source_id, tuple(observed_ids), "evidence is older than the configured freshness window", "stale", age, control.capability)
        if any(x[0] == "violation" for x in relevant): return ControlEvaluation(control.control_id, ComplianceStatus.NON_COMPLIANT, ComplianceReason.FINDING_OBSERVED, now, endpoint_id, source_id, tuple(observed_ids), "a matching finding was observed", "observed", age, control.capability)
        if any(x[0] in {"missing", "failed"} for x in relevant):
            reason = ComplianceReason.SCANNER_FAILED if any(x[0] == "failed" for x in relevant) else ComplianceReason.SCANNER_NOT_RUN
            return ControlEvaluation(control.control_id, ComplianceStatus.UNKNOWN, reason, now, endpoint_id, source_id, coverage_status="incomplete", evidence_age_seconds=age, capability=control.capability)
        strong = control.capability is ComplianceEvaluationCapability.FULL and all(_strong_execution(x[3], x[1]) for x in relevant)
        return ControlEvaluation(control.control_id, ComplianceStatus.COMPLIANT if strong else ComplianceStatus.UNKNOWN, ComplianceReason.EVIDENCE_SATISFIED if strong else ComplianceReason.COVERAGE_UNKNOWN, now, endpoint_id, source_id, coverage_status="covered" if strong else "unknown", evidence_age_seconds=age, capability=control.capability)


class TenantComplianceService:
    def __init__(self, endpoint_repository, assessment_repository, authorizer, registry=None, *, max_endpoints=100, evaluator=None, metrics=None, logger=None):
        self.endpoints=endpoint_repository; self.assessments=assessment_repository; self.authorizer=authorizer; self.registry=registry or ravenx_windows_baseline_registry(); self.max_endpoints=max_endpoints; self.evaluator=evaluator or ComplianceControlEvaluator(); self.metrics=metrics; self.logger=logger
    def frameworks(self, principal, context): self._authorize(principal,context,AuthorizationAction.COMPLIANCE_READ,"compliance") ; return self.registry.frameworks()
    def framework(self, principal, context, framework_id):
        self._authorize(principal,context,AuthorizationAction.COMPLIANCE_READ,"compliance"); value=self.registry.framework(framework_id)
        if value is None: raise KeyError("framework not found")
        return value
    def framework_detail(self, principal, context, framework_id):
        framework = self.framework(principal, context, framework_id)
        return {**framework.to_dict(), "controls": [item.to_dict() for item in self.registry.controls_for(framework.framework_id)]}
    def evaluate_endpoint(self, principal, context, endpoint_id, framework_id):
        self._authorize(principal,context,AuthorizationAction.COMPLIANCE_READ,"compliance"); self._authorize(principal,context,AuthorizationAction.ENDPOINT_READ,"endpoint",endpoint_id)
        endpoint=self.endpoints.get_for_organization(endpoint_id if isinstance(endpoint_id,EndpointId) else EndpointId(endpoint_id),context.organization_id)
        if endpoint is None: raise KeyError("endpoint not found")
        framework=self.framework(principal,context,framework_id); assessments=self.assessments.list_for_endpoint_and_organization(endpoint.endpoint_id,context.organization_id)
        return tuple(self.evaluator.evaluate(control,endpoint,assessments) for control in self.registry.controls_for(framework.framework_id))
    def summary(self, principal, context, framework_id):
        self._authorize(principal,context,AuthorizationAction.COMPLIANCE_READ,"compliance"); self._authorize(principal,context,AuthorizationAction.ENDPOINT_READ,"fleet")
        framework=self.framework(principal,context,framework_id); endpoints=tuple(x for x in self.endpoints.list_for_organization(context.organization_id) if x.status is not EndpointStatus.REVOKED)
        if len(endpoints)>self.max_endpoints: raise ValueError("compliance endpoint bound exceeded")
        values=[evaluation for endpoint in endpoints for evaluation in self.evaluate_endpoint(principal,context,endpoint.endpoint_id,framework_id)]
        counts=Counter(x.status for x in values)
        if self.metrics is not None: self.metrics.increment("compliance.evaluations",len(values))
        return CompliancePostureSummary(framework.framework_id,framework.version,str(context.organization_id),self.evaluator.clock(),len(endpoints),len(endpoints),True,len(values),counts[ComplianceStatus.COMPLIANT],counts[ComplianceStatus.NON_COMPLIANT],counts[ComplianceStatus.UNKNOWN],counts[ComplianceStatus.NOT_APPLICABLE])
    def _authorize(self,p,c,action,resource_type,resource_id=None):
        if p.principal_type is not PrincipalType.HUMAN or c is None: raise PermissionError("human context required")
        decision=self.authorizer.authorize(AuthorizationRequest(p,action,AuthorizationResource(resource_type,str(resource_id) if resource_id else None,{"organization_id":str(c.organization_id)}),organization_context=c))
        if not decision.allowed: raise PermissionError(decision.reason_code)

def _status(x):
    value=getattr(x,"state",getattr(x,"status","unknown")); return getattr(value,"value",str(value))
def _time(value):
    if value is None:return datetime.min.replace(tzinfo=timezone.utc)
    if isinstance(value,str):
        try:value=datetime.fromisoformat(value)
        except ValueError:return datetime.min.replace(tzinfo=timezone.utc)
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
def _scanner_results(a):
    result=getattr(a,"result",None); raw=getattr(result,"scanner_results",None) if result is not None else None
    if raw is None and isinstance(result,Mapping):raw=result.get("scanner_results",())
    return tuple(x for x in (raw or ()) if isinstance(x,Mapping))
def _findings(a):
    result=getattr(a,"result",None); raw=getattr(result,"findings",None) if result is not None else None
    if raw is None and isinstance(result,Mapping):raw=result.get("findings",())
    values=list(raw or ())
    for execution in _scanner_results(a): values.extend(execution.get("findings") or ())
    return tuple(x if isinstance(x,Mapping) else {"metadata":getattr(x,"metadata",{}),"finding_id":getattr(x,"finding_id",None)} for x in values)
def _matches(finding, requirement):
    metadata=finding.get("metadata",finding) if isinstance(finding,Mapping) else {}
    return str(metadata.get("scanner_id",finding.get("scanner_id", "")))==requirement.scanner_id and str(metadata.get("rule_id",finding.get("rule_id", "")))==requirement.rule_id and (requirement.resource_key is None or str(metadata.get("resource_key"))==requirement.resource_key)
def _strong_execution(executions, requirement):
    if not executions:return False
    execution=executions[-1];
    if str(execution.get("status","")).lower()!="success":return False
    evidence=execution.get("execution_evidence"); completeness=getattr(evidence,"completeness",None); complete=getattr(completeness,"value",completeness)=="complete"
    native=execution.get("native_metrics") or {}; return complete and not native.get("normalization_issue_count") and not native.get("partial")
