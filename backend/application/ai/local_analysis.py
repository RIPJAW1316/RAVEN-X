"""Bounded facts for optional local LLM interpretation of stored evidence."""

from datetime import datetime, timezone
import json

from ...domain.security import (AuthorizationAction, AuthorizationRequest,
                                AuthorizationResource, PrincipalType)
from ..organization.context import OrganizationContext
from .offline_rules import build_offline_fix_plan, reorder_plan_with_model_refs


class TenantLocalAnalysisService:
    def __init__(self, report_service, authorizer, provider, *, clock=None,
                 max_prompt_chars=12000, max_finding_facts=30):
        if not 2000 <= max_prompt_chars <= 12000 or max_finding_facts <= 0:
            raise ValueError("invalid local analysis bounds")
        self.reports = report_service
        self.authorizer = authorizer
        self.provider = provider
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.max_prompt_chars = max_prompt_chars
        self.max_finding_facts = max_finding_facts

    def analyze(self, principal, context, *, endpoint_id=None, assessment_ids=None, offline_plan: bool = False):
        if principal.principal_type is not PrincipalType.HUMAN or not isinstance(context, OrganizationContext):
            raise PermissionError("human organization context required")
        decision = self.authorizer.authorize(AuthorizationRequest(
            principal, AuthorizationAction.AI_USE,
            AuthorizationResource("local_ai_analysis", metadata={"organization_id": str(context.organization_id)}),
            organization_context=context))
        if not decision.allowed:
            raise PermissionError(decision.reason_code)
        # The report service separately enforces reports.read before fetching
        # any endpoint or assessment evidence.
        report = self.reports.build(principal, context, endpoint_id=endpoint_id,
                                    assessment_ids=assessment_ids)
        source = {
            "organization_id": report["organization_id"],
            "assessment_ids": [row["latest_assessment"]["assessment_id"] for row in report["endpoints"]
                               if row["latest_assessment"] is not None],
            "endpoint_ids": [row["endpoint_id"] for row in report["endpoints"]],
            "report_generated_at": report["generated_at"],
        }
        if report["summary"]["scanned"] + report["summary"]["partial"] == 0:
            return {"status": "unavailable", "reason_code": "NO_COMPLETED_EVIDENCE",
                    "advisory": True, "analysis": None, "source": source}

        if offline_plan:
            return self._fix_plan(report, source)

        if not self.provider.enabled:
            return {"status": "unavailable", "reason_code": "LOCAL_AI_DISABLED",
                    "advisory": True, "analysis": None, "source": source}
        facts, coverage = self._facts(report)
        if coverage["included_endpoints"] == 0:
            return {"status": "unavailable", "reason_code": "NO_COMPLETED_EVIDENCE",
                    "advisory": True, "analysis": None, "source": source,
                    "coverage": coverage}
        try:
            output = self.provider.analyze(facts)
        except Exception:
            return {"status": "unavailable", "reason_code": "LOCAL_AI_UNAVAILABLE",
                    "advisory": True, "analysis": None, "source": source,
                    "coverage": coverage}
        return {"status": "available", "reason_code": None, "advisory": True,
                "analysis": output, "model": self.provider.model,
                "generated_at": self.clock().astimezone(timezone.utc).isoformat(),
                "source": source, "coverage": coverage,
                "notice": "AI interpretation is advisory; stored assessment evidence is the source of truth."}

    def _fix_plan(self, report, source):
        plan = build_offline_fix_plan(report)
        findings = plan["plan"]
        scanned_count = report["summary"]["scanned"] + report["summary"]["partial"]
        ranked = self._prioritized_refs(findings) if self.provider.enabled and findings else None
        if ranked:
            plan = reorder_plan_with_model_refs(plan, ranked, scanned_count)
        return {
            "status": "available",
            "reason_code": None,
            "advisory": True,
            "analysis": plan["analysis"],
            "model": self.provider.model if ranked else "Offline rules",
            "provider": "lm_studio" if ranked else "offline",
            "fallback_used": not ranked and (not self.provider.enabled or bool(findings)),
            "generated_at": self.clock().astimezone(timezone.utc).isoformat(),
            "source": source,
            "coverage": {
                "scanned_endpoints": scanned_count,
                "included_endpoints": scanned_count,
                "included_findings": len(findings),
                "truncated": plan["findings_omitted"] > 0,
            },
            "plan": plan["plan"],
            "blind_spots": plan["blind_spots"],
            "out_of_scope_checks": plan["out_of_scope_checks"],
            "notice": "Review recommendations against the source assessment evidence before taking action.",
        }

    def _prioritized_refs(self, findings):
        # Keep prompt references short so the model can return the full order within its token budget.
        bound = {}
        items = []
        for index, finding in enumerate(findings[:self.max_finding_facts], start=1):
            ref = f"f{index}"
            item = {"ref": ref, **{key: finding[key] for key in ("severity", "title", "details", "hostname")}}
            candidate = json.dumps({"findings": [*items, item]}, ensure_ascii=True, separators=(",", ":"))
            if len(candidate) > self.max_prompt_chars:
                break
            items.append(item)
            bound[ref] = finding["finding_key"]
        if not items:
            return None

        prompt = json.dumps({"findings": items}, ensure_ascii=True, separators=(",", ":"))
        try:
            content = self.provider.prioritize_findings(prompt).strip()
            lines = content.splitlines()
            if len(lines) >= 3 and lines[0].lower() in {"```", "```json"} and lines[-1] == "```":
                content = "\n".join(lines[1:-1])
            refs = json.loads(content)
        except Exception:
            return None

        if (not isinstance(refs, list) or not refs
                or not all(isinstance(ref, str) and ref in bound for ref in refs)
                or len(refs) != len(set(refs))):
            return None
        return [bound[ref] for ref in refs]

    def _facts(self, report):
        facts = {"summary": report["summary"], "scanned_endpoints": []}
        scanned_count = 0
        for row in report["endpoints"]:
            if row["scan_status"] not in {"scanned", "partial"}:
                continue
            scanned_count += 1
            item = {"endpoint_id": row["endpoint_id"], "hostname": row["hostname"],
                    "assessment_id": row["latest_assessment"]["assessment_id"],
                    "completed_at": row["latest_assessment"]["completed_at"],
                    "scan_status": row["scan_status"], "scanner_results": row["scanner_results"],
                    "finding_count": row["findings_count"], "findings": []}
            for finding in row["findings"]:
                if sum(len(existing["findings"]) for existing in facts["scanned_endpoints"]) + len(item["findings"]) >= self.max_finding_facts:
                    break
                item["findings"].append({key: finding[key] for key in
                                         ("finding_id", "severity", "title", "description", "scanner_id", "evidence")})
            while item["findings"]:
                candidate = facts["scanned_endpoints"] + [item]
                encoded = json.dumps({**facts, "scanned_endpoints": candidate}, ensure_ascii=True,
                                     separators=(",", ":"))
                if len(encoded) <= self.max_prompt_chars:
                    break
                item["findings"].pop()
            candidate = facts["scanned_endpoints"] + [item]
            encoded = json.dumps({**facts, "scanned_endpoints": candidate}, ensure_ascii=True,
                                 separators=(",", ":"))
            if len(encoded) > self.max_prompt_chars:
                break
            facts["scanned_endpoints"] = candidate
        encoded = json.dumps(facts, ensure_ascii=True, separators=(",", ":"))
        coverage = {"scanned_endpoints": scanned_count,
                    "included_endpoints": len(facts["scanned_endpoints"]),
                    "included_findings": sum(len(item["findings"]) for item in facts["scanned_endpoints"]),
                    "truncated": len(facts["scanned_endpoints"]) < scanned_count or
                    sum(row["findings_count"] for row in report["endpoints"]
                        if row["scan_status"] in {"scanned", "partial"}) >
                    sum(len(item["findings"]) for item in facts["scanned_endpoints"])}
        return encoded, coverage
