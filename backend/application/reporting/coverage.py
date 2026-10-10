"""Derived scanner-coverage history; never a lifecycle engine."""
from collections.abc import Mapping
from datetime import datetime, timezone

from ...domain.reporting import (CoverageGranularity, CoverageObservation, CoverageStatus,
                                 CoverageAttestation, FindingCoverageHistory, FindingObservationStatus,
                                 LifecycleReadinessSummary,
                                 LifecycleEligibilityStatus, ScannerCoverageContract,
                                 derive_fingerprint, materialize_finding_identity)
from ...domain.security import PrincipalType


class ScannerCoverageRegistry:
    """Explicit scanner coverage guarantees. Undeclared scanners are UNKNOWN."""
    def __init__(self, contracts=()):
        self._contracts = {}
        for contract in contracts:
            self.register(contract)

    def register(self, contract):
        if not isinstance(contract, ScannerCoverageContract):
            raise TypeError("coverage registry accepts ScannerCoverageContract values")
        if contract.scanner_id in self._contracts:
            raise ValueError(f"coverage contract {contract.scanner_id!r} is already registered")
        self._contracts[contract.scanner_id] = contract

    def get(self, scanner_id): return self._contracts.get(scanner_id, ScannerCoverageContract(scanner_id))
    def list(self): return tuple(self._contracts.values())


def default_scanner_coverage_registry():
    # The legacy firewall adapter maps one deterministic read-only profile
    # check to this scanner. It is the only initial strong absence contract.
    return ScannerCoverageRegistry((
        ScannerCoverageContract(
            "windows.firewall", CoverageGranularity.RESOURCE,
            "the independent firewall adapter completes its deterministic profile check",
            contract_version=1, rule_ids=("firewall.profile",),
            resource_scope=("domain", "private", "public"), scanner_versions=("1.0",),
            allows_absence_inference=True),
        ScannerCoverageContract("windows.uac", CoverageGranularity.UNKNOWN,
                                "legacy registry output does not prove complete rule coverage"),
        ScannerCoverageContract("windows.bitlocker", CoverageGranularity.UNKNOWN,
                                "legacy C: volume output does not prove complete resource enumeration"),
        ScannerCoverageContract("windows.smb", CoverageGranularity.UNKNOWN,
                                "legacy SMB output does not prove complete protocol rule coverage"),
    ))


class TenantFindingCoverageService:
    def __init__(self, assessment_repository, detail_service, *, coverage_registry=None,
                 max_assessments=100, metrics=None, logger=None, clock=None):
        if max_assessments <= 0: raise ValueError("coverage history bound must be positive")
        self.assessments, self.details = assessment_repository, detail_service
        self.registry = coverage_registry or default_scanner_coverage_registry()
        self.max_assessments, self.metrics, self.logger = max_assessments, metrics, logger
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def history(self, principal, context, assessment_id, occurrence_id):
        if principal.principal_type is not PrincipalType.HUMAN or not hasattr(context, "organization_id"):
            raise PermissionError("human organization context required")
        source = self.details.get_finding(principal, context, assessment_id, occurrence_id)
        source_assessment = self.assessments.get_for_organization(assessment_id, context.organization_id)
        if source_assessment is None: raise KeyError("assessment not found")
        fingerprint = source.fingerprint if isinstance(source.fingerprint, Mapping) else None
        if not self._valid_fingerprint(fingerprint):
            return self._unresolved(source)
        scanner_id = str(fingerprint["components"]["scanner_id"])
        historical = list(self.assessments.list_for_endpoint_and_organization(source_assessment.endpoint_id, context.organization_id))
        chronological = sorted(historical, key=lambda item: (_time(getattr(item, "created_at", None)), str(item.assessment_id)))
        selected = chronological[-self.max_assessments:]
        if not any(item.assessment_id == source_assessment.assessment_id for item in selected): selected.insert(0, source_assessment)
        complete = len(chronological) <= self.max_assessments
        observations, malformed = [], 0
        for assessment in selected:
            observation, bad = self._evaluate(assessment, fingerprint, scanner_id)
            observations.append(observation); malformed += bad
        observations.sort(key=lambda item: (_time(item.observed_at), item.assessment_id))
        eligible = (LifecycleEligibilityStatus.ELIGIBLE if any(
            item.observation_status is FindingObservationStatus.NOT_OBSERVED and item.coverage_status is CoverageStatus.COVERED
            for item in observations) else LifecycleEligibilityStatus.INSUFFICIENT_DATA)
        strong = tuple(sorted({item.scanner_id for item in observations if item.attestation and item.attestation.absence_inference_allowed}))
        unknown = tuple(sorted({item.scanner_id for item in observations if item.observation_status is FindingObservationStatus.UNKNOWN}))
        readiness = LifecycleReadinessSummary(len(strong), len(unknown), strong, unknown, eligible is LifecycleEligibilityStatus.ELIGIBLE)
        result = FindingCoverageHistory(source.occurrence_id, source.endpoint_id, "candidate_matchable", tuple(observations), complete,
                                        len(selected), observations[-1].observation_status if observations else None,
                                        eligible, malformed, self.clock(), readiness)
        if self.metrics is not None:
            self.metrics.increment("finding_coverage.requests")
            for item in observations:
                if item.observation_status is FindingObservationStatus.UNKNOWN: self.metrics.increment("finding_coverage.unknown")
                if item.observation_status is FindingObservationStatus.NOT_EVALUATED: self.metrics.increment("finding_coverage.not_evaluated")
        if self.logger is not None: self.logger.info("finding_coverage_generated endpoint_id=%s assessments=%s", source.endpoint_id, len(selected))
        return result

    get_coverage_history = history
    get_coverage = history

    def _evaluate(self, assessment, fingerprint, scanner_id):
        contract = self.registry.get(scanner_id)
        raw = self._raw_findings(assessment)
        malformed = 0
        for index, item in enumerate(raw):
            if not isinstance(item, Mapping): malformed += 1; continue
            value = materialize_finding_identity(item, assessment_id=str(assessment.assessment_id), endpoint_id=str(assessment.endpoint_id), index=index)
            candidate = value.get("logical_fingerprint")
            if candidate is not None and not self._valid_fingerprint(candidate): malformed += 1; continue
            if self._matches(candidate, fingerprint):
                return self._observation(assessment, scanner_id, None, CoverageStatus.COVERED,
                                         FindingObservationStatus.OBSERVED, "MATCH_OBSERVED", contract=contract,
                                         fingerprint=fingerprint), malformed
        scanner_results = self._scanner_results(assessment)
        # Absence cannot be inferred while delivery/execution is incomplete.
        # A completed scanner result below may still establish a fact even if
        # the aggregate remote assessment later failed or was cancelled.
        state = _status(assessment)
        if not scanner_results and state in {
            "created", "queued", "dispatched", "running", "delivery_failed",
            "endpoint_unavailable", "expired", "cancel_requested", "cancelled",
        }:
            code = "DELIVERY_FAILED" if state == "delivery_failed" else "ASSESSMENT_INCOMPLETE"
            return self._observation(assessment, scanner_id, None, CoverageStatus.NOT_COVERED,
                                     FindingObservationStatus.NOT_EVALUATED, code, contract=contract,
                                     fingerprint=fingerprint), malformed
        if not scanner_results:
            return self._observation(assessment, scanner_id, None, CoverageStatus.INDETERMINATE,
                                     FindingObservationStatus.UNKNOWN, "LEGACY_DATA_INSUFFICIENT", contract=contract,
                                     fingerprint=fingerprint), malformed
        relevant = [item for item in scanner_results if str(item.get("scanner_id")) == scanner_id]
        if not relevant:
            selected = tuple(getattr(assessment, "scanner_ids", ()) or ())
            code = "SCANNER_NOT_SELECTED" if selected and scanner_id not in selected else "SCANNER_RESULT_MISSING"
            return self._observation(assessment, scanner_id, None,
                                     CoverageStatus.NOT_COVERED if code == "SCANNER_NOT_SELECTED" else CoverageStatus.INDETERMINATE,
                                     FindingObservationStatus.NOT_EVALUATED if code == "SCANNER_NOT_SELECTED" else FindingObservationStatus.UNKNOWN,
                                     code), malformed
        execution = relevant[-1]
        status = str(execution.get("status", "")).lower()
        scanner_version = execution.get("scanner_version")
        evidence = execution.get("execution_evidence")
        if isinstance(evidence, Mapping):
            try:
                from ...domain.scanner import ScannerExecutionEvidence
                evidence = ScannerExecutionEvidence.from_dict(evidence)
            except (TypeError, ValueError, KeyError):
                evidence = None
        if status == "success":
            native = execution.get("native_metrics") or {}
            if isinstance(native, Mapping) and (native.get("partial") or native.get("incomplete") or native.get("normalization_issue_count", 0)):
                return self._observation(assessment, scanner_id, status, CoverageStatus.INDETERMINATE,
                                         FindingObservationStatus.UNKNOWN, "PARTIAL_EXECUTION", contract=contract,
                                         scanner_version=scanner_version, fingerprint=fingerprint, execution_evidence=evidence), malformed
            if contract.covers(fingerprint, scanner_version, evidence):
                return self._observation(assessment, scanner_id, status, CoverageStatus.COVERED,
                                         FindingObservationStatus.NOT_OBSERVED, "SCANNER_SUCCESS_COVERED", contract=contract,
                                         scanner_version=scanner_version, fingerprint=fingerprint, execution_evidence=evidence), malformed
            return self._observation(assessment, scanner_id, status, CoverageStatus.INDETERMINATE,
                                     FindingObservationStatus.UNKNOWN, "RULE_COVERAGE_UNKNOWN", contract=contract,
                                     scanner_version=scanner_version, fingerprint=fingerprint, execution_evidence=evidence), malformed
        if status in {"skipped", "incompatible"}:
            code = "CAPABILITY_UNAVAILABLE" if status == "incompatible" else "SCANNER_SKIPPED"
            return self._observation(assessment, scanner_id, status, CoverageStatus.NOT_COVERED,
                                     FindingObservationStatus.NOT_EVALUATED, code, contract=contract,
                                     scanner_version=scanner_version, fingerprint=fingerprint), malformed
        if status == "failed":
            return self._observation(assessment, scanner_id, status, CoverageStatus.INDETERMINATE,
                                     FindingObservationStatus.UNKNOWN, "SCANNER_FAILED", contract=contract,
                                     scanner_version=scanner_version, fingerprint=fingerprint), malformed
        return self._observation(assessment, scanner_id, status or None, CoverageStatus.INDETERMINATE,
                                 FindingObservationStatus.UNKNOWN, "SCANNER_RESULT_MISSING", contract=contract,
                                 scanner_version=scanner_version, fingerprint=fingerprint), malformed

    @staticmethod
    def _raw_findings(assessment):
        result = getattr(assessment, "result", None)
        raw = getattr(result, "findings", None) if result is not None else None
        if raw is None and isinstance(result, Mapping):
            raw = result.get("findings", ())
        values = list(raw or ())
        # Some persisted protocol results expose findings only inside their
        # scanner result envelope. Include those as an observation source;
        # identity materialization remains assessment/endpoint scoped.
        for scanner_result in TenantFindingCoverageService._scanner_results(assessment):
            values.extend(scanner_result.get("findings") or ())
        return tuple(values)
    @staticmethod
    def _scanner_results(assessment):
        result = getattr(assessment, "result", None)
        raw = getattr(result, "scanner_results", None) if result is not None else None
        if raw is None and isinstance(result, Mapping):
            raw = result.get("scanner_results", ())
        return tuple(item for item in (raw or ()) if isinstance(item, Mapping))
    @staticmethod
    def _matches(candidate, source): return candidate is not None and candidate.get("version") == source.get("version") and candidate.get("digest") == source.get("digest")
    @staticmethod
    def _valid_fingerprint(value):
        if not isinstance(value, Mapping) or value.get("version") != 1 or value.get("match_semantics") != "candidate": return False
        components = value.get("components"); digest = value.get("digest")
        if not isinstance(components, Mapping) or not isinstance(digest, str): return False
        expected = derive_fingerprint({"scanner_id": components.get("scanner_id"), "rule_id": components.get("rule_id"), "resource_key": components.get("resource_key")}, components.get("endpoint_id", ""))
        return expected is not None and expected.digest == digest and dict(expected.components) == dict(components)
    @staticmethod
    def _observation(assessment, scanner_id, execution_status, coverage, observation, reason,
                     *, contract=None, scanner_version=None, fingerprint=None, execution_evidence=None):
        observed = getattr(assessment, "completed_at", None) or getattr(assessment, "created_at", None)
        attestation = CoverageAttestation(
            scanner_id, scanner_version,
            contract.granularity if contract else CoverageGranularity.UNKNOWN,
            (fingerprint or {}).get("components", {}).get("rule_id") if isinstance(fingerprint, Mapping) else None,
            (fingerprint or {}).get("components", {}).get("resource_key") if isinstance(fingerprint, Mapping) else None,
            execution_status, contract.contract_version if contract else 1, coverage,
            observation is FindingObservationStatus.NOT_OBSERVED and bool(contract and contract.covers(fingerprint, scanner_version, execution_evidence)), reason)
        return CoverageObservation(str(assessment.assessment_id), _status(assessment), scanner_id, execution_status,
                                   coverage, observation, reason, _time(observed), attestation)
    def _unresolved(self, source):
        if self.metrics is not None: self.metrics.increment("finding_coverage.unknown")
        return FindingCoverageHistory(source.occurrence_id, source.endpoint_id, "unresolved", (), True, 0, None,
                                      LifecycleEligibilityStatus.NOT_ELIGIBLE, 0, self.clock())


def _status(item):
    value = getattr(item, "state", getattr(item, "status", "unknown")); return getattr(value, "value", str(value))
def _time(value):
    if value is None: return datetime.min.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try: value = datetime.fromisoformat(value)
        except ValueError: return datetime.min.replace(tzinfo=timezone.utc)
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
