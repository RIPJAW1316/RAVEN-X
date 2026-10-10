"""Deterministic conversion of legacy scanner dictionaries into domain data."""

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Iterable, Mapping, Tuple

from ...domain.assessment import Evidence, Finding, FindingSeverity


_KNOWN_FIELDS = {
    "severity",
    "category",
    "title",
    "details",
    "component",
    "remediation",
    "powershell_command",
}


class MalformedLegacyFindingError(ValueError):
    """Raised when an item cannot be interpreted as a legacy finding mapping."""


@dataclass(frozen=True)
class NormalizationIssue:
    index: int
    reason: str
    raw_value: Any


def _as_text(value: Any, fallback: str = "") -> str:
    if value is None:
        return fallback
    return str(value)


def _stable_finding_id(finding: Mapping[str, Any]) -> str:
    identity = {
        key: finding.get(key)
        for key in ("severity", "category", "title", "details", "component")
    }
    serialized = json.dumps(identity, default=str, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def normalize_legacy_finding(finding: Mapping[str, Any]) -> Finding:
    """Normalize one legacy finding without discarding extra source fields."""
    if not isinstance(finding, Mapping):
        raise MalformedLegacyFindingError("legacy finding must be a mapping")

    missing_fields = [name for name in ("category", "title", "details", "component") if not finding.get(name)]
    details = _as_text(finding.get("details"))
    extra_fields = {key: value for key, value in finding.items() if key not in _KNOWN_FIELDS}
    metadata = {"missing_legacy_fields": tuple(missing_fields), "extra_legacy_fields": extra_fields}
    legacy_metadata = {}
    if finding.get("powershell_command") is not None:
        legacy_metadata["powershell_command"] = finding.get("powershell_command")

    return Finding(
        finding_id=_stable_finding_id(finding),
        severity=FindingSeverity.from_legacy(finding.get("severity")),
        category=_as_text(finding.get("category"), "Uncategorized"),
        title=_as_text(finding.get("title"), "Untitled legacy finding"),
        details=details,
        component=_as_text(finding.get("component"), "Unknown component"),
        remediation=_as_text(finding.get("remediation")) or None,
        evidence=(Evidence(source="legacy.scanner", description=details),) if details else (),
        metadata=metadata,
        legacy_metadata=legacy_metadata,
    )


def normalize_legacy_findings(raw_findings: Iterable[Any]) -> Tuple[Tuple[Finding, ...], Tuple[NormalizationIssue, ...]]:
    """Normalize every valid item and explicitly retain malformed input as issues."""
    findings = []
    issues = []
    for index, raw_finding in enumerate(raw_findings):
        try:
            findings.append(normalize_legacy_finding(raw_finding))
        except MalformedLegacyFindingError as error:
            issues.append(NormalizationIssue(index=index, reason=str(error), raw_value=raw_finding))
    return tuple(findings), tuple(issues)
