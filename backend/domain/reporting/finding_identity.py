"""Explainable, endpoint-scoped candidate identity for finding occurrences."""
from dataclasses import dataclass
import hashlib
import json
from typing import Mapping, Optional
from uuid import UUID, uuid5


_OCCURRENCE_NAMESPACE = UUID("34a1dc10-9f64-4e0d-b7f9-bdb2b740b844")
_RULE_KEYS = ("stable_rule_id", "rule_id", "check_id", "cve_id", "cve")
_RESOURCE_KEYS = ("resource_key", "resource_id", "registry_path", "service_name", "path", "port")


@dataclass(frozen=True)
class FindingOccurrenceId:
    """Opaque identity for one observed item in a single assessment result."""
    value: UUID

    def __post_init__(self):
        object.__setattr__(self, "value", UUID(str(self.value)))

    @classmethod
    def derived(cls, assessment_id: str, index: int, finding_id: object = None):
        if not assessment_id or index < 0:
            raise ValueError("assessment_id and non-negative index are required")
        return cls(uuid5(_OCCURRENCE_NAMESPACE, f"v1:{assessment_id}:{index}:{finding_id or ''}"))

    def __str__(self): return str(self.value)


@dataclass(frozen=True)
class FindingFingerprint:
    """Candidate logical identity; never a claim of automatic equivalence."""
    version: int
    components: Mapping[str, str]
    digest: str
    match_semantics: str = "candidate"

    def to_dict(self):
        return {"version": self.version, "components": dict(self.components),
                "digest": self.digest, "match_semantics": self.match_semantics}


def materialize_finding_identity(finding: Mapping, *, assessment_id: str, endpoint_id: str, index: int) -> dict:
    """Return a copy with stable occurrence data and a safe candidate key.

    The occurrence identifier is deterministic for legacy embedded result JSON;
    newly emitted result payloads persist it alongside the finding.  A logical
    fingerprint remains absent unless explicit scanner/rule/resource fields
    are available.
    """
    value = dict(finding)
    # Scanner-level result serialization may not carry the parent assessment
    # identity. Preserve that legacy mapping and let the top-level result
    # materialize occurrence identity when its context is available.
    if not assessment_id or not endpoint_id:
        return value
    occurrence = _occurrence(value.get("occurrence_id"), assessment_id, index, value.get("finding_id"))
    value["occurrence_id"] = str(occurrence)
    fingerprint = derive_fingerprint(value, endpoint_id)
    if fingerprint is not None:
        value["logical_fingerprint"] = fingerprint.to_dict()
    return value


def derive_fingerprint(finding: Mapping, endpoint_id: str) -> Optional[FindingFingerprint]:
    """Build v1 only from explicit scanner, rule, and resource identity hints."""
    source = _sources(finding)
    scanner_id = _first(source, ("scanner_id",))
    rule_id = _first(source, _RULE_KEYS)
    resource_key = _first(source, _RESOURCE_KEYS)
    if not scanner_id or not rule_id or not resource_key or not endpoint_id:
        return None
    components = {
        "endpoint_id": str(endpoint_id),
        "scanner_id": _normalize_machine(scanner_id),
        "rule_id": _normalize_machine(rule_id),
        "resource_key": _normalize_resource(resource_key),
    }
    canonical = json.dumps({"version": 1, "components": components}, sort_keys=True, separators=(",", ":"))
    return FindingFingerprint(1, components, hashlib.sha256(canonical.encode("utf-8")).hexdigest())


def _occurrence(value, assessment_id, index, finding_id):
    try:
        return FindingOccurrenceId(value)
    except (TypeError, ValueError, AttributeError):
        return FindingOccurrenceId.derived(assessment_id, index, finding_id)


def _sources(finding):
    result = [finding]
    for key in ("metadata", "legacy_metadata"):
        nested = finding.get(key)
        if isinstance(nested, Mapping):
            result.append(nested)
            extra = nested.get("extra_legacy_fields")
            if isinstance(extra, Mapping): result.append(extra)
    return tuple(result)


def _first(sources, keys):
    for source in sources:
        for key in keys:
            value = source.get(key)
            if value is not None and str(value).strip(): return str(value)
    return None


def _normalize_machine(value): return value.strip().casefold()
def _normalize_resource(value): return value.strip().replace("/", "\\").casefold()
