from datetime import datetime, timedelta, timezone
import json

import pytest

from backend.domain.assessment import AssessmentResult, AssessmentStatus, AssessmentTarget, Finding, FindingSeverity
from backend.domain.endpoint import EndpointId, PlatformInfo
from backend.domain.scanner import ScannerExecutionResult, ScannerExecutionStatus, ScannerCapability, TargetCapabilities
from backend.protocol.agent import (
    AgentCapabilityReport, AgentHeartbeat, AgentMessageEnvelope, AgentMessageType, AgentRuntimeState,
    AgentStatusReport, AssessmentDispatch, AssessmentProgress, AssessmentResultPayload, CorrelationId,
    EnrollmentRequestPayload, EnrollmentResponsePayload, InMemoryReplayGuard, MessageId, ProtocolError,
    ProtocolValidationPolicy, ProtocolVersion, ReplayDetectedError, UnsupportedProtocolVersion,
    default_message_registry, validate_envelope,
)


NOW = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)
ENDPOINT = EndpointId("123e4567-e89b-12d3-a456-426614174000")


def test_protocol_version_and_envelope_round_trip_are_deterministic():
    version = ProtocolVersion.parse("1.0")
    envelope = AgentMessageEnvelope(AgentMessageType.HEARTBEAT, {"health": "healthy"}, version, ENDPOINT, timestamp=NOW)
    encoded = envelope.to_dict()
    assert encoded == envelope.to_dict()
    assert AgentMessageEnvelope.from_dict(json.loads(json.dumps(encoded))).to_dict() == encoded
    with pytest.raises(UnsupportedProtocolVersion):
        ProtocolVersion.parse("2.0").ensure_supported()
    with pytest.raises(ValueError):
        ProtocolVersion.parse("future")


def test_freshness_policy_and_payload_limit():
    envelope = AgentMessageEnvelope(AgentMessageType.HEARTBEAT, {}, endpoint_id=ENDPOINT, timestamp=NOW)
    validate_envelope(envelope, now=NOW)
    with pytest.raises(ProtocolError):
        validate_envelope(envelope, now=NOW + timedelta(minutes=6))
    validate_envelope(envelope, now=NOW + timedelta(minutes=5), policy=ProtocolValidationPolicy(max_clock_skew=timedelta(minutes=5)))
    with pytest.raises(ProtocolError):
        validate_envelope(AgentMessageEnvelope(AgentMessageType.HEARTBEAT, {"x": "x" * 100}, endpoint_id=ENDPOINT, timestamp=NOW), now=NOW, policy=ProtocolValidationPolicy(max_payload_bytes=50))


def test_replay_guard_rejects_duplicate_message_ids():
    guard = InMemoryReplayGuard()
    message_id = MessageId()
    assert not guard.seen(message_id)
    guard.record(message_id)
    assert guard.seen(message_id)
    with pytest.raises(ReplayDetectedError):
        guard.record(message_id)


def test_message_registry_rejects_duplicates_and_lists_contracts():
    registry = default_message_registry()
    assert registry.get(AgentMessageType.HEARTBEAT) is AgentHeartbeat
    with pytest.raises(ValueError):
        registry.register(AgentMessageType.HEARTBEAT, AgentHeartbeat)


def test_enrollment_secrets_are_redacted_until_explicit_wire_serialization():
    request = EnrollmentRequestPayload("bootstrap-secret", "host", PlatformInfo("Windows"), "1.2.3")
    response = EnrollmentResponsePayload(ENDPOINT, "credential-id", "machine-secret")
    assert "bootstrap-secret" not in repr(request)
    assert "machine-secret" not in repr(response)
    assert request.to_dict()["enrollment_token"] == "<redacted>"
    assert response.to_dict()["credential_secret"] == "<redacted>"
    assert request.to_wire_dict()["enrollment_token"] == "bootstrap-secret"
    assert response.to_wire_dict()["credential_secret"] == "machine-secret"


def test_heartbeat_capabilities_status_and_dispatch_contracts():
    heartbeat = AgentHeartbeat(ENDPOINT, "1.0.0", "1.0", NOW, 4)
    assert AgentHeartbeat.from_dict(heartbeat.to_dict()).to_dict() == heartbeat.to_dict()
    report = AgentCapabilityReport(ENDPOINT, TargetCapabilities(frozenset({ScannerCapability("windows.firewall.read")})), NOW)
    assert AgentCapabilityReport.from_dict(report.to_dict()).to_dict() == report.to_dict()
    status = AgentStatusReport(ENDPOINT, "1.0.0", "1.0", AgentRuntimeState.RUNNING)
    assert status.to_dict()["runtime_state"] == "running"
    dispatch = AssessmentDispatch("assessment-1", ENDPOINT, ("windows.firewall",), NOW)
    assert dispatch.to_assessment_options().scanner_ids == ("windows.firewall",)
    progress = AssessmentProgress("assessment-1", "running", ("windows.firewall",), 1, None, NOW, CorrelationId())
    assert progress.to_dict()["total_scanners"] == 1


def test_assessment_result_mapping_preserves_findings_and_scanner_results():
    finding = Finding("f-1", FindingSeverity.HIGH, "firewall", "Blocked", "details", "firewall")
    scanner = ScannerExecutionResult("windows.firewall", ScannerExecutionStatus.SUCCESS, NOW, NOW, (finding,))
    result = AssessmentResult("assessment-1", AssessmentTarget("local:test", "host", "Windows"), AssessmentStatus.COMPLETED, NOW, NOW, (finding,), scanner_results=(scanner,))
    payload = AssessmentResultPayload.from_assessment_result(result)
    encoded = payload.to_dict()
    assert encoded["endpoint_id"] == "local:test"
    assert encoded["findings"][0]["finding_id"] == "f-1"
    assert encoded["scanner_results"][0]["scanner_id"] == "windows.firewall"
