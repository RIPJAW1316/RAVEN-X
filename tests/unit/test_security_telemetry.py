"""Windowed security telemetry: correctness, bounds, tenancy and thread safety."""
from datetime import datetime, timedelta, timezone

import pytest

from backend.domain.security_signals import (AuthenticationCounts, AuthorizationCounts,
                                             SecuritySignalSeverity, SecuritySignalType,
                                             SignalThresholds, evaluate_signals)
from backend.infrastructure.operational import MetricsCollector, SecurityTelemetry
from backend.infrastructure.operational.security_telemetry import UNATTRIBUTED

START = datetime(2026, 4, 1, 12, 0, tzinfo=timezone.utc)
ORG_A = "11111111-1111-1111-1111-111111111111"
ORG_B = "22222222-2222-2222-2222-222222222222"


class Clock:
    def __init__(self, start=START):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, **kwargs):
        self.now += timedelta(**kwargs)


def build(**kwargs):
    clock = Clock()
    metrics = MetricsCollector()
    return SecurityTelemetry(metrics=metrics, clock=clock, **kwargs), clock, metrics


# --------------------------------------------------------------- counting

def test_authorization_attempts_allowed_and_denied_are_counted():
    telemetry, _clock, _metrics = build()
    for _ in range(7):
        telemetry.record_authorization(organization_id=ORG_A, allowed=True, action="endpoint.read")
    for _ in range(3):
        telemetry.record_authorization(organization_id=ORG_A, allowed=False, action="endpoint.read",
                                       reason_code="permission_not_granted")

    counts = telemetry.authorization_counts(ORG_A, window_minutes=15)
    assert counts.attempts == 10
    assert counts.allowed == 7
    assert counts.denied == 3
    assert counts.denial_rate == pytest.approx(0.3)


def test_denials_are_broken_down_by_action_and_reason():
    telemetry, _clock, _metrics = build()
    telemetry.record_authorization(organization_id=ORG_A, allowed=False, action="endpoint.revoke",
                                   reason_code="permission_not_granted")
    telemetry.record_authorization(organization_id=ORG_A, allowed=False, action="endpoint.revoke",
                                   reason_code="permission_not_granted")
    telemetry.record_authorization(organization_id=ORG_A, allowed=False, action="assessment.create",
                                   reason_code="resource_organization_mismatch")

    counts = telemetry.authorization_counts(ORG_A, window_minutes=15)
    assert counts.denied_by_action == {"assessment.create": 1, "endpoint.revoke": 2}
    assert counts.denied_by_reason == {"permission_not_granted": 2,
                                       "resource_organization_mismatch": 1}


def test_authentication_outcomes_are_counted():
    telemetry, _clock, _metrics = build()
    for _ in range(4):
        telemetry.record_authentication(success=True)
    for _ in range(6):
        telemetry.record_authentication(success=False)
    counts = telemetry.authentication_counts(window_minutes=15)
    assert counts.success == 4 and counts.failure == 6
    assert counts.failure_rate == pytest.approx(0.6)


def test_flat_process_counters_still_feed_metricscollector():
    """The existing MetricsCollector must keep working alongside the windows."""
    telemetry, _clock, metrics = build()
    telemetry.record_authorization(organization_id=ORG_A, allowed=True, action="endpoint.read")
    telemetry.record_authorization(organization_id=ORG_A, allowed=False, action="endpoint.read",
                                   reason_code="permission_not_granted")
    telemetry.record_authentication(success=False)
    snapshot = metrics.snapshot()
    assert snapshot["authorization_attempts_total"] == 2
    assert snapshot["authorization_allowed_total"] == 1
    assert snapshot["authorization_denied_total"] == 1
    assert snapshot["authentication_failure_total"] == 1


# ------------------------------------------------------------- time windows

def test_events_outside_the_window_are_excluded():
    telemetry, clock, _metrics = build()
    telemetry.record_authorization(organization_id=ORG_A, allowed=False, action="endpoint.read",
                                   reason_code="permission_not_granted")
    clock.advance(minutes=10)
    telemetry.record_authorization(organization_id=ORG_A, allowed=False, action="endpoint.read",
                                   reason_code="permission_not_granted")

    assert telemetry.authorization_counts(ORG_A, window_minutes=5).denied == 1
    assert telemetry.authorization_counts(ORG_A, window_minutes=15).denied == 2


def test_old_buckets_are_pruned_so_memory_stays_bounded():
    telemetry, clock, _metrics = build(buckets=5)
    for _ in range(20):
        telemetry.record_authorization(organization_id=ORG_A, allowed=True, action="endpoint.read")
        clock.advance(minutes=1)
    assert telemetry.authorization_counts(ORG_A, window_minutes=5).attempts <= 5


@pytest.mark.parametrize("window", [0, -1, True, "5", 61])
def test_invalid_windows_are_rejected(window):
    telemetry, _clock, _metrics = build()
    with pytest.raises(ValueError):
        telemetry.authorization_counts(ORG_A, window_minutes=window)


# ------------------------------------------------------------ tenant safety

def test_telemetry_is_isolated_per_organization():
    telemetry, _clock, _metrics = build()
    for _ in range(5):
        telemetry.record_authorization(organization_id=ORG_A, allowed=False, action="endpoint.read",
                                       reason_code="permission_not_granted")
    telemetry.record_authorization(organization_id=ORG_B, allowed=True, action="endpoint.read")

    assert telemetry.authorization_counts(ORG_A, window_minutes=15).denied == 5
    assert telemetry.authorization_counts(ORG_B, window_minutes=15).denied == 0
    assert telemetry.authorization_counts(ORG_B, window_minutes=15).allowed == 1


def test_unattributed_traffic_is_never_reported_inside_a_tenant():
    """Unverified denials must not inflate a real tenant's numbers."""
    telemetry, _clock, _metrics = build()
    for _ in range(9):
        telemetry.record_authorization(organization_id=None, allowed=False, action="endpoint.read",
                                       reason_code="membership_context_mismatch")
    assert telemetry.authorization_counts(ORG_A, window_minutes=15).denied == 0
    assert telemetry.authorization_counts(UNATTRIBUTED, window_minutes=15).denied == 9


def test_blank_organization_is_treated_as_unattributed():
    telemetry, _clock, _metrics = build()
    telemetry.record_authorization(organization_id="   ", allowed=False, action="endpoint.read",
                                   reason_code="permission_not_granted")
    assert telemetry.authorization_counts(UNATTRIBUTED, window_minutes=15).denied == 1


# ---------------------------------------------------------- cardinality

def test_label_values_are_sanitised_against_injection():
    telemetry, _clock, _metrics = build()
    telemetry.record_authorization(organization_id=ORG_A, allowed=False,
                                   action="endpoint.read\nmalicious: 1",
                                   reason_code="a" * 500)
    counts = telemetry.authorization_counts(ORG_A, window_minutes=15)
    action = next(iter(counts.denied_by_action))
    reason = next(iter(counts.denied_by_reason))
    assert "\n" not in action and "\n" not in reason
    assert len(action) <= 64 and len(reason) <= 64


def test_series_cardinality_is_capped_rather_than_growing():
    telemetry, _clock, _metrics = build(max_series_per_bucket=8)
    for index in range(200):
        telemetry.record_authorization(organization_id=ORG_A, allowed=False,
                                       action=f"action.{index}", reason_code="permission_not_granted")
    counts = telemetry.authorization_counts(ORG_A, window_minutes=15)
    assert len(counts.denied_by_action) <= 8
    assert telemetry.dropped_series() > 0


def test_organization_count_is_capped_by_evicting_least_recently_used():
    telemetry, _clock, _metrics = build(max_organizations=3)
    for index in range(10):
        telemetry.record_authorization(organization_id=f"org-{index}", allowed=True,
                                       action="endpoint.read")
    tracked = sum(1 for index in range(10)
                  if telemetry.authorization_counts(f"org-{index}", window_minutes=15).attempts)
    assert tracked <= 3


# --------------------------------------------------------- thread safety

def test_concurrent_recording_does_not_lose_counts():
    from concurrent.futures import ThreadPoolExecutor
    telemetry = SecurityTelemetry(metrics=MetricsCollector(), clock=lambda: START)

    def worker(_):
        for _ in range(100):
            telemetry.record_authorization(organization_id=ORG_A, allowed=True,
                                           action="endpoint.read")

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(worker, range(8)))
    assert telemetry.authorization_counts(ORG_A, window_minutes=15).attempts == 800


# ------------------------------------------------------------- detection

def _authz(attempts, denied, **kwargs):
    return AuthorizationCounts(attempts=attempts, allowed=attempts - denied, denied=denied, **kwargs)


def test_normal_traffic_produces_no_signals():
    signals = evaluate_signals(_authz(500, 5), AuthenticationCounts(success=40, failure=1),
                               window_minutes=15, now=START)
    assert signals == ()


def test_a_few_denials_on_tiny_traffic_do_not_fire():
    """1 denial out of 1 attempt is a 100% rate but is not an incident."""
    signals = evaluate_signals(_authz(1, 1), AuthenticationCounts(), window_minutes=15, now=START)
    assert signals == ()


def test_denial_spike_fires_when_volume_and_rate_are_both_abnormal():
    signals = evaluate_signals(_authz(50, 30), AuthenticationCounts(), window_minutes=2, now=START)
    spike = next(s for s in signals if s.signal_type is SecuritySignalType.AUTHORIZATION_DENIAL_SPIKE)
    assert spike.severity is SecuritySignalSeverity.WARNING
    assert spike.evidence["denied"] == 30 and spike.evidence["attempts"] == 50
    assert "60.0%" in spike.reason


def test_large_denial_spike_is_critical():
    signals = evaluate_signals(_authz(100, 80), AuthenticationCounts(), window_minutes=2, now=START)
    spike = next(s for s in signals if s.signal_type is SecuritySignalType.AUTHORIZATION_DENIAL_SPIKE)
    assert spike.severity is SecuritySignalSeverity.CRITICAL


def test_high_volume_with_low_denial_rate_does_not_fire():
    signals = evaluate_signals(_authz(10_000, 25), AuthenticationCounts(), window_minutes=15, now=START)
    assert not any(s.signal_type is SecuritySignalType.AUTHORIZATION_DENIAL_SPIKE for s in signals)


def test_repeated_authentication_failures_fire():
    signals = evaluate_signals(_authz(10, 0), AuthenticationCounts(success=1, failure=12),
                               window_minutes=5, now=START)
    signal = next(s for s in signals
                  if s.signal_type is SecuritySignalType.REPEATED_AUTHENTICATION_FAILURE)
    assert signal.severity is SecuritySignalSeverity.WARNING
    assert signal.evidence["failure"] == 12


def test_cross_tenant_probing_is_critical():
    counts = _authz(40, 20, denied_by_reason={"resource_organization_mismatch": 6,
                                              "permission_not_granted": 14})
    signals = evaluate_signals(counts, AuthenticationCounts(), window_minutes=5, now=START)
    probing = next(s for s in signals if s.signal_type is SecuritySignalType.CROSS_TENANT_PROBING)
    assert probing.severity is SecuritySignalSeverity.CRITICAL
    assert probing.evidence["boundary_denials"] == 6


def test_permission_denials_alone_are_not_boundary_probing():
    counts = _authz(40, 30, denied_by_reason={"permission_not_granted": 30})
    signals = evaluate_signals(counts, AuthenticationCounts(), window_minutes=5, now=START)
    assert not any(s.signal_type is SecuritySignalType.CROSS_TENANT_PROBING for s in signals)


def test_repeated_denials_against_one_action_are_called_out():
    counts = _authz(60, 40, denied_by_action={"assessment.create": 20, "endpoint.read": 20})
    signals = evaluate_signals(counts, AuthenticationCounts(), window_minutes=5, now=START)
    scoped = [s for s in signals if s.signal_type is SecuritySignalType.SENSITIVE_ACTION_DENIALS]
    assert {s.scope for s in scoped} == {"assessment.create", "endpoint.read"}


def test_signals_are_ordered_most_severe_first():
    counts = _authz(100, 80, denied_by_reason={"resource_organization_mismatch": 10})
    signals = evaluate_signals(counts, AuthenticationCounts(success=0, failure=40),
                               window_minutes=5, now=START)
    severities = [s.severity for s in signals]
    assert severities == sorted(severities, key=lambda s: {"critical": 0, "warning": 1, "info": 2}[s.value])


def test_signal_serialises_with_its_evidence():
    signals = evaluate_signals(_authz(50, 30), AuthenticationCounts(), window_minutes=2, now=START)
    data = signals[0].to_dict()
    assert set(data) == {"signal_type", "severity", "detected_at", "window_minutes", "scope",
                         "reason", "evidence"}
    assert data["detected_at"].endswith("+00:00")
    assert data["evidence"]["denied"] == 30


def test_thresholds_are_validated():
    for kwargs in ({"denial_floor": 0}, {"denial_rate": 0}, {"denial_rate": 1.5},
                   {"denial_floor": 50, "denial_critical_floor": 10},
                   {"authentication_failure_floor": -1}):
        with pytest.raises(ValueError):
            SignalThresholds(**kwargs)


def test_detection_is_deterministic():
    counts = _authz(50, 30)
    first = evaluate_signals(counts, AuthenticationCounts(), window_minutes=2, now=START)
    second = evaluate_signals(counts, AuthenticationCounts(), window_minutes=2, now=START)
    assert [s.to_dict() for s in first] == [s.to_dict() for s in second]
