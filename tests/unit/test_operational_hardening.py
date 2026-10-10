from datetime import datetime, timedelta, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.api.human_control_plane import HumanControlPlaneDependencies, create_human_control_plane_router
from backend.infrastructure.operational import ApplicationSettings, ConfigurationError, InMemoryRateLimiter, MetricsCollector


def test_rate_limiter_threshold_expiry_and_reset_without_sleep():
    now = [datetime(2026, 1, 1, tzinfo=timezone.utc)]
    limiter = InMemoryRateLimiter(2, 60, clock=lambda: now[0])
    assert limiter.check("client:key").allowed
    assert limiter.check("client:key").allowed
    blocked = limiter.check("client:key")
    assert not blocked.allowed and blocked.retry_after > 0
    now[0] += timedelta(seconds=61)
    assert limiter.check("client:key").allowed
    limiter.reset("client:key")
    assert limiter.check("client:key").remaining == 1


def test_rate_limiter_keys_are_independent_and_metrics_are_low_cardinality():
    limiter = InMemoryRateLimiter(1, 60)
    assert limiter.check("a").allowed
    assert limiter.check("b").allowed
    metrics = MetricsCollector()
    metrics.increment("http.requests", 2)
    assert metrics.snapshot() == {"http.requests": 2}


def test_production_settings_reject_wildcard_cors_and_invalid_limits():
    try:
        ApplicationSettings(environment="production", cors_origins=("*",)).validate()
        assert False, "unsafe production settings must be rejected"
    except ConfigurationError:
        pass
    try:
        ApplicationSettings(login_rate_limit=0).validate()
        assert False, "invalid rate-limit settings must be rejected"
    except ConfigurationError:
        pass


class _Auth:
    def authenticate(self, email, password):
        raise ValueError("invalid credentials")


def test_login_rate_limit_is_generic_and_sets_retry_after():
    app = FastAPI()
    limiter = InMemoryRateLimiter(1, 60)
    app.include_router(create_human_control_plane_router(HumanControlPlaneDependencies(
        _Auth(), None, None, None, None, None, login_rate_limiter=limiter)), prefix="/api/v1")
    client = TestClient(app)
    first = client.post("/api/v1/auth/login", json={"email": "unknown@example.com", "password": "wrong"})
    second = client.post("/api/v1/auth/login", json={"email": "unknown@example.com", "password": "wrong"})
    assert first.status_code == 401
    assert second.status_code == 429
    assert second.headers["Retry-After"]
    assert "unknown@example.com" not in second.text
