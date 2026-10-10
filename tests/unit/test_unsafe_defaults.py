"""WS-01: unsafe defaults are closed.

The legacy scan/analysis/remediation/system routers are unauthenticated and
execute on the server host. Before this work they were mounted by default, CORS
allowed any origin, the config file's `environment` was unreachable, and
`/ws/realtime` accepted every connection.

These tests pin each of those shut. They assert on configuration and on the
composed application rather than on implementation details, so a future
refactor that reopens a hole fails here.
"""
import os
from unittest import mock

import pytest

from backend.infrastructure.operational.settings import ApplicationSettings, ConfigurationError


def settings(env=None, config=None):
    """Build settings with an explicit environment, ignoring the real one."""
    with mock.patch.dict(os.environ, env or {}, clear=True):
        return ApplicationSettings.from_environment(config or {})


# ------------------------------------------------- legacy routes are opt-in

def test_legacy_routes_are_disabled_by_default():
    assert settings().enable_legacy_routes is False


def test_legacy_routes_require_an_explicit_opt_in():
    assert settings({"RAVENX_ENABLE_LEGACY_ROUTES": "true"}).enable_legacy_routes is True
    assert settings({"RAVENX_ENABLE_LEGACY_ROUTES": "1"}).enable_legacy_routes is True
    assert settings({"RAVENX_ENABLE_LEGACY_ROUTES": "yes"}).enable_legacy_routes is True


@pytest.mark.parametrize("value", ["false", "0", "no", "", "   ", "maybe", "TRUEISH"])
def test_anything_but_an_explicit_yes_leaves_legacy_routes_off(value):
    assert settings({"RAVENX_ENABLE_LEGACY_ROUTES": value}).enable_legacy_routes is False


def test_the_dataclass_default_is_also_closed():
    """Constructing settings directly must not reopen the surface."""
    assert ApplicationSettings().enable_legacy_routes is False


# --------------------------------------------- production refuses to start

def test_production_with_legacy_routes_refuses_to_start():
    value = settings({
        "RAVENX_ENVIRONMENT": "production",
        "RAVENX_ENABLE_LEGACY_ROUTES": "true",
        "RAVENX_CORS_ORIGINS": "https://console.example.com",
    })
    with pytest.raises(ConfigurationError, match="legacy routes"):
        value.validate()


def test_production_without_legacy_routes_passes_that_check():
    value = settings({
        "RAVENX_ENVIRONMENT": "production",
        "RAVENX_CORS_ORIGINS": "https://console.example.com",
    })
    # Any remaining failure must not be the legacy-route check.
    try:
        value.validate()
    except ConfigurationError as error:
        assert "legacy routes" not in str(error)


def test_production_allows_same_origin_with_an_empty_cors_allow_list():
    value = settings({"RAVENX_ENVIRONMENT": "production"})
    assert value.cors_origins == ()
    value.validate()


def test_production_rejects_wildcard_cors_before_mount():
    value = settings({"RAVENX_ENVIRONMENT": "production", "RAVENX_CORS_ORIGINS": "*"})
    with pytest.raises(ConfigurationError, match="wildcard CORS"):
        value.validate_pre_mount()


def test_sqlite_refuses_multiple_declared_workers():
    value = settings(config={"server": {"workers": 4}, "database": {"type": "sqlite"}})
    with pytest.raises(ConfigurationError, match="one server worker"):
        value.validate_pre_mount()


# ------------------------------------- config environment is honoured (F-17)

def test_config_file_environment_is_honoured_when_the_env_var_is_unset():
    """The env-var default used to be truthy, so config.yaml could never win.

    A deployment whose config declared production therefore ran with
    development safety checks.
    """
    value = settings(config={"application": {"environment": "production"}})
    assert value.environment == "production"


def test_environment_variable_overrides_the_config_file():
    value = settings({"RAVENX_ENVIRONMENT": "development"},
                     {"application": {"environment": "production"}})
    assert value.environment == "development"


def test_environment_falls_back_to_development_when_neither_is_set():
    assert settings().environment == "development"


def test_a_production_config_file_alone_refuses_legacy_routes():
    """The combination that used to pass silently."""
    value = settings({"RAVENX_ENABLE_LEGACY_ROUTES": "true"},
                     {"application": {"environment": "production"}})
    assert value.environment == "production"
    with pytest.raises(ConfigurationError, match="legacy routes"):
        value.validate()


# ------------------------------------------------------ CORS is same-origin

def test_cors_origins_are_empty_by_default():
    assert settings().cors_origins == ()


def test_cors_origins_are_parsed_when_configured():
    value = settings({"RAVENX_CORS_ORIGINS": "https://a.example.com, https://b.example.com"})
    assert value.cors_origins == ("https://a.example.com", "https://b.example.com")


def test_default_cors_configuration_allows_no_foreign_origin():
    """Guards the middleware wiring, not just the setting.

    With no configured origins the allow-list must be empty rather than "*".
    """
    value = settings()
    allow_origins = list(value.cors_origins)
    assert allow_origins == []
    assert "*" not in allow_origins


# --------------------------------------------------- composed application
#
# These assertions must see a *cold start with a clean environment*.  Reloading
# `backend.api.main` inside this interpreter would corrupt the module for every
# other suite (the app object is shared), so the composed app is inspected in a
# fresh subprocess instead.  That also makes the test honest: it measures what
# actually happens when the server boots with no configuration.

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

_PROBE = r"""
import json, os, sys
sys.path.insert(0, %r)
# The parent process owns this environment; do not strip it here.
from backend.api import main
print("<<<JSON>>>" + json.dumps({
    "paths": sorted({getattr(r, "path", "") for r in main.app.routes}),
    "optional_components": {k: str(v) for k, v in main.optional_components.items()},
    "cors_origins": list(main.settings.cors_origins),
    "enable_legacy_routes": main.settings.enable_legacy_routes,
    "environment": main.settings.environment,
}))
""" % str(ROOT)


def _boot(**env):
    """Import the composed app in a clean interpreter with `env` applied."""
    environ = dict(os.environ)
    for key in ("RAVENX_ENABLE_LEGACY_ROUTES", "RAVENX_ENVIRONMENT", "RAVENX_CORS_ORIGINS"):
        environ.pop(key, None)
    environ.update(env)
    result = subprocess.run([sys.executable, "-c", _PROBE], capture_output=True,
                            text=True, cwd=str(ROOT), env=environ, timeout=300)
    assert result.returncode == 0, result.stderr[-3000:]
    marker = result.stdout.index("<<<JSON>>>") + len("<<<JSON>>>")
    return json.loads(result.stdout[marker:].strip())


LEGACY_PREFIXES = ("/api/v1/scan", "/api/v1/analysis", "/api/v1/remediation",
                   "/api/v1/reports", "/api/v1/system")


def _legacy_paths(booted):
    return [path for path in booted["paths"] if path.startswith(LEGACY_PREFIXES)]


@pytest.fixture(scope="module")
def cold_start():
    """A cold start with no configuration at all."""
    return _boot()


def test_cold_start_disables_legacy_routes(cold_start):
    assert cold_start["enable_legacy_routes"] is False


def test_cold_start_mounts_no_legacy_routers(cold_start):
    mounted = _legacy_paths(cold_start)
    assert mounted == [], f"legacy routes mounted on a cold start: {mounted}"


def test_production_never_mounts_legacy_routers_even_when_requested():
    """Defence in depth at the mount point.

    Routers are built at import time but settings.validate() only runs in the
    lifespan, so an embedder that skips lifespan would otherwise serve the
    unauthenticated legacy surface in production.
    """
    booted = _boot(RAVENX_ENVIRONMENT="production",
                   RAVENX_ENABLE_LEGACY_ROUTES="true",
                   RAVENX_CORS_ORIGINS="https://console.example.com")
    assert _legacy_paths(booted) == []
    assert booted["enable_legacy_routes"] is True, "the request itself should be visible"


def test_production_reports_legacy_as_refused_not_merely_disabled():
    """An operator must be able to tell a refusal from an unset flag."""
    booted = _boot(RAVENX_ENVIRONMENT="production",
                   RAVENX_ENABLE_LEGACY_ROUTES="true",
                   RAVENX_CORS_ORIGINS="https://console.example.com")
    refused = [status for status in booted["optional_components"].values()
               if "refused" in status]
    assert refused, booted["optional_components"]
    assert all("production" in status for status in refused)


def test_development_still_mounts_legacy_routers_when_requested():
    """Personal mode must keep working: `run.py` opts in explicitly."""
    booted = _boot(RAVENX_ENVIRONMENT="development", RAVENX_ENABLE_LEGACY_ROUTES="true")
    assert _legacy_paths(booted), "legacy opt-in no longer mounts the personal-mode API"


def test_cold_start_still_serves_the_control_plane(cold_start):
    """Hardening must not remove the real product surface."""
    paths = cold_start["paths"]
    assert "/health" in paths
    assert "/ready" in paths
    assert any(path.startswith("/api/v1/auth/") for path in paths)
    assert any("/audit-events" in path for path in paths)
    assert any(path.startswith("/api/v1/agent") for path in paths)


def test_cold_start_reports_legacy_as_disabled_not_crashed(cold_start):
    """Status must say 'disabled', so an operator can tell it is a choice."""
    disabled = {name: status for name, status in cold_start["optional_components"].items()
                if "disabled" in status}
    assert disabled, cold_start["optional_components"]
    assert all("RAVENX_ENABLE_LEGACY_ROUTES" in status for status in disabled.values())


def test_cold_start_allows_no_cross_origin_request(cold_start):
    assert cold_start["cors_origins"] == []


def test_production_wildcard_cors_refuses_import_before_lifespan():
    environ = dict(os.environ)
    environ.update(RAVENX_ENVIRONMENT="production", RAVENX_CORS_ORIGINS="*")
    environ.pop("RAVENX_ENABLE_LEGACY_ROUTES", None)
    result = subprocess.run([sys.executable, "-c", _PROBE], capture_output=True,
                            text=True, cwd=str(ROOT), env=environ, timeout=30)
    assert result.returncode != 0
    assert "wildcard CORS" in result.stderr


# ------------------------------------------------------- WebSocket ingress
#
# WebSocket authentication is independent of the legacy-route flag, so these run
# against the shared app the rest of the suite uses.

@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient
    from backend.api.main import app
    return TestClient(app)


def _expect_rejected(client, url, headers=None):
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect(url, headers=headers or {}):
            pass
    assert excinfo.value.code == 1008


def test_websocket_requires_a_bearer_token(client):
    _expect_rejected(client, "/ws/realtime")


def test_websocket_rejects_an_invalid_session(client):
    _expect_rejected(client, "/ws/realtime",
                     {"Authorization": "Bearer not-a-real-session"})


@pytest.mark.parametrize("header", ["", "Bearer", "Bearer    ", "Basic abc123", "token abc"])
def test_websocket_rejects_a_malformed_authorization_header(client, header):
    _expect_rejected(client, "/ws/realtime", {"Authorization": header})


def test_websocket_does_not_accept_a_query_string_token(client):
    """Query-string credentials land in access logs and proxy history."""
    _expect_rejected(client, "/ws/realtime?token=anything")


def test_retired_websocket_does_not_run_expensive_session_lookup(client, monkeypatch):
    from backend.api import main

    def unexpected_lookup(_token):
        raise AssertionError("retired WebSocket performed session lookup")

    monkeypatch.setattr(main.human_sessions, "authenticate_bearer", unexpected_lookup)
    _expect_rejected(client, "/ws/realtime", {"Authorization": "Bearer any-token"})


def test_foreign_origin_preflight_is_rejected_by_the_composed_app(client):
    response = client.options("/api/v1/auth/login", headers={
        "Origin": "https://foreign.example",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type",
    })
    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers
