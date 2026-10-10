"""The compatibility launcher must not expose legacy host actions to the LAN."""

import run


def test_personal_backend_binds_loopback_and_sets_local_legacy_mode(monkeypatch):
    monkeypatch.delenv("RAVENX_ENVIRONMENT", raising=False)
    monkeypatch.delenv("RAVENX_ENABLE_LEGACY_ROUTES", raising=False)
    captured = {}

    def fake_popen(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return object()

    monkeypatch.setattr(run.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(run.time, "sleep", lambda _: None)
    class HealthyResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

    monkeypatch.setattr("urllib.request.urlopen", lambda *args, **kwargs: HealthyResponse())

    run.RAVENXLauncher().start_backend()

    command = captured["command"]
    assert command[command.index("--host") + 1] == "127.0.0.1"
    assert "--reload" not in command
    environment = captured["kwargs"]["env"]
    assert environment["RAVENX_ENVIRONMENT"] == "development"
    assert environment["RAVENX_ENABLE_LEGACY_ROUTES"] == "true"
