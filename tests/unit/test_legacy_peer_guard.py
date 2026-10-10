"""Personal-mode host actions accept only local ASGI peers."""

import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
PREFIXES = ("/api/v1/scan", "/api/v1/analysis", "/api/v1/remediation",
            "/api/v1/reports", "/api/v1/system")

_PROBE = r"""
import json
from fastapi.testclient import TestClient
from backend.api import main

prefixes = %r
assert set(main._mounted_legacy_prefixes) == set(prefixes)
actual_host_actions = ("/api/v1/scan/start", "/api/v1/analysis/retrain",
                       "/api/v1/remediation/fix", "/api/v1/reports/generate",
                       "/api/v1/system/monitoring/start")
assert set(actual_host_actions) <= {route.path for route in main.app.routes}

class WithoutPeer:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            scope = dict(scope)
            scope["client"] = None
        await self.app(scope, receive, send)

remote = TestClient(main.app, client=("203.0.113.9", 50000))
remote_v6 = TestClient(main.app, client=("2001:db8::9", 50000))
unknown = TestClient(main.app, client=("testclient", 50000))
missing = TestClient(WithoutPeer(main.app), client=("127.0.0.1", 50000))
local = TestClient(main.app, client=("127.0.0.1", 50000))
local_v6 = TestClient(main.app, client=("::1", 50000))
mapped = TestClient(main.app, client=("::ffff:127.0.0.1", 50000))

# Missing paths are harmless even when local. They prove the guard runs before
# the legacy router and that local personal-mode traffic reaches routing.
results = {
    "actual_remote": [remote.post(path, headers={"X-Forwarded-For": "127.0.0.1"}).status_code
                      for path in actual_host_actions],
    "standalone_stats": remote.get("/api/v1/stats").status_code,
    "remote": [remote.get(path + "/peer-guard-probe",
                         headers={"X-Forwarded-For": "127.0.0.1"}).status_code for path in prefixes],
    "remote_v6": remote_v6.get(prefixes[2] + "/peer-guard-probe").status_code,
    "unknown": unknown.get(prefixes[2] + "/peer-guard-probe").status_code,
    "missing": missing.get(prefixes[2] + "/peer-guard-probe").status_code,
    "local": [local.get(path + "/peer-guard-probe",
                        headers={"X-Forwarded-For": "203.0.113.9"}).status_code for path in prefixes],
    "local_v6": local_v6.get(prefixes[2] + "/peer-guard-probe").status_code,
    "mapped": mapped.get(prefixes[2] + "/peer-guard-probe").status_code,
    "enterprise_health": remote.get("/health").status_code,
    "enterprise_report": remote.get("/api/v1/organizations/invalid/reports/fleet").status_code,
    "near_prefix": remote.get("/api/v1/scanner/peer-guard-probe").status_code,
}
print("<<<JSON>>>" + json.dumps(results))
""" % (PREFIXES,)


def test_explicit_legacy_mode_rejects_non_loopback_asgi_peers(tmp_path):
    env = dict(os.environ)
    env.update(RAVENX_ENVIRONMENT="development", RAVENX_ENABLE_LEGACY_ROUTES="true",
               RAVENX_CONFIG_PATH=str(ROOT / "config" / "config.yaml"),
               RAVENX_DATABASE_PATH=str(tmp_path / "peer-guard.db"))
    result = subprocess.run([sys.executable, "-c", _PROBE], cwd=ROOT, env=env,
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr[-3000:]
    marker = result.stdout.rfind("<<<JSON>>>")
    assert marker >= 0, result.stdout[-3000:]
    outcomes = json.loads(result.stdout[marker + len("<<<JSON>>>"):].strip())
    assert outcomes["actual_remote"] == [403] * len(PREFIXES)
    assert outcomes["standalone_stats"] == 403
    assert outcomes["remote"] == [403] * len(PREFIXES)
    assert outcomes["remote_v6"] == 403
    assert outcomes["unknown"] == 403
    assert outcomes["missing"] == 403
    assert outcomes["local"] == [404] * len(PREFIXES)
    assert outcomes["local_v6"] == 404
    assert outcomes["mapped"] == 404
    assert outcomes["enterprise_health"] == 200
    assert outcomes["enterprise_report"] == 401
    assert outcomes["near_prefix"] == 404
