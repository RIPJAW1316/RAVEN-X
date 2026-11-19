"""Release manifest failures before any elevated installer side effects."""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "scripts" / "release-integrity.ps1"
pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows release path")


def _stage(tmp_path):
    stage = tmp_path / "stage"
    (stage / "backend" / "agent").mkdir(parents=True)
    code = stage / "backend" / "agent" / "host.py"
    code.write_bytes(b"reviewed agent code\n")
    manifest = {
        "format": 1, "version": "1.0.0-rc9",
        "source_baseline": "b53ac0fea11432badcc13e89d0d0f3966d1689bd",
        "accepted_diff_sha256": "96e4cbd61c1154ea37a558fabb213075cd0378fb8232582acbfc02d5ee8e5d3a",
        "files": [{"path": "backend/agent/host.py", "sha256": hashlib.sha256(code.read_bytes()).hexdigest(),
                   "size": code.stat().st_size}],
    }
    (stage / "release-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return stage


def _verify(stage, *, trusted=False):
    command = "Assert-TrustedReleaseTree" if trusted else "Assert-ReleaseManifestFiles"
    escaped_script = str(VERIFIER).replace("'", "''")
    escaped_stage = str(stage).replace("'", "''")
    code = (f". '{escaped_script}'; try {{ {command} '{escaped_stage}' | Out-Null; 'ACCEPT' }} "
            "catch { 'REJECT:' + $_.Exception.Message }")
    result = subprocess.run([shutil.which("pwsh") or "powershell.exe", "-NoProfile", "-NonInteractive",
                             "-Command", code], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def test_complete_manifest_is_accepted(tmp_path):
    assert _verify(_stage(tmp_path)) == "ACCEPT"


def test_replacement_after_prior_validation_is_rejected_on_recheck(tmp_path):
    stage = _stage(tmp_path)
    assert _verify(stage) == "ACCEPT"
    (stage / "backend" / "agent" / "host.py").write_bytes(b"late replacement")
    assert _verify(stage).startswith("REJECT:")


@pytest.mark.parametrize("mutation", ["changed", "missing", "extra", "traversal", "duplicate", "symlink"])
def test_tampered_or_unsafe_payload_is_rejected(tmp_path, mutation):
    stage = _stage(tmp_path)
    code = stage / "backend" / "agent" / "host.py"
    manifest_path = stage / "release-manifest.json"
    if mutation == "changed":
        code.write_bytes(b"substituted code\n")
    elif mutation == "missing":
        code.unlink()
    elif mutation == "extra":
        (stage / "backend" / "agent" / "unreviewed.py").write_text("pass")
    elif mutation in {"traversal", "duplicate"}:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if mutation == "traversal":
            manifest["files"][0]["path"] = "../escape.py"
        else:
            manifest["files"].append(manifest["files"][0])
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    else:
        code.unlink()
        try:
            code.symlink_to(manifest_path)
        except OSError as error:
            pytest.skip(f"file symlink not available: {error}")
    assert _verify(stage).startswith("REJECT:")


def test_unprotected_user_stage_is_rejected_even_with_valid_hashes(tmp_path):
    assert _verify(_stage(tmp_path), trusted=True).startswith("REJECT:")
