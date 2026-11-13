"""Exercise generated RC6 commands without elevation or network access."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / "scripts" / "ws03c-launch-disposable.ps1"
REHEARSAL = ROOT / "scripts" / "ws03c-privileged-rehearsal.ps1"
ARCHIVE = ROOT / "scripts" / "archive-agent-ws03c.ps1"
FIXTURE = ROOT / "scripts" / "ws03c-synthetic-fixture.py"
pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows PowerShell release path")


def _powershell(code: str, *, cwd: Path | None = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PSModulePath"] = os.pathsep.join((
        str(Path(env["PROGRAMFILES"]) / "WindowsPowerShell" / "Modules"),
        str(Path(env["WINDIR"]) / "System32" / "WindowsPowerShell" / "v1.0" / "Modules"),
    ))
    binary = Path(env["WINDIR"]) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    return subprocess.run([str(binary), "-NoProfile", "-NonInteractive", "-Command", code],
                          cwd=cwd, env=env, capture_output=True, text=True, timeout=60)


def _literal(path: Path) -> str:
    return "'" + str(path).replace("'", "''") + "'"


def _generated(tmp_path: Path) -> str:
    package = tmp_path / "source package with spaces" / "RAVEN-X-Agent-Recovery-0.1.0-ws03c-rc6e.zip"
    package.parent.mkdir()
    package.write_bytes(b"synthetic preview input; never extracted")
    digest = hashlib.sha256(package.read_bytes()).hexdigest()
    command = (f"& {_literal(LAUNCHER)} -PackagePath {_literal(package)} "
               f"-ExpectedPackageSha256 {digest} "
               f"-SafeResultPath {_literal(tmp_path / 'preview result with spaces.json')} -Preview")
    result = _powershell(command)
    assert result.returncode == 0, result.stderr
    assert "$pipArgs=@(" in result.stdout
    return result.stdout


def test_generated_pip_command_parses_and_preserves_hashes_and_exit(tmp_path):
    generated = _generated(tmp_path)
    parser = ("$tokens=$null;$errors=$null;"
              "[System.Management.Automation.Language.Parser]::ParseInput($inputScript,[ref]$tokens,[ref]$errors)|Out-Null;"
              "'parse_errors='+@($errors).Count")
    code = "$inputScript=@'\n" + generated + "\n'@\n" + parser
    parsed = _powershell(code)
    assert parsed.returncode == 0, parsed.stderr
    assert "parse_errors=0" in parsed.stdout
    start = generated.index("  $pipArgs=@(")
    stop = generated.index("  if ($LASTEXITCODE -ne 0)", start)
    exact = generated[start:stop]
    assert "--no-index" in exact and "--require-hashes" in exact and "'-r'" in exact
    stage = tmp_path / "offline stage with spaces"
    (stage / "wheels").mkdir(parents=True)
    lock = stage / "requirements-recovery-lock.txt"
    for contents, expected in (("", 0), ("missing-package==999 --hash=sha256:" + "0" * 64, 1)):
        lock.write_text(contents, encoding="ascii")
        run = (f"$stage={_literal(stage)};$python={_literal(Path(sys.executable))};"
               + exact + "'native_exit='+$nativeExit")
        result = _powershell(run, cwd=tmp_path)
        assert result.returncode == 0, result.stderr
        assert f"native_exit={expected}" in result.stdout


def test_exact_fixture_invocation_imports_packaged_backend_from_other_cwd(tmp_path):
    release = tmp_path / "verified release with spaces"
    (release / "scripts").mkdir(parents=True)
    shutil.copytree(ROOT / "backend", release / "backend", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy2(FIXTURE, release / "scripts" / FIXTURE.name)
    (release / "release-manifest.json").write_text("{}", encoding="ascii")
    unrelated = tmp_path / "unrelated current directory with spaces"
    unrelated.mkdir()
    result = subprocess.run([sys.executable, "-B", "-E", "-s",
                             str(release / "scripts" / FIXTURE.name), "--help"],
                            cwd=unrelated, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert "--base-python" in result.stdout


@pytest.mark.parametrize(("mode", "expected_code", "expected_exit", "should_pass"), [
    ("origin", "AGENT_ORIGIN_MISMATCH", 20, True),
    ("ca", "AGENT_CA_MISMATCH", 21, True),
    ("ca", "AGENT_ORIGIN_MISMATCH", 20, False),
    ("generic", "AGENT_ORIGIN_MISMATCH", 20, False),
    ("missing", "AGENT_ORIGIN_MISMATCH", 20, False),
    ("crash", "AGENT_ORIGIN_MISMATCH", 20, False),
    ("unexpected_exit", "AGENT_ORIGIN_MISMATCH", 20, False),
    ("success", "AGENT_ORIGIN_MISMATCH", 20, False),
])
def test_rehearsal_negative_inspection_requires_exact_reason(
        tmp_path, mode, expected_code, expected_exit, should_pass):
    module = tmp_path / "backend" / "application" / "ops"
    module.mkdir(parents=True)
    (module / "agent_recovery.py").write_text(
        "import os, sys\n"
        "mode = sys.argv[-1]\n"
        "if mode == 'missing':\n"
        "    import nonexistent_ws03c_dependency\n"
        "if mode == 'crash':\n"
        "    os._exit(20)\n"
        "if mode == 'origin':\n"
        "    print('AGENT_ORIGIN_MISMATCH')\n"
        "    raise SystemExit(20)\n"
        "if mode == 'ca':\n"
        "    print('AGENT_CA_MISMATCH')\n"
        "    raise SystemExit(21)\n"
        "if mode == 'unexpected_exit':\n"
        "    print('AGENT_ORIGIN_MISMATCH')\n"
        "    raise SystemExit(7)\n"
        "if mode == 'generic':\n"
        "    print('unrelated failure', file=sys.stderr)\n"
        "    raise SystemExit(2)\n"
        "raise SystemExit(0)\n", encoding="utf-8")
    code = (
        f"$tokens=$null;$errors=$null;"
        f"$ast=[System.Management.Automation.Language.Parser]::ParseFile({_literal(REHEARSAL)},[ref]$tokens,[ref]$errors);"
        "$function=$ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] "
        "-and $n.Name -eq 'Assert-RejectedInspection'},$true) | Select-Object -First 1;"
        "if(@($errors).Count -ne 0 -or $null -eq $function){exit 10};"
        "Invoke-Expression $function.Extent.Text;"
        f"$python={_literal(Path(sys.executable))};$ErrorActionPreference='Stop';"
        f"$shouldPass=${str(should_pass).lower()};"
        f"try {{Assert-RejectedInspection -Arguments @('{mode}') "
        f"-ExpectedCode '{expected_code}' -ExpectedExit {expected_exit};"
        "if(-not $shouldPass){exit 11}} "
        "catch {if($shouldPass -or $_.Exception.Message -ne "
        "'Inspection did not reject for the expected security reason.'){exit 12}};"
        "if($ErrorActionPreference -ne 'Stop'){exit 13};'negative-check-ok'"
    )
    result = _powershell(code, cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert "negative-check-ok" in result.stdout


@pytest.mark.parametrize(("field", "value", "should_pass"), [
    ("UserId", "S-1-5-18", True),
    ("UserId", "Users", False),
    ("LogonType", "Password", False),
    ("LogonType", "", False),
    ("RunLevel", "Limited", False),
    ("Execute", r"C:\Users\Public\python.exe", False),
    ("WorkingDirectory", r"C:\Users\Public", False),
    ("Actions", "extra", False),
])
def test_archive_registered_task_identity_check(field, value, should_pass):
    source = ARCHIVE.read_text(encoding="utf-8-sig")
    start = source.index("if (@($task.Actions).Count -ne 1")
    stop = source.index("Push-Location $releaseRoot", start)
    exact = source[start:stop]
    change = ("$task.Actions=@($action,$action);" if field == "Actions" else
              f"$task.{'Actions[0]' if field in {'Execute', 'WorkingDirectory'} else 'Principal'}.{field}='{value}';")
    code = (
        "$install='C:\\protected\\Agent';"
        "$principal=[pscustomobject]@{UserId='S-1-5-18';LogonType='ServiceAccount';RunLevel='Highest'};"
        "$action=[pscustomobject]@{Execute=(Join-Path $install 'venv\\Scripts\\python.exe');"
        "WorkingDirectory=$install};"
        "$task=[pscustomobject]@{Principal=$principal;Actions=@($action)};"
        + change
        +
        f"$shouldPass=${str(should_pass).lower()};"
        "try {" + exact + "if(-not $shouldPass){exit 11}} "
        "catch {if($shouldPass -or $_.Exception.Message -ne "
        "'Scheduled Task identity differs from the expected agent.'){exit 12}};"
        "'task-identity-ok'"
    )
    result = _powershell(code)
    assert result.returncode == 0, result.stderr
    assert "task-identity-ok" in result.stdout
