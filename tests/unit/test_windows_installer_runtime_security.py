"""Exercise installer runtime selection without executing an interpreter or installer."""
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import textwrap

import pytest

ROOT = Path(__file__).resolve().parents[2]
SELECTOR = ROOT / "scripts" / "runtime-selection.ps1"
pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows installer path semantics")


def _powershell(script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [shutil.which("pwsh") or "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=20, check=True,
    )


def _select_python(lines: list[str], *, reparse_reject: str = "", writable_reject: str = "") -> str:
    listing = "\n".join(f"  '{line}'" for line in lines)
    harness = textwrap.dedent(f"""
        $ErrorActionPreference = 'Stop'
        . '{SELECTOR}'
        function Fake-Launcher {{
          param($Operation)
          if ($Operation -ne '-0p') {{ throw 'UNVERIFIED_EXECUTION' }}
          @(
            {listing}
          )
          $global:LASTEXITCODE = 0
        }}
        function Assert-NotReparseTree {{
          param($Path)
          if ('{reparse_reject}' -and $Path -eq '{reparse_reject}') {{ throw 'reparse point rejected' }}
        }}
        function Assert-ProtectedTree {{
          param($Path, $Root)
          if ('{writable_reject}' -and $Path -eq '{writable_reject}') {{ throw 'user-writable runtime rejected' }}
        }}
        try {{
          $selected = Select-RavenXPython313 -Launcher 'Fake-Launcher' -ProgramFiles 'C:\\Program Files' -ProtectedTreeCommand 'Assert-ProtectedTree'
          Write-Output ('ACCEPTED:' + $selected)
        }} catch {{
          Write-Output ('REJECTED:' + $_.Exception.Message)
        }}
    """)
    result = _powershell(harness)
    assert "UNVERIFIED_EXECUTION" not in result.stdout
    assert result.stderr.strip() == "" or "UNVERIFIED_EXECUTION" not in result.stderr
    return result.stdout


@pytest.mark.parametrize("name", ["install-agent.ps1", "install-server.ps1"])
def test_installers_delegate_selection_and_never_launch_unverified_python(name):
    source = (ROOT / "scripts" / name).read_text(encoding="utf-8")
    assert ". (Join-Path $PSScriptRoot 'runtime-selection.ps1')" in source
    assert "Select-RavenXPython313" in source
    assert "& $launcher -3.13" not in source
    assert "& $launcher -0p" not in source
    assert "& $basePython -I -m venv" in source


def test_server_installer_does_not_resolve_npm_from_the_command_search_path():
    source = (ROOT / "scripts" / "install-server.ps1").read_text(encoding="utf-8")
    assert "Get-Command npm.cmd" not in source
    assert "Select-RavenXNodeToolchain" in source


def test_agent_installer_configures_battery_resilient_scheduled_task_settings():
    source = (ROOT / "scripts" / "install-agent.ps1").read_text(encoding="utf-8")
    assert "-AllowStartIfOnBatteries" in source
    assert "-DontStopIfGoingOnBatteries" in source
    assert "Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings" in source


def test_agent_install_directories_grant_trusted_access_before_removing_inheritance():
    source = (ROOT / "scripts" / "install-agent.ps1").read_text(encoding="utf-8")
    block = source.split("function Protect-CodeDirectory", 1)[1].split("Assert-NotReparseTree $env:ProgramFiles", 1)[0]
    assert block.index("'/grant:r'") < block.index("'/inheritance:r'")


@pytest.mark.parametrize("relative", ["scripts/install-agent.ps1", "scripts/pilot/Install-PythonPortable.ps1"])
def test_runtime_smoke_expression_survives_windows_powershell_51_native_arguments(relative):
    source = (ROOT / relative).read_text(encoding="utf-8")
    expression = re.search(r" -I -c '([^']+)'", source)
    assert expression is not None
    python_path = sys.executable.replace("'", "''")
    command = f"& '{python_path}' -I -c '{expression.group(1)}'; exit $LASTEXITCODE"
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, timeout=20,
    )
    expected = f"{sys.version_info.major}|{sys.version_info.minor}|{platform.machine()}"
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected


def test_agent_installer_verifies_release_and_tls_before_creating_agent_state():
    source = (ROOT / "scripts" / "install-agent.ps1").read_text(encoding="utf-8")
    release = source.index("Assert-VerifiedRelease $repoRoot")
    trust = source.index("backend\\agent\\trust.py")
    first_install = source.index("Protect-CodeDirectory $installParent")
    enrollment = source.index("$enrollArgs = @(")
    assert release < trust < first_install < enrollment
    assert "--no-index --no-cache-dir" in source
    assert "--require-hashes" in source
    assert "-r (Join-Path $installRoot 'requirements-agent-lock.txt')" in source
    assert "'-m', 'backend.agent', 'enroll'" in source
    assert "& $agentPython @enrollArgs --token-stdin" in source
    assert "Bootstrap token" not in source.split("$arguments =", 1)[1]


def test_compiled_installer_source_pins_extraction_before_running_scripts():
    source = (ROOT / "scripts" / "RAVEN-X-Agent-Setup.iss").read_text(encoding="utf-8")
    assert "PrivilegesRequired=admin" in source
    assert "ArchitecturesAllowed=x64compatible" in source
    assert "function PrepareToInstall" in source
    assert "release extraction path was overridden" in source
    assert "CheckStageSecurity(Stage, Parent);" in source
    assert "GetSHA256OfFile(Stage + '\\scripts\\install-agent.ps1')" in source
    assert source.index("CheckStageSecurity(Stage, Parent);") < source.index("if not Exec(PowerShell, Params")


@pytest.mark.parametrize("candidate,accepted", [
    (r"C:\Users\untrusted\Python313\python.exe", False),
    (r"C:\Program Files\..\Users\untrusted\python.exe", False),
    (r"C:\Program Files\Python313\python.exe", True),
])
def test_python_discovery_never_executes_unverified_runtime(candidate, accepted):
    output = _select_python([f" -V:3.13 *        {candidate}"])
    assert ("ACCEPTED:" in output) is accepted
    if accepted:
        assert output.strip().endswith(r"C:\Program Files\Python313\python.exe")


def test_system_python_is_selected_when_a_per_user_python_is_also_registered():
    output = _select_python([
        r" -V:3.13          C:\Users\untrusted\AppData\Local\Programs\Python\Python313\python.exe",
        r" -V:3.13-64 *     C:\Program Files\Python313\python.exe",
    ])
    assert "ACCEPTED:C:\\Program Files\\Python313\\python.exe" in output.replace("\n", "")
    assert "AppData" not in output


def test_only_per_user_python_is_rejected():
    output = _select_python([
        r" -V:3.13 *        C:\Users\untrusted\AppData\Local\Programs\Python\Python313\python.exe",
    ])
    assert output.startswith("REJECTED:")
    assert "per-user interpreter is not used" in output
    assert "ACCEPTED:" not in output


def test_multiple_system_pythons_fail_closed():
    output = _select_python([
        r" -V:3.13          C:\Program Files\Python313\python.exe",
        r" -V:3.13-32       C:\Program Files\Python313-32\python.exe",
        r" -V:3.13          C:\Users\untrusted\AppData\Local\Programs\Python\Python313\python.exe",
    ])
    assert output.startswith("REJECTED:")
    assert "Multiple Python 3.13" in output
    assert "ACCEPTED:" not in output


def test_reparse_point_on_the_system_python_does_not_fall_back_to_the_user_python():
    trusted = r"C:\Program Files\Python313\python.exe"
    output = _select_python([
        r" -V:3.13          C:\Users\untrusted\AppData\Local\Programs\Python\Python313\python.exe",
        f" -V:3.13-64 *     {trusted}",
    ], reparse_reject=trusted)
    assert output.startswith("REJECTED:")
    assert "reparse point rejected" in output
    assert "ACCEPTED:" not in output


def test_user_writable_system_python_does_not_fall_back_to_the_user_python():
    trusted = r"C:\Program Files\Python313\python.exe"
    output = _select_python([
        r" -V:3.13          C:\Users\untrusted\AppData\Local\Programs\Python\Python313\python.exe",
        f" -V:3.13-64 *     {trusted}",
    ], writable_reject=trusted)
    assert output.startswith("REJECTED:")
    assert "user-writable runtime rejected" in output
    assert "ACCEPTED:" not in output


def _select_node(program_files: Path, nodes: list[Path], *, reparse_reject: Path | None = None,
                 writable_reject: Path | None = None) -> str:
    quoted = ", ".join("'" + str(path).replace("'", "''") + "'" for path in nodes)
    reparse = str(reparse_reject or "")
    writable = str(writable_reject or "")
    harness = textwrap.dedent(f"""
        $ErrorActionPreference = 'Stop'
        . '{SELECTOR}'
        function Assert-NotReparseTree {{
          param($Path)
          if ('{reparse}' -and $Path -eq '{reparse}') {{ throw 'reparse point rejected' }}
        }}
        function Assert-ProtectedTree {{
          param($Path, $Root)
          if ('{writable}' -and $Path -eq '{writable}') {{ throw 'user-writable runtime rejected' }}
        }}
        try {{
          $selected = Select-RavenXNodeToolchain -NodeExecutables @({quoted}) -ProgramFiles '{program_files}' -ProtectedTreeCommand 'Assert-ProtectedTree'
          Write-Output ('NODE:' + $selected.Node)
          Write-Output ('NPM:' + $selected.Npm)
        }} catch {{
          Write-Output ('REJECTED:' + $_.Exception.Message)
        }}
    """)
    return _powershell(harness).stdout


def test_system_node_is_paired_with_its_own_npm_when_a_user_npm_exists(tmp_path):
    program_files = tmp_path / "Program Files"
    system_dir = program_files / "nodejs"
    system_dir.mkdir(parents=True)
    node = system_dir / "node.exe"
    npm = system_dir / "npm.cmd"
    node.write_text("", encoding="utf-8")
    npm.write_text("@echo off", encoding="utf-8")
    user_node = tmp_path / "user" / "node.exe"
    user_node.parent.mkdir()
    user_node.write_text("", encoding="utf-8")
    user_npm = tmp_path / "user-global" / "npm.cmd"
    user_npm.parent.mkdir()
    user_npm.write_text("@echo off", encoding="utf-8")
    output = _select_node(program_files, [user_node, node])
    assert f"NODE:{node}" in output
    assert f"NPM:{npm}" in output
    assert "user-global" not in output


def test_node_without_a_sibling_npm_is_rejected(tmp_path):
    program_files = tmp_path / "Program Files"
    system_dir = program_files / "nodejs"
    system_dir.mkdir(parents=True)
    node = system_dir / "node.exe"
    node.write_text("", encoding="utf-8")
    output = _select_node(program_files, [node])
    assert output.startswith("REJECTED:")
    assert "npm.cmd was not found" in output


def test_only_per_user_node_is_rejected(tmp_path):
    user_node = tmp_path / "user" / "node.exe"
    user_node.parent.mkdir()
    user_node.write_text("", encoding="utf-8")
    output = _select_node(tmp_path / "Program Files", [user_node])
    assert output.startswith("REJECTED:")
    assert "per-user Node.js is not used" in output


def test_multiple_system_node_installations_fail_closed(tmp_path):
    program_files = tmp_path / "Program Files"
    first = program_files / "nodejs" / "node.exe"
    second = program_files / "nodejs-extra" / "node.exe"
    for path in (first, second):
        path.parent.mkdir(parents=True)
        path.write_text("", encoding="utf-8")
        (path.parent / "npm.cmd").write_text("@echo off", encoding="utf-8")
    output = _select_node(program_files, [first, second])
    assert output.startswith("REJECTED:")
    assert "Multiple Node.js" in output


def test_reparse_or_writable_node_pair_is_rejected(tmp_path):
    program_files = tmp_path / "Program Files"
    system_dir = program_files / "nodejs"
    system_dir.mkdir(parents=True)
    node = system_dir / "node.exe"
    npm = system_dir / "npm.cmd"
    node.write_text("", encoding="utf-8")
    npm.write_text("@echo off", encoding="utf-8")
    reparse = _select_node(program_files, [node], reparse_reject=node)
    assert reparse.startswith("REJECTED:")
    assert "reparse point rejected" in reparse
    writable = _select_node(program_files, [node], writable_reject=npm)
    assert writable.startswith("REJECTED:")
    assert "user-writable runtime rejected" in writable
