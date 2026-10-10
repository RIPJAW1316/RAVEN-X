"""Exercise installer discovery without executing an interpreter or installer."""
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows installer path semantics")


@pytest.mark.parametrize("name", ["install-agent.ps1", "install-server.ps1"])
@pytest.mark.parametrize("candidate,accepted", [
    (r"C:\Users\untrusted\Python311\python.exe", False),
    (r"C:\Program Files\..\Users\untrusted\python.exe", False),
    (r"C:\Program Files\Python311\python.exe", True),
])
def test_python_discovery_never_executes_unverified_runtime(name, candidate, accepted):
    source = (ROOT / "scripts" / name).read_text(encoding="utf-8")
    discovery = source[source.index("$pythonListing ="):source.index("Protect-CodeDirectory $installParent\n")]
    # A fake trusted launcher will only accept the runtime-listing operation.
    # Validators are mocked here; their real ACL logic is tested separately.
    harness = r"""
$ErrorActionPreference = 'Stop'
$env:ProgramFiles = 'C:\Program Files'
function Fake-Launcher {
  param($Operation)
  if ($Operation -ne '-0p') { throw 'UNVERIFIED_EXECUTION' }
  ' -V:3.11 *        CANDIDATE'
  $global:LASTEXITCODE = 0
}
function Assert-NotReparseTree { param($Path) }
function Assert-NoUntrustedWriteTree { param($Path, $Root) }
function Assert-ProtectedTree { param($Path, $Root) }
$launcher = 'Fake-Launcher'
try {
DISCOVERY
  Write-Output ('ACCEPTED:' + $basePython)
} catch { Write-Output ('REJECTED:' + $_.Exception.Message) }
""".replace("CANDIDATE", candidate).replace("DISCOVERY", discovery)
    result = subprocess.run([shutil.which("pwsh") or "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", harness],
                            capture_output=True, text=True, timeout=15, check=True)
    assert "UNVERIFIED_EXECUTION" not in result.stdout
    assert ("ACCEPTED:" in result.stdout) is accepted
    assert "& $launcher -3.11" not in source
    assert "& $basePython -I -m venv" in source
