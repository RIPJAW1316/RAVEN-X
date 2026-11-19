"""Execute public-input parsing in the exact Windows PowerShell 5.1 runtime.

No installed endpoint, real token or live server is used. Privileged filesystem
and SYSTEM tests are covered separately by the disposable setup rehearsal.
"""
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows setup")


def ps(script):
    return subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                          capture_output=True, text=True, timeout=30)


def literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def parse_connection(tmp_path, mutate=None):
    ca = tmp_path / "operator's public CA.pem"
    ca.write_text("public test fixture", encoding="utf-8")
    data = dict(server_url="https://192.168.1.121:8443", ca_path=str(ca),
                ca_sha256="a" * 64, enrollment_id="11111111-2222-4333-8444-555555555555")
    if mutate:
        mutate(data)
    config = tmp_path / "connection.json"
    config.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    # Load only the production pure validation function; never run the installer.
    script = f"""
    $ErrorActionPreference='Stop'
    $ast=[Management.Automation.Language.Parser]::ParseFile({literal(ROOT / 'scripts/setup-agent.ps1')},[ref]$null,[ref]$null)
    $fn=$ast.Find({{param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Read-RavenXSetupConnection'}},$true)
    . ([scriptblock]::Create($fn.Extent.Text))
    try {{ Read-RavenXSetupConnection {literal(config)} | ConvertTo-Json -Compress }}
    catch {{ Write-Output ('REJECTED: '+$_.Exception.Message); exit 2 }}
    """
    return ps(script), data


def test_public_connection_roundtrip_preserves_spaces_and_apostrophes(tmp_path):
    result, expected = parse_connection(tmp_path)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == expected


@pytest.mark.parametrize("field,value", [
    ("server_url", "http://192.168.1.121:8443"),
    ("server_url", "https://user:secret@example.com"),
    ("server_url", 'https://host/;Write-Output injected'),
    ("server_url", "https://host?token=bad"),
    ("server_url", "https://host/#fragment"),
    ("server_url", "https://host/path"),
    ("server_url", "https://host:99999"),
    ("enrollment_id", "not-a-uuid"),
    ("enrollment_id", "00000000-0000-0000-0000-000000000000"),
    ("ca_sha256", "g" * 64),
    ("ca_sha256", "a" * 63),
    ("ca_path", "C:\\nonexistent-ravenx-fixture\\ca.pem"),
    ("ca_path", ["unexpected", "array"]),
    ("server_url", None),
])
def test_invalid_connection_stops_before_runtime_or_enrollment(tmp_path, field, value):
    result, _ = parse_connection(tmp_path, lambda data: data.update({field: value}))
    assert result.returncode == 2
    assert result.stdout.startswith("REJECTED:")


def test_token_is_not_an_allowed_connection_file_property(tmp_path):
    result, _ = parse_connection(tmp_path, lambda data: data.update(token="PRIVATE_SENTINEL"))
    assert result.returncode == 2
    assert "PRIVATE_SENTINEL" not in result.stdout + result.stderr


def test_missing_field_is_rejected(tmp_path):
    result, _ = parse_connection(tmp_path, lambda data: data.pop("ca_sha256"))
    assert result.returncode == 2


def test_all_shipped_powershell_files_parse_in_windows_powershell_51():
    paths = [ROOT / "scripts" / name for name in
             ("setup-agent.ps1", "managed-python.ps1", "install-agent.ps1", "release-integrity.ps1",
              "runtime-selection.ps1", "Remove-RavenXClient.ps1")]
    result = ps("$ErrorActionPreference='Stop';" + "\n".join(
        f"$e=$null; [void][Management.Automation.Language.Parser]::ParseFile({literal(p)},[ref]$null,[ref]$e); if($e){{$e;exit 2}}"
        for p in paths))
    assert result.returncode == 0, result.stdout + result.stderr


def test_runtime_refuses_install_outside_program_files(tmp_path):
    result = ps(f"""
        $ErrorActionPreference='Stop'
        . {literal(ROOT / 'scripts/managed-python.ps1')}
        try {{ Ensure-RavenXManagedPython -ArchivePath 'not-used.zip' -RuntimeParent {literal(tmp_path / 'runtime')}; exit 3 }}
        catch {{ $_.Exception.Message; exit 2 }}
    """)
    assert result.returncode == 2
    assert "inside protected Program Files" in result.stdout
    assert not (tmp_path / "runtime").exists()


def test_bundled_runtime_probe_survives_powershell51_native_quoting():
    import re
    source = (ROOT / "scripts/managed-python.ps1").read_text()
    expression = re.search(r" -I -c '([^']+)'", source).group(1)
    result = ps(f"& {literal(sys.executable)} -B -I -c '{expression}'; exit $LASTEXITCODE")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "3|13|AMD64"
