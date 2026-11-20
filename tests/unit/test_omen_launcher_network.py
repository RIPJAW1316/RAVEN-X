import os
from pathlib import Path
import subprocess
import sys

import pytest

from backend.application.ops.listeners import select_profile_certificate
from backend.cli import generate_local_tls


def test_launcher_selects_certificate_for_vm_under_same_ca(tmp_path):
    tls = tmp_path / "profile"
    material = generate_local_tls(tls, ["192.168.56.1"], protect=lambda path: path.mkdir())
    foreign = generate_local_tls(tmp_path / "other", ["192.168.56.1"], protect=lambda path: path.mkdir())
    default = tls / "server.pem"
    alternate = tls / "server-vm.pem"
    alternate.write_bytes(default.read_bytes())
    hosts = ["127.0.0.1", "192.168.56.1"]
    assert select_profile_certificate(tls, hosts) == default
    default.write_bytes(Path(foreign["server.pem"]).read_bytes())
    assert select_profile_certificate(tls, hosts) == alternate
    with pytest.raises(ValueError, match="covers all listeners"):
        select_profile_certificate(tls, ["127.0.0.1", "10.0.0.7"])
    alternate.unlink()
    with pytest.raises(ValueError, match="covers all listeners"):
        select_profile_certificate(tls, hosts)
    assert Path(material["ca.pem"]).is_file()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows adapter discovery")
def test_picker_and_startup_network_policy():
    script = Path(__file__).resolve().parents[2] / "scripts/pilot/Get-OmenLanAddress.ps1"
    command = r"""
$ErrorActionPreference = 'Stop'
function Get-NetAdapter {
    foreach ($i in 1..8) {
        [pscustomobject]@{
            ifIndex = $i
            Status = if ($i -eq 8) { 'Down' } else { 'Up' }
            InterfaceDescription = if ($i -in 3,4,5,6) { 'VirtualBox Host-Only Ethernet Adapter' } else { 'Other' }
            DriverFileName = if ($i -in 3,4,5) { 'VBoxNetAdp6.sys' } else { 'other.sys' }
        }
    }
}
function Get-NetIPAddress {
    param($AddressFamily)
    foreach ($i in 1..8) {
        [pscustomobject]@{InterfaceIndex=$i; IPAddress="192.168.$i.1"; AddressState='Preferred'}
    }
}
function Get-NetRoute {
    param($AddressFamily)
    [pscustomobject]@{ InterfaceIndex=4; DestinationPrefix='0.0.0.0/0' }
}
function Get-NetConnectionProfile {
    foreach ($i in 1,2,5,8) {
        [pscustomobject]@{ InterfaceIndex=$i; NetworkCategory=if ($i -in 1,8) { 'Private' } else { 'Public' } }
    }
}
& $env:RAVENX_TEST_ADDRESS_SCRIPT
"""
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command],
        env={**os.environ, "RAVENX_TEST_ADDRESS_SCRIPT": str(script)},
        capture_output=True, text=True, check=True, timeout=30,
    )
    assert result.stdout.splitlines() == ["192.168.1.1", "192.168.3.1"]
