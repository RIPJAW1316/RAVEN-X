"""Exercise the Windows server installer's DNS preflight without installing it."""
import json
import ipaddress
from pathlib import Path
import re
import shutil
import subprocess
import sys
import textwrap

import pytest
from cryptography import x509

from backend.cli import generate_local_tls


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "scripts" / "install-server.ps1"
STARTER = ROOT / "scripts" / "start-server.ps1"
pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows DNS preflight")


def _run_preflight(command: str, resolver: str = "") -> str:
    quoted_path = str(INSTALLER).replace("'", "''")
    harness = textwrap.dedent(f"""
        $ErrorActionPreference = 'Stop'
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile('{quoted_path}', [ref]$tokens, [ref]$errors)
        if ($errors.Count -ne 0) {{ throw 'Installer cannot be parsed' }}
        $functions = @($ast.FindAll({{
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -in @('Assert-ServerName', 'Assert-ServerNameResolution')
        }}, $true))
        if ($functions.Count -ne 2) {{ throw 'DNS preflight functions are missing' }}
        foreach ($node in $functions) {{ . ([scriptblock]::Create($node.Extent.Text)) }}
        {resolver}
        try {{
            {command}
            'ACCEPTED'
        }} catch {{
            'REJECTED:' + $_.Exception.Message
        }}
    """)
    result = subprocess.run(
        [shutil.which("pwsh") or "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", harness],
        capture_output=True, text=True, timeout=20, check=True,
    )
    assert not result.stderr.strip(), result.stderr
    return result.stdout.strip()


@pytest.mark.parametrize("name", [
    "omen", "omen.", "omen..lan", "-omen.lan", "omen-.lan",
    "omen/*.lan", "192.168.1.121", "x" * 64 + ".lan",
])
def test_invalid_server_names_are_rejected_before_dns(name):
    output = _run_preflight(f"Assert-ServerName '{name}'")
    assert output.startswith("REJECTED:")


def test_name_must_resolve_via_dns_to_selected_local_ip():
    resolver = """
        function Resolve-DnsName {
            [CmdletBinding()]
            param([string]$Name, [string]$Type, [switch]$DnsOnly, [switch]$NoHostsFile)
            if ($Name -cne 'omen.ravenx.test' -or $Type -cne 'A' -or
                -not $DnsOnly -or -not $NoHostsFile) { throw 'DNS-only A preflight missing' }
            [pscustomobject]@{ Type = 'A'; IPAddress = '192.168.1.121' }
        }
    """
    output = _run_preflight(
        "Assert-ServerName 'omen.ravenx.test'; "
        "Assert-ServerNameResolution 'omen.ravenx.test' ([Net.IPAddress]::Parse('192.168.1.121'))",
        resolver,
    )
    assert output == "ACCEPTED"


@pytest.mark.parametrize("answers", [
    "[pscustomobject]@{ Type = 'A'; IPAddress = '192.168.1.122' }",
    "[pscustomobject]@{ Type = 'CNAME'; IPAddress = $null }",
    "[pscustomobject]@{ Type = 'A'; IPAddress = '192.168.1.121' }; "
    "[pscustomobject]@{ Type = 'A'; IPAddress = '192.168.1.122' }",
])
def test_wrong_missing_or_ambiguous_dns_answers_fail_closed(answers):
    resolver = f"""
        function Resolve-DnsName {{
            [CmdletBinding()]
            param([string]$Name, [string]$Type, [switch]$DnsOnly, [switch]$NoHostsFile)
            {answers}
        }}
    """
    output = _run_preflight(
        "Assert-ServerNameResolution 'omen.ravenx.test' ([Net.IPAddress]::Parse('192.168.1.121'))",
        resolver,
    )
    assert output.startswith("REJECTED:")
    assert "selected ServerHost" in output


def test_dns_preflight_precedes_installation_mutations():
    source = INSTALLER.read_text(encoding="utf-8")
    assert source.index("Assert-ServerNameResolution $ServerName $ip") < source.index(
        "Protect-CodeDirectory $installParent"
    )


def test_hostname_mode_persists_address_before_tls_and_starts_without_overrides(tmp_path):
    quoted_source = str(INSTALLER).replace("'", "''")
    config_path = tmp_path / "server-address.json"
    quoted_config = str(config_path).replace("'", "''")
    harness = textwrap.dedent(f"""
        $ErrorActionPreference = 'Stop'
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile('{quoted_source}', [ref]$tokens, [ref]$errors)
        if ($errors.Count -ne 0) {{ throw 'Installer cannot be parsed' }}
        $functions = @($ast.FindAll({{
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'Write-ServerAddressConfig'
        }}, $true))
        if ($functions.Count -ne 1) {{ throw 'Address writer is missing' }}
        . ([scriptblock]::Create($functions[0].Extent.Text))
        Write-ServerAddressConfig '{quoted_config}' 'omen.ravenx.test' 8443 'Wi-Fi'
        try {{
            Write-ServerAddressConfig '{quoted_config}' 'attacker.ravenx.test' 9443 'Ethernet'
            'OVERWROTE'
        }} catch {{
            'REFUSED_OVERWRITE'
        }}
    """)
    result = subprocess.run(
        [shutil.which("pwsh") or "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", harness],
        capture_output=True, text=True, timeout=20, check=True,
    )
    assert result.stdout.strip() == "REFUSED_OVERWRITE"
    assert not result.stderr.strip(), result.stderr
    assert json.loads(config_path.read_text(encoding="utf-8")) == {
        "server_name": "omen.ravenx.test", "port": 8443, "interface_alias": "Wi-Fi",
    }

    source = INSTALLER.read_text(encoding="utf-8")
    assert source.index("Write-ServerAddressConfig $serverAddressConfig") < source.index("tls-init --data-dir")
    assert "Assert-ProtectedTree $serverAddressConfig $env:ProgramFiles" in source
    assert 'Write-Host "  & \'$startServer\'"' in source
    assert re.search(r"(?m)^\s*& \$startServer\s*$", source)
    assert "& $startServer -ServerName" not in source


def test_server_certificate_covers_stable_hostname_and_initial_ip(tmp_path):
    tls_dir = tmp_path / "tls"
    material = generate_local_tls(
        tls_dir, ["192.168.1.121", "ravenx.home.arpa"],
        protect=lambda path: path.mkdir(parents=True),
    )
    certificate = x509.load_pem_x509_certificate(Path(material["server.pem"]).read_bytes())
    san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "ravenx.home.arpa" in san.get_values_for_type(x509.DNSName)
    assert ipaddress.ip_address("192.168.1.121") in san.get_values_for_type(x509.IPAddress)
    assert "different.home.arpa" not in san.get_values_for_type(x509.DNSName)


@pytest.mark.parametrize("server_name", [None, "omen.ravenx.test"])
def test_firewall_rule_tracks_interface_only_in_hostname_mode(server_name):
    quoted_path = str(INSTALLER).replace("'", "''")
    argument = f"-ServerName '{server_name}'" if server_name else ""
    harness = textwrap.dedent("""
        $ErrorActionPreference = 'Stop'
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile('@@PATH@@', [ref]$tokens, [ref]$errors)
        if ($errors.Count -ne 0) { throw 'Installer cannot be parsed' }
        Import-Module NetSecurity -ErrorAction Stop
        $blocks = @($ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.IfStatementAst] -and
                $node.Extent.Text.StartsWith('if ($OpenPrivateFirewall)')
        }, $true))
        if ($blocks.Count -ne 1) { throw 'Firewall rule block is missing' }
        function Get-NetFirewallRule {
            [CmdletBinding()]
            param([string]$DisplayName)
        }
        function New-NetFirewallRule {
            [CmdletBinding()]
            param([string]$DisplayName, [string]$Direction, [string]$Action,
                  [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled]$Enabled,
                  [string]$Profile, [string]$Protocol, [string]$LocalAddress,
                  [string]$InterfaceAlias, [int]$LocalPort, [string]$RemoteAddress)
            $script:captured = $PSBoundParameters
        }
        $body = @'
        function Invoke-Firewall {
            param([string]$ServerName)
            $OpenPrivateFirewall = $true
            $ServerHost = '192.168.1.121'
            $interfaceAlias = 'Wi-Fi'
            $Port = 8443
            @@BLOCK@@
        }
        '@.Replace('@@BLOCK@@', $blocks[0].Extent.Text)
        . ([scriptblock]::Create($body))
        Invoke-Firewall @@ARG@@
        $script:captured | ConvertTo-Json -Compress
    """).replace("@@PATH@@", quoted_path).replace("@@ARG@@", argument)
    result = subprocess.run(
        [shutil.which("pwsh") or "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", harness],
        capture_output=True, text=True, timeout=20, check=True,
    )
    assert not result.stderr.strip(), result.stderr
    arguments = json.loads(result.stdout.splitlines()[-1])
    assert arguments["Profile"] == "Private"
    assert arguments["RemoteAddress"] == "LocalSubnet"
    if server_name:
        assert arguments["InterfaceAlias"] == "Wi-Fi"
        assert "LocalAddress" not in arguments
    else:
        assert arguments["LocalAddress"] == "192.168.1.121"
        assert "InterfaceAlias" not in arguments


def test_firewall_enabled_value_binds_to_real_cmdlet_without_adding_rule():
    quoted_path = str(INSTALLER).replace("'", "''")
    harness = textwrap.dedent(f"""
        $ErrorActionPreference = 'Stop'
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile('{quoted_path}', [ref]$tokens, [ref]$errors)
        if ($errors.Count -ne 0) {{ throw 'Installer cannot be parsed' }}
        $assignments = @($ast.FindAll({{
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left.Extent.Text -eq '$firewall'
        }}, $true))
        if ($assignments.Count -ne 1) {{ throw 'Firewall arguments are missing' }}
        Import-Module NetSecurity -ErrorAction Stop
        $ruleName = 'RAVEN-X Firewall Binding Regression WhatIf'
        $Port = 8443
        . ([scriptblock]::Create($assignments[0].Extent.Text))
        New-NetFirewallRule @firewall -LocalAddress '127.0.0.1' -WhatIf -ErrorAction Stop | Out-Null
        'BINDING_OK'
    """)
    result = subprocess.run(
        [shutil.which("pwsh") or "powershell.exe", "-NoProfile", "-NonInteractive",
         "-Command", harness],
        capture_output=True, text=True, timeout=20, check=True,
    )
    assert not result.stderr.strip(), result.stderr
    assert result.stdout.splitlines()[-1] == "BINDING_OK"


@pytest.mark.parametrize(("configured_interface", "network_category", "expected"), [
    ("Wi-Fi", "Private", "ACCEPTED:192.168.1.121"),
    ("Ethernet", "Private", "REJECTED:The resolved server interface differs"),
    ("Wi-Fi", "Public", "REJECTED:The resolved server interface must use the Private"),
])
def test_startup_uses_pinned_config_and_current_private_interface(
    tmp_path, configured_interface, network_category, expected,
):
    install_root = tmp_path / "program-files" / "RAVEN-X" / "Server"
    python_path = install_root / "venv" / "Scripts" / "python.exe"
    python_path.parent.mkdir(parents=True)
    python_path.touch()
    (tmp_path / "program-data").mkdir()
    (install_root / "server-address.json").write_text(json.dumps({
        "server_name": "ravenx.home.arpa", "port": 8443,
        "interface_alias": configured_interface,
    }), encoding="utf-8")

    source = STARTER.read_text(encoding="utf-8")
    assert source.startswith("#Requires -RunAsAdministrator")
    preflight = source.split(
        "if ([string]::IsNullOrWhiteSpace($env:RAVENX_LOCAL_AI_ENABLED))", 1,
    )[0].replace("#Requires -RunAsAdministrator", "", 1)
    program_files = str(tmp_path / "program-files").replace("'", "''")
    program_data = str(tmp_path / "program-data").replace("'", "''")
    harness = textwrap.dedent(f"""
        $ErrorActionPreference = 'Stop'
        $env:ProgramFiles = '{program_files}'
        $env:ProgramData = '{program_data}'
        function Resolve-DnsName {{
            [CmdletBinding()]
            param([string]$Name, [string]$Type, [switch]$DnsOnly, [switch]$NoHostsFile)
            if ($Name -cne 'ravenx.home.arpa' -or $Type -cne 'A' -or
                -not $DnsOnly -or -not $NoHostsFile) {{ throw 'DNS-only A lookup missing' }}
            [pscustomobject]@{{ Type = 'A'; IPAddress = '192.168.1.121' }}
        }}
        function Get-NetIPAddress {{
            [CmdletBinding()]
            param([string]$IPAddress, [string]$AddressFamily)
            [pscustomobject]@{{ InterfaceAlias = 'Wi-Fi'; InterfaceIndex = 42 }}
        }}
        function Get-NetConnectionProfile {{
            [CmdletBinding()]
            param([int]$InterfaceIndex)
            [pscustomobject]@{{ NetworkCategory = '{network_category}' }}
        }}
        try {{
            {preflight}
            'ACCEPTED:' + $serverIp
        }} catch {{
            'REJECTED:' + $_.Exception.Message
        }}
    """)
    result = subprocess.run(
        [shutil.which("pwsh") or "powershell.exe", "-NoProfile", "-NonInteractive",
         "-Command", harness],
        capture_output=True, text=True, timeout=20, check=True,
    )
    assert not result.stderr.strip(), result.stderr
    assert result.stdout.strip().startswith(expected)
