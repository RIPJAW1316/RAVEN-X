#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Start one RAVEN-X process on exact Omen loopback and Private-LAN TLS addresses.
.DESCRIPTION
Requires the selected LAN IP to be assigned to the named Private interface and
present in the existing server certificate SAN. Does not change firewall rules.
#>
param(
    [Parameter(Mandatory=$true)][string]$LanAddress,
    [Parameter(Mandatory=$true)][string]$InterfaceAlias,
    [ValidateRange(1024,65535)][int]$Port = 8443
)
$ErrorActionPreference = 'Stop'
$installRoot = Join-Path $env:ProgramFiles 'RAVEN-X\Server'
$dataRoot = Join-Path $env:ProgramData 'RAVEN-X\server'
$python = Join-Path $installRoot 'venv\Scripts\python.exe'
$certificate = Join-Path $dataRoot 'tls\server.pem'
$key = Join-Path $dataRoot 'tls\server-key.pem'
$parsed = [Net.IPAddress]::None
if (-not [Net.IPAddress]::TryParse($LanAddress, [ref]$parsed) -or
    $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
    $parsed.ToString() -cne $LanAddress) { throw 'LanAddress must be a canonical IPv4 literal.' }
$octets = $parsed.GetAddressBytes()
$private = ($octets[0] -eq 10) -or
    ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) -or
    ($octets[0] -eq 192 -and $octets[1] -eq 168)
if (-not $private) { throw 'LanAddress must be RFC1918 private.' }
if ([string]::IsNullOrWhiteSpace($InterfaceAlias) -or $InterfaceAlias -match '[*?]') {
    throw 'InterfaceAlias must name one interface without wildcards.'
}
$assigned = @(Get-NetIPAddress -IPAddress $LanAddress -AddressFamily IPv4 -ErrorAction Stop)
if ($assigned.Count -ne 1 -or $assigned[0].InterfaceAlias -ine $InterfaceAlias) {
    throw 'LanAddress is not assigned to the approved interface.'
}
$profile = Get-NetConnectionProfile -InterfaceIndex $assigned[0].InterfaceIndex -ErrorAction Stop
if ($profile.NetworkCategory -ne 'Private') { throw 'The LAN interface must have a Private profile.' }
$rule = @(Get-NetFirewallRule -DisplayName 'RAVEN-X October 15 Control Plane' -ErrorAction Stop)
if ($rule.Count -ne 1 -or $rule[0].Enabled.ToString() -ne 'True' -or
    $rule[0].Direction.ToString() -ne 'Inbound' -or $rule[0].Action.ToString() -ne 'Allow' -or
    $rule[0].Profile.ToString() -ne 'Private') { throw 'Expected Private inbound firewall rule is missing or unsafe.' }
$portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule[0]
$addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule[0]
if ($portFilter.Protocol.ToString() -ne 'TCP' -or $portFilter.LocalPort.ToString() -ne $Port.ToString() -or
    @($addressFilter.RemoteAddress).Count -ne 1 -or @($addressFilter.RemoteAddress)[0] -ne 'LocalSubnet') {
    throw 'Firewall protocol, port or remote scope is not the approved pilot scope.'
}
foreach ($file in @($python, $certificate, $key)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw 'Installed runtime or TLS material is missing.' }
    if (((Get-Item -LiteralPath $file -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Installed runtime or TLS material contains a reparse point.'
    }
}
Push-Location $installRoot
try {
    & $python -B -E -s -m backend.application.ops.listeners --certificate $certificate --host '127.0.0.1' --host $LanAddress
    if ($LASTEXITCODE -ne 0) { throw 'TLS certificate SAN does not cover both listener addresses.' }
    if ([string]::IsNullOrWhiteSpace($env:RAVENX_LOCAL_AI_ENABLED)) { $env:RAVENX_LOCAL_AI_ENABLED = 'false' }
    & $python -B -E -s -m backend.cli serve --data-dir $dataRoot --listen-host '127.0.0.1' --listen-host $LanAddress --port $Port
    if ($LASTEXITCODE -ne 0) { throw "RAVEN-X server exited with code $LASTEXITCODE." }
} finally {
    Pop-Location
}
