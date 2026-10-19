#Requires -RunAsAdministrator
<#
.SYNOPSIS
Start the installed RAVEN-X control plane at the current LAN address of its DNS name.

.DESCRIPTION
The DNS name and port stay fixed for enrolled agents. The DNS A record may
change when the HP Omen receives a new private IPv4 address. This script reads
its protected installation config and refuses an unresolved, ambiguous,
nonlocal, non-Private, or wrong-interface address.
#>
$ErrorActionPreference = 'Stop'
$installRoot = Join-Path $env:ProgramFiles 'RAVEN-X\Server'
$dataRoot = Join-Path $env:ProgramData 'RAVEN-X\server'
$configPath = Join-Path $installRoot 'server-address.json'
$serverPython = Join-Path $installRoot 'venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
    throw 'The protected server address configuration is missing.'
}
if (((Get-Item -LiteralPath $configPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'The server address configuration must not be a reparse point.'
}
$config = Get-Content -LiteralPath $configPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
$serverName = [string]$config.server_name
$interfaceAlias = [string]$config.interface_alias
$port = 0
if (-not [int]::TryParse([string]$config.port, [ref]$port) -or $port -lt 1024 -or $port -gt 65535) {
    throw 'The installed server port is invalid.'
}
if ([string]::IsNullOrWhiteSpace($interfaceAlias) -or $interfaceAlias -match '[*?]') {
    throw 'The installed server interface alias is invalid.'
}
if ($serverName.Length -gt 253 -or $serverName -notmatch '\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\z') {
    throw 'ServerName must be a DNS name with at least two labels.'
}
$parsedAddress = [Net.IPAddress]::None
if ([Net.IPAddress]::TryParse($serverName, [ref]$parsedAddress)) {
    throw 'ServerName must be a DNS name, not an IP address.'
}

$answers = @(Resolve-DnsName -Name $serverName -Type A -DnsOnly -NoHostsFile -ErrorAction Stop |
    Where-Object { $_.Type -eq 'A' } |
    Select-Object -ExpandProperty IPAddress -Unique)
if ($answers.Count -ne 1) {
    throw 'ServerName must resolve to exactly one IPv4 address.'
}
$serverIp = $answers[0]
$ip = [Net.IPAddress]::None
if (-not [Net.IPAddress]::TryParse($serverIp, [ref]$ip) -or
    $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
    throw 'ServerName did not resolve to a valid IPv4 address.'
}
$octets = $ip.GetAddressBytes()
$privateIp = ($octets[0] -eq 10) -or
    ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) -or
    ($octets[0] -eq 192 -and $octets[1] -eq 168)
if (-not $privateIp) { throw 'ServerName must resolve to a private LAN IPv4 address.' }

$localAddresses = @(Get-NetIPAddress -IPAddress $serverIp -AddressFamily IPv4 -ErrorAction Stop)
if ($localAddresses.Count -ne 1) {
    throw 'ServerName must resolve to exactly one address assigned to this machine.'
}
if ($localAddresses[0].InterfaceAlias -ine $interfaceAlias) {
    throw 'The resolved server interface differs from the installed interface.'
}
$profile = Get-NetConnectionProfile -InterfaceIndex $localAddresses[0].InterfaceIndex -ErrorAction Stop
if ($profile.NetworkCategory -ne 'Private') {
    throw 'The resolved server interface must use the Private network profile.'
}

if (-not (Test-Path -LiteralPath $serverPython -PathType Leaf)) {
    throw 'The installed RAVEN-X server Python is missing.'
}
if ([string]::IsNullOrWhiteSpace($env:RAVENX_LOCAL_AI_ENABLED)) {
    $env:RAVENX_LOCAL_AI_ENABLED = 'false'
}
Write-Host "Starting RAVEN-X for $serverName at $serverIp`:$port on $interfaceAlias."
Push-Location $installRoot
try {
    & $serverPython -E -s -m backend.cli serve --data-dir $dataRoot --host $serverIp --port $port
    if ($LASTEXITCODE -ne 0) { throw "RAVEN-X server exited with code $LASTEXITCODE." }
} finally {
    Pop-Location
}
