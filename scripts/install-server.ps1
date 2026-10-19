#Requires -RunAsAdministrator
<#
.SYNOPSIS
Prepare a new single-host RAVEN-X control plane on the HP Omen LAN machine.

.DESCRIPTION
This first-install script preserves any existing install or ProgramData server
state by refusing to overwrite it. It copies code into an Administrators/SYSTEM
only Program Files directory, installs pinned dependencies, builds the portal,
creates TLS material, and prompts for the first administrator password.
No network firewall rule is added unless -OpenPrivateFirewall is supplied.
#>
param(
    [Parameter(Mandatory = $true)][string]$ServerHost,
    [string]$ServerName,
    [Parameter(Mandatory = $true)][string]$AdminEmail,
    [Parameter(Mandatory = $true)][string]$Organization,
    [ValidateRange(1024, 65535)][int]$Port = 8443,
    [switch]$OpenPrivateFirewall,
    [switch]$Start
)

$ErrorActionPreference = 'Stop'
if (-not $env:ProgramFiles -or -not $env:ProgramData -or -not $env:WINDIR) {
    throw 'ProgramFiles, ProgramData, and WINDIR are required.'
}
if ($ServerHost -match '["\\\x00-\x1F\x7F\s]' -or $AdminEmail -match '[\x00-\x1F\x7F]' -or
    $Organization -match '[\x00-\x1F\x7F]') {
    throw 'An argument contains unsafe characters.'
}
$ip = [Net.IPAddress]::None
if (-not [Net.IPAddress]::TryParse($ServerHost, [ref]$ip) -or
    $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
    throw 'ServerHost must be an IPv4 address assigned to the HP Omen LAN adapter.'
}
$octets = $ip.GetAddressBytes()
$privateIp = ($octets[0] -eq 10) -or
    ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) -or
    ($octets[0] -eq 192 -and $octets[1] -eq 168)
if (-not $privateIp) { throw 'ServerHost must be an RFC1918 private LAN IPv4 address.' }
$localAddresses = @(Get-NetIPAddress -IPAddress $ServerHost -AddressFamily IPv4 -ErrorAction Stop)
if ($localAddresses.Count -ne 1) { throw 'ServerHost must identify exactly one local interface.' }
$profile = Get-NetConnectionProfile -InterfaceIndex $localAddresses[0].InterfaceIndex -ErrorAction Stop
if ($profile.NetworkCategory -ne 'Private') { throw 'The server interface must use the Private network profile.' }
$interfaceAlias = [string]$localAddresses[0].InterfaceAlias
if ([string]::IsNullOrWhiteSpace($interfaceAlias) -or $interfaceAlias -match '[*?]') {
    throw 'The server interface alias is empty or ambiguous.'
}

function Assert-ServerName([string]$Name) {
    if ([string]::IsNullOrWhiteSpace($Name) -or $Name.Length -gt 253 -or
        $Name -cnotmatch '\A(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\z') {
        throw 'ServerName must be a fully qualified ASCII DNS name without a trailing dot.'
    }
    $parsedAddress = [Net.IPAddress]::None
    if ([Net.IPAddress]::TryParse($Name, [ref]$parsedAddress)) {
        throw 'ServerName must be a DNS name, not an IP address.'
    }
}

function Assert-ServerNameResolution([string]$Name, [Net.IPAddress]$ExpectedAddress) {
    $records = @(Resolve-DnsName -Name $Name -Type A -DnsOnly -NoHostsFile -ErrorAction Stop)
    $addresses = @($records | Where-Object { $_.Type -eq 'A' -and $_.IPAddress } |
        ForEach-Object {
            $resolved = [Net.IPAddress]::None
            if ([Net.IPAddress]::TryParse([string]$_.IPAddress, [ref]$resolved) -and
                $resolved.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
                $resolved.ToString()
            }
        } | Sort-Object -Unique)
    if ($addresses.Count -ne 1 -or $addresses[0] -ne $ExpectedAddress.ToString()) {
        throw 'ServerName must resolve to exactly the selected ServerHost IPv4 address.'
    }
}

function Write-ServerAddressConfig([string]$Path, [string]$Name, [int]$ListenPort,
                                   [string]$InterfaceAlias) {
    $payload = [ordered]@{
        server_name = $Name
        port = $ListenPort
        interface_alias = $InterfaceAlias
    } | ConvertTo-Json -Compress
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($payload)
    $file = [IO.File]::Open($Path, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $file.Write($bytes, 0, $bytes.Length)
        $file.Flush($true)
    } finally {
        $file.Dispose()
    }
}

if ($PSBoundParameters.ContainsKey('ServerName')) {
    Assert-ServerName $ServerName
    Assert-ServerNameResolution $ServerName $ip
}

$sourceRoot = Split-Path -Parent $PSScriptRoot
$startServerSource = Join-Path $PSScriptRoot 'start-server.ps1'
if ($PSBoundParameters.ContainsKey('ServerName') -and
    -not (Test-Path -LiteralPath $startServerSource -PathType Leaf)) {
    throw 'The protected server startup script is missing from the installation source.'
}
$installParent = Join-Path $env:ProgramFiles 'RAVEN-X'
$installRoot = Join-Path $installParent 'Server'
$dataRoot = Join-Path $env:ProgramData 'RAVEN-X\server'
$serverPython = Join-Path $installRoot 'venv\Scripts\python.exe'
$caPath = Join-Path $dataRoot 'tls\ca.pem'
if (Test-Path -LiteralPath $installParent) {
    throw 'Program Files RAVEN-X already exists. Inspect the existing installation; no files were replaced.'
}
if (Test-Path -LiteralPath (Join-Path $env:ProgramData 'RAVEN-X')) {
    throw 'ProgramData RAVEN-X already exists. Back up and inspect its database/TLS material before setup.'
}

function Assert-NotReparseTree([string]$Path) {
    $current = Get-Item -LiteralPath $Path -Force
    while ($null -ne $current) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Path contains a reparse point: $($current.FullName)"
        }
        $parentPath = Split-Path -Parent $current.FullName
        if (-not $parentPath -or $parentPath -eq $current.FullName) { break }
        $current = Get-Item -LiteralPath $parentPath -Force
    }
}

function Assert-NoUntrustedWrite([string]$Path) {
    $trusted = @('S-1-3-0', 'S-1-5-18', 'S-1-5-32-544',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $writeMask = [int][Security.AccessControl.FileSystemRights]::WriteData -bor `
        [int][Security.AccessControl.FileSystemRights]::AppendData -bor `
        [int][Security.AccessControl.FileSystemRights]::WriteAttributes -bor `
        [int][Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor `
        [int][Security.AccessControl.FileSystemRights]::Delete -bor `
        [int][Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor `
        [int][Security.AccessControl.FileSystemRights]::ChangePermissions -bor `
        [int][Security.AccessControl.FileSystemRights]::TakeOwnership -bor 0x10000000 -bor 0x40000000
    $acl = Get-Acl -LiteralPath $Path
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and `
            $rule.IdentityReference.Value -notin $trusted -and `
            (([int]$rule.FileSystemRights -band $writeMask) -ne 0)) {
            throw "Path is writable by an untrusted principal: $Path"
        }
    }
}

function Assert-ProtectedTree([string]$Path, [string]$StopAt) {
    $current = Get-Item -LiteralPath $Path -Force
    $stop = (Get-Item -LiteralPath $StopAt -Force).FullName.TrimEnd('\')
    while ($null -ne $current) {
        Assert-NoUntrustedWrite $current.FullName
        if ($current.FullName.TrimEnd('\') -ieq $stop) { return }
        $parentPath = Split-Path -Parent $current.FullName
        if (-not $parentPath -or $parentPath -eq $current.FullName) { break }
        $current = Get-Item -LiteralPath $parentPath -Force
    }
    throw 'Executable is not beneath Program Files.'
}

function Protect-CodeDirectory([string]$Path) {
    if (Test-Path -LiteralPath $Path) { throw "Install directory exists: $Path" }
    New-Item -ItemType Directory -Path $Path | Out-Null
    Assert-NotReparseTree $Path
    & icacls.exe $Path '/inheritance:r' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not remove inherited install ACL.' }
    & icacls.exe $Path '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not grant SYSTEM and Administrators access.' }
    & icacls.exe $Path '/setowner' '*S-1-5-32-544' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not set install owner.' }
    $acl = Get-Acl -LiteralPath $Path
    $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $rules = @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))
    if (-not $acl.AreAccessRulesProtected -or $ownerSid -notin @('S-1-5-18', 'S-1-5-32-544') -or
        $rules.Count -ne 2) { throw 'Install ACL could not be verified.' }
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $rule.IdentityReference.Value -notin @('S-1-5-18', 'S-1-5-32-544') -or
            (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne
             [Security.AccessControl.FileSystemRights]::FullControl)) {
            throw 'Install directory grants unexpected access.'
        }
    }
    Assert-NoUntrustedWrite $Path
}

Assert-NotReparseTree $env:ProgramFiles
Assert-NoUntrustedWrite $env:ProgramFiles
$launcher = Join-Path $env:WINDIR 'py.exe'
if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) {
    throw 'A system-wide Python 3.13 launcher at WINDIR\py.exe is required.'
}
Assert-NotReparseTree $launcher
Assert-NoUntrustedWrite $launcher
# Listing registered runtimes does not execute a selected interpreter.
# Never invoke py -3.13 before validating the chosen executable.
# A per-user Python 3.13 or npm.cmd does not disqualify a protected system pair.
. (Join-Path $PSScriptRoot 'runtime-selection.ps1')
$basePython = Select-RavenXPython313 -Launcher $launcher -ProgramFiles $env:ProgramFiles -ProtectedTreeCommand 'Assert-ProtectedTree'
$nodeCommands = @(Get-Command node.exe -CommandType Application -ErrorAction SilentlyContinue)
if ($nodeCommands.Count -eq 0) { throw 'Node.js was not found.' }
$toolchain = Select-RavenXNodeToolchain -NodeExecutables @($nodeCommands | ForEach-Object { $_.Source }) `
    -ProgramFiles $env:ProgramFiles -ProtectedTreeCommand 'Assert-ProtectedTree'
$node = $toolchain.Node
$npm = $toolchain.Npm

Protect-CodeDirectory $installParent
Protect-CodeDirectory $installRoot
Copy-Item -LiteralPath (Join-Path $sourceRoot 'backend') -Destination (Join-Path $installRoot 'backend') -Recurse
Copy-Item -LiteralPath (Join-Path $sourceRoot 'config') -Destination (Join-Path $installRoot 'config') -Recurse
Copy-Item -LiteralPath (Join-Path $sourceRoot 'requirements-server.txt') -Destination $installRoot
if ($PSBoundParameters.ContainsKey('ServerName')) {
    Copy-Item -LiteralPath $startServerSource -Destination (Join-Path $installRoot 'start-server.ps1')
    $serverAddressConfig = Join-Path $installRoot 'server-address.json'
    Write-ServerAddressConfig $serverAddressConfig $ServerName $Port $interfaceAlias
    Assert-NotReparseTree $serverAddressConfig
    Assert-ProtectedTree $serverAddressConfig $env:ProgramFiles
}
$frontendRoot = Join-Path $installRoot 'frontend'
New-Item -ItemType Directory -Path $frontendRoot | Out-Null
foreach ($name in @('package.json', 'package-lock.json', 'index.html', 'tsconfig.json', 'vite.config.ts')) {
    Copy-Item -LiteralPath (Join-Path (Join-Path $sourceRoot 'frontend') $name) -Destination $frontendRoot
}
Copy-Item -LiteralPath (Join-Path $sourceRoot 'frontend\src') -Destination (Join-Path $frontendRoot 'src') -Recurse

& $basePython -I -m venv (Join-Path $installRoot 'venv')
if ($LASTEXITCODE -ne 0) { throw 'Server virtual environment creation failed.' }
& $serverPython -E -s -m pip install --disable-pip-version-check -r (Join-Path $installRoot 'requirements-server.txt')
if ($LASTEXITCODE -ne 0) { throw 'Pinned Python dependency installation failed.' }
Push-Location $frontendRoot
try {
    & $npm ci
    if ($LASTEXITCODE -ne 0) { throw 'npm ci failed.' }
    & $npm run build
    if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
} finally {
    Pop-Location
}
if (-not (Test-Path -LiteralPath (Join-Path $frontendRoot 'dist\index.html') -PathType Leaf)) {
    throw 'Frontend build did not produce dist\index.html.'
}

Push-Location $installRoot
try {
    $tlsHosts = @('--host', $ServerHost)
    if ($PSBoundParameters.ContainsKey('ServerName')) { $tlsHosts += @('--host', $ServerName) }
    & $serverPython -E -s -m backend.cli tls-init --data-dir $dataRoot @tlsHosts
    if ($LASTEXITCODE -ne 0) { throw 'TLS setup failed. Existing material was preserved.' }
    & $serverPython -E -s -m backend.cli bootstrap --data-dir $dataRoot --email $AdminEmail `
        --organization $Organization
    if ($LASTEXITCODE -ne 0) { throw 'Administrator bootstrap failed. Inspect state before retrying.' }
} finally {
    Pop-Location
}

$fingerprint = (Get-FileHash -Algorithm SHA256 -LiteralPath $caPath).Hash
Write-Host "Public CA: $caPath"
Write-Host "SHA-256: $fingerprint"
if ($OpenPrivateFirewall) {
    $ruleName = 'RAVEN-X October 15 Control Plane'
    if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) {
        throw 'A RAVEN-X firewall rule already exists; inspect it before adding another.'
    }
    $firewall = @{
        DisplayName = $ruleName; Direction = 'Inbound'; Action = 'Allow'; Enabled = 'True'
        Profile = 'Private'; Protocol = 'TCP'; LocalPort = $Port; RemoteAddress = 'LocalSubnet'
    }
    if ($PSBoundParameters.ContainsKey('ServerName')) {
        $firewall.InterfaceAlias = $interfaceAlias
    } else {
        $firewall.LocalAddress = $ServerHost
    }
    New-NetFirewallRule @firewall | Out-Null
    Write-Host 'Private-profile LocalSubnet firewall rule installed.'
} else {
    Write-Host 'No firewall rule installed. Use -OpenPrivateFirewall after confirming the LAN interface.'
}

Write-Host "Setup complete. Run elevated from $installRoot with:"
if ($PSBoundParameters.ContainsKey('ServerName')) {
    $startServer = Join-Path $installRoot 'start-server.ps1'
    Write-Host "  & '$startServer'"
} else {
    Write-Host "  & '$serverPython' -E -s -m backend.cli serve --data-dir '$dataRoot' --host $ServerHost --port $Port"
}
if ($Start) {
    Push-Location $installRoot
    try {
        if ($null -eq [Environment]::GetEnvironmentVariable('RAVENX_LOCAL_AI_ENABLED', 'Process')) {
            $env:RAVENX_LOCAL_AI_ENABLED = 'false'
        }
        if ($PSBoundParameters.ContainsKey('ServerName')) {
            & $startServer
        } else {
            & $serverPython -E -s -m backend.cli serve --data-dir $dataRoot --host $ServerHost --port $Port
        }
    } finally {
        Pop-Location
    }
}
