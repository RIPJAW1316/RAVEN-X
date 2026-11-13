#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
WS-03 production-mode candidate. Run only from an independently authenticated
release extracted into a protected sibling of the installed Server directory.
The operator must quiesce all server writers before -Execute. This script is
not invoked by the build or by tests against the live Omen.
#>
param(
    [Parameter(Mandatory=$true)][string]$PackagePath,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedPackageSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedCaSha256,
    [Parameter(Mandatory=$true)][string]$LanAddress,
    [Parameter(Mandatory=$true)][string]$InterfaceAlias,
    [Parameter(Mandatory=$true)][string]$BasePython,
    [Parameter(Mandatory=$true)][string]$BackupParent,
    [string]$RehearsalRoot,
    [ValidateRange(20000,65535)][int]$RehearsalPort = 28443,
    [switch]$Execute
)
$ErrorActionPreference = 'Stop'
$isRehearsal = -not [string]::IsNullOrWhiteSpace($RehearsalRoot)
if ($isRehearsal) {
    $RehearsalRoot = [IO.Path]::GetFullPath($RehearsalRoot).TrimEnd('\')
    $allowedParent = Join-Path $env:ProgramData 'RAVEN-X'
    if ((Split-Path -Parent $RehearsalRoot) -ine $allowedParent -or
        (Split-Path -Leaf $RehearsalRoot) -notmatch '^ws03b-disposable-[0-9a-f]{32}$') {
        throw 'Rehearsal root must be a fresh named child of the protected RAVEN-X ProgramData parent.'
    }
    if ([IO.Path]::GetFullPath($BackupParent).TrimEnd('\') -ine $RehearsalRoot) {
        throw 'Rehearsal backups must remain inside the disposable root.'
    }
    $installParent = Join-Path $RehearsalRoot 'RAVEN-X'
    $dataRoot = Join-Path $RehearsalRoot 'server'
    $port = $RehearsalPort
} else {
    $installParent = Join-Path $env:ProgramFiles 'RAVEN-X'
    $dataRoot = Join-Path $env:ProgramData 'RAVEN-X\server'
    $port = 8443
}
$installRoot = Join-Path $installParent 'Server'
$stageRoot = Join-Path $installParent 'Server.ws03.stage'
$previousRoot = Join-Path $installParent 'Server.ws03.previous'
$certificate = Join-Path $dataRoot 'tls\server.pem'
$ca = Join-Path $dataRoot 'tls\ca.pem'
$key = Join-Path $dataRoot 'tls\server-key.pem'
$journal = Join-Path $dataRoot 'ws03-upgrade-state.json'

function Assert-NoReparse([string]$Path) {
    $current = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    while ($null -ne $current) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'A release or installed path crosses a reparse point.'
        }
        $current = $current.Parent
    }
}

function Assert-AdminSystemCustody([string]$Path) {
    Assert-NoReparse $Path
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @('S-1-5-18','S-1-5-32-544')) {
        throw 'A release or installed path has an untrusted owner.'
    }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            throw 'A release or installed path grants unexpected access.'
        }
    }
}

foreach ($path in @($installParent,$installRoot,$stageRoot,$dataRoot,$ca,$certificate,$key,$PackagePath,$BackupParent,$BasePython)) {
    if (-not (Test-Path -LiteralPath $path)) { throw 'Upgrade prerequisite is missing.' }
    Assert-NoReparse $path
}
if (Test-Path -LiteralPath $previousRoot) { throw 'Previous server tree exists; recovery review required.' }
if (Test-Path -LiteralPath $journal) { throw 'Upgrade journal exists; repeated upgrade is refused.' }
if ($stageRoot -ne (Split-Path -Parent $PSScriptRoot)) { throw 'Run this script from the protected WS-03 stage.' }
foreach ($path in @($installParent,$installRoot,$stageRoot,$dataRoot,$PackagePath,$BackupParent)) {
    Assert-AdminSystemCustody $path
}
if ($isRehearsal) { Assert-AdminSystemCustody $RehearsalRoot }
if ((Get-FileHash -LiteralPath $PackagePath -Algorithm SHA256).Hash -ine $ExpectedPackageSha256) {
    throw 'Independently supplied package digest differs.'
}
if ((Get-FileHash -LiteralPath $ca -Algorithm SHA256).Hash -ine $ExpectedCaSha256) {
    throw 'Existing CA identity differs from operator-approved fingerprint.'
}
$signature = Get-AuthenticodeSignature -LiteralPath $BasePython
if ($signature.Status -ne 'Valid') { throw 'External Python runtime signature is not valid.' }
$parsed = [Net.IPAddress]::None
if (-not [Net.IPAddress]::TryParse($LanAddress,[ref]$parsed) -or
    $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
    $parsed.ToString() -cne $LanAddress) { throw 'LAN address must be a canonical IPv4 literal.' }
$octets = $parsed.GetAddressBytes()
if (-not (($octets[0] -eq 10) -or ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) -or
           ($octets[0] -eq 192 -and $octets[1] -eq 168))) { throw 'LAN address must be RFC1918.' }
$assigned = @(Get-NetIPAddress -IPAddress $LanAddress -AddressFamily IPv4 -ErrorAction Stop)
if ($assigned.Count -ne 1 -or $assigned[0].InterfaceAlias -ine $InterfaceAlias) {
    throw 'LAN address is not assigned to the approved interface.'
}
if ((Get-NetConnectionProfile -InterfaceIndex $assigned[0].InterfaceIndex).NetworkCategory -ne 'Private') {
    throw 'LAN interface is not Private.'
}
if (-not $isRehearsal) {
    $rule = @(Get-NetFirewallRule -DisplayName 'RAVEN-X October 15 Control Plane' -ErrorAction Stop)
    if ($rule.Count -ne 1 -or $rule[0].Enabled.ToString() -ne 'True' -or
        $rule[0].Direction.ToString() -ne 'Inbound' -or $rule[0].Action.ToString() -ne 'Allow' -or
        $rule[0].Profile.ToString() -ne 'Private') { throw 'Approved Private inbound firewall rule is missing.' }
    $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule[0]
    $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule[0]
    if ($portFilter.Protocol.ToString() -ne 'TCP' -or $portFilter.LocalPort.ToString() -ne '8443' -or
        @($addressFilter.RemoteAddress).Count -ne 1 -or @($addressFilter.RemoteAddress)[0] -ne 'LocalSubnet') {
        throw 'Firewall protocol, port or remote scope differs from the pilot boundary.'
    }
}
if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) {
    throw 'Selected TCP port is occupied; server is not quiescent.'
}
$running = @(Get-CimInstance Win32_Process | Where-Object {
    $_.ExecutablePath -and $_.ExecutablePath.StartsWith($installRoot + '\',[StringComparison]::OrdinalIgnoreCase)
})
if ($running.Count -ne 0) { throw 'Installed server runtime is still running.' }
Push-Location $stageRoot
try {
    & $BasePython -B -E -s scripts/build-server-release.py verify-extracted $PackagePath `
        --root $stageRoot --expected-sha256 $ExpectedPackageSha256
    if ($LASTEXITCODE -ne 0) { throw 'Extracted release differs from authenticated ZIP.' }
    & $BasePython -B -E -s scripts/ws03-verify-san.py --certificate $certificate `
        --host '127.0.0.1' --host $LanAddress
    if ($LASTEXITCODE -ne 0) { throw 'Existing server certificate SAN does not cover both listener addresses.' }
} finally { Pop-Location }
if (-not $Execute) {
    Write-Output 'WS-03 preflight passed. No backup, migration, key creation or code switch was performed.'
    return
}

$venv = Join-Path $stageRoot 'venv\Scripts\python.exe'
& $BasePython -B -E -s -m venv (Join-Path $stageRoot 'venv')
if ($LASTEXITCODE -ne 0) { throw 'Staged Python environment creation failed.' }
& $venv -B -E -s -m pip install --no-index --find-links (Join-Path $stageRoot 'wheels') `
    --require-hashes -r (Join-Path $stageRoot 'requirements-server-lock.txt')
if ($LASTEXITCODE -ne 0) { throw 'Offline dependency installation failed.' }

$backup = Join-Path $BackupParent ('ws03-backup-' + [guid]::NewGuid().ToString('N'))
Push-Location $stageRoot
try {
    & $venv -B -E -s -m backend.application.ops.server_backup create --data-root $dataRoot `
        --install-root $installRoot --destination $backup
    if ($LASTEXITCODE -ne 0) { throw 'Mandatory encrypted backup failed; upgrade stopped.' }
    & $venv -B -E -s -m backend.application.ops.server_backup verify --backup-root $backup
    if ($LASTEXITCODE -ne 0) { throw 'Backup verification failed; upgrade stopped.' }
    & $venv -B -E -s -m backend.application.ops.server_upgrade mark --data-root $dataRoot `
        --phase backup_verified --package-sha256 $ExpectedPackageSha256 --backup-path $backup
    if ($LASTEXITCODE -ne 0) { throw 'Upgrade journal could not record verified backup.' }

    & $venv -B -E -s -m backend.cli migrate --data-dir $dataRoot
    if ($LASTEXITCODE -ne 0) { throw 'Additive database migration failed; preserve backup and journal.' }
    & $venv -B -E -s -m backend.application.ops.server_upgrade mark --data-root $dataRoot `
        --phase migrated --package-sha256 $ExpectedPackageSha256 --backup-path $backup
    if ($LASTEXITCODE -ne 0) { throw 'Migration journal update failed; preserve state.' }

    & $venv -B -E -s -m backend.application.ops.server_upgrade key-check `
        --database (Join-Path $dataRoot 'raven_x.db')
    if ($LASTEXITCODE -ne 0) { throw 'Verifier-key binding failed; preserve state.' }
    & $venv -B -E -s -m backend.application.ops.server_upgrade mark --data-root $dataRoot `
        --phase key_bound --package-sha256 $ExpectedPackageSha256 --backup-path $backup
    if ($LASTEXITCODE -ne 0) { throw 'Verifier-key journal update failed; preserve state.' }
} finally { Pop-Location }

# Every staged Python subprocess has exited before the directory rename.
Push-Location $installParent
try {
    Rename-Item -LiteralPath $installRoot -NewName 'Server.ws03.previous' -ErrorAction Stop
    Rename-Item -LiteralPath $stageRoot -NewName 'Server' -ErrorAction Stop
} finally { Pop-Location }
$newPython = Join-Path $installRoot 'venv\Scripts\python.exe'
Push-Location $installRoot
try {
    & $newPython -B -E -s -m backend.application.ops.server_upgrade mark --data-root $dataRoot `
        --phase code_switched --package-sha256 $ExpectedPackageSha256 --backup-path $backup
    if ($LASTEXITCODE -ne 0) { throw 'Code switch journal update failed; preserve all state.' }
    $arguments = '-B -E -s -m backend.cli serve --data-dir "' + $dataRoot + '" --listen-host 127.0.0.1 --listen-host ' + $LanAddress + ' --port ' + $port
    $server = Start-Process -FilePath $newPython -ArgumentList $arguments -WorkingDirectory $installRoot `
        -WindowStyle Hidden -PassThru
    & $newPython -B -E -s -m backend.application.ops.server_upgrade ready --lan-address $LanAddress `
        --port $port --ca $ca
    if ($LASTEXITCODE -ne 0 -or $server.HasExited) {
        if (-not $server.HasExited) { Stop-Process -Id $server.Id -ErrorAction SilentlyContinue }
        throw 'Upgraded TLS readiness failed; no database rollback was attempted.'
    }
    & $newPython -B -E -s -m backend.application.ops.server_upgrade mark --data-root $dataRoot `
        --phase ready --package-sha256 $ExpectedPackageSha256 --backup-path $backup
    if ($LASTEXITCODE -ne 0) { throw 'Ready journal update failed; preserve state.' }
    Write-Output 'WS-03 server is TLS-ready on loopback and the approved LAN address. Agent continuity remains a separate gate.'
} finally { Pop-Location }
