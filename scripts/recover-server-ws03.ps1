#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
Forward-only recovery after a WS-03 interruption. Never restores an older DB,
recreates a missing verifier key, or starts the pre-WS-01 binary automatically.
#>
param(
    [Parameter(Mandatory=$true)][string]$PackagePath,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedPackageSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedCaSha256,
    [Parameter(Mandatory=$true)][string]$LanAddress,
    [Parameter(Mandatory=$true)][string]$InterfaceAlias,
    [string]$RehearsalRoot,
    [ValidateRange(20000,65535)][int]$RehearsalPort = 28443
)
$ErrorActionPreference = 'Stop'
$isRehearsal = -not [string]::IsNullOrWhiteSpace($RehearsalRoot)
if ($isRehearsal) {
    $RehearsalRoot = [IO.Path]::GetFullPath($RehearsalRoot).TrimEnd('\')
    $allowedParent = Join-Path $env:ProgramData 'RAVEN-X'
    if ((Split-Path -Parent $RehearsalRoot) -ine $allowedParent -or
        (Split-Path -Leaf $RehearsalRoot) -notmatch '^ws03b-disposable-[0-9a-f]{32}$') {
        throw 'Recovery rehearsal root is outside the protected disposable parent.'
    }
    $parent = Join-Path $RehearsalRoot 'RAVEN-X'
    $data = Join-Path $RehearsalRoot 'server'
    $port = $RehearsalPort
} else {
    $parent = Join-Path $env:ProgramFiles 'RAVEN-X'
    $data = Join-Path $env:ProgramData 'RAVEN-X\server'
    $port = 8443
}
$installed = Join-Path $parent 'Server'
$stage = Join-Path $parent 'Server.ws03.stage'
$previous = Join-Path $parent 'Server.ws03.previous'
$journalPath = Join-Path $data 'ws03-upgrade-state.json'
$ca = Join-Path $data 'tls\ca.pem'
function Assert-ProtectedPath([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    while ($null -ne $item) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Recovery path crosses a reparse point.'
        }
        $item = $item.Parent
    }
    $acl = Get-Acl -LiteralPath $Path
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')) {
        throw 'Recovery path has an untrusted owner.'
    }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            throw 'Recovery path grants unexpected access.'
        }
    }
}
if (-not (Test-Path -LiteralPath $journalPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $ca -PathType Leaf)) { throw 'Recovery journal or CA is missing.' }
foreach ($path in @($parent,$data,$journalPath,$ca,$PackagePath)) { Assert-ProtectedPath $path }
if ($isRehearsal) { Assert-ProtectedPath $RehearsalRoot }
$journal = Get-Content -LiteralPath $journalPath -Raw | ConvertFrom-Json
if ($journal.format -ne 1 -or $journal.package_sha256 -ine $ExpectedPackageSha256 -or
    $journal.phase -notin @('backup_verified','migrated','key_bound','code_switched')) {
    throw 'Upgrade journal does not authorize forward recovery.'
}
if ((Get-FileHash -LiteralPath $ca -Algorithm SHA256).Hash -ine $ExpectedCaSha256) {
    throw 'CA identity changed; recovery refused.'
}
if (-not (Test-Path -LiteralPath $journal.backup_path -PathType Container)) {
    throw 'Mandatory backup is missing.'
}
Assert-ProtectedPath $journal.backup_path
if (-not (Test-Path -LiteralPath $PackagePath -PathType Leaf) -or
    (Get-FileHash -LiteralPath $PackagePath -Algorithm SHA256).Hash -ine $ExpectedPackageSha256) {
    throw 'Authenticated release package is missing or changed.'
}
$candidate = if (Test-Path -LiteralPath $stage -PathType Container) {
    $stage
} elseif (Test-Path -LiteralPath (Join-Path $installed 'VERSION') -PathType Leaf) {
    $installed
} else { throw 'No WS-03 code candidate is present.' }
Assert-ProtectedPath $candidate
if (Test-Path -LiteralPath $previous) { Assert-ProtectedPath $previous }
if (Test-Path -LiteralPath $installed) { Assert-ProtectedPath $installed }
$python = Join-Path $candidate 'venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw 'Staged runtime is missing.' }
Push-Location $candidate
try {
    & $python -B -E -s scripts/build-server-release.py verify-extracted $PackagePath `
        --root $candidate --expected-sha256 $ExpectedPackageSha256
    if ($LASTEXITCODE -ne 0) { throw 'Candidate code differs from the authenticated release.' }
    & $python -B -E -s -m backend.application.ops.server_backup verify --backup-root $journal.backup_path
    if ($LASTEXITCODE -ne 0) { throw 'Backup verification failed; recovery refused.' }
    & $python -B -E -s -m backend.application.ops.listeners --certificate (Join-Path $data 'tls\server.pem') `
        --host 127.0.0.1 --host $LanAddress
    if ($LASTEXITCODE -ne 0) { throw 'TLS SAN does not match recovery listeners.' }
    if ($journal.phase -eq 'backup_verified') {
        if ($candidate -ne $stage) { throw 'Migration recovery requires the protected stage.' }
        & $python -B -E -s -m backend.cli migrate --data-dir $data
        if ($LASTEXITCODE -ne 0) { throw 'Migration recovery failed.' }
        & $python -B -E -s -m backend.application.ops.server_upgrade mark --data-root $data `
            --phase migrated --package-sha256 $ExpectedPackageSha256 --backup-path $journal.backup_path
        if ($LASTEXITCODE -ne 0) { throw 'Migration recovery journal update failed.' }
        $journal.phase = 'migrated'
    }
    if ($journal.phase -eq 'migrated') {
        if ($candidate -ne $stage) { throw 'Verifier-key recovery requires the protected stage.' }
        & $python -B -E -s -m backend.application.ops.server_upgrade key-check `
            --database (Join-Path $data 'raven_x.db')
        if ($LASTEXITCODE -ne 0) { throw 'Verifier-key recovery failed.' }
        & $python -B -E -s -m backend.application.ops.server_upgrade mark --data-root $data `
            --phase key_bound --package-sha256 $ExpectedPackageSha256 --backup-path $journal.backup_path
        if ($LASTEXITCODE -ne 0) { throw 'Verifier-key recovery journal update failed.' }
        $journal.phase = 'key_bound'
    }
} finally { Pop-Location }
$assigned = @(Get-NetIPAddress -IPAddress $LanAddress -AddressFamily IPv4 -ErrorAction Stop)
if ($assigned.Count -ne 1 -or $assigned[0].InterfaceAlias -ine $InterfaceAlias -or
    (Get-NetConnectionProfile -InterfaceIndex $assigned[0].InterfaceIndex).NetworkCategory -ne 'Private') {
    throw 'Recovery LAN address or profile is not approved.'
}
if (-not $isRehearsal) {
    $rule = @(Get-NetFirewallRule -DisplayName 'RAVEN-X October 15 Control Plane' -ErrorAction Stop)
    if ($rule.Count -ne 1 -or $rule[0].Enabled.ToString() -ne 'True' -or
        $rule[0].Direction.ToString() -ne 'Inbound' -or $rule[0].Action.ToString() -ne 'Allow' -or
        $rule[0].Profile.ToString() -ne 'Private') { throw 'Approved Private firewall rule is missing.' }
    $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule[0]
    $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule[0]
    if ($portFilter.Protocol.ToString() -ne 'TCP' -or $portFilter.LocalPort.ToString() -ne '8443' -or
        @($addressFilter.RemoteAddress).Count -ne 1 -or @($addressFilter.RemoteAddress)[0] -ne 'LocalSubnet') {
        throw 'Firewall protocol, port or remote scope differs from the pilot boundary.'
    }
}
if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) {
    throw 'Selected TCP port is already occupied.'
}
if ($candidate -eq $stage) {
    Push-Location $parent
    try {
        if (Test-Path -LiteralPath $installed) {
            if (Test-Path -LiteralPath $previous) { throw 'Old and previous server trees coexist; manual review required.' }
            Rename-Item -LiteralPath $installed -NewName 'Server.ws03.previous'
        } elseif (-not (Test-Path -LiteralPath $previous)) {
            throw 'Old server tree is missing; manual review required.'
        }
        Rename-Item -LiteralPath $stage -NewName 'Server'
    } finally { Pop-Location }
}
$python = Join-Path $installed 'venv\Scripts\python.exe'
Push-Location $installed
try {
    if ($journal.phase -eq 'key_bound') {
        & $python -B -E -s -m backend.application.ops.server_upgrade mark --data-root $data `
            --phase code_switched --package-sha256 $ExpectedPackageSha256 --backup-path $journal.backup_path
        if ($LASTEXITCODE -ne 0) { throw 'Recovery journal update failed.' }
    }
    $arguments = '-B -E -s -m backend.cli serve --data-dir "' + $data + '" --listen-host 127.0.0.1 --listen-host ' + $LanAddress + ' --port ' + $port
    $server = Start-Process -FilePath $python -ArgumentList $arguments -WorkingDirectory $installed `
        -WindowStyle Hidden -PassThru
    & $python -B -E -s -m backend.application.ops.server_upgrade ready --lan-address $LanAddress `
        --port $port --ca $ca
    if ($LASTEXITCODE -ne 0 -or $server.HasExited) {
        if (-not $server.HasExited) { Stop-Process -Id $server.Id -ErrorAction SilentlyContinue }
        throw 'Recovered code did not become TLS-ready; no database rollback occurred.'
    }
    & $python -B -E -s -m backend.application.ops.server_upgrade mark --data-root $data `
        --phase ready --package-sha256 $ExpectedPackageSha256 --backup-path $journal.backup_path
    if ($LASTEXITCODE -ne 0) { throw 'Ready journal update failed.' }
    Write-Output 'WS-03 forward recovery reached TLS readiness.'
} finally { Pop-Location }
