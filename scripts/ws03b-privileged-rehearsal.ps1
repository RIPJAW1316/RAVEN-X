#Requires -Version 5.1
#Requires -RunAsAdministrator
<# Run only from a hash-verified release inside a fresh protected disposable root. #>
param(
    [Parameter(Mandatory=$true)][string]$RehearsalRoot,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedPackageSha256,
    [Parameter(Mandatory=$true)][string]$LanAddress,
    [Parameter(Mandatory=$true)][string]$InterfaceAlias,
    [Parameter(Mandatory=$true)][string]$BasePython,
    [Parameter(Mandatory=$true)][string]$SafeResultPath,
    [ValidateRange(20000,65535)][int]$Port = 28443
)
$ErrorActionPreference = 'Stop'
$RehearsalRoot = [IO.Path]::GetFullPath($RehearsalRoot).TrimEnd('\')
$expectedParent = Join-Path $env:ProgramData 'RAVEN-X'
if ((Split-Path -Parent $RehearsalRoot) -ine $expectedParent -or
    (Split-Path -Leaf $RehearsalRoot) -notmatch '^ws03b-disposable-[0-9a-f]{32}$') {
    throw 'Disposable root is outside protected RAVEN-X ProgramData.'
}
$installParent = Join-Path $RehearsalRoot 'RAVEN-X'
$stage = Join-Path $installParent 'Server.ws03.stage'
$package = Join-Path $installParent 'Server.ws03-package.zip'
if ((Split-Path -Parent $PSScriptRoot) -ine $stage) {
    throw 'Rehearsal script must run from the protected extracted release.'
}
$result = [ordered]@{status='failed'; phase='preflight'; root=$RehearsalRoot; port=$Port;
                    synthetic_only=$true; live_state_touched=$false}
try {
    $acl = Get-Acl -LiteralPath $RehearsalRoot
    if (-not $acl.AreAccessRulesProtected -or
        $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')) {
        throw 'Disposable root ownership or DACL is untrusted.'
    }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            throw 'Disposable root grants unexpected access.'
        }
    }
    if ((Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash -ine $ExpectedPackageSha256) {
        throw 'Protected package digest differs from independent value.'
    }
    if ((Get-AuthenticodeSignature -LiteralPath $BasePython).Status -ne 'Valid') {
        throw 'Protected Python signature is invalid.'
    }
    try {
        & $BasePython -B -E -s (Join-Path $stage 'scripts\build-server-release.py') verify-extracted $package `
            --root $stage --expected-sha256 $ExpectedPackageSha256 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Protected extracted release is invalid.' }
        $result.phase='dependencies'
        $fixturePython = Join-Path $RehearsalRoot 'fixture-venv\Scripts\python.exe'
        & $BasePython -B -E -s -m venv (Join-Path $RehearsalRoot 'fixture-venv')
        if ($LASTEXITCODE -ne 0) { throw 'Fixture environment creation failed.' }
        & $fixturePython -B -E -s -m pip install --no-index --find-links (Join-Path $stage 'wheels') `
            --require-hashes -r (Join-Path $stage 'requirements-server-lock.txt') | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Offline fixture dependencies failed.' }
        $result.phase='fixture'
        & $fixturePython -B -E -s (Join-Path $stage 'scripts\ws03b-synthetic-fixture.py') --root $RehearsalRoot `
            --lan-address $LanAddress | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Synthetic fixture creation failed.' }
        $ca = Join-Path $RehearsalRoot 'server\tls\ca.pem'
        $caSha = (Get-FileHash -LiteralPath $ca -Algorithm SHA256).Hash
        $result.synthetic_ca_sha256=$caSha.ToLower()
        $tampered = Join-Path $installParent 'ws03b-tampered.zip'
        Copy-Item -LiteralPath $package -Destination $tampered -ErrorAction Stop
        [IO.File]::AppendAllText($tampered,'x')
        $result.phase='tamper-check'
        $tamperRejected=$false
        try {
            & (Join-Path $stage 'scripts\upgrade-server-ws03.ps1') -PackagePath $tampered `
                -ExpectedPackageSha256 $ExpectedPackageSha256 -ExpectedCaSha256 $caSha `
                -LanAddress $LanAddress -InterfaceAlias $InterfaceAlias -BasePython $BasePython `
                -BackupParent $RehearsalRoot -RehearsalRoot $RehearsalRoot -RehearsalPort $Port | Out-Null
        } catch { $tamperRejected=$true }
        if (-not $tamperRejected) { throw 'Tampered package was accepted.' }
        $result.tampered_package_refused=$true
        $result.phase='upgrade'
        & (Join-Path $stage 'scripts\upgrade-server-ws03.ps1') -PackagePath $package `
            -ExpectedPackageSha256 $ExpectedPackageSha256 -ExpectedCaSha256 $caSha `
            -LanAddress $LanAddress -InterfaceAlias $InterfaceAlias -BasePython $BasePython `
            -BackupParent $RehearsalRoot -RehearsalRoot $RehearsalRoot -RehearsalPort $Port -Execute | Out-Null
        $result.phase='post-upgrade'
        $installed = Join-Path $installParent 'Server'
        $result.installed_version=(Get-Content -LiteralPath (Join-Path $installed 'VERSION') -Raw).Trim()
        $result.previous_preserved=Test-Path -LiteralPath (Join-Path $installParent 'Server.ws03.previous')
        $journal=(Get-Content -LiteralPath (Join-Path $RehearsalRoot 'server\ws03-upgrade-state.json') -Raw | ConvertFrom-Json)
        $result.journal_phase=$journal.phase
        $result.backup_present=Test-Path -LiteralPath $journal.backup_path
        if ($result.backup_present) {
            $backupManifest = Get-Content -LiteralPath (Join-Path $journal.backup_path 'manifest.json') -Raw | ConvertFrom-Json
            $result.installed_config_backed_up =
                @($backupManifest.files | Where-Object name -eq 'install/config/config.yaml').Count -eq 1
        }
        $repeatRejected=$false
        try {
            & (Join-Path $installed 'scripts\upgrade-server-ws03.ps1') -PackagePath $package `
                -ExpectedPackageSha256 $ExpectedPackageSha256 -ExpectedCaSha256 $caSha `
                -LanAddress $LanAddress -InterfaceAlias $InterfaceAlias -BasePython $BasePython `
                -BackupParent $RehearsalRoot -RehearsalRoot $RehearsalRoot -RehearsalPort $Port | Out-Null
        } catch { $repeatRejected=$true }
        $result.repeated_upgrade_refused=$repeatRejected
        if ($result.installed_version -ne '0.5.0-ws03b-rc7' -or -not $result.previous_preserved -or
            $result.journal_phase -ne 'ready' -or -not $result.backup_present -or
            -not $result.installed_config_backed_up -or -not $repeatRejected) {
            throw 'Disposable post-upgrade invariants failed.'
        }
        $result.status='passed'
        $result.phase='complete'
    } finally { }
} catch {
    $result.error_type=$_.Exception.GetType().Name
} finally {
    # Stop only a listener whose executable resides in this disposable root.
    foreach ($connection in @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)) {
        $process = Get-CimInstance Win32_Process -Filter ("ProcessId=" + $connection.OwningProcess) -ErrorAction SilentlyContinue
        $expectedCommand = '"' + (Join-Path $RehearsalRoot 'RAVEN-X\Server\venv\Scripts\python.exe') +
            '" -B -E -s -m backend.cli serve --data-dir "' + (Join-Path $RehearsalRoot 'server') +
            '" --listen-host 127.0.0.1 --listen-host ' + $LanAddress + ' --port ' + $Port + ' '
        if ($process -and $process.CommandLine -ceq $expectedCommand) {
            Stop-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
            $result.synthetic_server_stopped=$true
        }
    }
    $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $SafeResultPath -Encoding UTF8
}
if ($result.status -ne 'passed') { exit 2 }
