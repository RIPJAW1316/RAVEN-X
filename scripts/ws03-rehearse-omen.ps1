#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
Authorized read-only Omen source capture into a protected, machine-local
directory. It never starts a server from the restored state or changes live
server, agent, task, TLS, firewall or database files.
#>
param(
    [Parameter(Mandatory=$true)][string]$StageRoot,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedPackageSha256,
    [Parameter(Mandatory=$true)][string]$SafeResultPath
)
$ErrorActionPreference = 'Stop'
$package = Join-Path $StageRoot 'release.zip'
$release = Join-Path $StageRoot 'release'
$venvRoot = Join-Path $StageRoot 'venv'
$venv = Join-Path $venvRoot 'Scripts\python.exe'
$backup = Join-Path $StageRoot 'backup'
$restore = Join-Path $StageRoot 'restore'
$baseline = Join-Path $StageRoot 'baseline'
$basePython = Join-Path $env:ProgramFiles 'RavenXRuntime\Python313\python.exe'
$liveInstall = Join-Path $env:ProgramFiles 'RAVEN-X\Server'
$liveData = Join-Path $env:ProgramData 'RAVEN-X\server'
$result = [ordered]@{status='failed';stage=$StageRoot;step='preflight'}
try {
    $expectedParent = Join-Path $env:ProgramData 'RAVEN-X'
    if ((Split-Path -Parent $StageRoot) -ine $expectedParent) { throw 'Stage is outside protected RAVEN-X parent.' }
    foreach ($path in @($StageRoot,$package,$basePython,$liveInstall,$liveData)) {
        if (-not (Test-Path -LiteralPath $path)) { throw 'Required installed or staged path is missing.' }
        if (((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Reparse-point path is refused.'
        }
    }
    $acl = Get-Acl -LiteralPath $StageRoot
    if (-not $acl.AreAccessRulesProtected -or
        $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')) {
        throw 'Stage custody is not protected.'
    }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')) {
            throw 'Stage grants unexpected access.'
        }
    }
    if ((Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash -ine $ExpectedPackageSha256) {
        throw 'Package hash differs from independently supplied value.'
    }
    if ((Get-AuthenticodeSignature -LiteralPath $basePython).Status -ne 'Valid') {
        throw 'Protected Python runtime signature is invalid.'
    }
    $result.step='extract'
    Expand-Archive -LiteralPath $package -DestinationPath $release -ErrorAction Stop
    Push-Location $release
    try {
        & $basePython -B -E -s scripts/build-server-release.py verify-extracted $package `
            --root $release --expected-sha256 $ExpectedPackageSha256 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Extracted release differs from ZIP.' }
        & $basePython -B -E -s -m venv $venvRoot
        if ($LASTEXITCODE -ne 0) { throw 'Staged Python environment failed.' }
        & $venv -B -E -s -m pip install --no-index --find-links (Join-Path $release 'wheels') `
            --require-hashes -r (Join-Path $release 'requirements-server-lock.txt') | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Offline dependency installation failed.' }
        $result.step='backup'
        $backupOutput = & $venv -B -E -s -m backend.application.ops.server_backup create `
            --data-root $liveData --install-root $liveInstall --destination $backup
        if ($LASTEXITCODE -ne 0) { throw 'Protected live-state backup failed.' }
        $backupInfo = $backupOutput | ConvertFrom-Json
        & $venv -B -E -s -m backend.application.ops.server_backup verify --backup-root $backup | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Backup verification failed.' }
        $result.step='restore'
        $restoreOutput = & $venv -B -E -s -m backend.application.ops.server_backup restore-isolated `
            --backup-root $backup --destination $restore
        if ($LASTEXITCODE -ne 0) { throw 'Isolated restore failed.' }
        $restored = $restoreOutput | ConvertFrom-Json
        & $venv -B -E -s -m backend.application.ops.server_backup restore-isolated `
            --backup-root $backup --destination $baseline | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Baseline restore for row comparison failed.' }
        $result.step='migration'
        & $venv -B -E -s -m backend.cli migrate --data-dir $restore | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Isolated schema migration failed.' }
        $summaryOutput = & $venv -B -E -s -m backend.application.ops.server_backup summarize `
            --database (Join-Path $restore 'raven_x.db')
        if ($LASTEXITCODE -ne 0) { throw 'Migrated record inspection failed.' }
        $summary = $summaryOutput | ConvertFrom-Json
        foreach ($property in $restored.counts.PSObject.Properties) {
            if ($summary.counts.$($property.Name) -ne $property.Value) {
                throw 'A pre-existing table count changed during isolated migration.'
            }
        }
        $comparisonOutput = & $venv -B -E -s -m backend.application.ops.server_backup compare-records `
            --before (Join-Path $baseline 'raven_x.db') --after (Join-Path $restore 'raven_x.db')
        if ($LASTEXITCODE -ne 0) { throw 'Pre-existing rows changed during isolated migration.' }
        $comparison = $comparisonOutput | ConvertFrom-Json
        if (-not $comparison.preserved) { throw 'Pre-existing rows changed during isolated migration.' }
        $result.step='key-binding'
        & $venv -B -E -s -m backend.application.ops.server_upgrade key-check `
            --database (Join-Path $restore 'raven_x.db') | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Isolated verifier-key binding failed.' }
        $result.status='passed'
        $result.step='complete'
        $result.backup_manifest_sha256=$backupInfo.manifest_sha256
        $result.original_tables=$backupInfo.tables
        $result.restored_tables=$summary.tables.Count
        $result.original_counts=$restored.counts
        $result.records_preserved=$true
        $result.record_tables_compared=$comparison.checked_tables
        $result.network_server_started=$false
    } finally { Pop-Location }
} catch {
    $result.error_type=$_.Exception.GetType().Name
} finally {
    # This report contains aggregate counts and hashes only, never raw rows or secrets.
    $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $SafeResultPath -Encoding UTF8
}
