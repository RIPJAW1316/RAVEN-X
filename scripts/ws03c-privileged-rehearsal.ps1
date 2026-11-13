#Requires -Version 5.1
#Requires -RunAsAdministrator
<# Synthetic only. Must be run from a digest-verified protected WS-03C release. #>
param(
    [Parameter(Mandatory=$true)][string]$DisposableRoot,
    [Parameter(Mandatory=$true)][string]$BasePython,
    [Parameter(Mandatory=$true)][string]$SafeResultPath
)
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath($DisposableRoot).TrimEnd('\')
$expectedParent=Join-Path $env:ProgramData 'RAVEN-X'
$leaf=Split-Path -Leaf $root
if ((Split-Path -Parent $root) -ine $expectedParent -or $leaf -notmatch '^ws03c-disposable-([0-9a-f]{32})$') {
    throw 'Rehearsal root is outside disposable protected storage.'
}
$taskName='RAVEN-X WS03C Disposable '+$Matches[1]
$releaseRoot=Split-Path -Parent $PSScriptRoot
$python=Join-Path $releaseRoot 'venv\Scripts\python.exe'
$phase='fixture'
$report=[ordered]@{synthetic_only=$true;root=$root;task=$taskName;status='failed';phase=$phase;checks=@()}
function Run-Recovery([string[]]$Arguments) {
    Push-Location $releaseRoot
    try {
        $output=& $python -B -E -s -m backend.application.ops.agent_recovery @Arguments
        if ($LASTEXITCODE -ne 0) { throw 'Protected recovery command failed.' }
        return $output
    } finally { Pop-Location }
}
function Assert-RejectedInspection([string[]]$Arguments, [string]$ExpectedCode, [int]$ExpectedExit) {
    $previousPreference=$ErrorActionPreference
    try {
        # Windows PowerShell 5.1 promotes expected native stderr to a terminating
        # RemoteException under Stop before the caller can inspect LASTEXITCODE.
        $ErrorActionPreference='Continue'
        $output=@(& $python -B -E -s -m backend.application.ops.agent_recovery inspect @Arguments 2>$null)
        $exitCode=$LASTEXITCODE
    } finally {
        $ErrorActionPreference=$previousPreference
    }
    if ($exitCode -ne $ExpectedExit -or $output.Count -ne 1 -or $output[0] -cne $ExpectedCode) {
        throw 'Inspection did not reject for the expected security reason.'
    }
}
try {
    Push-Location $releaseRoot
    try {
        $fixtureText=& $python -B -E -s scripts/ws03c-synthetic-fixture.py --root $root --base-python $BasePython
        if ($LASTEXITCODE -ne 0) { throw 'Synthetic DPAPI fixture failed.' }
    } finally { Pop-Location }
    $fixture=$fixtureText | ConvertFrom-Json
    $report.checks+=@('synthetic expired DPAPI credential created','protected code, state, outbox created')
    $phase='task'
    $action=New-ScheduledTaskAction -Execute (Join-Path $fixture.install 'venv\Scripts\python.exe') `
        -Argument ('-E -s -m backend.agent run --server "'+$fixture.origin+'" --ca-cert "'+(Join-Path $fixture.data 'server-ca.pem')+'" --data-dir "'+$fixture.data+'"') `
        -WorkingDirectory $fixture.install
    $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -ErrorAction Stop | Out-Null
    Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
    $marker=Join-Path $fixture.data 'system-execution.txt'
    $deadline=[DateTime]::UtcNow.AddSeconds(20)
    while (-not (Test-Path -LiteralPath $marker) -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 250
    }
    if (-not (Test-Path -LiteralPath $marker) -or (Get-Content -LiteralPath $marker -Raw).Trim() -ine 'nt authority\system') {
        throw 'Disposable task did not prove SYSTEM execution.'
    }
    $report.checks+='real disposable task started under SYSTEM'
    $phase='negative-preflight'
    Run-Recovery -Arguments @('inspect','--install',$fixture.install,'--data',$fixture.data,'--task-name',$taskName,
                   '--expected-server-url',$fixture.origin,'--expected-ca-sha256',$fixture.ca_sha256) | Out-Null
    Push-Location $releaseRoot
    try {
        Assert-RejectedInspection -Arguments @('--install',$fixture.install,'--data',$fixture.data,
            '--task-name',$taskName,'--expected-server-url','https://127.0.0.1:29999',
            '--expected-ca-sha256',$fixture.ca_sha256) -ExpectedCode 'AGENT_ORIGIN_MISMATCH' -ExpectedExit 20
        Assert-RejectedInspection -Arguments @('--install',$fixture.install,'--data',$fixture.data,
            '--task-name',$taskName,'--expected-server-url',$fixture.origin,
            '--expected-ca-sha256',('0'*64)) -ExpectedCode 'AGENT_CA_MISMATCH' -ExpectedExit 21
    } finally { Pop-Location }
    $report.checks+='wrong server URL and CA rejected'
    $phase='preview'
    & (Join-Path $PSScriptRoot 'archive-agent-ws03c.ps1') -Python $python -BackupParent (Join-Path $root 'backups') `
        -ExpectedServerUrl $fixture.origin -ExpectedCaSha256 $fixture.ca_sha256 -DisposableRoot $root | Out-Null
    if (-not (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) { throw 'Preview removed task.' }
    $report.checks+='preview left disposable task and state intact'
    $phase='archive'
    & (Join-Path $PSScriptRoot 'archive-agent-ws03c.ps1') -Python $python -BackupParent (Join-Path $root 'backups') `
        -ExpectedServerUrl $fixture.origin -ExpectedCaSha256 $fixture.ca_sha256 -DisposableRoot $root `
        -Execute -ApprovalId ([guid]::NewGuid()) | Out-Null
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { throw 'Disposable task remained registered.' }
    if (-not (Test-Path -LiteralPath ((Join-Path $root 'Program Files\RavenX')+'.ws03c.previous')) -or
        -not (Test-Path -LiteralPath ((Join-Path $root 'ProgramData\RavenX')+'.ws03c.previous'))) {
        throw 'Agent code or state archive is missing.'
    }
    $backup=@(Get-ChildItem -LiteralPath (Join-Path $root 'backups') -Directory | Where-Object Name -Like 'ws03c-agent-backup-*')
    if ($backup.Count -ne 1) { throw 'Expected exactly one encrypted backup.' }
    $verified=Run-Recovery -Arguments @('verify','--backup',$backup[0].FullName)
    $restored=Run-Recovery -Arguments @('restore-isolated','--backup',$backup[0].FullName,
                             '--destination',(Join-Path $root 'restores\checked'))
    $journal=Get-Content -LiteralPath (Join-Path $root 'backups\ws03c-transition.json') -Raw | ConvertFrom-Json
    if ($journal.phase -ne 'task_removed') { throw 'Transition journal is incomplete.' }
    if ((Get-Content -LiteralPath (Join-Path $root 'restores\checked\state\outbox\pending.json') -Raw) `
        -notmatch 'pending-evidence') { throw 'Pending evidence was not restored.' }
    $report.checks+=@('protected encrypted backup verified','original code and state archived',
                      'exact task removed','same-machine DPAPI identity and outbox restored in isolation')
    $report.status='passed'
    $report.phase='complete'
    $report.endpoint_id=$fixture.endpoint_id
    $report.backup_manifest_sha256=($verified | ConvertFrom-Json).manifest_sha256
} catch {
    $report.status='failed'
    $report.phase=$phase
    $report.error_type=$_.Exception.GetType().Name
} finally {
    $report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $SafeResultPath -Encoding UTF8
}
if ($report.status -ne 'passed') { exit 2 }
