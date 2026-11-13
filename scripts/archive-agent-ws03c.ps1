#Requires -Version 5.1
#Requires -RunAsAdministrator
<# Operator-controlled archive. Never invokes enrollment or approves an endpoint. #>
param(
    [Parameter(Mandatory=$true)][string]$Python,
    [Parameter(Mandatory=$true)][string]$BackupParent,
    [Parameter(Mandatory=$true)][string]$ExpectedServerUrl,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedCaSha256,
    [string]$DisposableRoot,
    [guid]$ApprovalId,
    [switch]$Execute
)
$ErrorActionPreference='Stop'
$live = [string]::IsNullOrWhiteSpace($DisposableRoot)
if ($live) {
    $installParent=Join-Path $env:ProgramFiles 'RavenX'
    $dataParent=Join-Path $env:ProgramData 'RavenX'
    $taskName='RAVEN-X Endpoint Agent'
} else {
    $DisposableRoot=[IO.Path]::GetFullPath($DisposableRoot).TrimEnd('\')
    $expectedParent=Join-Path $env:ProgramData 'RAVEN-X'
    $leaf=Split-Path -Leaf $DisposableRoot
    if ((Split-Path -Parent $DisposableRoot) -ine $expectedParent -or
        $leaf -notmatch '^ws03c-disposable-([0-9a-f]{32})$') {
        throw 'Disposable root is outside the protected WS-03C parent.'
    }
    $installParent=Join-Path $DisposableRoot 'Program Files\RavenX'
    $dataParent=Join-Path $DisposableRoot 'ProgramData\RavenX'
    $taskName='RAVEN-X WS03C Disposable '+$Matches[1]
}
if ($Execute -and $ApprovalId -eq [guid]::Empty) {
    throw 'Execute requires a recorded operator approval UUID.'
}
$install=Join-Path $installParent 'Agent'
$data=Join-Path $dataParent 'agent'
$BackupParent=[IO.Path]::GetFullPath($BackupParent).TrimEnd('\')
foreach($parent in @($installParent,$dataParent)) {
    $canonical=[IO.Path]::GetFullPath($parent).TrimEnd('\')
    if ($BackupParent.StartsWith($canonical+'\',[StringComparison]::OrdinalIgnoreCase) -or
        $BackupParent -ieq $canonical) {
        throw 'Backup parent must be outside agent code and state parents.'
    }
}
$archiveInstall=$installParent+'.ws03c.previous'
$archiveData=$dataParent+'.ws03c.previous'
$journal=Join-Path $BackupParent 'ws03c-transition.json'
function Assert-Strict([string]$Path) {
    $current=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    while($null -ne $current) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Agent transition path crosses a reparse point.'
        }
        $current=$current.Parent
    }
    $acl=Get-Acl -LiteralPath $Path
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544') -or
        -not $acl.AreAccessRulesProtected) { throw 'Agent transition root custody is unsafe.' }
    foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            throw 'Agent transition root grants unexpected access.'
        }
    }
}
$releaseRoot=Split-Path -Parent $PSScriptRoot
Assert-Strict $releaseRoot
if ([IO.Path]::GetFullPath($Python) -ine [IO.Path]::GetFullPath((Join-Path $releaseRoot 'venv\Scripts\python.exe'))) {
    throw 'Archive must use the protected release Python runtime.'
}
foreach($path in @($installParent,$install,$dataParent,$data,$BackupParent)) { Assert-Strict $path }
if (-not $live) { Assert-Strict $DisposableRoot }
if (@(Get-ChildItem -LiteralPath $BackupParent -Force | Where-Object {
    $_.Name -like 'ws03c-agent-backup-*'
}).Count -ne 0) {
    throw 'Previous complete or incomplete agent backup requires recovery review.'
}
if ((Test-Path -LiteralPath $archiveInstall) -or (Test-Path -LiteralPath $archiveData) -or
    (Test-Path -LiteralPath $journal)) { throw 'Existing archive or transition journal requires recovery review.' }
if (@(Get-ChildItem -LiteralPath $installParent -Force).Count -ne 1 -or
    @(Get-ChildItem -LiteralPath $dataParent -Force).Count -ne 1) {
    throw 'Agent parent contains unexpected entries; whole-parent archive refused.'
}
$task=Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
if (@($task.Actions).Count -ne 1 -or
    $task.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or
    $task.Principal.LogonType -ne 'ServiceAccount' -or
    $task.Principal.RunLevel -ne 'Highest' -or
    $task.Actions[0].WorkingDirectory -ine $install -or
    $task.Actions[0].Execute -ine (Join-Path $install 'venv\Scripts\python.exe')) {
    throw 'Scheduled Task identity differs from the expected agent.'
}
Push-Location $releaseRoot
try {
    $inspection=& $Python -B -E -s -m backend.application.ops.agent_recovery inspect `
        --install $install --data $data --task-name $taskName `
        --expected-server-url $ExpectedServerUrl --expected-ca-sha256 $ExpectedCaSha256
    if ($LASTEXITCODE -ne 0) { throw 'Agent custody and DPAPI inspection failed.' }
} finally { Pop-Location }
if (-not $Execute) {
    Write-Output 'WS-03C preview passed. No backup, task change, code move, or enrollment occurred.'
    Write-Output $inspection
    return
}
$backup=Join-Path $BackupParent ('ws03c-agent-backup-'+[guid]::NewGuid().ToString('N'))
Push-Location $releaseRoot
try {
    & $Python -B -E -s -m backend.application.ops.agent_recovery create `
        --install $install --data $data --destination $backup --task-name $taskName `
        --expected-server-url $ExpectedServerUrl --expected-ca-sha256 $ExpectedCaSha256 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Mandatory agent backup failed.' }
    & $Python -B -E -s -m backend.application.ops.agent_recovery verify --backup $backup | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Agent backup verification failed.' }
    & $Python -B -E -s -m backend.application.ops.agent_recovery mark --root $BackupParent `
        --phase backup_verified --backup $backup | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Agent transition journal creation failed.' }
    Disable-ScheduledTask -TaskName $taskName -ErrorAction Stop | Out-Null
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    $deadline=[DateTime]::UtcNow.AddSeconds(20)
    do {
        Start-Sleep -Milliseconds 250
        $state=(Get-ScheduledTask -TaskName $taskName).State
    } while($state -eq 'Running' -and [DateTime]::UtcNow -lt $deadline)
    if ($state -eq 'Running') { throw 'Exact agent task did not quiesce.' }
    $active=@(Get-CimInstance Win32_Process | Where-Object {
        $_.CommandLine -and $_.CommandLine.Contains('--data-dir "'+$data+'"') -and
        $_.CommandLine.Contains('-m backend.agent run')
    })
    if ($active.Count) { throw 'An agent process still uses the protected state.' }
    & $Python -B -E -s -m backend.application.ops.agent_recovery mark --root $BackupParent `
        --phase task_disabled --backup $backup | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Task-disable phase could not be recorded.' }
    Rename-Item -LiteralPath $installParent -NewName (Split-Path -Leaf $archiveInstall) -ErrorAction Stop
    & $Python -B -E -s -m backend.application.ops.agent_recovery mark --root $BackupParent `
        --phase code_archived --backup $backup | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Code-archive phase could not be recorded.' }
    Rename-Item -LiteralPath $dataParent -NewName (Split-Path -Leaf $archiveData) -ErrorAction Stop
    & $Python -B -E -s -m backend.application.ops.agent_recovery mark --root $BackupParent `
        --phase state_archived --backup $backup | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'State-archive phase could not be recorded.' }
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
    & $Python -B -E -s -m backend.application.ops.agent_recovery mark --root $BackupParent `
        --phase task_removed --backup $backup | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Task-removal phase could not be recorded.' }
    Write-Output 'Old agent archived and exact task removed. New enrollment still requires a fresh token and human approval.'
} finally { Pop-Location }
