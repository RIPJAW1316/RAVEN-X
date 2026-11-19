#Requires -Version 5.1
#Requires -RunAsAdministrator
# Run only from a hash-verified, newly protected disposable package.
param([Parameter(Mandatory=$true)][string]$Root)
$ErrorActionPreference='Stop'
$Root=[IO.Path]::GetFullPath($Root).TrimEnd('\')
$prefix=Join-Path $env:ProgramFiles 'RavenXSetupRehearsal-'
if (-not $Root.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -or
    (Split-Path -Parent $Root) -ine $env:ProgramFiles) { throw 'Not a disposable rehearsal root.' }
$payload=Join-Path $Root 'payload'
$taskName='RAVEN-X Setup Rehearsal '+(Split-Path -Leaf $Root)
$taskCreated=$false
$report=[ordered]@{status='BLOCKED';phase='verification';checks=@();native_exit_codes=@();task=$taskName;root=$Root}
function Run-Native([string]$Executable,[string[]]$Arguments) {
    & $Executable @Arguments
    $report.native_exit_codes+=@{executable=(Split-Path -Leaf $Executable);exit=$LASTEXITCODE}
    if ($LASTEXITCODE -ne 0) { throw ('Native test step failed: '+(Split-Path -Leaf $Executable)) }
}
function Expect-Rejection([scriptblock]$Action,[string]$Message) {
    $rejected=$false
    try { & $Action | Out-Null } catch { if($_.Exception.Message -like $Message){$rejected=$true}else{throw} }
    if(-not $rejected){throw ('Expected rejection was not observed: '+$Message)}
}
try {
    . (Join-Path $payload 'scripts\release-integrity.ps1')
    Assert-VerifiedRelease $payload | Out-Null
    . (Join-Path $payload 'scripts\managed-python.ps1')
    $report.checks+='protected payload manifest and ACLs verified'
    $archive=Join-Path $payload 'runtime\python-3.13.17-amd64.zip'
    $runtime=Join-Path $Root 'runtime'
    $report.phase='fresh runtime'
    $python=Ensure-RavenXManagedPython -ArchivePath $archive -RuntimeParent $runtime
    $report.checks+='fresh protected runtime, full file hashes and PSF signatures verified'
    $report.phase='runtime reuse and failure cases'
    if ((Ensure-RavenXManagedPython -ArchivePath $archive -RuntimeParent $runtime) -cne $python) { throw 'Runtime reuse changed executable.' }
    $report.checks+='existing runtime reused without MSI'
    $bad=Join-Path $Root 'bad-runtime.zip'
    [IO.File]::WriteAllText($bad,'intentional invalid archive')
    Expect-Rejection {Ensure-RavenXManagedPython -ArchivePath $bad -RuntimeParent $runtime} '*archive hash mismatch*'
    $empty=Join-Path $Root 'incomplete-runtime'
    New-RavenXProtectedDirectory $empty
    Expect-Rejection {Ensure-RavenXManagedPython -ArchivePath $archive -RuntimeParent $empty} '*runtime is incomplete*'
    $probe=Join-Path (Split-Path -Parent $python) 'Lib\colorsys.py'
    $saved=[IO.File]::ReadAllBytes($probe)
    try {
        [IO.File]::AppendAllText($probe,'# intentional tamper fixture')
        Expect-Rejection {Ensure-RavenXManagedPython -ArchivePath $archive -RuntimeParent $runtime} '*differs from the official archive*'
    } finally { [IO.File]::WriteAllBytes($probe,$saved) }
    Run-Native "$env:WINDIR\System32\icacls.exe" @($probe,'/grant:r','*S-1-5-32-545:W')
    try { Expect-Rejection {Ensure-RavenXManagedPython -ArchivePath $archive -RuntimeParent $runtime} '*writable by an untrusted identity*' }
    finally { Run-Native "$env:WINDIR\System32\icacls.exe" @($probe,'/remove:g','*S-1-5-32-545') }
    Assert-TrustedReleaseTree $runtime
    $report.checks+='bad archive, incomplete runtime, modified library and user-writable runtime rejected'
    $report.phase='offline dependencies'
    $code=Join-Path $Root 'agent-code'
    New-RavenXProtectedDirectory $code
    Copy-Item -LiteralPath (Join-Path $payload 'backend') -Destination $code -Recurse
    Run-Native $python @('-B','-I','-m','venv',(Join-Path $code 'venv'))
    $venv=Join-Path $code 'venv\Scripts\python.exe'
    Run-Native $venv @('-B','-I','-m','pip','install','--disable-pip-version-check','--no-index','--no-cache-dir','--require-hashes','--only-binary=:all:','--find-links',(Join-Path $payload 'wheels'),'-r',(Join-Path $payload 'requirements-agent-lock.txt'))
    Push-Location $code
    try { Run-Native $venv @('-B','-E','-s','-m','backend.agent','--help') } finally {Pop-Location}
    $report.checks+='new venv, eight offline locked dependencies and backend.agent import succeeded'
    $state=Join-Path $Root 'synthetic-state'
    New-RavenXProtectedDirectory $state
    $fixture=Join-Path $code 'probe.py'
    Copy-Item -LiteralPath (Join-Path $Root 'unified-setup-fixture.py') -Destination $fixture
    $report.phase='DPAPI and SYSTEM execution'
    Run-Native $venv @('-B','-E','-s',$fixture,'create',$state)
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {throw 'Disposable task name already exists.'}
    $action=New-ScheduledTaskAction -Execute $venv -Argument ('-B -E -s "'+$fixture+'" system "'+$state+'"') -WorkingDirectory $code
    $principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
    $settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null
    $taskCreated=$true
    Start-ScheduledTask -TaskName $taskName
    $marker=Join-Path $state 'system-result.json'
    $deadline=[DateTime]::UtcNow.AddSeconds(90)
    while (-not (Test-Path -LiteralPath $marker) -and [DateTime]::UtcNow -lt $deadline) {Start-Sleep -Milliseconds 300}
    if (-not (Test-Path -LiteralPath $marker)) {throw 'SYSTEM task did not publish success evidence.'}
    $system=Get-Content -LiteralPath $marker -Raw | ConvertFrom-Json
    if ($system.sid -ne 'S-1-5-18' -or $system.dpapi -ne 'passed') {throw 'SYSTEM or DPAPI assertion failed.'}
    $report.checks+='real machine DPAPI credential saved by Administrator and loaded by SYSTEM'
    $report.phase='task result'
    $deadline=[DateTime]::UtcNow.AddSeconds(15)
    while ((Get-ScheduledTask -TaskName $taskName).State -eq 'Running' -and [DateTime]::UtcNow -lt $deadline) {Start-Sleep -Milliseconds 250}
    $taskExit=(Get-ScheduledTaskInfo -TaskName $taskName).LastTaskResult
    $report.native_exit_codes+=@{executable='disposable SYSTEM task';exit=$taskExit}
    if ($taskExit -ne 0){throw 'SYSTEM task did not exit successfully.'}
    $report.checks+='SYSTEM task started, exited 0 and used battery-compatible settings'
    $report.status='PASS'
    $report.phase='complete'
} catch {
    $report.status='FAIL'
    $report.error=$_.Exception.Message
    $report.location=$_.InvocationInfo.PositionMessage
} finally {
    if ($taskCreated) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {$report.status='FAIL';$report.cleanup='task remains'}else{$report.cleanup='only disposable task removed'}
    }
    $result=Join-Path $Root 'safe-result.json'
    $report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $result -Encoding UTF8
    # Publish ONLY public result metadata. No inherited read permission on state.
    & "$env:WINDIR\System32\icacls.exe" $Root '/grant:r' '*S-1-5-32-545:RX' | Out-Null
    & "$env:WINDIR\System32\icacls.exe" $result '/grant:r' '*S-1-5-32-545:R' | Out-Null
}
if ($report.status -ne 'PASS') {exit 1}
exit 0
