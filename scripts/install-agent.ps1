#Requires -RunAsAdministrator
<#
.SYNOPSIS
Install and enroll the RAVEN-X Windows endpoint agent for a pilot machine.

.DESCRIPTION
Run from an elevated PowerShell window with Python 3.13 available through
the py launcher. The bootstrap token is requested by Python's hidden prompt;
it is never supplied in a command argument, task definition, or file.

.EXAMPLE
.\scripts\install-agent.ps1 -ServerUrl https://control.example:8443 `
  -EnrollmentId 65e38624-4cfc-4f43-9897-4e1eb9eaa140 `
  -CaCertPath C:\Temp\ravenx-ca.pem `
  -CaCertSha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
#>
param(
    [Parameter(Mandatory = $true)][string]$ServerUrl,
    [Parameter(Mandatory = $true)][guid]$EnrollmentId,
    [Parameter(Mandatory = $true)][string]$CaCertPath,
    [Parameter(Mandatory = $true)][string]$CaCertSha256,
    [switch]$NoStart
)

$ErrorActionPreference = 'Stop'
if ($ServerUrl.Length -gt 2048 -or $ServerUrl -match '["\\\x00-\x1F\x7F\s]') {
    throw 'ServerUrl contains characters unsafe for a scheduled task argument.'
}
$uri = [Uri]$ServerUrl
if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or -not $uri.Host -or $uri.UserInfo -or $uri.Query -or $uri.Fragment) {
    throw 'ServerUrl must be an HTTPS server URL without credentials, query, or fragment.'
}
if (-not (Test-Path -LiteralPath $CaCertPath -PathType Leaf)) {
    throw 'The CA certificate file does not exist.'
}
if ($CaCertSha256 -cnotmatch '\A[0-9a-fA-F]{64}\z') {
    throw 'CaCertSha256 must be the independently verified 64-character SHA-256 fingerprint.'
}
if (-not $env:ProgramFiles -or -not $env:ProgramData) {
    throw 'ProgramFiles and ProgramData are required.'
}
foreach ($basePath in @($env:ProgramFiles, $env:ProgramData)) {
    if ($basePath -match '["\x00-\x1F\x7F]') {
        throw 'A system installation path contains unsafe characters.'
    }
}

$repoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'release-integrity.ps1')
$release = Assert-VerifiedRelease $repoRoot
$installParent = Join-Path $env:ProgramFiles 'RavenX'
$installRoot = Join-Path $env:ProgramFiles 'RavenX\Agent'
$dataRoot = Join-Path $env:ProgramData 'RavenX\agent'
$caTarget = Join-Path $dataRoot 'server-ca.pem'
$agentPython = Join-Path $installRoot 'venv\Scripts\python.exe'
$taskName = 'RAVEN-X Endpoint Agent'
if (Test-Path -LiteralPath $installRoot) {
    throw 'The agent is already installed. Use a reviewed update procedure before replacing it.'
}
if (Test-Path -LiteralPath $installParent) {
    throw 'The RavenX Program Files directory already exists; inspect its owner and ACL before installation.'
}
if (Test-Path -LiteralPath (Split-Path -Parent $dataRoot)) {
    throw 'The RavenX ProgramData directory already exists; preserve and inspect its state before installation.'
}
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    throw 'The endpoint task already exists.'
}

function Assert-NotReparseTree([string]$Path) {
    $current = Get-Item -LiteralPath $Path -Force
    while ($null -ne $current) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Installation path contains a reparse point: $($current.FullName)"
        }
        $parentPath = Split-Path -Parent $current.FullName
        if (-not $parentPath -or $parentPath -eq $current.FullName) { break }
        $current = Get-Item -LiteralPath $parentPath -Force
    }
}

function Assert-NoUntrustedWrite([string]$Path) {
    $acl = Get-Acl -LiteralPath $Path
    $trusted = @('S-1-3-0', 'S-1-5-18', 'S-1-5-32-544',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($ownerSid -notin $trusted) {
        throw "Installation path has an unauthorized owner: $Path"
    }
    $writeMask = [int][Security.AccessControl.FileSystemRights]::WriteData -bor `
        [int][Security.AccessControl.FileSystemRights]::AppendData -bor `
        [int][Security.AccessControl.FileSystemRights]::WriteAttributes -bor `
        [int][Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor `
        [int][Security.AccessControl.FileSystemRights]::Delete -bor `
        [int][Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor `
        [int][Security.AccessControl.FileSystemRights]::ChangePermissions -bor `
        [int][Security.AccessControl.FileSystemRights]::TakeOwnership -bor `
        0x10000000 -bor 0x40000000
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and `
            $rule.IdentityReference.Value -notin $trusted -and `
            (([int]$rule.FileSystemRights -band $writeMask) -ne 0)) {
            throw "Installation path is writable by standard users: $Path"
        }
    }
}

function Assert-NoUntrustedWriteTree([string]$Path, [string]$StopAt) {
    $current = Get-Item -LiteralPath $Path -Force
    $stop = (Get-Item -LiteralPath $StopAt -Force).FullName.TrimEnd('\')
    while ($null -ne $current) {
        Assert-NoUntrustedWrite $current.FullName
        if ($current.FullName.TrimEnd('\') -ieq $stop) { return }
        $parentPath = Split-Path -Parent $current.FullName
        if (-not $parentPath -or $parentPath -eq $current.FullName) { break }
        $current = Get-Item -LiteralPath $parentPath -Force
    }
    throw 'Python installation is not beneath the protected Program Files directory.'
}

function Protect-CodeDirectory([string]$Path) {
    if (Test-Path -LiteralPath $Path) { throw "Install directory already exists: $Path" }
    New-Item -ItemType Directory -Path $Path | Out-Null
    Assert-NotReparseTree $Path
    & icacls.exe $Path '/inheritance:r' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to remove inherited install ACL.' }
    & icacls.exe $Path '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to grant SYSTEM and Administrators access.' }
    & icacls.exe $Path '/setowner' '*S-1-5-32-544' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to set the install directory owner.' }
    $acl = Get-Acl -LiteralPath $Path
    $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if (-not $acl.AreAccessRulesProtected -or `
        $ownerSid -notin @('S-1-5-32-544', 'S-1-5-18')) {
        throw 'Install directory ownership or ACL protection could not be verified.'
    }
    $rules = @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))
    $allowed = @('S-1-5-18', 'S-1-5-32-544')
    if ($rules.Count -ne 2) { throw 'Install directory has unexpected explicit ACL entries.' }
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or `
            $rule.IdentityReference.Value -notin $allowed -or `
            (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne [Security.AccessControl.FileSystemRights]::FullControl)) {
            throw 'Install directory grants unexpected access.'
        }
    }
    Assert-NoUntrustedWrite $Path
}

Assert-NotReparseTree $env:ProgramFiles
Assert-NoUntrustedWrite $env:ProgramFiles
$launcher = Join-Path $env:WINDIR 'py.exe'
if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) {
    throw 'Install the system-wide Python 3.13 launcher before deploying the SYSTEM agent.'
}
Assert-NotReparseTree $launcher
Assert-NoUntrustedWrite $launcher
# Listing registered runtimes does not execute a selected interpreter.
# Never invoke py -3.13 before validating the chosen executable.
# A per-user Python 3.13 does not disqualify one protected system interpreter.
. (Join-Path $PSScriptRoot 'runtime-selection.ps1')
$basePython = Select-RavenXPython313 -Launcher $launcher -ProgramFiles $env:ProgramFiles -ProtectedTreeCommand 'Assert-NoUntrustedWriteTree'
$runtime = & $basePython -I -c 'import platform,sys; print("{0}|{1}|{2}".format(sys.version_info.major,sys.version_info.minor,platform.machine()))'
if ($LASTEXITCODE -ne 0 -or $runtime -ne '3|13|AMD64') {
    throw 'A protected Windows AMD64 Python 3.13 runtime is required.'
}
& $basePython -I (Join-Path $repoRoot 'backend\agent\trust.py') --server $ServerUrl --ca-cert $CaCertPath `
    --expected-ca-sha256 $CaCertSha256
if ($LASTEXITCODE -ne 0) { throw 'Omen HTTPS trust verification failed before installation.' }
Protect-CodeDirectory $installParent
Protect-CodeDirectory $installRoot
Copy-Item -LiteralPath (Join-Path $repoRoot 'backend') -Destination (Join-Path $installRoot 'backend') -Recurse
Copy-Item -LiteralPath (Join-Path $repoRoot 'requirements-agent-lock.txt') -Destination $installRoot
foreach ($entry in @($release.files)) {
    if ($entry.path -notlike 'backend/*' -and $entry.path -ne 'requirements-agent-lock.txt') { continue }
    $target = Join-Path $installRoot ($entry.path.Replace('/', '\'))
    if (-not (Test-Path -LiteralPath $target -PathType Leaf) -or
        (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ine [string]$entry.sha256) {
        throw 'Copied agent code differs from the verified release.'
    }
}
& $basePython -I -m venv (Join-Path $installRoot 'venv')
if ($LASTEXITCODE -ne 0) { throw 'Python virtual environment creation failed.' }
& $agentPython -E -s -m pip install --disable-pip-version-check --no-index --no-cache-dir `
    --only-binary=:all: --require-hashes --find-links (Join-Path $repoRoot 'wheels') `
    -r (Join-Path $installRoot 'requirements-agent-lock.txt')
if ($LASTEXITCODE -ne 0) { throw 'Agent dependency installation failed.' }

Push-Location $installRoot
try {
    & $agentPython -E -s -m backend.agent prepare --ca-cert-source $CaCertPath --expected-ca-sha256 $CaCertSha256 --data-dir $dataRoot
    if ($LASTEXITCODE -ne 0) { throw 'Protected storage preparation failed.' }
    & $agentPython -E -s -m backend.agent enroll --server $ServerUrl --enrollment-id $EnrollmentId --ca-cert $caTarget --data-dir $dataRoot
    if ($LASTEXITCODE -ne 0) { throw 'Agent enrollment failed.' }

    $arguments = '-E -s -m backend.agent run --server "{0}" --ca-cert "{1}" --data-dir "{2}"' -f $ServerUrl, $caTarget, $dataRoot
    $action = New-ScheduledTaskAction -Execute $agentPython -Argument $arguments -WorkingDirectory $installRoot
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    # The agent must stay available when a laptop is running on battery.
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable `
        -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
        -Description 'RAVEN-X outbound Windows endpoint agent' | Out-Null
    $registered = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    if ($registered.Principal.UserId -notin @('SYSTEM', 'S-1-5-18') -or
        $registered.Principal.RunLevel -ne 'Highest' -or
        @($registered.Actions).Count -ne 1 -or
        $registered.Actions[0].Execute -ine $agentPython -or
        $registered.Actions[0].WorkingDirectory -ine $installRoot -or
        $registered.Actions[0].Arguments -cne $arguments -or
        $registered.Settings.DisallowStartIfOnBatteries -or
        $registered.Settings.StopIfGoingOnBatteries) {
        throw 'Registered agent task differs from the expected SYSTEM configuration.'
    }
    if (-not $NoStart) { Start-ScheduledTask -TaskName $taskName }
} finally {
    Pop-Location
}

Write-Host "Installed and enrolled RAVEN-X endpoint agent. Await portal approval before assessments."
