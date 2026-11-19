#Requires -Version 5.1
# Interactive, supervised pilot helper. No enrollment secret is accepted here.
param()
$ErrorActionPreference = 'Stop'
$kit = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonInstaller = Join-Path $kit 'python-3.13.17-amd64.exe'
$agentInstaller = Join-Path $kit 'RAVEN-X-Agent-Setup-rc2.exe'
$expectedPython = '5DA012101BA2E17113A9A1CD901E9CE1441086F2B7ECB5DE06EC94163899A190'
$expectedAgent = 'F373AB512D4E4DB9C1B2BAD051662BB9BBF73655C5037C7E28BCEB56E67F60FC'

function Assert-Hash([string]$path, [string]$expected) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing kit file: $(Split-Path -Leaf $path)" }
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    if ($actual -ine $expected) { throw "Kit file hash mismatch: $(Split-Path -Leaf $path)" }
}

function Find-SystemPython {
    $launcher = Join-Path $env:WINDIR 'py.exe'
    if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) { return $null }
    $entries = @(& $launcher -0p)
    if ($LASTEXITCODE -ne 0) { return $null }
    $prefix = [IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\') + '\'
    $candidates = @($entries | ForEach-Object {
        if ($_ -match '^\s*-(?:V:)?3\.13(?:-\d+)?\s+\*?\s*(?<Runtime>[A-Za-z]:\\.+\\python\.exe)\s*$') {
            $candidate = [IO.Path]::GetFullPath($Matches.Runtime.Trim())
            if ($candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { $candidate }
        }
    } | Select-Object -Unique)
    if ($candidates.Count -ne 1) { return $null }
    return $candidates[0]
}

function Test-SystemPython([string]$path) {
    if (-not $path) { return $false }
    try {
        $runtime = & $path -I -c 'import platform,sys,venv,ensurepip;print("{0}|{1}|{2}".format(sys.version_info.major,sys.version_info.minor,platform.machine()))'
        return ($LASTEXITCODE -eq 0 -and $runtime -eq '3|13|AMD64')
    } catch { return $false }
}

try {
    Write-Host 'RAVEN-X Dell pilot: Windows prerequisite and agent setup'
    if (-not [Environment]::Is64BitOperatingSystem -or [Environment]::OSVersion.Version.Major -lt 10) {
        throw 'This kit requires 64-bit Windows 10 or later.'
    }
    Assert-Hash $pythonInstaller $expectedPython
    Assert-Hash $agentInstaller $expectedAgent
    $signature = Get-AuthenticodeSignature -LiteralPath $pythonInstaller
    if ($signature.Status -ne 'Valid' -or
        $signature.SignerCertificate.Subject -notmatch 'Python Software Foundation') {
        throw 'Official Python installer signature did not verify.'
    }
    $python = Find-SystemPython
    if (-not (Test-SystemPython $python)) {
        Write-Host 'A complete protected, all-users Python 3.13 is missing or broken.'
        Write-Host 'Windows will request administrator approval to install or repair official Python 3.13.17.'
        $reply = Read-Host 'Install Python now? Type YES'
        if ($reply -cne 'YES') { throw 'Python installation was not approved.' }
        $arguments = '/passive InstallAllUsers=1 TargetDir="C:\Program Files\Python313" Include_launcher=1 InstallLauncherAllUsers=1 Include_dev=0 Include_doc=0 Include_tcltk=0 Include_test=0 PrependPath=0'
        $process = Start-Process -FilePath $pythonInstaller -ArgumentList $arguments -Verb RunAs -Wait -PassThru
        if ($process.ExitCode -ne 0) { throw "Python installer exited with code $($process.ExitCode)." }
        $python = Find-SystemPython
        if (-not (Test-SystemPython $python)) { throw 'System Python 3.13 is still incomplete; do not run agent setup.' }
    }
    if (-not (Test-SystemPython $python)) { throw 'Protected Python is not a complete CPython 3.13 AMD64 runtime.' }
    Write-Host "Python ready: $python"
    Write-Host 'Next, the agent wizard asks for the Omen HTTPS URL, enrollment UUID, public CA PEM and CA SHA-256.'
    Write-Host 'The one-time token is entered only at the hidden PowerShell prompt. Keep it out of this kit.'
    $reply = Read-Host 'Is the Omen server reachable and is a fresh enrollment token ready? Type YES'
    if ($reply -cne 'YES') { throw 'Agent setup was not started.' }
    $process = Start-Process -FilePath $agentInstaller -Verb RunAs -Wait -PassThru
    if ($process.ExitCode -ne 0) { throw "Agent setup exited with code $($process.ExitCode). Inspect the setup window and partial state." }
    Write-Host 'Setup exited successfully. Approve this Dell endpoint in the Omen portal, then verify it is Online.'
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
