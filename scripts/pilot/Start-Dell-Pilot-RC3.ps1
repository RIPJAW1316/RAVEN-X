#Requires -Version 5.1
# Interactive pilot helper. Enrollment secrets are never accepted as arguments.
param()

$ErrorActionPreference = 'Stop'
$kit = Split-Path -Parent $MyInvocation.MyCommand.Path
$archive = Join-Path $kit 'python-3.13.17-amd64.zip'
$runtimeInstaller = Join-Path $kit 'Install-PythonPortable.ps1'
$agentInstaller = Join-Path $kit 'RAVEN-X-Agent-Setup-rc3.exe'
$managedPython = Join-Path $env:ProgramFiles 'RavenXRuntime\Python313-3.13.17\python.exe'
$expectedArchive = 'B26CA4B4EE51E157836049934D2B8EABD55939BE296F3130254251B6DF96EC2F'
$expectedAgent = '9628BD91014FC16BD4C74B95D748254209238C2CA603E2A335CFCBFAEFF7894F'
$expectedRuntimeScript = 'D525AE57D3E98159086ADC839A8AF45C1624F86D16EA67EBFE341E83D6293518'

function Assert-Hash([string]$Path, [string]$Expected) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf) -or
        (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ine $Expected) {
        throw "Kit file is missing or differs: $(Split-Path -Leaf $Path)"
    }
}

try {
    Write-Host 'RAVEN-X Dell pilot RC3: protected Python and agent setup'
    if (-not [Environment]::Is64BitOperatingSystem -or [Environment]::OSVersion.Version.Major -lt 10) {
        throw '64-bit Windows 10 or later is required.'
    }
    Assert-Hash $archive $expectedArchive
    Assert-Hash $agentInstaller $expectedAgent
    Assert-Hash $runtimeInstaller $expectedRuntimeScript
    if (-not (Test-Path -LiteralPath $managedPython -PathType Leaf)) {
        Write-Host 'The official full CPython runtime will be installed in protected Program Files.'
        Write-Host 'This does not use or repair the Dell Windows Installer Python registration.'
        if ((Read-Host 'Install protected Python now? Type YES') -cne 'YES') {
            throw 'Runtime installation was not approved.'
        }
        $powershell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $arguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -ArchivePath "{1}"' -f $runtimeInstaller, $archive
        $result = Start-Process -FilePath $powershell -ArgumentList $arguments -Verb RunAs -WindowStyle Hidden -Wait -PassThru
        if ($result.ExitCode -ne 0) {
            throw "Protected Python installation failed (exit $($result.ExitCode)). Stop and inspect the runtime parent."
        }
    }
    if (-not (Test-Path -LiteralPath $managedPython -PathType Leaf)) {
        throw 'Managed Python executable is missing.'
    }
    Write-Host 'Protected Python is present. Agent Setup will independently verify its ACLs and signature.'
    Write-Host 'Have the Omen HTTPS URL, fresh enrollment UUID, public CA PEM and independent CA SHA-256 ready.'
    Write-Host 'Enter the one-time token only at the hidden prompt inside Agent Setup.'
    if ((Read-Host 'Is the Omen server reachable and a fresh token ready? Type YES') -cne 'YES') {
        throw 'Agent setup was not started.'
    }
    $result = Start-Process -FilePath $agentInstaller -Verb RunAs -Wait -PassThru
    if ($result.ExitCode -ne 0) {
        throw "Agent Setup exited with code $($result.ExitCode). Preserve partial state for inspection."
    }
    Write-Host 'Setup completed. Approve Dell in Omen Fleet, confirm Online, then run an assessment.'
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
