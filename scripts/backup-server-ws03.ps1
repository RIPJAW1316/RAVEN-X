#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
Run only from an authenticated ZIP extracted into an Administrators/SYSTEM-only
directory. This makes a new encrypted DPAPI backup and never changes source.
#>
param(
    [Parameter(Mandatory=$true)][string]$PythonExe,
    [Parameter(Mandatory=$true)][string]$InstallRoot,
    [Parameter(Mandatory=$true)][string]$DataRoot,
    [Parameter(Mandatory=$true)][string]$Destination
)
$ErrorActionPreference = 'Stop'
foreach ($path in @($PythonExe, $InstallRoot, $DataRoot)) {
    if (-not (Test-Path -LiteralPath $path)) { throw 'Installed source or runtime is missing.' }
}
if (Test-Path -LiteralPath $Destination) { throw 'Backup destination already exists.' }
$packageRoot = Split-Path -Parent $PSScriptRoot
Push-Location $packageRoot
try {
    & $PythonExe -B -E -s -m backend.application.ops.server_backup create `
        --data-root $DataRoot --install-root $InstallRoot --destination $Destination
    if ($LASTEXITCODE -ne 0) { throw 'Protected backup failed; do not upgrade.' }
} finally {
    Pop-Location
}
