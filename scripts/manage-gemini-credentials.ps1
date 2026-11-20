#Requires -Version 5.1
<# Manage the current Windows account's local Gemini key using the masked credential CLI. #>
param(
    [ValidateSet('Set','Rotate','Status','Delete')][string]$Action = 'Status',
    [string]$PythonPath,
    [switch]$ReleasePackage
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$packaged = $ReleasePackage -or (Test-Path -LiteralPath (Join-Path $root 'release-manifest.json') -PathType Leaf)
if ($PythonPath -and $packaged) { throw 'The release uses its own verified Python environment.' }
. (Join-Path $PSScriptRoot 'server-runtime.ps1')
if ($PythonPath) {
    $python = (Resolve-Path -LiteralPath $PythonPath).Path
} else {
    $python = Get-RavenXServerPython -Root $root -ReleasePackage:$packaged
}

Push-Location $root
try {
    & $python -B -E -s -m backend.cli gemini-key $Action.ToLowerInvariant()
    if ($LASTEXITCODE -ne 0) { throw 'The Gemini key operation failed.' }
} finally { Pop-Location }
