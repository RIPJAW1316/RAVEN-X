#Requires -Version 5.1
<#
.SYNOPSIS
Plan a disposable RAVEN-X control-plane upgrade. Not a production upgrader.

.DESCRIPTION
WS-03 owns a verified, transactional, recoverable in-place upgrade. This
script only plans against a disposable tree. -Execute is refused and does not
modify files. Live HP Omen Program Files and ProgramData paths are refused,
including paths that resolve through a reparse point.
#>
param(
    [Parameter(Mandatory = $true)][string]$SourceRoot,
    [Parameter(Mandatory = $true)][string]$InstallRoot,
    [Parameter(Mandatory = $true)][string]$DataRoot,
    [string]$ExpectedSha256,
    [string]$PythonExe,
    [switch]$Execute
)

$ErrorActionPreference = 'Stop'

if ($Execute) {
    throw 'In-place -Execute is refused. These scripts are not a production upgrade. WS-03 owns transactional recovery. No files were modified.'
}

if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256) -and $ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$') {
    throw 'ExpectedSha256 must be 64 hexadecimal characters.'
}

function Test-LiveOmenPath([string]$Path, [string]$Label) {
    $full = [IO.Path]::GetFullPath($Path)
    $blocked = @(
        (Join-Path $env:ProgramFiles 'RavenX'),
        (Join-Path $env:ProgramData 'RavenX'),
        (Join-Path $env:ProgramData 'RAVEN-X')
    )
    foreach ($root in $blocked) {
        if ($root -and $full.StartsWith([IO.Path]::GetFullPath($root), [StringComparison]::OrdinalIgnoreCase)) {
            throw "$Label points at an installed Omen path and is refused: $full"
        }
    }
}

function Test-NoReparsePoint([string]$Path, [string]$Label) {
    $full = [IO.Path]::GetFullPath($Path)
    $current = Get-Item -LiteralPath $full -Force
    while ($null -ne $current) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label resolves through a reparse point and is refused: $($current.FullName)"
        }
        $current = $current.Parent
    }
}

if (-not $env:ProgramFiles -or -not $env:ProgramData) {
    throw 'ProgramFiles and ProgramData are required so live install paths can be refused.'
}
Test-LiveOmenPath $SourceRoot 'SourceRoot'
Test-LiveOmenPath $InstallRoot 'InstallRoot'
Test-LiveOmenPath $DataRoot 'DataRoot'
if (-not (Test-Path -LiteralPath $SourceRoot -PathType Container)) { throw 'SourceRoot does not exist.' }
if (-not (Test-Path -LiteralPath $InstallRoot -PathType Container)) { throw 'InstallRoot does not exist; use first-install.' }
if (-not (Test-Path -LiteralPath $DataRoot -PathType Container)) { throw 'DataRoot does not exist; enrollment or TLS would be lost.' }
Test-NoReparsePoint $SourceRoot 'SourceRoot'
Test-NoReparsePoint $InstallRoot 'InstallRoot'
Test-NoReparsePoint $DataRoot 'DataRoot'

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $PythonExe) {
    $PythonExe = Join-Path $repoRoot '.venv-ravenx-313\Scripts\python.exe'
}
if (-not (Test-Path -LiteralPath $PythonExe -PathType Leaf)) {
    throw 'Python 3.13 interpreter not found. Pass -PythonExe.'
}

$env:PYTHONPATH = $repoRoot
$env:RAVENX_PLAN_SOURCE = [IO.Path]::GetFullPath($SourceRoot)
$env:RAVENX_PLAN_INSTALL = [IO.Path]::GetFullPath($InstallRoot)
$env:RAVENX_PLAN_DATA = [IO.Path]::GetFullPath($DataRoot)
if ([string]::IsNullOrWhiteSpace($ExpectedSha256)) {
    Remove-Item Env:\RAVENX_PLAN_SHA256 -ErrorAction SilentlyContinue
} else {
    $env:RAVENX_PLAN_SHA256 = $ExpectedSha256
}

$plan = & $PythonExe (Join-Path $PSScriptRoot 'plan_upgrade.py')
if ($LASTEXITCODE -ne 0) { throw "Upgrade plan refused: $plan" }
Write-Output $plan
Write-Output 'Plan only. This script is not a production upgrade. -Execute is refused.'
