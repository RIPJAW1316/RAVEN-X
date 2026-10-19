# Shared runtime selection for the elevated Windows installers.
# A per-user registration is ignored. Zero or multiple protected matches fail closed.
# This file does not execute a selected interpreter; callers run only the returned path.

function Select-RavenXPython313 {
    param(
        [Parameter(Mandatory = $true)][string]$Launcher,
        [Parameter(Mandatory = $true)][string]$ProgramFiles,
        [Parameter(Mandatory = $true)][string]$ProtectedTreeCommand
    )
    if ($ProtectedTreeCommand -notmatch '^Assert-[A-Za-z]+$') {
        throw 'Protected-tree check name is invalid.'
    }
    # Listing registered runtimes does not execute a selected interpreter.
    $pythonListing = @(& $Launcher -0p)
    if ($LASTEXITCODE -ne 0) { throw 'Could not list registered Python runtimes.' }
    $pythonCandidates = @(
        $pythonListing | ForEach-Object {
            if ($_ -match '^\s*-(?:V:)?3\.13(?:-\d+)?\s+\*?\s*(?<Runtime>[A-Za-z]:\\.+\\python\.exe)\s*$') {
                [IO.Path]::GetFullPath($Matches.Runtime.Trim())
            }
        } | Where-Object { $_ }
    )
    $programFilesRoot = [IO.Path]::GetFullPath($ProgramFiles).TrimEnd('\') + '\'
    $trustedCandidates = @(
        $pythonCandidates |
            Where-Object { $_.StartsWith($programFilesRoot, [StringComparison]::OrdinalIgnoreCase) } |
            Select-Object -Unique
    )
    if ($trustedCandidates.Count -eq 0) {
        throw 'No registered Python 3.13 executable is installed beneath protected Program Files. A per-user interpreter is not used.'
    }
    if ($trustedCandidates.Count -gt 1) {
        throw 'Multiple Python 3.13 executables are registered beneath Program Files. Refusing to choose.'
    }
    $basePython = $trustedCandidates[0]
    Assert-NotReparseTree $basePython
    & $ProtectedTreeCommand $basePython $ProgramFiles
    return $basePython
}

function Select-RavenXNodeToolchain {
    param(
        [Parameter(Mandatory = $true)][string[]]$NodeExecutables,
        [Parameter(Mandatory = $true)][string]$ProgramFiles,
        [Parameter(Mandatory = $true)][string]$ProtectedTreeCommand
    )
    if ($ProtectedTreeCommand -notmatch '^Assert-[A-Za-z]+$') {
        throw 'Protected-tree check name is invalid.'
    }
    $programFilesRoot = [IO.Path]::GetFullPath($ProgramFiles).TrimEnd('\') + '\'
    $trustedNodes = @(
        $NodeExecutables | ForEach-Object {
            if (-not $_) { return }
            $full = [IO.Path]::GetFullPath($_)
            if ($full.StartsWith($programFilesRoot, [StringComparison]::OrdinalIgnoreCase) -and
                $full.EndsWith('\node.exe', [StringComparison]::OrdinalIgnoreCase)) {
                $full
            }
        } | Where-Object { $_ } | Select-Object -Unique
    )
    if ($trustedNodes.Count -eq 0) {
        throw 'No Node.js executable is installed beneath protected Program Files. A per-user Node.js is not used.'
    }
    if ($trustedNodes.Count -gt 1) {
        throw 'Multiple Node.js executables are registered beneath Program Files. Refusing to choose.'
    }
    $node = $trustedNodes[0]
    Assert-NotReparseTree $node
    & $ProtectedTreeCommand $node $ProgramFiles
    $npm = [IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $node) 'npm.cmd'))
    if (-not $npm.StartsWith($programFilesRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Matching npm.cmd escaped the protected Program Files directory.'
    }
    if (-not (Test-Path -LiteralPath $npm -PathType Leaf)) {
        throw 'Matching npm.cmd was not found beside the trusted Node.js executable.'
    }
    Assert-NotReparseTree $npm
    & $ProtectedTreeCommand $npm $ProgramFiles
    return [pscustomobject]@{ Node = $node; Npm = $npm }
}
