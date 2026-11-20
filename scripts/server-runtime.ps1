# Resolve the same interpreter for the launcher and the Gemini credential CLI.
function Get-RavenXServerPython {
    param(
        [Parameter(Mandatory=$true)][string]$Root,
        [switch]$ReleasePackage
    )
    if (-not $ReleasePackage) {
        foreach ($relative in @('venv\Scripts\python.exe','.venv-ravenx-313\Scripts\python.exe','.venv-ravenx\Scripts\python.exe')) {
            $candidate = Join-Path $Root $relative
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
        }
        throw 'Create a Python 3.13 virtual environment in the RAVEN-X checkout first.'
    }

    . (Join-Path $Root 'scripts\release-integrity.ps1')
    . (Join-Path $Root 'scripts\managed-python.ps1')
    $venv = Join-Path $Root 'venv'
    $python = Join-Path $venv 'Scripts\python.exe'
    $lockFile = Join-Path $Root 'requirements-server-lock.txt'
    $stamp = Join-Path $venv '.ravenx-dependencies'
    $mutex = [Threading.Mutex]::new($false,'Global\NorthCypher-RavenX-AdminRuntime')
    $locked = $false
    try {
        try { $locked = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked = $true }
        if (-not $locked) { throw 'Another RAVEN-X window is preparing the offline runtime. Try again when it finishes.' }
        Assert-TrustedReleaseTree $Root
        $digest = (Get-FileHash -LiteralPath $lockFile -Algorithm SHA256).Hash
        if ((Test-Path -LiteralPath $python -PathType Leaf) -and
            (Test-Path -LiteralPath $stamp -PathType Leaf) -and
            ((Get-Content -LiteralPath $stamp -Raw).Trim() -ceq $digest)) {
            return $python
        }
        Write-Host 'Preparing the bundled Python runtime and installing offline dependencies.'
        $base = Ensure-RavenXManagedPython `
            -ArchivePath (Join-Path $Root 'runtime\python-3.13.17-amd64.zip') `
            -RuntimeParent (Join-Path $env:ProgramFiles 'RavenXServerRuntime')
        & $base -B -I -m venv $venv | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'Server virtual environment creation failed.' }
        & $python -B -I -m pip --isolated --disable-pip-version-check install `
            --no-index --no-cache-dir --only-binary ':all:' --require-hashes `
            --find-links (Join-Path $Root 'wheels') -r $lockFile | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'Offline server dependency installation failed.' }
        & $python -B -I -m pip --isolated --disable-pip-version-check check | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'The installed server dependencies did not pass verification.' }
        Set-Content -LiteralPath $stamp -Value $digest -Encoding ASCII
        $icaclsPath = Join-Path ([Environment]::SystemDirectory) 'icacls.exe'
        & $icaclsPath $venv '/setowner' '*S-1-5-32-544' '/T' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not protect the server virtual environment owner.' }
        Assert-TrustedReleaseTree $venv
        return $python
    } finally {
        if ($locked) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}
