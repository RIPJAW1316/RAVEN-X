# Full offline CPython, installed/reused only after protected-path verification.
# Requires release-integrity.ps1. No MSI, launcher registration or PATH changes.
function New-RavenXProtectedDirectory([string]$Path) {
    if (Test-Path -LiteralPath $Path) { throw 'Protected directory already exists.' }
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    $admins = New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'
    $acl.SetOwner($admins)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $identity = New-Object Security.Principal.SecurityIdentifier $sid
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        $acl.AddAccessRule($rule)
    }
    [IO.Directory]::CreateDirectory($Path,$acl) | Out-Null
    Assert-TrustedReleaseTree $Path
}

function Ensure-RavenXManagedPython {
    param(
        [Parameter(Mandatory=$true)][string]$ArchivePath,
        [string]$RuntimeParent = (Join-Path $env:ProgramFiles 'RavenXRuntime')
    )
    $expected = 'B26CA4B4EE51E157836049934D2B8EABD55939BE296F3130254251B6DF96EC2F'
    if (-not [Environment]::Is64BitProcess) { throw 'Native 64-bit Windows PowerShell is required.' }
    $pf = [IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\')
    $RuntimeParent = [IO.Path]::GetFullPath($RuntimeParent).TrimEnd('\')
    if (-not $RuntimeParent.StartsWith($pf+'\',[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Runtime must be inside protected Program Files.'
    }
    # Check every existing ancestor without recursively traversing Program Files.
    $ancestor = Split-Path -Parent $RuntimeParent
    $trusted = @('S-1-3-0','S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $mask = 0x10000000 -bor 0x40000000 -bor 0xD0156
    while ($true) {
        $item = Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop
        $acl = Get-Acl -LiteralPath $ancestor -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) {
            throw 'Runtime ancestry is not protected.'
        }
        foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $trusted -and
                (([int]$rule.FileSystemRights -band $mask) -ne 0)) { throw 'Runtime ancestor is user-writable.' }
        }
        if ($ancestor -ieq $pf) { break }
        $ancestor = Split-Path -Parent $ancestor
    }
    if ((Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash -ine $expected) {
        throw 'Bundled Python archive hash mismatch.'
    }
    $target = Join-Path $RuntimeParent 'Python313-3.13.17'
    if (Test-Path -LiteralPath $RuntimeParent) {
        Assert-TrustedReleaseTree $RuntimeParent
        if (-not (Test-Path -LiteralPath (Join-Path $target 'python.exe') -PathType Leaf)) {
            throw 'Existing managed runtime is incomplete. Preserve it for inspection.'
        }
    } else {
        New-RavenXProtectedDirectory $RuntimeParent
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::ExtractToDirectory($ArchivePath,$target)
        & "$env:WINDIR\System32\icacls.exe" $target '/setowner' '*S-1-5-32-544' '/T' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not set Python runtime ownership.' }
    }
    Assert-TrustedReleaseTree $target
    # Reuse is verified against the original archive, not just python.exe.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        foreach ($entry in $archive.Entries) {
            if ($entry.FullName.EndsWith('/')) { continue }
            $file = [IO.Path]::GetFullPath((Join-Path $target $entry.FullName.Replace('/','\')))
            if (-not $file.StartsWith($target+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe runtime archive member.' }
            $stream = $entry.Open()
            try { $digest = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','') } finally { $stream.Dispose() }
            if (-not (Test-Path -LiteralPath $file -PathType Leaf) -or
                (Get-Item -LiteralPath $file).Length -ne $entry.Length -or
                (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ine $digest) {
                throw ('Managed Python file differs from the official archive: '+$entry.FullName)
            }
        }
    } finally { $sha.Dispose(); $archive.Dispose() }
    foreach ($name in @('python.exe','python313.dll')) {
        $signature = Get-AuthenticodeSignature -LiteralPath (Join-Path $target $name)
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Python Software Foundation') {
            throw ('Python signature verification failed: '+$name)
        }
    }
    $python = Join-Path $target 'python.exe'
    $result = & $python -B -I -c 'import sys,platform,ssl,venv,ensurepip;print(str(sys.version_info.major)+chr(124)+str(sys.version_info.minor)+chr(124)+platform.machine())'
    if ($LASTEXITCODE -ne 0 -or $result -ne '3|13|AMD64') { throw 'Python 3.13 AMD64 prerequisite check failed.' }
    return $python
}
