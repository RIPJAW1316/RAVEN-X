#Requires -Version 5.1
#Requires -RunAsAdministrator
param([Parameter(Mandatory=$true)][string]$ArchivePath)

$ErrorActionPreference = 'Stop'
$expected = 'B26CA4B4EE51E157836049934D2B8EABD55939BE296F3130254251B6DF96EC2F'
$parent = Join-Path $env:ProgramFiles 'RavenXRuntime'
$target = Join-Path $parent 'Python313-3.13.17'
$storedArchive = Join-Path $parent 'python-3.13.17-amd64.zip'
$trusted = @('S-1-3-0','S-1-5-18','S-1-5-32-544',
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
$writeMask = 0x10000000 -bor 0x40000000 -bor 0x00080000 -bor 0x00040000 -bor `
    0x00010000 -bor 0x00000002 -bor 0x00000004 -bor 0x00000010 -bor `
    0x00000100 -bor 0x00000040

function Assert-Protected([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Runtime contains a reparse point.' }
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) {
        throw 'Runtime has an untrusted owner.'
    }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            $rule.IdentityReference.Value -notin $trusted -and
            (([int]$rule.FileSystemRights -band $writeMask) -ne 0)) {
            throw 'Runtime is writable by an untrusted identity.'
        }
    }
}

try {
    if (-not [Environment]::Is64BitOperatingSystem) { throw 'AMD64 Windows is required.' }
    if ((Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash -ine $expected) {
        throw 'Official Python archive hash mismatch.'
    }
    if (Test-Path -LiteralPath $parent) { throw 'Managed runtime parent exists; inspect it before retrying.' }
    Assert-Protected $env:ProgramFiles
    New-Item -ItemType Directory -Path $parent -ErrorAction Stop | Out-Null
    & "$env:WINDIR\System32\icacls.exe" $parent '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to grant managed runtime ACL.' }
    & "$env:WINDIR\System32\icacls.exe" $parent '/inheritance:r' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to protect managed runtime ACL.' }
    & "$env:WINDIR\System32\icacls.exe" $parent '/setowner' '*S-1-5-32-544' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to set managed runtime owner.' }
    Assert-Protected $parent
    Copy-Item -LiteralPath $ArchivePath -Destination $storedArchive -ErrorAction Stop
    & "$env:WINDIR\System32\icacls.exe" $storedArchive '/setowner' '*S-1-5-32-544' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to set protected archive owner.' }
    Assert-Protected $storedArchive
    if ((Get-FileHash -LiteralPath $storedArchive -Algorithm SHA256).Hash -ine $expected) {
        throw 'Protected Python archive hash mismatch.'
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($storedArchive,$target)
    & "$env:WINDIR\System32\icacls.exe" $target '/setowner' '*S-1-5-32-544' '/T' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to set managed runtime owners.' }
    Assert-Protected $target
    foreach ($item in @(Get-ChildItem -LiteralPath $target -Recurse -Force -ErrorAction Stop)) {
        Assert-Protected $item.FullName
    }
    foreach ($name in @('python.exe','python313.dll')) {
        $signature = Get-AuthenticodeSignature -LiteralPath (Join-Path $target $name)
        if ($signature.Status -ne 'Valid' -or
            $signature.SignerCertificate.Subject -notmatch 'Python Software Foundation') {
            throw "Official Python signature check failed: $name"
        }
    }
    $python = Join-Path $target 'python.exe'
    $runtime = & $python -I -c 'import platform,sys,venv,ensurepip;print(str(sys.version_info.major)+chr(124)+str(sys.version_info.minor)+chr(124)+platform.machine())'
    if ($LASTEXITCODE -ne 0 -or $runtime -ne '3|13|AMD64') {
        throw 'Protected Python runtime smoke test failed.'
    }
    Write-Host "Managed Python ready: $python"
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
