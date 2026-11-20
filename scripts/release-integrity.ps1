# Verify only a frozen installer payload in a protected Program Files stage.
# The independent SHA-256 of Setup.exe is the authenticity root; this manifest
# protects extracted bytes and detects omission or addition before execution.

function Assert-ReleaseManifestFiles {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [ValidatePattern('\A[0-9a-fA-F]{64}\z')][string]$ExpectedManifestSha256
    )
    $rootItem = Get-Item -LiteralPath $Root -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Release stage is not a normal directory.'
    }
    $manifestPath = Join-Path $rootItem.FullName 'release-manifest.json'
    $manifestItem = Get-Item -LiteralPath $manifestPath -Force -ErrorAction Stop
    if (($manifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $manifestItem.Length -gt 262144) {
        throw 'Release manifest is unsafe.'
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    if ($manifest.format -ne 1) { throw 'Release manifest format is unexpected.' }
    if ($ExpectedManifestSha256) {
        if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash -ine $ExpectedManifestSha256 -or
            $manifest.version -ne '1.0.0' -or
            $manifest.package -ne 'RAVEN-X Enterprise Endpoint Agent' -or
            [string]$manifest.source_commit -cnotmatch '\A[0-9a-f]{40}\z') {
            throw 'Release manifest differs from the compiled installer.'
        }
    } elseif ($manifest.version -ne '1.0.0-rc11' -or
        $manifest.source_baseline -ne 'b53ac0fea11432badcc13e89d0d0f3966d1689bd' -or
        $manifest.accepted_diff_sha256 -ne '2a2a8693049af4644312d8e234c6cd5c589c317792326c4e2aecd354c10aa34c') {
        throw 'Release manifest identity is unexpected.'
    }
    $expected = @{}
    foreach ($entry in @($manifest.files)) {
        $relative = [string]$entry.path
        if ($relative -notmatch '\A[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\z' -or
            @($relative.Split('/')) -contains '..' -or @($relative.Split('/')) -contains '.' -or
            $relative -eq 'release-manifest.json' -or
            [string]$entry.sha256 -notmatch '\A[0-9a-f]{64}\z' -or
            $expected.ContainsKey($relative)) {
            throw 'Release manifest contains an unsafe or duplicate entry.'
        }
        $expected[$relative] = $entry
    }
    if ($expected.Count -lt 1) { throw 'Release manifest has no payload.' }
    $seen = @{}
    $pending = [Collections.Generic.Stack[System.IO.DirectoryInfo]]::new()
    $pending.Push([IO.DirectoryInfo]$rootItem)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($item in @(Get-ChildItem -LiteralPath $directory.FullName -Force -ErrorAction Stop)) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Release payload contains a reparse point.'
            }
            if ($item.PSIsContainer) {
                $pending.Push([IO.DirectoryInfo]$item)
                continue
            }
            $relative = $item.FullName.Substring($rootItem.FullName.TrimEnd('\').Length + 1).Replace('\', '/')
            if ($relative -eq 'release-manifest.json') { continue }
            if (-not $expected.ContainsKey($relative) -or $seen.ContainsKey($relative)) {
                throw 'Release payload has an unexpected or duplicate file.'
            }
            $entry = $expected[$relative]
            if ($item.Length -ne [long]$entry.size -or
                (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash -ine [string]$entry.sha256) {
                throw 'Release payload file differs from its manifest.'
            }
            $seen[$relative] = $true
        }
    }
    if ($seen.Count -ne $expected.Count) { throw 'Release payload is incomplete.' }
    return $manifest
}

function Assert-TrustedReleaseTree {
    param([Parameter(Mandatory = $true)][string]$Root)
    $programFiles = [IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\')
    $full = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    if (-not $full.StartsWith($programFiles + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Release stage must be below protected Program Files.'
    }
    $trusted = @('S-1-3-0', 'S-1-5-18', 'S-1-5-32-544',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $writeMask = 0x10000000 -bor 0x40000000 -bor 0x00080000 -bor 0x00040000 -bor 0x00010000 -bor `
        0x00000002 -bor 0x00000004 -bor 0x00000010 -bor 0x00000100 -bor 0x00000040
    $paths = [Collections.Generic.List[string]]::new()
    $current = $full
    while ($current.Length -ge $programFiles.Length) {
        $paths.Add($current)
        if ($current -ieq $programFiles) { break }
        $current = Split-Path -Parent $current
    }
    if ($paths[$paths.Count - 1] -ine $programFiles) { throw 'Release stage escaped Program Files.' }
    foreach ($path in $paths) {
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Release stage ancestry contains a reparse point.'
        }
        $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin $trusted) { throw 'Release stage ancestry has an unauthorized owner.' }
        foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                $rule.IdentityReference.Value -notin $trusted -and
                (([int]$rule.FileSystemRights -band $writeMask) -ne 0)) {
                throw 'Release stage ancestry is writable by an untrusted identity.'
            }
        }
    }
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($full)
    while ($pending.Count -gt 0) {
        $path = $pending.Pop()
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Release stage contains a reparse point.'
        }
        $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin $trusted) { throw 'Release stage has an unauthorized owner.' }
        foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                $rule.IdentityReference.Value -notin $trusted -and
                (([int]$rule.FileSystemRights -band $writeMask) -ne 0)) {
                throw 'Release stage is writable by an untrusted identity.'
            }
        }
        if ($item.PSIsContainer) {
            foreach ($child in @(Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop)) {
                $pending.Push($child.FullName)
            }
        }
    }
}

function Assert-VerifiedRelease {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [ValidatePattern('\A[0-9a-fA-F]{64}\z')][string]$ExpectedManifestSha256
    )
    Assert-TrustedReleaseTree $Root
    if ($ExpectedManifestSha256) {
        return Assert-ReleaseManifestFiles $Root -ExpectedManifestSha256 $ExpectedManifestSha256
    }
    return Assert-ReleaseManifestFiles $Root
}
