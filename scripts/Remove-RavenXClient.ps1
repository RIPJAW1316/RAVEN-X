#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Remove a partial RAVEN-X endpoint install or reset the client completely.
.DESCRIPTION
Recovery refuses clients with a stored identity. Uninstall deletes local identity
and approved RAVEN-X client artifacts. It does not revoke the endpoint in Omen.
Run in 64-bit Administrator PowerShell. Use -WhatIf to preview either mode.
#>
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param([ValidateSet('Recovery','Uninstall')][string]$Mode = 'Recovery')

$ErrorActionPreference = 'Stop'
if (-not [Environment]::Is64BitProcess) { throw 'Use native 64-bit Administrator PowerShell.' }
$programFiles = [Environment]::GetFolderPath('ProgramFiles')
$programData = [Environment]::GetFolderPath('CommonApplicationData')
foreach ($base in @($programFiles,$programData)) {
    if ($base -notmatch '\A[A-Za-z]:\\[^\\]' -or
        [IO.Path]::GetFullPath($base) -ine $base) { throw 'Unexpected Windows installation directory.' }
}

$agentParent = Join-Path $programFiles 'RavenX'
$dataParent = Join-Path $programData 'RavenX'
$agent = Join-Path $agentParent 'Agent'
$data = Join-Path $dataParent 'agent'
$runtime = Join-Path $programFiles 'RavenXRuntime'
$taskName = 'RAVEN-X Endpoint Agent'
$trustedOwners = @('S-1-5-18','S-1-3-0','S-1-5-32-544',
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
$writeMask = 0x10000000 -bor 0x40000000 -bor 0xD0156

function Get-ExistingItem([string]$Path) {
    try { Get-Item -LiteralPath $Path -Force -ErrorAction Stop }
    catch [Management.Automation.ItemNotFoundException] { }
}

function Assert-NormalItem($Item) {
    if ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Removal stopped at a reparse point: $($Item.FullName)"
    }
}

function Assert-ProtectedDirectory($Item) {
    if (-not $Item.PSIsContainer) { throw "Expected a directory: $($Item.FullName)" }
    $acl = Get-Acl -LiteralPath $Item.FullName
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trustedOwners) {
        throw "Unexpected directory owner: $($Item.FullName)"
    }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $trustedOwners -and
            (([int]$rule.FileSystemRights -band $writeMask) -ne 0)) {
            throw "Directory has an untrusted write grant: $($Item.FullName)"
        }
    }
}

function Get-RemovalInventory($Item) {
    Assert-NormalItem $Item
    if ($Item.PSIsContainer) {
        Assert-ProtectedDirectory $Item
        foreach ($child in Get-ChildItem -LiteralPath $Item.FullName -Force) {
            Get-RemovalInventory $child
        }
    }
    $Item
}

function Get-OwnedTask {
    $matches = @(Get-ScheduledTask | Where-Object TaskName -eq $taskName)
    if ($matches.Count -eq 0) { return }
    if ($matches.Count -ne 1) { throw 'Multiple scheduled tasks share the RAVEN-X task name.' }
    $task = $matches[0]
    $actions = @($task.Actions)
    if ($task.TaskPath -ne '\' -or $task.Principal.UserId -notin @('SYSTEM','NT AUTHORITY\SYSTEM','S-1-5-18') -or
        $actions.Count -ne 1 -or $actions[0].Execute -ine (Join-Path $agent 'venv\Scripts\python.exe') -or
        $actions[0].WorkingDirectory -ine $agent -or $actions[0].Arguments -notmatch '(?:^| )-m backend\.agent run(?: |$)') {
        throw 'Scheduled task configuration differs from the RAVEN-X client task.'
    }
    $task
}

$newLock = $false
$removalLock = [Threading.Mutex]::new($false,'Global\NorthCypher-RavenX-Endpoint-Removal',[ref]$newLock)
try {
    if (-not $newLock) { throw 'Another RAVEN-X removal is in progress.' }
    $setupLock = $null
    try {
        $setupLock = [Threading.Mutex]::OpenExisting('Global\NorthCypher-RavenX-Endpoint-Setup')
    } catch [Threading.WaitHandleCannotBeOpenedException] { }
    if ($null -ne $setupLock) { $setupLock.Dispose(); throw 'Close RAVEN-X Setup before removing the client.' }

    foreach ($base in @($programFiles,$programData)) {
        for ($ancestor = $base; $ancestor; $ancestor = Split-Path -Parent $ancestor) {
            Assert-NormalItem (Get-Item -LiteralPath $ancestor -Force)
        }
    }
    $roots = @()
    foreach ($pair in @(@($agentParent,'Agent'),@($dataParent,'agent'))) {
        $parent = Get-ExistingItem $pair[0]
        if ($null -eq $parent) { continue }
        Assert-NormalItem $parent
        Assert-ProtectedDirectory $parent
        foreach ($child in Get-ChildItem -LiteralPath $parent.FullName -Force) {
            if ($child.Name -ine $pair[1] -or -not $child.PSIsContainer) {
                throw "Unexpected content in client directory: $($child.FullName)"
            }
            Assert-NormalItem $child
        }
        $roots += $parent
    }
    if ($Mode -eq 'Recovery') {
        foreach ($name in @('credential.bin','renewal.bin','credential.bin.*.tmp','renewal.bin.*.tmp')) {
            if (Test-Path -LiteralPath $data -PathType Container) {
                if (Get-ChildItem -LiteralPath $data -Force -Filter $name) {
                    throw 'Enrollment state exists. Use Uninstall to reset an enrolled client.'
                }
            }
        }
    }
    foreach ($name in @('RavenXSetup','RavenXRelease','RavenXRuntime')) {
        $parent = Get-ExistingItem (Join-Path $programFiles $name)
        if ($null -eq $parent) { continue }
        Assert-NormalItem $parent
        Assert-ProtectedDirectory $parent
        if ($name -eq 'RavenXRuntime') {
            $allowed = '^(Python313-3\.13\.17|python-3\.13\.17-amd64\.zip)$'
        } elseif ($name -eq 'RavenXSetup') {
            $allowed = '^1\.0\.0-rc\d+-\d{8}-\d{6}-\d+$'
        } else {
            $allowed = '^1\.0\.0-rc\d+$'
        }
        $children = @(Get-ChildItem -LiteralPath $parent.FullName -Force)
        $owned = @($children | Where-Object Name -Match $allowed)
        if ($owned.Count -eq $children.Count) { $roots += $parent }
        else { $roots += $owned }
    }
    $task = Get-OwnedTask
    $inventory = @(foreach ($root in $roots) { Get-RemovalInventory $root })
    if (-not $task -and -not $inventory) {
        Write-Host 'No RAVEN-X client installation artifacts found.'
        return
    }
    foreach ($root in $roots) { Write-Host "  $($root.FullName)" }
    if ($task) { Write-Host "  Scheduled task: $taskName" }
    if (-not $PSCmdlet.ShouldProcess('this computer', "RAVEN-X client $Mode")) { return }
    if ($task) {
        $scheduler = New-Object -ComObject 'Schedule.Service'
        $scheduler.Connect()
        $registered = $scheduler.GetFolder('\').GetTask($taskName)
        Disable-ScheduledTask -InputObject $task | Out-Null
        if ($registered.GetInstances(0).Count -gt 0) { $registered.Stop(0) }
        $deadline = [DateTime]::UtcNow.AddSeconds(15)
        while ($registered.GetInstances(0).Count -gt 0 -and [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 200
        }
        if ($registered.GetInstances(0).Count -gt 0) { throw 'Agent task has not stopped. Retry after it exits.' }
        $task = Get-OwnedTask
        if ($task) { Unregister-ScheduledTask -InputObject $task -Confirm:$false }
    }
    # Build the inventory again after stopping the task so late writes are included.
    $inventory = @(foreach ($root in $roots) { Get-RemovalInventory $root })
    foreach ($entry in $inventory) {
        $item = Get-ExistingItem $entry.FullName
        if ($null -eq $item) { continue }
        Assert-NormalItem $item
        if ($item.PSIsContainer -and (Get-ChildItem -LiteralPath $item.FullName -Force)) {
            throw "A directory changed during removal. Run removal again: $($item.FullName)"
        }
        Remove-Item -LiteralPath $item.FullName -Force -Confirm:$false
    }
    if ((Get-OwnedTask) -or @($roots | Where-Object { Get-ExistingItem $_.FullName }).Count) {
        throw 'RAVEN-X client removal could not be verified.'
    }
    Write-Host "RAVEN-X client $Mode complete."
} finally { $removalLock.Dispose() }
