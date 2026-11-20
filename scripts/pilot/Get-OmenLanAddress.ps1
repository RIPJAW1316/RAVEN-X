#Requires -Version 5.1
# Both the address picker and the final bind check use this inventory.
$ErrorActionPreference = 'Stop'
$adapters = @(Get-NetAdapter | Where-Object Status -eq 'Up')
$profiles = @(Get-NetConnectionProfile)
$defaultRoutes = @(Get-NetRoute -AddressFamily IPv4 | Where-Object DestinationPrefix -eq '0.0.0.0/0')
$addresses = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object AddressState -eq 'Preferred')
foreach ($adapter in $adapters) {
    $idx = $adapter.ifIndex
    $categories = @($profiles | Where-Object InterfaceIndex -eq $idx | ForEach-Object NetworkCategory)
    $private = $categories.Count -eq 1 -and $categories[0] -eq 'Private'
    $isolated = $categories.Count -eq 0 -and
        $adapter.DriverFileName -ieq 'VBoxNetAdp6.sys' -and
        $adapter.InterfaceDescription -match '^VirtualBox Host-Only Ethernet Adapter(?: #\d+)?$' -and
        $idx -notin $defaultRoutes.InterfaceIndex
    if (-not ($private -or $isolated)) { continue }
    foreach ($entry in $addresses | Where-Object InterfaceIndex -eq $idx) {
        if ($entry.IPAddress -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)' -and
            @($addresses | Where-Object IPAddress -eq $entry.IPAddress).Count -eq 1) {
            $entry.IPAddress
        }
    }
}
