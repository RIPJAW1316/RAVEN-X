#Requires -Version 5.1
#Requires -RunAsAdministrator
<# Start a fresh college pilot control plane. Never changes the installed server. #>
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^\d{1,3}(\.\d{1,3}){3}$')][string]$LabAddress,
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9-]{0,31}$')][string]$PilotName = 'college',
    [ValidateRange(1024,65535)][int]$Port = 8443,
    # Local AI is part of this pilot when the loopback model is available.
    # An operator can explicitly pass -EnableLocalAi:$false for recovery.
    [switch]$EnableLocalAi = $true,
    [switch]$DisableLocalAi,
    [switch]$LoopbackOnly,
    [switch]$ManagedByLauncher,
    [string]$AdministratorEmail
)
$ErrorActionPreference = 'Stop'
if ($ManagedByLauncher) {
    [Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
    [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
}
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$python = Join-Path $root '.venv-ravenx-313\Scripts\python.exe'
$data = Join-Path $env:ProgramData ("RAVEN-X\$PilotName-pilot")
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw 'Python 3.13 server venv is missing.' }
if (-not (Test-Path -LiteralPath (Join-Path $root 'frontend\dist\index.html') -PathType Leaf)) {
    throw 'Built portal is missing; run npm run build in frontend first.'
}
$parsed = [Net.IPAddress]::None
if (-not [Net.IPAddress]::TryParse($LabAddress, [ref]$parsed) -or
    $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
    $parsed.ToString() -cne $LabAddress) { throw 'Supply the Omen LAN IPv4 address.' }
$listeners = @('127.0.0.1')
if ($LoopbackOnly) {
    if ($LabAddress -ne '127.0.0.1') { throw 'Loopback mode requires address 127.0.0.1.' }
} else {
    $bytes = $parsed.GetAddressBytes()
    if ($bytes[0] -ne 10 -and -not ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -and
        -not ($bytes[0] -eq 192 -and $bytes[1] -eq 168)) { throw 'Select a private LAN IPv4 address.' }
    $assigned = @(Get-NetIPAddress -IPAddress $LabAddress -AddressFamily IPv4 -ErrorAction Stop)
    if ($assigned.Count -ne 1) { throw 'Address is not assigned to exactly one Omen interface.' }
    $profile = Get-NetConnectionProfile -InterfaceIndex $assigned[0].InterfaceIndex -ErrorAction Stop
    if ($profile.NetworkCategory -ne 'Private') { throw 'The pilot LAN must be a Private Windows network.' }
    $listeners += $LabAddress
}
if (@(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue).Count -gt 0) {
    throw 'The requested port already has a listener.'
}
$tls = Join-Path $data 'tls\server.pem'
$ca = Join-Path $data 'tls\ca.pem'
$newLock = $false
$pilotLock = [Threading.Mutex]::new($false, ('Global\NorthCypher-RavenX-Pilot-' + $PilotName.ToLowerInvariant()), [ref]$newLock)
$locationPushed = $false
try {
    if (-not $newLock) { throw 'This pilot is already starting or running.' }
    $firstRun = -not (Test-Path -LiteralPath $data)
    if (-not $firstRun -and (-not (Test-Path -LiteralPath $tls) -or -not (Test-Path -LiteralPath $ca) -or
        -not (Test-Path -LiteralPath (Join-Path $data 'raven_x.db')))) {
        throw 'Pilot data is partial; inspect it before retrying.'
    }
    Push-Location $root
    $locationPushed = $true
    if ($EnableLocalAi -and -not $DisableLocalAi) {
        $modelId = 'meta-llama-3.1-8b-instruct'
        $baseUrl = 'http://127.0.0.1:1234/v1'
        try {
            $models = Invoke-RestMethod -Method Get -Uri "$baseUrl/models" -TimeoutSec 10 -ErrorAction Stop
        } catch {
            throw 'LM Studio is not reachable on Omen loopback port 1234. Start its local server and load the model before enabling AI.'
        }
        if ($modelId -cnotin @($models.data | ForEach-Object { [string]$_.id })) {
            throw 'LM Studio does not list the required meta-llama-3.1-8b-instruct model as loaded.'
        }
        $env:RAVENX_LOCAL_AI_BASE_URL = $baseUrl
        $env:RAVENX_LOCAL_AI_MODEL = $modelId
        $env:RAVENX_LOCAL_AI_TIMEOUT_SECONDS = '120'
        $env:RAVENX_LOCAL_AI_MAX_OUTPUT_TOKENS = '512'
        $env:RAVENX_LOCAL_AI_ENABLED = 'true'
        Write-Host "Local AI enabled through Omen loopback: $modelId"
    } else {
        $env:RAVENX_LOCAL_AI_ENABLED = 'false'
    }
    if ($firstRun) {
        $adminEmail = if ($ManagedByLauncher) { $AdministratorEmail } else { Read-Host 'Pilot administrator email' }
        if ($adminEmail -notmatch '^[^\s@]+@[^\s@]+$') { throw 'Enter a valid administrator email.' }
        $password = $null
        if ($ManagedByLauncher) {
            $password = [Console]::In.ReadLine()
            if ($null -eq $password -or $password.Length -lt 12 -or $password.Length -gt 128) {
                throw 'Enter an administrator password of 12 to 128 characters.'
            }
        }
        try {
            Write-Host 'Creating a separate protected pilot database and certificate.'
            & $python -B -E -s -m backend.cli tls-init --data-dir $data --host $LabAddress
            if ($LASTEXITCODE -ne 0) { throw 'Pilot TLS initialization failed; preserve the partial data.' }
            & $python -B -E -s -m backend.cli migrate --data-dir $data
            if ($LASTEXITCODE -ne 0) { throw 'Pilot migration failed; preserve the partial data.' }
            $bootstrap = @('-B','-E','-s','-X','utf8','-m','backend.cli','bootstrap','--data-dir',$data,
                '--email',$adminEmail,'--organization','RAVEN-X College Pilot')
            if ($ManagedByLauncher) {
                $OutputEncoding = [Text.UTF8Encoding]::new($false)
                $password | & $python @bootstrap --password-stdin
            } else {
                & $python @bootstrap
            }
            if ($LASTEXITCODE -ne 0) { throw 'Pilot bootstrap failed; preserve the partial data.' }
        } finally { $password = $null }
    }
    $hostArgs = @(foreach ($address in $listeners) { '--host'; $address })
    & $python -B -E -s -m backend.application.ops.listeners --certificate $tls @hostArgs
    if ($LASTEXITCODE -ne 0) { throw 'Pilot certificate does not cover this address. Choose its original address or create a separate pilot.' }
    $digest = (Get-FileHash -LiteralPath $ca -Algorithm SHA256).Hash
    Write-Host "Omen portal: https://${LabAddress}:$Port"
    Write-Host "Public CA PEM: $ca"
    Write-Host "Public CA SHA-256: $digest"
    $serve = @('-B','-E','-s','-m','backend.cli','serve','--data-dir',$data,'--port',$Port)
    $serve += @(foreach ($address in $listeners) { '--listen-host'; $address })
    if ($ManagedByLauncher) { $serve += '--stop-on-stdin-eof' }
    & $python @serve
    if ($LASTEXITCODE -ne 0) { throw "Pilot server exited with code $LASTEXITCODE." }
} finally {
    if ($locationPushed) { Pop-Location }
    $pilotLock.Dispose()
}
