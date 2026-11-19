#Requires -Version 5.1
#Requires -RunAsAdministrator
param([Parameter(Mandatory=$true)][string]$ConfigPath)
$ErrorActionPreference = 'Stop'
$phase = 'initialization'
$sessionVerified = $false
$session = Split-Path -Parent $ConfigPath
$payload = Split-Path -Parent $PSScriptRoot
$token = $null

function Read-RavenXSetupConnection([string]$Path) {
    $config = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    $keys = @($config.PSObject.Properties.Name | Sort-Object)
    if (($keys -join ',') -cne 'ca_path,ca_sha256,enrollment_id,server_url') { throw 'Unexpected connection settings.' }
    foreach ($key in $keys) { if ($config.$key -isnot [string] -or -not $config.$key) { throw 'Missing connection setting.' } }
    [guid]$id = $config.enrollment_id
    if ($id -eq [guid]::Empty) { throw 'Use a fresh enrollment ID from the Omen portal.' }
    if ($config.ca_sha256 -cnotmatch '\A[0-9a-fA-F]{64}\z') { throw 'CA fingerprint must contain 64 hexadecimal characters.' }
    if ($config.server_url -notmatch '\Ahttps://[a-zA-Z0-9.:-]+/?\z') { throw 'Use a plain HTTPS server origin, including the port.' }
    $uri = [Uri]$config.server_url
    if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or -not $uri.Host -or $uri.UserInfo -or $uri.Query -or $uri.Fragment) {
        throw 'Invalid Omen HTTPS origin.'
    }
    if (-not (Test-Path -LiteralPath $config.ca_path -PathType Leaf)) { throw 'The selected CA file does not exist on this computer.' }
    return $config
}

try {
    if (-not [Environment]::Is64BitProcess) { throw 'Setup requires native 64-bit PowerShell.' }
    $expectedConfig = Join-Path (Split-Path -Parent $payload) 'session\connection.json'
    if ([IO.Path]::GetFullPath($ConfigPath) -ine $expectedConfig) { throw 'Unexpected setup configuration path.' }
    . (Join-Path $PSScriptRoot 'release-integrity.ps1')
    $phase = 'release verification'
    Write-Host '[1/4] Verifying installer payload and public connection settings'
    Assert-VerifiedRelease $payload | Out-Null
    Assert-TrustedReleaseTree $session
    $sessionVerified = $true
    $line = [Console]::In.ReadLine()
    try {
        if ($line -cnotmatch '\A[A-Za-z0-9_-]{43}\z') { throw 'The setup wizard did not supply a valid bootstrap token.' }
        $token = ConvertTo-SecureString -String $line -AsPlainText -Force
    } finally { $line = $null }
    $config = Read-RavenXSetupConnection $ConfigPath
    [guid]$enrollmentId = $config.enrollment_id
    # Do not install a runtime or modify an existing endpoint before detecting it.
    foreach ($path in @((Join-Path $env:ProgramFiles 'RavenX'),(Join-Path $env:ProgramData 'RavenX'))) {
        if (Test-Path -LiteralPath $path) { throw ('Existing agent state requires recovery; it will not be overwritten: '+$path) }
    }
    if (Get-ScheduledTask -TaskName 'RAVEN-X Endpoint Agent' -ErrorAction SilentlyContinue) { throw 'Agent task already exists.' }
    $phase = 'Python runtime'
    Write-Host '[2/4] Preparing and verifying bundled Python (this may take several minutes)'
    . (Join-Path $PSScriptRoot 'managed-python.ps1')
    $python = Ensure-RavenXManagedPython -ArchivePath (Join-Path $payload 'runtime\python-3.13.17-amd64.zip')
    $phase = 'HTTPS trust'
    Write-Host '[3/4] Checking Omen HTTPS, certificate name, dates and CA fingerprint'
    try {
        # Windows PowerShell 5.1 wraps redirected native stderr as error records.
        $ErrorActionPreference = 'Continue'
        $trustOutput = & $python -B -I (Join-Path $payload 'backend\agent\trust.py') --server $config.server_url --ca-cert $config.ca_path --expected-ca-sha256 $config.ca_sha256 2>&1
    } finally { $ErrorActionPreference = 'Stop' }
    if ($LASTEXITCODE -ne 0) { throw ($trustOutput -join ' ') }
    $phase = 'agent installation and enrollment'
    Write-Host '[4/4] Installing and enrolling the agent'
    $arguments = @{ServerUrl=$config.server_url;EnrollmentId=$enrollmentId;CaCertPath=$config.ca_path;CaCertSha256=$config.ca_sha256;BootstrapToken=$token;AllowEnrollmentRetry=$true}
    & (Join-Path $PSScriptRoot 'install-agent.ps1') @arguments
    'Installed and enrolled. Approve this computer in Omen Enrollment, then check Fleet for Online.' | Set-Content -LiteralPath (Join-Path $session 'result.txt') -Encoding UTF8
    exit 0
} catch {
    $message = $_.Exception.Message
    Write-Host ("SETUP STOPPED during: "+$phase) -ForegroundColor Red
    Write-Host $message
    # No transcript, Python input or token is saved. This contains public error metadata only.
    try { if ($sessionVerified) {
        ("Failed during: "+$phase+"`r`n"+$message) | Set-Content -LiteralPath (Join-Path $session 'result.txt') -Encoding UTF8
    } } catch { Write-Host 'Could not save the setup error summary.' }
    exit 1
} finally {
    if ($null -ne $token) { $token.Dispose() }
}
