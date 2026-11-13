#Requires -Version 5.1
<# Unelevated launcher. Elevated code is inline; only verified protected release files execute. #>
param(
    [Parameter(Mandatory=$true)][string]$PackagePath,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedPackageSha256,
    [Parameter(Mandatory=$true)][string]$LanAddress,
    [Parameter(Mandatory=$true)][string]$InterfaceAlias,
    [Parameter(Mandatory=$true)][string]$SafeResultPath,
    [ValidateRange(20000,65535)][int]$Port = 28443,
    [switch]$Preview
)
$ErrorActionPreference = 'Stop'
$package = [IO.Path]::GetFullPath($PackagePath)
$result = [IO.Path]::GetFullPath($SafeResultPath)
$sourceRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
if (-not $package.StartsWith($sourceRoot + '\',[StringComparison]::OrdinalIgnoreCase) -or
    (Split-Path -Leaf $package) -ne 'RAVEN-X-Server-0.5.0-ws03b-rc7.zip') {
    throw 'Launcher accepts only the reviewed WS-03B RC7 package in the current source tree.'
}
if ((Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash -ine $ExpectedPackageSha256) {
    throw 'Source package does not match the independently recorded digest.'
}
if (Test-Path -LiteralPath $result) { throw 'Result path already exists.' }
$base = Join-Path $env:ProgramFiles 'RavenXRuntime\Python313\python.exe'
if ((Get-AuthenticodeSignature -LiteralPath $base).Status -ne 'Valid') {
    throw 'Protected Python runtime signature is invalid.'
}
$guid = [guid]::NewGuid().ToString('N')
$root = Join-Path (Join-Path $env:ProgramData 'RAVEN-X') ('ws03b-disposable-' + $guid)
$sourceLiteral = $package.Replace("'","''")
$resultLiteral = $result.Replace("'","''")
$baseLiteral = $base.Replace("'","''")
$rootLiteral = $root.Replace("'","''")
$shaLiteral = $ExpectedPackageSha256.ToLowerInvariant()
$lanLiteral = $LanAddress.Replace("'","''")
$interfaceLiteral = $InterfaceAlias.Replace("'","''")
$script = @"
`$ErrorActionPreference='Stop'
`$source='$sourceLiteral'
`$result='$resultLiteral'
`$base='$baseLiteral'
`$root='$rootLiteral'
`$expected='$shaLiteral'
`$lan='$lanLiteral'
`$interface='$interfaceLiteral'
`$port=$Port
`$phase='parent'
try {
  `$parent=Split-Path -Parent `$root
  `$parentAcl=Get-Acl -LiteralPath `$parent
  if (-not `$parentAcl.AreAccessRulesProtected -or
      `$parentAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')) {
    throw 'Protected staging parent is not Administrator/SYSTEM controlled.'
  }
  foreach(`$ace in `$parentAcl.GetAccessRules(`$true,`$true,[Security.Principal.SecurityIdentifier])) {
    if (`$ace.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')) {
      throw 'Protected staging parent has unexpected access.'
    }
  }
  if (Test-Path -LiteralPath `$root) { throw 'Disposable root already exists.' }
  function Protect-FreshDirectory([string]`$path) {
    New-Item -ItemType Directory -Path `$path -ErrorAction Stop | Out-Null
    & icacls.exe `$path '/inheritance:r' | Out-Null
    if (`$LASTEXITCODE -ne 0) { throw 'Could not protect directory inheritance.' }
    & icacls.exe `$path '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if (`$LASTEXITCODE -ne 0) { throw 'Could not restrict directory access.' }
    & icacls.exe `$path '/setowner' '*S-1-5-32-544' | Out-Null
    if (`$LASTEXITCODE -ne 0) { throw 'Could not set directory owner.' }
  }
  `$phase='stage'
  Protect-FreshDirectory `$root
  `$install=Join-Path `$root 'RAVEN-X'
  Protect-FreshDirectory `$install
  `$stage=Join-Path `$install 'Server.ws03.stage'
  Protect-FreshDirectory `$stage
  `$zip=Join-Path `$install 'Server.ws03-package.zip'
  Copy-Item -LiteralPath `$source -Destination `$zip -ErrorAction Stop
  & icacls.exe `$zip '/inheritance:r' | Out-Null
  if (`$LASTEXITCODE -ne 0) { throw 'Could not protect package inheritance.' }
  & icacls.exe `$zip '/grant:r' '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
  if (`$LASTEXITCODE -ne 0) { throw 'Could not restrict package access.' }
  & icacls.exe `$zip '/setowner' '*S-1-5-32-544' | Out-Null
  if (`$LASTEXITCODE -ne 0) { throw 'Could not set package owner.' }
  if ((Get-FileHash -LiteralPath `$zip -Algorithm SHA256).Hash -ine `$expected) {
    throw 'Protected package digest differs.'
  }
  `$phase='extract'
  Expand-Archive -LiteralPath `$zip -DestinationPath `$stage -ErrorAction Stop
  Push-Location `$stage
  try {
    & `$base -B -E -s scripts/build-server-release.py verify-extracted `$zip --root `$stage --expected-sha256 `$expected | Out-Null
    if (`$LASTEXITCODE -ne 0) { throw 'Protected extracted release failed verification.' }
  } finally { Pop-Location }
  `$phase='rehearsal'
  & (Join-Path `$stage 'scripts\ws03b-privileged-rehearsal.ps1') -RehearsalRoot `$root -ExpectedPackageSha256 `$expected -LanAddress `$lan -InterfaceAlias `$interface -BasePython `$base -SafeResultPath `$result -Port `$port
  if (`$LASTEXITCODE -ne 0) { exit 2 }
  exit 0
} catch {
  [ordered]@{status='failed';phase=`$phase;root=`$root;error_type=`$_.Exception.GetType().Name;
             synthetic_only=`$true;live_state_touched=`$false} | ConvertTo-Json |
    Set-Content -LiteralPath `$result -Encoding UTF8
  exit 2
}
"@
$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
if ($Preview) { Write-Output $script; return }
$powershell=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$process=Start-Process -FilePath $powershell -Verb RunAs -ArgumentList ('-NoProfile -NonInteractive -EncodedCommand ' + $encoded) -Wait -PassThru
Write-Output ('elevated_exit=' + $process.ExitCode)
Write-Output ('result_path=' + $result)
if (Test-Path -LiteralPath $result) { Get-Content -LiteralPath $result }
if ($process.ExitCode -ne 0) { exit $process.ExitCode }
