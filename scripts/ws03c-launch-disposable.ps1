#Requires -Version 5.1
<# UAC launcher. The elevated command verifies a copied ZIP before running protected release code. #>
param(
    [Parameter(Mandatory=$true)][string]$PackagePath,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedPackageSha256,
    [Parameter(Mandatory=$true)][string]$SafeResultPath,
    [switch]$Preview
)
$ErrorActionPreference='Stop'
$package=[IO.Path]::GetFullPath($PackagePath)
$result=[IO.Path]::GetFullPath($SafeResultPath)
if ((Split-Path -Leaf $package) -ne 'RAVEN-X-Agent-Recovery-0.1.0-ws03c-rc6e.zip') {
    throw 'Unexpected WS-03C package name.'
}
if ((Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash -ine $ExpectedPackageSha256) {
    throw 'Source ZIP differs from the independently supplied digest.'
}
if (Test-Path -LiteralPath $result) { throw 'Result path already exists.' }
$base=Join-Path $env:ProgramFiles 'RavenXRuntime\Python313\python.exe'
if ((Get-AuthenticodeSignature -LiteralPath $base).Status -ne 'Valid') {
    throw 'Protected Python runtime signature is invalid.'
}
$guid=[guid]::NewGuid().ToString('N')
$root=Join-Path (Join-Path $env:ProgramData 'RAVEN-X') ('ws03c-disposable-'+$guid)
$sourceLiteral=$package.Replace("'","''")
$resultLiteral=$result.Replace("'","''")
$baseLiteral=$base.Replace("'","''")
$rootLiteral=$root.Replace("'","''")
$shaLiteral=$ExpectedPackageSha256.ToLowerInvariant()
$script=@"
`$ErrorActionPreference='Stop'
`$source='$sourceLiteral'
`$result='$resultLiteral'
`$base='$baseLiteral'
`$root='$rootLiteral'
`$expected='$shaLiteral'
`$phase='parent'
`$nativeExit=0
try {
  function Protect-FreshDirectory([string]`$path) {
    New-Item -ItemType Directory -Path `$path -ErrorAction Stop | Out-Null
    & icacls.exe `$path '/inheritance:r' | Out-Null
    if (`$LASTEXITCODE -ne 0) { throw 'Could not protect directory inheritance.' }
    & icacls.exe `$path '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if (`$LASTEXITCODE -ne 0) { throw 'Could not restrict directory access.' }
    & icacls.exe `$path '/setowner' '*S-1-5-32-544' | Out-Null
    if (`$LASTEXITCODE -ne 0) { throw 'Could not set directory owner.' }
  }
  `$parent=Split-Path -Parent `$root
  if (-not (Test-Path -LiteralPath `$parent)) {
    throw 'Pre-existing protected RAVEN-X disposable parent is required.'
  }
  `$acl=Get-Acl -LiteralPath `$parent
  if (-not `$acl.AreAccessRulesProtected -or
      `$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')) {
    throw 'Disposable parent is not Administrator/SYSTEM controlled.'
  }
  foreach(`$ace in `$acl.GetAccessRules(`$true,`$true,[Security.Principal.SecurityIdentifier])) {
    if (`$ace.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -or
        `$ace.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
      throw 'Disposable parent grants unexpected access.'
    }
  }
  if (Test-Path -LiteralPath `$root) { throw 'Disposable root already exists.' }
  `$phase='stage'
  Protect-FreshDirectory `$root
  `$stage=Join-Path `$root 'release'
  Protect-FreshDirectory `$stage
  `$zip=Join-Path `$root 'reviewed-release.zip'
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
  & `$base -I (Join-Path `$stage 'scripts\build-agent-recovery-release.py') verify `$zip --expected-sha256 `$expected | Out-Null
  if (`$LASTEXITCODE -ne 0) { throw 'Protected extracted package failed manifest verification.' }
  `$phase='dependencies'
  & `$base -I -m venv (Join-Path `$stage 'venv')
  `$nativeExit=`$LASTEXITCODE
  if (`$LASTEXITCODE -ne 0) { throw 'Protected recovery venv creation failed.' }
  `$python=Join-Path `$stage 'venv\Scripts\python.exe'
  `$pipArgs=@('-I','-m','pip','install','--no-index','--find-links',
      (Join-Path `$stage 'wheels'),'--require-hashes','-r',
      (Join-Path `$stage 'requirements-recovery-lock.txt'))
  & `$python @pipArgs | Out-Null
  `$nativeExit=`$LASTEXITCODE
  if (`$LASTEXITCODE -ne 0) { throw 'Offline recovery dependency installation failed.' }
  `$phase='rehearsal'
  & (Join-Path `$stage 'scripts\ws03c-privileged-rehearsal.ps1') -DisposableRoot `$root -BasePython `$base -SafeResultPath `$result
  if (`$LASTEXITCODE -ne 0) { exit 2 }
  exit 0
} catch {
  [ordered]@{status='failed';phase=`$phase;root=`$root;error_type=`$_.Exception.GetType().Name;
             native_exit=`$nativeExit;synthetic_only=`$true;live_state_touched=`$false} | ConvertTo-Json |
    Set-Content -LiteralPath `$result -Encoding UTF8
  if (`$nativeExit -ne 0) { exit `$nativeExit }
  exit 2
}
"@
$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
if ($Preview) { Write-Output $script; return }
$powershell=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$process=Start-Process -FilePath $powershell -Verb RunAs -ArgumentList ('-NoProfile -NonInteractive -EncodedCommand '+$encoded) -Wait -PassThru -WindowStyle Hidden
Write-Output ('elevated_exit='+$process.ExitCode)
Write-Output ('result_path='+$result)
if (Test-Path -LiteralPath $result) { Get-Content -LiteralPath $result }
if ($process.ExitCode -ne 0) { exit $process.ExitCode }
