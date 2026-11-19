"""Fixed, read-only Windows observations adapted from the personal scanner.

Each command returns only allowlisted issue identifiers. No account names,
exclusion paths, share names, DNS addresses, or command output leave the host.
These rules deliberately make narrower claims than the personal scanner.
"""

from dataclasses import dataclass

from ..domain.assessment import FindingSeverity


@dataclass(frozen=True)
class Rule:
    title: str
    severity: FindingSeverity
    details: str


@dataclass(frozen=True)
class Check:
    name: str
    description: str
    category: str
    body: str
    rules: dict[str, Rule]


def _check(name, description, category, body, **rules):
    return Check(name, description, category, body, rules)


CHECKS = {
    "windows.updates": _check(
        "Windows Update Service", "Checks whether Windows Update is disabled; does not claim patch compliance.",
        "Windows Update", """$s=Get-CimInstance Win32_Service -Filter \"Name='wuauserv'\" -ErrorAction Stop
if($null -eq $s){throw 'service unavailable'}
if($s.StartMode -eq 'Disabled'){$issues.Add('updates.disabled')}
elseif($s.StartMode -notin @('Auto','Manual')){throw 'unknown service mode'}""",
        **{"updates.disabled": Rule("Windows Update Service Disabled", FindingSeverity.HIGH,
                                     "The Windows Update service is disabled; this check does not establish missing patches.")}),
    "windows.defender": _check(
        "Microsoft Defender", "Checks active Microsoft Defender antivirus and real-time protection.",
        "Antivirus", """$s=Get-MpComputerStatus -ErrorAction Stop
if($null -eq $s){throw 'Defender status unavailable'}
if([string]$s.AMRunningMode -ne 'Normal'){$unsupported=$true}
else {
  if($s.AntivirusEnabled -isnot [bool] -or $s.RealTimeProtectionEnabled -isnot [bool]){throw 'invalid Defender status'}
  if(-not $s.AntivirusEnabled){$issues.Add('defender.antivirus_off')}
  if(-not $s.RealTimeProtectionEnabled){$issues.Add('defender.realtime_off')}
}""",
        **{"defender.antivirus_off": Rule("Microsoft Defender Antivirus Off", FindingSeverity.HIGH,
                                           "Defender reports that its antivirus engine is disabled."),
           "defender.realtime_off": Rule("Defender Real-Time Protection Off", FindingSeverity.HIGH,
                                          "Defender reports that real-time protection is disabled.")}),
    "windows.defender-exclusions": _check(
        "Defender Exclusions", "Flags configured Defender exclusions for administrator review without disclosing their values.",
        "Antivirus", """$p=Get-MpPreference -ErrorAction Stop
if($null -eq $p){throw 'Defender preferences unavailable'}
if(@($p.ExclusionPath).Where({$null -ne $_}).Count -gt 0){$issues.Add('defender.path_exclusions')}
if(@($p.ExclusionExtension).Where({$null -ne $_}).Count -gt 0){$issues.Add('defender.extension_exclusions')}
if(@($p.ExclusionProcess).Where({$null -ne $_}).Count -gt 0){$issues.Add('defender.process_exclusions')}""",
        **{"defender.path_exclusions": Rule("Defender Path Exclusions Configured", FindingSeverity.LOW,
                                             "At least one path exclusion is configured; review against approved policy."),
           "defender.extension_exclusions": Rule("Defender Extension Exclusions Configured", FindingSeverity.LOW,
                                                  "At least one extension exclusion is configured; review against approved policy."),
           "defender.process_exclusions": Rule("Defender Process Exclusions Configured", FindingSeverity.LOW,
                                                "At least one process exclusion is configured; review against approved policy.")}),
    "windows.autologon": _check(
        "Automatic Logon", "Checks the machine AutoAdminLogon setting without reading credentials.",
        "Authentication", r"""$p=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction Stop
if([string]$p.AutoAdminLogon -eq '1'){$issues.Add('autologon.enabled')}""",
        **{"autologon.enabled": Rule("Automatic Windows Logon Enabled", FindingSeverity.HIGH,
                                      "The machine is configured for automatic interactive logon.")}),
    "windows.rdp": _check(
        "Remote Desktop and NLA", "Checks RDP enablement and Network Level Authentication policy.",
        "Remote Access", r"""$t=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop
if($t.fDenyTSConnections -eq 0){
  $issues.Add('rdp.enabled')
  try {
    $n=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction Stop
    if($null -eq $n.UserAuthentication){$partial=$true}
    elseif($n.UserAuthentication -eq 0){$issues.Add('rdp.nla_off')}
    elseif($n.UserAuthentication -ne 1){$partial=$true}
  } catch {$partial=$true}
} elseif($t.fDenyTSConnections -ne 1){throw 'invalid RDP status'}""",
        **{"rdp.enabled": Rule("Remote Desktop Enabled", FindingSeverity.LOW,
                                "RDP accepts connections if firewall policy permits; confirm it is required."),
           "rdp.nla_off": Rule("RDP Network Level Authentication Disabled", FindingSeverity.HIGH,
                              "Remote Desktop is enabled without Network Level Authentication.")}),
    "windows.guest": _check(
        "Built-In Guest Account", "Checks the built-in Guest account by SID, independent of display language.",
        "Accounts", """$u=@(Get-LocalUser -ErrorAction Stop | Where-Object {$_.SID.Value -match '-501$'})
if($u.Count -ne 1){throw 'Guest identity unavailable'}
if($u[0].Enabled -isnot [bool]){throw 'invalid Guest status'}
if($u[0].Enabled){$issues.Add('guest.enabled')}""",
        **{"guest.enabled": Rule("Built-In Guest Account Enabled", FindingSeverity.HIGH,
                                  "The built-in Guest account is enabled.")}),
    "windows.password-policy": _check(
        "Local Password Requirement", "Checks enabled local accounts that do not require a password.",
        "Authentication", """$u=@(Get-LocalUser -ErrorAction Stop | Where-Object {$_.Enabled})
foreach($a in $u){
  if($a.PasswordRequired -isnot [bool]){throw 'password requirement unavailable'}
  if(-not $a.PasswordRequired){$issues.Add('password.not_required');break}
}""",
        **{"password.not_required": Rule("Local Account Without Password Requirement", FindingSeverity.HIGH,
                                          "At least one enabled local account does not require a password; account names are withheld.")}),
    "windows.open-ports": _check(
        "Sensitive TCP Listeners", "Checks selected local TCP listening ports; does not scan the network.",
        "Network", """$p=@(Get-NetTCPConnection -State Listen -ErrorAction Stop | Select-Object -ExpandProperty LocalPort -Unique)
foreach($port in @(21,23,110,3389,5900)){
  if($p -contains $port){$issues.Add('port.'+[string]$port)}
}""",
        **{f"port.{port}": Rule(f"TCP Port {port} Listening", FindingSeverity.MEDIUM,
                                f"A service is listening locally on TCP port {port}; confirm exposure and necessity.")
           for port in (21, 23, 110, 3389, 5900)}),
    "windows.network-sharing": _check(
        "Non-Default SMB Shares", "Checks for non-special SMB shares; approved shares need human review.",
        "Network Sharing", """$s=@(Get-SmbShare -ErrorAction Stop | Where-Object {-not $_.Special})
if($s.Count -gt 0){$issues.Add('sharing.nondefault')}""",
        **{"sharing.nondefault": Rule("Non-Default SMB Share Present", FindingSeverity.LOW,
                                       "At least one non-default SMB share exists; review its access controls.")}),
    "windows.powershell-policy": _check(
        "PowerShell Execution Policy", "Reports permissive execution policy as an advisory, not a security boundary.",
        "Scripting", """Import-Module (Join-Path $PSHOME 'Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
$p=Get-ExecutionPolicy -ErrorAction Stop
if($p -in @('Bypass','Unrestricted')){$issues.Add('powershell.permissive')}
elseif($p -notin @('Restricted','AllSigned','RemoteSigned','Undefined','Default')){throw 'unknown execution policy'}""",
        **{"powershell.permissive": Rule("Permissive PowerShell Execution Policy", FindingSeverity.LOW,
                                          "PowerShell execution policy is Bypass or Unrestricted; execution policy is not a security boundary.")}),
    "windows.autorun": _check(
        "Machine AutoRun Policy", "Checks whether machine policy disables AutoRun on all drive types.",
        "AutoRun", r"""$p=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -ErrorAction Stop
if($null -eq $p.NoDriveTypeAutoRun){$issues.Add('autorun.not_enforced')}
elseif($p.NoDriveTypeAutoRun -isnot [int]){throw 'invalid AutoRun policy'}
elseif($p.NoDriveTypeAutoRun -ne 255){$issues.Add('autorun.not_enforced')}""",
        **{"autorun.not_enforced": Rule("Machine AutoRun Restriction Not Enforced", FindingSeverity.MEDIUM,
                                        "The machine policy does not disable AutoRun for every drive type.")}),
    "windows.services": _check(
        "Remote Registry Service", "Checks whether the Windows Remote Registry service is running.",
        "Services", """$s=Get-CimInstance Win32_Service -Filter \"Name='RemoteRegistry'\" -ErrorAction Stop
if($null -eq $s){throw 'service unavailable'}
if($s.State -eq 'Running'){$issues.Add('services.remote_registry')}
elseif($s.State -notin @('Stopped','Start Pending','Stop Pending','Paused','Pause Pending','Continue Pending')){throw 'unknown service state'}""",
        **{"services.remote_registry": Rule("Remote Registry Service Running", FindingSeverity.MEDIUM,
                                             "The Remote Registry service is running; confirm it is required and restricted.")}),
    "windows.ntp": _check(
        "Windows Time Service", "Checks whether the Windows Time service is disabled; does not assert NTP sync quality.",
        "Time Synchronization", """$s=Get-CimInstance Win32_Service -Filter \"Name='W32Time'\" -ErrorAction Stop
if($null -eq $s){throw 'service unavailable'}
if($s.StartMode -eq 'Disabled'){$issues.Add('time.disabled')}
elseif($s.StartMode -notin @('Auto','Manual')){throw 'unknown service mode'}""",
        **{"time.disabled": Rule("Windows Time Service Disabled", FindingSeverity.MEDIUM,
                                  "The Windows Time service is disabled; clock synchronization may be unavailable.")}),
    "windows.telnet": _check(
        "Telnet Client Feature", "Checks whether the optional Telnet Client feature is enabled.",
        "Optional Features", """$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$elevated=$identity.IsSystem -or ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if(-not $elevated){$unsupported=$true}
else {
  $f=Get-WindowsOptionalFeature -Online -FeatureName TelnetClient -ErrorAction Stop
  if($null -eq $f){throw 'feature unavailable'}
  if($f.State -eq 'Enabled'){$issues.Add('telnet.enabled')}
  elseif($f.State -notin @('Disabled','DisabledWithPayloadRemoved')){throw 'unknown feature state'}
}""",
        **{"telnet.enabled": Rule("Telnet Client Installed", FindingSeverity.MEDIUM,
                                   "The legacy Telnet Client feature is enabled.")}),
    "windows.dns": _check(
        "Active DNS Configuration", "Checks whether an active network interface has configured DNS servers.",
        "DNS", """$up=@(Get-NetAdapter -ErrorAction Stop | Where-Object {$_.Status -eq 'Up'})
if($up.Count -eq 0){$unsupported=$true}
else {
  $a=@(Get-DnsClientServerAddress -ErrorAction Stop | Where-Object {$up.ifIndex -contains $_.InterfaceIndex})
  if($a.Count -eq 0){throw 'DNS state unavailable'}
  if(@($a | Where-Object {@($_.ServerAddresses).Count -gt 0}).Count -eq 0){$issues.Add('dns.none')}
}""",
        **{"dns.none": Rule("No DNS Server on Active Interface", FindingSeverity.LOW,
                             "No DNS server is configured on an active network interface.")}),
    "windows.file-integrity": _check(
        "Core Windows Binary Signatures", "Checks Authenticode status of selected system binaries; does not replace SFC.",
        "File Integrity", """Import-Module (Join-Path $PSHOME 'Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
foreach($relative in @('System32\\kernel32.dll','System32\\user32.dll','System32\\ntdll.dll',
                       'System32\\cmd.exe','System32\\WindowsPowerShell\\v1.0\\powershell.exe')){
  $path=Join-Path $env:WINDIR $relative
  if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw 'system file unavailable'}
  $sig=Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
  if($sig.Status -ne 'Valid'){$issues.Add('integrity.signature_invalid');break}
  if($null -eq $sig.SignerCertificate -or $sig.SignerCertificate.Subject -notmatch 'Microsoft'){
    $issues.Add('integrity.signer_unexpected');break
  }
}""",
        **{"integrity.signature_invalid": Rule("Core Windows Binary Signature Invalid", FindingSeverity.HIGH,
                                                 "A selected core Windows file lacks a valid Authenticode signature."),
           "integrity.signer_unexpected": Rule("Core Windows Binary Signer Unexpected", FindingSeverity.HIGH,
                                               "A selected core Windows file is not signed by Microsoft.")}),
    "windows.admin-accounts": _check(
        "Built-In Administrator Account", "Checks the built-in Administrator by SID; does not judge approved admin membership.",
        "Accounts", """$u=@(Get-LocalUser -ErrorAction Stop | Where-Object {$_.SID.Value -match '-500$'})
if($u.Count -ne 1){throw 'Administrator identity unavailable'}
if($u[0].Enabled -isnot [bool]){throw 'invalid Administrator status'}
if($u[0].Enabled){$issues.Add('admin.builtin_enabled')}""",
        **{"admin.builtin_enabled": Rule("Built-In Administrator Account Enabled", FindingSeverity.LOW,
                                         "The built-in Administrator account is enabled; confirm this matches local policy.")}),
    "windows.startup": _check(
        "Machine Startup Scripts", "Flags script-based machine Run entries for review without collecting entry names or commands.",
        "Startup", r"""foreach($path in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                         'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')){
  if(-not(Test-Path -LiteralPath $path)){continue}
  $key=Get-Item -LiteralPath $path -ErrorAction Stop
  foreach($entry in $key.GetValueNames()){
    $value=$key.GetValue($entry)
    if($value -isnot [string]){$partial=$true;continue}
    if($value -match '(?i)\.(vbs|js|jse|wsf|bat|cmd|ps1)(?:[\s"'']|$)'){
      $issues.Add('startup.script_entry');break
    }
  }
  if($issues.Contains('startup.script_entry')){break}
}""",
        **{"startup.script_entry": Rule("Script-Based Machine Startup Entry", FindingSeverity.LOW,
                                         "A machine Run entry invokes a script; review its origin and necessity.")}),
    "windows.wifi": _check(
        "Connected Wi-Fi Cipher", "Checks the active Wi-Fi cipher; unsupported on wired hosts or localized output it cannot parse.",
        "Wireless", r"""$output=@(& netsh.exe wlan show interfaces 2>$null)
if($LASTEXITCODE -ne 0){throw 'wireless status unavailable'}
$cipherLines=@($output | Where-Object {$_ -match '^\s*Cipher\s*:\s*(\S+)'})
if($cipherLines.Count -eq 0){$unsupported=$true}
else {
  foreach($line in $cipherLines){
    $null=$line -match '^\s*Cipher\s*:\s*(\S+)'
    $cipher=$Matches[1].ToUpperInvariant()
    if($cipher -match '^(WEP|TKIP)'){$issues.Add('wifi.weak_cipher')}
    elseif($cipher -eq 'NONE'){$issues.Add('wifi.open_network')}
    elseif($cipher -notin @('CCMP','GCMP','GCMP-256','CCMP-256','AES')){$partial=$true}
  }
  if($issues.Count -eq 0 -and $partial){$unsupported=$true;$partial=$false}
  $authentication=@($output | Where-Object {$_ -match '^\s*Authentication\s*:\s*(.+)$'})
  if($authentication.Count -gt 0 -and $authentication[0] -match ':\s*Open\s*$' -and
     -not $issues.Contains('wifi.open_network')){
    $issues.Add('wifi.open_network')
  }
}""",
        **{"wifi.weak_cipher": Rule("Weak Wi-Fi Cipher", FindingSeverity.HIGH,
                                     "The connected Wi-Fi interface reports WEP or TKIP encryption."),
           "wifi.open_network": Rule("Open Wi-Fi Network", FindingSeverity.MEDIUM,
                                     "The connected Wi-Fi interface reports open authentication.")}),
    "windows.audit": _check(
        "Logon Audit Policy", "Checks successful and failed logon auditing when an elevated English auditpol result is available.",
        "Auditing", """$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$elevated=$identity.IsSystem -or ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if(-not $elevated){$unsupported=$true}
else {
  $raw=@(& auditpol.exe /get /subcategory:Logon /r 2>$null)
  if($LASTEXITCODE -ne 0){throw 'audit policy unavailable'}
  $rows=@($raw | ConvertFrom-Csv)
  if($rows.Count -ne 1){$unsupported=$true}
  else {
    $setting=[string]$rows[0].'Inclusion Setting'
    if($setting -eq 'Success and Failure'){}
    elseif($setting -in @('No Auditing','Success','Failure')){$issues.Add('audit.logon_incomplete')}
    else {$unsupported=$true}
  }
}""",
        **{"audit.logon_incomplete": Rule("Logon Auditing Incomplete", FindingSeverity.MEDIUM,
                                           "Logon auditing does not include both successful and failed events.")}),
}


def script_for(check: Check) -> str:
    return ("$ErrorActionPreference='Stop'; "
            "$issues=New-Object 'System.Collections.Generic.List[string]'; $unsupported=$false; $partial=$false; "
            + check.body + "; "
            "[pscustomobject]@{CollectionStatus=$(if($unsupported){'unsupported'}elseif($partial){'partial'}else{'ok'}); "
            "Issues=@($issues.ToArray())} | ConvertTo-Json -Compress -Depth 3")
