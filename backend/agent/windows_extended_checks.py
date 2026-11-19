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


def _boolean_setting(command, property_name, expected, rule_id):
    state = "$true" if expected else "$false"
    return f"""if(-not (Get-Command {command} -ErrorAction SilentlyContinue)){{$unsupported=$true}}
else {{
  $value=({command} -ErrorAction Stop).{property_name}
  if($value -isnot [bool]){{throw 'setting unavailable'}}
  if($value -ne {state}){{$issues.Add('{rule_id}')}}
}}"""


def _machine_policy(path, property_name, expected, rule_id, *, flag_missing):
    return rf"""$key=$null
try {{ $key=Get-Item -LiteralPath 'HKLM:\{path}' -ErrorAction Stop }}
catch [System.Management.Automation.ItemNotFoundException] {{}}
$value=$null
if($null -ne $key){{$value=$key.GetValue('{property_name}',$null)}}
if($null -eq $value){{{"$issues.Add('" + rule_id + "')" if flag_missing else ""}}}
elseif(($key.GetValueKind('{property_name}')) -ne [Microsoft.Win32.RegistryValueKind]::DWord -or
       $value -notin @(0,1)){{throw 'invalid machine policy'}}
elseif($value -ne {expected}){{$issues.Add('{rule_id}')}}"""


_DEFENDER_STATUS = """if(-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)){$unsupported=$true}
else {
  $s=Get-MpComputerStatus -ErrorAction Stop
  if($null -eq $s -or [string]::IsNullOrEmpty($s.AMRunningMode)){throw 'Defender status unavailable'}
  if($s.AMRunningMode -ne 'Normal'){$unsupported=$true}
  else {
"""


CHECKS.update({
    "windows.hotfix-recency": _check(
        "Windows Hotfix Recency", "Checks the newest dated entry in Windows hotfix inventory.",
        "Windows Update",
        """$dates=[Collections.Generic.List[DateTime]]::new()
foreach($entry in @(Get-HotFix -ErrorAction Stop)){
  if($entry.InstalledOn -is [DateTime] -and $entry.InstalledOn -gt [DateTime]::MinValue){
    $dates.Add($entry.InstalledOn)
  } else {$partial=$true}
}
if($dates.Count -eq 0){throw 'no dated hotfix records'}
$newest=($dates | Sort-Object -Descending | Select-Object -First 1)
$now=Get-Date
if($newest -gt $now){throw 'hotfix date is in the future'}
if(-not $partial -and ($now-$newest).TotalDays -gt 60){$issues.Add('updates.hotfix_inventory_old')}""",
        **{"updates.hotfix_inventory_old": Rule(
            "Newest Recorded Hotfix Older Than 60 Days", FindingSeverity.LOW,
            "The newest dated entry in Windows hotfix inventory is more than 60 days old.")},
    ),
    "windows.smb-client-signing": _check(
        "SMB Client Signing", "Reads whether the Windows SMB client requires signing.", "Network",
        _boolean_setting("Get-SmbClientConfiguration", "RequireSecuritySignature", True, "smb.client_signing_not_required"),
        **{"smb.client_signing_not_required": Rule("SMB Client Signing Not Required", FindingSeverity.MEDIUM,
                       "The SMB client reports that outbound connections do not require signing.")},
    ),
    "windows.smb-server-signing": _check(
        "SMB Server Signing", "Reads whether the Windows SMB server requires signing.", "Network",
        _boolean_setting("Get-SmbServerConfiguration", "RequireSecuritySignature", True, "smb.server_signing_not_required"),
        **{"smb.server_signing_not_required": Rule("SMB Server Signing Not Required", FindingSeverity.MEDIUM,
                       "The SMB server reports that inbound connections do not require signing.")},
    ),
    "windows.smb-guest-logons": _check(
        "SMB Guest Logons", "Reads whether the SMB client allows insecure guest connections.", "Network",
        _boolean_setting("Get-SmbClientConfiguration", "EnableInsecureGuestLogons", False, "smb.insecure_guest_allowed"),
        **{"smb.insecure_guest_allowed": Rule("Insecure SMB Guest Logons Allowed", FindingSeverity.HIGH,
                       "The SMB client allows insecure guest logons by configuration.")},
    ),
    "windows.defender-signature-age": _check(
        "Defender Signature Age", "Reads the antivirus signature age for active Defender.", "Antivirus",
        _DEFENDER_STATUS + """    $age=$s.AntivirusSignatureAge
    if(($null -eq $age) -or ($null -eq ($age -as [long])) -or ($age -lt 0) -or ($age -ge 65535)){throw 'signature age unavailable'}
    if($age -gt 7){$issues.Add('defender.signatures_stale')}
  }
}""",
        **{"defender.signatures_stale": Rule("Defender Signatures Older Than Seven Days", FindingSeverity.HIGH,
                       "Active Defender reports that antivirus signatures are more than seven days old.")},
    ),
    "windows.defender-pua": _check(
        "Defender PUA Protection", "Reads Defender potentially unwanted application policy.", "Antivirus",
        _DEFENDER_STATUS + """    $pref=Get-MpPreference -ErrorAction Stop
    if($null -eq $pref.PUAProtection -or $pref.PUAProtection -notin @(0,1,2)){throw 'PUA policy unavailable'}
    if($pref.PUAProtection -ne 1){$issues.Add('defender.pua_not_blocking')}
  }
}""",
        **{"defender.pua_not_blocking": Rule("Defender PUA Blocking Not Active", FindingSeverity.MEDIUM,
                       "Active Defender reports PUA protection disabled or in audit mode.")},
    ),
    "windows.defender-exclusion-scope": _check(
        "Defender User-Path Exclusions", "Recognizes Downloads and temporary path exclusions without reporting the paths.", "Antivirus",
        _DEFENDER_STATUS + r"""    $pref=Get-MpPreference -ErrorAction Stop
    if($null -eq $pref -or $null -eq $pref.PSObject.Properties['ExclusionPath']){throw 'exclusion list unavailable'}
    foreach($value in @($pref.ExclusionPath)){
      if($null -eq $value){continue}
      if($value -isnot [string]){$partial=$true;continue}
      if($value -match '(?i)(?:\\Users\\[^\\]+\\(?:Downloads|AppData\\Local\\Temp)(?:\\|$)|^%(?:TEMP|TMP)%(?:\\|$)|^%USERPROFILE%\\Downloads(?:\\|$))'){
        $issues.Add('defender.user_path_excluded');break
      }
    }
  }
}""",
        **{"defender.user_path_excluded": Rule("Defender Exclusion Covers Downloads or Temp", FindingSeverity.HIGH,
                       "A configured exclusion matches a profile Downloads or temporary path pattern.")},
    ),
    "windows.pending-reboot": _check(
        "Pending Servicing Reboot", "Reads Windows Update and component-servicing reboot markers.", "Windows Update",
        r"""$pending=$false
foreach($key in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')){
  try { $null=Get-Item -LiteralPath $key -ErrorAction Stop; $pending=$true }
  catch [System.Management.Automation.ItemNotFoundException] {}
  catch {$partial=$true}
}
if($pending){$issues.Add('updates.reboot_pending')}""",
        **{"updates.reboot_pending": Rule("Windows Servicing Reboot Pending", FindingSeverity.LOW,
                       "Windows Update or component servicing indicates that a reboot is pending.")},
    ),
    "windows.powershell-script-block-logging": _check(
        "PowerShell Script Block Policy", "Reads the Windows PowerShell machine script-block logging policy.", "Auditing",
        _machine_policy(r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging", 1, "powershell.script_block_not_enforced", flag_missing=True),
        **{"powershell.script_block_not_enforced": Rule("PowerShell Script Block Logging Policy Not Enabled", FindingSeverity.MEDIUM,
                       "Machine policy does not explicitly enable Windows PowerShell script block logging.")},
    ),
    "windows.powershell-module-logging": _check(
        "PowerShell Module Logging Policy", "Reads the Windows PowerShell machine module logging policy.", "Auditing",
        _machine_policy(r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging", "EnableModuleLogging", 1, "powershell.module_logging_not_enforced", flag_missing=True),
        **{"powershell.module_logging_not_enforced": Rule("PowerShell Module Logging Policy Not Enabled", FindingSeverity.LOW,
                       "Machine policy does not explicitly enable Windows PowerShell module logging.")},
    ),
    "windows.llmnr-policy": _check(
        "LLMNR Machine Policy", "Checks whether DNS Client machine policy disables multicast name resolution.", "Network",
        _machine_policy(r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", 0, "dns.llmnr_not_disabled", flag_missing=True),
        **{"dns.llmnr_not_disabled": Rule("LLMNR Not Disabled by Machine Policy", FindingSeverity.MEDIUM,
                       "DNS Client machine policy does not explicitly turn off multicast name resolution.")},
    ),
    "windows.wdigest-policy": _check(
        "WDigest Credential Policy", "Detects an explicit WDigest credential-caching override.", "Authentication",
        _machine_policy(r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", 0, "auth.wdigest_credential_caching", flag_missing=False),
        **{"auth.wdigest_credential_caching": Rule("WDigest Credential Caching Explicitly Enabled", FindingSeverity.HIGH,
                       "The WDigest UseLogonCredential setting is explicitly enabled.")},
    ),
    "windows.security-event-log": _check(
        "Windows Security Event Log", "Checks whether Windows reports the Security event log enabled.", "Auditing",
        """$log=Get-WinEvent -ListLog 'Security' -ErrorAction Stop
if($log.IsEnabled -isnot [bool]){throw 'Security log state unavailable'}
if(-not $log.IsEnabled){$issues.Add('audit.security_log_disabled')}""",
        **{"audit.security_log_disabled": Rule("Windows Security Event Log Disabled", FindingSeverity.MEDIUM,
                       "Windows reports the Security event log disabled.")},
    ),
    "windows.secure-boot": _check(
        "Secure Boot", "Reads UEFI Secure Boot state when the firmware exposes it.", "Platform",
        """if(-not (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)){$unsupported=$true}
else {
  try { $enabled=Confirm-SecureBootUEFI -ErrorAction Stop }
  catch [System.PlatformNotSupportedException] {$enabled=$null;$unsupported=$true}
  if(-not $unsupported){
    if($enabled -isnot [bool]){throw 'Secure Boot state unavailable'}
    if(-not $enabled){$issues.Add('platform.secure_boot_off')}
  }
}""",
        **{"platform.secure_boot_off": Rule("Secure Boot Disabled", FindingSeverity.HIGH,
                       "The firmware query reports Secure Boot disabled.")},
    ),
    "windows.remote-support-service": _check(
        "Remote Support Service Review", "Checks for a running, automatically started TeamViewer service.", "Remote Access",
        """$services=@(Get-CimInstance Win32_Service -Filter "Name='TeamViewer'" -ErrorAction Stop)
if($services.Count -gt 1){throw 'service state unavailable'}
if($services.Count -eq 1){
  if($null -eq $services[0].State -or $null -eq $services[0].StartMode){throw 'service state unavailable'}
  if($services[0].State -eq 'Running' -and $services[0].StartMode -eq 'Auto'){$issues.Add('services.teamviewer_auto_running')}
}""",
        **{"services.teamviewer_auto_running": Rule("TeamViewer Service Running Automatically", FindingSeverity.LOW,
                       "A TeamViewer service is running and configured to start automatically.")},
    ),
})


def script_for(check: Check) -> str:
    return ("$ErrorActionPreference='Stop'; "
            "$issues=New-Object 'System.Collections.Generic.List[string]'; $unsupported=$false; $partial=$false; "
            + check.body + "; "
            "[pscustomobject]@{CollectionStatus=$(if($unsupported){'unsupported'}elseif($partial){'partial'}else{'ok'}); "
            "Issues=@($issues.ToArray())} | ConvertTo-Json -Compress -Depth 3")
