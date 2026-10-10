"""
RAVEN-X ENTERPRISE: Rapid AI Vulnerability and Exploitation Nexus
AI-Powered Windows Vulnerability Scanner v4.0 – Ultimate Edition

DISCLAIMER: For authorized security testing only.
Requires: pip install openai psutil pywin32 customtkinter
"""

import tkinter as tk
import customtkinter as ctk
from tkinter import filedialog, messagebox, ttk
import subprocess, winreg, os, sys, psutil, json, socket, re
import hashlib, csv, time, smtplib, sqlite3, html
from datetime import datetime, timedelta
from openai import OpenAI
import threading, logging, tempfile, platform, uuid, webbrowser
from collections import defaultdict
import ctypes, pathlib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("raven_x.log"), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

CONFIG_FILE  = "raven_x_config.json"
DB_FILE      = "raven_x.db"

# ── Compliance framework control mappings ──────────────────────────────────
COMPLIANCE = {
    "CIS": {
        "Windows Update": ["CIS 1.1","CIS 1.2"], "Firewall": ["CIS 9.1","CIS 9.2","CIS 9.3"],
        "Antivirus": ["CIS 8.1","CIS 8.2"], "User Account Control": ["CIS 2.3.17"],
        "Authentication": ["CIS 1.1.1","CIS 5.1"], "Remote Access": ["CIS 18.8","CIS 18.9"],
        "Network": ["CIS 9.1","CIS 9.2"], "Services": ["CIS 5.1","CIS 5.2"],
        "Auditing": ["CIS 17.1","CIS 17.2"],
    },
    "NIST": {
        "Windows Update": ["SI-2"], "Firewall": ["SC-7","AC-4"], "Antivirus": ["SI-3"],
        "User Account Control": ["AC-6"], "Authentication": ["IA-2","IA-5"],
        "Remote Access": ["AC-17"], "Network": ["SC-7","CM-7"],
        "Services": ["CM-7"], "Auditing": ["AU-2","AU-12"],
    },
    "ISO 27001": {
        "Windows Update": ["A.12.6.1"], "Firewall": ["A.13.1.3"], "Antivirus": ["A.12.2.1"],
        "User Account Control": ["A.9.2.3"], "Authentication": ["A.9.2.1","A.9.4.3"],
        "Remote Access": ["A.6.2.1"], "Network": ["A.13.1.1"],
        "Services": ["A.12.5.1"], "Auditing": ["A.12.4.1"],
    },
    "PCI-DSS": {
        "Windows Update": ["6.2"], "Firewall": ["1.1","1.2"], "Antivirus": ["5.1","5.2"],
        "User Account Control": ["7.1","8.1"], "Authentication": ["8.2","8.3"],
        "Remote Access": ["8.3"], "Network": ["1.3","2.2"],
        "Services": ["2.2"], "Auditing": ["10.2","10.3"],
    },
}

# CVSS base scores for known issue types
CVSS_MAP = {
    "SMBv1":9.8, "Real-time Protection Disabled":9.1, "Firewall Disabled":8.8,
    "Guest Account Enabled":7.5, "RDP Network Level":7.5, "Tamper Protection":7.3,
    "UAC Not Fully":7.0, "Weak Wi-Fi":6.5, "Automatic Login":6.5,
    "Remote Desktop Enabled":5.9, "PowerShell Execution":5.5,
    "Outdated Windows Updates":7.8, "BitLocker":7.2, "No Password Required":9.3,
    "Defender Exclusion":8.5,
}

def cvss_for(vuln):
    title = vuln.get("title","")
    for k,v in CVSS_MAP.items():
        if k.lower() in title.lower():
            return v
    return {"critical":9.0,"high":7.0,"medium":5.0,"low":3.0}.get(vuln.get("severity","low"),5.0)

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

def run_ps(script, timeout=20):
    """Run a PowerShell snippet; return parsed JSON dict/list or raw string."""
    try:
        r = subprocess.run(
            ["powershell.exe","-NoProfile","-ExecutionPolicy","Bypass","-Command", script],
            capture_output=True, text=True, timeout=timeout
        )
        if r.returncode == 0 and r.stdout.strip():
            try: return json.loads(r.stdout)
            except: return r.stdout.strip()
    except Exception as e:
        logger.error(f"PS error: {e}")
    return None

def html_esc(s):
    return html.escape(str(s)) if s else ""

# ══════════════════════════════════════════════════════════════════════════
# DATABASE
# ══════════════════════════════════════════════════════════════════════════
class DB:
    def __init__(self):
        self.path = DB_FILE
        conn = sqlite3.connect(self.path)
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT UNIQUE,
            ts TEXT, host TEXT, total INTEGER, critical INTEGER,
            high INTEGER, medium INTEGER, low INTEGER,
            risk_score REAL, duration REAL, scan_type TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS vulns(
            id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT,
            severity TEXT, category TEXT, title TEXT, details TEXT,
            remediation TEXT, powershell_cmd TEXT,
            cvss REAL, cis TEXT, nist TEXT, iso TEXT, pci TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS trends(
            id INTEGER PRIMARY KEY AUTOINCREMENT, date TEXT,
            host TEXT, risk_score REAL, total INTEGER,
            critical INTEGER, high INTEGER)""")
        conn.commit(); conn.close()

    def save(self, data):
        conn = sqlite3.connect(self.path); c = conn.cursor()
        try:
            c.execute("""INSERT OR REPLACE INTO scans
                (scan_id,ts,host,total,critical,high,medium,low,risk_score,duration,scan_type)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (data["scan_id"],data["ts"],data["host"],data["total"],
                 data["critical"],data["high"],data["medium"],data["low"],
                 data["risk_score"],data["duration"],data.get("scan_type","full")))
            for v in data["vulns"]:
                ctrls = {fw: ",".join(COMPLIANCE.get(fw,{}).get(v.get("category",""),[]))
                         for fw in ["CIS","NIST","ISO 27001","PCI-DSS"]}
                c.execute("""INSERT INTO vulns
                    (scan_id,severity,category,title,details,remediation,
                     powershell_cmd,cvss,cis,nist,iso,pci)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (data["scan_id"],v.get("severity"),v.get("category"),
                     v.get("title"),v.get("details"),v.get("remediation",""),
                     v.get("powershell_command",""),cvss_for(v),
                     ctrls["CIS"],ctrls["NIST"],ctrls["ISO 27001"],ctrls["PCI-DSS"]))
            c.execute("INSERT INTO trends(date,host,risk_score,total,critical,high) VALUES(?,?,?,?,?,?)",
                      (datetime.now().strftime("%Y-%m-%d"),data["host"],
                       data["risk_score"],data["total"],data["critical"],data["high"]))
            conn.commit()
        except Exception as e:
            logger.error(f"DB save: {e}"); conn.rollback()
        finally: conn.close()

    def history(self, n=30):
        conn = sqlite3.connect(self.path); c = conn.cursor()
        c.execute("SELECT * FROM scans ORDER BY ts DESC LIMIT ?", (n,))
        rows = c.fetchall(); conn.close(); return rows

    def trends(self, days=30):
        conn = sqlite3.connect(self.path); c = conn.cursor()
        cutoff = (datetime.now()-timedelta(days=days)).strftime("%Y-%m-%d")
        c.execute("""SELECT date,AVG(risk_score),AVG(total),AVG(critical),AVG(high)
                     FROM trends WHERE date>=? GROUP BY date ORDER BY date""",(cutoff,))
        rows = c.fetchall(); conn.close(); return rows

    def compliance_history(self, fw="CIS", n=10):
        # Returns raw vuln rows for compliance calculation from last n scans
        conn = sqlite3.connect(self.path); c = conn.cursor()
        c.execute("SELECT scan_id FROM scans ORDER BY ts DESC LIMIT ?", (n,))
        ids = [r[0] for r in c.fetchall()]
        if not ids: conn.close(); return []
        placeholders = ",".join("?"*len(ids))
        col = {"CIS":"cis","NIST":"nist","ISO 27001":"iso","PCI-DSS":"pci"}.get(fw,"cis")
        c.execute(f"SELECT category,{col} FROM vulns WHERE scan_id IN ({placeholders})", ids)
        rows = c.fetchall(); conn.close(); return rows

    def calc_compliance(self, vulns, fw):
        all_controls = set()
        for controls in COMPLIANCE.get(fw,{}).values():
            all_controls.update(controls)
        failed = set()
        for v in vulns:
            cat = v.get("category","")
            failed.update(COMPLIANCE.get(fw,{}).get(cat,[]))
        total = len(all_controls); f = len(failed)
        passed = total - f
        score = round((passed/total*100) if total else 100, 1)
        return {"total":total,"passed":passed,"failed":f,"score":score}

# ══════════════════════════════════════════════════════════════════════════
# EMAIL
# ══════════════════════════════════════════════════════════════════════════
class EmailManager:
    def __init__(self, cfg): self.cfg = cfg

    def _smtp(self):
        s = smtplib.SMTP(self.cfg.get("smtp_server","smtp.gmail.com"),
                         int(self.cfg.get("smtp_port",587)))
        s.starttls()
        s.login(self.cfg["smtp_user"], self.cfg["smtp_pass"])
        return s

    def send_report(self, scan_data, html_report, recipients):
        try:
            msg = MIMEMultipart("alternative")
            msg["From"]    = self.cfg["smtp_user"]
            msg["To"]      = ", ".join(recipients)
            msg["Subject"] = (f"RAVEN-X Report — {scan_data['host']} — "
                              f"Risk {scan_data['risk_score']}%")
            msg.attach(MIMEText(html_report,"html"))
            with self._smtp() as s: s.send_message(msg)
            logger.info("Report email sent"); return True
        except Exception as e: logger.error(f"Email: {e}"); return False

    def send_alert(self, scan_data, critical_vulns, recipients):
        try:
            body  = f"🚨 CRITICAL ALERT — {scan_data['host']}\n\n"
            body += f"Risk Score : {scan_data['risk_score']}%\n"
            body += f"Critical   : {len(critical_vulns)}\n\n"
            for i,v in enumerate(critical_vulns,1):
                body += f"{i}. {v['title']}\n   {v['details']}\n\n"
            msg = MIMEMultipart()
            msg["From"]    = self.cfg["smtp_user"]
            msg["To"]      = ", ".join(recipients)
            msg["Subject"] = f"🚨 {len(critical_vulns)} Critical Issues — {scan_data['host']}"
            msg.attach(MIMEText(body,"plain"))
            with self._smtp() as s: s.send_message(msg)
            logger.info("Alert email sent"); return True
        except Exception as e: logger.error(f"Alert email: {e}"); return False

# ══════════════════════════════════════════════════════════════════════════
# SCANNER
# ══════════════════════════════════════════════════════════════════════════
class VulnerabilityScanner:
    def __init__(self):
        self.vulnerabilities = []
        self.scan_start_time = self.scan_end_time = None
        self.system_info = {}
        self.scan_id = str(uuid.uuid4())[:8]

    # ── helpers ────────────────────────────────────────────────────────────
    def _add(self, severity, category, title, details, component,
             remediation, ps_cmd=""):
        self.vulnerabilities.append({
            "severity": severity, "category": category, "title": title,
            "details": details, "component": component,
            "remediation": remediation, "powershell_command": ps_cmd
        })

    def _reg_read(self, hive, path, key):
        k = winreg.OpenKey(hive, path)
        v, _ = winreg.QueryValueEx(k, key)
        winreg.CloseKey(k)
        return v

    # ── system info ────────────────────────────────────────────────────────
    def get_system_info(self):
        try:
            mem  = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            self.system_info = {
                "os_version": platform.platform(),
                "architecture": platform.architecture()[0],
                "processor": platform.processor(),
                "hostname": socket.gethostname(),
                "scan_id": self.scan_id,
                "scan_time": datetime.now().isoformat(),
                "total_ram_gb": round(mem.total/(1024**3),2),
                "available_ram_gb": round(mem.available/(1024**3),2),
                "total_disk_gb": round(disk.total/(1024**3),2),
                "used_disk_gb": round(disk.used/(1024**3),2),
                "cpu_cores": psutil.cpu_count(logical=True),
            }
        except Exception as e: logger.error(f"sysinfo: {e}")
        return self.system_info

    # ── individual checks ──────────────────────────────────────────────────
    def check_windows_updates(self):
        data = run_ps("Get-HotFix | Select-Object -Last 1 | ConvertTo-Json -Compress")
        if isinstance(data, dict):
            ts = data.get("InstalledOn","")
            if ts:
                try:
                    last = datetime.strptime(ts.split("T")[0],"%Y-%m-%d")
                    age  = (datetime.now()-last).days
                    if age > 60:
                        self._add("high","Windows Update","Outdated Windows Updates",
                            f"Last update {age} days ago. Missing critical patches.",
                            "Windows Update Service",
                            "Run Windows Update from Settings.",
                            "Start-Process ms-settings:windowsupdate")
                except: pass
        r = subprocess.run(["sc","query","wuauserv"],capture_output=True,text=True,timeout=5)
        if "RUNNING" not in r.stdout:
            self._add("medium","Windows Update","Windows Update Service Not Running",
                "Automatic updates disabled.",
                "Windows Update Service",
                "Start the Windows Update service.",
                "Start-Service -Name wuauserv; Set-Service -Name wuauserv -StartupType Automatic")

    def check_firewall(self):
        profiles = [("DomainProfile","domain"),("PrivateProfile","private"),("PublicProfile","public")]
        for name, arg in profiles:
            r = subprocess.run(["netsh","advfirewall","show",arg,"state"],
                               capture_output=True,text=True,timeout=5)
            if "OFF" in r.stdout or "Disabled" in r.stdout:
                sev = "critical" if name == "PublicProfile" else "high"
                self._add(sev,"Firewall",f"Windows Firewall Disabled – {name}",
                    f"Firewall is OFF for {name}. Network attacks are possible.",
                    "Windows Defender Firewall",
                    f"Enable the {name} firewall profile.",
                    f"Set-NetFirewallProfile -Profile {name} -Enabled True")

    def _get_defender_status(self):
        script = """
$s=$null; $p=$null
try{$s=Get-MpComputerStatus;$p=Get-MpPreference}catch{}
if($s -and $p){@{
  RealTimeProtectionEnabled=$s.RealTimeProtectionEnabled;
  AntivirusEnabled=$s.AntivirusEnabled;
  BehaviorMonitorEnabled=$s.BehaviorMonitorEnabled;
  IoavProtectionEnabled=$s.IoavProtectionEnabled;
  NISEnabled=$s.NISEnabled;
  IsTamperProtected=$s.IsTamperProtected;
  AMRunningMode=$s.AMRunningMode;
  AntivirusSignatureAgeDays=if($s.AntivirusSignatureLastUpdated){((Get-Date)-$s.AntivirusSignatureLastUpdated).Days}else{999};
  MAPSReporting=$p.MAPSReporting;
  SubmitSamplesConsent=$p.SubmitSamplesConsent;
  DisableBlockAtFirstSeen=$p.DisableBlockAtFirstSeen;
  PUAProtection=$p.PUAProtection;
  DisableScriptScanning=$p.DisableScriptScanning;
  DisableArchiveScanning=$p.DisableArchiveScanning
}|ConvertTo-Json -Compress}else{"null"}"""
        return run_ps(script, timeout=15)

    def check_antivirus(self):
        st = self._get_defender_status()
        if not st or st == "null":
            self._add("medium","Antivirus","Cannot Query Windows Defender",
                "Defender status unavailable. Windows Security may be broken.",
                "Windows Defender","Open Windows Security and check for issues.",
                "Start-Process windowsdefender:"); return
        passive = st.get("AMRunningMode","") == "Passive"
        tp  = st.get("IsTamperProtected", False)
        def av(sev,title,details,cmd):
            note = "\n(Defender passive – third-party AV active)" if passive else ""
            self._add(sev,"Antivirus",title,details+note,"Windows Defender","",cmd)

        checks = [
            ("RealTimeProtectionEnabled","critical","Real-time Protection Disabled",
             "Malware protection is off.","Set-MpPreference -DisableRealtimeMonitoring $false"),
            ("AntivirusEnabled","critical","Antivirus Engine Disabled",
             "Core AV engine is disabled.","Set-MpPreference -DisableRealtimeMonitoring $false"),
            ("BehaviorMonitorEnabled","high","Behavior Monitoring Disabled",
             "Behavioral analysis is off.","Set-MpPreference -DisableBehaviorMonitoring $false"),
            ("IoavProtectionEnabled","medium","IOAV Protection Disabled",
             "Downloaded-file scanning is off.","Set-MpPreference -DisableIOAVProtection $false"),
            ("NISEnabled","medium","Network Inspection Disabled",
             "Network Inspection System is off.","Set-MpPreference -DisableIntrusionPreventionSystem $false"),
        ]
        for key,sev,title,details,cmd in checks:
            if not st.get(key,True if key.startswith("Disable") else False):
                av(sev,title,details,cmd)

        age = st.get("AntivirusSignatureAgeDays",999)
        if age > 7:
            av("high","Outdated Virus Definitions",f"Definitions are {age} days old.","Update-MpSignature")
        if st.get("MAPSReporting",0)==0:
            av("medium","Cloud Protection Disabled","MAPS cloud protection is off.","Set-MpPreference -MAPSReporting Advanced")
        if st.get("DisableBlockAtFirstSeen",False):
            av("medium","Block at First Sight Disabled","Block at First Sight is off.","Set-MpPreference -DisableBlockAtFirstSeen $false")
        if st.get("PUAProtection",0)==0:
            av("medium","PUA Protection Disabled","Unwanted app protection is off.","Set-MpPreference -PUAProtection Enabled")
        if not tp:
            av("high","Tamper Protection Disabled",
               "Malware could disable Defender silently.",
               "# Enable Tamper Protection manually in Windows Security > Virus & threat protection settings")

    def check_defender_exclusions(self):
        data = run_ps("""
$p=Get-MpPreference
@{ExclusionPath=$p.ExclusionPath;ExclusionExtension=$p.ExclusionExtension;ExclusionProcess=$p.ExclusionProcess}|ConvertTo-Json -Compress""", 15)
        if not isinstance(data, dict): return
        risky = ["desktop","downloads","temp","appdata","documents","public"]
        for path in (data.get("ExclusionPath") or []):
            sev = "critical" if any(r in str(path).lower() for r in risky) else "high"
            self._add(sev,"Antivirus",f"Defender Path Exclusion: {path}",
                f'Defender is NOT scanning "{path}". Malware can hide here undetected.',
                "Windows Defender Exclusions",
                "Remove this exclusion unless absolutely required.",
                f'Remove-MpPreference -ExclusionPath "{path}"')
        for ext in (data.get("ExclusionExtension") or []):
            self._add("high","Antivirus",f"Defender Extension Exclusion: {ext}",
                f'Files ending in "{ext}" are not scanned by Defender.',
                "Windows Defender Exclusions",
                "Remove this extension exclusion.",
                f'Remove-MpPreference -ExclusionExtension "{ext}"')
        for proc in (data.get("ExclusionProcess") or []):
            self._add("critical","Antivirus",f"Defender Process Exclusion: {proc}",
                f'Process "{proc}" is excluded from Defender scanning.',
                "Windows Defender Exclusions",
                "Remove this process exclusion.",
                f'Remove-MpPreference -ExclusionProcess "{proc}"')

    def check_uac(self):
        try:
            consent = self._reg_read(winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System","ConsentPromptBehaviorAdmin")
            desktop = self._reg_read(winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System","PromptOnSecureDesktop")
            if consent != 2 or desktop != 1:
                self._add("high","User Account Control","UAC Not at Maximum Security",
                    f"ConsentPromptBehaviorAdmin={consent}, PromptOnSecureDesktop={desktop}.",
                    "UAC","Set UAC to 'Always notify'.",
                    'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name "ConsentPromptBehaviorAdmin" -Value 2; Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name "PromptOnSecureDesktop" -Value 1')
        except: pass

    def check_auto_login(self):
        try:
            v = self._reg_read(winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon","AutoAdminLogon")
            if v == "1":
                self._add("high","Authentication","Automatic Login Enabled",
                    "Windows logs in automatically without a password.",
                    "Winlogon","Disable AutoAdminLogon.",
                    'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" -Name "AutoAdminLogon" -Value "0"')
        except: pass

    def check_remote_desktop(self):
        try:
            v = self._reg_read(winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server","fDenyTSConnections")
            if v == 0:
                self._add("medium","Remote Access","Remote Desktop (RDP) Enabled",
                    "RDP is enabled. Unnecessary exposure if not required.",
                    "Terminal Services","Disable RDP if not needed.",
                    'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" -Name "fDenyTSConnections" -Value 1')
        except: pass

    def check_rdp_nla(self):
        try:
            v = self._reg_read(winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp","UserAuthentication")
            if v == 0:
                self._add("high","Remote Access","RDP NLA (Network Level Auth) Disabled",
                    "RDP does not require NLA. Brute-force attacks are easier.",
                    "Terminal Services","Enable NLA for RDP.",
                    'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name "UserAuthentication" -Value 1')
        except: pass

    def check_guest_account(self):
        r = subprocess.run(["net","user","Guest"],capture_output=True,text=True,timeout=5)
        if "Account active" in r.stdout and "Yes" in r.stdout:
            self._add("high","User Accounts","Guest Account Enabled",
                "The built-in Guest account is active. Unauthorized access risk.",
                "Local Users","Disable the Guest account.",
                'Disable-LocalUser -Name "Guest"')

    def check_admin_accounts(self):
        data = run_ps('Get-LocalGroupMember -Group Administrators | Where-Object {$_.ObjectClass -eq "User"} | Select-Object Name,Enabled | ConvertTo-Json -Compress')
        if not data: return
        if isinstance(data, dict): data = [data]
        for a in data:
            if a.get("Enabled"):
                self._add("low","Privilege Management",f'Admin Account Enabled: {a["Name"]}',
                    f'{a["Name"]} is an active administrator.',
                    "Local Users","Ensure admin rights are required.",
                    f'Disable-LocalUser -Name "{a["Name"]}"')

    def check_open_ports(self):
        r = subprocess.run(["netstat","-an"],capture_output=True,text=True,timeout=10)
        risky = {21:"FTP",23:"Telnet",25:"SMTP",110:"POP3",135:"RPC",
                 139:"NetBIOS",445:"SMB",1433:"MSSQL",3306:"MySQL",
                 3389:"RDP",5900:"VNC",8080:"HTTP-Proxy"}
        seen = set()
        for m in re.finditer(r":(\d+)\s",r.stdout):
            p = int(m.group(1))
            if p in risky and p not in seen:
                seen.add(p)
                self._add("medium","Network",f"Risky Port Open: {p} ({risky[p]})",
                    f"Port {p} ({risky[p]}) is listening. Common attack target.",
                    "TCP Port",f"Block or close port {p} if not required.",
                    f"New-NetFirewallRule -DisplayName 'Block Port {p}' -Direction Inbound -LocalPort {p} -Protocol TCP -Action Block")

    def check_network_sharing(self):
        for name, gname in [("Network Discovery","Network Discovery"),
                             ("File and Printer Sharing","File and Printer Sharing")]:
            r = subprocess.run(["netsh","advfirewall","firewall","show","rule",f'name="{name}"'],
                               capture_output=True,text=True,timeout=10)
            if "Yes" in r.stdout:
                self._add("medium","Network Sharing",f"{name} Enabled",
                    f"{name} is enabled and may expose this device.",
                    "Firewall Rule",f"Disable {name} when not needed.",
                    f'Set-NetFirewallRule -DisplayGroup "{gname}" -Enabled False')

    def check_smb_protocol(self):
        data = run_ps("Get-SmbServerConfiguration|Select-Object EnableSMB1Protocol,EnableSMB2Protocol|ConvertTo-Json -Compress",5)
        if isinstance(data,dict) and data.get("EnableSMB1Protocol"):
            self._add("critical","Network","SMBv1 Protocol Enabled",
                "SMBv1 is enabled. Vulnerable to EternalBlue/WannaCry.",
                "SMB Protocol","Disable SMBv1 immediately.",
                "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force")

    def check_password_policy(self):
        data = run_ps("Get-LocalUser|Where-Object{$_.Enabled}|Select-Object Name,PasswordRequired|ConvertTo-Json -Compress")
        if not data: return
        if isinstance(data,dict): data=[data]
        for u in data:
            if u.get("PasswordRequired")==False:
                self._add("critical","Authentication",f'No Password Required: {u["Name"]}',
                    f'User "{u["Name"]}" has no password requirement.',
                    "Local User Accounts","Set a strong password.",
                    f'Set-LocalUser -Name "{u["Name"]}" -Password (Read-Host -AsSecureString "New password")')

    def check_bitlocker_status(self):
        data = run_ps("Get-BitLockerVolume -MountPoint C:|Select-Object VolumeStatus,EncryptionPercentage|ConvertTo-Json -Compress")
        if isinstance(data,dict) and data.get("VolumeStatus")!="FullyEncrypted":
            pct = data.get("EncryptionPercentage",0)
            self._add("high","Disk Encryption","BitLocker Not Fully Enabled",
                f"C: drive is {pct}% encrypted. Data at rest is not protected.",
                "BitLocker","Enable BitLocker on the C: drive.",
                "Enable-BitLocker -MountPoint 'C:' -SkipHardwareTest -TpmProtector")

    def check_powershell_execution_policy(self):
        r = subprocess.run(["powershell","-Command","Get-ExecutionPolicy"],
                           capture_output=True,text=True,timeout=5)
        policy = r.stdout.strip()
        if policy in ["Unrestricted","Bypass","RemoteSigned"]:
            self._add("high","Scripting",f"PowerShell Execution Policy: {policy}",
                f"Policy is '{policy}'. Malicious scripts may run without restriction.",
                "PowerShell","Set to Restricted or AllSigned.",
                "Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope LocalMachine -Force")

    def check_audit_policy(self):
        r = subprocess.run(["auditpol","/get","/category:*"],
                           capture_output=True,text=True,timeout=10)
        for audit in ["Logon","Logoff","Account Lockout","Process Creation","Object Access","Policy Change"]:
            if audit in r.stdout and "Success and Failure" not in r.stdout:
                self._add("medium","Auditing",f"Audit Policy Incomplete: {audit}",
                    f"'{audit}' auditing is not fully configured.",
                    "Windows Audit Policy","Configure audit policy via auditpol or Group Policy.",
                    f'auditpol /set /subcategory:"{audit}" /success:enable /failure:enable')

    def check_autorun(self):
        try:
            v = self._reg_read(winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer","NoDriveTypeAutoRun")
            if v != 0xFF:
                self._add("medium","Autorun","AutoRun Not Fully Disabled",
                    "AutoRun for removable media is not fully disabled.",
                    "Windows Explorer","Set NoDriveTypeAutoRun to 255.",
                    'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord')
        except:
            self._add("medium","Autorun","AutoRun Policy Key Missing",
                "AutoRun may be enabled for removable drives.",
                "Windows Explorer","Disable AutoRun.",
                'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord')

    def check_startup_programs(self):
        locs = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE,r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ]
        suspicious = ["temp","tmp","appdata","%userprofile%",".vbs",".js",".bat"]
        for hive, path in locs:
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(key, i); i+=1
                        if any(s in val.lower() for s in suspicious):
                            self._add("medium","Startup","Suspicious Startup Entry",
                                f'Entry "{name}" runs from a suspicious path: {val}',
                                "Windows Startup","Review in Task Manager > Startup.",
                                f'Remove-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "{name}" -ErrorAction SilentlyContinue')
                    except OSError: break
                winreg.CloseKey(key)
            except: continue

    def check_wifi_security(self):
        r = subprocess.run(["netsh","wlan","show","profiles"],
                           capture_output=True,text=True,timeout=10)
        for profile in re.findall(r"All User Profile\s*:\s*(.+)",r.stdout)[:5]:
            pr = subprocess.run(["netsh","wlan","show","profile",f"name={profile}","key=clear"],
                                capture_output=True,text=True,timeout=10)
            if "WEP" in pr.stdout or "TKIP" in pr.stdout:
                self._add("high","Wireless",f"Weak Wi-Fi Security: {profile}",
                    f'"{profile}" uses deprecated WEP/TKIP encryption.',
                    "Wi-Fi Profile","Update router to WPA2-AES or WPA3.",
                    f'Write-Host "Manually update router settings for SSID: {profile}"')

    def check_services(self):
        data = run_ps('Get-Service|Where-Object{$_.StartType -eq "Automatic"}|Select-Object Name,DisplayName,Status|ConvertTo-Json -Compress')
        if not data: return
        if isinstance(data, dict): data=[data]
        risky = ["RemoteRegistry","Telnet","TFTP","W3SVC","MSSQLSERVER","MYSQL","VNC","TeamViewer"]
        for svc in data:
            name = svc.get("Name",""); disp = svc.get("DisplayName","")
            for r in risky:
                if r.lower() in name.lower() or r.lower() in disp.lower():
                    self._add("medium","Services",f"Risky Service Running: {disp}",
                        f'"{disp}" runs automatically and may not be required.',
                        "Windows Services","Disable if not needed.",
                        f'Stop-Service -Name "{name}" -Force; Set-Service -Name "{name}" -StartupType Disabled')

    def check_ntp(self):
        try:
            v = self._reg_read(winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\W32Time\Parameters","NtpServer")
            if not v:
                raise ValueError("empty")
        except:
            self._add("low","Time Synchronization","NTP Server Not Configured",
                "System clock may drift, affecting logs and authentication.",
                "Windows Time Service","Configure an NTP server.",
                'w32tm /config /manualpeerlist:"time.windows.com" /syncfromflags:manual /update; Restart-Service w32tm')

    def check_telnet(self):
        r = subprocess.run(["dism","/online","/Get-Features"],
                           capture_output=True,text=True,timeout=15)
        if "TelnetClient" in r.stdout and "Enabled" in r.stdout:
            self._add("medium","Optional Features","Telnet Client Installed",
                "Telnet transmits all data (including passwords) unencrypted.",
                "Windows Features","Remove Telnet Client.",
                "Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient")

    def check_dns_settings(self):
        data = run_ps("Get-DnsClientServerAddress -AddressFamily IPv4|Select-Object InterfaceAlias,ServerAddresses|ConvertTo-Json -Compress")
        if not data: return
        if isinstance(data,dict): data=[data]
        known = {"8.8.8.8","8.8.4.4","1.1.1.1","1.0.0.1","208.67.222.222","208.67.220.220"}
        for iface in data:
            for dns in (iface.get("ServerAddresses") or []):
                if dns not in known and not dns.startswith(("192.168.","10.","172.")):
                    self._add("low","DNS","Non-Standard DNS Server",
                        f'Interface "{iface["InterfaceAlias"]}" uses DNS {dns} (not a known privacy-safe server).',
                        "DNS Client","Consider using 1.1.1.1 or 8.8.8.8.",
                        f'Set-DnsClientServerAddress -InterfaceAlias "{iface["InterfaceAlias"]}" -ServerAddresses "1.1.1.1","1.0.0.1"')

    def check_file_integrity(self, callback=None):
        sysroot = os.environ.get("SystemRoot","C:\\Windows")
        files = [f"{sysroot}\\System32\\{f}" for f in
                 ["kernel32.dll","user32.dll","ntdll.dll","cmd.exe",
                  "powershell.exe","regedit.exe","taskmgr.exe"]]
        for i,fp in enumerate(files):
            if callback: callback(i,len(files),f"Checking {os.path.basename(fp)}...")
            if not os.path.exists(fp): continue
            try:
                mt   = datetime.fromtimestamp(os.stat(fp).st_mtime)
                diff = (datetime.now()-mt).days
                if diff < 1 or diff > 365*5:
                    self._add("medium","File Integrity",
                        f"Suspicious Modification: {os.path.basename(fp)}",
                        f"File modified {diff} days ago ({mt}). Unexpected for a system file.",
                        "System Files","Run sfc /scannow to verify integrity.",
                        "sfc /scannow")
            except Exception as e: logger.error(f"File check {fp}: {e}")

    # ── orchestration ──────────────────────────────────────────────────────
    def scan_all(self, progress_callback=None):
        self.vulnerabilities = []
        self.scan_start_time = datetime.now()
        checks = [
            (self.get_system_info,             "Gathering system information…"),
            (self.check_windows_updates,       "Checking Windows updates…"),
            (self.check_firewall,              "Checking firewall…"),
            (self.check_antivirus,             "Checking antivirus…"),
            (self.check_defender_exclusions,   "Checking Defender exclusions…"),
            (self.check_uac,                   "Checking UAC…"),
            (self.check_auto_login,            "Checking auto-login…"),
            (self.check_remote_desktop,        "Checking Remote Desktop…"),
            (self.check_rdp_nla,               "Checking RDP NLA…"),
            (self.check_guest_account,         "Checking guest account…"),
            (self.check_admin_accounts,        "Checking admin accounts…"),
            (self.check_open_ports,            "Checking open ports…"),
            (self.check_network_sharing,       "Checking network sharing…"),
            (self.check_smb_protocol,          "Checking SMB protocol…"),
            (self.check_password_policy,       "Checking password policy…"),
            (self.check_bitlocker_status,      "Checking BitLocker…"),
            (self.check_powershell_execution_policy,"Checking PowerShell policy…"),
            (self.check_audit_policy,          "Checking audit policy…"),
            (self.check_autorun,               "Checking AutoRun…"),
            (self.check_startup_programs,      "Checking startup programs…"),
            (self.check_wifi_security,         "Checking Wi-Fi security…"),
            (self.check_services,              "Checking services…"),
            (self.check_ntp,                   "Checking NTP configuration…"),
            (self.check_telnet,                "Checking Telnet client…"),
            (self.check_dns_settings,          "Checking DNS settings…"),
            (lambda: self.check_file_integrity(progress_callback), "Checking file integrity…"),
        ]
        for i,(fn,msg) in enumerate(checks):
            if progress_callback: progress_callback(i,len(checks),msg)
            try: fn()
            except Exception as e: logger.error(f"Check failed [{msg}]: {e}")
        self.scan_end_time = datetime.now()
        return self.vulnerabilities

    def risk_score(self):
        if not self.vulnerabilities: return 0,"Low Risk"
        w = {"critical":10,"high":7,"medium":4,"low":1}
        total = sum(w.get(v["severity"],0) for v in self.vulnerabilities)
        pct   = round(total/(len(self.vulnerabilities)*10)*100,1)
        level = ("Critical Risk" if pct>=70 else "High Risk" if pct>=40
                 else "Medium Risk" if pct>=20 else "Low Risk")
        return pct, level

    def generate_html_report(self):
        vulns = sorted(self.vulnerabilities,
                       key=lambda v:{"critical":0,"high":1,"medium":2,"low":3}.get(v["severity"],4))
        pct, level = self.risk_score()
        sev_colors = {"critical":"#e74c3c","high":"#e67e22","medium":"#f39c12","low":"#95a5a6"}
        rows = ""
        for i,v in enumerate(vulns,1):
            c = sev_colors.get(v["severity"],"#000")
            ctrl = ""
            for fw in ["CIS","NIST","ISO 27001","PCI-DSS"]:
                tags = COMPLIANCE.get(fw,{}).get(v.get("category",""),[])
                if tags: ctrl += f"<span style='background:{c};color:#fff;border-radius:3px;padding:1px 5px;margin:2px;font-size:10px'>{fw}: {', '.join(tags)}</span>"
            rows += f"""<tr>
<td>{i}</td>
<td><b style='color:{c}'>{v['severity'].upper()}</b></td>
<td>{html_esc(v.get('category',''))}</td>
<td>{html_esc(v.get('title',''))}</td>
<td>{html_esc(v.get('details',''))}</td>
<td style='font-size:11px'>{html_esc(v.get('remediation',''))}</td>
<td style='font-size:10px'>{ctrl}</td>
</tr>"""
        return f"""<!DOCTYPE html><html><head><meta charset='utf-8'>
<title>RAVEN-X Enterprise Report</title>
<style>
body{{font-family:Segoe UI,sans-serif;margin:40px;background:#f5f7fa}}
.container{{max-width:1400px;margin:0 auto;background:#fff;padding:30px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,.1)}}
.header{{background:#2c3e50;color:#fff;padding:20px;border-radius:5px;margin-bottom:20px}}
.kpi{{display:grid;grid-template-columns:repeat(5,1fr);gap:15px;margin:20px 0}}
.kpi-card{{background:#f8f9fa;padding:15px;border-radius:8px;text-align:center;border-top:4px solid}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{background:#2c3e50;color:#fff;padding:10px;text-align:left}}
td{{padding:8px;border-bottom:1px solid #eee;vertical-align:top}}
tr:nth-child(even){{background:#fafafa}}
</style></head><body><div class='container'>
<div class='header'><h1>🔒 RAVEN-X Enterprise Security Report</h1>
<p>Host: {self.system_info.get('hostname','N/A')} | Scan ID: {self.scan_id} | {datetime.now().strftime('%Y-%m-%d %H:%M')} | Risk: {pct}% – {level}</p></div>
<div class='kpi'>
<div class='kpi-card' style='border-color:#e74c3c'><h3>Critical</h3><p style='font-size:30px;font-weight:bold;color:#e74c3c'>{sum(1 for v in vulns if v['severity']=='critical')}</p></div>
<div class='kpi-card' style='border-color:#e67e22'><h3>High</h3><p style='font-size:30px;font-weight:bold;color:#e67e22'>{sum(1 for v in vulns if v['severity']=='high')}</p></div>
<div class='kpi-card' style='border-color:#f39c12'><h3>Medium</h3><p style='font-size:30px;font-weight:bold;color:#f39c12'>{sum(1 for v in vulns if v['severity']=='medium')}</p></div>
<div class='kpi-card' style='border-color:#95a5a6'><h3>Low</h3><p style='font-size:30px;font-weight:bold;color:#95a5a6'>{sum(1 for v in vulns if v['severity']=='low')}</p></div>
<div class='kpi-card' style='border-color:#3498db'><h3>Risk Score</h3><p style='font-size:30px;font-weight:bold;color:#3498db'>{pct}%</p></div>
</div>
<h2>Detailed Findings</h2>
<table><tr><th>#</th><th>Severity</th><th>Category</th><th>Title</th><th>Details</th><th>Remediation</th><th>Compliance Controls</th></tr>
{rows}</table>
<p style='color:#888;font-size:11px;margin-top:20px'>Generated by RAVEN-X Enterprise v4.0 | For authorized use only</p>
</div></body></html>"""

# ══════════════════════════════════════════════════════════════════════════
# GUI
# ══════════════════════════════════════════════════════════════════════════
class VulnerabilityGUI:
    # ── init ────────────────────────────────────────────────────────────────
    def __init__(self):
        ctk.set_appearance_mode("light")
        ctk.set_default_color_theme("blue")
        self.root = ctk.CTk()
        self.root.title("RAVEN-X Enterprise v4.0")
        self.root.geometry("1440x920")
        # centre window
        self.root.update_idletasks()
        w,h = self.root.winfo_width(), self.root.winfo_height()
        self.root.geometry(f"{w}x{h}+{(self.root.winfo_screenwidth()-w)//2}+{(self.root.winfo_screenheight()-h)//2}")

        self.scanner      = VulnerabilityScanner()
        self.db           = DB()
        self.vulnerabilities = []
        self.is_scanning  = False
        self.config       = self._load_config()
        self.email_mgr    = EmailManager(self.config)

        self.C = dict(
            bg_primary="#f5f7fa", bg_secondary="#ffffff",
            sidebar="#2c3e50", accent="#3498db", accent_hover="#2980b9",
            text_primary="#2c3e50", text_secondary="#7f8c8d",
            border="#e1e8ed", critical="#e74c3c", high="#e67e22",
            medium="#f39c12", low="#95a5a6", success="#27ae60", warning="#f1c40f"
        )
        self._build_ui()
        if not is_admin():
            self.root.after(200, self._warn_admin)

    def _load_config(self):
        defaults = dict(
            lm_studio_url="http://localhost:1234/v1", model_name="llama-3.1-8b",
            safe_mode=True, auto_create_restore=True, schedule_interval=24,
            export_format="html", smtp_server="smtp.gmail.com", smtp_port=587,
            smtp_user="", smtp_pass="", email_recipients="", alert_on_critical=True
        )
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE) as f: defaults.update(json.load(f))
            except: pass
        return defaults

    def _save_config(self):
        with open(CONFIG_FILE,"w") as f: json.dump(self.config,f,indent=2)

    def _warn_admin(self):
        if messagebox.askyesno("Admin Required",
            "Running without admin rights. Some checks will be limited.\n\nRestart as Administrator?",
            parent=self.root):
            ctypes.windll.shell32.ShellExecuteW(None,"runas",sys.executable," ".join(sys.argv),None,1)
            sys.exit()

    # ── UI scaffold ─────────────────────────────────────────────────────────
    def _build_ui(self):
        main = ctk.CTkFrame(self.root, fg_color=self.C["bg_primary"])
        main.pack(fill="both", expand=True)

        # ── sidebar ──────────────────────────────────────────────────────────
        sb = ctk.CTkFrame(main, width=340, fg_color=self.C["sidebar"], corner_radius=0)
        sb.pack(side="left", fill="y"); sb.pack_propagate(False)

        ctk.CTkLabel(sb, text="RAVEN-X", font=("Segoe UI",30,"bold"),
                     text_color="#fff").pack(pady=(30,2))
        ctk.CTkLabel(sb, text="Enterprise v4.0", font=("Segoe UI",12),
                     text_color="#bdc3c7").pack()
        ctk.CTkLabel(sb, text="AI-Powered Security Scanner", font=("Segoe UI",9),
                     text_color="#7f8c8d").pack(pady=(0,20))

        # progress
        self._prog_lbl = ctk.CTkLabel(sb, text="", font=("Segoe UI",10), text_color="#bdc3c7")
        self._prog_lbl.pack(padx=20, fill="x")
        self._prog_bar = ctk.CTkProgressBar(sb, height=8)
        self._prog_bar.pack(padx=20, fill="x", pady=(4,15)); self._prog_bar.set(0)

        # scan buttons
        for text, cmd, fg, hov in [
            ("🔍  Start Full Scan", self.start_scan, self.C["accent"], self.C["accent_hover"]),
            ("⚡  Quick Scan",      self.start_quick_scan, self.C["medium"], "#e67e22"),
        ]:
            ctk.CTkButton(sb, text=text, command=cmd, height=46, font=("Segoe UI",13,"bold"),
                          fg_color=fg, hover_color=hov, corner_radius=8
                          ).pack(padx=20, fill="x", pady=4)

        # stats box
        stats_box = ctk.CTkFrame(sb, fg_color="#34495e", corner_radius=10)
        stats_box.pack(padx=20, pady=15, fill="x")
        ctk.CTkLabel(stats_box, text="Last Scan Summary", font=("Segoe UI",11,"bold"),
                     text_color="#fff").pack(pady=(12,6))
        self._risk_lbl    = ctk.CTkLabel(stats_box, text="Risk: –", font=("Segoe UI",18,"bold"), text_color="#fff")
        self._risk_lbl.pack()
        self._stats = {}
        for sev,color,sym in [("critical","#e74c3c","🔴"),("high","#e67e22","🟠"),
                               ("medium","#f39c12","🟡"),("low","#95a5a6","⚪")]:
            lbl = ctk.CTkLabel(stats_box, text=f"{sym} {sev.capitalize()}: 0",
                               font=("Segoe UI",11), text_color=color)
            lbl.pack(pady=2); self._stats[sev] = lbl
        self._total_lbl = ctk.CTkLabel(stats_box, text="Total Issues: 0",
                                       font=("Segoe UI",12,"bold"), text_color="#fff")
        self._total_lbl.pack(pady=(8,14))

        # action buttons
        actions = [
            ("🤖  AI Analysis",     self.get_ai_analysis, "#9b59b6","#8e44ad","ai"),
            ("🔧  Fix Issues",      self.fix_vulnerabilities, self.C["success"],"#229954","fix"),
            ("📤  Export Report",   self.export_report, self.C["accent"],self.C["accent_hover"],"export"),
            ("📜  Generate Script", self.generate_remediation_script, "#f39c12","#e67e22","script"),
            ("📋  Copy Results",    self.copy_results, "#7f8c8d","#95a5a6","copy"),
        ]
        self._btns = {}
        for text, cmd, fg, hov, key in actions:
            b = ctk.CTkButton(sb, text=text, command=cmd, height=38,
                              font=("Segoe UI",11), state="disabled",
                              fg_color=fg, hover_color=hov, corner_radius=8)
            b.pack(padx=20, fill="x", pady=3); self._btns[key] = b

        # safe mode
        self._safe_var = ctk.BooleanVar(value=self.config["safe_mode"])
        ctk.CTkSwitch(sb, text="🛡️  Safe Mode (review only)",
                      variable=self._safe_var, command=self._toggle_safe,
                      font=("Segoe UI",10), fg_color=self.C["success"]
                      ).pack(padx=20, pady=15)

        # ── right panel ───────────────────────────────────────────────────
        right = ctk.CTkFrame(main, fg_color=self.C["bg_primary"])
        right.pack(side="right", fill="both", expand=True)

        hbar = ctk.CTkFrame(right, fg_color=self.C["bg_secondary"], height=76, corner_radius=0)
        hbar.pack(fill="x", padx=20, pady=(20,0)); hbar.pack_propagate(False)
        hc = ctk.CTkFrame(hbar, fg_color="transparent")
        hc.pack(fill="both", expand=True, padx=25, pady=10)
        ctk.CTkLabel(hc, text="Security Assessment Dashboard",
                     font=("Segoe UI",20,"bold"), text_color=self.C["text_primary"]).pack(anchor="w")
        self._status_lbl = ctk.CTkLabel(hc, text="Ready – click Scan to begin",
                                        font=("Segoe UI",11), text_color=self.C["text_secondary"])
        self._status_lbl.pack(anchor="w", pady=(3,0))

        # tabs
        self.tabs = ctk.CTkTabview(right, fg_color=self.C["bg_primary"])
        self.tabs.pack(fill="both", expand=True, padx=20, pady=12)
        for name in ["📊 Results","🤖 AI Config","📋 Compliance",
                     "📈 History","💼 Executive","⚙️ Settings","💻 System"]:
            self.tabs.add(name)

        self._setup_results_tab()
        self._setup_ai_tab()
        self._setup_compliance_tab()
        self._setup_history_tab()
        self._setup_executive_tab()
        self._setup_settings_tab()
        self._setup_system_tab()

    # ── tab builders ─────────────────────────────────────────────────────────
    def _textbox(self, parent, **kw):
        defaults = dict(font=("Consolas",11), fg_color="#fafbfc",
                        text_color=self.C["text_primary"],
                        border_width=1, border_color=self.C["border"],
                        corner_radius=6, wrap="word")
        defaults.update(kw)
        return ctk.CTkTextbox(parent, **defaults)

    def _setup_results_tab(self):
        tab = self.tabs.tab("📊 Results")
        f   = ctk.CTkFrame(tab, fg_color=self.C["bg_secondary"], corner_radius=10)
        f.pack(fill="both", expand=True)
        hdr = ctk.CTkFrame(f, fg_color="transparent")
        hdr.pack(fill="x", padx=20, pady=12)
        ctk.CTkLabel(hdr, text="Scan Results", font=("Segoe UI",15,"bold"),
                     text_color=self.C["text_primary"]).pack(side="left")
        flt = ctk.CTkFrame(hdr, fg_color="transparent"); flt.pack(side="right")
        for label, sev, fg in [("All","all",self.C["accent"]),("Critical","critical",self.C["critical"]),
                                ("High","high",self.C["high"]),("Medium","medium",self.C["medium"])]:
            ctk.CTkButton(flt, text=label, width=72, height=28,
                          command=lambda s=sev: self._filter(s),
                          fg_color=fg, hover_color="#555").pack(side="left", padx=2)
        self._res_txt = self._textbox(f)
        self._res_txt.pack(fill="both", expand=True, padx=20, pady=(0,20))
        self._res_txt.insert("1.0", WELCOME_MSG)
        self._res_txt.configure(state="disabled")

    def _setup_ai_tab(self):
        tab = self.tabs.tab("🤖 AI Config")
        f   = ctk.CTkFrame(tab, fg_color=self.C["bg_secondary"], corner_radius=10)
        f.pack(fill="both", expand=True, padx=20, pady=20)
        form = ctk.CTkFrame(f, fg_color="transparent")
        form.pack(fill="x", padx=20, pady=20)
        for row,(lbl,key,show) in enumerate([("LM Studio URL:","lm_studio_url",""),
                                              ("Model Name:","model_name","")]):
            ctk.CTkLabel(form, text=lbl, font=("Segoe UI",12)).grid(row=row,column=0,sticky="w",pady=8)
            e = ctk.CTkEntry(form, width=380, height=36, show=show,
                             border_color=self.C["border"])
            e.insert(0, self.config[key])
            e.grid(row=row, column=1, padx=10, pady=8, sticky="w")
            setattr(self, f"_ai_{key}", e)
        self._conn_status = ctk.CTkLabel(form, text="● Not tested",
                                         font=("Segoe UI",11), text_color=self.C["medium"])
        self._conn_status.grid(row=0, column=2, padx=10)
        ctk.CTkButton(form, text="Test Connection", width=140, height=36,
                      command=self._test_connection,
                      fg_color=self.C["accent"], corner_radius=8
                      ).grid(row=1, column=2, padx=10, pady=8)

    def _setup_compliance_tab(self):
        tab = self.tabs.tab("📋 Compliance")
        f   = ctk.CTkFrame(tab, fg_color=self.C["bg_secondary"], corner_radius=10)
        f.pack(fill="both", expand=True, padx=20, pady=20)
        ctk.CTkLabel(f, text="Compliance Mapping", font=("Segoe UI",15,"bold"),
                     text_color=self.C["text_primary"]).pack(anchor="w", padx=20, pady=(20,10))
        # score cards
        cards = ctk.CTkFrame(f, fg_color="transparent")
        cards.pack(fill="x", padx=20, pady=10)
        self._comp_cards = {}
        for i,fw in enumerate(["CIS","NIST","ISO 27001","PCI-DSS"]):
            card = ctk.CTkFrame(cards, fg_color="#f8f9fa", corner_radius=8, width=200)
            card.grid(row=0,column=i,padx=8,pady=8,sticky="nsew")
            ctk.CTkLabel(card, text=fw, font=("Segoe UI",13,"bold"),
                         text_color=self.C["text_primary"]).pack(pady=(15,4))
            sc = ctk.CTkLabel(card, text="–%", font=("Segoe UI",28,"bold"),
                              text_color=self.C["accent"])
            sc.pack()
            st = ctk.CTkLabel(card, text="No scan yet", font=("Segoe UI",9),
                              text_color=self.C["text_secondary"])
            st.pack(pady=(2,15))
            self._comp_cards[fw] = (sc,st)
        for i in range(4): cards.grid_columnconfigure(i,weight=1)
        # detail table
        ctk.CTkLabel(f, text="Controls by Category", font=("Segoe UI",13,"bold"),
                     text_color=self.C["text_primary"]).pack(anchor="w", padx=20, pady=(10,4))
        self._comp_text = self._textbox(f, height=300)
        self._comp_text.pack(fill="both", expand=True, padx=20, pady=(0,20))

    def _update_compliance_ui(self):
        """Refresh compliance cards and detail text from latest scan."""
        for fw,(score_lbl,status_lbl) in self._comp_cards.items():
            res = self.db.calc_compliance(self.vulnerabilities, fw)
            color = (self.C["success"] if res["score"]>=80
                     else self.C["medium"] if res["score"]>=60 else self.C["critical"])
            score_lbl.configure(text=f"{res['score']}%", text_color=color)
            status_lbl.configure(text=f"{res['passed']}/{res['total']} controls passed")
        # detail text
        lines = []
        for cat, controls_map in COMPLIANCE.items():
            lines.append(f"\n{'─'*50}")
            lines.append(f"  {cat}")
            lines.append(f"{'─'*50}")
            for category, controls in controls_map.items():
                failed = any(v.get("category")==category for v in self.vulnerabilities)
                mark = "❌ FAIL" if failed else "✅ PASS"
                lines.append(f"  {mark}  {category:35s} {', '.join(controls)}")
        self._comp_text.configure(state="normal")
        self._comp_text.delete("1.0","end")
        self._comp_text.insert("1.0","\n".join(lines))
        self._comp_text.configure(state="disabled")

    def _setup_history_tab(self):
        tab = self.tabs.tab("📈 History")
        f   = ctk.CTkFrame(tab, fg_color=self.C["bg_secondary"], corner_radius=10)
        f.pack(fill="both", expand=True, padx=20, pady=20)
        ctk.CTkLabel(f, text="Scan History", font=("Segoe UI",15,"bold"),
                     text_color=self.C["text_primary"]).pack(anchor="w", padx=20, pady=(20,10))
        self._hist_txt = self._textbox(f)
        self._hist_txt.pack(fill="both", expand=True, padx=20, pady=(0,20))
        self._refresh_history()

    def _refresh_history(self):
        rows = self.db.history()
        self._hist_txt.configure(state="normal")
        self._hist_txt.delete("1.0","end")
        if not rows:
            self._hist_txt.insert("1.0","No scan history yet. Run a scan to begin tracking.")
        else:
            header = f"{'Timestamp':<22} {'Host':<20} {'Risk':>6} {'Total':>6} {'C':>4} {'H':>4} {'M':>4} {'L':>4}  Type\n"
            self._hist_txt.insert("end", header + "─"*80+"\n")
            for row in rows:
                _, sid, ts, host, total, crit, high, med, low, risk, dur, stype = row
                self._hist_txt.insert("end",
                    f"{ts[:19]:<22} {host:<20} {risk:>5.1f}% {total:>6} {crit:>4} {high:>4} {med:>4} {low:>4}  {stype}\n")
        self._hist_txt.configure(state="disabled")

    def _setup_executive_tab(self):
        tab = self.tabs.tab("💼 Executive")
        self._exec_frame = ctk.CTkFrame(tab, fg_color=self.C["bg_secondary"], corner_radius=10)
        self._exec_frame.pack(fill="both", expand=True, padx=20, pady=20)
        ctk.CTkLabel(self._exec_frame, text="Executive Dashboard",
                     font=("Segoe UI",16,"bold"), text_color=self.C["text_primary"]
                     ).pack(anchor="w", padx=20, pady=(20,10))
        self._exec_txt = self._textbox(self._exec_frame, font=("Segoe UI",11))
        self._exec_txt.pack(fill="both", expand=True, padx=20, pady=(0,20))
        self._exec_txt.insert("1.0","Run a scan to populate this dashboard.")
        self._exec_txt.configure(state="disabled")

    def _update_executive_ui(self):
        pct, level = self.scanner.risk_score()
        stats = {s:sum(1 for v in self.vulnerabilities if v["severity"]==s)
                 for s in ["critical","high","medium","low"]}
        crit_list = [v for v in self.vulnerabilities if v["severity"]=="critical"]
        top5 = "\n".join(f"  {i+1}. [{cvss_for(v):.1f}] {v['title']}"
                         for i,v in enumerate(crit_list[:5]))
        comp_lines = ""
        for fw in ["CIS","NIST","ISO 27001","PCI-DSS"]:
            r = self.db.calc_compliance(self.vulnerabilities, fw)
            bar = "█"*int(r["score"]//10)+"░"*(10-int(r["score"]//10))
            comp_lines += f"  {fw:<12} [{bar}] {r['score']:>5.1f}%  ({r['passed']}/{r['total']} passed)\n"
        text = f"""{'='*60}
  RAVEN-X ENTERPRISE — EXECUTIVE SUMMARY
{'='*60}
  System  : {self.scanner.system_info.get('hostname','N/A')}
  Scan ID : {self.scanner.scan_id}
  Time    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  Risk    : {pct}%  ({level})

{'─'*60}
  VULNERABILITY COUNTS
{'─'*60}
  🔴 Critical  : {stats['critical']:>4}
  🟠 High      : {stats['high']:>4}
  🟡 Medium    : {stats['medium']:>4}
  ⚪ Low       : {stats['low']:>4}
  ─────────────────────
  Total        : {len(self.vulnerabilities):>4}

{'─'*60}
  TOP {min(5,len(crit_list))} CRITICAL RISKS (CVSS Score)
{'─'*60}
{top5 if top5 else '  None — great job!'}

{'─'*60}
  COMPLIANCE STATUS
{'─'*60}
{comp_lines}
{'─'*60}
  RECOMMENDED ACTIONS
{'─'*60}
  1. Address all CRITICAL issues within 24 hours
  2. Fix HIGH severity issues within 7 days
  3. Use 'Generate Script' for automated remediation
  4. Re-scan after applying fixes
  5. Schedule weekly automated scans
{'='*60}
"""
        self._exec_txt.configure(state="normal")
        self._exec_txt.delete("1.0","end")
        self._exec_txt.insert("1.0",text)
        self._exec_txt.configure(state="disabled")

    def _setup_settings_tab(self):
        tab = self.tabs.tab("⚙️ Settings")
        sf  = ctk.CTkScrollableFrame(tab, fg_color=self.C["bg_secondary"], corner_radius=10)
        sf.pack(fill="both", expand=True, padx=20, pady=20)
        ctk.CTkLabel(sf, text="Settings", font=("Segoe UI",15,"bold"),
                     text_color=self.C["text_primary"]).grid(row=0,column=0,sticky="w",pady=(10,20),columnspan=3)

        fields = [
            ("SMTP Server:",   "smtp_server",  ""),
            ("SMTP Port:",     "smtp_port",    ""),
            ("Email Address:", "smtp_user",    ""),
            ("Email Password:","smtp_pass",    "*"),
            ("Recipients (comma-sep):","email_recipients",""),
        ]
        self._sett_entries = {}
        for r,(lbl,key,show) in enumerate(fields,1):
            ctk.CTkLabel(sf, text=lbl, font=("Segoe UI",12)).grid(row=r,column=0,sticky="w",padx=10,pady=8)
            e = ctk.CTkEntry(sf, width=340, height=35, show=show)
            e.insert(0, str(self.config.get(key,"")))
            e.grid(row=r,column=1,padx=10,pady=8,sticky="w")
            self._sett_entries[key] = e

        # restore toggle
        self._restore_var = ctk.BooleanVar(value=self.config.get("auto_create_restore",True))
        ctk.CTkSwitch(sf, text="Create restore point before fixes",
                      variable=self._restore_var, fg_color=self.C["success"]
                      ).grid(row=len(fields)+1,column=0,sticky="w",padx=10,pady=10,columnspan=2)

        # export format
        ctk.CTkLabel(sf, text="Export Format:", font=("Segoe UI",12)
                     ).grid(row=len(fields)+2,column=0,sticky="w",padx=10,pady=8)
        self._fmt_var = ctk.StringVar(value=self.config.get("export_format","html").upper())
        ctk.CTkOptionMenu(sf, variable=self._fmt_var, values=["HTML","JSON","CSV"],
                          width=140).grid(row=len(fields)+2,column=1,padx=10,pady=8,sticky="w")

        ctk.CTkButton(sf, text="💾  Save Settings", command=self._save_settings,
                      height=44, font=("Segoe UI",12,"bold"),
                      fg_color=self.C["success"], corner_radius=8
                      ).grid(row=len(fields)+3,column=0,pady=20,columnspan=2,sticky="w",padx=10)

    def _save_settings(self):
        for key,entry in self._sett_entries.items():
            self.config[key] = entry.get()
        self.config["auto_create_restore"] = self._restore_var.get()
        self.config["export_format"] = self._fmt_var.get().lower()
        self.email_mgr = EmailManager(self.config)
        self._save_config()
        messagebox.showinfo("Settings","Settings saved successfully!", parent=self.root)

    def _setup_system_tab(self):
        tab = self.tabs.tab("💻 System")
        f   = ctk.CTkFrame(tab, fg_color=self.C["bg_secondary"], corner_radius=10)
        f.pack(fill="both", expand=True, padx=20, pady=20)
        hdr = ctk.CTkFrame(f, fg_color="transparent")
        hdr.pack(fill="x", padx=20, pady=(20,10))
        ctk.CTkLabel(hdr, text="System Information", font=("Segoe UI",15,"bold"),
                     text_color=self.C["text_primary"]).pack(side="left")
        ctk.CTkButton(hdr, text="🔄 Refresh", command=self._refresh_system,
                      width=100, height=32).pack(side="right")
        self._sys_txt = self._textbox(f)
        self._sys_txt.pack(fill="both", expand=True, padx=20, pady=(0,20))
        self._refresh_system()

    def _refresh_system(self):
        try:
            mem  = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            info = f"""
  OS          : {platform.platform()}
  Architecture: {platform.architecture()[0]}
  Hostname    : {socket.gethostname()}
  Processor   : {platform.processor()[:60]}

  CPU Cores   : {psutil.cpu_count(logical=True)} logical
  CPU Usage   : {psutil.cpu_percent(interval=0.5)}%
  RAM Total   : {mem.total//(1024**3)} GB
  RAM Used    : {mem.used//(1024**3)} GB  ({mem.percent}%)
  Disk Total  : {disk.total//(1024**3)} GB
  Disk Used   : {disk.used//(1024**3)} GB  ({disk.percent}%)

  Python      : {platform.python_version()}
  Admin       : {'Yes ✅' if is_admin() else 'No ⚠️'}
  Scan ID     : {self.scanner.scan_id}
  RAVEN-X     : Enterprise v4.0
"""
        except Exception as e: info = f"Error: {e}"
        self._sys_txt.configure(state="normal")
        self._sys_txt.delete("1.0","end")
        self._sys_txt.insert("1.0",info)
        self._sys_txt.configure(state="disabled")

    # ── scan flow ────────────────────────────────────────────────────────────
    def _update_progress(self, current, total, msg):
        self._prog_bar.set(current/total if total else 0)
        self._prog_lbl.configure(text=f"{msg} ({current}/{total})")
        self.root.update()

    def start_scan(self):
        if self.is_scanning: return
        self._begin_scan("full")
        def run():
            try:
                self.vulnerabilities = self.scanner.scan_all(self._update_progress)
                self.root.after(0, self._show_results)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Scan Error", str(e)))
            finally: self.root.after(0, self._end_scan)
        threading.Thread(target=run, daemon=True).start()

    def start_quick_scan(self):
        if self.is_scanning: return
        self._begin_scan("quick")
        def run():
            try:
                self.scanner.vulnerabilities = []
                for fn in [self.scanner.check_windows_updates,
                           self.scanner.check_firewall,
                           self.scanner.check_antivirus,
                           self.scanner.check_defender_exclusions,
                           self.scanner.check_open_ports,
                           self.scanner.check_smb_protocol,
                           self.scanner.check_powershell_execution_policy]:
                    fn()
                self.vulnerabilities = self.scanner.vulnerabilities
                self.root.after(0, self._show_results)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Quick Scan Error",str(e)))
            finally: self.root.after(0, self._end_scan)
        threading.Thread(target=run, daemon=True).start()

    def _begin_scan(self, kind):
        self.is_scanning = True
        label = "🔍 Scanning…" if kind=="full" else "⚡ Quick Scanning…"
        self._btns["ai"].configure(state="disabled")
        self._btns["fix"].configure(state="disabled")
        self._btns["export"].configure(state="disabled")
        self._btns["script"].configure(state="disabled")
        self._btns["copy"].configure(state="disabled")
        self._status_lbl.configure(text=f"Running {kind} scan…")
        self._res_txt.configure(state="normal")
        self._res_txt.delete("1.0","end")
        self._res_txt.insert("1.0",f"🚀 Starting {kind} scan…\n{'='*60}\n\n")
        self._res_txt.configure(state="disabled")

    def _end_scan(self):
        self.is_scanning = False
        self._prog_bar.set(0); self._prog_lbl.configure(text="")

    def _show_results(self):
        vulns = self.vulnerabilities
        sev_order = {"critical":0,"high":1,"medium":2,"low":3}
        sorted_v  = sorted(vulns, key=lambda v: sev_order.get(v["severity"],4))
        stats = {s:sum(1 for v in vulns if v["severity"]==s)
                 for s in ["critical","high","medium","low"]}
        pct, level = self.scanner.risk_score()

        # update sidebar
        for sev,lbl in self._stats.items():
            sym = {"critical":"🔴","high":"🟠","medium":"🟡","low":"⚪"}[sev]
            lbl.configure(text=f"{sym} {sev.capitalize()}: {stats[sev]}")
        self._total_lbl.configure(text=f"Total Issues: {len(vulns)}")
        self._risk_lbl.configure(text=f"Risk: {pct}%")
        self._status_lbl.configure(text=f"Scan complete – {len(vulns)} issues | Risk {pct}% ({level})")

        # build result text
        sev_sym = {"critical":"🔴 CRITICAL","high":"🟠 HIGH","medium":"🟡 MEDIUM","low":"⚪ LOW"}
        lines = [f"SECURITY SCAN COMPLETE — {len(vulns)} ISSUES FOUND",
                 f"Risk Score: {pct}% ({level})  |  Scan ID: {self.scanner.scan_id}",
                 f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                 "","─"*60]
        for i,v in enumerate(sorted_v,1):
            lines += [f"\n{i}. {sev_sym.get(v['severity'],'UNKNOWN')} — {v['title']}",
                      f"   Category : {v['category']}",
                      f"   Component: {v['component']}",
                      f"   Details  : {v['details']}",
                      f"   Fix      : {v.get('remediation','')}",
                      "   "+"-"*50]
        lines += ["","─"*60,"NEXT STEPS:",
                  "  1. Review critical issues first",
                  "  2. Click 'Generate Script' for automated PowerShell fixes",
                  "  3. Use 'AI Analysis' for detailed guidance",
                  "  4. Export report for compliance/documentation"]
        if self.config["safe_mode"]:
            lines.append("\n⚠️  SAFE MODE: No changes will be made automatically")

        self._res_txt.configure(state="normal")
        self._res_txt.delete("1.0","end")
        self._res_txt.insert("1.0","\n".join(lines))
        self._res_txt.configure(state="disabled")

        # enable buttons
        for b in self._btns.values(): b.configure(state="normal")

        # update other tabs
        self._update_compliance_ui()
        self._update_executive_ui()
        self._refresh_history()

        # save to DB
        end = self.scanner.scan_end_time or datetime.now()
        dur = (end - self.scanner.scan_start_time).total_seconds() if self.scanner.scan_start_time else 0
        self.db.save({
            "scan_id": self.scanner.scan_id,
            "ts": datetime.now().isoformat(),
            "host": socket.gethostname(),
            "total": len(vulns), "critical": stats["critical"],
            "high": stats["high"], "medium": stats["medium"],
            "low": stats["low"], "risk_score": pct,
            "duration": dur, "vulns": vulns
        })

        # email alert for criticals
        if (self.config.get("alert_on_critical") and stats["critical"] > 0
                and self.config.get("smtp_user") and self.config.get("email_recipients")):
            recs = [r.strip() for r in self.config["email_recipients"].split(",") if r.strip()]
            crit = [v for v in vulns if v["severity"]=="critical"]
            threading.Thread(
                target=self.email_mgr.send_alert,
                args=({"host":socket.gethostname(),"risk_score":pct,"scan_id":self.scanner.scan_id},
                      crit, recs),
                daemon=True
            ).start()

    def _filter(self, sev):
        if not self.vulnerabilities: return
        if sev == "all": self._show_results(); return
        filtered = [v for v in self.vulnerabilities if v["severity"]==sev]
        self._res_txt.configure(state="normal")
        self._res_txt.delete("1.0","end")
        if not filtered:
            self._res_txt.insert("1.0",f"No {sev} severity issues found.")
        else:
            lines=[f"{sev.upper()} ISSUES ({len(filtered)} found)\n","─"*60]
            for i,v in enumerate(filtered,1):
                lines+=[f"\n{i}. {v['title']}",
                        f"   Category : {v['category']}",
                        f"   Details  : {v['details']}",
                        f"   Fix      : {v.get('remediation','')}",
                        "   "+"-"*40]
            self._res_txt.insert("1.0","\n".join(lines))
        self._res_txt.configure(state="disabled")

    # ── actions ─────────────────────────────────────────────────────────────
    def generate_remediation_script(self):
        """
        Generate a clean, working PowerShell remediation script.
        Each fix is wrapped in its own try/catch and written as LIVE code
        (not commented out) so the script is immediately executable.
        A -WhatIf / -DryRun switch lets users preview before applying.
        """
        if not self.vulnerabilities:
            messagebox.showinfo("Nothing to fix", "Run a scan first.", parent=self.root)
            return

        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_v = sorted(self.vulnerabilities, key=lambda v: order.get(v["severity"], 4))

        # ── Only include vulns that have a real PS command ────────────────
        fixable   = [v for v in sorted_v
                     if v.get("powershell_command", "").strip()
                     and not v["powershell_command"].strip().startswith("#")]
        no_fix    = [v for v in sorted_v
                     if not v.get("powershell_command", "").strip()
                     or v["powershell_command"].strip().startswith("#")]

        host    = socket.gethostname()
        scan_id = self.scanner.scan_id
        ts      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        lines = [
            "#Requires -RunAsAdministrator",
            "<#",
            ".SYNOPSIS",
            "    RAVEN-X Enterprise — Automated Remediation Script",
            ".DESCRIPTION",
            f"    Generated : {ts}",
            f"    Scan ID   : {scan_id}",
            f"    Host      : {host}",
            f"    Fixable   : {len(fixable)} issue(s)",
            f"    Manual    : {len(no_fix)} issue(s) require manual action",
            "",
            "    Run with  -DryRun to preview changes without applying them.",
            "    Run without flags to apply all fixes.",
            ".EXAMPLE",
            "    .\\RAVENX_Remediation.ps1 -DryRun",
            "    .\\RAVENX_Remediation.ps1",
            "#>",
            "",
            "param(",
            "    [switch]$DryRun",
            ")",
            "",
            "# ── Initialise ────────────────────────────────────────────────────",
            "$ErrorActionPreference = 'Stop'",
            "$Results   = [System.Collections.Generic.List[PSObject]]::new()",
            "$StartTime = Get-Date",
            "",
            'if ($DryRun) { Write-Host "[DRY RUN MODE — no changes will be made]" -ForegroundColor Yellow }',
            "",
            "# ── Helper function ───────────────────────────────────────────────",
            "function Invoke-Fix {",
            "    param([string]$Title, [string]$Severity, [string]$Category, [scriptblock]$Action)",
            "    $status  = 'Skipped'",
            "    $message = ''",
            "    try {",
            "        if (-not $DryRun) {",
            "            & $Action",
            "            $status = 'Fixed'",
            '            Write-Host "  [OK] $Title" -ForegroundColor Green',
            "        } else {",
            "            $status  = 'DryRun'",
            '            Write-Host "  [DR] $Title" -ForegroundColor Cyan',
            "        }",
            "    } catch {",
            "        $status  = 'Failed'",
            "        $message = $_.Exception.Message",
            '        Write-Host "  [!!] $Title — $message" -ForegroundColor Red',
            "    }",
            "    $Results.Add([PSCustomObject]@{",
            "        Severity = $Severity",
            "        Category = $Category",
            "        Fix      = $Title",
            "        Status   = $status",
            "        Message  = $message",
            "    })",
            "}",
            "",
        ]

        # ── Fixable blocks grouped by severity ────────────────────────────
        current_sev = None
        for v in fixable:
            sev = v["severity"]
            if sev != current_sev:
                current_sev = sev
                lines += [
                    "",
                    f"# {'=' * 60}",
                    f"# {sev.upper()} SEVERITY",
                    f"# {'=' * 60}",
                ]

            title    = v.get("title", "Unknown").replace("'", "''").replace('"', '`"')
            category = v.get("category", "").replace("'", "''")
            detail   = v.get("details", "").replace("'", "''")
            rem      = v.get("remediation", "").replace("'", "''")
            cmd      = v["powershell_command"].strip()

            lines.append("")
            lines.append(f"# {v.get('title','')} — {v.get('category','')}")
            lines.append(f"# Details : {v.get('details','')}")
            lines.append(f"# Fix     : {v.get('remediation','')}")

            # Build the scriptblock — indent each cmd line
            cmd_lines = [f"        {cl.strip()}" for cl in cmd.splitlines() if cl.strip()]
            sb_body   = "\n".join(cmd_lines)

            lines.append(f"Invoke-Fix -Title '{title}' -Severity '{sev}' -Category '{category}' -Action {{")
            lines.append(sb_body)
            lines.append("}")

        # ── Manual-only section ───────────────────────────────────────────
        if no_fix:
            lines += [
                "",
                "",
                f"# {'=' * 60}",
                "# MANUAL ACTION REQUIRED (no automated fix available)",
                f"# {'=' * 60}",
            ]
            for v in no_fix:
                lines.append(f"# [{v['severity'].upper()}] {v.get('title','')}")
                lines.append(f"#   Category   : {v.get('category','')}")
                lines.append(f"#   Details    : {v.get('details','')}")
                lines.append(f"#   Action     : {v.get('remediation','')}")
                lines.append("#")

        # ── Summary report ────────────────────────────────────────────────
        lines += [
            "",
            "",
            "# ── Summary ──────────────────────────────────────────────────────",
            "$Duration = (Get-Date) - $StartTime",
            "Write-Host ''",
            r'Write-Host "╔══════════════════════════════════════════════╗" -ForegroundColor Cyan',
            r'Write-Host "║        RAVEN-X REMEDIATION SUMMARY           ║" -ForegroundColor Cyan',
            r'Write-Host "╚══════════════════════════════════════════════╝" -ForegroundColor Cyan',
            "",
            "if ($Results.Count -gt 0) {",
            "    $Results | Sort-Object Severity, Status | Format-Table Severity,Category,Fix,Status,Message -AutoSize -Wrap",
            "    $fixed   = ($Results | Where-Object { $_.Status -eq 'Fixed'   }).Count",
            "    $failed  = ($Results | Where-Object { $_.Status -eq 'Failed'  }).Count",
            "    $dryrun  = ($Results | Where-Object { $_.Status -eq 'DryRun'  }).Count",
            '    Write-Host "Fixed   : $fixed"   -ForegroundColor Green',
            '    Write-Host "Failed  : $failed"  -ForegroundColor Red',
            '    if ($dryrun -gt 0) { Write-Host "DryRun  : $dryrun" -ForegroundColor Cyan }',
            "} else {",
            '    Write-Host "No automated fixes were run." -ForegroundColor Yellow',
            "}",
            "",
            f'Write-Host ""',
            f'Write-Host "Manual action required for {len(no_fix)} issue(s) — see comments above."',
            r'Write-Host "Duration: $($Duration.TotalSeconds.ToString(\"F1\"))s"',
            r'Write-Host "Re-run RAVEN-X scan after applying fixes to verify."',
        ]

        # ── Save ──────────────────────────────────────────────────────────
        fname = filedialog.asksaveasfilename(
            parent=self.root,
            defaultextension=".ps1",
            filetypes=[("PowerShell Script", "*.ps1"), ("All Files", "*.*")],
            initialfile=f"RAVENX_Remediation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.ps1"
        )
        if not fname:
            return

        script_content = "\n".join(lines)
        try:
            with open(fname, "w", encoding="utf-8") as f:
                f.write(script_content)

            msg = (
                f"Script saved to:\n{fname}\n\n"
                f"• {len(fixable)} automated fix(es)\n"
                f"• {len(no_fix)} manual action(s)\n\n"
                f"Run with:  .\\{os.path.basename(fname)} -DryRun   (preview)\n"
                f"Run with:  .\\{os.path.basename(fname)}           (apply)\n\n"
                f"Open in Notepad to review?"
            )
            if messagebox.askyesno("Script Saved", msg, parent=self.root):
                subprocess.Popen(["notepad.exe", fname])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save script:\n{e}", parent=self.root)

    def export_report(self):
        if not self.vulnerabilities:
            messagebox.showinfo("Nothing to Export","Run a scan first.",parent=self.root); return
        fmt = self.config.get("export_format","html").lower()
        if fmt=="html":
            content  = self.scanner.generate_html_report()
            ext,mime = "html","HTML files"
        elif fmt=="json":
            pct,level = self.scanner.risk_score()
            content   = json.dumps({"scan_id":self.scanner.scan_id,
                                    "timestamp":datetime.now().isoformat(),
                                    "risk_score":pct,"risk_level":level,
                                    "vulnerabilities":self.vulnerabilities},indent=2,default=str)
            ext,mime = "json","JSON files"
        else:
            import io; buf=io.StringIO(); w=csv.writer(buf)
            w.writerow(["Severity","Category","Title","Details","Remediation","CVSS"])
            for v in self.vulnerabilities:
                w.writerow([v["severity"],v["category"],v["title"],
                            v["details"],v.get("remediation",""),cvss_for(v)])
            content=buf.getvalue(); ext,mime="csv","CSV files"

        fname = filedialog.asksaveasfilename(
            parent=self.root, defaultextension=f".{ext}",
            filetypes=[(mime,f"*.{ext}"),("All Files","*.*")],
            initialfile=f"RAVENX_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}")
        if fname:
            with open(fname,"w",encoding="utf-8") as f: f.write(content)
            messagebox.showinfo("Exported",f"Report saved:\n{fname}",parent=self.root)
            if ext=="html": webbrowser.open(f"file://{os.path.abspath(fname)}")

    def copy_results(self):
        text = self._res_txt.get("1.0","end-1c")
        self.root.clipboard_clear(); self.root.clipboard_append(text)
        messagebox.showinfo("Copied","Results copied to clipboard!",parent=self.root)

    def fix_vulnerabilities(self):
        if not self.vulnerabilities:
            messagebox.showinfo("Nothing","Run a scan first.",parent=self.root); return
        if self.config["safe_mode"]:
            if not messagebox.askyesno("Safe Mode Active",
                "Safe Mode is ON.\nDisable it and apply fixes?",parent=self.root): return
            self.config["safe_mode"]=False; self._safe_var.set(False)
        if not messagebox.askyesno("Confirm Fixes",
            f"Apply automated fixes for {len(self.vulnerabilities)} issues?\n\nA restore point will be created first (if enabled).",
            parent=self.root): return
        if self.config.get("auto_create_restore") and is_admin():
            self._status_lbl.configure(text="Creating restore point…")
            run_ps('Checkpoint-Computer -Description "RAVEN-X Pre-Fix" -RestorePointType MODIFY_SETTINGS',30)
        self._status_lbl.configure(text="Applying fixes…")
        self._btns["fix"].configure(state="disabled",text="Fixing…")
        def run():
            results=[]
            for v in self.vulnerabilities:
                cmd = v.get("powershell_command","").strip()
                if not cmd or cmd.startswith("#"): continue
                try:
                    r = run_ps(cmd, timeout=20)
                    # run_ps returns None on failure; treat as failure
                    if r is None:
                        results.append(f"✗ {v['title']} – command failed (no output)")
                    else:
                        results.append(f"✓ {v['title']}")
                except Exception as e:
                    results.append(f"✗ {v['title']}: {e}")
            self.root.after(0,lambda: self._show_fix_results(results))
        threading.Thread(target=run,daemon=True).start()

    def _show_fix_results(self, results):
        self._btns["fix"].configure(state="normal",text="🔧  Fix Issues")
        self._status_lbl.configure(text="Fixes applied – run new scan to verify")
        ok = sum(1 for r in results if r.startswith("✓"))
        fail = sum(1 for r in results if r.startswith("✗"))
        summary = f"FIXES APPLIED\n{'─'*40}\n"
        summary += "\n".join(results)
        summary += f"\n{'─'*40}\n✓ {ok} fixed   ✗ {fail} failed\n"
        if messagebox.askyesno("Fix Results",
            f"{ok} fixes applied, {fail} failed.\n\nRun a new scan to verify?\nReboot to see the changes",parent=self.root):
            self.start_scan()

    def get_ai_analysis(self):
        if not self.vulnerabilities:
            messagebox.showinfo("Nothing","Run a scan first.",parent=self.root); return
        self._btns["ai"].configure(state="disabled",text="Analyzing…")
        url   = self._ai_lm_studio_url.get()
        model = self._ai_model_name.get()
        self.config["lm_studio_url"]=url; self.config["model_name"]=model

        summary = "\n\n".join(
            f"[{v['severity'].upper()}] {v['title']}\nCategory: {v['category']}\n"
            f"Details: {v['details']}\nFix: {v.get('remediation','')}"
            for v in self.vulnerabilities[:20])

        def run():
            try:
                client = OpenAI(base_url=url, api_key="lm-studio")
                resp   = client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role":"system","content":"You are an expert Windows security analyst."},
                        {"role":"user","content":
                            f"Analyse these vulnerabilities and provide:\n"
                            f"1. Executive summary\n2. Top 5 priorities\n"
                            f"3. Step-by-step remediation\n4. Compliance implications\n\n{summary}"}
                    ], temperature=0.7, max_tokens=3000)
                analysis = resp.choices[0].message.content
            except Exception as e:
                analysis = f"⚠️  Could not connect to LM Studio.\n\nError: {e}\n\nEnsure LM Studio is running at {url}."
            self.root.after(0,lambda: self._show_ai_window(analysis))
            self.root.after(0,lambda: self._btns["ai"].configure(state="normal",text="🤖  AI Analysis"))
        threading.Thread(target=run,daemon=True).start()

    def _show_ai_window(self, text):
        win = ctk.CTkToplevel(self.root)
        win.title("AI Security Analysis"); win.geometry("1100x750")
        ctk.CTkLabel(win,text="🤖 AI Security Analysis",font=("Segoe UI",18,"bold")).pack(pady=20)
        tb = ctk.CTkTextbox(win,font=("Segoe UI",11),wrap="word")
        tb.pack(fill="both",expand=True,padx=20,pady=(0,10))
        tb.insert("1.0",text); tb.configure(state="disabled")
        ctk.CTkButton(win,text="Close",command=win.destroy,width=120).pack(pady=10)

    def _test_connection(self):
        self._conn_status.configure(text="● Testing…",text_color=self.C["medium"])
        url   = self._ai_lm_studio_url.get()
        model = self._ai_model_name.get()
        def run():
            try:
                client=OpenAI(base_url=url,api_key="lm-studio")
                resp=client.chat.completions.create(
                    model=model,messages=[{"role":"user","content":"Reply with OK"}],max_tokens=5)
                self.root.after(0,lambda: self._conn_status.configure(
                    text="● Connected ✅",text_color=self.C["success"]))
            except Exception as e:
                self.root.after(0,lambda: self._conn_status.configure(
                    text="● Failed ✗",text_color=self.C["critical"]))
        threading.Thread(target=run,daemon=True).start()

    def _toggle_safe(self):
        self.config["safe_mode"]=self._safe_var.get(); self._save_config()

    # ── run ────────────────────────────────────────────────────────────────
    def run(self):
        if not os.path.exists(".disclaimer_shown"):
            if messagebox.askyesno("Disclaimer",
                "RAVEN-X is for AUTHORIZED security testing only.\n\n"
                "By continuing you confirm you have permission to scan this system.\n\n"
                "Accept?", parent=self.root):
                open(".disclaimer_shown","w").write("1")
            else:
                self.root.destroy(); return
        self.root.mainloop()

# ── welcome message ─────────────────────────────────────────────────────────
WELCOME_MSG = """╔══════════════════════════════════════════════════════════════╗
║          RAVEN-X Enterprise Security Scanner v4.0            ║
║          AI-Powered Windows Vulnerability Assessment         ║
╚══════════════════════════════════════════════════════════════╝

Welcome! This enterprise scanner checks 26 security categories:

  Security Checks              Compliance & Reporting
  ─────────────────            ──────────────────────
  Windows Updates              CIS Controls
  Firewall (all profiles)      NIST 800-53
  Windows Defender             ISO 27001
  Defender Exclusions          PCI-DSS
  UAC Configuration
  Auto-Login                   Enterprise Features
  Remote Desktop / NLA         ─────────────────────
  Guest & Admin Accounts       Email Alerts
  Open Ports                   Scan History DB
  Network Sharing              Executive Dashboard
  SMBv1 Protocol               Trend Analysis
  Password Policy              Compliance Scoring
  BitLocker Encryption         AI-Powered Analysis
  PowerShell Policy            Remediation Scripts
  Audit Policy                 HTML/JSON/CSV Reports
  AutoRun Settings
  Suspicious Startup Programs
  Wi-Fi Security
  Services
  NTP / Time Sync
  Telnet Client
  DNS Settings
  File Integrity

Click "Start Full Scan" for a comprehensive assessment,
or "Quick Scan" for a rapid critical-only check.
"""

# ── entry point ─────────────────────────────────────────────────────────────
def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║          RAVEN-X Enterprise Security Scanner v4.0            ║
╚══════════════════════════════════════════════════════════════╝
Loading…
""")
    if sys.version_info < (3,7):
        print("Python 3.7+ required."); sys.exit(1)
    VulnerabilityGUI().run()

if __name__ == "__main__":
    main()