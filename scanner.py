"""
RAVEN-X: Rapid AI Vulnerability and Exploitation Nexus
AI-Powered Windows Vulnerability Scanner with Local LLM (LM Studio)
Professional Corporate UI Edition v3.0

IMPORTANT DISCLAIMER:
This tool is for educational and authorized security testing purposes only.
Always ensure you have proper authorization before scanning systems.
Some fixes require administrator privileges and may modify system settings.

Requires: pip install openai psutil pywin32 customtkinter
"""

import tkinter as tk
import customtkinter as ctk
from tkinter import filedialog, messagebox
import subprocess
import winreg
import os
import sys
import psutil
import json
import socket
import re
import time
import random
import hashlib
import csv
import html
from datetime import datetime, timedelta
from openai import OpenAI
import threading
import logging
import tempfile
import platform
import uuid
import webbrowser
from collections import defaultdict

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('raven_x_scan.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class VulnerabilityScanner:
    def __init__(self):
        self.vulnerabilities = []
        self.scan_start_time = None
        self.scan_end_time = None
        self.system_info = {}
        self.scan_id = str(uuid.uuid4())[:8]

    def get_system_info(self):
        """Gather comprehensive system information"""
        try:
            self.system_info = {
                'os_version': platform.platform(),
                'architecture': platform.architecture()[0],
                'processor': platform.processor(),
                'hostname': socket.gethostname(),
                'scan_id': self.scan_id,
                'scan_time': datetime.now().isoformat()
            }

            # Get RAM
            mem = psutil.virtual_memory()
            self.system_info['total_ram_gb'] = round(mem.total / (1024**3), 2)
            self.system_info['available_ram_gb'] = round(mem.available / (1024**3), 2)

            # Get disk info
            disk = psutil.disk_usage('/')
            self.system_info['total_disk_gb'] = round(disk.total / (1024**3), 2)
            self.system_info['used_disk_gb'] = round(disk.used / (1024**3), 2)

            # Get CPU info
            self.system_info['cpu_cores'] = psutil.cpu_count(logical=True)
            self.system_info['cpu_physical_cores'] = psutil.cpu_count(logical=False)

            logger.info(f"System info gathered: {self.system_info}")
            return self.system_info
        except Exception as e:
            logger.error(f"Error gathering system info: {e}")
            return {}

    def get_defender_status(self):
        """Returns structured Defender status or None if failed"""
        try:
            cmd = '''powershell -NoProfile -ExecutionPolicy Bypass -Command "
$ErrorActionPreference='Stop';
$s = Get-MpComputerStatus;
$p = Get-MpPreference;
@{
    RealTimeProtectionEnabled = $s.RealTimeProtectionEnabled;
    AMRunningMode = $s.AMRunningMode;
    IsTamperProtected = $s.IsTamperProtected;
    AntivirusEnabled = $s.AntivirusEnabled;
    BehaviorMonitorEnabled = $s.BehaviorMonitorEnabled;
    IoavProtectionEnabled = $s.IoavProtectionEnabled;
    NISEnabled = $s.NISEnabled;
    OnAccessProtectionEnabled = $s.OnAccessProtectionEnabled;
    AntivirusSignatureAgeDays = if($s.AntivirusSignatureLastUpdated){((Get-Date) - $s.AntivirusSignatureLastUpdated).Days}else{999};
    MAPSReporting = $p.MAPSReporting;
    SubmitSamplesConsent = $p.SubmitSamplesConsent;
    DisableBlockAtFirstSeen = $p.DisableBlockAtFirstSeen;
    PUAProtection = $p.PUAProtection;
    DisableScriptScanning = $p.DisableScriptScanning;
    DisableArchiveScanning = $p.DisableArchiveScanning;
} | ConvertTo-Json -Compress"
'''
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=12, check=True)
            return json.loads(result.stdout)
        except Exception as e:
            logger.error(f"Defender status query failed: {e}")
            return None

    # ==================== NEW / MISSING CHECKS ====================
    def check_uac(self):
        """Check User Account Control settings"""
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System')
            consent, _ = winreg.QueryValueEx(key, 'ConsentPromptBehaviorAdmin')
            secure_desktop, _ = winreg.QueryValueEx(key, 'PromptOnSecureDesktop')
            winreg.CloseKey(key)

            if consent != 2 or secure_desktop != 1:
                self.vulnerabilities.append({
                    'severity': 'high',
                    'category': 'User Account Control',
                    'title': 'UAC Not Fully Enabled',
                    'details': f'UAC settings are not at maximum security. ConsentPromptBehaviorAdmin={consent}, PromptOnSecureDesktop={secure_desktop}',
                    'component': 'UAC',
                    'remediation': 'Set UAC to "Always notify" via Control Panel or registry.'
                })
        except Exception as e:
            logger.error(f"UAC check failed: {e}")

    def check_auto_login(self):
        """Check if automatic login is enabled"""
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon')
            auto_admin, _ = winreg.QueryValueEx(key, 'AutoAdminLogon')
            winreg.CloseKey(key)

            if auto_admin == '1':
                self.vulnerabilities.append({
                    'severity': 'high',
                    'category': 'Authentication',
                    'title': 'Automatic Login Enabled',
                    'details': 'Windows is configured to log in automatically without requiring a password.',
                    'component': 'Winlogon',
                    'remediation': 'Disable AutoAdminLogon in registry or via Control Panel user accounts.'
                })
        except Exception:
            # Key or value missing → automatic login is disabled
            pass

    def check_remote_desktop(self):
        """Check if Remote Desktop is enabled"""
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r'SYSTEM\CurrentControlSet\Control\Terminal Server')
            deny, _ = winreg.QueryValueEx(key, 'fDenyTSConnections')
            winreg.CloseKey(key)

            if deny == 0:
                self.vulnerabilities.append({
                    'severity': 'medium',
                    'category': 'Remote Access',
                    'title': 'Remote Desktop Enabled',
                    'details': 'Remote Desktop is enabled. If not required, this increases attack surface.',
                    'component': 'Terminal Services',
                    'remediation': 'Disable Remote Desktop via System Properties or PowerShell: Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" -Name fDenyTSConnections -Value 1'
                })
        except Exception as e:
            logger.error(f"Remote Desktop check failed: {e}")

    def check_admin_accounts(self):
        """Check for enabled administrator accounts"""
        try:
            cmd = 'powershell "Get-LocalGroupMember -Group Administrators | Where-Object {$_.ObjectClass -eq \'User\'} | Select-Object Name, Enabled | ConvertTo-Json"'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                admins = json.loads(result.stdout)
                if isinstance(admins, dict):
                    admins = [admins]
                for admin in admins:
                    if admin.get('Enabled') == True:
                        self.vulnerabilities.append({
                            'severity': 'low',
                            'category': 'Privilege Management',
                            'title': f'Enabled Administrator Account: {admin["Name"]}',
                            'details': f'User {admin["Name"]} is an enabled member of the Administrators group.',
                            'component': 'Local Users',
                            'remediation': 'Ensure this user needs administrative rights; otherwise remove or disable.'
                        })
        except Exception as e:
            logger.error(f"Admin account check failed: {e}")

    def check_open_ports(self):
        """Check for listening ports that are commonly targeted"""
        try:
            cmd = 'netstat -an | findstr "LISTENING"'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=10)
            open_ports = re.findall(r':(\d+)', result.stdout)

            risky_ports = {
                21: 'FTP',
                23: 'Telnet',
                25: 'SMTP',
                110: 'POP3',
                135: 'RPC',
                139: 'NetBIOS',
                445: 'SMB',
                1433: 'MSSQL',
                3306: 'MySQL',
                3389: 'RDP',
                5900: 'VNC',
                8080: 'HTTP-Proxy'
            }

            for port_str in open_ports:
                try:
                    port = int(port_str)
                    if port in risky_ports:
                        self.vulnerabilities.append({
                            'severity': 'medium',
                            'category': 'Network',
                            'title': f'Risky Port Open: {port} ({risky_ports[port]})',
                            'details': f'Port {port} is listening. This service is often targeted by attackers.',
                            'component': 'TCP Port',
                            'remediation': f'Close port {port} or restrict access via Windows Firewall.',
                            'port': port
                        })
                except ValueError:
                    continue
        except Exception as e:
            logger.error(f"Port scan failed: {e}")

    def check_network_sharing(self):
        """Check if network discovery and file sharing are enabled"""
        try:
            # Check Network Discovery
            cmd = 'netsh advfirewall firewall show rule name="Network Discovery" | findstr "Enable"'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=10)
            if 'Yes' in result.stdout:
                self.vulnerabilities.append({
                    'severity': 'medium',
                    'category': 'Network Sharing',
                    'title': 'Network Discovery Enabled',
                    'details': 'Network Discovery is enabled, potentially exposing the device on the network.',
                    'component': 'Firewall Rule',
                    'remediation': 'Disable Network Discovery via Windows Settings or netsh.'
                })

            # Check File and Printer Sharing
            cmd = 'netsh advfirewall firewall show rule name="File and Printer Sharing" | findstr "Enable"'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=10)
            if 'Yes' in result.stdout:
                self.vulnerabilities.append({
                    'severity': 'medium',
                    'category': 'Network Sharing',
                    'title': 'File and Printer Sharing Enabled',
                    'details': 'File and Printer Sharing is enabled, which can leak information on untrusted networks.',
                    'component': 'Firewall Rule',
                    'remediation': 'Disable File and Printer Sharing when not needed.'
                })
        except Exception as e:
            logger.error(f"Network sharing check failed: {e}")

    def check_wifi_security(self):
        """Check if any Wi‑Fi profiles are using outdated security"""
        try:
            cmd = 'netsh wlan show profiles'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=10)
            profiles = re.findall(r'All User Profile\s*:\s*(.+)', result.stdout)

            for profile in profiles[:5]:  # limit to avoid slowdown
                cmd = f'netsh wlan show profile name="{profile}" key=clear'
                prof_result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=10)
                if 'WEP' in prof_result.stdout or 'TKIP' in prof_result.stdout:
                    self.vulnerabilities.append({
                        'severity': 'high',
                        'category': 'Wireless',
                        'title': 'Weak Wi‑Fi Security Protocol',
                        'details': f'SSID "{profile}" uses deprecated encryption (WEP/TKIP).',
                        'component': 'Wi-Fi Profile',
                        'remediation': 'Update router to use WPA2‑AES or WPA3.'
                    })
        except Exception as e:
            logger.error(f"Wi-Fi security check failed: {e}")

    def check_dns_settings(self):
        """Check if DNS is set to a secure provider (basic check)"""
        try:
            # Get active network interfaces
            cmd = 'powershell "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, ServerAddresses | ConvertTo-Json"'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                interfaces = json.loads(result.stdout)
                if isinstance(interfaces, dict):
                    interfaces = [interfaces]

                # This list is just an example – we flag any DNS not in these "privacy" ones
                privacy_dns = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '208.67.222.222', '208.67.220.220']
                for iface in interfaces:
                    addresses = iface.get('ServerAddresses', [])
                    if addresses:
                        for dns in addresses:
                            # If it's not one of the common privacy DNS, and not local (ISP), flag it.
                            # This is informational, not a high‑risk vulnerability.
                            if dns not in privacy_dns and not dns.startswith('192.168.') and not dns.startswith('10.'):
                                self.vulnerabilities.append({
                                    'severity': 'low',
                                    'category': 'DNS',
                                    'title': 'Non‑Privacy DNS Server',
                                    'details': f'Interface "{iface["InterfaceAlias"]}" uses DNS: {dns}.',
                                    'component': 'DNS Client',
                                    'remediation': 'Consider using encrypted DNS or a privacy‑focused provider.'
                                })
        except Exception as e:
            logger.error(f"DNS check failed: {e}")

    # ==================== EXISTING METHODS (unchanged) ====================
    def check_bitlocker_status(self):
        """Check BitLocker encryption status"""
        try:
            cmd = 'powershell "Get-BitLockerVolume -MountPoint C: | Select-Object -Property VolumeStatus, ProtectionStatus, EncryptionPercentage | ConvertTo-Json"'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=10)

            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if data.get('VolumeStatus') != 'FullyEncrypted':
                    self.vulnerabilities.append({
                        'severity': 'high',
                        'category': 'Disk Encryption',
                        'title': 'BitLocker Not Fully Encrypted',
                        'details': f'System drive is not fully encrypted. Status: {data.get("VolumeStatus", "Unknown")}, {data.get("EncryptionPercentage", 0)}% encrypted.',
                        'component': 'BitLocker',
                        'remediation': 'Enable BitLocker encryption from Windows Security or Control Panel.'
                    })
        except Exception as e:
            logger.info(f"BitLocker check skipped or not available: {e}")

    def check_password_policy(self):
        """Check password policy settings"""
        try:
            cmd = '''powershell -Command "
$policy = Get-LocalUser | Where-Object {$_.Enabled -eq $true} | ForEach-Object {
    $user = $_.Name;
    try {
        $status = net user $user;
        @{
            User = $user;
            PasswordExpires = if($status -match 'Password expires.*Never'){'Never'}else{$status -match 'Password expires.*(\\d+/\\d+/\\d+)' | Out-Null; $matches[1]};
            PasswordChangeable = if($status -match 'User may change password.*Yes'){$true}else{$false};
            PasswordRequired = if($status -match 'Password required.*Yes'){$true}else{$false};
        }
    } catch { @{User=$user; Error=$_.Exception.Message} }
} | ConvertTo-Json"
'''
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=10)

            if result.returncode == 0 and result.stdout.strip():
                users = json.loads(result.stdout)
                for user in users:
                    if isinstance(user, dict):
                        if user.get('PasswordRequired') == False:
                            self.vulnerabilities.append({
                                'severity': 'critical',
                                'category': 'Authentication',
                                'title': f'No Password Required - {user.get("User")}',
                                'details': f'User "{user.get("User")}" does not require a password.',
                                'component': 'Local User Accounts',
                                'remediation': 'Set a password for this user account.'
                            })
        except Exception as e:
            logger.error(f"Error checking password policy: {e}")

    def check_audit_policy(self):
        """Check Windows audit policy settings"""
        try:
            cmd = 'auditpol /get /category:*'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=10)

            # Check for critical audit categories that should be enabled
            critical_audits = [
                'Logon', 'Logoff', 'Account Lockout',
                'Process Creation', 'Process Termination',
                'Object Access', 'Policy Change'
            ]

            for audit in critical_audits:
                if audit in result.stdout and 'Success and Failure' not in result.stdout:
                    self.vulnerabilities.append({
                        'severity': 'medium',
                        'category': 'Auditing',
                        'title': f'Audit Policy Incomplete - {audit}',
                        'details': f'Audit category "{audit}" is not configured for both success and failure.',
                        'component': 'Windows Audit Policy',
                        'remediation': 'Configure audit policy via "auditpol" command or Group Policy.'
                    })
        except Exception as e:
            logger.error(f"Error checking audit policy: {e}")

    def check_outdated_software(self):
        """Check for outdated software versions"""
        try:
            # Common software paths to check
            software_checks = [
                ('chrome.exe', r'C:\Program Files\Google\Chrome\Application\chrome.exe', 'Google Chrome'),
                ('firefox.exe', r'C:\Program Files\Mozilla Firefox\firefox.exe', 'Mozilla Firefox'),
                ('javaw.exe', r'C:\Program Files\Java', 'Java Runtime'),
                ('python.exe', r'C:\Python', 'Python'),
                ('node.exe', r'C:\Program Files\nodejs', 'Node.js'),
                ('adobe.exe', r'C:\Program Files\Adobe', 'Adobe Reader')
            ]

            for exe_name, common_path, software_name in software_checks:
                try:
                    # Try to get version via wmic
                    cmd = f'wmic datafile where "name=\'{common_path}\\{exe_name}\'" get Version /value'
                    result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=5)

                    if 'Version=' in result.stdout:
                        version = result.stdout.split('Version=')[1].strip()
                        logger.info(f"Found {software_name} version: {version}")

                        # Add check for known vulnerable versions here
                        # This is a simplified example
                        if software_name == 'Java Runtime' and version.startswith('8.'):
                            if int(version.split('.')[1]) < 300:
                                self.vulnerabilities.append({
                                    'severity': 'high',
                                    'category': 'Software',
                                    'title': f'Outdated {software_name}',
                                    'details': f'{software_name} version {version} may have known vulnerabilities.',
                                    'component': software_name,
                                    'remediation': f'Update {software_name} to the latest version.'
                                })
                except:
                    continue
        except Exception as e:
            logger.error(f"Error checking outdated software: {e}")

    def check_startup_programs(self):
        """Check for suspicious startup programs"""
        try:
            # Check registry startup locations
            startup_locations = [
                (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run'),
                (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Run'),
                (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
                (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\RunOnce')
            ]

            suspicious_keywords = ['temp', 'tmp', 'appdata', '%userprofile%', '.vbs', '.js', '.bat']
            startup_programs = []

            for hive, path in startup_locations:
                try:
                    key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            startup_programs.append((name, value))
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except Exception:
                    continue

            # Analyze startup programs
            for name, value in startup_programs:
                value_lower = value.lower()
                if any(keyword in value_lower for keyword in suspicious_keywords):
                    self.vulnerabilities.append({
                        'severity': 'medium',
                        'category': 'Startup',
                        'title': 'Suspicious Startup Program',
                        'details': f'Startup entry "{name}" points to suspicious location: {value}',
                        'component': 'Windows Startup',
                        'remediation': 'Review this startup entry in Task Manager or MSConfig.'
                    })
        except Exception as e:
            logger.error(f"Error checking startup programs: {e}")

    def check_powershell_execution_policy(self):
        """Check PowerShell execution policy"""
        try:
            cmd = 'powershell "Get-ExecutionPolicy"'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=5)

            policy = result.stdout.strip()
            risky_policies = ['Unrestricted', 'Bypass', 'RemoteSigned']

            if policy in risky_policies:
                self.vulnerabilities.append({
                    'severity': 'high',
                    'category': 'Scripting',
                    'title': f'PowerShell Execution Policy: {policy}',
                    'details': f'PowerShell execution policy is set to {policy}. This may allow execution of malicious scripts.',
                    'component': 'PowerShell',
                    'remediation': 'Set PowerShell execution policy to "Restricted" or "AllSigned".'
                })
        except Exception as e:
            logger.error(f"Error checking PowerShell execution policy: {e}")

    def check_smb_protocol(self):
        """Check SMB protocol versions and settings"""
        try:
            cmd = 'powershell "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol | ConvertTo-Json"'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=5)

            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if data.get('EnableSMB1Protocol'):
                    self.vulnerabilities.append({
                        'severity': 'critical',
                        'category': 'Network',
                        'title': 'SMBv1 Protocol Enabled',
                        'details': 'SMBv1 protocol is enabled. This protocol is deprecated and vulnerable to attacks like EternalBlue.',
                        'component': 'SMB Protocol',
                        'remediation': 'Disable SMBv1 via PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false'
                    })
        except Exception as e:
            logger.error(f"Error checking SMB protocol: {e}")

    def check_file_integrity(self, progress_callback=None):
        """Check integrity of critical system files"""
        critical_files = [
            r'C:\Windows\System32\kernel32.dll',
            r'C:\Windows\System32\user32.dll',
            r'C:\Windows\System32\ntdll.dll',
            r'C:\Windows\System32\cmd.exe',
            r'C:\Windows\System32\powershell.exe',
            r'C:\Windows\System32\regedit.exe',
            r'C:\Windows\System32\taskmgr.exe'
        ]

        for i, file_path in enumerate(critical_files):
            if progress_callback:
                progress_callback(i, len(critical_files), f"Checking {os.path.basename(file_path)}...")

            if os.path.exists(file_path):
                try:
                    # Get file hash
                    with open(file_path, 'rb') as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()

                    # Get file metadata
                    file_stat = os.stat(file_path)
                    file_size = file_stat.st_size
                    modified_time = datetime.fromtimestamp(file_stat.st_mtime)

                    # Check for suspicious modifications (very recent or very old)
                    time_diff = (datetime.now() - modified_time).days
                    if time_diff < 1 or time_diff > 365 * 5:  # Modified today or over 5 years ago
                        self.vulnerabilities.append({
                            'severity': 'medium',
                            'category': 'File Integrity',
                            'title': f'Suspicious File Modification - {os.path.basename(file_path)}',
                            'details': f'Critical system file modified {time_diff} days ago. Last modified: {modified_time}.',
                            'component': 'System Files',
                            'remediation': 'Verify file integrity with Windows System File Checker (sfc /scannow).'
                        })
                except Exception as e:
                    logger.error(f"Error checking file {file_path}: {e}")

    def check_services(self):
        """Check for vulnerable or unnecessary services"""
        try:
            cmd = '''powershell "Get-Service | Where-Object {$_.StartType -eq 'Automatic'} | 
                     Select-Object Name, DisplayName, Status | ConvertTo-Json"'''
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=10)

            if result.returncode == 0 and result.stdout.strip():
                services = json.loads(result.stdout)

                risky_services = [
                    'RemoteRegistry', 'Telnet', 'TFTP', 'W3SVC',
                    'MSSQLSERVER', 'MYSQL', 'VNC', 'TeamViewer'
                ]

                for service in services:
                    if isinstance(service, dict):
                        service_name = service.get('Name', '')
                        display_name = service.get('DisplayName', '')

                        # Check for risky services
                        for risky in risky_services:
                            if risky.lower() in service_name.lower() or risky.lower() in display_name.lower():
                                self.vulnerabilities.append({
                                    'severity': 'medium',
                                    'category': 'Services',
                                    'title': f'Risky Service Running - {display_name}',
                                    'details': f'Service "{display_name}" ({service_name}) may pose security risks if not needed.',
                                    'component': 'Windows Services',
                                    'remediation': f'Review if {display_name} service is necessary and disable if not needed.'
                                })
        except Exception as e:
            logger.error(f"Error checking services: {e}")

    def check_windows_updates(self):
        """Check for pending Windows updates"""
        try:
            logger.info("Checking Windows updates...")
            cmd = 'powershell "Get-HotFix | Select-Object -Last 1 | ConvertTo-Json"'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=10)

            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                install_date = data.get('InstalledOn', '')

                if install_date:
                    try:
                        last_update = datetime.strptime(install_date.split('T')[0], '%Y-%m-%d')
                        days_old = (datetime.now() - last_update).days

                        if days_old > 60:
                            self.vulnerabilities.append({
                                'severity': 'high',
                                'category': 'Windows Update',
                                'title': 'Outdated Windows Updates',
                                'details': f'Last Windows update was {days_old} days ago. System may be missing critical security patches.',
                                'component': 'Windows Update Service',
                                'remediation': 'Run Windows Update from Settings or use: Start-Process ms-settings:windowsupdate'
                            })
                            logger.warning(f"Windows updates outdated: {days_old} days old")
                    except Exception as e:
                        logger.error(f"Error parsing update date: {e}")

            cmd_service = 'sc query wuauserv'
            result = subprocess.run(cmd_service, capture_output=True, text=True, shell=True, timeout=5)

            if 'RUNNING' not in result.stdout:
                self.vulnerabilities.append({
                    'severity': 'medium',
                    'category': 'Windows Update',
                    'title': 'Windows Update Service Not Running',
                    'details': 'The Windows Update service is not active. Automatic updates are disabled.',
                    'component': 'Windows Update Service',
                    'remediation': 'Start Windows Update service: sc start wuauserv'
                })
                logger.warning("Windows Update service not running")

        except Exception as e:
            logger.error(f"Error checking updates: {e}")

    def check_firewall(self):
        """Check Windows Firewall status with more comprehensive checks"""
        try:
            logger.info("Checking firewall...")
            profiles = ['DomainProfile', 'PrivateProfile', 'PublicProfile']

            for profile in profiles:
                cmd = f'netsh advfirewall show {profile.lower()} state'
                result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=5)

                if 'OFF' in result.stdout or 'Disabled' in result.stdout:
                    severity = 'critical' if profile == 'PublicProfile' else 'high'
                    self.vulnerabilities.append({
                        'severity': severity,
                        'category': 'Firewall',
                        'title': f'Windows Firewall Disabled - {profile}',
                        'details': f'Windows Defender Firewall is turned off for {profile}. System is exposed to network attacks.',
                        'component': 'Windows Defender Firewall',
                        'remediation': f'Enable firewall: netsh advfirewall set {profile.lower()} state on'
                    })
                    logger.warning(f"Firewall disabled for {profile}")
        except Exception as e:
            logger.error(f"Error checking firewall: {e}")

    def check_antivirus(self):
        """Check Windows Defender status - comprehensive check"""
        logger.info("Checking antivirus...")
        status = self.get_defender_status()
        if not status:
            self.vulnerabilities.append({
                'severity': 'medium',
                'category': 'Antivirus',
                'title': 'Could not query Windows Defender status',
                'details': 'Failed to retrieve Defender configuration. Check if Windows Security is functional.',
                'component': 'Windows Defender',
                'remediation': 'Open Windows Security and check for issues.'
            })
            logger.error("Could not query Defender status")
            return

        tp = status.get('IsTamperProtected', False)
        passive = status.get('AMRunningMode', '') == 'Passive'

        def add_vuln(sev, title, details, remediation):
            extra = {'tamper_protected': tp} if tp else {}
            if passive:
                details += "\n(Windows Defender is in passive mode — another AV is controlling protection)"
            self.vulnerabilities.append({
                'severity': sev,
                'category': 'Antivirus',
                'title': title,
                'details': details,
                'component': 'Windows Defender',
                'remediation': remediation,
                'extra_info': extra
            })

        # Check all Defender settings
        checks = [
            ('RealTimeProtectionEnabled', 'critical', 'Real-time Protection Disabled',
             'Critical protection feature is off.', 'Enable via Windows Security or PowerShell'),
            ('AntivirusEnabled', 'critical', 'Antivirus Engine Disabled',
             'Core antivirus functionality is disabled.', 'Enable via Windows Security'),
            ('BehaviorMonitorEnabled', 'high', 'Behavior Monitoring Disabled',
             'Behavior monitoring is disabled.', 'Enable behavior monitoring'),
            ('IoavProtectionEnabled', 'medium', 'IOAV Protection Disabled',
             'Downloaded file protection is disabled.', 'Enable IOAV protection'),
            ('NISEnabled', 'medium', 'Network Protection Disabled',
             'Network Inspection System is disabled.', 'Enable network protection'),
            ('DisableScriptScanning', 'medium', 'Script Scanning Disabled',
             'Script scanning is disabled.', 'Enable script scanning'),
            ('DisableArchiveScanning', 'low', 'Archive Scanning Disabled',
             'Archive file scanning is disabled.', 'Enable archive scanning')
        ]

        for setting, severity, title, details, remediation in checks:
            if not status.get(setting, True) if setting.startswith('Disable') else not status.get(setting, False):
                add_vuln(severity, title, details, remediation)

        if status.get('AntivirusSignatureAgeDays', 999) > 7:
            add_vuln('high', 'Outdated Virus Definitions',
                f'Definitions are {status["AntivirusSignatureAgeDays"]} days old.',
                'Update definitions via Windows Security')

        if status.get('MAPSReporting', 0) == 0:
            add_vuln('medium', 'Cloud-delivered Protection Disabled',
                'Cloud-delivered protection (MAPS) is disabled.',
                'Enable cloud protection')

        if status.get('SubmitSamplesConsent', 0) == 2:
            add_vuln('low', 'Automatic Sample Submission Disabled',
                'Automatic sample submission is disabled.',
                'Enable sample submission')

        if status.get('DisableBlockAtFirstSeen', False):
            add_vuln('medium', 'Block at First Sight Disabled',
                'Block at First Sight is disabled.',
                'Enable Block at First Sight')

        if status.get('PUAProtection', 0) == 0:
            add_vuln('medium', 'PUA Protection Disabled',
                'Potentially Unwanted Application protection is disabled.',
                'Enable PUA protection')

        if not tp:
            add_vuln('high', 'Tamper Protection Disabled',
                'Tamper Protection is OFF — malware may disable Defender silently.',
                'Enable Tamper Protection in Windows Security')

        if passive and status.get('RealTimeProtectionEnabled'):
            add_vuln('medium', 'Defender Running in Passive Mode',
                'Third-party antivirus detected. Windows Defender is passive.',
                'Check if third-party AV is properly configured')

    def scan_all(self, progress_callback=None):
        """Run all vulnerability checks with progress reporting"""
        self.vulnerabilities = []
        self.scan_start_time = datetime.now()

        logger.info(f"Starting comprehensive system scan (ID: {self.scan_id})")

        checks = [
            (self.get_system_info, "Gathering system information..."),
            (self.check_windows_updates, "Checking Windows updates..."),
            (self.check_firewall, "Checking firewall..."),
            (self.check_antivirus, "Checking antivirus..."),
            (self.check_uac, "Checking User Account Control..."),
            (self.check_auto_login, "Checking auto-login..."),
            (self.check_remote_desktop, "Checking Remote Desktop..."),
            (self.check_admin_accounts, "Checking admin accounts..."),
            (self.check_open_ports, "Checking open ports..."),
            (self.check_network_sharing, "Checking network sharing..."),
            (self.check_wifi_security, "Checking WiFi security..."),
            (self.check_dns_settings, "Checking DNS settings..."),
            (self.check_bitlocker_status, "Checking BitLocker..."),
            (self.check_password_policy, "Checking password policy..."),
            (self.check_audit_policy, "Checking audit policy..."),
            (self.check_outdated_software, "Checking software versions..."),
            (self.check_startup_programs, "Checking startup programs..."),
            (self.check_powershell_execution_policy, "Checking PowerShell..."),
            (self.check_smb_protocol, "Checking SMB protocol..."),
            (self.check_services, "Checking services..."),
            (lambda: self.check_file_integrity(progress_callback), "Checking file integrity...")
        ]

        for i, (check_func, message) in enumerate(checks):
            if progress_callback:
                progress_callback(i, len(checks), message)

            try:
                check_func()
                logger.info(f"Completed: {message}")
            except Exception as e:
                logger.error(f"Error in {message}: {e}")

        self.scan_end_time = datetime.now()
        scan_duration = (self.scan_end_time - self.scan_start_time).total_seconds()

        logger.info(f"Scan complete. Found {len(self.vulnerabilities)} vulnerabilities in {scan_duration:.2f} seconds")

        # Calculate risk score
        severity_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1}
        risk_score = sum(severity_weights.get(v['severity'], 0) for v in self.vulnerabilities)
        max_possible = len(self.vulnerabilities) * 10
        self.risk_percentage = (risk_score / max_possible * 100) if max_possible > 0 else 0

        return self.vulnerabilities

    def calculate_risk_score(self):
        """Calculate overall risk score based on vulnerabilities"""
        if not self.vulnerabilities:
            return 0, "Low Risk"

        severity_scores = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 1
        }

        total_score = sum(severity_scores.get(v['severity'], 0) for v in self.vulnerabilities)
        max_possible = len(self.vulnerabilities) * 10
        risk_percentage = (total_score / max_possible * 100) if max_possible > 0 else 0

        if risk_percentage >= 70:
            risk_level = "Critical Risk"
        elif risk_percentage >= 40:
            risk_level = "High Risk"
        elif risk_percentage >= 20:
            risk_level = "Medium Risk"
        else:
            risk_level = "Low Risk"

        return round(risk_percentage, 1), risk_level

    def generate_report(self, format='html'):
        """Generate scan report in various formats"""
        report = {
            'scan_id': self.scan_id,
            'scan_start': self.scan_start_time.isoformat() if self.scan_start_time else '',
            'scan_end': self.scan_end_time.isoformat() if self.scan_end_time else '',
            'duration': (self.scan_end_time - self.scan_start_time).total_seconds() if self.scan_start_time and self.scan_end_time else 0,
            'system_info': self.system_info,
            'vulnerabilities': self.vulnerabilities,
            'summary': {
                'total': len(self.vulnerabilities),
                'critical': sum(1 for v in self.vulnerabilities if v['severity'] == 'critical'),
                'high': sum(1 for v in self.vulnerabilities if v['severity'] == 'high'),
                'medium': sum(1 for v in self.vulnerabilities if v['severity'] == 'medium'),
                'low': sum(1 for v in self.vulnerabilities if v['severity'] == 'low')
            },
            'risk_score': self.calculate_risk_score()[0],
            'risk_level': self.calculate_risk_score()[1]
        }

        if format == 'json':
            return json.dumps(report, indent=2, default=str)

        elif format == 'html':
            return self._generate_html_report(report)

        elif format == 'csv':
            return self._generate_csv_report(report)

        return report

    def _generate_html_report(self, report):
        """Generate HTML report"""
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>RAVEN-X Security Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f7fa; }}
                .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
                .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
                .summary-card {{ background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid; }}
                .critical {{ border-color: #e74c3c; }}
                .high {{ border-color: #e67e22; }}
                .medium {{ border-color: #f39c12; }}
                .low {{ border-color: #95a5a6; }}
                .vulnerability {{ margin: 15px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .severity-critical {{ background: #ffeaea; border-left: 4px solid #e74c3c; }}
                .severity-high {{ background: #fff3e6; border-left: 4px solid #e67e22; }}
                .severity-medium {{ background: #fff9e6; border-left: 4px solid #f39c12; }}
                .severity-low {{ background: #f8f9fa; border-left: 4px solid #95a5a6; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f2f2f2; }}
                .risk-meter {{ height: 30px; background: linear-gradient(to right, #27ae60, #f39c12, #e74c3c); margin: 20px 0; border-radius: 15px; position: relative; }}
                .risk-indicator {{ position: absolute; top: -10px; width: 3px; height: 50px; background: black; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔒 RAVEN-X Security Scan Report</h1>
                    <p>Scan ID: {report['scan_id']} | {report['scan_start'][:19]} | Duration: {report['duration']:.1f}s</p>
                </div>

                <h2>📊 System Summary</h2>
                <table>
                    <tr><th>Hostname</th><td>{report['system_info'].get('hostname', 'N/A')}</td></tr>
                    <tr><th>OS Version</th><td>{report['system_info'].get('os_version', 'N/A')}</td></tr>
                    <tr><th>Architecture</th><td>{report['system_info'].get('architecture', 'N/A')}</td></tr>
                    <tr><th>Risk Score</th><td>{report['risk_score']}% - {report['risk_level']}</td></tr>
                </table>

                <h2>📈 Vulnerability Summary</h2>
                <div class="summary">
                    <div class="summary-card critical">
                        <h3>Critical</h3>
                        <p style="font-size: 24px; font-weight: bold; color: #e74c3c;">{report['summary']['critical']}</p>
                    </div>
                    <div class="summary-card high">
                        <h3>High</h3>
                        <p style="font-size: 24px; font-weight: bold; color: #e67e22;">{report['summary']['high']}</p>
                    </div>
                    <div class="summary-card medium">
                        <h3>Medium</h3>
                        <p style="font-size: 24px; font-weight: bold; color: #f39c12;">{report['summary']['medium']}</p>
                    </div>
                    <div class="summary-card low">
                        <h3>Low</h3>
                        <p style="font-size: 24px; font-weight: bold; color: #95a5a6;">{report['summary']['low']}</p>
                    </div>
                </div>

                <div class="risk-meter">
                    <div class="risk-indicator" style="left: {report['risk_score']}%;"></div>
                </div>
                <p style="text-align: center;">Risk Level: {report['risk_score']}%</p>

                <h2>🔍 Detailed Vulnerabilities</h2>
        """

        for i, vuln in enumerate(report['vulnerabilities'], 1):
            severity_class = f"severity-{vuln['severity']}"
            html_template += f"""
                <div class="vulnerability {severity_class}">
                    <h3>{i}. {vuln['title']}</h3>
                    <p><strong>Severity:</strong> <span style="color: {self._get_severity_color(vuln['severity'])}">{vuln['severity'].upper()}</span></p>
                    <p><strong>Category:</strong> {vuln['category']}</p>
                    <p><strong>Component:</strong> {vuln['component']}</p>
                    <p><strong>Details:</strong> {vuln['details']}</p>
                    <p><strong>Remediation:</strong> {vuln.get('remediation', 'No specific remediation provided.')}</p>
                </div>
            """

        html_template += """
                <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #666;">
                    <p>Report generated by RAVEN-X Security Scanner v3.0</p>
                    <p>⚠️ This report is for authorized security assessment purposes only.</p>
                    <p>© 2024 RAVEN-X. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """

        return html_template

    def _generate_csv_report(self, report):
        """Generate CSV report"""
        import io
        import csv

        output = io.StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow(['RAVEN-X Security Scan Report'])
        writer.writerow(['Scan ID:', report['scan_id']])
        writer.writerow(['Scan Start:', report['scan_start']])
        writer.writerow(['Scan End:', report['scan_end']])
        writer.writerow(['Duration (s):', report['duration']])
        writer.writerow(['Hostname:', report['system_info'].get('hostname', 'N/A')])
        writer.writerow(['Risk Score:', f"{report['risk_score']}%"])
        writer.writerow(['Risk Level:', report['risk_level']])
        writer.writerow([])

        # Write summary
        writer.writerow(['VULNERABILITY SUMMARY'])
        writer.writerow(['Critical', report['summary']['critical']])
        writer.writerow(['High', report['summary']['high']])
        writer.writerow(['Medium', report['summary']['medium']])
        writer.writerow(['Low', report['summary']['low']])
        writer.writerow(['Total', report['summary']['total']])
        writer.writerow([])

        # Write vulnerabilities
        writer.writerow(['DETAILED VULNERABILITIES'])
        writer.writerow(['#', 'Severity', 'Title', 'Category', 'Component', 'Details', 'Remediation'])

        for i, vuln in enumerate(report['vulnerabilities'], 1):
            writer.writerow([
                i,
                vuln['severity'].upper(),
                vuln['title'],
                vuln['category'],
                vuln['component'],
                vuln['details'],
                vuln.get('remediation', '')
            ])

        return output.getvalue()

    def _get_severity_color(self, severity):
        """Get color for severity level"""
        colors = {
            'critical': '#e74c3c',
            'high': '#e67e22',
            'medium': '#f39c12',
            'low': '#95a5a6'
        }
        return colors.get(severity, '#000000')


class VulnerabilityGUI:
    def __init__(self):
        ctk.set_appearance_mode("light")
        ctk.set_default_color_theme("blue")

        self.root = ctk.CTk()
        self.root.title("RAVEN-X Security Scanner v3.0")
        self.root.geometry("1400x900")

        # Center window on screen
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

        self.scanner = VulnerabilityScanner()
        self.vulnerabilities = []
        self.is_scanning = False
        self.scheduled_scans = []

        # Configuration
        self.config = {
            'lm_studio_url': "http://localhost:1234/v1",
            'model_name': "llama-3.1-8b",
            'safe_mode': True,  # Only report, don't fix
            'auto_create_restore': True,
            'schedule_interval': 24,  # Hours
            'export_format': 'html'
        }

        # Modern color scheme
        self.colors = {
            'bg_primary': '#f5f7fa',
            'bg_secondary': '#ffffff',
            'bg_sidebar': '#2c3e50',
            'accent': '#3498db',
            'accent_hover': '#2980b9',
            'text_primary': '#2c3e50',
            'text_secondary': '#7f8c8d',
            'border': '#e1e8ed',
            'critical': '#e74c3c',
            'high': '#e67e22',
            'medium': '#f39c12',
            'low': '#95a5a6',
            'success': '#27ae60',
            'warning': '#f1c40f'
        }

        self.create_widgets()

    def create_widgets(self):
        # Main container with sidebar layout
        main_container = ctk.CTkFrame(self.root, fg_color=self.colors['bg_primary'])
        main_container.pack(fill="both", expand=True)

        # ==================== LEFT SIDEBAR ====================
        sidebar = ctk.CTkFrame(main_container, width=320, fg_color=self.colors['bg_sidebar'], corner_radius=0)
        sidebar.pack(side="left", fill="y", padx=0, pady=0)
        sidebar.pack_propagate(False)

        # Logo/Header in sidebar
        logo_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        logo_frame.pack(pady=(30, 20), padx=20)

        app_title = ctk.CTkLabel(logo_frame, text="RAVEN-X",
                                font=("Segoe UI", 28, "bold"),
                                text_color="#ffffff")
        app_title.pack()

        subtitle = ctk.CTkLabel(logo_frame, text="Security Scanner v3.0",
                               font=("Segoe UI", 13),
                               text_color="#bdc3c7")
        subtitle.pack(pady=(0, 5))

        version = ctk.CTkLabel(logo_frame, text="Professional Edition",
                              font=("Segoe UI", 10),
                              text_color="#7f8c8d")
        version.pack()

        # Scan Progress
        self.progress_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        self.progress_frame.pack(pady=10, padx=20, fill="x")

        self.progress_label = ctk.CTkLabel(self.progress_frame, text="",
                                          font=("Segoe UI", 10),
                                          text_color="#bdc3c7")
        self.progress_label.pack()

        self.progress_bar = ctk.CTkProgressBar(self.progress_frame, height=8)
        self.progress_bar.pack(fill="x", pady=(5, 0))
        self.progress_bar.set(0)

        # Scan button in sidebar
        scan_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        scan_frame.pack(pady=20, padx=20, fill="x")

        self.scan_button = ctk.CTkButton(scan_frame, text="🔍 Start Security Scan",
                                        command=self.start_scan,
                                        font=("Segoe UI", 14, "bold"),
                                        height=50,
                                        fg_color=self.colors['accent'],
                                        hover_color=self.colors['accent_hover'],
                                        corner_radius=8)
        self.scan_button.pack(fill="x")

        # Quick scan button
        self.quick_scan_button = ctk.CTkButton(scan_frame, text="⚡ Quick Scan",
                                              command=self.start_quick_scan,
                                              font=("Segoe UI", 12),
                                              height=40,
                                              fg_color=self.colors['medium'],
                                              hover_color="#e67e22",
                                              corner_radius=8)
        self.quick_scan_button.pack(fill="x", pady=(10, 0))

        # Quick stats (will update after scan)
        stats_frame = ctk.CTkFrame(sidebar, fg_color="#34495e", corner_radius=10)
        stats_frame.pack(pady=20, padx=20, fill="x")

        stats_title = ctk.CTkLabel(stats_frame, text="Scan Summary",
                                  font=("Segoe UI", 12, "bold"),
                                  text_color="#ffffff")
        stats_title.pack(pady=(15, 10))

        self.risk_score_label = ctk.CTkLabel(stats_frame, text="Risk: 0%",
                                           font=("Segoe UI", 16, "bold"),
                                           text_color="#ffffff")
        self.risk_score_label.pack(pady=(0, 10))

        self.stats_critical = ctk.CTkLabel(stats_frame, text="🔴 Critical: 0",
                                          font=("Segoe UI", 11),
                                          text_color="#e74c3c")
        self.stats_critical.pack(pady=3)

        self.stats_high = ctk.CTkLabel(stats_frame, text="🟠 High: 0",
                                      font=("Segoe UI", 11),
                                      text_color="#e67e22")
        self.stats_high.pack(pady=3)

        self.stats_medium = ctk.CTkLabel(stats_frame, text="🟡 Medium: 0",
                                        font=("Segoe UI", 11),
                                        text_color="#f39c12")
        self.stats_medium.pack(pady=3)

        self.stats_low = ctk.CTkLabel(stats_frame, text="⚪ Low: 0",
                                     font=("Segoe UI", 11),
                                     text_color="#95a5a6")
        self.stats_low.pack(pady=3)

        self.stats_total = ctk.CTkLabel(stats_frame, text="Total Issues: 0",
                                       font=("Segoe UI", 12, "bold"),
                                       text_color="#ffffff")
        self.stats_total.pack(pady=(10, 15))

        # Action buttons in sidebar
        action_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        action_frame.pack(pady=10, padx=20, fill="x")

        self.ai_button = ctk.CTkButton(action_frame, text="🤖 AI Analysis",
                                      command=self.get_ai_analysis,
                                      font=("Segoe UI", 12),
                                      height=40,
                                      state="disabled",
                                      fg_color="#9b59b6",
                                      hover_color="#8e44ad",
                                      corner_radius=8)
        self.ai_button.pack(fill="x", pady=5)

        self.fix_button = ctk.CTkButton(action_frame, text="🔧 Fix Issues",
                                       command=self.fix_vulnerabilities,
                                       font=("Segoe UI", 12),
                                       height=40,
                                       state="disabled",
                                       fg_color=self.colors['success'],
                                       hover_color="#229954",
                                       corner_radius=8)
        self.fix_button.pack(fill="x", pady=5)

        self.export_button = ctk.CTkButton(action_frame, text="📤 Export Report",
                                          command=self.export_report,
                                          font=("Segoe UI", 12),
                                          height=40,
                                          state="disabled",
                                          fg_color=self.colors['accent'],
                                          hover_color=self.colors['accent_hover'],
                                          corner_radius=8)
        self.export_button.pack(fill="x", pady=5)

        # Safe mode toggle
        safe_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        safe_frame.pack(pady=20, padx=20, fill="x")

        self.safe_mode_var = ctk.BooleanVar(value=self.config['safe_mode'])
        self.safe_mode_switch = ctk.CTkSwitch(safe_frame, text="🛡️ Safe Mode",
                                             variable=self.safe_mode_var,
                                             command=self.toggle_safe_mode,
                                             font=("Segoe UI", 11),
                                             fg_color=self.colors['success'])
        self.safe_mode_switch.pack()

        # ==================== RIGHT CONTENT AREA ====================
        content_area = ctk.CTkFrame(main_container, fg_color=self.colors['bg_primary'])
        content_area.pack(side="right", fill="both", expand=True, padx=0, pady=0)

        # Top header bar
        header_bar = ctk.CTkFrame(content_area, fg_color=self.colors['bg_secondary'],
                                 height=80, corner_radius=0)
        header_bar.pack(fill="x", padx=20, pady=(20, 0))
        header_bar.pack_propagate(False)

        header_content = ctk.CTkFrame(header_bar, fg_color="transparent")
        header_content.pack(fill="both", expand=True, padx=25, pady=15)

        header_title = ctk.CTkLabel(header_content, text="Security Assessment Dashboard",
                                   font=("Segoe UI", 22, "bold"),
                                   text_color=self.colors['text_primary'])
        header_title.pack(anchor="w")

        self.status_label = ctk.CTkLabel(header_content, text="Ready to scan",
                                        font=("Segoe UI", 12),
                                        text_color=self.colors['text_secondary'])
        self.status_label.pack(anchor="w", pady=(5, 0))

        # Tabview for different sections
        self.tabview = ctk.CTkTabview(content_area, fg_color=self.colors['bg_primary'])
        self.tabview.pack(fill="both", expand=True, padx=20, pady=15)

        # Scan Results Tab
        self.scan_tab = self.tabview.add("📊 Scan Results")
        self.setup_scan_tab()

        # AI Configuration Tab
        self.ai_tab = self.tabview.add("🤖 AI Configuration")
        self.setup_ai_tab()

        # Settings Tab
        self.settings_tab = self.tabview.add("⚙️ Settings")
        self.setup_settings_tab()

        # System Info Tab
        self.system_tab = self.tabview.add("💻 System Info")
        self.setup_system_tab()

    def setup_scan_tab(self):
        """Setup scan results tab"""
        # Results area
        results_frame = ctk.CTkFrame(self.scan_tab, fg_color=self.colors['bg_secondary'], corner_radius=10)
        results_frame.pack(fill="both", expand=True, padx=0, pady=0)

        # Results header with filter buttons
        results_header = ctk.CTkFrame(results_frame, fg_color=self.colors['bg_secondary'])
        results_header.pack(fill="x", padx=20, pady=15)

        results_title = ctk.CTkLabel(results_header, text="Scan Results",
                                    font=("Segoe UI", 16, "bold"),
                                    text_color=self.colors['text_primary'])
        results_title.pack(side="left")

        # Filter buttons
        filter_frame = ctk.CTkFrame(results_header, fg_color="transparent")
        filter_frame.pack(side="right")

        self.filter_all = ctk.CTkButton(filter_frame, text="All",
                                       width=70, height=30,
                                       command=lambda: self.filter_results('all'),
                                       fg_color=self.colors['accent'],
                                       hover_color=self.colors['accent_hover'])
        self.filter_all.pack(side="left", padx=2)

        self.filter_critical = ctk.CTkButton(filter_frame, text="Critical",
                                           width=70, height=30,
                                           command=lambda: self.filter_results('critical'),
                                           fg_color=self.colors['critical'],
                                           hover_color="#c0392b")
        self.filter_critical.pack(side="left", padx=2)

        self.filter_high = ctk.CTkButton(filter_frame, text="High",
                                        width=70, height=30,
                                        command=lambda: self.filter_results('high'),
                                        fg_color=self.colors['high'],
                                        hover_color="#d35400")
        self.filter_high.pack(side="left", padx=2)

        # Scrollable text area with better formatting
        text_container = ctk.CTkFrame(results_frame, fg_color=self.colors['bg_primary'])
        text_container.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        self.results_text = ctk.CTkTextbox(text_container,
                                          font=("Consolas", 11),
                                          fg_color="#fafbfc",
                                          text_color=self.colors['text_primary'],
                                          border_width=1,
                                          border_color=self.colors['border'],
                                          corner_radius=6,
                                          wrap="word")
        self.results_text.pack(fill="both", expand=True)

        # Initial message
        welcome_msg = """╔══════════════════════════════════════════════════════════════╗
║                    RAVEN-X Security Scanner v3.0                   ║
╚══════════════════════════════════════════════════════════════╝

Welcome to RAVEN-X Security Scanner!

This professional security assessment tool will scan your Windows system 
for vulnerabilities across multiple categories:

🔹 Windows Updates & Patches
🔹 Firewall Configuration
🔹 Antivirus & Malware Protection
🔹 User Account Security
🔹 Network Security & Ports
🔹 Disk Encryption (BitLocker)
🔹 Password Policies
🔹 Audit & Logging Settings
🔹 Software Versions
🔹 Startup Programs
🔹 File Integrity
🔹 Service Configuration

⚠️  IMPORTANT DISCLAIMER:
This tool is for authorized security testing only.
Always ensure you have proper permissions before scanning systems.

Click "Start Security Scan" to begin the assessment.
"""
        self.results_text.insert("1.0", welcome_msg)
        self.results_text.configure(state="disabled")

    def setup_ai_tab(self):
        """Setup AI configuration tab"""
        ai_frame = ctk.CTkFrame(self.ai_tab, fg_color=self.colors['bg_secondary'], corner_radius=10)
        ai_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # LLM Configuration Section
        config_header = ctk.CTkFrame(ai_frame, fg_color="transparent")
        config_header.pack(fill="x", padx=20, pady=(20, 10))

        config_title = ctk.CTkLabel(config_header, text="AI Configuration",
                                   font=("Segoe UI", 16, "bold"),
                                   text_color=self.colors['text_primary'])
        config_title.pack(side="left")

        config_content = ctk.CTkFrame(ai_frame, fg_color="transparent")
        config_content.pack(fill="x", padx=20, pady=(0, 20))

        # URL input
        url_label = ctk.CTkLabel(config_content, text="LM Studio URL:",
                                font=("Segoe UI", 12),
                                text_color=self.colors['text_secondary'])
        url_label.grid(row=0, column=0, sticky="w", padx=(0, 10), pady=10)

        self.url_entry = ctk.CTkEntry(config_content, width=400, height=40,
                                      font=("Segoe UI", 11),
                                      border_color=self.colors['border'])
        self.url_entry.insert(0, self.config['lm_studio_url'])
        self.url_entry.grid(row=0, column=1, padx=5, pady=10, sticky="w", columnspan=3)

        # Model input
        model_label = ctk.CTkLabel(config_content, text="Model Name:",
                                  font=("Segoe UI", 12),
                                  text_color=self.colors['text_secondary'])
        model_label.grid(row=1, column=0, sticky="w", padx=(0, 10), pady=10)

        self.model_entry = ctk.CTkEntry(config_content, width=300, height=40,
                                       font=("Segoe UI", 11),
                                       border_color=self.colors['border'])
        self.model_entry.insert(0, self.config['model_name'])
        self.model_entry.grid(row=1, column=1, padx=5, pady=10, sticky="w")

        # Test button
        self.test_btn = ctk.CTkButton(config_content, text="Test Connection",
                                     command=self.test_connection,
                                     width=140, height=40,
                                     font=("Segoe UI", 11),
                                     fg_color=self.colors['accent'],
                                     hover_color=self.colors['accent_hover'],
                                     corner_radius=8)
        self.test_btn.grid(row=1, column=2, padx=20, pady=10)

        # Connection status
        self.connection_status = ctk.CTkLabel(config_content, text="● Not tested",
                                             font=("Segoe UI", 11),
                                             text_color=self.colors['medium'])
        self.connection_status.grid(row=1, column=3, padx=10, pady=10)

        # AI Analysis Examples
        examples_frame = ctk.CTkFrame(ai_frame, fg_color="#f8f9fa", corner_radius=8)
        examples_frame.pack(fill="x", padx=20, pady=20)

        examples_label = ctk.CTkLabel(examples_frame, text="AI Analysis Examples",
                                     font=("Segoe UI", 14, "bold"),
                                     text_color=self.colors['text_primary'])
        examples_label.pack(pady=(15, 10), padx=20, anchor="w")

        examples_text = """The AI assistant can provide:

1. Risk Assessment - Overall security posture analysis
2. Prioritization - Which issues to fix first
3. Step-by-Step Guides - Detailed remediation steps
4. Compliance Mapping - How findings relate to standards
5. Threat Modeling - Potential attack scenarios
6. Best Practices - Industry security recommendations

To get the best analysis:
• Ensure LM Studio is running with a loaded model
• Use models trained on security/code (like CodeLlama, Security-focused models)
• The AI works best when vulnerabilities have been detected
"""

        examples_content = ctk.CTkTextbox(examples_frame, height=200,
                                         font=("Segoe UI", 11),
                                         fg_color="white",
                                         text_color=self.colors['text_secondary'])
        examples_content.pack(fill="x", padx=20, pady=(0, 20))
        examples_content.insert("1.0", examples_text)
        examples_content.configure(state="disabled")

    def setup_settings_tab(self):
        """Setup settings tab"""
        settings_frame = ctk.CTkFrame(self.settings_tab, fg_color=self.colors['bg_secondary'], corner_radius=10)
        settings_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Settings header
        settings_header = ctk.CTkFrame(settings_frame, fg_color="transparent")
        settings_header.pack(fill="x", padx=20, pady=(20, 10))

        settings_title = ctk.CTkLabel(settings_header, text="Application Settings",
                                     font=("Segoe UI", 16, "bold"),
                                     text_color=self.colors['text_primary'])
        settings_title.pack(side="left")

        # Settings content
        settings_content = ctk.CTkFrame(settings_frame, fg_color="transparent")
        settings_content.pack(fill="x", padx=20, pady=(0, 20))

        # Auto-create restore point
        self.restore_var = ctk.BooleanVar(value=self.config['auto_create_restore'])
        restore_switch = ctk.CTkSwitch(settings_content, text="Auto-create restore point before fixes",
                                      variable=self.restore_var,
                                      font=("Segoe UI", 12),
                                      fg_color=self.colors['success'])
        restore_switch.grid(row=0, column=0, sticky="w", pady=10, columnspan=2)

        # Schedule scans
        schedule_label = ctk.CTkLabel(settings_content, text="Schedule scans (hours):",
                                     font=("Segoe UI", 12),
                                     text_color=self.colors['text_secondary'])
        schedule_label.grid(row=1, column=0, sticky="w", pady=10)

        self.schedule_entry = ctk.CTkEntry(settings_content, width=100, height=35,
                                          font=("Segoe UI", 11))
        self.schedule_entry.insert(0, str(self.config['schedule_interval']))
        self.schedule_entry.grid(row=1, column=1, sticky="w", pady=10, padx=10)

        schedule_btn = ctk.CTkButton(settings_content, text="Set Schedule",
                                    command=self.set_schedule,
                                    width=120, height=35)
        schedule_btn.grid(row=1, column=2, sticky="w", pady=10, padx=10)

        # Export format
        export_label = ctk.CTkLabel(settings_content, text="Export format:",
                                   font=("Segoe UI", 12),
                                   text_color=self.colors['text_secondary'])
        export_label.grid(row=2, column=0, sticky="w", pady=10)

        self.export_format = ctk.CTkOptionMenu(settings_content,
                                              values=["HTML", "JSON", "CSV", "PDF"],
                                              width=120, height=35)
        self.export_format.set(self.config['export_format'].upper())
        self.export_format.grid(row=2, column=1, sticky="w", pady=10, padx=10)

        # Logging level
        log_label = ctk.CTkLabel(settings_content, text="Logging level:",
                                font=("Segoe UI", 12),
                                text_color=self.colors['text_secondary'])
        log_label.grid(row=3, column=0, sticky="w", pady=10)

        self.log_level = ctk.CTkOptionMenu(settings_content,
                                          values=["INFO", "WARNING", "ERROR", "DEBUG"],
                                          width=120, height=35)
        self.log_level.set("INFO")
        self.log_level.grid(row=3, column=1, sticky="w", pady=10, padx=10)

        # Save settings button
        save_btn = ctk.CTkButton(settings_content, text="💾 Save Settings",
                                command=self.save_settings,
                                width=150, height=45,
                                fg_color=self.colors['success'],
                                hover_color="#229954",
                                font=("Segoe UI", 12, "bold"))
        save_btn.grid(row=4, column=0, pady=30, columnspan=3)

        # Disclaimer
        disclaimer_frame = ctk.CTkFrame(settings_frame, fg_color="#fff8e6", corner_radius=8)
        disclaimer_frame.pack(fill="x", padx=20, pady=20)

        disclaimer_text = """⚠️  DISCLAIMER & WARNING

This tool performs system scans and can apply security fixes.
By using this tool, you acknowledge and agree that:

1. You have proper authorization to scan the target system
2. You understand the risks of applying automated fixes
3. You have backed up important data before making changes
4. The developers are not responsible for any system damage
5. This tool is for legitimate security assessment only

Always run in Safe Mode first to review findings before applying fixes.
"""

        disclaimer = ctk.CTkTextbox(disclaimer_frame, height=180,
                                   font=("Segoe UI", 10),
                                   fg_color="#fff8e6",
                                   text_color="#e67e22")
        disclaimer.pack(fill="both", padx=15, pady=15)
        disclaimer.insert("1.0", disclaimer_text)
        disclaimer.configure(state="disabled")

    def setup_system_tab(self):
        """Setup system information tab"""
        system_frame = ctk.CTkFrame(self.system_tab, fg_color=self.colors['bg_secondary'], corner_radius=10)
        system_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # System info header
        system_header = ctk.CTkFrame(system_frame, fg_color="transparent")
        system_header.pack(fill="x", padx=20, pady=(20, 10))

        system_title = ctk.CTkLabel(system_header, text="System Information",
                                   font=("Segoe UI", 16, "bold"),
                                   text_color=self.colors['text_primary'])
        system_title.pack(side="left")

        refresh_btn = ctk.CTkButton(system_header, text="🔄 Refresh",
                                   command=self.refresh_system_info,
                                   width=100, height=35)
        refresh_btn.pack(side="right")

        # System info content
        self.system_text = ctk.CTkTextbox(system_frame,
                                         font=("Consolas", 11),
                                         fg_color="#fafbfc",
                                         text_color=self.colors['text_primary'],
                                         border_width=1,
                                         border_color=self.colors['border'],
                                         corner_radius=6)
        self.system_text.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # Initial system info
        self.refresh_system_info()

    def refresh_system_info(self):
        """Refresh and display system information"""
        try:
            import psutil
            import platform

            system_info = f"""
╔══════════════════════════════════════════════════════════════╗
║                      SYSTEM INFORMATION                      ║
╚══════════════════════════════════════════════════════════════╝

Operating System:
    System: {platform.system()} {platform.release()}
    Version: {platform.version()}
    Architecture: {platform.architecture()[0]}

Computer Details:
    Hostname: {socket.gethostname()}
    Processor: {platform.processor()}
    Machine: {platform.machine()}

Hardware Information:
"""
            # CPU info
            cpu_count = psutil.cpu_count(logical=True)
            cpu_percent = psutil.cpu_percent(interval=1)
            system_info += f"    CPU Cores: {cpu_count} (Logical)\n"
            system_info += f"    CPU Usage: {cpu_percent}%\n"

            # Memory info
            mem = psutil.virtual_memory()
            system_info += f"    Total RAM: {mem.total // (1024**3)} GB\n"
            system_info += f"    Available RAM: {mem.available // (1024**3)} GB\n"
            system_info += f"    RAM Usage: {mem.percent}%\n"

            # Disk info
            disk = psutil.disk_usage('/')
            system_info += f"    Total Disk: {disk.total // (1024**3)} GB\n"
            system_info += f"    Used Disk: {disk.used // (1024**3)} GB\n"
            system_info += f"    Free Disk: {disk.free // (1024**3)} GB\n"

            # Network info
            system_info += "\nNetwork Information:\n"
            try:
                hostname = socket.gethostname()
                ip_address = socket.gethostbyname(hostname)
                system_info += f"    IP Address: {ip_address}\n"
            except:
                system_info += "    IP Address: Not available\n"

            # Python info
            system_info += f"""
Python Environment:
    Python Version: {platform.python_version()}
    Python Implementation: {platform.python_implementation()}

RAVEN-X Information:
    Scan ID: {self.scanner.scan_id}
    Version: 3.0 Professional
    Safe Mode: {'Enabled' if self.config['safe_mode'] else 'Disabled'}
"""

            self.system_text.configure(state="normal")
            self.system_text.delete("1.0", "end")
            self.system_text.insert("1.0", system_info)
            self.system_text.configure(state="disabled")

        except Exception as e:
            self.system_text.configure(state="normal")
            self.system_text.delete("1.0", "end")
            self.system_text.insert("1.0", f"Error gathering system info: {str(e)}")
            self.system_text.configure(state="disabled")

    def update_progress(self, current, total, message):
        """Update progress bar and label"""
        self.progress_bar.set(current / total if total > 0 else 0)
        self.progress_label.configure(text=f"{message} ({current}/{total})")
        self.root.update()

    def start_scan(self):
        """Start comprehensive security scan"""
        if self.is_scanning:
            return

        self.is_scanning = True
        self.scan_button.configure(state="disabled", text="Scanning...")
        self.quick_scan_button.configure(state="disabled")
        self.status_label.configure(text="Starting comprehensive security scan...")

        self.results_text.configure(state="normal")
        self.results_text.delete("1.0", "end")
        self.results_text.insert("1.0", "🚀 Starting comprehensive security scan...\n" + "="*60 + "\n\n")
        self.results_text.configure(state="disabled")

        def scan_thread():
            try:
                self.vulnerabilities = self.scanner.scan_all(progress_callback=self.update_progress)
                self.root.after(0, self.display_results)
            except Exception as e:
                error_msg = str(e)
                logger.error(f"Scan error: {error_msg}")
                self.root.after(0, lambda msg=error_msg: self.show_error(f"Scan failed: {msg}"))
            finally:
                self.root.after(0, lambda: self.scan_button.configure(state="normal", text="🔍 Start Security Scan"))
                self.root.after(0, lambda: self.quick_scan_button.configure(state="normal"))
                self.root.after(0, lambda: setattr(self, 'is_scanning', False))
                self.root.after(0, lambda: self.progress_bar.set(0))
                self.root.after(0, lambda: self.progress_label.configure(text=""))

        threading.Thread(target=scan_thread, daemon=True).start()

    def start_quick_scan(self):
        """Start quick scan (basic checks only)"""
        if self.is_scanning:
            return

        self.is_scanning = True
        self.scan_button.configure(state="disabled")
        self.quick_scan_button.configure(state="disabled", text="Quick Scanning...")
        self.status_label.configure(text="Starting quick scan...")

        self.results_text.configure(state="normal")
        self.results_text.delete("1.0", "end")
        self.results_text.insert("1.0", "⚡ Starting quick security scan...\n" + "="*60 + "\n\n")
        self.results_text.configure(state="disabled")

        def quick_scan_thread():
            try:
                # Run only critical checks
                self.scanner.vulnerabilities = []
                self.scanner.check_windows_updates()
                self.scanner.check_firewall()
                self.scanner.check_antivirus()
                self.scanner.check_open_ports()
                self.vulnerabilities = self.scanner.vulnerabilities

                self.root.after(0, self.display_results)
            except Exception as e:
                error_msg = str(e)
                logger.error(f"Quick scan error: {error_msg}")
                self.root.after(0, lambda msg=error_msg: self.show_error(f"Quick scan failed: {msg}"))
            finally:
                self.root.after(0, lambda: self.scan_button.configure(state="normal"))
                self.root.after(0, lambda: self.quick_scan_button.configure(state="normal", text="⚡ Quick Scan"))
                self.root.after(0, lambda: setattr(self, 'is_scanning', False))

        threading.Thread(target=quick_scan_thread, daemon=True).start()

    def display_results(self):
        """Display scan results with enhanced formatting"""
        self.results_text.configure(state="normal")
        self.results_text.delete("1.0", "end")

        if not self.vulnerabilities:
            success_msg = """✅ SCAN COMPLETE - NO VULNERABILITIES DETECTED

╔══════════════════════════════════════════════════════════════╗
║                    SECURE SYSTEM STATUS                      ║
╚══════════════════════════════════════════════════════════════╝

Congratulations! Your system appears to be properly configured 
with no security issues found in the scanned categories.

🔹 RECOMMENDATIONS FOR MAINTAINING SECURITY:

1. Keep Windows Update enabled and check regularly
2. Maintain regular security scans (weekly recommended)
3. Keep antivirus definitions up to date
4. Review security logs periodically
5. Use strong, unique passwords
6. Enable BitLocker for disk encryption
7. Regular system backups

⚠️  Note: This scan covers common security configurations but
does not guarantee complete security. Regular updates and 
vigilance are essential.

"""
            self.results_text.insert("1.0", success_msg)
            self.results_text.configure(state="disabled")

            self.scan_button.configure(state="normal", text="🔍 Start Security Scan")
            self.quick_scan_button.configure(state="normal")
            self.status_label.configure(text="Scan complete - System secure")

            # Update stats
            self.stats_critical.configure(text="🔴 Critical: 0")
            self.stats_high.configure(text="🟠 High: 0")
            self.stats_medium.configure(text="🟡 Medium: 0")
            self.stats_low.configure(text="⚪ Low: 0")
            self.stats_total.configure(text="Total Issues: 0")
            self.risk_score_label.configure(text="Risk: 0%")

            return

        # Sort vulnerabilities by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        sorted_vulns = sorted(self.vulnerabilities,
                            key=lambda x: severity_order.get(x['severity'], 4))

        # Update stats
        stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for v in self.vulnerabilities:
            severity = v['severity']
            if severity in stats:
                stats[severity] += 1

        total_vulns = len(self.vulnerabilities)

        self.stats_critical.configure(text=f"🔴 Critical: {stats['critical']}")
        self.stats_high.configure(text=f"🟠 High: {stats['high']}")
        self.stats_medium.configure(text=f"🟡 Medium: {stats['medium']}")
        self.stats_low.configure(text=f"⚪ Low: {stats['low']}")
        self.stats_total.configure(text=f"Total Issues: {total_vulns}")

        # Calculate and display risk score
        risk_score, risk_level = self.scanner.calculate_risk_score()
        self.risk_score_label.configure(text=f"Risk: {risk_score}%")

        # Build results text with enhanced formatting
        result_text = f"""🔍 SECURITY SCAN COMPLETE - {total_vulns} ISSUES FOUND

╔══════════════════════════════════════════════════════════════╗
║                      SCAN SUMMARY                            ║
╚══════════════════════════════════════════════════════════════╝

Overall Risk Score: {risk_score}% - {risk_level}
Scan ID: {self.scanner.scan_id}
Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Severity Breakdown:
🔴 Critical: {stats['critical']} issue(s)
🟠 High: {stats['high']} issue(s)
🟡 Medium: {stats['medium']} issue(s)
⚪ Low: {stats['low']} issue(s)

════════════════════════════════════════════════════════════════
                    DETAILED FINDINGS
════════════════════════════════════════════════════════════════

"""

        severity_symbols = {
            'critical': '🔴 CRITICAL',
            'high': '🟠 HIGH',
            'medium': '🟡 MEDIUM',
            'low': '⚪ LOW'
        }

        severity_colors = {
            'critical': '#e74c3c',
            'high': '#e67e22',
            'medium': '#f39c12',
            'low': '#95a5a6'
        }

        for i, vuln in enumerate(sorted_vulns, 1):
            symbol = severity_symbols.get(vuln['severity'], '⚪ UNKNOWN')
            color = severity_colors.get(vuln['severity'], '#000000')

            # Format each vulnerability with clear sections
            result_text += f"\n{'━' * 60}\n"
            result_text += f"{i}. {symbol} - {vuln['title']}\n"
            result_text += f"{'─' * 40}\n"
            result_text += f"   📂 Category: {vuln['category']}\n"
            result_text += f"   ⚙️  Component: {vuln['component']}\n"
            result_text += f"\n   📝 Details:\n   {vuln['details']}\n"

            if 'remediation' in vuln and vuln['remediation']:
                result_text += f"\n   🔧 Remediation:\n   {vuln['remediation']}\n"

            result_text += f"\n   {'─' * 40}\n"

        result_text += f"\n{'━' * 60}\n\n"
        result_text += "💡 RECOMMENDED ACTIONS:\n\n"
        result_text += "1. Review all critical and high severity issues first\n"
        result_text += "2. Use 'AI Analysis' for prioritized remediation steps\n"
        result_text += "3. Consider using 'Fix Issues' for automated remediation\n"
        result_text += "4. Export report for documentation and compliance\n"
        result_text += "5. Schedule regular scans to monitor security posture\n"

        if self.config['safe_mode']:
            result_text += "\n⚠️  SAFE MODE ENABLED: No automatic fixes will be applied\n"

        self.results_text.insert("1.0", result_text)
        self.results_text.configure(state="disabled")

        # Enable action buttons
        self.scan_button.configure(state="normal", text="🔍 Start Security Scan")
        self.quick_scan_button.configure(state="normal")
        self.status_label.configure(text=f"Scan complete - {total_vulns} issues detected - Risk: {risk_score}%")

        self.ai_button.configure(state="normal")
        self.fix_button.configure(state="normal")
        self.export_button.configure(state="normal")

    def filter_results(self, severity):
        """Filter results by severity"""
        if not self.vulnerabilities:
            return

        self.results_text.configure(state="normal")
        self.results_text.delete("1.0", "end")

        if severity == 'all':
            self.display_results()
            return

        filtered = [v for v in self.vulnerabilities if v['severity'] == severity]

        if not filtered:
            self.results_text.insert("1.0", f"No {severity} severity issues found.")
            self.results_text.configure(state="disabled")
            return

        result_text = f"🔍 {severity.upper()} SEVERITY ISSUES ({len(filtered)} found)\n\n"

        for i, vuln in enumerate(filtered, 1):
            result_text += f"{i}. {vuln['title']}\n"
            result_text += f"   Category: {vuln['category']}\n"
            result_text += f"   Component: {vuln['component']}\n"
            result_text += f"   Details: {vuln['details']}\n"
            result_text += f"   Remediation: {vuln.get('remediation', 'N/A')}\n"
            result_text += "-" * 60 + "\n\n"

        self.results_text.insert("1.0", result_text)
        self.results_text.configure(state="disabled")

    def create_system_restore_point(self):
        """Create a system restore point before making changes"""
        try:
            import ctypes
            from ctypes import wintypes

            # Check if we have admin privileges
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                logger.warning("Admin privileges required for restore point creation")
                return False

            # Create restore point using PowerShell
            ps_script = '''
$ErrorActionPreference = "Stop"
try {
    $restorePointName = "RAVEN-X Security Fixes - " + (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    Checkpoint-Computer -Description $restorePointName -RestorePointType "MODIFY_SETTINGS"
    Write-Output "[SUCCESS] Restore point created: $restorePointName"
    return $true
} catch {
    Write-Output "[ERROR] Failed to create restore point: $($_.Exception.Message)"
    return $false
}
'''

            with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False) as f:
                script_path = f.name
                f.write(ps_script)

            cmd = f'powershell -ExecutionPolicy Bypass -File "{script_path}"'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=30)

            os.unlink(script_path)

            if '[SUCCESS]' in result.stdout:
                logger.info("System restore point created successfully")
                return True
            else:
                logger.error(f"Failed to create restore point: {result.stdout}")
                return False

        except Exception as e:
            logger.error(f"Error creating restore point: {e}")
            return False

    def fix_vulnerabilities(self):
        """Fix vulnerabilities with enhanced safety features"""
        if not self.vulnerabilities:
            self.show_info("No vulnerabilities to fix.")
            return

        # Check if in safe mode
        if self.config['safe_mode']:
            response = messagebox.askyesno(
                "Safe Mode Enabled",
                "Safe Mode is currently enabled. This means you can review findings "
                "but fixes won't be applied automatically.\n\n"
                "Would you like to disable Safe Mode and proceed with fixes?",
                parent=self.root
            )
            if not response:
                return
            self.config['safe_mode'] = False
            self.safe_mode_switch.deselect()

        # Ask for confirmation
        confirm_msg = f"""⚠️  CONFIRM AUTOMATED FIXES

This will attempt to fix {len(self.vulnerabilities)} security issues.

IMPORTANT:
• Some fixes require administrator privileges
• System restart may be required for some changes
• A system restore point will be created (if enabled)
• Review each change carefully before proceeding

Do you want to proceed with the automated fixes?"""

        response = messagebox.askyesno(
            "Confirm Auto-Fix",
            confirm_msg,
            parent=self.root
        )

        if not response:
            return

        # Create restore point if enabled
        if self.config['auto_create_restore']:
            self.status_label.configure(text="Creating system restore point...")
            success = self.create_system_restore_point()
            if not success:
                response = messagebox.askyesno(
                    "Restore Point Failed",
                    "Failed to create system restore point. Continue anyway?",
                    parent=self.root
                )
                if not response:
                    return

        # Proceed with fixes
        self.execute_fixes()

    def execute_fixes(self):
        """Execute fixes with enhanced error handling and logging"""
        self.fix_button.configure(state="disabled", text="Applying fixes...")
        self.status_label.configure(text="Applying security fixes...")

        def fix_thread():
            fix_results = []
            fix_results.append("🔧 RAVEN-X AUTOMATED FIXES")
            fix_results.append("=" * 60)
            fix_results.append(f"Fix started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            fix_results.append("")

            # Check admin privileges
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if not is_admin:
                    fix_results.append("❌ ERROR: Administrator privileges required!")
                    fix_results.append("   Please run the application as Administrator to apply fixes.")
                    self.root.after(0, lambda: self.show_fix_results(fix_results))
                    return
            except:
                fix_results.append("⚠️  Warning: Could not verify administrator privileges")

            # Group fixes by category for better organization
            fixes_by_category = defaultdict(list)
            for vuln in self.vulnerabilities:
                fixes_by_category[vuln['category']].append(vuln)

            # Process fixes by category
            for category, vulns in fixes_by_category.items():
                fix_results.append(f"\n📂 {category.upper()} FIXES")
                fix_results.append("-" * 40)

                for vuln in vulns:
                    result = self.apply_fix(vuln)
                    fix_results.extend(result)

            fix_results.append("\n" + "=" * 60)
            fix_results.append("✅ FIX PROCESS COMPLETE")
            fix_results.append("")

            # Summary
            critical_fixed = sum(1 for r in fix_results if '✓ Fixed' in r and 'CRITICAL' in r)
            high_fixed = sum(1 for r in fix_results if '✓ Fixed' in r and 'HIGH' in r)
            total_fixed = sum(1 for r in fix_results if '✓ Fixed' in r)
            total_failed = sum(1 for r in fix_results if '✗ Failed' in r)

            fix_results.append(f"SUMMARY:")
            fix_results.append(f"  Total fixed: {total_fixed}")
            fix_results.append(f"  Critical fixed: {critical_fixed}")
            fix_results.append(f"  High fixed: {high_fixed}")
            fix_results.append(f"  Failed: {total_failed}")
            fix_results.append(f"  Manual actions required: {sum(1 for r in fix_results if '⚠ MANUAL' in r)}")

            fix_results.append("\n📋 NEXT STEPS:")
            fix_results.append("  1. Run a new scan to verify fixes")
            fix_results.append("  2. Restart system if prompted")
            fix_results.append("  3. Review any manual actions needed")
            fix_results.append("  4. Check Windows Update for patches")
            fix_results.append("  5. Monitor system stability")

            self.root.after(0, lambda: self.show_fix_results(fix_results))

        threading.Thread(target=fix_thread, daemon=True).start()

    def apply_fix(self, vuln):
        """Apply a single fix with comprehensive error handling"""
        results = []
        category = vuln['category']
        title = vuln['title']
        severity = vuln['severity'].upper()

        try:
            if 'Firewall' in category:
                results.append(f"🔧 Fixing firewall: {title}")
                if 'DomainProfile' in title:
                    cmd = 'netsh advfirewall set domainprofile state on'
                elif 'PrivateProfile' in title:
                    cmd = 'netsh advfirewall set privateprofile state on'
                elif 'PublicProfile' in title:
                    cmd = 'netsh advfirewall set publicprofile state on'
                else:
                    cmd = 'netsh advfirewall set allprofiles state on'

                result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=10)
                if result.returncode == 0:
                    results.append(f"  ✓ {severity} FIXED: {title}")
                else:
                    results.append(f"  ✗ {severity} FAILED: {title}")
                    results.append(f"    Error: {result.stderr[:100]}")

            elif 'Windows Update' in category:
                if 'Service' in title:
                    results.append(f"🔧 Fixing Windows Update service")
                    cmd = 'sc config wuauserv start=auto && sc start wuauserv'
                    result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=15)
                    if result.returncode == 0 or 'already running' in result.stdout.lower():
                        results.append(f"  ✓ {severity} FIXED: {title}")
                    else:
                        results.append(f"  ✗ {severity} FAILED: {title}")

                elif 'Outdated' in title:
                    results.append(f"⚠ {severity} MANUAL: {title}")
                    results.append("  Open Windows Update settings to install updates")
                    subprocess.Popen('start ms-settings:windowsupdate', shell=True)

            elif 'User Account Control' in category:
                results.append(f"🔧 Fixing UAC settings")
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                       r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
                                       0, winreg.KEY_SET_VALUE)
                    winreg.SetValueEx(key, 'ConsentPromptBehaviorAdmin', 0, winreg.REG_DWORD, 2)
                    winreg.SetValueEx(key, 'PromptOnSecureDesktop', 0, winreg.REG_DWORD, 1)
                    winreg.CloseKey(key)
                    results.append(f"  ✓ {severity} FIXED: {title} (restart required)")
                except Exception as e:
                    results.append(f"  ✗ {severity} FAILED: {title}")
                    results.append(f"    Error: {str(e)}")

            elif 'Remote Desktop' in category or 'RDP' in title:
                results.append(f"🔧 Disabling Remote Desktop")
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                       r'SYSTEM\CurrentControlSet\Control\Terminal Server',
                                       0, winreg.KEY_SET_VALUE)
                    winreg.SetValueEx(key, 'fDenyTSConnections', 0, winreg.REG_DWORD, 1)
                    winreg.CloseKey(key)
                    results.append(f"  ✓ {severity} FIXED: {title}")
                except Exception as e:
                    results.append(f"  ✗ {severity} FAILED: {title}")
                    results.append(f"    Error: {str(e)}")

            elif 'Network' in category:
                if 'Risky Port' in title:
                    port = vuln.get('port')
                    if port:
                        results.append(f"🔧 Blocking risky port {port}")
                        cmd_block = f'netsh advfirewall firewall add rule name="RAVEN-X Block Port {port}" dir=in action=block protocol=TCP localport={port}'
                        result = subprocess.run(cmd_block, capture_output=True, text=True, shell=True, timeout=10)
                        if result.returncode == 0:
                            results.append(f"  ✓ {severity} FIXED: Blocked port {port}")
                        else:
                            results.append(f"  ✗ {severity} FAILED: Port {port}")

                elif 'Network Discovery' in title:
                    cmd = 'netsh advfirewall firewall set rule group="Network Discovery" new enable=No'
                    result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=10)
                    if result.returncode == 0:
                        results.append(f"  ✓ {severity} FIXED: {title}")
                    else:
                        results.append(f"  ✗ {severity} FAILED: {title}")

                elif 'File and Printer Sharing' in title:
                    cmd = 'netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No'
                    result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=10)
                    if result.returncode == 0:
                        results.append(f"  ✓ {severity} FIXED: {title}")
                    else:
                        results.append(f"  ✗ {severity} FAILED: {title}")

            else:
                results.append(f"⚠ {severity} MANUAL REQUIRED: {title}")
                if 'remediation' in vuln:
                    results.append(f"  Action: {vuln['remediation']}")

        except Exception as e:
            results.append(f"✗ {severity} ERROR: {title}")
            results.append(f"  Exception: {str(e)}")

        return results

    def show_fix_results(self, results):
        """Display fix results in a dialog"""
        result_window = ctk.CTkToplevel(self.root)
        result_window.title("Fix Results")
        result_window.geometry("1000x700")

        # Center the window
        result_window.update_idletasks()
        width = result_window.winfo_width()
        height = result_window.winfo_height()
        x = (result_window.winfo_screenwidth() // 2) - (width // 2)
        y = (result_window.winfo_screenheight() // 2) - (height // 2)
        result_window.geometry(f'{width}x{height}+{x}+{y}')

        # Header
        header_frame = ctk.CTkFrame(result_window, fg_color=self.colors['bg_secondary'],
                                   corner_radius=0, height=80)
        header_frame.pack(fill="x", padx=0, pady=0)
        header_frame.pack_propagate(False)

        header_content = ctk.CTkFrame(header_frame, fg_color="transparent")
        header_content.pack(fill="both", expand=True, padx=25, pady=15)

        header_title = ctk.CTkLabel(header_content, text="Remediation Results",
                                   font=("Segoe UI", 20, "bold"),
                                   text_color=self.colors['text_primary'])
        header_title.pack(anchor="w")

        subtitle = ctk.CTkLabel(header_content, text="Review the changes made to your system",
                               font=("Segoe UI", 11),
                               text_color=self.colors['text_secondary'])
        subtitle.pack(anchor="w", pady=(5, 0))

        # Results text
        text_frame = ctk.CTkFrame(result_window, fg_color=self.colors['bg_primary'])
        text_frame.pack(fill="both", expand=True, padx=20, pady=20)

        result_text = ctk.CTkTextbox(text_frame,
                                    font=("Consolas", 11),
                                    fg_color=self.colors['bg_secondary'],
                                    text_color=self.colors['text_primary'],
                                    border_width=1,
                                    border_color=self.colors['border'],
                                    corner_radius=8)
        result_text.pack(fill="both", expand=True)

        result_summary = "\n".join(results)
        result_text.insert("1.0", result_summary)
        result_text.configure(state="disabled")

        # Buttons
        btn_frame = ctk.CTkFrame(result_window, fg_color=self.colors['bg_primary'])
        btn_frame.pack(pady=20)

        rescan_btn = ctk.CTkButton(btn_frame, text="🔄 Run New Scan",
                                  command=lambda: [result_window.destroy(), self.start_scan()],
                                  fg_color=self.colors['accent'],
                                  hover_color=self.colors['accent_hover'],
                                  width=180, height=45,
                                  font=("Segoe UI", 12, "bold"),
                                  corner_radius=8)
        rescan_btn.pack(side="left", padx=10)

        export_btn = ctk.CTkButton(btn_frame, text="📤 Export Results",
                                  command=lambda: self.export_fix_results(results, result_window),
                                  fg_color=self.colors['success'],
                                  hover_color="#229954",
                                  width=180, height=45,
                                  font=("Segoe UI", 12, "bold"),
                                  corner_radius=8)
        export_btn.pack(side="left", padx=10)

        close_btn = ctk.CTkButton(btn_frame, text="✗ Close",
                                 command=result_window.destroy,
                                 fg_color=self.colors['text_secondary'],
                                 hover_color="#7f8c8d",
                                 width=120, height=45,
                                 font=("Segoe UI", 12, "bold"),
                                 corner_radius=8)
        close_btn.pack(side="left", padx=10)

        self.fix_button.configure(state="normal", text="🔧 Fix Issues")
        self.status_label.configure(text="Fixes applied - Ready for new scan")

    def export_fix_results(self, results, parent_window):
        """Export fix results to file"""
        filename = filedialog.asksaveasfilename(
            parent=parent_window,
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("Log files", "*.log"),
                ("All files", "*.*")
            ],
            initialfile=f"raven_x_fix_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )

        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("\n".join(results))
                self.show_info(f"Results exported to:\n{filename}")
            except Exception as e:
                self.show_error(f"Failed to export results: {str(e)}")

    def export_report(self):
        """Export scan report in selected format"""
        if not self.vulnerabilities:
            self.show_info("No scan results to export.")
            return

        format_map = {
            'HTML': 'html',
            'JSON': 'json',
            'CSV': 'csv',
            'PDF': 'html'  # PDF would need additional library
        }

        selected_format = self.export_format.get()
        format_ext = format_map.get(selected_format, 'html')

        filename = filedialog.asksaveasfilename(
            parent=self.root,
            defaultextension=f".{format_ext.lower()}",
            filetypes=[
                (f"{selected_format} files", f"*.{format_ext.lower()}"),
                ("All files", "*.*")
            ],
            initialfile=f"raven_x_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format_ext.lower()}"
        )

        if filename:
            try:
                report = self.scanner.generate_report(format=format_ext.lower())

                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(report)

                self.show_info(f"Report exported to:\n{filename}")

                # Open the file if it's HTML
                if format_ext.lower() == 'html' and messagebox.askyesno(
                    "Open Report",
                    "Would you like to open the HTML report in your browser?",
                    parent=self.root
                ):
                    webbrowser.open(f"file://{os.path.abspath(filename)}")

            except Exception as e:
                self.show_error(f"Failed to export report: {str(e)}")

    def get_ai_analysis(self):
        """Get AI analysis of vulnerabilities"""
        if not self.vulnerabilities:
            self.show_info("No vulnerabilities to analyze.")
            return

        self.ai_button.configure(state="disabled", text="Analyzing...")

        def analyze_thread():
            try:
                self.config['lm_studio_url'] = self.url_entry.get()
                self.config['model_name'] = self.model_entry.get()

                # Prepare vulnerability summary
                vuln_summary = "\n\n".join([
                    f"## {v['severity'].upper()}: {v['title']}\n"
                    f"**Category**: {v['category']}\n"
                    f"**Component**: {v['component']}\n"
                    f"**Details**: {v['details']}\n"
                    f"**Remediation**: {v.get('remediation', 'Not specified')}"
                    for v in self.vulnerabilities[:20]  # Limit to first 20 for token limits
                ])

                client = OpenAI(base_url=self.config['lm_studio_url'], api_key="lm-studio")

                prompt = f"""You are a cybersecurity expert analyzing Windows system vulnerabilities.

DETECTED VULNERABILITIES:
{vuln_summary}

SYSTEM CONTEXT:
- This is a Windows system security assessment
- Vulnerabilities have been detected by automated scanning
- The user may have limited technical expertise

PLEASE PROVIDE:
1. EXECUTIVE SUMMARY (2-3 paragraphs)
   - Overall risk assessment
   - Most critical issues to address immediately

2. PRIORITIZED REMEDIATION PLAN
   - Top 5 issues to fix first (with severity and reasoning)
   - Step-by-step instructions for each (clear, actionable)

3. SECURITY RECOMMENDATIONS
   - General security best practices
   - Monitoring and maintenance advice
   - Additional security tools to consider

4. COMPLIANCE & STANDARDS
   - How these findings relate to common standards (CIS, NIST, etc.)
   - Documentation and reporting advice

FORMAT:
- Use clear headings and bullet points
- Avoid technical jargon where possible
- Provide specific commands or steps when applicable
- Include warnings about potential risks

IMPORTANT: Be practical and actionable. The user needs clear guidance.
"""

                response = client.chat.completions.create(
                    model=self.config['model_name'],
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity expert specializing in Windows security."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.7,
                    max_tokens=3000,
                    stream=False
                )

                analysis = response.choices[0].message.content
                self.root.after(0, lambda: self.show_ai_analysis(analysis))

            except Exception as e:
                error_msg = str(e)
                error_display = f"""## CONNECTION ERROR

Failed to connect to LM Studio: {error_msg}

### TROUBLESHOOTING STEPS:

1. **Ensure LM Studio is running**
   - Open LM Studio application
   - Load a model (like Llama 3.1, CodeLlama, etc.)
   - Start the local server (usually http://localhost:1234)

2. **Verify Configuration**
   - URL: {self.config['lm_studio_url']}
   - Model: {self.config['model_name']}
   - Check if the model is loaded in LM Studio

3. **Alternative Actions**
   - Try a different model if available
   - Check firewall settings
   - Restart LM Studio

4. **Continue Without AI**
   - You can still review vulnerabilities manually
   - Use the remediation suggestions in the scan results
   - Consult online security resources

**Note:** AI analysis requires LM Studio running locally with a compatible model.
"""
                self.root.after(0, lambda: self.show_ai_analysis(error_display))
            finally:
                self.root.after(0, lambda: self.ai_button.configure(state="normal", text="🤖 AI Analysis"))

        threading.Thread(target=analyze_thread, daemon=True).start()

    def show_ai_analysis(self, analysis):
        """Display AI analysis in a window"""
        ai_window = ctk.CTkToplevel(self.root)
        ai_window.title("AI Security Analysis")
        ai_window.geometry("1200x800")

        # Center the window
        ai_window.update_idletasks()
        width = ai_window.winfo_width()
        height = ai_window.winfo_height()
        x = (ai_window.winfo_screenwidth() // 2) - (width // 2)
        y = (ai_window.winfo_screenheight() // 2) - (height // 2)
        ai_window.geometry(f'{width}x{height}+{x}+{y}')

        # Header
        header_frame = ctk.CTkFrame(ai_window, fg_color=self.colors['bg_secondary'],
                                   corner_radius=0, height=80)
        header_frame.pack(fill="x", padx=0, pady=0)
        header_frame.pack_propagate(False)

        header_content = ctk.CTkFrame(header_frame, fg_color="transparent")
        header_content.pack(fill="both", expand=True, padx=25, pady=15)

        header_title = ctk.CTkLabel(header_content, text="🤖 AI Security Analysis",
                                   font=("Segoe UI", 20, "bold"),
                                   text_color=self.colors['text_primary'])
        header_title.pack(anchor="w")

        subtitle = ctk.CTkLabel(header_content, text=f"Generated by {self.config['model_name']} | {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                               font=("Segoe UI", 11),
                               text_color=self.colors['text_secondary'])
        subtitle.pack(anchor="w", pady=(5, 0))

        # Analysis text with scrollbar
        text_frame = ctk.CTkFrame(ai_window, fg_color=self.colors['bg_primary'])
        text_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Add scrollbar
        text_container = ctk.CTkFrame(text_frame, fg_color=self.colors['bg_secondary'])
        text_container.pack(fill="both", expand=True)

        analysis_text = ctk.CTkTextbox(text_container,
                                      font=("Segoe UI", 11),
                                      fg_color=self.colors['bg_secondary'],
                                      text_color=self.colors['text_primary'],
                                      border_width=0,
                                      wrap="word")

        scrollbar = ctk.CTkScrollbar(text_container, command=analysis_text.yview)
        analysis_text.configure(yscrollcommand=scrollbar.set)

        analysis_text.pack(side="left", fill="both", expand=True, padx=0, pady=0)
        scrollbar.pack(side="right", fill="y", padx=0, pady=0)

        # Insert and format the analysis
        analysis_text.insert("1.0", analysis)

        # Apply some basic formatting
        analysis_text.configure(state="normal")

        # Make headers bold (basic formatting)
        text_content = analysis_text.get("1.0", "end")
        lines = text_content.split('\n')

        analysis_text.delete("1.0", "end")
        for line in lines:
            if line.strip().startswith('#') or line.strip().upper() == line.strip() and len(line.strip()) > 3:
                # This is likely a header
                analysis_text.insert("end", line + "\n", "header")
            else:
                analysis_text.insert("end", line + "\n")

        analysis_text.tag_configure("header", font=("Segoe UI", 12, "bold"), foreground=self.colors['accent'])
        analysis_text.configure(state="disabled")

        # Buttons
        btn_frame = ctk.CTkFrame(ai_window, fg_color=self.colors['bg_primary'])
        btn_frame.pack(pady=20)

        export_btn = ctk.CTkButton(btn_frame, text="💾 Save Analysis",
                                  command=lambda: self.export_analysis(analysis, ai_window),
                                  fg_color=self.colors['accent'],
                                  hover_color=self.colors['accent_hover'],
                                  width=180, height=45,
                                  font=("Segoe UI", 12, "bold"),
                                  corner_radius=8)
        export_btn.pack(side="left", padx=10)

        close_btn = ctk.CTkButton(btn_frame, text="✗ Close",
                                 command=ai_window.destroy,
                                 fg_color=self.colors['text_secondary'],
                                 hover_color="#7f8c8d",
                                 width=120, height=45,
                                 font=("Segoe UI", 12, "bold"),
                                 corner_radius=8)
        close_btn.pack(side="left", padx=10)

    def export_analysis(self, analysis, parent_window):
        """Export AI analysis to file"""
        filename = filedialog.asksaveasfilename(
            parent=parent_window,
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("Markdown files", "*.md"),
                ("All files", "*.*")
            ],
            initialfile=f"raven_x_ai_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )

        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"RAVEN-X AI Security Analysis\n")
                    f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Model: {self.config['model_name']}\n")
                    f.write("=" * 60 + "\n\n")
                    f.write(analysis)
                self.show_info(f"Analysis exported to:\n{filename}")
            except Exception as e:
                self.show_error(f"Failed to export analysis: {str(e)}")

    def test_connection(self):
        """Test connection to LM Studio"""
        self.test_btn.configure(state="disabled", text="Testing...")
        self.connection_status.configure(text="● Testing...", text_color=self.colors['medium'])

        def test_thread():
            try:
                url = self.url_entry.get()
                model = self.model_entry.get()

                self.config['lm_studio_url'] = url
                self.config['model_name'] = model

                client = OpenAI(base_url=url, api_key="lm-studio")

                # Test with a simple prompt
                response = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": "Hello, please respond with 'OK' if you can read this."}],
                    max_tokens=10,
                    temperature=0.1
                )

                if response.choices[0].message.content:
                    self.root.after(0, lambda: self.connection_status.configure(
                        text="● Connected", text_color=self.colors['success']))
                    logger.info(f"LM Studio connection successful: {model}")
                else:
                    self.root.after(0, lambda: self.connection_status.configure(
                        text="● No response", text_color=self.colors['warning']))

            except Exception as e:
                logger.error(f"LM Studio connection failed: {e}")
                self.root.after(0, lambda: self.connection_status.configure(
                    text="● Connection failed", text_color=self.colors['critical']))
            finally:
                self.root.after(0, lambda: self.test_btn.configure(state="normal", text="Test Connection"))

        threading.Thread(target=test_thread, daemon=True).start()

    def toggle_safe_mode(self):
        """Toggle safe mode on/off"""
        self.config['safe_mode'] = self.safe_mode_var.get()
        status = "enabled" if self.config['safe_mode'] else "disabled"
        self.status_label.configure(text=f"Safe mode {status}")
        logger.info(f"Safe mode {status}")

    def set_schedule(self):
        """Set scheduled scans"""
        try:
            hours = int(self.schedule_entry.get())
            if hours < 1 or hours > 168:  # Max 1 week
                self.show_error("Please enter a value between 1 and 168 hours.")
                return

            self.config['schedule_interval'] = hours
            self.show_info(f"Scheduled scans set to every {hours} hours.")
            logger.info(f"Scan schedule set to {hours} hours")

        except ValueError:
            self.show_error("Please enter a valid number of hours.")

    def save_settings(self):
        """Save application settings"""
        try:
            self.config['auto_create_restore'] = self.restore_var.get()
            self.config['schedule_interval'] = int(self.schedule_entry.get())
            self.config['export_format'] = self.export_format.get().lower()

            # Update logging level
            log_level = self.log_level.get()
            logging.getLogger().setLevel(getattr(logging, log_level))

            self.show_info("Settings saved successfully.")
            logger.info(f"Settings saved: {self.config}")

        except Exception as e:
            self.show_error(f"Failed to save settings: {str(e)}")

    def show_info(self, message):
        """Show information message"""
        messagebox.showinfo("Information", message, parent=self.root)

    def show_error(self, message):
        """Show error message"""
        messagebox.showerror("Error", message, parent=self.root)

    def run(self):
        """Run the application"""
        # Show disclaimer on first run
        try:
            disclaimer_shown = os.path.exists('.disclaimer_shown')
            if not disclaimer_shown:
                disclaimer = """
                ⚠️  RAVEN-X SECURITY SCANNER - DISCLAIMER

                This tool is for authorized security testing and educational purposes only.

                BY USING THIS SOFTWARE, YOU AGREE THAT:

                1. You have proper authorization to scan the target system
                2. You understand the risks of automated security fixes
                3. You will backup important data before making changes
                4. The developers are not responsible for any system damage
                5. This tool is for legitimate security assessment only

                Always test in a controlled environment first.
                """

                response = messagebox.askyesno(
                    "Disclaimer",
                    disclaimer + "\n\nDo you accept these terms and conditions?",
                    parent=self.root
                )

                if response:
                    with open('.disclaimer_shown', 'w') as f:
                        f.write('1')
                else:
                    self.root.destroy()
                    return
        except:
            pass

        self.root.mainloop()


def main():
    """Main entry point with enhanced startup"""
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                 RAVEN-X SECURITY SCANNER v3.0                ║
    ║         AI-Powered Windows Vulnerability Scanner             ║
    ╚══════════════════════════════════════════════════════════════╝

    Version: 3.0 Professional Edition
    Author: Security Research Team
    License: Educational/Authorized Use Only

    Loading...
    """)

    # Check requirements
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()

        if not is_admin:
            print("⚠️  Warning: Not running as administrator.")
            print("   Some scans and fixes may be limited.")
            print("   For full functionality, run as Administrator.\n")

        # Check Python version
        if sys.version_info < (3, 7):
            print("❌ Error: Python 3.7 or higher is required.")
            sys.exit(1)

    except Exception as e:
        print(f"⚠️  Warning: Could not check privileges: {e}")

    # Start the application
    try:
        app = VulnerabilityGUI()
        app.run()
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        print("\nTroubleshooting tips:")
        print("1. Run as Administrator")
        print("2. Install requirements: pip install -r requirements.txt")
        print("3. Check Windows version compatibility")
        input("\nPress Enter to exit...")


if __name__ == "__main__":
    main()