"""
RAVEN-X Enterprise - Auto-Fixer
Intelligent vulnerability remediation
"""

import subprocess
import winreg
import logging
from typing import Dict
from datetime import datetime
import tempfile
import os

logger = logging.getLogger(__name__)

class AutoFixer:
    """
    Automated vulnerability remediation engine
    """
    
    def __init__(self):
        self.fix_history = []
        logger.info("🔧 Auto-Fixer initialized")
    
    async def create_restore_point(self) -> bool:
        """
        Create system restore point
        """
        try:
            ps_script = '''
$ErrorActionPreference = "Stop"
$restorePointName = "RAVEN-X Auto-Fix - " + (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Checkpoint-Computer -Description $restorePointName -RestorePointType "MODIFY_SETTINGS"
Write-Output "SUCCESS"
'''
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False) as f:
                script_path = f.name
                f.write(ps_script)
            
            cmd = f'powershell -ExecutionPolicy Bypass -File "{script_path}"'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=60)
            
            os.unlink(script_path)
            
            success = 'SUCCESS' in result.stdout
            
            if success:
                logger.info("✅ System restore point created")
            else:
                logger.error(f"❌ Failed to create restore point: {result.stderr}")
            
            return success
            
        except Exception as e:
            logger.error(f"❌ Error creating restore point: {e}")
            return False
    
    async def apply_fix(self, vulnerability: Dict) -> Dict:
        """
        Apply fix for a vulnerability
        Returns: {success: bool, command: str, output: str, error: str}
        """
        category = vulnerability['category']
        title = vulnerability['title']
        
        logger.info(f"🔧 Applying fix: {title}")
        
        try:
            # Route to appropriate fixer
            if 'Firewall' in category:
                return await self._fix_firewall(vulnerability)
            elif 'Windows Update' in category:
                return await self._fix_windows_update(vulnerability)
            elif 'User Account Control' in category or 'UAC' in title:
                return await self._fix_uac(vulnerability)
            elif 'Remote Desktop' in category or 'RDP' in title:
                return await self._fix_rdp(vulnerability)
            elif 'Network' in category:
                return await self._fix_network(vulnerability)
            elif 'SMB' in title:
                return await self._fix_smb(vulnerability)
            elif 'PowerShell' in title:
                return await self._fix_powershell_policy(vulnerability)
            else:
                return {
                    'success': False,
                    'command': None,
                    'output': None,
                    'error': 'No automated fix available for this vulnerability type'
                }
        
        except Exception as e:
            logger.error(f"❌ Fix failed: {e}")
            return {
                'success': False,
                'command': None,
                'output': None,
                'error': str(e)
            }
    
    async def _fix_firewall(self, vulnerability: Dict) -> Dict:
        """Fix firewall issues"""
        title = vulnerability['title']
        
        if 'DomainProfile' in title:
            cmd = 'netsh advfirewall set domainprofile state on'
        elif 'PrivateProfile' in title:
            cmd = 'netsh advfirewall set privateprofile state on'
        elif 'PublicProfile' in title:
            cmd = 'netsh advfirewall set publicprofile state on'
        else:
            cmd = 'netsh advfirewall set allprofiles state on'
        
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=15)
        
        return {
            'success': result.returncode == 0,
            'command': cmd,
            'output': result.stdout,
            'error': result.stderr if result.returncode != 0 else None
        }
    
    async def _fix_windows_update(self, vulnerability: Dict) -> Dict:
        """Fix Windows Update service"""
        if 'Service' in vulnerability['title']:
            cmd = 'sc config wuauserv start=auto && sc start wuauserv'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=20)
            
            return {
                'success': result.returncode == 0 or 'already running' in result.stdout.lower(),
                'command': cmd,
                'output': result.stdout,
                'error': result.stderr if result.returncode != 0 else None
            }
        else:
            # Can't auto-install updates, just return instructions
            return {
                'success': False,
                'command': None,
                'output': 'Please run Windows Update manually from Settings',
                'error': 'Automatic update installation requires user interaction'
            }
    
    async def _fix_uac(self, vulnerability: Dict) -> Dict:
        """Fix UAC settings"""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
                0,
                winreg.KEY_SET_VALUE
            )
            
            winreg.SetValueEx(key, 'ConsentPromptBehaviorAdmin', 0, winreg.REG_DWORD, 2)
            winreg.SetValueEx(key, 'PromptOnSecureDesktop', 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
            
            return {
                'success': True,
                'command': 'Registry modification',
                'output': 'UAC enabled (restart required)',
                'error': None
            }
        except Exception as e:
            return {
                'success': False,
                'command': 'Registry modification',
                'output': None,
                'error': str(e)
            }
    
    async def _fix_rdp(self, vulnerability: Dict) -> Dict:
        """Disable RDP"""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r'SYSTEM\CurrentControlSet\Control\Terminal Server',
                0,
                winreg.KEY_SET_VALUE
            )
            
            winreg.SetValueEx(key, 'fDenyTSConnections', 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
            
            return {
                'success': True,
                'command': 'Registry modification',
                'output': 'Remote Desktop disabled',
                'error': None
            }
        except Exception as e:
            return {
                'success': False,
                'command': 'Registry modification',
                'output': None,
                'error': str(e)
            }
    
    async def _fix_network(self, vulnerability: Dict) -> Dict:
        """Fix network issues"""
        title = vulnerability['title']
        
        if 'Network Discovery' in title:
            cmd = 'netsh advfirewall firewall set rule group="Network Discovery" new enable=No'
        elif 'File and Printer Sharing' in title:
            cmd = 'netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No'
        elif 'Risky Port' in title:
            # Extract port number
            import re
            match = re.search(r'port (\d+)', title.lower())
            if match:
                port = match.group(1)
                cmd = f'netsh advfirewall firewall add rule name="RAVEN-X Block {port}" dir=in action=block protocol=TCP localport={port}'
            else:
                return {'success': False, 'command': None, 'output': None, 'error': 'Could not extract port number'}
        else:
            return {'success': False, 'command': None, 'output': None, 'error': 'Unknown network issue'}
        
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=15)
        
        return {
            'success': result.returncode == 0,
            'command': cmd,
            'output': result.stdout,
            'error': result.stderr if result.returncode != 0 else None
        }
    
    async def _fix_smb(self, vulnerability: Dict) -> Dict:
        """Disable SMBv1"""
        cmd = 'powershell "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"'
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=20)
        
        return {
            'success': result.returncode == 0,
            'command': cmd,
            'output': result.stdout,
            'error': result.stderr if result.returncode != 0 else None
        }
    
    async def _fix_powershell_policy(self, vulnerability: Dict) -> Dict:
        """Fix PowerShell execution policy"""
        cmd = 'powershell "Set-ExecutionPolicy Restricted -Force"'
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=15)
        
        return {
            'success': result.returncode == 0,
            'command': cmd,
            'output': result.stdout,
            'error': result.stderr if result.returncode != 0 else None
        }
    
    async def rollback_fix(self, fix: 'Fix') -> Dict:
        """
        Attempt to rollback a fix
        """
        logger.info(f"🔄 Attempting rollback of fix {fix.id}")
        
        # In production, would store original state and restore it
        # For now, just return a message
        
        return {
            'success': False,
            'error': 'Rollback functionality requires system restore point. Use Windows System Restore.'
        }


# Global auto-fixer instance
auto_fixer = AutoFixer()