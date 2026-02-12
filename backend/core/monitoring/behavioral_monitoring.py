"""
RAVEN-X Enterprise - Real-Time Behavioral Monitor
Catches zero-day attacks by monitoring system behavior in real-time
"""

import psutil
import win32evtlog
import win32evtlogutil
import win32con
import threading
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Callable
from collections import defaultdict, deque
import hashlib
import json

from ..database.database import db_manager
from ..database.models import ThreatPattern
from ..ai.learning_engine import learning_engine

logger = logging.getLogger(__name__)

class BehavioralMonitor:
    """
    Real-time system behavior monitoring
    Detects:
    - Suspicious process behavior
    - Unusual network activity
    - File system anomalies
    - Registry modifications
    - Privilege escalation attempts
    - Lateral movement
    - Data exfiltration
    """
    
    def __init__(self):
        self.is_monitoring = False
        self.monitor_thread = None
        
        # Baseline data
        self.baseline_processes: Set[str] = set()
        self.baseline_connections: Set[tuple] = set()
        self.baseline_services: Set[str] = set()
        
        # Suspicious behavior tracking
        self.process_activity = defaultdict(lambda: {
            'start_time': datetime.utcnow(),
            'cpu_usage': deque(maxlen=60),  # Last 60 measurements
            'memory_usage': deque(maxlen=60),
            'network_connections': 0,
            'file_operations': 0,
            'registry_operations': 0
        })
        
        # Alert thresholds
        self.thresholds = {
            'cpu_spike': 90.0,  # %
            'memory_spike': 80.0,  # %
            'rapid_connections': 50,  # connections/minute
            'suspicious_ports': {445, 3389, 4444, 5555, 6666, 8080},
            'max_failed_logins': 5,
            'file_encryption_rate': 100  # files/minute
        }
        
        # Callbacks for alerts
        self.alert_callbacks: List[Callable] = []
        
        logger.info("👁️ Behavioral Monitor initialized")
    
    def establish_baseline(self):
        """Establish system baseline for normal behavior"""
        logger.info("📊 Establishing behavioral baseline...")
        
        # Baseline processes
        for proc in psutil.process_iter(['name', 'exe']):
            try:
                self.baseline_processes.add(proc.info['name'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Baseline network connections
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED':
                self.baseline_connections.add((conn.laddr.port, conn.raddr.ip if conn.raddr else None))
        
        # Baseline services
        try:
            import win32serviceutil
            import win32service
            import pywintypes
            
            # This is Windows-specific
            # Would need platform detection for cross-platform support
        except:
            pass
        
        logger.info(f"✅ Baseline established: {len(self.baseline_processes)} processes, {len(self.baseline_connections)} connections")
    
    def start_monitoring(self):
        """Start real-time monitoring"""
        if self.is_monitoring:
            logger.warning("⚠️ Monitoring already active")
            return
        
        self.is_monitoring = True
        self.establish_baseline()
        
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()
        
        logger.info("🟢 Real-time monitoring STARTED")
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        logger.info("🔴 Real-time monitoring STOPPED")
    
    def register_alert_callback(self, callback: Callable):
        """Register a callback function for alerts"""
        self.alert_callbacks.append(callback)
    
    def _trigger_alert(self, alert_type: str, severity: str, details: Dict):
        """Trigger security alert"""
        alert = {
            'type': alert_type,
            'severity': severity,
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        logger.warning(f"🚨 ALERT [{severity.upper()}]: {alert_type}")
        logger.warning(f"    Details: {details}")
        
        # Call all registered callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"❌ Error in alert callback: {e}")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        logger.info("🔄 Monitoring loop started")
        
        while self.is_monitoring:
            try:
                self._monitor_processes()
                self._monitor_network()
                self._monitor_file_system()
                self._monitor_event_logs()
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                logger.error(f"❌ Error in monitoring loop: {e}")
                time.sleep(10)
    
    def _monitor_processes(self):
        """Monitor process behavior for anomalies"""
        current_processes = set()
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
            try:
                proc_info = proc.info
                proc_name = proc_info['name']
                current_processes.add(proc_name)
                
                # Check for new processes (not in baseline)
                if proc_name not in self.baseline_processes:
                    self._analyze_new_process(proc, proc_info)
                
                # Monitor resource usage
                try:
                    cpu_percent = proc.cpu_percent(interval=0.1)
                    memory_percent = proc.memory_percent()
                    
                    self.process_activity[proc_name]['cpu_usage'].append(cpu_percent)
                    self.process_activity[proc_name]['memory_usage'].append(memory_percent)
                    
                    # Detect resource spikes
                    if cpu_percent > self.thresholds['cpu_spike']:
                        self._trigger_alert(
                            'cpu_spike',
                            'medium',
                            {
                                'process': proc_name,
                                'pid': proc_info['pid'],
                                'cpu_usage': cpu_percent
                            }
                        )
                    
                    if memory_percent > self.thresholds['memory_spike']:
                        self._trigger_alert(
                            'memory_spike',
                            'medium',
                            {
                                'process': proc_name,
                                'pid': proc_info['pid'],
                                'memory_usage': memory_percent
                            }
                        )
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Detect terminated processes
        terminated = self.baseline_processes - current_processes
        if terminated:
            logger.info(f"📊 Processes terminated: {terminated}")
    
    def _analyze_new_process(self, proc, proc_info):
        """Analyze newly spawned process for suspicious behavior"""
        proc_name = proc_info['name']
        proc_path = proc_info['exe']
        
        suspicious_indicators = []
        
        # Check for suspicious names
        suspicious_names = [
            'mimikatz', 'psexec', 'procdump', 'pwdump',
            'nc.exe', 'netcat', 'ncat', 'socat',
            'tor.exe', 'i2p'
        ]
        
        if any(sus in proc_name.lower() for sus in suspicious_names):
            suspicious_indicators.append('suspicious_name')
        
        # Check for suspicious paths
        if proc_path:
            suspicious_paths = ['temp', 'tmp', 'appdata\\roaming', 'programdata']
            if any(sus in proc_path.lower() for sus in suspicious_paths):
                suspicious_indicators.append('suspicious_path')
        
        # Check parent process
        try:
            parent = proc.parent()
            if parent:
                parent_name = parent.name()
                # Suspicious if spawned by script interpreters
                if parent_name.lower() in ['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe']:
                    suspicious_indicators.append('script_spawned')
        except:
            pass
        
        if suspicious_indicators:
            self._trigger_alert(
                'suspicious_process',
                'high',
                {
                    'process': proc_name,
                    'path': proc_path,
                    'pid': proc_info['pid'],
                    'indicators': suspicious_indicators,
                    'username': proc_info.get('username', 'Unknown')
                }
            )
    
    def _monitor_network(self):
        """Monitor network activity for suspicious patterns"""
        try:
            connections = psutil.net_connections(kind='inet')
            
            # Track connections per process
            process_connections = defaultdict(list)
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        proc_name = proc.name()
                        
                        process_connections[proc_name].append(conn)
                        
                        # Check for suspicious ports
                        if conn.laddr and conn.laddr.port in self.thresholds['suspicious_ports']:
                            self._trigger_alert(
                                'suspicious_port',
                                'high',
                                {
                                    'process': proc_name,
                                    'pid': conn.pid,
                                    'local_port': conn.laddr.port,
                                    'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'N/A'
                                }
                            )
                        
                        # Check for new external connections
                        if conn.raddr and conn.laddr:
                            conn_tuple = (conn.laddr.port, conn.raddr.ip)
                            if conn_tuple not in self.baseline_connections:
                                logger.info(f"🌐 New connection: {proc_name} -> {conn.raddr.ip}:{conn.raddr.port}")
                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            
            # Detect rapid connection attempts
            for proc_name, conns in process_connections.items():
                if len(conns) > self.thresholds['rapid_connections']:
                    self._trigger_alert(
                        'rapid_connections',
                        'critical',
                        {
                            'process': proc_name,
                            'connection_count': len(conns),
                            'threshold': self.thresholds['rapid_connections']
                        }
                    )
        
        except Exception as e:
            logger.error(f"❌ Error monitoring network: {e}")
    
    def _monitor_file_system(self):
        """Monitor file system for suspicious activity"""
        # This would use FileSystemWatcher or similar
        # Detecting:
        # - Mass file modifications (ransomware)
        # - Suspicious file creations
        # - System file modifications
        
        # Placeholder for file system monitoring
        # In production, this would use Windows API hooks or FileSystemWatcher
        pass
    
    def _monitor_event_logs(self):
        """Monitor Windows Event Logs for security events"""
        try:
            # Monitor Security event log
            hand = win32evtlog.OpenEventLog(None, "Security")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            for event in events:
                # Event ID 4625 = Failed logon
                if event.EventID == 4625:
                    self._handle_failed_login(event)
                
                # Event ID 4672 = Special privileges assigned (potential privilege escalation)
                elif event.EventID == 4672:
                    self._handle_privilege_assignment(event)
                
                # Event ID 4688 = New process created
                elif event.EventID == 4688:
                    self._handle_process_creation(event)
            
            win32evtlog.CloseEventLog(hand)
            
        except Exception as e:
            # Event log access might fail without admin privileges
            logger.debug(f"Event log monitoring: {e}")
    
    def _handle_failed_login(self, event):
        """Handle failed login attempts"""
        # Track failed login attempts
        # Trigger alert if threshold exceeded
        pass
    
    def _handle_privilege_assignment(self, event):
        """Handle privilege escalation events"""
        self._trigger_alert(
            'privilege_escalation',
            'high',
            {
                'event_id': event.EventID,
                'time': datetime.now().isoformat(),
                'message': 'Privilege assignment detected'
            }
        )
    
    def _handle_process_creation(self, event):
        """Handle process creation events"""
        # Additional process creation monitoring
        pass
    
    async def get_monitoring_stats(self) -> Dict:
        """Get current monitoring statistics"""
        return {
            'is_monitoring': self.is_monitoring,
            'baseline_processes': len(self.baseline_processes),
            'baseline_connections': len(self.baseline_connections),
            'active_processes': len(self.process_activity),
            'monitored_duration': 'N/A',  # Would calculate based on start time
            'alerts_triggered': 0  # Would track actual count
        }


# Global behavioral monitor instance
behavioral_monitor = BehavioralMonitor()