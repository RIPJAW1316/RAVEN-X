"""
RAVEN-X Enterprise - System Monitoring API
Real-time system monitoring and control
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, List
import psutil
import platform
import socket
from datetime import datetime

from ..core.monitoring.behavioral_monitoring import behavioral_monitor

router = APIRouter()

class SystemMetrics(BaseModel):
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    network_sent_mb: float
    network_recv_mb: float
    active_processes: int
    uptime_seconds: float

@router.get("/metrics", response_model=SystemMetrics)
async def get_system_metrics():
    """
    Get current system metrics
    """
    try:
        # CPU
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Memory
        mem = psutil.virtual_memory()
        memory_percent = mem.percent
        
        # Disk
        disk = psutil.disk_usage('/')
        disk_percent = disk.percent
        
        # Network
        net_io = psutil.net_io_counters()
        network_sent_mb = net_io.bytes_sent / (1024**2)
        network_recv_mb = net_io.bytes_recv / (1024**2)
        
        # Processes
        active_processes = len(psutil.pids())
        
        # Uptime
        boot_time = psutil.boot_time()
        uptime_seconds = datetime.now().timestamp() - boot_time
        
        return SystemMetrics(
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            disk_percent=disk_percent,
            network_sent_mb=round(network_sent_mb, 2),
            network_recv_mb=round(network_recv_mb, 2),
            active_processes=active_processes,
            uptime_seconds=uptime_seconds
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/info")
async def get_system_info():
    """
    Get detailed system information
    """
    try:
        return {
            'os': platform.system(),
            'os_version': platform.version(),
            'os_release': platform.release(),
            'architecture': platform.architecture()[0],
            'hostname': socket.gethostname(),
            'processor': platform.processor(),
            'cpu_cores': psutil.cpu_count(logical=True),
            'cpu_physical_cores': psutil.cpu_count(logical=False),
            'total_ram_gb': round(psutil.virtual_memory().total / (1024**3), 2),
            'total_disk_gb': round(psutil.disk_usage('/').total / (1024**3), 2),
            'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/processes")
async def get_processes(limit: int = 50):
    """
    Get running processes
    """
    try:
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
            try:
                processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'username': proc.info['username'],
                    'cpu_percent': proc.info['cpu_percent'],
                    'memory_percent': round(proc.info['memory_percent'], 2)
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Sort by CPU usage
        processes.sort(key=lambda x: x['cpu_percent'] or 0, reverse=True)
        
        return {
            'processes': processes[:limit],
            'total': len(processes)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/network/connections")
async def get_network_connections():
    """
    Get active network connections
    """
    try:
        connections = []
        
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED':
                connections.append({
                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else 'N/A',
                    'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'N/A',
                    'status': conn.status,
                    'pid': conn.pid
                })
        
        return {
            'connections': connections,
            'total': len(connections)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/monitoring/start")
async def start_behavioral_monitoring():
    """
    Start real-time behavioral monitoring
    """
    try:
        if behavioral_monitor.is_monitoring:
            return {
                'status': 'already_running',
                'message': 'Behavioral monitoring is already active'
            }
        
        behavioral_monitor.start_monitoring()
        
        return {
            'status': 'started',
            'message': 'Behavioral monitoring started successfully'
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/monitoring/stop")
async def stop_behavioral_monitoring():
    """
    Stop real-time behavioral monitoring
    """
    try:
        if not behavioral_monitor.is_monitoring:
            return {
                'status': 'not_running',
                'message': 'Behavioral monitoring is not active'
            }
        
        behavioral_monitor.stop_monitoring()
        
        return {
            'status': 'stopped',
            'message': 'Behavioral monitoring stopped'
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/monitoring/status")
async def get_monitoring_status():
    """
    Get monitoring status
    """
    stats = await behavioral_monitor.get_monitoring_stats()
    
    return {
        'is_active': behavioral_monitor.is_monitoring,
        'stats': stats
    }

@router.get("/health")
async def system_health_check():
    """
    Overall system health check
    """
    try:
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        health_status = 'healthy'
        issues = []
        
        if cpu > 90:
            health_status = 'warning'
            issues.append('High CPU usage')
        
        if mem.percent > 90:
            health_status = 'warning'
            issues.append('High memory usage')
        
        if disk.percent > 90:
            health_status = 'critical'
            issues.append('Low disk space')
        
        return {
            'status': health_status,
            'issues': issues,
            'metrics': {
                'cpu_percent': cpu,
                'memory_percent': mem.percent,
                'disk_percent': disk.percent
            },
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
