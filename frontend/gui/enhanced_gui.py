"""
RAVEN-X Enterprise - Enhanced GUI with Backend Integration
Your existing GUI + REST API integration + Real-time updates
"""

import customtkinter as ctk
from tkinter import messagebox, filedialog
import requests
import asyncio
import json
import threading
from datetime import datetime
from typing import Dict, List, Optional
import logging
import sys
from pathlib import Path

# Add parent directory to path for imports
ROOT_DIR = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))

# NOW import backend modules
try:
    from backend.core.scanner.enhanced_scanner import EnhancedScanner
    from backend.core.database.database import db_manager
    BACKEND_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Backend modules not available: {e}")
    BACKEND_AVAILABLE = False
    # We'll define a fallback scanner

logger = logging.getLogger(__name__)

# Import your existing scanner
import sys
sys.path.append('../..')
from backend.core.scanner.enhanced_scanner import EnhancedScanner
from backend.core.database.database import db_manager

logger = logging.getLogger(__name__)

class EnhancedGUI:
    """
    Enhanced GUI with full backend integration
    """
    
    def __init__(self):
        # API Configuration
        self.api_base_url = "http://localhost:8000/api/v1"
        self.ws_url = "ws://localhost:8000/ws/realtime"
        
        # Your existing GUI code here
        # ... (All your current GUI code from scanner.py)
        
        # Add new methods for API integration
        self.setup_api_integration()
    
    def setup_api_integration(self):
        """
        Setup API integration
        """
        # Test API connection
        try:
            response = requests.get(f"{self.api_base_url}/../..", timeout=5)
            if response.status_code == 200:
                logger.info("✅ Connected to RAVEN-X backend API")
                self.api_connected = True
            else:
                logger.warning("⚠️ Backend API not responding")
                self.api_connected = False
        except:
            logger.warning("⚠️ Backend API not available - running in standalone mode")
            self.api_connected = False
        
        # Start WebSocket connection for real-time updates
        if self.api_connected:
            threading.Thread(target=self.websocket_listener, daemon=True).start()
    
    def websocket_listener(self):
        """
        Listen for real-time updates via WebSocket
        """
        async def listen():
            try:
                async with websockets.connect(self.ws_url) as websocket:
                    logger.info("🔌 WebSocket connected")
                    
                    while True:
                        message = await websocket.recv()
                        data = json.loads(message)
                        
                        # Handle real-time updates
                        self.handle_realtime_update(data)
                        
            except Exception as e:
                logger.error(f"WebSocket error: {e}")
        
        asyncio.run(listen())
    
    def handle_realtime_update(self, data: Dict):
        """
        Handle real-time updates from backend
        """
        update_type = data.get('type')
        
        if update_type == 'scan_progress':
            self.update_scan_progress(data)
        elif update_type == 'alert':
            self.show_security_alert(data)
        elif update_type == 'anomaly_detected':
            self.handle_anomaly_alert(data)
    
    def start_scan_via_api(self):
        """
        Start scan using backend API
        """
        if not self.api_connected:
            # Fallback to local scanning
            self.start_scan()  # Your existing method
            return
        
        try:
            # Call API
            response = requests.post(
                f"{self.api_base_url}/scan/start",
                json={
                    "scan_type": "full",
                    "deep_scan": True,
                    "ai_analysis": True
                },
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                scan_id = data['scan_id']
                
                self.current_scan_id = scan_id
                self.status_label.configure(text=f"Scan started: {scan_id}")
                
                # Poll for results
                threading.Thread(
                    target=self.poll_scan_results,
                    args=(scan_id,),
                    daemon=True
                ).start()
            else:
                self.show_error(f"Scan failed: {response.text}")
                
        except Exception as e:
            logger.error(f"API scan failed: {e}")
            # Fallback to local scan
            self.start_scan()
    
    def poll_scan_results(self, scan_id: str):
        """
        Poll API for scan results
        """
        import time
        
        while True:
            try:
                response = requests.get(
                    f"{self.api_base_url}/scan/status/{scan_id}",
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    status = data['status']
                    
                    if status == 'completed':
                        # Get full results
                        self.load_scan_results_from_api(scan_id)
                        break
                    elif status == 'failed':
                        self.root.after(0, lambda: self.show_error("Scan failed"))
                        break
                
                time.sleep(5)  # Poll every 5 seconds
                
            except Exception as e:
                logger.error(f"Polling error: {e}")
                break
    
    def load_scan_results_from_api(self, scan_id: str):
        """
        Load complete scan results from API
        """
        try:
            response = requests.get(
                f"{self.api_base_url}/scan/results/{scan_id}",
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Convert API response to your existing format
                self.vulnerabilities = [
                    {
                        'severity': v['severity'],
                        'category': v['category'],
                        'title': v['title'],
                        'details': v['details'],
                        'component': v['component'],
                        'remediation': v['remediation']
                    }
                    for v in data['vulnerabilities']
                ]
                
                # Update UI
                self.root.after(0, self.display_results)
                
        except Exception as e:
            logger.error(f"Failed to load results: {e}")
    
    def get_ai_analysis_from_api(self):
        """
        Get AI analysis from backend
        """
        if not self.api_connected or not hasattr(self, 'current_scan_id'):
            # Fallback to local AI
            self.get_ai_analysis()  # Your existing method
            return
        
        try:
            # Request AI analysis
            response = requests.post(
                f"{self.api_base_url}/analysis/analyze",
                json={
                    "scan_id": self.current_scan_id,
                    "analysis_type": "comprehensive"
                },
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                analysis_id = data['analysis_id']
                
                self.status_label.configure(text="AI analysis in progress...")
                
                # Poll for analysis results
                threading.Thread(
                    target=self.poll_ai_analysis,
                    args=(analysis_id,),
                    daemon=True
                ).start()
            
        except Exception as e:
            logger.error(f"AI analysis request failed: {e}")
            self.get_ai_analysis()  # Fallback
    
    def poll_ai_analysis(self, analysis_id: str):
        """
        Poll for AI analysis completion
        """
        import time
        
        max_wait = 120  # 2 minutes
        waited = 0
        
        while waited < max_wait:
            try:
                response = requests.get(
                    f"{self.api_base_url}/analysis/result/{analysis_id}",
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    analysis_text = data['executive_summary'] + "\n\n" + str(data.get('recommendations', []))
                    
                    self.root.after(0, lambda: self.show_ai_analysis(analysis_text))
                    break
                
                time.sleep(5)
                waited += 5
                
            except Exception as e:
                logger.error(f"AI analysis polling error: {e}")
                break
    
    def export_report_via_api(self):
        """
        Generate report via API
        """
        if not self.api_connected or not hasattr(self, 'current_scan_id'):
            self.export_report()  # Fallback
            return
        
        # Ask user for format
        format_window = ctk.CTkToplevel(self.root)
        format_window.title("Export Report")
        format_window.geometry("400x300")
        
        ctk.CTkLabel(format_window, text="Select Report Format", font=("Segoe UI", 16, "bold")).pack(pady=20)
        
        format_var = ctk.StringVar(value="html")
        
        for fmt in ["HTML", "PDF", "JSON", "CSV", "DOCX"]:
            ctk.CTkRadioButton(
                format_window,
                text=fmt,
                variable=format_var,
                value=fmt.lower()
            ).pack(pady=5)
        
        def download_report():
            try:
                response = requests.get(
                    f"{self.api_base_url}/reports/download/{self.current_scan_id}/{format_var.get()}",
                    timeout=60
                )
                
                if response.status_code == 200:
                    # Save file
                    filename = filedialog.asksaveasfilename(
                        defaultextension=f".{format_var.get()}",
                        filetypes=[(f"{format_var.get().upper()} files", f"*.{format_var.get()}")]
                    )
                    
                    if filename:
                        with open(filename, 'wb') as f:
                            f.write(response.content)
                        
                        messagebox.showinfo("Success", f"Report saved to {filename}")
                        format_window.destroy()
                
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {e}")
        
        ctk.CTkButton(
            format_window,
            text="Download",
            command=download_report
        ).pack(pady=20)


# Run the enhanced GUI
if __name__ == "__main__":
    app = EnhancedGUI()
    app.run()