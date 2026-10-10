"""
RAVEN-X Enterprise - Master Launcher
ONE SCRIPT TO START EVERYTHING!

Usage:
    python run.py --mode all          # Start everything
    python run.py --mode backend      # Backend only
    python run.py --mode gui          # GUI only
    python run.py --mode setup        # First-time setup
"""

import subprocess
import sys
import os
import time
import argparse
import logging
from pathlib import Path
import yaml

# ASCII Art Banner
BANNER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ██████╗  █████╗ ██╗   ██╗███████╗███╗   ██╗      ██╗  ██╗                  ║
║   ██╔══██╗██╔══██╗██║   ██║██╔════╝████╗  ██║      ╚██╗██╔╝                  ║
║   ██████╔╝███████║██║   ██║█████╗  ██╔██╗ ██║       ╚███╔╝                   ║
║   ██╔══██╗██╔══██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║       ██╔██╗                   ║
║   ██║  ██║██║  ██║ ╚████╔╝ ███████╗██║ ╚████║      ██╔╝ ██╗                  ║
║   ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝      ╚═╝  ╚═╝                  ║
║                                                                              ║
║                    ENTERPRISE SECURITY PLATFORM v4.0                         ║
║                  AI-Powered Vulnerability Scanner & Fixer                    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

[*] Initializing RAVEN-X Enterprise...
"""

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class RAVENXLauncher:
    """
    Master launcher for RAVEN-X Enterprise
    """
    
    def __init__(self):
        self.root_dir = Path(__file__).parent
        self.backend_dir = self.root_dir / "backend"
        self.frontend_dir = self.root_dir / "frontend"
        self.config_dir = self.root_dir / "config"
        self.data_dir = self.root_dir / "data"
        
        self.processes = []
    
    def check_python_version(self):
        """Check Python version"""
        logger.info("🐍 Checking Python version...")
        
        if sys.version_info < (3, 8):
            logger.error("❌ Python 3.8+ required!")
            logger.error(f"   Current version: {sys.version}")
            sys.exit(1)
        
        logger.info(f"✅ Python {sys.version.split()[0]} - OK")
    
    def check_dependencies(self):
        """Check if all dependencies are installed"""
        logger.info("📦 Checking dependencies...")
        
        required_packages = [
            ('fastapi','fastapi'), ('uvicorn','uvicorn'), ('sqlalchemy','sqlalchemy'), ('pydantic','pydantic'),
            ('customtkinter','customtkinter'), ('psutil','psutil'), ('openai','openai'), ('scikit-learn','sklearn'),
            ('jinja2','jinja2'), ('requests','requests'), ('websockets','websockets'), ('pyyaml','yaml')
        ]
        
        missing = []
        
        for package, import_name in required_packages:
            try:
                __import__(import_name)
            except ImportError:
                missing.append(package)
        
        if missing:
            logger.warning(f"⚠️  Missing packages: {', '.join(missing)}")
            logger.info("📥 Installing missing packages...")
            
            subprocess.run(
                [sys.executable, "-m", "pip", "install"] + missing,
                check=True
            )
            
            logger.info("✅ All dependencies installed")
        else:
            logger.info("✅ All dependencies satisfied")
    
    def setup_directories(self):
        """Create necessary directories"""
        logger.info("📁 Setting up directories...")
        
        directories = [
            self.data_dir,
            self.data_dir / "reports",
            self.data_dir / "logs",
            self.root_dir / "ml_models",
            self.root_dir / "ml_models" / "malware_classifier",
            self.root_dir / "ml_models" / "anomaly_detector",
            self.root_dir / "ml_models" / "threat_patterns",
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
        
        logger.info("✅ Directories created")
    
    def initialize_database(self):
        """Initialize database"""
        logger.info("🗄️  Initializing database...")
        
        try:
            # Import and run database initialization
            sys.path.insert(0, str(self.root_dir))
            
            from backend.core.database.database import db_manager
            
            db_manager.initialize_sync_engine()
            db_manager.create_tables()
            
            logger.info("✅ Database initialized")
            
        except Exception as e:
            logger.error("❌ Database initialization failed error_type=%s", type(e).__name__)
            sys.exit(1)
    
    def start_backend(self):
        """Start FastAPI backend"""
        logger.info("🚀 Starting backend API server...")
        
        backend_cmd = [
            sys.executable,
            "-m", "uvicorn",
            "backend.api.main:app",
            "--host", "127.0.0.1",
            "--port", "8000"
        ]
        
        # This launcher is the legacy/personal entry point: the bundled GUI and
        # the older desktop workflow call /api/v1/scan, /analysis, /remediation
        # and /system.  Those routers are off by default in the enterprise
        # control plane, so opt in explicitly here to preserve the historical
        # behaviour of `python run.py`.  Keep this unauthenticated legacy API
        # on loopback only; a LAN control plane uses the separate enterprise
        # launcher with legacy routes disabled.
        backend_env = dict(os.environ)
        backend_env.setdefault("RAVENX_ENVIRONMENT", "development")
        backend_env.setdefault("RAVENX_ENABLE_LEGACY_ROUTES", "true")

        backend_process = subprocess.Popen(
            backend_cmd,
            cwd=self.root_dir,
            env=backend_env,
            stdout=None,
            stderr=None
        )
        
        self.processes.append(backend_process)
        
        # Wait for backend to start
        time.sleep(3)
        
        # Check if backend is running
        from urllib.request import urlopen
        try:
            with urlopen("http://127.0.0.1:8000/health", timeout=5) as response:
                healthy = response.status == 200
            if healthy:
                logger.info("✅ Backend API running on http://localhost:8000")
                logger.info("📖 API Docs: http://localhost:8000/api/docs")
            else:
                logger.warning("⚠️  Backend started but health check failed")
        except Exception:
            logger.warning("⚠️  Backend starting... (may take a moment)")
    
    def start_gui(self):
        """Start GUI application"""
        logger.info("🖥️  Starting GUI application...")
        
        # Try multiple possible locations for the scanner
        possible_locations = [
            self.root_dir / "scanner.py",  # Original location
            self.backend_dir / "core" / "scanner" / "enhanced_scanner.py",  # Backend location
        ]
        
        gui_script = None
        for location in possible_locations:
            if location.exists():
                gui_script = location
                logger.info(f"   Found scanner at: {location}")
                break
        
        if gui_script:
            # For enhanced_scanner.py, we need to run it as a module
            if "enhanced_scanner" in str(gui_script):
                # Run as Python module
                gui_cmd = [
                    sys.executable, 
                    "-c",
                    "import sys; sys.path.insert(0, '.'); from backend.core.scanner.enhanced_scanner import EnhancedScanner; scanner = EnhancedScanner(); print('Enhanced Scanner loaded')"
                ]
            else:
                gui_cmd = [sys.executable, str(gui_script)]
            
            gui_process = subprocess.Popen(
                gui_cmd,
                cwd=self.root_dir
            )
            
            self.processes.append(gui_process)
            logger.info("✅ GUI application started")
        else:
            logger.error("❌ Scanner not found!")
            logger.info("💡 Searched in:")
            for loc in possible_locations:
                logger.info(f"   - {loc}")
            logger.info("\n💡 Please ensure scanner.py or enhanced_scanner.py is available")
    
    def start_all(self):
        """Start everything"""
        print(BANNER)
        
        logger.info("🔧 Running pre-flight checks...")
        self.check_python_version()
        self.check_dependencies()
        self.setup_directories()
        self.initialize_database()
        
        logger.info("\n" + "="*80)
        logger.info("🚀 LAUNCHING RAVEN-X ENTERPRISE")
        logger.info("="*80 + "\n")
        
        # Start backend
        self.start_backend()
        
        # Wait a bit
        time.sleep(2)
        
        # Start GUI
        self.start_gui()
        
        logger.info("\n" + "="*80)
        logger.info("✅ RAVEN-X ENTERPRISE IS NOW RUNNING!")
        logger.info("="*80)
        logger.info("")
        logger.info("🌐 Backend API: http://localhost:8000")
        logger.info("📖 API Documentation: http://localhost:8000/api/docs")
        logger.info("🖥️  GUI: Running in separate window")
        logger.info("")
        logger.info("Press Ctrl+C to stop all services")
        logger.info("")
        
        # Keep running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("\n🛑 Shutting down RAVEN-X Enterprise...")
            self.cleanup()
    
    def cleanup(self):
        """Clean up processes"""
        for process in self.processes:
            try:
                process.terminate()
                process.wait(timeout=5)
            except:
                process.kill()
        
        logger.info("✅ All services stopped. Goodbye!")
    
    def first_time_setup(self):
        """First-time setup wizard"""
        print(BANNER)
        print("\n🎉 Welcome to RAVEN-X Enterprise Setup Wizard!\n")
        
        logger.info("Running first-time setup...")
        
        # Check system
        self.check_python_version()
        
        # Install dependencies
        logger.info("\n📥 Installing dependencies...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
            check=True
        )
        
        # Setup directories
        self.setup_directories()
        
        # Initialize database
        self.initialize_database()
        
        # Create config if not exists
        config_file = self.config_dir / "config.yaml"
        if not config_file.exists():
            logger.info("📝 Creating default configuration...")
            
            default_config = """
# RAVEN-X Enterprise Configuration
application:
  name: "RAVEN-X Enterprise Security Platform"
  version: "4.0.0"
  environment: "production"

server:
  host: "127.0.0.1"
  port: 8000
  workers: 1

database:
  type: "sqlite"
  sqlite_path: "data/raven_x.db"

ai:
  lm_studio:
    url: "http://localhost:1234/v1"
    model: "llama-3.1-8b-instruct-q4_k_m"
    timeout: 120
    max_tokens: 4000
    temperature: 0.7

scanning:
  default_scan_type: "full"
  max_concurrent_scans: 3

monitoring:
  real_time_enabled: true
  behavioral_analysis: true
"""
            
            with open(config_file, 'w') as f:
                f.write(default_config)
            
            logger.info(f"✅ Config created: {config_file}")
        
        print("\n" + "="*80)
        print("✅ SETUP COMPLETE!")
        print("="*80)
        print("\nNext steps:")
        print("1. Configure LM Studio (if using AI features)")
        print("2. Review config/config.yaml")
        print("3. Run: python run.py --mode all")
        print("\n🚀 Ready to scan!")


def main():
    parser = argparse.ArgumentParser(
        description="RAVEN-X Enterprise Security Platform Launcher"
    )
    
    parser.add_argument(
        '--mode',
        choices=['all', 'backend', 'gui', 'setup'],
        default='all',
        help='Launch mode'
    )
    
    args = parser.parse_args()
    
    launcher = RAVENXLauncher()
    
    if args.mode == 'setup':
        launcher.first_time_setup()
    elif args.mode == 'all':
        launcher.start_all()
    elif args.mode == 'backend':
        launcher.start_backend()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            launcher.cleanup()
    elif args.mode == 'gui':
        launcher.start_gui()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            launcher.cleanup()


if __name__ == "__main__":
    main()
