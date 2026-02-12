"""
RAVEN-X Enterprise - FastAPI Backend
The brain surgery begins HERE!
"""

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from contextlib import asynccontextmanager
import logging
from datetime import datetime
from typing import List, Optional
import uvicorn
import yaml
from pathlib import Path

from ..core.database.database import db_manager, get_async_db_session
from ..core.ai.learning_engine import learning_engine
from ..core.monitoring.behavioral_monitor import behavioral_monitor

# API Routers
from .v1 import scan, analysis, remediation, reports, system

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load config
with open('config/config.yaml', 'r') as f:
    config = yaml.safe_load(f)

# Lifespan context manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    # Startup
    logger.info("🚀 RAVEN-X Enterprise API Starting...")
    
    # Initialize database
    await db_manager.create_tables_async()
    logger.info("✅ Database initialized")
    
    # Start behavioral monitoring
    if config['monitoring']['real_time_enabled']:
        behavioral_monitor.start_monitoring()
        logger.info("✅ Behavioral monitoring active")
    
    logger.info("🟢 RAVEN-X Enterprise API READY!")
    
    yield
    
    # Shutdown
    logger.info("🛑 Shutting down RAVEN-X Enterprise API...")
    behavioral_monitor.stop_monitoring()
    await db_manager.close_async()
    logger.info("✅ Shutdown complete")

# Create FastAPI app
app = FastAPI(
    title="RAVEN-X Enterprise Security Platform",
    description="AI-Powered Windows Vulnerability Scanner & Auto-Remediation Engine",
    version="4.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(scan.router, prefix="/api/v1/scan", tags=["Scanning"])
app.include_router(analysis.router, prefix="/api/v1/analysis", tags=["AI Analysis"])
app.include_router(remediation.router, prefix="/api/v1/remediation", tags=["Remediation"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])
app.include_router(system.router, prefix="/api/v1/system", tags=["System"])

# WebSocket for real-time updates
active_connections: List[WebSocket] = []

@app.websocket("/ws/realtime")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    await websocket.accept()
    active_connections.append(websocket)
    
    try:
        while True:
            # Keep connection alive
            data = await websocket.receive_text()
            
            # Echo back for now (would send real-time scan updates)
            await websocket.send_json({
                "type": "ping",
                "timestamp": datetime.utcnow().isoformat()
            })
    except WebSocketDisconnect:
        active_connections.remove(websocket)
        logger.info("WebSocket disconnected")

async def broadcast_update(message: dict):
    """Broadcast update to all connected WebSocket clients"""
    for connection in active_connections:
        try:
            await connection.send_json(message)
        except:
            pass

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "RAVEN-X Enterprise Security Platform",
        "version": "4.0.0",
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat(),
        "endpoints": {
            "docs": "/api/docs",
            "health": "/health",
            "scan": "/api/v1/scan",
            "analysis": "/api/v1/analysis",
            "remediation": "/api/v1/remediation",
            "reports": "/api/v1/reports",
            "system": "/api/v1/system"
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {
            "database": "operational",
            "ai_engine": "operational",
            "behavioral_monitor": "active" if behavioral_monitor.is_monitoring else "inactive"
        }
    }

@app.get("/api/v1/stats")
async def get_platform_stats():
    """Get overall platform statistics"""
    learning_stats = await learning_engine.get_learning_stats()
    monitoring_stats = await behavioral_monitor.get_monitoring_stats()
    
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "learning": learning_stats,
        "monitoring": monitoring_stats,
        "uptime": "N/A"  # Would calculate actual uptime
    }

if __name__ == "__main__":
    # Run the API server
    server_config = config.get('server', {})
    
    uvicorn.run(
        "backend.api.main:app",
        host=server_config.get('host', '0.0.0.0'),
        port=server_config.get('port', 8000),
        reload=server_config.get('reload', False),
        workers=server_config.get('workers', 4),
        log_level=server_config.get('log_level', 'info')
    )