"""
RAVEN-X Enterprise - Scan API Endpoints
All scanning operations accessible via REST API
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from pydantic import BaseModel, Field
from typing import List, Optional, Dict
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
import uuid

from ...core.database.database import get_async_db_session
from ...core.database.models import Scan, Vulnerability
from ...core.scanner.enhanced_scanner import EnhancedScanner
from ...core.ai.learning_engine import learning_engine

router = APIRouter()

# Pydantic models
class ScanRequest(BaseModel):
    scan_type: str = Field(default="full", description="Scan type: full, quick, targeted")
    target_categories: Optional[List[str]] = Field(default=None, description="Specific categories to scan")
    deep_scan: bool = Field(default=True, description="Enable deep scanning")
    ai_analysis: bool = Field(default=True, description="Enable AI-powered analysis")

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str
    estimated_duration: Optional[int] = None

class VulnerabilityResponse(BaseModel):
    id: str
    severity: str
    category: str
    title: str
    details: str
    component: str
    remediation: Optional[str] = None
    discovered_at: str

class ScanResultResponse(BaseModel):
    scan_id: str
    scan_type: str
    start_time: str
    end_time: Optional[str] = None
    duration_seconds: Optional[float] = None
    status: str
    risk_score: float
    risk_level: str
    vulnerabilities: List[VulnerabilityResponse]
    summary: Dict

# Global scanner instance
scanner = EnhancedScanner()

@router.post("/start", response_model=ScanResponse)
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_async_db_session)
):
    """
    Start a new security scan
    """
    try:
        # Create scan record
        scan_id = str(uuid.uuid4())
        
        new_scan = Scan(
            id=scan_id,
            scan_type=request.scan_type,
            start_time=datetime.utcnow(),
            status="running",
            system_info=scanner.get_system_info()
        )
        
        db.add(new_scan)
        await db.commit()
        
        # Start scan in background
        background_tasks.add_task(
            execute_scan,
            scan_id=scan_id,
            scan_type=request.scan_type,
            target_categories=request.target_categories,
            deep_scan=request.deep_scan,
            ai_analysis=request.ai_analysis
        )
        
        estimated_duration = 300 if request.scan_type == "full" else 60
        
        return ScanResponse(
            scan_id=scan_id,
            status="started",
            message=f"Scan {scan_id} initiated successfully",
            estimated_duration=estimated_duration
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start scan: {str(e)}")

async def execute_scan(
    scan_id: str,
    scan_type: str,
    target_categories: Optional[List[str]],
    deep_scan: bool,
    ai_analysis: bool
):
    """
    Execute scan in background
    """
    try:
        async with db_manager.get_async_db() as db:
            # Get scan record
            stmt = select(Scan).where(Scan.id == scan_id)
            result = await db.execute(stmt)
            scan = result.scalar_one()
            
            # Execute scan
            vulnerabilities = await scanner.scan_all_async(
                scan_type=scan_type,
                target_categories=target_categories,
                deep_scan=deep_scan
            )
            
            # Save vulnerabilities
            for vuln_data in vulnerabilities:
                vuln = Vulnerability(
                    scan_id=scan_id,
                    severity=vuln_data['severity'],
                    category=vuln_data['category'],
                    title=vuln_data['title'],
                    details=vuln_data['details'],
                    component=vuln_data['component'],
                    remediation=vuln_data.get('remediation'),
                    signature=learning_engine.generate_threat_signature(vuln_data)
                )
                db.add(vuln)
            
            # Update scan record
            scan.end_time = datetime.utcnow()
            scan.duration_seconds = (scan.end_time - scan.start_time).total_seconds()
            scan.status = "completed"
            scan.total_vulnerabilities = len(vulnerabilities)
            
            # Calculate severity counts
            scan.critical_count = sum(1 for v in vulnerabilities if v['severity'] == 'critical')
            scan.high_count = sum(1 for v in vulnerabilities if v['severity'] == 'high')
            scan.medium_count = sum(1 for v in vulnerabilities if v['severity'] == 'medium')
            scan.low_count = sum(1 for v in vulnerabilities if v['severity'] == 'low')
            
            # Calculate risk score
            risk_score, risk_level = scanner.calculate_risk_score(vulnerabilities)
            scan.risk_score = risk_score
            scan.risk_level = risk_level
            
            await db.commit()
            
            # Learn from scan results
            if ai_analysis:
                await learning_engine.learn_from_scan(scan_id, vulnerabilities)
            
            logger.info(f"✅ Scan {scan_id} completed: {len(vulnerabilities)} vulnerabilities found")
            
    except Exception as e:
        logger.error(f"❌ Scan {scan_id} failed: {e}")
        
        # Update scan status to failed
        async with db_manager.get_async_db() as db:
            stmt = select(Scan).where(Scan.id == scan_id)
            result = await db.execute(stmt)
            scan = result.scalar_one_or_none()
            
            if scan:
                scan.status = "failed"
                scan.end_time = datetime.utcnow()
                await db.commit()

@router.get("/status/{scan_id}")
async def get_scan_status(
    scan_id: str,
    db: AsyncSession = Depends(get_async_db_session)
):
    """
    Get status of a specific scan
    """
    try:
        stmt = select(Scan).where(Scan.id == scan_id)
        result = await db.execute(stmt)
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        
        return {
            "scan_id": scan.id,
            "status": scan.status,
            "scan_type": scan.scan_type,
            "start_time": scan.start_time.isoformat(),
            "end_time": scan.end_time.isoformat() if scan.end_time else None,
            "duration_seconds": scan.duration_seconds,
            "vulnerabilities_found": scan.total_vulnerabilities,
            "risk_score": scan.risk_score,
            "risk_level": scan.risk_level
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/results/{scan_id}", response_model=ScanResultResponse)
async def get_scan_results(
    scan_id: str,
    db: AsyncSession = Depends(get_async_db_session)
):
    """
    Get complete results of a scan
    """
    try:
        # Get scan
        scan_stmt = select(Scan).where(Scan.id == scan_id)
        scan_result = await db.execute(scan_stmt)
        scan = scan_result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        
        # Get vulnerabilities
        vuln_stmt = select(Vulnerability).where(Vulnerability.scan_id == scan_id)
        vuln_result = await db.execute(vuln_stmt)
        vulnerabilities = vuln_result.scalars().all()
        
        # Build response
        vuln_responses = [
            VulnerabilityResponse(
                id=v.id,
                severity=v.severity,
                category=v.category,
                title=v.title,
                details=v.details,
                component=v.component,
                remediation=v.remediation,
                discovered_at=v.discovered_at.isoformat()
            )
            for v in vulnerabilities
        ]
        
        return ScanResultResponse(
            scan_id=scan.id,
            scan_type=scan.scan_type,
            start_time=scan.start_time.isoformat(),
            end_time=scan.end_time.isoformat() if scan.end_time else None,
            duration_seconds=scan.duration_seconds,
            status=scan.status,
            risk_score=scan.risk_score or 0.0,
            risk_level=scan.risk_level or "Unknown",
            vulnerabilities=vuln_responses,
            summary={
                "total": scan.total_vulnerabilities,
                "critical": scan.critical_count,
                "high": scan.high_count,
                "medium": scan.medium_count,
                "low": scan.low_count
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/history")
async def get_scan_history(
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_async_db_session)
):
    """
    Get scan history
    """
    try:
        stmt = select(Scan).order_by(desc(Scan.start_time)).limit(limit).offset(offset)
        result = await db.execute(stmt)
        scans = result.scalars().all()
        
        return {
            "scans": [
                {
                    "scan_id": scan.id,
                    "scan_type": scan.scan_type,
                    "start_time": scan.start_time.isoformat(),
                    "status": scan.status,
                    "vulnerabilities": scan.total_vulnerabilities,
                    "risk_score": scan.risk_score,
                    "risk_level": scan.risk_level
                }
                for scan in scans
            ],
            "total": len(scans),
            "limit": limit,
            "offset": offset
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/delete/{scan_id}")
async def delete_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_async_db_session)
):
    """
    Delete a scan and its results
    """
    try:
        stmt = select(Scan).where(Scan.id == scan_id)
        result = await db.execute(stmt)
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        
        await db.delete(scan)
        await db.commit()
        
        return {"message": f"Scan {scan_id} deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))