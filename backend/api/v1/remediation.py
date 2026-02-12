"""
RAVEN-X Enterprise - Remediation API Endpoints
Auto-fix vulnerabilities with AI assistance
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from pydantic import BaseModel, Field
from typing import List, Optional, Dict
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import uuid

from ...core.database.database import get_async_db_session
from ...core.database.models import Scan, Vulnerability, Fix
from ...core.remediation.auto_fixer import AutoFixer
from ...core.ai.learning_engine import learning_engine

router = APIRouter()

# Pydantic models
class RemediationRequest(BaseModel):
    vulnerability_ids: List[str]
    auto_fix: bool = Field(default=False, description="Apply fixes automatically")
    create_restore_point: bool = Field(default=True, description="Create system restore point")
    dry_run: bool = Field(default=False, description="Simulate fixes without applying")

class RemediationResponse(BaseModel):
    remediation_id: str
    status: str
    message: str
    estimated_duration: Optional[int] = None

class FixResult(BaseModel):
    fix_id: str
    vulnerability_id: str
    status: str
    applied_at: Optional[str] = None
    execution_time: Optional[float] = None
    output: Optional[str] = None
    error_message: Optional[str] = None

# Auto-fixer instance
auto_fixer = AutoFixer()

@router.post("/fix", response_model=RemediationResponse)
async def fix_vulnerabilities(
    request: RemediationRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_async_db_session)
):
    """
    Fix vulnerabilities automatically or generate remediation plan
    """
    try:
        # Verify vulnerabilities exist
        stmt = select(Vulnerability).where(Vulnerability.id.in_(request.vulnerability_ids))
        result = await db.execute(stmt)
        vulnerabilities = result.scalars().all()
        
        if not vulnerabilities:
            raise HTTPException(status_code=404, detail="No vulnerabilities found")
        
        remediation_id = str(uuid.uuid4())
        
        # Start remediation in background
        background_tasks.add_task(
            execute_remediation,
            remediation_id=remediation_id,
            vulnerabilities=[
                {
                    'id': v.id,
                    'severity': v.severity,
                    'category': v.category,
                    'title': v.title,
                    'details': v.details,
                    'component': v.component,
                    'remediation': v.remediation,
                    'scan_id': v.scan_id
                }
                for v in vulnerabilities
            ],
            auto_fix=request.auto_fix,
            create_restore_point=request.create_restore_point,
            dry_run=request.dry_run
        )
        
        return RemediationResponse(
            remediation_id=remediation_id,
            status="started",
            message=f"Remediation initiated for {len(vulnerabilities)} vulnerabilities",
            estimated_duration=len(vulnerabilities) * 10
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

async def execute_remediation(
    remediation_id: str,
    vulnerabilities: List[Dict],
    auto_fix: bool,
    create_restore_point: bool,
    dry_run: bool
):
    """
    Execute remediation in background
    """
    try:
        async with db_manager.get_async_db() as db:
            # Create restore point if requested
            if create_restore_point and not dry_run:
                restore_success = await auto_fixer.create_restore_point()
                if not restore_success:
                    logger.warning("Failed to create restore point, continuing anyway...")
            
            # Process each vulnerability
            for vuln in vulnerabilities:
                fix_id = str(uuid.uuid4())
                start_time = datetime.utcnow()
                
                # Create fix record
                fix = Fix(
                    id=fix_id,
                    scan_id=vuln['scan_id'],
                    vulnerability_id=vuln['id'],
                    fix_type='automated' if auto_fix else 'manual',
                    status='pending'
                )
                db.add(fix)
                await db.commit()
                
                if auto_fix and not dry_run:
                    # Actually apply the fix
                    result = await auto_fixer.apply_fix(vuln)
                    
                    fix.status = 'success' if result['success'] else 'failed'
                    fix.applied_at = datetime.utcnow()
                    fix.execution_time = (datetime.utcnow() - start_time).total_seconds()
                    fix.command_executed = result.get('command')
                    fix.output = result.get('output')
                    fix.error_message = result.get('error')
                    
                    # Learn from fix attempt
                    await learning_engine.learn_from_fix(
                        fix_id=fix_id,
                        success=result['success'],
                        execution_time=fix.execution_time
                    )
                    
                elif dry_run:
                    # Simulate fix
                    fix.status = 'simulated'
                    fix.output = "Dry run - no changes applied"
                    
                else:
                    # Manual fix - just provide instructions
                    fix.status = 'manual'
                    fix.output = vuln.get('remediation', 'Manual remediation required')
                
                await db.commit()
            
            logger.info(f"✅ Remediation {remediation_id} completed")
            
    except Exception as e:
        logger.error(f"❌ Remediation {remediation_id} failed: {e}")

@router.get("/status/{remediation_id}")
async def get_remediation_status(
    remediation_id: str,
    db: AsyncSession = Depends(get_async_db_session)
):
    """
    Get status of remediation
    """
    # This would track overall remediation progress
    # For now, return a placeholder
    return {
        "remediation_id": remediation_id,
        "status": "in_progress",
        "completed": 0,
        "total": 0,
        "success": 0,
        "failed": 0
    }

@router.get("/results/{fix_id}", response_model=FixResult)
async def get_fix_result(
    fix_id: str,
    db: AsyncSession = Depends(get_async_db_session)
):
    """
    Get result of a specific fix
    """
    try:
        stmt = select(Fix).where(Fix.id == fix_id)
        result = await db.execute(stmt)
        fix = result.scalar_one_or_none()
        
        if not fix:
            raise HTTPException(status_code=404, detail=f"Fix {fix_id} not found")
        
        return FixResult(
            fix_id=fix.id,
            vulnerability_id=fix.vulnerability_id,
            status=fix.status,
            applied_at=fix.applied_at.isoformat() if fix.applied_at else None,
            execution_time=fix.execution_time,
            output=fix.output,
            error_message=fix.error_message
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/rollback/{fix_id}")
async def rollback_fix(
    fix_id: str,
    db: AsyncSession = Depends(get_async_db_session)
):
    """
    Rollback a fix
    """
    try:
        stmt = select(Fix).where(Fix.id == fix_id)
        result = await db.execute(stmt)
        fix = result.scalar_one_or_none()
        
        if not fix:
            raise HTTPException(status_code=404, detail=f"Fix {fix_id} not found")
        
        # Attempt rollback
        rollback_result = await auto_fixer.rollback_fix(fix)
        
        if rollback_result['success']:
            fix.rollback_performed = True
            fix.status = 'rolled_back'
            await db.commit()
            
            return {
                "status": "success",
                "message": "Fix rolled back successfully"
            }
        else:
            return {
                "status": "failed",
                "message": f"Rollback failed: {rollback_result.get('error')}"
            }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/generate-script")
async def generate_remediation_script(
    vulnerability_ids: List[str],
    db: AsyncSession = Depends(get_async_db_session)
):
    """
    Generate PowerShell script for manual remediation
    """
    try:
        stmt = select(Vulnerability).where(Vulnerability.id.in_(vulnerability_ids))
        result = await db.execute(stmt)
        vulnerabilities = result.scalars().all()
        
        if not vulnerabilities:
            raise HTTPException(status_code=404, detail="No vulnerabilities found")
        
        # Generate script using AI
        from ...core.ai.llm_client import llm_client
        
        vuln_data = [
            {
                'title': v.title,
                'severity': v.severity,
                'category': v.category,
                'remediation': v.remediation
            }
            for v in vulnerabilities
        ]
        
        script = await llm_client.generate_remediation_script(vuln_data)
        
        return {
            "script": script,
            "vulnerabilities_count": len(vulnerabilities),
            "warning": "Review this script carefully before execution. Run as Administrator."
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))