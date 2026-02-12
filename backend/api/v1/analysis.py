"""
RAVEN-X Enterprise - AI Analysis API Endpoints
The BRAIN of the operation!
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel, Field
from typing import List, Optional, Dict
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import uuid

from ...core.database.database import get_async_db_session
from ...core.database.models import Scan, Vulnerability, AIAnalysis
from ...core.ai.llm_client import LLMClient
from ...core.ai.learning_engine import learning_engine

router = APIRouter()

# Pydantic models
class AnalysisRequest(BaseModel):
    scan_id: str
    analysis_type: str = Field(default="comprehensive", description="comprehensive, quick, compliance")
    focus_areas: Optional[List[str]] = Field(default=None, description="Specific areas to focus on")

class AnalysisResponse(BaseModel):
    analysis_id: str
    scan_id: str
    status: str
    message: str

class AIAnalysisResult(BaseModel):
    analysis_id: str
    scan_id: str
    executive_summary: str
    risk_assessment: Dict
    prioritized_fixes: List[Dict]
    compliance_mapping: Dict
    recommendations: List[str]
    generated_at: str

# LLM Client instance
llm_client = LLMClient()

@router.post("/analyze", response_model=AnalysisResponse)
async def request_ai_analysis(
    request: AnalysisRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_async_db_session)
):
    """
    Request AI analysis of scan results
    """
    try:
        # Verify scan exists
        stmt = select(Scan).where(Scan.id == request.scan_id)
        result = await db.execute(stmt)
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan {request.scan_id} not found")
        
        if scan.status != "completed":
            raise HTTPException(status_code=400, detail="Scan must be completed before analysis")
        
        analysis_id = str(uuid.uuid4())
        
        # Start analysis in background
        background_tasks.add_task(
            perform_ai_analysis,
            analysis_id=analysis_id,
            scan_id=request.scan_id,
            analysis_type=request.analysis_type,
            focus_areas=request.focus_areas
        )
        
        return AnalysisResponse(
            analysis_id=analysis_id,
            scan_id=request.scan_id,
            status="started",
            message="AI analysis initiated"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

async def perform_ai_analysis(
    analysis_id: str,
    scan_id: str,
    analysis_type: str,
    focus_areas: Optional[List[str]]
):
    """
    Perform AI analysis in background
    """
    try:
        async with db_manager.get_async_db() as db:
            # Get scan and vulnerabilities
            scan_stmt = select(Scan).where(Scan.id == scan_id)
            scan_result = await db.execute(scan_stmt)
            scan = scan_result.scalar_one()
            
            vuln_stmt = select(Vulnerability).where(Vulnerability.scan_id == scan_id)
            vuln_result = await db.execute(vuln_stmt)
            vulnerabilities = vuln_result.scalars().all()
            
            # Prepare vulnerability data for LLM
            vuln_data = [
                {
                    'severity': v.severity,
                    'category': v.category,
                    'title': v.title,
                    'details': v.details,
                    'component': v.component,
                    'remediation': v.remediation
                }
                for v in vulnerabilities
            ]
            
            # Get AI analysis
            start_time = datetime.utcnow()
            analysis_result = await llm_client.analyze_vulnerabilities(
                vulnerabilities=vuln_data,
                system_info=scan.system_info,
                analysis_type=analysis_type,
                focus_areas=focus_areas
            )
            end_time = datetime.utcnow()
            
            execution_time = (end_time - start_time).total_seconds()
            
            # Save analysis
            ai_analysis = AIAnalysis(
                id=analysis_id,
                scan_id=scan_id,
                model_name=llm_client.model_name,
                prompt_tokens=analysis_result.get('prompt_tokens', 0),
                completion_tokens=analysis_result.get('completion_tokens', 0),
                analysis_text=analysis_result.get('full_analysis', ''),
                recommendations=analysis_result.get('recommendations', []),
                priority_fixes=analysis_result.get('priority_fixes', []),
                compliance_mapping=analysis_result.get('compliance_mapping', {}),
                execution_time=execution_time
            )
            
            db.add(ai_analysis)
            await db.commit()
            
            logger.info(f"✅ AI analysis {analysis_id} completed in {execution_time:.2f}s")
            
    except Exception as e:
        logger.error(f"❌ AI analysis {analysis_id} failed: {e}")

@router.get("/result/{analysis_id}", response_model=AIAnalysisResult)
async def get_analysis_result(
    analysis_id: str,
    db: AsyncSession = Depends(get_async_db_session)
):
    """
    Get AI analysis result
    """
    try:
        stmt = select(AIAnalysis).where(AIAnalysis.id == analysis_id)
        result = await db.execute(stmt)
        analysis = result.scalar_one_or_none()
        
        if not analysis:
            raise HTTPException(status_code=404, detail=f"Analysis {analysis_id} not found")
        
        # Parse analysis text for structured response
        return AIAnalysisResult(
            analysis_id=analysis.id,
            scan_id=analysis.scan_id,
            executive_summary=analysis.analysis_text[:500] + "...",  # First 500 chars
            risk_assessment={
                'overall_risk': 'High',  # Would parse from analysis
                'attack_likelihood': 'Medium',
                'business_impact': 'High'
            },
            prioritized_fixes=analysis.priority_fixes or [],
            compliance_mapping=analysis.compliance_mapping or {},
            recommendations=analysis.recommendations or [],
            generated_at=analysis.generated_at.isoformat()
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/retrain")
async def trigger_model_retraining(
    background_tasks: BackgroundTasks
):
    """
    Trigger ML model retraining
    """
    background_tasks.add_task(learning_engine.retrain_models)
    
    return {
        "status": "started",
        "message": "Model retraining initiated"
    }

@router.get("/learning-stats")
async def get_learning_stats():
    """
    Get AI learning statistics
    """
    stats = await learning_engine.get_learning_stats()
    
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "stats": stats
    }

@router.post("/feedback")
async def submit_feedback(
    vulnerability_id: Optional[str] = None,
    fix_id: Optional[str] = None,
    feedback_type: str = "true_positive",
    rating: Optional[int] = None,
    comment: Optional[str] = None,
    db: AsyncSession = Depends(get_async_db_session)
):
    """
    Submit user feedback for learning
    """
    try:
        feedback_data = {
            'vulnerability_id': vulnerability_id,
            'fix_id': fix_id,
            'feedback_type': feedback_type,
            'rating': rating,
            'comment': comment
        }
        
        await learning_engine.learn_from_user_feedback(feedback_data)
        
        return {
            "status": "success",
            "message": "Feedback received and processed"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))