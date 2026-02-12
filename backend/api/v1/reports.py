"""
RAVEN-X Enterprise - Reports API Endpoints
Generate professional security reports
"""

from fastapi import APIRouter, HTTPException, Depends, Response
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import io
import json

from ...core.database.database import get_async_db_session
from ...core.database.models import Scan, Vulnerability, AIAnalysis
from ...core.reporting.report_generator import ReportGenerator

router = APIRouter()

# Pydantic models
class ReportRequest(BaseModel):
    scan_id: str
    format: str = Field(default="html", description="html, pdf, json, csv, docx")
    include_ai_analysis: bool = Field(default=True)
    include_system_info: bool = Field(default=True)
    include_remediation_steps: bool = Field(default=True)

class ReportResponse(BaseModel):
    report_id: str
    format: str
    generated_at: str
    download_url: str

# Report generator instance
report_gen = ReportGenerator()

@router.post("/generate")
async def generate_report(
    request: ReportRequest,
    db: AsyncSession = Depends(get_async_db_session)
):
    """
    Generate security report in specified format
    """
    try:
        # Get scan data
        scan_stmt = select(Scan).where(Scan.id == request.scan_id)
        scan_result = await db.execute(scan_stmt)
        scan = scan_result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan {request.scan_id} not found")
        
        # Get vulnerabilities
        vuln_stmt = select(Vulnerability).where(Vulnerability.scan_id == request.scan_id)
        vuln_result = await db.execute(vuln_stmt)
        vulnerabilities = vuln_result.scalars().all()
        
        # Get AI analysis if requested
        ai_analysis = None
        if request.include_ai_analysis:
            ai_stmt = select(AIAnalysis).where(AIAnalysis.scan_id == request.scan_id).order_by(AIAnalysis.generated_at.desc())
            ai_result = await db.execute(ai_stmt)
            ai_analysis = ai_result.scalar_one_or_none()
        
        # Generate report
        report_data = {
            'scan': scan,
            'vulnerabilities': vulnerabilities,
            'ai_analysis': ai_analysis,
            'include_system_info': request.include_system_info,
            'include_remediation': request.include_remediation_steps
        }
        
        if request.format == 'html':
            report_content = report_gen.generate_html_report(report_data)
            media_type = 'text/html'
            filename = f"raven_x_report_{scan.id[:8]}.html"
            
        elif request.format == 'pdf':
            report_content = report_gen.generate_pdf_report(report_data)
            media_type = 'application/pdf'
            filename = f"raven_x_report_{scan.id[:8]}.pdf"
            
        elif request.format == 'json':
            report_content = report_gen.generate_json_report(report_data)
            media_type = 'application/json'
            filename = f"raven_x_report_{scan.id[:8]}.json"
            
        elif request.format == 'csv':
            report_content = report_gen.generate_csv_report(report_data)
            media_type = 'text/csv'
            filename = f"raven_x_report_{scan.id[:8]}.csv"
            
        elif request.format == 'docx':
            report_content = report_gen.generate_docx_report(report_data)
            media_type = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            filename = f"raven_x_report_{scan.id[:8]}.docx"
            
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported format: {request.format}")
        
        # Return as downloadable file
        if isinstance(report_content, str):
            content = io.BytesIO(report_content.encode('utf-8'))
        else:
            content = io.BytesIO(report_content)
        
        return StreamingResponse(
            content,
            media_type=media_type,
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"'
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/download/{scan_id}/{format}")
async def download_report(
    scan_id: str,
    format: str,
    db: AsyncSession = Depends(get_async_db_session)
):
    """
    Quick download report
    """
    request = ReportRequest(
        scan_id=scan_id,
        format=format,
        include_ai_analysis=True,
        include_system_info=True,
        include_remediation_steps=True
    )
    
    return await generate_report(request, db)

@router.get("/templates")
async def get_report_templates():
    """
    Get available report templates
    """
    return {
        "templates": [
            {
                "name": "Executive Summary",
                "description": "High-level report for executives",
                "format": "pdf"
            },
            {
                "name": "Technical Details",
                "description": "Detailed technical report for IT staff",
                "format": "html"
            },
            {
                "name": "Compliance Report",
                "description": "Report mapped to compliance standards",
                "format": "pdf"
            },
            {
                "name": "Vulnerability Database",
                "description": "Machine-readable vulnerability export",
                "format": "json"
            }
        ]
    }