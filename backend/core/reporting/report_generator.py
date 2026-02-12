"""
RAVEN-X Enterprise - Report Generator
Professional security report generation
"""

from jinja2 import Template
from datetime import datetime
import json
import csv
import io
import logging
from typing import Dict
from pathlib import Path

logger = logging.getLogger(__name__)

class ReportGenerator:
    """
    Generate professional security reports in multiple formats
    """
    
    def __init__(self):
        self.templates_dir = Path(__file__).parent / "templates"
        self.templates_dir.mkdir(exist_ok=True)
        logger.info("📊 Report Generator initialized")
    
    def generate_html_report(self, data: Dict) -> str:
        """
        Generate HTML report
        """
        scan = data['scan']
        vulnerabilities = data['vulnerabilities']
        ai_analysis = data.get('ai_analysis')
        
        # Calculate statistics
        stats = {
            'total': len(vulnerabilities),
            'critical': sum(1 for v in vulnerabilities if v.severity == 'critical'),
            'high': sum(1 for v in vulnerabilities if v.severity == 'high'),
            'medium': sum(1 for v in vulnerabilities if v.severity == 'medium'),
            'low': sum(1 for v in vulnerabilities if v.severity == 'low')
        }
        
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RAVEN-X Security Report - {{ scan.id }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 50px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 48px;
            font-weight: 700;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .header .subtitle {
            font-size: 18px;
            opacity: 0.9;
        }
        
        .risk-banner {
            background: {% if scan.risk_score >= 70 %}#e74c3c{% elif scan.risk_score >= 40 %}#e67e22{% else %}#27ae60{% endif %};
            color: white;
            padding: 30px;
            text-align: center;
            font-size: 32px;
            font-weight: bold;
        }
        
        .content {
            padding: 50px;
        }
        
        .section {
            margin-bottom: 40px;
        }
        
        .section h2 {
            font-size: 32px;
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 15px;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            transition: transform 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-card.critical { background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); }
        .stat-card.high { background: linear-gradient(135deg, #e67e22 0%, #d35400 100%); }
        .stat-card.medium { background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%); }
        .stat-card.low { background: linear-gradient(135deg, #95a5a6 0%, #7f8c8d 100%); }
        
        .stat-number {
            font-size: 48px;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        .stat-label {
            font-size: 16px;
            opacity: 0.9;
        }
        
        .vulnerability {
            background: #f8f9fa;
            border-left: 5px solid;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
            transition: all 0.3s;
        }
        
        .vulnerability:hover {
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            transform: translateX(5px);
        }
        
        .vulnerability.critical { border-color: #e74c3c; background: #ffeaea; }
        .vulnerability.high { border-color: #e67e22; background: #fff3e6; }
        .vulnerability.medium { border-color: #f39c12; background: #fff9e6; }
        .vulnerability.low { border-color: #95a5a6; background: #f8f9fa; }
        
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .vuln-title {
            font-size: 20px;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .vuln-badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            color: white;
        }
        
        .badge-critical { background: #e74c3c; }
        .badge-high { background: #e67e22; }
        .badge-medium { background: #f39c12; }
        .badge-low { background: #95a5a6; }
        
        .vuln-details {
            color: #34495e;
            line-height: 1.6;
            margin-bottom: 15px;
        }
        
        .vuln-meta {
            display: flex;
            gap: 20px;
            font-size: 14px;
            color: #7f8c8d;
            margin-bottom: 15px;
        }
        
        .remediation {
            background: white;
            padding: 15px;
            border-radius: 5px;
            border: 1px solid #3498db;
        }
        
        .remediation-title {
            font-weight: bold;
            color: #3498db;
            margin-bottom: 10px;
        }
        
        .ai-section {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 15px;
            margin: 30px 0;
        }
        
        .ai-section h3 {
            font-size: 28px;
            margin-bottom: 20px;
        }
        
        .ai-content {
            line-height: 1.8;
            white-space: pre-wrap;
        }
        
        .system-info {
            background: #ecf0f1;
            padding: 20px;
            border-radius: 10px;
        }
        
        .system-info table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .system-info td {
            padding: 10px;
            border-bottom: 1px solid #bdc3c7;
        }
        
        .system-info td:first-child {
            font-weight: bold;
            color: #2c3e50;
            width: 200px;
        }
        
        .footer {
            background: #2c3e50;
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .footer-logo {
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        @media print {
            body { background: white; padding: 0; }
            .container { box-shadow: none; }
            .vulnerability { page-break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🔒 RAVEN-X SECURITY REPORT</h1>
            <div class="subtitle">Enterprise Security Assessment</div>
            <div class="subtitle">{{ scan.start_time.strftime('%B %d, %Y at %H:%M') }}</div>
        </div>
        
        <!-- Risk Banner -->
        <div class="risk-banner">
            RISK SCORE: {{ scan.risk_score }}% - {{ scan.risk_level }}
        </div>
        
        <!-- Content -->
        <div class="content">
            <!-- Executive Summary -->
            <div class="section">
                <h2>📊 Executive Summary</h2>
                <p style="font-size: 18px; line-height: 1.8; color: #34495e; margin: 20px 0;">
                    This comprehensive security assessment identified <strong>{{ stats.total }} vulnerabilities</strong> 
                    across multiple categories. The system's overall risk score is <strong>{{ scan.risk_score }}%</strong>, 
                    categorized as <strong>{{ scan.risk_level }}</strong>. Immediate attention is required for 
                    <strong>{{ stats.critical }} critical</strong> and <strong>{{ stats.high }} high-severity</strong> issues.
                </p>
            </div>
            
            <!-- Statistics -->
            <div class="section">
                <h2>📈 Vulnerability Statistics</h2>
                <div class="stats-grid">
                    <div class="stat-card critical">
                        <div class="stat-number">{{ stats.critical }}</div>
                        <div class="stat-label">Critical</div>
                    </div>
                    <div class="stat-card high">
                        <div class="stat-number">{{ stats.high }}</div>
                        <div class="stat-label">High</div>
                    </div>
                    <div class="stat-card medium">
                        <div class="stat-number">{{ stats.medium }}</div>
                        <div class="stat-label">Medium</div>
                    </div>
                    <div class="stat-card low">
                        <div class="stat-number">{{ stats.low }}</div>
                        <div class="stat-label">Low</div>
                    </div>
                </div>
            </div>
            
            <!-- System Information -->
            {% if data.include_system_info %}
            <div class="section">
                <h2>💻 System Information</h2>
                <div class="system-info">
                    <table>
                        <tr>
                            <td>Hostname</td>
                            <td>{{ scan.system_info.get('hostname', 'Unknown') }}</td>
                        </tr>
                        <tr>
                            <td>Operating System</td>
                            <td>{{ scan.system_info.get('os_version', 'Unknown') }}</td>
                        </tr>
                        <tr>
                            <td>Architecture</td>
                            <td>{{ scan.system_info.get('architecture', 'Unknown') }}</td>
                        </tr>
                        <tr>
                            <td>Scan ID</td>
                            <td>{{ scan.id }}</td>
                        </tr>
                        <tr>
                            <td>Scan Duration</td>
                            <td>{{ scan.duration_seconds|round(2) }} seconds</td>
                        </tr>
                    </table>
                </div>
            </div>
            {% endif %}
            
            <!-- AI Analysis -->
            {% if ai_analysis %}
            <div class="ai-section">
                <h3>🤖 AI-Powered Analysis</h3>
                <div class="ai-content">{{ ai_analysis.analysis_text[:1000] }}...</div>
            </div>
            {% endif %}
            
            <!-- Detailed Vulnerabilities -->
            <div class="section">
                <h2>🔍 Detailed Findings</h2>
                
                {% for vuln in vulnerabilities %}
                <div class="vulnerability {{ vuln.severity }}">
                    <div class="vuln-header">
                        <div class="vuln-title">{{ loop.index }}. {{ vuln.title }}</div>
                        <div class="vuln-badge badge-{{ vuln.severity }}">{{ vuln.severity.upper() }}</div>
                    </div>
                    
                    <div class="vuln-meta">
                        <div>📂 Category: {{ vuln.category }}</div>
                        <div>⚙️ Component: {{ vuln.component }}</div>
                        <div>📅 Detected: {{ vuln.discovered_at.strftime('%Y-%m-%d %H:%M') }}</div>
                    </div>
                    
                    <div class="vuln-details">
                        <strong>Details:</strong><br>
                        {{ vuln.details }}
                    </div>
                    
                    {% if data.include_remediation and vuln.remediation %}
                    <div class="remediation">
                        <div class="remediation-title">🔧 Remediation Steps:</div>
                        {{ vuln.remediation }}
                    </div>
                    {% endif %}
                </div>
                {% endfor %}
            </div>
            
            <!-- Recommendations -->
            <div class="section">
                <h2>💡 Recommendations</h2>
                <ol style="line-height: 2; font-size: 16px; color: #34495e;">
                    <li>Address all critical and high-severity vulnerabilities immediately</li>
                    <li>Implement regular security scanning (weekly recommended)</li>
                    <li>Enable automatic Windows updates</li>
                    <li>Review and strengthen access controls</li>
                    <li>Implement network segmentation where possible</li>
                    <li>Regular security awareness training for staff</li>
                    <li>Deploy endpoint detection and response (EDR) solution</li>
                    <li>Maintain audit logs and review regularly</li>
                </ol>
            </div>
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <div class="footer-logo">RAVEN-X Enterprise Security Platform v4.0</div>
            <div>Report Generated: {{ datetime.now().strftime('%Y-%m-%d %H:%M:%S') }}</div>
            <div style="margin-top: 10px; opacity: 0.8;">
                © 2025 RAVEN-X. For authorized security assessment purposes only.
            </div>
        </div>
    </div>
</body>
</html>
"""
        
        template = Template(html_template)
        
        return template.render(
            scan=scan,
            vulnerabilities=vulnerabilities,
            ai_analysis=ai_analysis,
            stats=stats,
            data=data,
            datetime=datetime
        )
    
    def generate_pdf_report(self, data: Dict) -> bytes:
        """
        Generate PDF report
        """
        # For PDF, we'll use reportlab
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
            from reportlab.lib.units import inch
            
            scan = data['scan']
            vulnerabilities = data['vulnerabilities']
            
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter)
            
            # Container for PDF elements
            elements = []
            styles = getSampleStyleSheet()
            
            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#1e3c72'),
                spaceAfter=30,
                alignment=1  # Center
            )
            
            elements.append(Paragraph("RAVEN-X SECURITY REPORT", title_style))
            elements.append(Paragraph(f"Scan ID: {scan.id}", styles['Normal']))
            elements.append(Paragraph(f"Date: {scan.start_time.strftime('%Y-%m-%d %H:%M')}", styles['Normal']))
            elements.append(Spacer(1, 0.5 * inch))
            
            # Executive Summary
            elements.append(Paragraph("Executive Summary", styles['Heading2']))
            summary_text = f"""
            This security assessment identified {len(vulnerabilities)} vulnerabilities.
            Risk Score: {scan.risk_score}% ({scan.risk_level})
            """
            elements.append(Paragraph(summary_text, styles['Normal']))
            elements.append(Spacer(1, 0.3 * inch))
            
            # Statistics Table
            stats_data = [
                ['Severity', 'Count'],
                ['Critical', sum(1 for v in vulnerabilities if v.severity == 'critical')],
                ['High', sum(1 for v in vulnerabilities if v.severity == 'high')],
                ['Medium', sum(1 for v in vulnerabilities if v.severity == 'medium')],
                ['Low', sum(1 for v in vulnerabilities if v.severity == 'low')],
            ]
            
            stats_table = Table(stats_data)
            stats_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            elements.append(stats_table)
            elements.append(PageBreak())
            
            # Vulnerabilities
            elements.append(Paragraph("Detailed Findings", styles['Heading2']))
            
            for i, vuln in enumerate(vulnerabilities[:20], 1):  # Limit to 20 for PDF
                elements.append(Paragraph(f"{i}. {vuln.title}", styles['Heading3']))
                elements.append(Paragraph(f"Severity: {vuln.severity.upper()}", styles['Normal']))
                elements.append(Paragraph(f"Category: {vuln.category}", styles['Normal']))
                elements.append(Paragraph(f"Details: {vuln.details}", styles['Normal']))
                
                if vuln.remediation:
                    elements.append(Paragraph(f"Remediation: {vuln.remediation}", styles['Normal']))
                
                elements.append(Spacer(1, 0.2 * inch))
            
            # Build PDF
            doc.build(elements)
            
            pdf_content = buffer.getvalue()
            buffer.close()
            
            return pdf_content
            
        except ImportError:
            logger.error("reportlab not installed, falling back to HTML")
            return self.generate_html_report(data).encode('utf-8')
    
    def generate_json_report(self, data: Dict) -> str:
        """
        Generate JSON report
        """
        scan = data['scan']
        vulnerabilities = data['vulnerabilities']
        
        report = {
            'scan_id': scan.id,
            'scan_type': scan.scan_type,
            'start_time': scan.start_time.isoformat(),
            'end_time': scan.end_time.isoformat() if scan.end_time else None,
            'duration_seconds': scan.duration_seconds,
            'risk_score': scan.risk_score,
            'risk_level': scan.risk_level,
            'system_info': scan.system_info,
            'summary': {
                'total': len(vulnerabilities),
                'critical': sum(1 for v in vulnerabilities if v.severity == 'critical'),
                'high': sum(1 for v in vulnerabilities if v.severity == 'high'),
                'medium': sum(1 for v in vulnerabilities if v.severity == 'medium'),
                'low': sum(1 for v in vulnerabilities if v.severity == 'low')
            },
            'vulnerabilities': [
                {
                    'id': v.id,
                    'severity': v.severity,
                    'category': v.category,
                    'title': v.title,
                    'details': v.details,
                    'component': v.component,
                    'remediation': v.remediation,
                    'discovered_at': v.discovered_at.isoformat()
                }
                for v in vulnerabilities
            ]
        }
        
        return json.dumps(report, indent=2)
    
    def generate_csv_report(self, data: Dict) -> str:
        """
        Generate CSV report
        """
        scan = data['scan']
        vulnerabilities = data['vulnerabilities']
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow(['RAVEN-X Security Report'])
        writer.writerow(['Scan ID', scan.id])
        writer.writerow(['Date', scan.start_time.strftime('%Y-%m-%d %H:%M')])
        writer.writerow(['Risk Score', f'{scan.risk_score}%'])
        writer.writerow([])
        
        # Vulnerabilities
        writer.writerow(['#', 'Severity', 'Title', 'Category', 'Component', 'Details', 'Remediation'])
        
        for i, vuln in enumerate(vulnerabilities, 1):
            writer.writerow([
                i,
                vuln.severity.upper(),
                vuln.title,
                vuln.category,
                vuln.component,
                vuln.details,
                vuln.remediation or ''
            ])
        
        return output.getvalue()
    
    def generate_docx_report(self, data: Dict) -> bytes:
        """
        Generate DOCX report
        """
        try:
            from docx import Document
            from docx.shared import Inches, Pt, RGBColor
            from docx.enum.text import WD_ALIGN_PARAGRAPH
            
            scan = data['scan']
            vulnerabilities = data['vulnerabilities']
            
            doc = Document()
            
            # Title
            title = doc.add_heading('RAVEN-X SECURITY REPORT', 0)
            title.alignment = WD_ALIGN_PARAGRAPH.CENTER
            
            # Metadata
            doc.add_paragraph(f'Scan ID: {scan.id}')
            doc.add_paragraph(f'Date: {scan.start_time.strftime("%Y-%m-%d %H:%M")}')
            doc.add_paragraph(f'Risk Score: {scan.risk_score}% ({scan.risk_level})')
            doc.add_page_break()
            
            # Executive Summary
            doc.add_heading('Executive Summary', 1)
            doc.add_paragraph(
                f'This security assessment identified {len(vulnerabilities)} vulnerabilities '
                f'with an overall risk score of {scan.risk_score}%.'
            )
            
            # Statistics
            doc.add_heading('Vulnerability Statistics', 2)
            table = doc.add_table(rows=5, cols=2)
            table.style = 'Light Grid Accent 1'
            
            table.rows[0].cells[0].text = 'Critical'
            table.rows[0].cells[1].text = str(sum(1 for v in vulnerabilities if v.severity == 'critical'))
            table.rows[1].cells[0].text = 'High'
            table.rows[1].cells[1].text = str(sum(1 for v in vulnerabilities if v.severity == 'high'))
            table.rows[2].cells[0].text = 'Medium'
            table.rows[2].cells[1].text = str(sum(1 for v in vulnerabilities if v.severity == 'medium'))
            table.rows[3].cells[0].text = 'Low'
            table.rows[3].cells[1].text = str(sum(1 for v in vulnerabilities if v.severity == 'low'))
            table.rows[4].cells[0].text = 'Total'
            table.rows[4].cells[1].text = str(len(vulnerabilities))
            
            doc.add_page_break()
            
            # Vulnerabilities
            doc.add_heading('Detailed Findings', 1)
            
            for i, vuln in enumerate(vulnerabilities, 1):
                doc.add_heading(f'{i}. {vuln.title}', 2)
                doc.add_paragraph(f'Severity: {vuln.severity.upper()}')
                doc.add_paragraph(f'Category: {vuln.category}')
                doc.add_paragraph(f'Component: {vuln.component}')
                doc.add_paragraph(f'Details: {vuln.details}')
                
                if vuln.remediation:
                    doc.add_paragraph(f'Remediation: {vuln.remediation}')
                
                doc.add_paragraph()  # Spacing
            
            # Save to bytes
            buffer = io.BytesIO()
            doc.save(buffer)
            buffer.seek(0)
            
            return buffer.getvalue()
            
        except ImportError:
            logger.error("python-docx not installed")
            return b"Error: python-docx not installed"


# Global report generator
report_gen = ReportGenerator()