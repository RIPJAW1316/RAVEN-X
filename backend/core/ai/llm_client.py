"""
RAVEN-X Enterprise - LLM Client
Connects to LM Studio for AI-powered analysis
"""

from openai import OpenAI
import logging
from typing import Dict, List, Optional
import yaml
import json

logger = logging.getLogger(__name__)

class LLMClient:
    """
    Client for LM Studio (local LLM)
    Provides intelligent vulnerability analysis
    """
    
    def __init__(self, config_path: str = "config/config.yaml"):
        # Load config
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        ai_config = config['ai']['lm_studio']
        
        self.base_url = ai_config['url']
        self.model_name = ai_config['model']
        self.timeout = ai_config['timeout']
        self.max_tokens = ai_config['max_tokens']
        self.temperature = ai_config['temperature']
        
        # Initialize OpenAI client (compatible with LM Studio)
        self.client = OpenAI(
            base_url=self.base_url,
            api_key="lm-studio"  # LM Studio doesn't need real key
        )
        
        logger.info(f"🤖 LLM Client initialized: {self.model_name}")
    
    async def analyze_vulnerabilities(
        self,
        vulnerabilities: List[Dict],
        system_info: Dict,
        analysis_type: str = "comprehensive",
        focus_areas: Optional[List[str]] = None
    ) -> Dict:
        """
        Analyze vulnerabilities using LLM
        """
        try:
            # Prepare vulnerability summary
            vuln_summary = self._prepare_vulnerability_summary(vulnerabilities)
            
            # Build prompt based on analysis type
            if analysis_type == "comprehensive":
                prompt = self._build_comprehensive_prompt(vuln_summary, system_info)
            elif analysis_type == "quick":
                prompt = self._build_quick_prompt(vuln_summary)
            elif analysis_type == "compliance":
                prompt = self._build_compliance_prompt(vuln_summary)
            else:
                prompt = self._build_comprehensive_prompt(vuln_summary, system_info)
            
            # Call LLM
            logger.info(f"🧠 Sending analysis request to LLM...")
            
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {
                        "role": "system",
                        "content": "You are an elite cybersecurity expert specializing in Windows security, penetration testing, and threat analysis."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                stream=False
            )
            
            analysis_text = response.choices[0].message.content
            
            logger.info(f"✅ LLM analysis received ({len(analysis_text)} chars)")
            
            # Parse structured data from response
            result = {
                'full_analysis': analysis_text,
                'prompt_tokens': response.usage.prompt_tokens if hasattr(response, 'usage') else 0,
                'completion_tokens': response.usage.completion_tokens if hasattr(response, 'usage') else 0,
                'recommendations': self._extract_recommendations(analysis_text),
                'priority_fixes': self._extract_priority_fixes(analysis_text),
                'compliance_mapping': self._extract_compliance_mapping(analysis_text)
            }
            
            return result
            
        except Exception as e:
            logger.error(f"❌ LLM analysis failed: {e}")
            
            # Return fallback analysis
            return {
                'full_analysis': f"Error: {str(e)}",
                'prompt_tokens': 0,
                'completion_tokens': 0,
                'recommendations': [],
                'priority_fixes': [],
                'compliance_mapping': {}
            }
    
    def _prepare_vulnerability_summary(self, vulnerabilities: List[Dict]) -> str:
        """
        Prepare vulnerability data for LLM
        """
        summary = "## DETECTED VULNERABILITIES\n\n"
        
        # Group by severity
        by_severity = {'critical': [], 'high': [], 'medium': [], 'low': []}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'medium')
            by_severity[severity].append(vuln)
        
        for severity in ['critical', 'high', 'medium', 'low']:
            vulns = by_severity[severity]
            if vulns:
                summary += f"\n### {severity.upper()} SEVERITY ({len(vulns)} issues)\n\n"
                
                for i, vuln in enumerate(vulns[:10], 1):  # Limit to top 10 per severity
                    summary += f"{i}. **{vuln['title']}**\n"
                    summary += f"   - Category: {vuln['category']}\n"
                    summary += f"   - Component: {vuln['component']}\n"
                    summary += f"   - Details: {vuln['details'][:200]}...\n"
                    if vuln.get('remediation'):
                        summary += f"   - Remediation: {vuln['remediation'][:100]}...\n"
                    summary += "\n"
        
        return summary
    
    def _build_comprehensive_prompt(self, vuln_summary: str, system_info: Dict) -> str:
        """
        Build comprehensive analysis prompt
        """
        return f"""You are analyzing a Windows security assessment for:

**SYSTEM INFORMATION:**
- OS: {system_info.get('os_version', 'Unknown')}
- Hostname: {system_info.get('hostname', 'Unknown')}
- Architecture: {system_info.get('architecture', 'Unknown')}

{vuln_summary}

**PROVIDE A COMPREHENSIVE SECURITY ANALYSIS:**

## 1. EXECUTIVE SUMMARY (3-4 paragraphs)
- Overall security posture assessment
- Most critical findings
- Business impact and risk level
- Immediate action items

## 2. RISK ASSESSMENT
- Attack likelihood (High/Medium/Low)
- Potential business impact
- Exploitability analysis
- Threat actor capabilities required

## 3. PRIORITIZED REMEDIATION PLAN
List the TOP 5 issues to fix FIRST with:
- Issue name and severity
- Why this is critical
- Step-by-step fix instructions (specific commands/steps)
- Estimated time to fix
- Potential side effects

## 4. ATTACK CHAIN ANALYSIS
- Identify potential attack paths
- How vulnerabilities could be chained together
- What attackers could achieve

## 5. COMPLIANCE & STANDARDS
Map findings to:
- CIS Benchmarks
- NIST Cybersecurity Framework
- ISO 27001
- PCI DSS (if applicable)

## 6. STRATEGIC RECOMMENDATIONS
- Long-term security improvements
- Process/policy changes needed
- Tools to implement
- Training requirements

## 7. MONITORING & DETECTION
- What to monitor after fixes
- Detection strategies for these attack vectors
- Log sources to review

**IMPORTANT:**
- Be specific and actionable
- Provide exact commands where possible
- Consider real-world attack scenarios
- Think like both defender and attacker
"""
    
    def _build_quick_prompt(self, vuln_summary: str) -> str:
        """
        Build quick analysis prompt
        """
        return f"""Provide a QUICK security analysis:

{vuln_summary}

**DELIVER:**
1. 2-paragraph executive summary
2. Top 3 critical fixes with exact steps
3. Overall risk score (0-100)
4. One-sentence attack scenario

Be concise and actionable.
"""
    
    def _build_compliance_prompt(self, vuln_summary: str) -> str:
        """
        Build compliance-focused prompt
        """
        return f"""Perform a COMPLIANCE-FOCUSED analysis:

{vuln_summary}

**MAP FINDINGS TO:**
- CIS Windows Benchmarks
- NIST CSF
- ISO 27001 controls
- PCI DSS requirements
- GDPR technical measures

For each finding, specify:
- Relevant control/requirement
- Compliance gap severity
- Remediation for compliance
"""
    
    def _extract_recommendations(self, analysis_text: str) -> List[str]:
        """
        Extract structured recommendations from analysis
        """
        recommendations = []
        
        # Simple extraction (in production, would use better parsing)
        if "RECOMMENDATIONS" in analysis_text.upper():
            # Extract section
            start = analysis_text.upper().find("RECOMMENDATIONS")
            section = analysis_text[start:start+2000]
            
            # Find bullet points or numbered items
            lines = section.split('\n')
            for line in lines:
                if line.strip().startswith(('-', '*', '•')) or (len(line) > 2 and line[0].isdigit() and line[1] == '.'):
                    recommendations.append(line.strip())
        
        return recommendations[:10]  # Top 10
    
    def _extract_priority_fixes(self, analysis_text: str) -> List[Dict]:
        """
        Extract priority fixes from analysis
        """
        priority_fixes = []
        
        # Simple extraction
        if "PRIORITIZED" in analysis_text.upper() or "TOP" in analysis_text.upper():
            # Would use better parsing in production
            pass
        
        return priority_fixes
    
    def _extract_compliance_mapping(self, analysis_text: str) -> Dict:
        """
        Extract compliance mappings from analysis
        """
        compliance = {}
        
        # Extract compliance mentions
        standards = ['CIS', 'NIST', 'ISO 27001', 'PCI DSS', 'GDPR']
        
        for standard in standards:
            if standard in analysis_text:
                compliance[standard] = "Mentioned in analysis"
        
        return compliance
    
    async def explain_vulnerability(self, vulnerability: Dict) -> str:
        """
        Get detailed explanation of a single vulnerability
        """
        try:
            prompt = f"""Explain this security vulnerability in detail:

**Vulnerability:** {vulnerability['title']}
**Severity:** {vulnerability['severity']}
**Category:** {vulnerability['category']}
**Component:** {vulnerability['component']}
**Details:** {vulnerability['details']}

**PROVIDE:**
1. What this vulnerability means (in plain English)
2. How attackers could exploit it
3. Real-world attack examples
4. Detailed remediation steps
5. Prevention strategies
"""
            
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=1000
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            logger.error(f"Error explaining vulnerability: {e}")
            return "Error generating explanation"
    
    async def generate_remediation_script(self, vulnerabilities: List[Dict]) -> str:
        """
        Generate PowerShell remediation script
        """
        try:
            vuln_list = "\n".join([
                f"- {v['title']} ({v['severity']})"
                for v in vulnerabilities[:10]
            ])
            
            prompt = f"""Generate a PowerShell script to fix these vulnerabilities:

{vuln_list}

**REQUIREMENTS:**
- Safe, production-ready code
- Include error handling
- Create restore point first
- Log all actions
- Require admin privileges check
- Add comments explaining each fix

Generate ONLY the PowerShell script, no explanation.
"""
            
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": "You are a PowerShell and Windows security expert."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,  # Lower temperature for code generation
                max_tokens=2000
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            logger.error(f"Error generating script: {e}")
            return "# Error generating script"


# Global LLM client instance
llm_client = LLMClient()