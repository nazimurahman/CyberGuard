# src/inference/response_parser.py
"""
Response Parser Module for CyberGuard

Handles:
1. Formatting inference results for different output formats
2. Generating human-readable explanations
3. Creating actionable security recommendations
4. Structuring evidence and findings
5. Supporting different presentation formats (JSON, HTML, Markdown, etc.)
"""

import json
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field
from datetime import datetime
import html
from enum import Enum

# Local imports
from . import InferenceResult

# Configure logging
import logging
logger = logging.getLogger(__name__)

class OutputFormat(Enum):
    """Supported output formats"""
    JSON = "json"
    HTML = "html"
    MARKDOWN = "markdown"
    PLAIN_TEXT = "plain_text"
    CSV = "csv"
    XML = "xml"

class SeverityColor(Enum):
    """Color coding for severity levels"""
    CRITICAL = "#dc3545"  # Red
    HIGH = "#fd7e14"      # Orange
    MEDIUM = "#ffc107"    # Yellow
    LOW = "#17a2b8"       # Blue
    INFO = "#6c757d"      # Gray

@dataclass
class SecurityRecommendation:
    """
    Structured security recommendation with actionable items.
    
    Attributes:
        title (str): Short title of the recommendation
        description (str): Detailed description
        priority (str): Implementation priority (CRITICAL, HIGH, MEDIUM, LOW)
        category (str): Security category (authentication, input_validation, etc.)
        action_items (List[str]): Specific actionable steps
        references (List[str]): Reference links or documents
        estimated_effort (str): Estimated implementation effort (LOW, MEDIUM, HIGH)
        risk_reduction (float): Estimated risk reduction (0.0 to 1.0)
    """
    title: str
    description: str
    priority: str = "MEDIUM"
    category: str = "general"
    action_items: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    estimated_effort: str = "MEDIUM"
    risk_reduction: float = 0.5
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'title': self.title,
            'description': self.description,
            'priority': self.priority,
            'category': self.category,
            'action_items': self.action_items,
            'references': self.references,
            'estimated_effort': self.estimated_effort,
            'risk_reduction': self.risk_reduction
        }
    
    def validate(self) -> bool:
        """Validate recommendation"""
        if not self.title or not self.description:
            return False
        
        valid_priorities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        if self.priority not in valid_priorities:
            return False
        
        if not 0.0 <= self.risk_reduction <= 1.0:
            return False
        
        return True

class ResponseParser:
    """
    Main response parser for formatting inference results.
    
    Supports multiple output formats and generates human-readable
    explanations and actionable recommendations.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize response parser.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        
        # Template configurations
        self.templates = self._load_templates()
        
        # Threat type explanations
        self.threat_explanations = self._load_threat_explanations()
        
        # Recommendation templates
        self.recommendation_templates = self._load_recommendation_templates()
        
        logger.info("ResponseParser initialized")
    
    def _load_templates(self) -> Dict[str, Any]:
        """Load output templates"""
        return {
            'json': {
                'pretty': True,
                'indent': 2,
                'sort_keys': True
            },
            'html': {
                'include_css': True,
                'responsive': True,
                'dark_mode': False
            },
            'markdown': {
                'include_toc': True,
                'code_blocks': True
            },
            'plain_text': {
                'line_width': 80,
                'bullet_char': '•'
            }
        }
    
    def _load_threat_explanations(self) -> Dict[str, Dict[str, str]]:
        """Load explanations for different threat types"""
        return {
            'XSS': {
                'what': 'Cross-Site Scripting allows attackers to inject malicious scripts into web pages.',
                'how': 'Attackers inject scripts through user inputs that are not properly sanitized.',
                'impact': 'Can steal session cookies, redirect users, deface websites, or perform actions as the user.',
                'example': 'User enters <script>alert("XSS")</script> in a comment field that gets executed.'
            },
            'SQL_INJECTION': {
                'what': 'SQL Injection allows attackers to execute arbitrary SQL commands on the database.',
                'how': 'Attackers inject SQL code through user inputs that are concatenated into SQL queries.',
                'impact': 'Can read, modify, or delete database data, bypass authentication, or execute administrative operations.',
                'example': "Entering ' OR '1'='1 in a login form to bypass authentication."
            },
            'CSRF': {
                'what': 'Cross-Site Request Forgery tricks users into performing unwanted actions.',
                'how': 'Attackers create malicious requests that are executed when users visit a malicious site.',
                'impact': 'Can perform state-changing actions like transferring funds or changing passwords.',
                'example': 'Image tag with src pointing to banking transfer URL: <img src="https://bank.com/transfer?to=attacker&amount=1000">'
            },
            'SSRF': {
                'what': 'Server-Side Request Forgery forces a server to make requests to internal or external resources.',
                'how': 'Attackers control URL parameters that the server uses to make requests.',
                'impact': 'Can access internal services, scan ports, or attack other systems from the server.',
                'example': 'Requesting http://169.254.169.254/latest/meta-data/ to access AWS metadata.'
            },
            'COMMAND_INJECTION': {
                'what': 'Command Injection allows attackers to execute arbitrary commands on the host system.',
                'how': 'Attackers inject shell commands through user inputs that are passed to system commands.',
                'impact': 'Can execute any command with the privileges of the application.',
                'example': 'Inputting ; rm -rf / in a form field that gets passed to a shell command.'
            },
            'PATH_TRAVERSAL': {
                'what': 'Path Traversal allows attackers to access files outside the web root directory.',
                'how': 'Attackers use ../ sequences to traverse directory structures.',
                'impact': 'Can read sensitive files like /etc/passwd or application source code.',
                'example': 'Accessing ../../../etc/passwd through a file download parameter.'
            },
            'XXE': {
                'what': 'XML External Entity processing allows attackers to read files or cause DoS.',
                'how': 'Attackers inject external entity references in XML documents.',
                'impact': 'Can read local files, perform SSRF, or cause denial of service.',
                'example': 'Injecting <!ENTITY xxe SYSTEM "file:///etc/passwd"> into XML input.'
            },
            'DESERIALIZATION': {
                'what': 'Insecure deserialization allows attackers to execute code during deserialization.',
                'how': 'Attackers craft malicious serialized objects that execute code when deserialized.',
                'impact': 'Can lead to remote code execution, privilege escalation, or denial of service.',
                'example': 'Crafting a malicious pickle object in Python that executes os.system() when deserialized.'
            },
            'IDOR': {
                'what': 'Insecure Direct Object Reference allows attackers to access unauthorized resources.',
                'how': 'Attackers manipulate object references (like IDs) to access other users\' data.',
                'impact': 'Can access, modify, or delete other users\' data.',
                'example': 'Changing /user/profile?id=123 to /user/profile?id=124 to access another user\'s profile.'
            },
            'BROKEN_AUTH': {
                'what': 'Broken Authentication allows attackers to compromise passwords, keys, or session tokens.',
                'how': 'Weak authentication mechanisms allow credential stuffing, session hijacking, or bypass.',
                'impact': 'Can lead to account takeover, unauthorized access, or privilege escalation.',
                'example': 'Using default credentials or weak passwords that can be easily guessed.'
            }
        }
    
    def _load_recommendation_templates(self) -> Dict[str, SecurityRecommendation]:
        """Load template recommendations for different threat types"""
        return {
            'XSS': SecurityRecommendation(
                title="Prevent Cross-Site Scripting (XSS)",
                description="Implement comprehensive XSS protections",
                priority="HIGH",
                category="input_validation",
                action_items=[
                    "Implement Content Security Policy (CSP)",
                    "Use context-aware output encoding",
                    "Validate and sanitize all user inputs",
                    "Use HTTP-only cookies for session management",
                    "Implement XSS filters in WAF"
                ],
                references=[
                    "OWASP XSS Prevention Cheat Sheet",
                    "Content Security Policy Reference"
                ],
                estimated_effort="MEDIUM",
                risk_reduction=0.9
            ),
            'SQL_INJECTION': SecurityRecommendation(
                title="Prevent SQL Injection",
                description="Implement SQL injection protections",
                priority="CRITICAL",
                category="database_security",
                action_items=[
                    "Use parameterized queries or prepared statements",
                    "Implement proper input validation",
                    "Apply principle of least privilege to database accounts",
                    "Use stored procedures with validation",
                    "Implement SQL injection detection in WAF"
                ],
                references=[
                    "OWASP SQL Injection Prevention Cheat Sheet",
                    "Database Security Best Practices"
                ],
                estimated_effort="MEDIUM",
                risk_reduction=0.95
            ),
            'CSRF': SecurityRecommendation(
                title="Prevent Cross-Site Request Forgery (CSRF)",
                description="Implement CSRF protections",
                priority="HIGH",
                category="session_management",
                action_items=[
                    "Implement CSRF tokens for all state-changing requests",
                    "Use SameSite cookie attribute",
                    "Validate Origin and Referer headers",
                    "Implement double-submit cookie pattern",
                    "Use anti-CSRF libraries/frameworks"
                ],
                references=[
                    "OWASP CSRF Prevention Cheat Sheet",
                    "SameSite Cookies Explained"
                ],
                estimated_effort="LOW",
                risk_reduction=0.85
            ),
            'GENERAL': SecurityRecommendation(
                title="General Security Hardening",
                description="Implement defense-in-depth security controls",
                priority="MEDIUM",
                category="general",
                action_items=[
                    "Enable Web Application Firewall (WAF)",
                    "Implement rate limiting on sensitive endpoints",
                    "Enable security headers (CSP, HSTS, etc.)",
                    "Implement comprehensive logging and monitoring",
                    "Conduct regular security testing and code reviews"
                ],
                references=[
                    "OWASP Top 10 Security Risks",
                    "Web Security Best Practices"
                ],
                estimated_effort="HIGH",
                risk_reduction=0.7
            )
        }
    
    def parse(self, result: InferenceResult, 
              format: OutputFormat = OutputFormat.JSON) -> Union[str, Dict[str, Any]]:
        """
        Parse inference result to specified format.
        
        Args:
            result: Inference result to parse
            format: Output format
        
        Returns:
            Formatted result (string or dictionary)
        
        Raises:
            ValueError: If format is not supported
        """
        logger.debug(f"Parsing result to {format.value} format")
        
        # Validate result
        try:
            result.validate()
        except ValueError as e:
            logger.error(f"Invalid inference result: {e}")
            raise
        
        # Parse based on format
        if format == OutputFormat.JSON:
            return self._parse_to_json(result)
        elif format == OutputFormat.HTML:
            return self._parse_to_html(result)
        elif format == OutputFormat.MARKDOWN:
            return self._parse_to_markdown(result)
        elif format == OutputFormat.PLAIN_TEXT:
            return self._parse_to_plain_text(result)
        elif format == OutputFormat.CSV:
            return self._parse_to_csv(result)
        elif format == OutputFormat.XML:
            return self._parse_to_xml(result)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _parse_to_json(self, result: InferenceResult) -> Dict[str, Any]:
        """Parse to JSON format"""
        output = result.to_dict()
        
        # Add additional context
        output['analysis'] = {
            'severity_explanation': self._get_severity_explanation(result.severity),
            'threat_explanation': self._get_threat_explanation(result.threat_type),
            'confidence_interpretation': self._interpret_confidence(result.confidence)
        }
        
        return output
    
    def _parse_to_html(self, result: InferenceResult) -> str:
        """Parse to HTML format"""
        css = self._generate_css()
        
        html_output = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>CyberGuard Security Report</title>
            <style>{css}</style>
        </head>
        <body>
            <div class="container">
                {self._generate_html_header(result)}
                {self._generate_html_summary(result)}
                {self._generate_html_threat_details(result)}
                {self._generate_html_evidence(result)}
                {self._generate_html_recommendations(result)}
                {self._generate_html_footer(result)}
            </div>
        </body>
        </html>
        """
        
        return html_output
    
    def _parse_to_markdown(self, result: InferenceResult) -> str:
        """Parse to Markdown format"""
        md_output = f"""
# 🛡️ CyberGuard Security Report

**Generated**: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
**Model Version**: {result.model_version}

## 📊 Executive Summary

| Metric | Value |
|--------|-------|
| Threat Level | {result.threat_level:.2f} ({result.severity}) |
| Confidence | {result.confidence:.2f} |
| Primary Threat | {result.threat_type} |
| Evidence Items | {len(result.evidence)} |

## 🔍 Threat Analysis

**{result.threat_type}** - {self._get_threat_description(result.threat_type)}

**Severity**: {result.severity} - {self._get_severity_explanation(result.severity)}

**Confidence**: {result.confidence:.2f} ({self._interpret_confidence(result.confidence)})

## 📋 Evidence

{self._generate_markdown_evidence(result)}

## 💡 Recommendations

{self._generate_markdown_recommendations(result)}

## 📝 Metadata

- Analysis Mode: {result.metadata.get('analysis_mode', 'standard')}
- Model Used: {result.metadata.get('model_used', 'unknown')}
- Processing Time: {result.metadata.get('processing_time_ms', 'unknown')}ms

---
*Report generated by CyberGuard Security AI System*
        """
        
        return md_output
    
    def _parse_to_plain_text(self, result: InferenceResult) -> str:
        """Parse to plain text format"""
        text_output = f"""
CYBERGUARD SECURITY REPORT
{'='*60}

Generated: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
Model: {result.model_version}

SUMMARY
{'='*60}
Threat Level: {result.threat_level:.2f} ({result.severity})
Confidence:   {result.confidence:.2f}
Primary Threat: {result.threat_type}
Evidence Items: {len(result.evidence)}

THREAT ANALYSIS
{'='*60}
{result.threat_type}: {self._get_threat_description(result.threat_type)}

Severity: {result.severity}
{self._get_severity_explanation(result.severity)}

Confidence: {self._interpret_confidence(result.confidence)}

EVIDENCE
{'='*60}
{self._generate_plain_text_evidence(result)}

RECOMMENDATIONS
{'='*60}
{self._generate_plain_text_recommendations(result)}

METADATA
{'='*60}
{self._generate_plain_text_metadata(result)}

{'='*60}
CyberGuard Security AI System
        """
        
        return text_output
    
    def _parse_to_csv(self, result: InferenceResult) -> str:
        """Parse to CSV format"""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'timestamp', 'model_version', 'threat_level', 'confidence',
            'threat_type', 'severity', 'evidence_count', 'recommendation_count'
        ])
        
        # Write data
        writer.writerow([
            result.timestamp.isoformat(),
            result.model_version,
            result.threat_level,
            result.confidence,
            result.threat_type,
            result.severity,
            len(result.evidence),
            len(result.recommendations)
        ])
        
        # Write evidence
        writer.writerow([])
        writer.writerow(['EVIDENCE'])
        writer.writerow(['type', 'description', 'severity', 'confidence'])
        for evidence in result.evidence:
            writer.writerow([
                evidence.get('type', ''),
                evidence.get('description', '')[:100],
                evidence.get('severity', ''),
                evidence.get('confidence', 0)
            ])
        
        # Write recommendations
        writer.writerow([])
        writer.writerow(['RECOMMENDATIONS'])
        writer.writerow(['title', 'priority', 'category', 'action_items'])
        for rec in result.recommendations:
            writer.writerow([
                rec.title,
                rec.priority,
                rec.category,
                '; '.join(rec.action_items[:3])
            ])
        
        return output.getvalue()
    
    def _parse_to_xml(self, result: InferenceResult) -> str:
        """Parse to XML format"""
        import xml.etree.ElementTree as ET
        
        root = ET.Element('CyberGuardReport')
        
        # Add metadata
        meta = ET.SubElement(root, 'Metadata')
        ET.SubElement(meta, 'Timestamp').text = result.timestamp.isoformat()
        ET.SubElement(meta, 'ModelVersion').text = result.model_version
        
        # Add summary
        summary = ET.SubElement(root, 'Summary')
        ET.SubElement(summary, 'ThreatLevel').text = str(result.threat_level)
        ET.SubElement(summary, 'Confidence').text = str(result.confidence)
        ET.SubElement(summary, 'ThreatType').text = result.threat_type
        ET.SubElement(summary, 'Severity').text = result.severity
        
        # Add evidence
        evidence_elem = ET.SubElement(root, 'Evidence')
        for ev in result.evidence:
            item = ET.SubElement(evidence_elem, 'Item')
            ET.SubElement(item, 'Type').text = ev.get('type', '')
            ET.SubElement(item, 'Description').text = ev.get('description', '')
            ET.SubElement(item, 'Severity').text = ev.get('severity', '')
            ET.SubElement(item, 'Confidence').text = str(ev.get('confidence', 0))
        
        # Add recommendations
        recs_elem = ET.SubElement(root, 'Recommendations')
        for rec in result.recommendations:
            item = ET.SubElement(recs_elem, 'Recommendation')
            ET.SubElement(item, 'Title').text = rec.title
            ET.SubElement(item, 'Description').text = rec.description
            ET.SubElement(item, 'Priority').text = rec.priority
            ET.SubElement(item, 'Category').text = rec.category
        
        # Convert to string
        return ET.tostring(root, encoding='unicode', method='xml')
    
    def _generate_css(self) -> str:
        """Generate CSS for HTML output"""
        return """
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }
        
        body {
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 30px;
        }
        
        .header {
            text-align: center;
            margin-bottom: 30px;
            border-bottom: 2px solid #007bff;
            padding-bottom: 20px;
        }
        
        .header h1 {
            color: #007bff;
            margin-bottom: 10px;
        }
        
        .summary {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .summary-item {
            text-align: center;
            padding: 15px;
            background: white;
            border-radius: 6px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        
        .summary-value {
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .summary-label {
            font-size: 14px;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .severity-critical { color: #dc3545; }
        .severity-high { color: #fd7e14; }
        .severity-medium { color: #ffc107; }
        .severity-low { color: #17a2b8; }
        .severity-info { color: #6c757d; }
        
        .section {
            margin-bottom: 30px;
        }
        
        .section h2 {
            color: #495057;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid #dee2e6;
        }
        
        .evidence-item, .recommendation-item {
            background: #f8f9fa;
            border-left: 4px solid #007bff;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 4px;
        }
        
        .evidence-type {
            font-weight: bold;
            color: #007bff;
            margin-bottom: 5px;
        }
        
        .evidence-description {
            margin-bottom: 10px;
        }
        
        .evidence-meta {
            font-size: 12px;
            color: #6c757d;
        }
        
        .recommendation-priority {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            margin-right: 10px;
        }
        
        .priority-critical { background: #dc3545; color: white; }
        .priority-high { background: #fd7e14; color: white; }
        .priority-medium { background: #ffc107; }
        .priority-low { background: #17a2b8; color: white; }
        
        .action-items {
            margin-top: 10px;
            padding-left: 20px;
        }
        
        .action-items li {
            margin-bottom: 5px;
        }
        
        .footer {
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
            color: #6c757d;
            font-size: 14px;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 15px;
            }
            
            .summary-grid {
                grid-template-columns: 1fr;
            }
        }
        """
    
    def _generate_html_header(self, result: InferenceResult) -> str:
        """Generate HTML header"""
        severity_class = f"severity-{result.severity.lower()}"
        
        return f"""
        <div class="header">
            <h1>🛡️ CyberGuard Security Report</h1>
            <div class="metadata">
                <p><strong>Generated:</strong> {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Model Version:</strong> {result.model_version}</p>
            </div>
        </div>
        """
    
    def _generate_html_summary(self, result: InferenceResult) -> str:
        """Generate HTML summary section"""
        severity_class = f"severity-{result.severity.lower()}"
        
        return f"""
        <div class="summary">
            <h2>📊 Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="summary-value {severity_class}">{result.threat_level:.2f}</div>
                    <div class="summary-label">Threat Level</div>
                    <div class="summary-subtitle">{result.severity}</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">{result.confidence:.2f}</div>
                    <div class="summary-label">Confidence</div>
                    <div class="summary-subtitle">{self._interpret_confidence(result.confidence)}</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">{result.threat_type}</div>
                    <div class="summary-label">Primary Threat</div>
                    <div class="summary-subtitle">{self._get_threat_description(result.threat_type)}</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">{len(result.evidence)}</div>
                    <div class="summary-label">Evidence Items</div>
                    <div class="summary-subtitle">{len(result.recommendations)} recommendations</div>
                </div>
            </div>
        </div>
        """
    
    def _generate_html_threat_details(self, result: InferenceResult) -> str:
        """Generate HTML threat details section"""
        explanation = self.threat_explanations.get(result.threat_type, {})
        
        return f"""
        <div class="section">
            <h2>🔍 Threat Analysis</h2>
            <div class="threat-details">
                <h3>{result.threat_type}</h3>
                <p><strong>What is it?</strong> {explanation.get('what', 'No description available')}</p>
                <p><strong>How it works:</strong> {explanation.get('how', 'No details available')}</p>
                <p><strong>Potential impact:</strong> {explanation.get('impact', 'No impact information')}</p>
                <p><strong>Example:</strong> <code>{html.escape(explanation.get('example', 'No example'))}</code></p>
                
                <div class="severity-explanation">
                    <h4>Severity: {result.severity}</h4>
                    <p>{self._get_severity_explanation(result.severity)}</p>
                </div>
                
                <div class="confidence-explanation">
                    <h4>Confidence: {result.confidence:.2f}</h4>
                    <p>{self._interpret_confidence(result.confidence)}</p>
                </div>
            </div>
        </div>
        """
    
    def _generate_html_evidence(self, result: InferenceResult) -> str:
        """Generate HTML evidence section"""
        evidence_html = ""
        
        for i, evidence in enumerate(result.evidence[:10], 1):
            severity_class = f"severity-{evidence.get('severity', 'info').lower()}"
            
            evidence_html += f"""
            <div class="evidence-item">
                <div class="evidence-type">{evidence.get('type', 'Unknown')}</div>
                <div class="evidence-description">{html.escape(evidence.get('description', ''))}</div>
                <div class="evidence-meta">
                    <span class="{severity_class}">Severity: {evidence.get('severity', 'Unknown')}</span> | 
                    <span>Confidence: {evidence.get('confidence', 0):.2f}</span>
                </div>
            </div>
            """
        
        return f"""
        <div class="section">
            <h2>📋 Evidence ({len(result.evidence)} items)</h2>
            {evidence_html if evidence_html else '<p>No evidence available.</p>'}
        </div>
        """
    
    def _generate_html_recommendations(self, result: InferenceResult) -> str:
        """Generate HTML recommendations section"""
        recommendations_html = ""
        
        for i, rec in enumerate(result.recommendations[:10], 1):
            priority_class = f"priority-{rec.priority.lower()}"
            
            action_items = ""
            if rec.action_items:
                action_items = "<ul class='action-items'>"
                for action in rec.action_items[:5]:
                    action_items += f"<li>{html.escape(action)}</li>"
                action_items += "</ul>"
            
            recommendations_html += f"""
            <div class="recommendation-item">
                <div class="recommendation-header">
                    <span class="recommendation-priority {priority_class}">{rec.priority}</span>
                    <span class="recommendation-category">{rec.category}</span>
                </div>
                <h3>{html.escape(rec.title)}</h3>
                <p>{html.escape(rec.description)}</p>
                {action_items}
                <div class="recommendation-meta">
                    <span>Effort: {rec.estimated_effort}</span> | 
                    <span>Risk Reduction: {rec.risk_reduction:.0%}</span>
                </div>
            </div>
            """
        
        return f"""
        <div class="section">
            <h2>💡 Recommendations ({len(result.recommendations)} items)</h2>
            {recommendations_html if recommendations_html else '<p>No recommendations available.</p>'}
        </div>
        """
    
    def _generate_html_footer(self, result: InferenceResult) -> str:
        """Generate HTML footer"""
        return """
        <div class="footer">
            <p>Report generated by CyberGuard Security AI System</p>
            <p>For more information, visit the CyberGuard Security Dashboard</p>
        </div>
        """
    
    def _generate_markdown_evidence(self, result: InferenceResult) -> str:
        """Generate Markdown evidence section"""
        evidence_md = ""
        
        for i, evidence in enumerate(result.evidence[:10], 1):
            severity = evidence.get('severity', 'Unknown')
            confidence = evidence.get('confidence', 0)
            
            evidence_md += f"""
### {i}. {evidence.get('type', 'Unknown')}
**Description**: {evidence.get('description', '')}
**Severity**: {severity} | **Confidence**: {confidence:.2f}

"""
        
        return evidence_md
    
    def _generate_markdown_recommendations(self, result: InferenceResult) -> str:
        """Generate Markdown recommendations section"""
        recommendations_md = ""
        
        for i, rec in enumerate(result.recommendations[:10], 1):
            action_items = ""
            if rec.action_items:
                for action in rec.action_items[:5]:
                    action_items += f"  - {action}\n"
            
            recommendations_md += f"""
### {i}. [{rec.priority}] {rec.title}
{rec.description}

**Actions**:
{action_items}
**Category**: {rec.category} | **Effort**: {rec.estimated_effort} | **Risk Reduction**: {rec.risk_reduction:.0%}

"""
        
        return recommendations_md
    
    def _generate_plain_text_evidence(self, result: InferenceResult) -> str:
        """Generate plain text evidence section"""
        evidence_text = ""
        
        for i, evidence in enumerate(result.evidence[:10], 1):
            evidence_text += f"""
{i}. [{evidence.get('type', 'Unknown')}]
    Description: {evidence.get('description', '')}
    Severity: {evidence.get('severity', 'Unknown')}
    Confidence: {evidence.get('confidence', 0):.2f}
"""
        
        return evidence_text
    
    def _generate_plain_text_recommendations(self, result: InferenceResult) -> str:
        """Generate plain text recommendations section"""
        recommendations_text = ""
        
        for i, rec in enumerate(result.recommendations[:10], 1):
            action_items = ""
            if rec.action_items:
                for action in rec.action_items[:5]:
                    action_items += f"    - {action}\n"
            
            recommendations_text += f"""
{i}. [{rec.priority}] {rec.title}
    {rec.description}
    
    Actions:
{action_items}
    Category: {rec.category}
    Effort: {rec.estimated_effort}
    Risk Reduction: {rec.risk_reduction:.0%}
"""
        
        return recommendations_text
    
    def _generate_plain_text_metadata(self, result: InferenceResult) -> str:
        """Generate plain text metadata section"""
        metadata_text = ""
        
        for key, value in result.metadata.items():
            metadata_text += f"{key}: {value}\n"
        
        return metadata_text
    
    def _get_severity_explanation(self, severity: str) -> str:
        """Get explanation for severity level"""
        explanations = {
            'CRITICAL': 'Requires immediate attention. Could lead to complete system compromise.',
            'HIGH': 'High priority. Could lead to significant data loss or system damage.',
            'MEDIUM': 'Should be addressed in a timely manner. Moderate risk to system.',
            'LOW': 'Low priority. Minor risk that should be monitored.',
            'INFO': 'Informational finding. No immediate risk, but good to know.'
        }
        return explanations.get(severity, 'Unknown severity level.')
    
    def _get_threat_description(self, threat_type: str) -> str:
        """Get description for threat type"""
        explanation = self.threat_explanations.get(threat_type, {})
        return explanation.get('what', f'{threat_type} security threat.')
    
    def _get_threat_explanation(self, threat_type: str) -> Dict[str, str]:
        """Get full explanation for threat type"""
        return self.threat_explanations.get(threat_type, {
            'what': 'Unknown threat type',
            'how': 'No information available',
            'impact': 'Unknown impact',
            'example': 'No example available'
        })
    
    def _interpret_confidence(self, confidence: float) -> str:
        """Interpret confidence score"""
        if confidence >= 0.9:
            return 'Very High Confidence'
        elif confidence >= 0.7:
            return 'High Confidence'
        elif confidence >= 0.5:
            return 'Moderate Confidence'
        elif confidence >= 0.3:
            return 'Low Confidence'
        else:
            return 'Very Low Confidence'
    
    def generate_recommendations(self, threat_type: str, 
                                threat_level: float,
                                evidence: List[Dict[str, Any]]) -> List[SecurityRecommendation]:
        """
        Generate security recommendations based on threat analysis.
        
        Args:
            threat_type: Type of threat detected
            threat_level: Threat severity score
            evidence: Supporting evidence
        
        Returns:
            List of SecurityRecommendation objects
        """
        recommendations = []
        
        # Add threat-specific recommendation
        if threat_type in self.recommendation_templates:
            base_rec = self.recommendation_templates[threat_type]
            
            # Customize based on threat level
            if threat_level >= 0.8:
                base_rec.priority = "CRITICAL"
                base_rec.risk_reduction = 0.95
            elif threat_level >= 0.6:
                base_rec.priority = "HIGH"
                base_rec.risk_reduction = 0.85
            
            recommendations.append(base_rec)
        
        # Add general recommendation
        if threat_level >= 0.5:
            general_rec = self.recommendation_templates.get('GENERAL')
            if general_rec:
                # Adjust based on evidence
                if len(evidence) > 5:
                    general_rec.priority = "HIGH"
                    general_rec.description = "Multiple security issues detected. Comprehensive security hardening recommended."
                
                recommendations.append(general_rec)
        
        # Add evidence-based recommendations
        evidence_based = self._generate_evidence_based_recommendations(evidence)
        recommendations.extend(evidence_based)
        
        # Remove duplicates
        unique_recs = []
        seen_titles = set()
        
        for rec in recommendations:
            if rec.title not in seen_titles:
                unique_recs.append(rec)
                seen_titles.add(rec.title)
        
        return unique_recs[:10]  # Limit to 10 recommendations
    
    def _generate_evidence_based_recommendations(self, evidence: List[Dict[str, Any]]) -> List[SecurityRecommendation]:
        """Generate recommendations based on specific evidence"""
        recommendations = []
        
        for ev in evidence[:5]:  # Limit to top 5 evidence items
            ev_type = ev.get('type', '')
            ev_severity = ev.get('severity', 'MEDIUM')
            
            if ev_type == 'MISSING_SECURITY_HEADERS':
                rec = SecurityRecommendation(
                    title="Implement Security Headers",
                    description="Missing critical security headers that protect against common web attacks.",
                    priority=ev_severity,
                    category="http_security",
                    action_items=[
                        "Implement Content-Security-Policy (CSP)",
                        "Add X-Frame-Options to prevent clickjacking",
                        "Enable X-Content-Type-Options to prevent MIME sniffing",
                        "Add X-XSS-Protection header",
                        "Implement Strict-Transport-Security (HSTS)"
                    ],
                    estimated_effort="LOW",
                    risk_reduction=0.7
                )
                recommendations.append(rec)
            
            elif ev_type == 'INSECURE_COOKIE':
                rec = SecurityRecommendation(
                    title="Secure Cookie Configuration",
                    description="Insecure cookie configuration detected.",
                    priority="HIGH",
                    category="session_management",
                    action_items=[
                        "Set Secure flag on all cookies",
                        "Set HttpOnly flag on session cookies",
                        "Implement SameSite cookie attribute",
                        "Use short session timeouts",
                        "Regenerate session IDs after login"
                    ],
                    estimated_effort="LOW",
                    risk_reduction=0.8
                )
                recommendations.append(rec)
        
        return recommendations
    
    def get_formats_supported(self) -> List[str]:
        """Get list of supported output formats"""
        return [fmt.value for fmt in OutputFormat]

# Utility function for quick parsing
def parse_result(result: InferenceResult, format: str = "json") -> Union[str, Dict[str, Any]]:
    """
    Quick utility function to parse inference result.
    
    Args:
        result: Inference result
        format: Output format (json, html, markdown, plain_text)
    
    Returns:
        Parsed result in specified format
    """
    parser = ResponseParser()
    
    try:
        output_format = OutputFormat(format.lower())
        return parser.parse(result, output_format)
    except ValueError:
        # Default to JSON
        return parser.parse(result, OutputFormat.JSON)