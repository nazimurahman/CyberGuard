# src/inference/response_parser.py
"""
Response Parser Module for CyberGuard

This module handles the transformation of inference results into various output formats.
It provides:
1. Formatting inference results for different output formats (JSON, HTML, Markdown, etc.)
2. Generating human-readable explanations for security findings
3. Creating actionable security recommendations with priorities and effort estimates
4. Structuring evidence and findings in a consistent format
5. Supporting multiple presentation formats for different use cases
"""

import json
import logging
import csv
import io
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field
from datetime import datetime
import html
from enum import Enum

# Configure logging for the module
logger = logging.getLogger(__name__)

class OutputFormat(Enum):
    """
    Enumeration of all supported output formats for the response parser.
    Each format serves different use cases:
    - JSON: For API responses and machine consumption
    - HTML: For web-based reporting and dashboards
    - Markdown: For documentation and version-controlled reports
    - Plain Text: For command-line interfaces and logs
    - CSV: For spreadsheet analysis and data processing
    - XML: For legacy systems and SOAP APIs
    """
    JSON = "json"           # Structured format for APIs and data exchange
    HTML = "html"           # Web-friendly format with styling
    MARKDOWN = "markdown"   # Documentation-friendly format
    PLAIN_TEXT = "plain_text"  # Simple text format for terminals
    CSV = "csv"             # Tabular format for spreadsheets
    XML = "xml"             # Structured format for legacy systems

class SeverityColor(Enum):
    """
    Color codes mapped to severity levels for visualization purposes.
    These colors follow standard security industry conventions:
    - CRITICAL: Red for immediate attention needed
    - HIGH: Orange for urgent issues
    - MEDIUM: Yellow for important issues
    - LOW: Blue for informational issues
    - INFO: Gray for general information
    """
    CRITICAL = "#dc3545"  # Red - requires immediate action
    HIGH = "#fd7e14"      # Orange - requires urgent attention
    MEDIUM = "#ffc107"    # Yellow - requires attention soon
    LOW = "#17a2b8"       # Blue - informational, monitor
    INFO = "#6c757d"      # Gray - general information only

@dataclass
class SecurityRecommendation:
    """
    Data class representing a structured security recommendation.
    Each recommendation includes:
    - Actionable title and description
    - Priority level for triaging
    - Category for organizing similar recommendations
    - Specific action items for implementation
    - References for further learning
    - Effort estimation for planning
    - Risk reduction percentage for ROI calculation
    
    This structured approach ensures recommendations are specific, measurable,
    and actionable for security teams.
    """
    title: str                      # Short, descriptive title of recommendation
    description: str                # Detailed explanation of recommendation
    priority: str = "MEDIUM"        # Priority level: CRITICAL, HIGH, MEDIUM, LOW
    category: str = "general"       # Category for grouping: input_validation, session_management, etc.
    action_items: List[str] = field(default_factory=list)  # Specific steps to implement
    references: List[str] = field(default_factory=list)    # External references for guidance
    estimated_effort: str = "MEDIUM"  # Implementation effort: LOW, MEDIUM, HIGH
    risk_reduction: float = 0.5     # Estimated risk reduction (0.0 to 1.0)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the recommendation object to a dictionary for serialization.
        This enables the recommendation to be easily converted to JSON, YAML, etc.
        
        Returns:
            Dictionary representation of the recommendation
        """
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
        """
        Validate the recommendation data for correctness and completeness.
        Ensures all required fields are present and values are within valid ranges.
        
        Returns:
            True if valid, False otherwise
        """
        # Check required fields
        if not self.title or not self.description:
            logger.warning("Recommendation missing title or description")
            return False
        
        # Validate priority value
        valid_priorities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        if self.priority not in valid_priorities:
            logger.warning(f"Invalid priority '{self.priority}'. Must be one of {valid_priorities}")
            return False
        
        # Validate risk reduction is within 0-1 range
        if not 0.0 <= self.risk_reduction <= 1.0:
            logger.warning(f"Risk reduction {self.risk_reduction} must be between 0.0 and 1.0")
            return False
        
        # Validate effort estimation
        valid_efforts = ["LOW", "MEDIUM", "HIGH"]
        if self.estimated_effort not in valid_efforts:
            logger.warning(f"Invalid estimated effort '{self.estimated_effort}'. Must be one of {valid_efforts}")
            return False
        
        return True

class ResponseParser:
    """
    Main parser class for formatting inference results into various output formats.
    
    Responsibilities:
    1. Convert raw inference results to human-readable formats
    2. Generate actionable security recommendations
    3. Create structured reports with evidence and findings
    4. Support multiple output formats for different audiences
    5. Provide consistent formatting and styling
    
    The parser uses templates and configuration to customize output
    based on user needs and system requirements.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the response parser with configuration and templates.
        
        Args:
            config: Optional configuration dictionary for customizing parser behavior.
                   Can include format-specific settings, styling preferences, etc.
        """
        # Store configuration or use empty dictionary as default
        self.config = config or {}
        
        # Load templates for different output formats and content types
        self.templates = self._load_templates()  # Formatting templates
        self.threat_explanations = self._load_threat_explanations()  # Threat descriptions
        self.recommendation_templates = self._load_recommendation_templates()  # Recommendation templates
        
        logger.info("ResponseParser initialized with configuration")

    def _load_templates(self) -> Dict[str, Any]:
        """
        Load configuration templates for different output formats.
        These templates control formatting options like indentation,
        styling, and feature toggles for each output format.
        
        Returns:
            Dictionary of template configurations for each format
        """
        return {
            'json': {
                'pretty': True,      # Enable pretty printing with indentation
                'indent': 2,         # Number of spaces for indentation
                'sort_keys': True,   # Sort dictionary keys alphabetically
                'ensure_ascii': False  # Allow Unicode characters
            },
            'html': {
                'include_css': True,   # Include CSS styles in HTML output
                'responsive': True,    # Use responsive design for mobile
                'dark_mode': False,    # Enable/disable dark mode
                'collapsible_sections': True  # Make sections collapsible
            },
            'markdown': {
                'include_toc': True,   # Include table of contents
                'code_blocks': True,   # Enable syntax highlighting for code
                'escape_html': True    # Escape HTML tags in markdown
            },
            'plain_text': {
                'line_width': 80,      # Maximum line width for wrapping
                'bullet_char': '•',    # Character for bullet points
                'header_char': '='     # Character for section headers
            },
            'csv': {
                'delimiter': ',',      # CSV field delimiter
                'quote_all': True      # Quote all fields in CSV
            },
            'xml': {
                'pretty_print': True,  # Pretty print XML with indentation
                'encoding': 'UTF-8'    # XML document encoding
            }
        }
    
    def _load_threat_explanations(self) -> Dict[str, Dict[str, str]]:
        """
        Load detailed explanations for different security threat types.
        Each threat explanation includes:
        - What: Brief description of the threat
        - How: Explanation of how the attack works
        - Impact: Potential consequences if exploited
        - Example: Concrete example of the vulnerability
        
        These explanations help users understand the security findings
        without requiring deep security expertise.
        
        Returns:
            Dictionary of threat explanations keyed by threat type
        """
        return {
            'XSS': {
                'what': 'Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other users.',
                'how': 'Attackers inject scripts through user inputs that are not properly sanitized before being rendered.',
                'impact': 'Can steal session cookies, redirect users to malicious sites, deface websites, or perform actions on behalf of users.',
                'example': 'User enters <script>alert("XSS")</script> in a comment field that gets executed when displayed.'
            },
            'SQL_INJECTION': {
                'what': 'SQL Injection allows attackers to execute arbitrary SQL commands on the database.',
                'how': 'Attackers inject SQL code through user inputs that are concatenated into SQL queries without proper escaping.',
                'impact': 'Can read, modify, or delete database data, bypass authentication, or execute administrative operations.',
                'example': "Entering ' OR '1'='1 in a login form to bypass authentication."
            },
            'CSRF': {
                'what': 'Cross-Site Request Forgery (CSRF) tricks users into performing unwanted actions on web applications.',
                'how': 'Attackers create malicious requests that are automatically executed when users visit a malicious site while authenticated.',
                'impact': 'Can perform state-changing actions like transferring funds, changing passwords, or making purchases.',
                'example': 'Image tag with src pointing to banking transfer URL: <img src="https://bank.com/transfer?to=attacker&amount=1000">'
            },
            'SSRF': {
                'what': 'Server-Side Request Forgery (SSRF) forces a server to make requests to internal or external resources.',
                'how': 'Attackers control URL parameters that the server uses to make HTTP requests to internal services.',
                'impact': 'Can access internal services, scan ports, or attack other systems from the server perspective.',
                'example': 'Requesting http://169.254.169.254/latest/meta-data/ to access AWS metadata service.'
            },
            'COMMAND_INJECTION': {
                'what': 'Command Injection allows attackers to execute arbitrary commands on the host operating system.',
                'how': 'Attackers inject shell commands through user inputs that are passed to system commands without proper validation.',
                'impact': 'Can execute any command with the privileges of the vulnerable application, potentially leading to full system compromise.',
                'example': 'Inputting ; rm -rf / in a form field that gets passed to a shell command.'
            },
            'PATH_TRAVERSAL': {
                'what': 'Path Traversal (Directory Traversal) allows attackers to access files outside the web root directory.',
                'how': 'Attackers use ../ sequences or absolute paths to traverse directory structures.',
                'impact': 'Can read sensitive files like /etc/passwd, application source code, or configuration files.',
                'example': 'Accessing ../../../etc/passwd through a file download parameter.'
            },
            'XXE': {
                'what': 'XML External Entity (XXE) processing allows attackers to read local files or cause denial of service.',
                'how': 'Attackers inject external entity references in XML documents that are processed by vulnerable parsers.',
                'impact': 'Can read local files, perform SSRF attacks, or cause denial of service through billion laughs attack.',
                'example': 'Injecting <!ENTITY xxe SYSTEM "file:///etc/passwd"> into XML input.'
            },
            'DESERIALIZATION': {
                'what': 'Insecure deserialization allows attackers to execute arbitrary code during object deserialization.',
                'how': 'Attackers craft malicious serialized objects that execute code when deserialized by vulnerable applications.',
                'impact': 'Can lead to remote code execution, privilege escalation, or denial of service.',
                'example': 'Crafting a malicious pickle object in Python that executes os.system() when deserialized.'
            },
            'IDOR': {
                'what': 'Insecure Direct Object Reference (IDOR) allows attackers to access unauthorized resources.',
                'how': 'Attackers manipulate object references (like IDs or filenames) to access other users data.',
                'impact': 'Can access, modify, or delete other users data, leading to data breaches.',
                'example': 'Changing /user/profile?id=123 to /user/profile?id=124 to access another users profile.'
            },
            'BROKEN_AUTH': {
                'what': 'Broken Authentication allows attackers to compromise passwords, keys, or session tokens.',
                'how': 'Weak authentication mechanisms allow credential stuffing, session hijacking, or authentication bypass.',
                'impact': 'Can lead to account takeover, unauthorized access, or privilege escalation.',
                'example': 'Using default credentials (admin/admin) or weak passwords that can be easily guessed.'
            },
            'DEFAULT_CREDENTIALS': {
                'what': 'Default or weak credentials that can be easily guessed or are publicly known.',
                'how': 'Attackers use common default credentials, dictionary attacks, or brute force to gain access.',
                'impact': 'Unauthorized access to systems, data exposure, or complete system compromise.',
                'example': 'Using admin/password or root/123456 to access administrative interfaces.'
            }
        }
    
    def _load_recommendation_templates(self) -> Dict[str, SecurityRecommendation]:
        """
        Load pre-defined security recommendation templates for common threat types.
        These templates provide standardized, proven security recommendations
        that can be customized based on specific findings.
        
        Returns:
            Dictionary of SecurityRecommendation objects keyed by threat type
        """
        return {
            'XSS': SecurityRecommendation(
                title="Prevent Cross-Site Scripting (XSS) Attacks",
                description="Implement comprehensive XSS protections to prevent script injection attacks through proper input handling and output encoding.",
                priority="HIGH",
                category="input_validation",
                action_items=[
                    "Implement Content Security Policy (CSP) with appropriate directives",
                    "Use context-aware output encoding for all user-controlled data",
                    "Validate and sanitize all user inputs using allow-list approach",
                    "Use HTTP-only and Secure flags for session cookies",
                    "Implement XSS filters in Web Application Firewall (WAF)"
                ],
                references=[
                    "OWASP XSS Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                    "Content Security Policy Reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
                ],
                estimated_effort="MEDIUM",
                risk_reduction=0.9
            ),
            'SQL_INJECTION': SecurityRecommendation(
                title="Prevent SQL Injection Attacks",
                description="Implement SQL injection protections to secure database interactions through parameterized queries and proper input validation.",
                priority="CRITICAL",
                category="database_security",
                action_items=[
                    "Use parameterized queries or prepared statements for all database operations",
                    "Implement strict input validation using allow-lists",
                    "Apply principle of least privilege to database accounts",
                    "Use stored procedures with parameter validation",
                    "Implement SQL injection detection rules in WAF"
                ],
                references=[
                    "OWASP SQL Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                    "Database Security Best Practices Guide"
                ],
                estimated_effort="MEDIUM",
                risk_reduction=0.95
            ),
            'CSRF': SecurityRecommendation(
                title="Prevent Cross-Site Request Forgery (CSRF)",
                description="Implement CSRF protections to prevent unauthorized state-changing requests through token validation and same-site cookies.",
                priority="HIGH",
                category="session_management",
                action_items=[
                    "Implement CSRF tokens for all state-changing HTTP requests",
                    "Use SameSite cookie attribute with Strict or Lax setting",
                    "Validate Origin and Referer headers for sensitive requests",
                    "Implement double-submit cookie pattern for additional protection",
                    "Use anti-CSRF libraries provided by your framework"
                ],
                references=[
                    "OWASP CSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                    "SameSite Cookies Explained: https://web.dev/samesite-cookies-explained/"
                ],
                estimated_effort="LOW",
                risk_reduction=0.85
            ),
            'GENERAL': SecurityRecommendation(
                title="General Security Hardening and Best Practices",
                description="Implement defense-in-depth security controls for comprehensive protection across multiple layers.",
                priority="MEDIUM",
                category="general",
                action_items=[
                    "Enable and configure Web Application Firewall (WAF) with appropriate rules",
                    "Implement rate limiting on sensitive endpoints and authentication",
                    "Enable security headers (CSP, HSTS, X-Frame-Options, etc.)",
                    "Implement comprehensive logging and monitoring with alerting",
                    "Conduct regular security testing, code reviews, and penetration testing"
                ],
                references=[
                    "OWASP Top 10 Security Risks: https://owasp.org/www-project-top-ten/",
                    "Web Security Best Practices: https://developer.mozilla.org/en-US/docs/Web/Security"
                ],
                estimated_effort="HIGH",
                risk_reduction=0.7
            ),
            'DEFAULT_CREDENTIALS': SecurityRecommendation(
                title="Eliminate Default and Weak Credentials",
                description="Remove or change default credentials and enforce strong password policies to prevent unauthorized access.",
                priority="CRITICAL",
                category="authentication",
                action_items=[
                    "Change all default passwords and usernames immediately",
                    "Implement strong password policies (min 12 chars, complexity)",
                    "Enable multi-factor authentication for all privileged accounts",
                    "Use password managers and avoid password reuse",
                    "Regularly audit and rotate credentials"
                ],
                references=[
                    "NIST Password Guidelines: https://pages.nist.gov/800-63-3/sp800-63b.html",
                    "OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
                ],
                estimated_effort="LOW",
                risk_reduction=0.9
            )
        }
    
    def parse(self, result: Any, format: OutputFormat = OutputFormat.JSON) -> Union[str, Dict[str, Any]]:
        """
        Main method to parse inference result into specified output format.
        
        Args:
            result: The inference result object containing security findings.
                   Expected to have methods: validate(), to_dict()
            format: Desired output format as OutputFormat enum value
        
        Returns:
            Formatted result as string (for text formats) or dict (for JSON)
        
        Raises:
            ValueError: If the format is not supported or result is invalid
            TypeError: If result object doesn't have required methods
        """
        logger.debug(f"Parsing result to {format.value} format")
        
        try:
            # Validate the input result has required methods
            if not hasattr(result, 'validate') or not hasattr(result, 'to_dict'):
                raise TypeError("Result object must have validate() and to_dict() methods")
            
            # Validate the input result data before processing
            result.validate()
        except (ValueError, AttributeError, TypeError) as e:
            logger.error(f"Invalid inference result: {e}")
            raise ValueError(f"Invalid inference result: {e}")
        
        # Route to appropriate formatter based on requested format
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
            # This should never happen with enum, but included for completeness
            supported_formats = self.get_formats_supported()
            raise ValueError(f"Unsupported format: {format}. Supported formats: {supported_formats}")
    
    def _parse_to_json(self, result: Any) -> Dict[str, Any]:
        """
        Convert inference result to structured JSON-compatible dictionary.
        
        Args:
            result: Inference result object
        
        Returns:
            Dictionary ready for JSON serialization
        """
        # Start with the basic result dictionary
        output = result.to_dict()
        
        # Enhance with additional analysis context for better understanding
        output['analysis'] = {
            'severity_explanation': self._get_severity_explanation(getattr(result, 'severity', 'INFO')),
            'threat_explanation': self._get_threat_explanation(getattr(result, 'threat_type', 'UNKNOWN')),
            'confidence_interpretation': self._interpret_confidence(getattr(result, 'confidence', 0.5)),
            'report_generated': datetime.now().isoformat(),
            'parser_version': '1.0.0'
        }
        
        # Apply JSON formatting options from templates if needed
        # (Note: The actual JSON serialization with options happens outside this method)
        return output
    
    def _parse_to_html(self, result: Any) -> str:
        """
        Generate complete HTML report from inference result.
        Creates a self-contained HTML document with embedded CSS for easy sharing.
        
        Args:
            result: Inference result object
        
        Returns:
            Complete HTML document as string
        """
        # Generate CSS styles for the report
        css = self._generate_css()
        
        # Build the complete HTML document with all sections
        html_output = f"""<!DOCTYPE html>
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
</html>"""
        
        return html_output
    
    def _parse_to_markdown(self, result: Any) -> str:
        """
        Generate Markdown formatted report from inference result.
        Markdown is ideal for documentation, version control, and plain text readability.
        
        Args:
            result: Inference result object
        
        Returns:
            Markdown formatted report as string
        """
        # Get result attributes with safe defaults
        timestamp = getattr(result, 'timestamp', datetime.now())
        model_version = getattr(result, 'model_version', 'unknown')
        threat_level = getattr(result, 'threat_level', 0.0)
        confidence = getattr(result, 'confidence', 0.0)
        threat_type = getattr(result, 'threat_type', 'UNKNOWN')
        severity = getattr(result, 'severity', 'INFO')
        evidence = getattr(result, 'evidence', [])
        recommendations = getattr(result, 'recommendations', [])
        metadata = getattr(result, 'metadata', {})
        
        # Format timestamp if it's a datetime object
        if isinstance(timestamp, datetime):
            timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
        else:
            timestamp_str = str(timestamp)
        
        # Generate the complete markdown report
        md_output = f"""# CyberGuard Security Report

**Generated**: {timestamp_str}
**Model Version**: {model_version}

## Executive Summary

| Metric | Value |
|--------|-------|
| Threat Level | {threat_level:.2f} ({severity}) |
| Confidence | {confidence:.2f} |
| Primary Threat | {threat_type} |
| Evidence Items | {len(evidence)} |
| Recommendations | {len(recommendations)} |

## Threat Analysis

**{threat_type}** - {self._get_threat_description(threat_type)}

**Severity**: {severity} - {self._get_severity_explanation(severity)}

**Confidence**: {confidence:.2f} ({self._interpret_confidence(confidence)})

## Evidence

{self._generate_markdown_evidence(result)}

## Recommendations

{self._generate_markdown_recommendations(result)}

## Metadata

{self._generate_markdown_metadata(result)}

---
*Report generated by CyberGuard Security AI System*"""
        
        return md_output
    
    def _parse_to_plain_text(self, result: Any) -> str:
        """
        Generate plain text report from inference result.
        Plain text is ideal for command-line output, logs, and email notifications.
        
        Args:
            result: Inference result object
        
        Returns:
            Plain text formatted report as string
        """
        # Get result attributes with safe defaults
        timestamp = getattr(result, 'timestamp', datetime.now())
        model_version = getattr(result, 'model_version', 'unknown')
        threat_level = getattr(result, 'threat_level', 0.0)
        confidence = getattr(result, 'confidence', 0.0)
        threat_type = getattr(result, 'threat_type', 'UNKNOWN')
        severity = getattr(result, 'severity', 'INFO')
        evidence = getattr(result, 'evidence', [])
        recommendations = getattr(result, 'recommendations', [])
        metadata = getattr(result, 'metadata', {})
        
        # Format timestamp if it's a datetime object
        if isinstance(timestamp, datetime):
            timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
        else:
            timestamp_str = str(timestamp)
        
        # Get plain text formatting options
        header_char = self.templates['plain_text']['header_char']
        line_width = min(80, self.templates['plain_text']['line_width'])
        
        # Generate the complete plain text report
        text_output = f"""
CYBERGUARD SECURITY REPORT
{header_char * line_width}

Generated: {timestamp_str}
Model: {model_version}

SUMMARY
{header_char * line_width}
Threat Level: {threat_level:.2f} ({severity})
Confidence:   {confidence:.2f}
Primary Threat: {threat_type}
Evidence Items: {len(evidence)}
Recommendations: {len(recommendations)}

THREAT ANALYSIS
{header_char * line_width}
{threat_type}: {self._get_threat_description(threat_type)}

Severity: {severity}
{self._get_severity_explanation(severity)}

Confidence: {self._interpret_confidence(confidence)}

EVIDENCE
{header_char * line_width}
{self._generate_plain_text_evidence(result)}

RECOMMENDATIONS
{header_char * line_width}
{self._generate_plain_text_recommendations(result)}

METADATA
{header_char * line_width}
{self._generate_plain_text_metadata(result)}

{header_char * line_width}
CyberGuard Security AI System
        """
        
        return text_output
    
    def _parse_to_csv(self, result: Any) -> str:
        """
        Generate CSV formatted report from inference result.
        CSV format is ideal for spreadsheet analysis, data processing, and bulk operations.
        
        Args:
            result: Inference result object
        
        Returns:
            CSV formatted report as string
        """
        # Get result attributes with safe defaults
        timestamp = getattr(result, 'timestamp', datetime.now())
        model_version = getattr(result, 'model_version', 'unknown')
        threat_level = getattr(result, 'threat_level', 0.0)
        confidence = getattr(result, 'confidence', 0.0)
        threat_type = getattr(result, 'threat_type', 'UNKNOWN')
        severity = getattr(result, 'severity', 'INFO')
        evidence = getattr(result, 'evidence', [])
        recommendations = getattr(result, 'recommendations', [])
        
        # Create StringIO buffer for CSV output
        output = io.StringIO()
        writer = csv.writer(output, delimiter=self.templates['csv']['delimiter'])
        
        # Write main summary header
        writer.writerow([
            'timestamp', 'model_version', 'threat_level', 'confidence',
            'threat_type', 'severity', 'evidence_count', 'recommendation_count'
        ])
        
        # Format timestamp for CSV
        if isinstance(timestamp, datetime):
            timestamp_str = timestamp.isoformat()
        else:
            timestamp_str = str(timestamp)
        
        # Write main data row
        writer.writerow([
            timestamp_str,
            model_version,
            threat_level,
            confidence,
            threat_type,
            severity,
            len(evidence),
            len(recommendations)
        ])
        
        # Write evidence section with separator
        writer.writerow([])  # Empty row for separation
        writer.writerow(['EVIDENCE'])
        writer.writerow(['type', 'description', 'severity', 'confidence'])
        
        for evidence_item in evidence[:20]:  # Limit to 20 items for readability
            # Safely get evidence attributes
            if isinstance(evidence_item, dict):
                ev_type = evidence_item.get('type', '')
                description = evidence_item.get('description', '')
                ev_severity = evidence_item.get('severity', '')
                ev_confidence = evidence_item.get('confidence', 0)
            else:
                # Try to get attributes if it's an object
                ev_type = getattr(evidence_item, 'type', '')
                description = getattr(evidence_item, 'description', '')
                ev_severity = getattr(evidence_item, 'severity', '')
                ev_confidence = getattr(evidence_item, 'confidence', 0)
            
            # Truncate long descriptions for CSV
            if len(description) > 200:
                description = description[:197] + "..."
            
            writer.writerow([
                ev_type,
                description,
                ev_severity,
                ev_confidence
            ])
        
        # Write recommendations section
        writer.writerow([])  # Empty row for separation
        writer.writerow(['RECOMMENDATIONS'])
        writer.writerow(['title', 'priority', 'category', 'action_items', 'estimated_effort', 'risk_reduction'])
        
        for rec in recommendations[:20]:  # Limit to 20 recommendations
            # Handle both SecurityRecommendation objects and dictionaries
            if hasattr(rec, 'to_dict'):
                # It's a SecurityRecommendation object
                rec_dict = rec.to_dict()
                title = rec_dict['title']
                priority = rec_dict['priority']
                category = rec_dict['category']
                action_items = rec_dict['action_items']
                estimated_effort = rec_dict['estimated_effort']
                risk_reduction = rec_dict['risk_reduction']
            elif isinstance(rec, dict):
                # It's a dictionary
                title = rec.get('title', '')
                priority = rec.get('priority', 'MEDIUM')
                category = rec.get('category', 'general')
                action_items = rec.get('action_items', [])
                estimated_effort = rec.get('estimated_effort', 'MEDIUM')
                risk_reduction = rec.get('risk_reduction', 0.5)
            else:
                # Unknown type, skip
                continue
            
            # Format action items as semicolon-separated string
            action_items_str = '; '.join(str(item) for item in action_items[:3])  # Limit to 3 items
            
            writer.writerow([
                title[:100],  # Truncate long titles
                priority,
                category,
                action_items_str,
                estimated_effort,
                f"{risk_reduction:.0%}"
            ])
        
        return output.getvalue()
    
    def _parse_to_xml(self, result: Any) -> str:
        """
        Generate XML formatted report from inference result.
        XML format is useful for legacy systems, SOAP APIs, and structured data exchange.
        
        Args:
            result: Inference result object
        
        Returns:
            XML formatted report as string
        """
        # Create root element
        root = ET.Element('CyberGuardReport')
        
        # Add metadata section
        meta = ET.SubElement(root, 'Metadata')
        
        # Format timestamp
        timestamp = getattr(result, 'timestamp', datetime.now())
        if isinstance(timestamp, datetime):
            timestamp_text = timestamp.isoformat()
        else:
            timestamp_text = str(timestamp)
        
        ET.SubElement(meta, 'Timestamp').text = timestamp_text
        ET.SubElement(meta, 'ModelVersion').text = getattr(result, 'model_version', 'unknown')
        ET.SubElement(meta, 'ReportGenerated').text = datetime.now().isoformat()
        
        # Add summary section
        summary = ET.SubElement(root, 'Summary')
        ET.SubElement(summary, 'ThreatLevel').text = str(getattr(result, 'threat_level', 0.0))
        ET.SubElement(summary, 'Confidence').text = str(getattr(result, 'confidence', 0.0))
        ET.SubElement(summary, 'ThreatType').text = getattr(result, 'threat_type', 'UNKNOWN')
        ET.SubElement(summary, 'Severity').text = getattr(result, 'severity', 'INFO')
        ET.SubElement(summary, 'EvidenceCount').text = str(len(getattr(result, 'evidence', [])))
        ET.SubElement(summary, 'RecommendationCount').text = str(len(getattr(result, 'recommendations', [])))
        
        # Add threat analysis section
        analysis = ET.SubElement(root, 'ThreatAnalysis')
        ET.SubElement(analysis, 'Description').text = self._get_threat_description(getattr(result, 'threat_type', 'UNKNOWN'))
        ET.SubElement(analysis, 'SeverityExplanation').text = self._get_severity_explanation(getattr(result, 'severity', 'INFO'))
        ET.SubElement(analysis, 'ConfidenceInterpretation').text = self._interpret_confidence(getattr(result, 'confidence', 0.0))
        
        # Add evidence section
        evidence_elem = ET.SubElement(root, 'Evidence')
        evidence_list = getattr(result, 'evidence', [])
        
        for i, ev in enumerate(evidence_list[:50], 1):  # Limit to 50 items
            item = ET.SubElement(evidence_elem, 'Item')
            item.set('id', str(i))
            
            # Safely extract evidence attributes
            if isinstance(ev, dict):
                ev_type = ev.get('type', '')
                description = ev.get('description', '')
                ev_severity = ev.get('severity', '')
                ev_confidence = ev.get('confidence', 0)
            else:
                ev_type = getattr(ev, 'type', '')
                description = getattr(ev, 'description', '')
                ev_severity = getattr(ev, 'severity', '')
                ev_confidence = getattr(ev, 'confidence', 0)
            
            ET.SubElement(item, 'Type').text = ev_type
            ET.SubElement(item, 'Description').text = description
            ET.SubElement(item, 'Severity').text = ev_severity
            ET.SubElement(item, 'Confidence').text = str(ev_confidence)
        
        # Add recommendations section
        recs_elem = ET.SubElement(root, 'Recommendations')
        recommendations_list = getattr(result, 'recommendations', [])
        
        for i, rec in enumerate(recommendations_list[:20], 1):  # Limit to 20 recommendations
            item = ET.SubElement(recs_elem, 'Recommendation')
            item.set('id', str(i))
            
            # Safely extract recommendation attributes
            if hasattr(rec, 'to_dict'):
                rec_dict = rec.to_dict()
                title = rec_dict['title']
                description = rec_dict['description']
                priority = rec_dict['priority']
                category = rec_dict['category']
                action_items = rec_dict['action_items']
            elif isinstance(rec, dict):
                title = rec.get('title', '')
                description = rec.get('description', '')
                priority = rec.get('priority', 'MEDIUM')
                category = rec.get('category', 'general')
                action_items = rec.get('action_items', [])
            else:
                # Skip unknown types
                continue
            
            ET.SubElement(item, 'Title').text = title
            ET.SubElement(item, 'Description').text = description
            ET.SubElement(item, 'Priority').text = priority
            ET.SubElement(item, 'Category').text = category
            
            # Add action items as sub-elements
            actions_elem = ET.SubElement(item, 'ActionItems')
            for action in action_items[:5]:  # Limit to 5 action items
                ET.SubElement(actions_elem, 'Action').text = str(action)
        
        # Convert XML tree to string with pretty printing if enabled
        if self.templates['xml']['pretty_print']:
            # Import here to avoid circular imports
            from xml.dom import minidom
            rough_string = ET.tostring(root, encoding='unicode')
            reparsed = minidom.parseString(rough_string)
            return reparsed.toprettyxml(indent="  ")
        else:
            return ET.tostring(root, encoding='unicode', method='xml')
    
    def _generate_css(self) -> str:
        """
        Generate CSS styles for HTML report.
        Creates a responsive, accessible design with proper color coding for severity levels.
        
        Returns:
            CSS styles as string
        """
        return """
        /* Reset and base styles */
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
        }
        
        body {
            background: #f8f9fa;
            color: #212529;
            line-height: 1.6;
            padding: 20px;
            font-size: 16px;
        }
        
        /* Container for report content */
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
            padding: 40px;
            overflow: hidden;
        }
        
        /* Header section */
        .header {
            text-align: center;
            margin-bottom: 40px;
            padding-bottom: 25px;
            border-bottom: 3px solid #007bff;
            background: linear-gradient(135deg, #007bff 0%, #0056b3 100%);
            color: white;
            padding: 30px;
            margin: -40px -40px 40px -40px;
            border-radius: 12px 12px 0 0;
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 15px;
            font-weight: 700;
        }
        
        .metadata {
            font-size: 0.95rem;
            opacity: 0.9;
        }
        
        .metadata p {
            margin: 5px 0;
        }
        
        /* Summary section */
        .summary {
            background: #f1f8ff;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 40px;
            border: 1px solid #d1e7ff;
        }
        
        .summary h2 {
            color: #0056b3;
            margin-bottom: 20px;
            font-size: 1.8rem;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 25px;
            margin-top: 20px;
        }
        
        .summary-item {
            text-align: center;
            padding: 20px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }
        
        .summary-item:hover {
            transform: translateY(-3px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }
        
        .summary-value {
            font-size: 2.2rem;
            font-weight: 700;
            margin-bottom: 8px;
            line-height: 1;
        }
        
        .summary-label {
            font-size: 0.9rem;
            color: #6c757d;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
            margin-bottom: 5px;
        }
        
        .summary-subtitle {
            font-size: 0.85rem;
            color: #495057;
            margin-top: 8px;
        }
        
        /* Severity color classes */
        .severity-critical { color: #dc3545; }
        .severity-high { color: #fd7e14; }
        .severity-medium { color: #ffc107; }
        .severity-low { color: #17a2b8; }
        .severity-info { color: #6c757d; }
        
        /* Section styling */
        .section {
            margin-bottom: 40px;
        }
        
        .section h2 {
            color: #343a40;
            margin-bottom: 20px;
            padding-bottom: 12px;
            border-bottom: 2px solid #e9ecef;
            font-size: 1.6rem;
            font-weight: 600;
        }
        
        /* Threat details section */
        .threat-details {
            background: #fff9e6;
            border-radius: 8px;
            padding: 25px;
            border-left: 5px solid #ffc107;
        }
        
        .threat-details h3 {
            color: #d39e00;
            margin-bottom: 15px;
            font-size: 1.4rem;
        }
        
        .threat-details p {
            margin-bottom: 12px;
            line-height: 1.7;
        }
        
        .threat-details strong {
            color: #495057;
        }
        
        .threat-details code {
            background: #f8f9fa;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            color: #e83e8c;
            border: 1px solid #dee2e6;
        }
        
        /* Evidence items */
        .evidence-item {
            background: #f8f9fa;
            border-left: 4px solid #6f42c1;
            padding: 18px;
            margin-bottom: 15px;
            border-radius: 6px;
            transition: background-color 0.2s ease;
        }
        
        .evidence-item:hover {
            background: #e9ecef;
        }
        
        .evidence-type {
            font-weight: 700;
            color: #6f42c1;
            margin-bottom: 8px;
            font-size: 1.1rem;
        }
        
        .evidence-description {
            margin-bottom: 12px;
            line-height: 1.6;
        }
        
        .evidence-meta {
            font-size: 0.85rem;
            color: #6c757d;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }
        
        /* Recommendations */
        .recommendation-item {
            background: #e7f5ff;
            border-radius: 8px;
            padding: 22px;
            margin-bottom: 20px;
            border: 1px solid #c5e1ff;
        }
        
        .recommendation-header {
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 15px;
            flex-wrap: wrap;
        }
        
        .recommendation-priority {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .priority-critical { background: #dc3545; color: white; }
        .priority-high { background: #fd7e14; color: white; }
        .priority-medium { background: #ffc107; color: #212529; }
        .priority-low { background: #17a2b8; color: white; }
        
        .recommendation-category {
            background: #6c757d;
            color: white;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.8rem;
        }
        
        .recommendation-item h3 {
            color: #0056b3;
            margin-bottom: 12px;
            font-size: 1.3rem;
        }
        
        .recommendation-item p {
            margin-bottom: 15px;
            line-height: 1.7;
        }
        
        .action-items {
            margin-top: 15px;
            padding-left: 25px;
        }
        
        .action-items li {
            margin-bottom: 8px;
            line-height: 1.5;
        }
        
        .recommendation-meta {
            margin-top: 15px;
            padding-top: 12px;
            border-top: 1px dashed #b3d7ff;
            font-size: 0.85rem;
            color: #495057;
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
        }
        
        /* Footer */
        .footer {
            text-align: center;
            margin-top: 50px;
            padding-top: 25px;
            border-top: 1px solid #dee2e6;
            color: #6c757d;
            font-size: 0.9rem;
            line-height: 1.6;
        }
        
        .footer p {
            margin: 8px 0;
        }
        
        /* Responsive design */
        @media (max-width: 768px) {
            body {
                padding: 10px;
            }
            
            .container {
                padding: 20px;
                border-radius: 8px;
            }
            
            .header {
                padding: 20px;
                margin: -20px -20px 30px -20px;
                border-radius: 8px 8px 0 0;
            }
            
            .header h1 {
                font-size: 2rem;
            }
            
            .summary-grid {
                grid-template-columns: 1fr;
                gap: 15px;
            }
            
            .evidence-meta {
                flex-direction: column;
                gap: 5px;
            }
            
            .recommendation-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }
            
            .section h2 {
                font-size: 1.4rem;
            }
        }
        
        @media print {
            body {
                background: white;
                padding: 0;
            }
            
            .container {
                box-shadow: none;
                padding: 0;
            }
            
            .summary-item:hover {
                transform: none;
                box-shadow: none;
            }
        }
        """
    
    def _generate_html_header(self, result: Any) -> str:
        """
        Generate HTML header section with report metadata and title.
        
        Args:
            result: Inference result object
        
        Returns:
            HTML string for header section
        """
        # Get timestamp with safe handling
        timestamp = getattr(result, 'timestamp', datetime.now())
        if isinstance(timestamp, datetime):
            timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
        else:
            timestamp_str = str(timestamp)
        
        model_version = getattr(result, 'model_version', 'unknown')
        
        return f"""
        <div class="header">
            <h1>CyberGuard Security Report</h1>
            <div class="metadata">
                <p><strong>Report Generated:</strong> {timestamp_str}</p>
                <p><strong>Model Version:</strong> {model_version}</p>
                <p><strong>Report ID:</strong> {id(result)}</p>
            </div>
        </div>
        """
    
    def _generate_html_summary(self, result: Any) -> str:
        """
        Generate HTML summary section with key security metrics.
        
        Args:
            result: Inference result object
        
        Returns:
            HTML string for summary section
        """
        # Get result attributes with safe defaults
        threat_level = getattr(result, 'threat_level', 0.0)
        confidence = getattr(result, 'confidence', 0.0)
        threat_type = getattr(result, 'threat_type', 'UNKNOWN')
        severity = getattr(result, 'severity', 'INFO')
        evidence_count = len(getattr(result, 'evidence', []))
        recommendation_count = len(getattr(result, 'recommendations', []))
        
        # Determine severity class for styling
        severity_class = f"severity-{severity.lower()}"
        
        return f"""
        <div class="summary">
            <h2>Executive Summary</h2>
            <p>This report provides a comprehensive analysis of security findings detected by the CyberGuard system.</p>
            
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="summary-value {severity_class}">{threat_level:.2f}</div>
                    <div class="summary-label">Threat Level</div>
                    <div class="summary-subtitle">{severity} Severity</div>
                </div>
                
                <div class="summary-item">
                    <div class="summary-value">{confidence:.2f}</div>
                    <div class="summary-label">Confidence Score</div>
                    <div class="summary-subtitle">{self._interpret_confidence(confidence)}</div>
                </div>
                
                <div class="summary-item">
                    <div class="summary-value">{threat_type}</div>
                    <div class="summary-label">Primary Threat</div>
                    <div class="summary-subtitle">{self._get_threat_description(threat_type)}</div>
                </div>
                
                <div class="summary-item">
                    <div class="summary-value">{evidence_count}</div>
                    <div class="summary-label">Evidence Items</div>
                    <div class="summary-subtitle">{recommendation_count} recommendations</div>
                </div>
            </div>
        </div>
        """
    
    def _generate_html_threat_details(self, result: Any) -> str:
        """
        Generate HTML threat details section with comprehensive explanation.
        
        Args:
            result: Inference result object
        
        Returns:
            HTML string for threat details section
        """
        threat_type = getattr(result, 'threat_type', 'UNKNOWN')
        severity = getattr(result, 'severity', 'INFO')
        confidence = getattr(result, 'confidence', 0.0)
        
        # Get threat explanation from dictionary
        explanation = self.threat_explanations.get(threat_type, {})
        
        # Escape HTML in example to prevent XSS in our own report
        example = explanation.get('example', 'No example available')
        escaped_example = html.escape(example)
        
        return f"""
        <div class="section">
            <h2>Threat Analysis</h2>
            <div class="threat-details">
                <h3>{threat_type}</h3>
                
                <p><strong>What is it?</strong><br>
                {explanation.get('what', 'No description available for this threat type.')}</p>
                
                <p><strong>How it works:</strong><br>
                {explanation.get('how', 'No detailed explanation available.')}</p>
                
                <p><strong>Potential impact:</strong><br>
                {explanation.get('impact', 'No impact information available.')}</p>
                
                <p><strong>Example:</strong><br>
                <code>{escaped_example}</code></p>
                
                <div class="severity-explanation">
                    <h4>Severity Assessment: {severity}</h4>
                    <p>{self._get_severity_explanation(severity)}</p>
                </div>
                
                <div class="confidence-explanation">
                    <h4>Confidence Level: {confidence:.2f}</h4>
                    <p>{self._interpret_confidence(confidence)}</p>
                </div>
            </div>
        </div>
        """
    
    def _generate_html_evidence(self, result: Any) -> str:
        """
        Generate HTML evidence section listing all security evidence items.
        
        Args:
            result: Inference result object
        
        Returns:
            HTML string for evidence section
        """
        evidence_list = getattr(result, 'evidence', [])
        evidence_count = len(evidence_list)
        
        evidence_html = ""
        
        # Generate HTML for each evidence item
        for i, evidence in enumerate(evidence_list[:15], 1):  # Limit to 15 items for readability
            # Safely extract evidence attributes
            if isinstance(evidence, dict):
                ev_type = evidence.get('type', 'Unknown')
                description = evidence.get('description', '')
                severity = evidence.get('severity', 'info')
                confidence = evidence.get('confidence', 0)
            else:
                ev_type = getattr(evidence, 'type', 'Unknown')
                description = getattr(evidence, 'description', '')
                severity = getattr(evidence, 'severity', 'info')
                confidence = getattr(evidence, 'confidence', 0)
            
            # Sanitize HTML in description
            sanitized_description = html.escape(description)
            
            # Determine severity class for styling
            severity_class = f"severity-{severity.lower()}"
            
            evidence_html += f"""
            <div class="evidence-item">
                <div class="evidence-type">#{i}: {ev_type}</div>
                <div class="evidence-description">{sanitized_description}</div>
                <div class="evidence-meta">
                    <span class="{severity_class}"><strong>Severity:</strong> {severity}</span>
                    <span><strong>Confidence:</strong> {confidence:.2f}</span>
                </div>
            </div>
            """
        
        # If no evidence, show message
        if not evidence_html:
            evidence_html = '<div class="evidence-item"><p>No evidence items were found during analysis.</p></div>'
        
        return f"""
        <div class="section">
            <h2>Evidence Analysis ({evidence_count} items found)</h2>
            <p>This section details the specific evidence that led to the security findings.</p>
            {evidence_html}
            {f'<p class="evidence-note"><em>Showing {min(15, evidence_count)} of {evidence_count} evidence items. Some items may be omitted for brevity.</em></p>' if evidence_count > 15 else ''}
        </div>
        """
    
    def _generate_html_recommendations(self, result: Any) -> str:
        """
        Generate HTML recommendations section with actionable security advice.
        
        Args:
            result: Inference result object
        
        Returns:
            HTML string for recommendations section
        """
        recommendations_list = getattr(result, 'recommendations', [])
        recommendation_count = len(recommendations_list)
        
        recommendations_html = ""
        
        # Generate HTML for each recommendation
        for i, rec in enumerate(recommendations_list[:10], 1):  # Limit to 10 recommendations
            # Handle both SecurityRecommendation objects and dictionaries
            if hasattr(rec, 'to_dict'):
                # It's a SecurityRecommendation object
                rec_dict = rec.to_dict()
                title = rec_dict['title']
                description = rec_dict['description']
                priority = rec_dict['priority']
                category = rec_dict['category']
                action_items = rec_dict['action_items']
                estimated_effort = rec_dict['estimated_effort']
                risk_reduction = rec_dict['risk_reduction']
            elif isinstance(rec, dict):
                # It's a dictionary
                title = rec.get('title', '')
                description = rec.get('description', '')
                priority = rec.get('priority', 'MEDIUM')
                category = rec.get('category', 'general')
                action_items = rec.get('action_items', [])
                estimated_effort = rec.get('estimated_effort', 'MEDIUM')
                risk_reduction = rec.get('risk_reduction', 0.5)
            else:
                # Skip unknown types
                continue
            
            # Sanitize HTML in text fields
            sanitized_title = html.escape(title)
            sanitized_description = html.escape(description)
            
            # Determine priority class for styling
            priority_class = f"priority-{priority.lower()}"
            
            # Generate action items list
            action_items_html = ""
            if action_items:
                action_items_html = "<ul class='action-items'>"
                for action in action_items[:5]:  # Limit to 5 action items
                    sanitized_action = html.escape(str(action))
                    action_items_html += f"<li>{sanitized_action}</li>"
                action_items_html += "</ul>"
            else:
                action_items_html = "<p><em>No specific action items provided.</em></p>"
            
            recommendations_html += f"""
            <div class="recommendation-item">
                <div class="recommendation-header">
                    <span class="recommendation-priority {priority_class}">{priority}</span>
                    <span class="recommendation-category">{category}</span>
                </div>
                
                <h3>{sanitized_title}</h3>
                <p>{sanitized_description}</p>
                
                {action_items_html}
                
                <div class="recommendation-meta">
                    <span><strong>Estimated Effort:</strong> {estimated_effort}</span>
                    <span><strong>Risk Reduction:</strong> {risk_reduction:.0%}</span>
                </div>
            </div>
            """
        
        # If no recommendations, show message
        if not recommendations_html:
            recommendations_html = '<div class="recommendation-item"><p>No specific recommendations available for this finding.</p></div>'
        
        return f"""
        <div class="section">
            <h2>Security Recommendations ({recommendation_count} items)</h2>
            <p>These recommendations provide actionable steps to address the identified security issues.</p>
            {recommendations_html}
            {f'<p class="recommendation-note"><em>Showing {min(10, recommendation_count)} of {recommendation_count} recommendations. Prioritize items with higher priority ratings.</em></p>' if recommendation_count > 10 else ''}
        </div>
        """
    
    def _generate_html_footer(self, result: Any) -> str:
        """
        Generate HTML footer with system information and disclaimers.
        
        Args:
            result: Inference result object (unused in footer but kept for consistency)
        
        Returns:
            HTML string for footer section
        """
        return """
        <div class="footer">
            <p><strong>Report generated by CyberGuard Security AI System</strong></p>
            <p>Version 1.0.0 | © 2024 CyberGuard Security Inc.</p>
            <p>For more information, visit the CyberGuard Security Dashboard or contact your security administrator.</p>
            <p><em>Disclaimer: This report is generated by automated systems and should be reviewed by qualified security professionals. 
            The recommendations provided are suggestions and may need to be adapted to your specific environment and requirements.</em></p>
        </div>
        """
    
    def _generate_markdown_evidence(self, result: Any) -> str:
        """
        Generate Markdown formatted evidence section.
        
        Args:
            result: Inference result object
        
        Returns:
            Markdown string for evidence section
        """
        evidence_list = getattr(result, 'evidence', [])
        
        evidence_md = ""
        
        # Generate Markdown for each evidence item
        for i, evidence in enumerate(evidence_list[:10], 1):  # Limit to 10 items
            # Safely extract evidence attributes
            if isinstance(evidence, dict):
                ev_type = evidence.get('type', 'Unknown')
                description = evidence.get('description', '')
                severity = evidence.get('severity', 'Unknown')
                confidence = evidence.get('confidence', 0)
            else:
                ev_type = getattr(evidence, 'type', 'Unknown')
                description = getattr(evidence, 'description', '')
                severity = getattr(evidence, 'severity', 'Unknown')
                confidence = getattr(evidence, 'confidence', 0)
            
            evidence_md += f"""
### {i}. {ev_type}
**Description**: {description}
**Severity**: {severity} | **Confidence**: {confidence:.2f}

"""
        
        if not evidence_md:
            evidence_md = "*No evidence items were found during analysis.*\n"
        
        return evidence_md
    
    def _generate_markdown_recommendations(self, result: Any) -> str:
        """
        Generate Markdown formatted recommendations section.
        
        Args:
            result: Inference result object
        
        Returns:
            Markdown string for recommendations section
        """
        recommendations_list = getattr(result, 'recommendations', [])
        
        recommendations_md = ""
        
        # Generate Markdown for each recommendation
        for i, rec in enumerate(recommendations_list[:8], 1):  # Limit to 8 recommendations
            # Handle both SecurityRecommendation objects and dictionaries
            if hasattr(rec, 'to_dict'):
                rec_dict = rec.to_dict()
                title = rec_dict['title']
                description = rec_dict['description']
                priority = rec_dict['priority']
                category = rec_dict['category']
                action_items = rec_dict['action_items']
                estimated_effort = rec_dict['estimated_effort']
                risk_reduction = rec_dict['risk_reduction']
            elif isinstance(rec, dict):
                title = rec.get('title', '')
                description = rec.get('description', '')
                priority = rec.get('priority', 'MEDIUM')
                category = rec.get('category', 'general')
                action_items = rec.get('action_items', [])
                estimated_effort = rec.get('estimated_effort', 'MEDIUM')
                risk_reduction = rec.get('risk_reduction', 0.5)
            else:
                continue
            
            # Format action items
            action_items_text = ""
            if action_items:
                for action in action_items[:4]:  # Limit to 4 action items
                    action_items_text += f"  - {action}\n"
            else:
                action_items_text = "  *No specific action items provided.*\n"
            
            recommendations_md += f"""
### {i}. [{priority}] {title}
{description}

**Actions**:
{action_items_text}
**Category**: {category} | **Effort**: {estimated_effort} | **Risk Reduction**: {risk_reduction:.0%}

"""
        
        if not recommendations_md:
            recommendations_md = "*No specific recommendations available for this finding.*\n"
        
        return recommendations_md
    
    def _generate_markdown_metadata(self, result: Any) -> str:
        """
        Generate Markdown formatted metadata section.
        
        Args:
            result: Inference result object
        
        Returns:
            Markdown string for metadata section
        """
        metadata = getattr(result, 'metadata', {})
        
        metadata_md = ""
        
        for key, value in metadata.items():
            if isinstance(value, list):
                value_str = ", ".join(str(v) for v in value[:5])  # Limit list items
                if len(value) > 5:
                    value_str += f" ... and {len(value) - 5} more"
            elif isinstance(value, dict):
                value_str = str(value)[:100] + "..." if len(str(value)) > 100 else str(value)
            else:
                value_str = str(value)
            
            metadata_md += f"- **{key}**: {value_str}\n"
        
        if not metadata_md:
            metadata_md = "*No additional metadata available.*\n"
        
        return metadata_md
    
    def _generate_plain_text_evidence(self, result: Any) -> str:
        """
        Generate plain text formatted evidence section.
        
        Args:
            result: Inference result object
        
        Returns:
            Plain text string for evidence section
        """
        evidence_list = getattr(result, 'evidence', [])
        
        evidence_text = ""
        
        # Get bullet character from templates
        bullet_char = self.templates['plain_text']['bullet_char']
        
        # Generate plain text for each evidence item
        for i, evidence in enumerate(evidence_list[:8], 1):  # Limit to 8 items
            # Safely extract evidence attributes
            if isinstance(evidence, dict):
                ev_type = evidence.get('type', 'Unknown')
                description = evidence.get('description', '')
                severity = evidence.get('severity', 'Unknown')
                confidence = evidence.get('confidence', 0)
            else:
                ev_type = getattr(evidence, 'type', 'Unknown')
                description = getattr(evidence, 'description', '')
                severity = getattr(evidence, 'severity', 'Unknown')
                confidence = getattr(evidence, 'confidence', 0)
            
            # Truncate long descriptions
            if len(description) > 120:
                description = description[:117] + "..."
            
            evidence_text += f"""
{bullet_char} {ev_type}
    Description: {description}
    Severity: {severity}
    Confidence: {confidence:.2f}
"""
        
        if not evidence_text:
            evidence_text = "  No evidence items were found during analysis.\n"
        
        return evidence_text
    
    def _generate_plain_text_recommendations(self, result: Any) -> str:
        """
        Generate plain text formatted recommendations section.
        
        Args:
            result: Inference result object
        
        Returns:
            Plain text string for recommendations section
        """
        recommendations_list = getattr(result, 'recommendations', [])
        
        recommendations_text = ""
        
        # Get bullet character from templates
        bullet_char = self.templates['plain_text']['bullet_char']
        
        # Generate plain text for each recommendation
        for i, rec in enumerate(recommendations_list[:6], 1):  # Limit to 6 recommendations
            # Handle both SecurityRecommendation objects and dictionaries
            if hasattr(rec, 'to_dict'):
                rec_dict = rec.to_dict()
                title = rec_dict['title']
                description = rec_dict['description']
                priority = rec_dict['priority']
                category = rec_dict['category']
                action_items = rec_dict['action_items']
                estimated_effort = rec_dict['estimated_effort']
                risk_reduction = rec_dict['risk_reduction']
            elif isinstance(rec, dict):
                title = rec.get('title', '')
                description = rec.get('description', '')
                priority = rec.get('priority', 'MEDIUM')
                category = rec.get('category', 'general')
                action_items = rec.get('action_items', [])
                estimated_effort = rec.get('estimated_effort', 'MEDIUM')
                risk_reduction = rec.get('risk_reduction', 0.5)
            else:
                continue
            
            # Format action items
            action_items_text = ""
            if action_items:
                for action in action_items[:3]:  # Limit to 3 action items
                    action_items_text += f"      {bullet_char} {action}\n"
            else:
                action_items_text = "      No specific action items provided.\n"
            
            recommendations_text += f"""
{bullet_char} [{priority}] {title}
    {description}
    
    Actions:
{action_items_text}
    Category: {category}
    Effort: {estimated_effort}
    Risk Reduction: {risk_reduction:.0%}
"""
        
        if not recommendations_text:
            recommendations_text = "  No specific recommendations available for this finding.\n"
        
        return recommendations_text
    
    def _generate_plain_text_metadata(self, result: Any) -> str:
        """
        Generate plain text formatted metadata section.
        
        Args:
            result: Inference result object
        
        Returns:
            Plain text string for metadata section
        """
        metadata = getattr(result, 'metadata', {})
        
        metadata_text = ""
        
        # Get bullet character from templates
        bullet_char = self.templates['plain_text']['bullet_char']
        
        for key, value in metadata.items():
            if isinstance(value, list):
                value_str = ", ".join(str(v) for v in value[:3])  # Limit list items
                if len(value) > 3:
                    value_str += f" ... ({len(value) - 3} more)"
            elif isinstance(value, dict):
                value_str = str(value)[:80] + "..." if len(str(value)) > 80 else str(value)
            else:
                value_str = str(value)[:100]  # Truncate long values
            
            metadata_text += f"{bullet_char} {key}: {value_str}\n"
        
        if not metadata_text:
            metadata_text = "  No additional metadata available.\n"
        
        return metadata_text
    
    def _get_severity_explanation(self, severity: str) -> str:
        """
        Get human-readable explanation for severity level.
        
        Args:
            severity: Severity level string (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        
        Returns:
            Explanation of what the severity level means
        """
        explanations = {
            'CRITICAL': 'Requires immediate attention. This finding indicates a high likelihood of system compromise or major data breach if not addressed immediately.',
            'HIGH': 'High priority issue. Could lead to significant data loss, system damage, or unauthorized access. Should be addressed as soon as possible.',
            'MEDIUM': 'Should be addressed in a timely manner. Represents a moderate risk to the system that could be exploited under certain conditions.',
            'LOW': 'Low priority finding. Represents a minor risk that should be monitored and addressed during regular maintenance cycles.',
            'INFO': 'Informational finding. No immediate security risk, but provides useful context or best practice recommendations.'
        }
        
        # Convert to uppercase for case-insensitive lookup
        severity_upper = severity.upper()
        return explanations.get(severity_upper, f'Unknown severity level: {severity}. Please review the finding manually.')
    
    def _get_threat_description(self, threat_type: str) -> str:
        """
        Get brief description for a threat type.
        
        Args:
            threat_type: String identifier for the threat type
        
        Returns:
            Brief description of the threat
        """
        explanation = self.threat_explanations.get(threat_type, {})
        return explanation.get('what', f'{threat_type} - A security threat that requires attention.')
    
    def _get_threat_explanation(self, threat_type: str) -> Dict[str, str]:
        """
        Get comprehensive explanation for a threat type.
        
        Args:
            threat_type: String identifier for the threat type
        
        Returns:
            Dictionary with comprehensive threat explanation
        """
        return self.threat_explanations.get(threat_type, {
            'what': f'Unknown threat type: {threat_type}',
            'how': 'No detailed information available about how this threat operates.',
            'impact': 'Potential impact is unknown. Further investigation is recommended.',
            'example': 'No example available for this threat type.'
        })
    
    def _interpret_confidence(self, confidence: float) -> str:
        """
        Convert numerical confidence score to human-readable interpretation.
        
        Args:
            confidence: Confidence score between 0.0 and 1.0
        
        Returns:
            Human-readable interpretation of confidence level
        """
        if not isinstance(confidence, (int, float)):
            return 'Invalid confidence score'
        
        if confidence >= 0.95:
            return 'Very High Confidence - Finding is almost certainly accurate'
        elif confidence >= 0.85:
            return 'High Confidence - Finding is highly likely to be accurate'
        elif confidence >= 0.70:
            return 'Moderate Confidence - Finding is likely accurate'
        elif confidence >= 0.50:
            return 'Low Confidence - Finding may be accurate, verification recommended'
        elif confidence >= 0.30:
            return 'Very Low Confidence - Finding is uncertain, requires manual verification'
        else:
            return 'Minimal Confidence - Finding is speculative, likely requires additional investigation'
    
    def generate_recommendations(self, 
                                threat_type: str, 
                                threat_level: float,
                                evidence: List[Dict[str, Any]]) -> List[SecurityRecommendation]:
        """
        Generate customized security recommendations based on threat analysis.
        This method creates actionable recommendations tailored to the specific
        threat type, severity level, and evidence.
        
        Args:
            threat_type: Type of threat detected (e.g., 'XSS', 'SQL_INJECTION')
            threat_level: Numeric threat severity score between 0.0 and 1.0
            evidence: List of evidence dictionaries supporting the finding
        
        Returns:
            List of SecurityRecommendation objects tailored to the specific threat
        """
        recommendations = []
        
        # Validate inputs
        if not isinstance(threat_level, (int, float)):
            threat_level = 0.5  # Default to medium if invalid
        elif threat_level < 0 or threat_level > 1:
            threat_level = max(0.0, min(1.0, threat_level))  # Clamp to 0-1 range
        
        # Add threat-specific recommendation from templates
        if threat_type in self.recommendation_templates:
            base_rec = self.recommendation_templates[threat_type]
            
            # Create a copy to avoid modifying the template
            customized_rec = SecurityRecommendation(
                title=base_rec.title,
                description=base_rec.description,
                priority=base_rec.priority,
                category=base_rec.category,
                action_items=base_rec.action_items.copy(),
                references=base_rec.references.copy(),
                estimated_effort=base_rec.estimated_effort,
                risk_reduction=base_rec.risk_reduction
            )
            
            # Customize priority based on threat level
            if threat_level >= 0.8:
                customized_rec.priority = "CRITICAL"
                customized_rec.risk_reduction = 0.95
                customized_rec.description += " CRITICAL PRIORITY: Requires immediate attention due to high threat level."
            elif threat_level >= 0.6:
                customized_rec.priority = "HIGH"
                customized_rec.risk_reduction = 0.85
                customized_rec.description += " HIGH PRIORITY: Should be addressed promptly."
            
            recommendations.append(customized_rec)
        else:
            # Create a generic recommendation for unknown threat types
            generic_rec = SecurityRecommendation(
                title=f"Address {threat_type} Security Threat",
                description=f"Security analysis detected a {threat_type} threat with severity level {threat_level:.2f}. Implement appropriate security controls.",
                priority="HIGH" if threat_level >= 0.6 else "MEDIUM",
                category="general",
                action_items=[
                    "Review the specific evidence for this threat",
                    "Research best practices for mitigating this type of threat",
                    "Implement appropriate security controls based on findings",
                    "Test the implemented controls thoroughly",
                    "Monitor for similar threats in the future"
                ],
                estimated_effort="MEDIUM",
                risk_reduction=0.7
            )
            recommendations.append(generic_rec)
        
        # Add general security hardening recommendation for significant threats
        if threat_level >= 0.5:
            general_rec_template = self.recommendation_templates.get('GENERAL')
            if general_rec_template:
                general_rec = SecurityRecommendation(
                    title=general_rec_template.title,
                    description=general_rec_template.description,
                    priority="HIGH" if threat_level >= 0.7 else "MEDIUM",
                    category=general_rec_template.category,
                    action_items=general_rec_template.action_items.copy(),
                    references=general_rec_template.references.copy(),
                    estimated_effort=general_rec_template.estimated_effort,
                    risk_reduction=general_rec_template.risk_reduction
                )
                
                # Adjust based on evidence volume
                if len(evidence) > 5:
                    general_rec.priority = "HIGH"
                    general_rec.description = "Multiple security issues detected. Comprehensive security hardening is strongly recommended to address systemic issues."
                
                recommendations.append(general_rec)
        
        # Add evidence-specific recommendations
        evidence_based = self._generate_evidence_based_recommendations(evidence)
        recommendations.extend(evidence_based)
        
        # Remove duplicate recommendations based on title and category
        unique_recs = []
        seen_keys = set()
        
        for rec in recommendations:
            # Create a unique key from title and category
            key = f"{rec.title}|{rec.category}"
            if key not in seen_keys:
                unique_recs.append(rec)
                seen_keys.add(key)
        
        # Sort recommendations by priority (CRITICAL first, INFO last)
        priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        unique_recs.sort(key=lambda x: priority_order.get(x.priority, 5))
        
        # Return top 10 unique recommendations (or fewer)
        return unique_recs[:10]
    
    def _generate_evidence_based_recommendations(self, evidence: List[Dict[str, Any]]) -> List[SecurityRecommendation]:
        """
        Generate recommendations based on specific evidence items.
        This allows for highly targeted recommendations based on the actual
        evidence found during analysis.
        
        Args:
            evidence: List of evidence dictionaries
        
        Returns:
            List of SecurityRecommendation objects based on evidence
        """
        recommendations = []
        
        # Limit to top 5 evidence items to avoid overwhelming the user
        for ev in evidence[:5]:
            # Extract evidence type and severity
            if isinstance(ev, dict):
                ev_type = ev.get('type', '')
                ev_severity = ev.get('severity', 'MEDIUM')
                ev_description = ev.get('description', '')
            else:
                ev_type = getattr(ev, 'type', '')
                ev_severity = getattr(ev, 'severity', 'MEDIUM')
                ev_description = getattr(ev, 'description', '')
            
            # Generate recommendation for missing security headers
            if 'HEADER' in ev_type.upper() or 'CSP' in ev_type.upper() or 'HSTS' in ev_type.upper():
                rec = SecurityRecommendation(
                    title="Implement Missing Security Headers",
                    description=f"Security analysis identified missing or misconfigured HTTP security headers: {ev_description}",
                    priority=ev_severity,
                    category="http_security",
                    action_items=[
                        "Implement Content-Security-Policy (CSP) header with appropriate directives",
                        "Add X-Frame-Options header to prevent clickjacking attacks",
                        "Enable X-Content-Type-Options: nosniff to prevent MIME sniffing",
                        "Add X-XSS-Protection header for legacy browser protection",
                        "Implement Strict-Transport-Security (HSTS) header for HTTPS enforcement",
                        "Add Referrer-Policy header to control referrer information leakage"
                    ],
                    estimated_effort="LOW",
                    risk_reduction=0.7
                )
                recommendations.append(rec)
            
            # Generate recommendation for insecure cookie configuration
            elif 'COOKIE' in ev_type.upper() or 'SESSION' in ev_type.upper():
                rec = SecurityRecommendation(
                    title="Secure Cookie Configuration",
                    description=f"Insecure cookie configuration detected: {ev_description}",
                    priority="HIGH",
                    category="session_management",
                    action_items=[
                        "Set Secure flag on all cookies to ensure they're only sent over HTTPS",
                        "Set HttpOnly flag on session cookies to prevent JavaScript access",
                        "Implement SameSite cookie attribute with Strict or Lax setting",
                        "Use short session timeouts to limit exposure windows",
                        "Regenerate session IDs after user authentication",
                        "Implement proper session invalidation on logout"
                    ],
                    estimated_effort="LOW",
                    risk_reduction=0.8
                )
                recommendations.append(rec)
            
            # Generate recommendation for authentication issues
            elif 'AUTH' in ev_type.upper() or 'LOGIN' in ev_type.upper() or 'PASSWORD' in ev_type.upper():
                rec = SecurityRecommendation(
                    title="Strengthen Authentication Mechanisms",
                    description=f"Authentication-related issue detected: {ev_description}",
                    priority="HIGH" if ev_severity in ['HIGH', 'CRITICAL'] else "MEDIUM",
                    category="authentication",
                    action_items=[
                        "Implement multi-factor authentication for sensitive accounts",
                        "Enforce strong password policies (minimum length, complexity)",
                        "Implement account lockout after failed login attempts",
                        "Monitor for suspicious authentication patterns",
                        "Ensure proper session management and timeout"
                    ],
                    estimated_effort="MEDIUM",
                    risk_reduction=0.75
                )
                recommendations.append(rec)
        
        return recommendations
    
    def get_formats_supported(self) -> List[str]:
        """
        Get list of all supported output formats.
        
        Returns:
            List of format strings that can be used with the parse() method
        """
        return [fmt.value for fmt in OutputFormat]
    
    def validate_result_structure(self, result: Any) -> bool:
        """
        Validate that a result object has the minimum required structure for parsing.
        This is a more lenient validation than the strict validate() method
        that might be implemented in the InferenceResult class.
        
        Args:
            result: The result object to validate
        
        Returns:
            True if the result has minimum required structure, False otherwise
        """
        required_attrs = [
            'timestamp',
            'model_version', 
            'threat_level',
            'confidence',
            'threat_type',
            'severity',
            'evidence',
            'recommendations'
        ]
        
        for attr in required_attrs:
            if not hasattr(result, attr):
                logger.warning(f"Result missing required attribute: {attr}")
                return False
        
        # Check that evidence and recommendations are iterable
        try:
            _ = list(result.evidence)
            _ = list(result.recommendations)
        except (TypeError, AttributeError):
            logger.warning("Result evidence or recommendations are not iterable")
            return False
        
        return True


def parse_result(result: Any, format: str = "json") -> Union[str, Dict[str, Any]]:
    """
    Convenience function for quickly parsing inference results.
    This function creates a ResponseParser instance and uses it to parse
    the result, handling common errors and providing sensible defaults.
    
    Args:
        result: InferenceResult object (or any object with appropriate attributes) to parse
        format: Desired output format string (json, html, markdown, plain_text, csv, xml)
    
    Returns:
        Parsed result in specified format
    
    Raises:
        ValueError: If the result cannot be parsed or format is invalid
    
    Example:
        >>> report = parse_result(result, "html")
        >>> with open("security_report.html", "w") as f:
        ...     f.write(report)
    """
    # Create parser instance
    parser = ResponseParser()
    
    try:
        # Convert string format to OutputFormat enum
        format_lower = format.lower()
        
        # Map common format variations
        format_map = {
            'json': OutputFormat.JSON,
            'html': OutputFormat.HTML,
            'md': OutputFormat.MARKDOWN,
            'markdown': OutputFormat.MARKDOWN,
            'text': OutputFormat.PLAIN_TEXT,
            'txt': OutputFormat.PLAIN_TEXT,
            'plaintext': OutputFormat.PLAIN_TEXT,
            'csv': OutputFormat.CSV,
            'xml': OutputFormat.XML
        }
        
        if format_lower in format_map:
            output_format = format_map[format_lower]
        else:
            # Try direct conversion
            output_format = OutputFormat(format_lower)
        
        # Validate result structure before parsing
        if not parser.validate_result_structure(result):
            logger.warning("Result structure validation failed, attempting to parse anyway")
        
        # Parse the result
        return parser.parse(result, output_format)
        
    except ValueError as e:
        logger.warning(f"Invalid format '{format}', defaulting to JSON. Error: {e}")
        # Default to JSON format on error
        return parser.parse(result, OutputFormat.JSON)
    except Exception as e:
        logger.error(f"Error parsing result: {e}")
        raise ValueError(f"Failed to parse result: {e}")


# Example usage and testing code
if __name__ == "__main__":
    """
    This section provides example usage and basic testing of the ResponseParser.
    It creates a mock inference result and demonstrates different output formats.
    """
    
    # Create a mock inference result for testing
    @dataclass
    class MockInferenceResult:
        """Mock class for testing the ResponseParser"""
        timestamp: datetime = field(default_factory=datetime.now)
        model_version: str = "1.2.3"
        threat_level: float = 0.85
        confidence: float = 0.92
        threat_type: str = "SQL_INJECTION"
        severity: str = "CRITICAL"
        evidence: List[Dict[str, Any]] = field(default_factory=lambda: [
            {"type": "SQL_PATTERN", "description": "Detected potential SQL injection pattern in user input", "severity": "HIGH", "confidence": 0.88},
            {"type": "INPUT_VALIDATION", "description": "Missing input validation on login form", "severity": "MEDIUM", "confidence": 0.75},
            {"type": "MISSING_SECURITY_HEADERS", "description": "CSP header not implemented", "severity": "MEDIUM", "confidence": 0.95}
        ])
        recommendations: List[SecurityRecommendation] = field(default_factory=list)
        metadata: Dict[str, Any] = field(default_factory=lambda: {
            "analysis_mode": "deep_scan",
            "processing_time_ms": 245,
            "scanned_endpoints": 15,
            "user_id": "test_user_123"
        })
        
        def validate(self) -> bool:
            """Mock validation method"""
            return True
        
        def to_dict(self) -> Dict[str, Any]:
            """Mock to_dict method"""
            return {
                'timestamp': self.timestamp.isoformat(),
                'model_version': self.model_version,
                'threat_level': self.threat_level,
                'confidence': self.confidence,
                'threat_type': self.threat_type,
                'severity': self.severity,
                'evidence': self.evidence,
                'recommendations': [rec.to_dict() if hasattr(rec, 'to_dict') else str(rec) for rec in self.recommendations],
                'metadata': self.metadata
            }
    
    # Test the parser
    print("Testing ResponseParser...")
    
    # Create mock result
    mock_result = MockInferenceResult()
    
    # Add some recommendations
    parser = ResponseParser()
    recommendations = parser.generate_recommendations(
        threat_type="SQL_INJECTION",
        threat_level=0.85,
        evidence=mock_result.evidence
    )
    mock_result.recommendations = recommendations
    
    # Test different output formats
    try:
        # Test JSON output
        json_output = parser.parse(mock_result, OutputFormat.JSON)
        print(f"✓ JSON output generated successfully (keys: {list(json_output.keys())})")
        
        # Test HTML output
        html_output = parser.parse(mock_result, OutputFormat.HTML)
        print(f"✓ HTML output generated successfully ({len(html_output)} characters)")
        
        # Test Markdown output
        markdown_output = parser.parse(mock_result, OutputFormat.MARKDOWN)
        print(f"✓ Markdown output generated successfully ({len(markdown_output)} characters)")
        
        # Test plain text output
        text_output = parser.parse(mock_result, OutputFormat.PLAIN_TEXT)
        print(f"✓ Plain text output generated successfully ({len(text_output)} characters)")
        
        # Test CSV output
        csv_output = parser.parse(mock_result, OutputFormat.CSV)
        print(f"✓ CSV output generated successfully ({len(csv_output)} characters)")
        
        # Test XML output
        xml_output = parser.parse(mock_result, OutputFormat.XML)
        print(f"✓ XML output generated successfully ({len(xml_output)} characters)")
        
        # Test convenience function
        convenience_output = parse_result(mock_result, "html")
        print(f"✓ Convenience function works correctly")
        
        print("\n All tests passed successfully!")
        
    except Exception as e:
        print(f" Error during testing: {e}")
        import traceback
        traceback.print_exc()