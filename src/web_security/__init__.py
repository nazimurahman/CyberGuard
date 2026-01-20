"""
CyberGuard Web Security Core Module
Comprehensive web security analysis toolkit for websites, APIs, and web applications

This module provides:
1. Website vulnerability scanning
2. API security analysis
3. JavaScript security auditing
4. Form validation and security checks
5. HTTP header security analysis
6. Traffic parsing and anomaly detection
7. Comprehensive security reporting

All modules work together to provide enterprise-grade web security analysis
with explainable AI-powered threat detection.
"""

# Core web security modules
from .scanner import WebSecurityScanner, SecurityScanConfig, ScanResult
from .vulnerability_detector import VulnerabilityDetector, ThreatLevel
from .api_analyzer import APIAnalyzer, APISecurityAssessment
from .traffic_parser import TrafficParser, TrafficAnalysis, AnomalyDetection
from .javascript_analyzer import JavaScriptAnalyzer, JSAnalysis
from .form_validator import FormValidator, FormSecurityAssessment
from .header_analyzer import HeaderAnalyzer, HeaderSecurityAssessment

# Security enums and constants
from .vulnerability_detector import (
    VulnerabilityType,
    SeverityLevel,
    OWASPCategory,
    CWE
)

# Data models
from .scanner import (
    SecurityFinding,
    Vulnerability,
    SecurityHeader,
    Technology,
    FormAnalysis,
    EndpointDiscovery,
    RiskAssessment
)

# Configuration models
from .scanner import ScannerConfig, RateLimitConfig, AuthenticationConfig

# Utility functions
from .utils import (
    validate_url,
    sanitize_input,
    extract_domain,
    normalize_url,
    calculate_risk_score,
    generate_security_report,
    format_findings_for_dashboard
)

# Error handling
from .exceptions import (
    SecurityScanError,
    InvalidURLException,
    RequestTimeoutException,
    AuthenticationRequiredException,
    RateLimitExceededException,
    ParseError
)

__version__ = "1.0.0"
__author__ = "CyberGuard Security Team"
__email__ = "security@cyberguard.ai"

__all__ = [
    # Main classes
    'WebSecurityScanner',
    'VulnerabilityDetector',
    'APIAnalyzer',
    'TrafficParser',
    'JavaScriptAnalyzer',
    'FormValidator',
    'HeaderAnalyzer',
    
    # Data models
    'SecurityScanConfig',
    'ScanResult',
    'ThreatLevel',
    'APISecurityAssessment',
    'TrafficAnalysis',
    'AnomalyDetection',
    'JSAnalysis',
    'FormSecurityAssessment',
    'HeaderSecurityAssessment',
    'SecurityFinding',
    'Vulnerability',
    'SecurityHeader',
    'Technology',
    'FormAnalysis',
    'EndpointDiscovery',
    'RiskAssessment',
    
    # Enums
    'VulnerabilityType',
    'SeverityLevel',
    'OWASPCategory',
    'CWE',
    
    # Configurations
    'ScannerConfig',
    'RateLimitConfig',
    'AuthenticationConfig',
    
    # Utilities
    'validate_url',
    'sanitize_input',
    'extract_domain',
    'normalize_url',
    'calculate_risk_score',
    'generate_security_report',
    'format_findings_for_dashboard',
    
    # Exceptions
    'SecurityScanError',
    'InvalidURLException',
    'RequestTimeoutException',
    'AuthenticationRequiredException',
    'RateLimitExceededException',
    'ParseError'
]

def get_version() -> str:
    """Get the current version of the web security module"""
    return __version__

def list_available_scanners() -> list:
    """List all available security scanners in the module"""
    return [
        "WebSecurityScanner",
        "VulnerabilityDetector",
        "APIAnalyzer",
        "TrafficParser",
        "JavaScriptAnalyzer",
        "FormValidator",
        "HeaderAnalyzer"
    ]

def get_owasp_categories() -> dict:
    """Get OWASP Top 10 categories with descriptions"""
    return {
        "A01:2021-Broken Access Control": {
            "description": "Restrictions on what authenticated users are allowed to do are not properly enforced.",
            "cwe_ids": [22, 352, 862]
        },
        "A02:2021-Cryptographic Failures": {
            "description": "Failure related to cryptography which often leads to sensitive data exposure.",
            "cwe_ids": [256, 310, 311, 312, 326]
        },
        "A03:2021-Injection": {
            "description": "Untrusted data is sent to an interpreter as part of a command or query.",
            "cwe_ids": [77, 78, 79, 89, 91]
        },
        "A04:2021-Insecure Design": {
            "description": "Missing or ineffective control design.",
            "cwe_ids": [250, 269, 280, 281, 284]
        },
        "A05:2021-Security Misconfiguration": {
            "description": "Insecure configuration options in any part of the application stack.",
            "cwe_ids": [2, 16, 209, 352, 434]
        },
        "A06:2021-Vulnerable and Outdated Components": {
            "description": "Use of known vulnerable components that can be exploited.",
            "cwe_ids": [937]
        },
        "A07:2021-Identification and Authentication Failures": {
            "description": "Functions related to identification and authentication are implemented incorrectly.",
            "cwe_ids": [287, 288, 289, 290]
        },
        "A08:2021-Software and Data Integrity Failures": {
            "description": "Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations.",
            "cwe_ids": [345, 346, 347, 348]
        },
        "A09:2021-Security Logging and Monitoring Failures": {
            "description": "Insufficient logging, monitoring, and incident response capabilities.",
            "cwe_ids": [223, 778]
        },
        "A10:2021-Server-Side Request Forgery": {
            "description": "Web applications that fetch remote resources without validating user-supplied URLs.",
            "cwe_ids": [918]
        }
    }

# Initialize logging configuration
import logging

logging.getLogger(__name__).addHandler(logging.NullHandler())

# Create a default logger for the module
def get_logger(name: str = None) -> logging.Logger:
    """Get a logger for web security operations"""
    if name is None:
        name = __name__
    return logging.getLogger(name)