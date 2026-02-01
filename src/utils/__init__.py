"""
Utility modules for CyberGuard Web Security AI System.

This package provides essential utilities for:
- Security validation and sanitization
- Comprehensive logging and monitoring
- Cryptographic operations and key management
- Compliance checks and audit trails
- Performance monitoring and metrics

All utilities are designed with security-first principles and enterprise readiness.
"""

# Import all utility modules to expose their functionality at package level
from .security_utils import (
    validate_url,
    sanitize_input,
    hash_data,
    verify_hash,
    check_xss_patterns,
    detect_sql_injection,
    validate_email,
    validate_ip_address,
    generate_secure_token,
    SecurityValidator,
    InputSanitizer
)

from .logging_utils import (
    setup_logger,
    get_logger,
    SecurityLogger,
    AuditLogger,
    PerformanceMonitor,
    log_security_event,
    log_threat_detection,
    log_agent_activity
)

from .crypto_utils import (
    encrypt_data,
    decrypt_data,
    generate_key_pair,
    sign_data,
    verify_signature,
    generate_hmac,
    verify_hmac,
    generate_csrf_token,
    verify_csrf_token,
    CryptoManager,
    KeyManager
)

from .compliance_utils import (
    check_gdpr_compliance,
    check_hipaa_compliance,
    check_pci_dss_compliance,
    audit_trail,
    generate_compliance_report,
    DataPrivacyManager,
    ComplianceAuditor
)

# Package version metadata
__version__ = "1.0.0"  # Current version of the utilities package
__author__ = "CyberGuard Security Team"  # Author/team responsible for the package

# Initialize a package-level logger for internal package logging
import logging  # Import Python's standard logging module
logger = logging.getLogger(__name__)  # Create logger instance with package name

# Define public API - list of all functions/classes exposed by this package
__all__ = [
    # Security Utilities exports
    'validate_url',  # Function to validate URL format and safety
    'sanitize_input',  # Function to clean user inputs
    'hash_data',  # Function to create cryptographic hash of data
    'verify_hash',  # Function to verify data against a hash
    'check_xss_patterns',  # Function to detect XSS attack patterns
    'detect_sql_injection',  # Function to identify SQL injection attempts
    'validate_email',  # Function to validate email address format
    'validate_ip_address',  # Function to validate IP address format
    'generate_secure_token',  # Function to generate cryptographically secure tokens
    'SecurityValidator',  # Class for comprehensive security validation
    'InputSanitizer',  # Class for input sanitization operations
    
    # Logging Utilities exports
    'setup_logger',  # Function to configure logging system
    'get_logger',  # Function to retrieve logger instance
    'SecurityLogger',  # Class for security-specific logging
    'AuditLogger',  # Class for audit trail logging
    'PerformanceMonitor',  # Class for performance metrics tracking
    'log_security_event',  # Function to log security events
    'log_threat_detection',  # Function to log threat detections
    'log_agent_activity',  # Function to log agent activities
    
    # Cryptography Utilities exports
    'encrypt_data',  # Function to encrypt sensitive data
    'decrypt_data',  # Function to decrypt encrypted data
    'generate_key_pair',  # Function to generate public/private key pair
    'sign_data',  # Function to create digital signature
    'verify_signature',  # Function to verify digital signature
    'generate_hmac',  # Function to generate HMAC for data integrity
    'verify_hmac',  # Function to verify HMAC integrity
    'generate_csrf_token',  # Function to generate CSRF protection tokens
    'verify_csrf_token',  # Function to verify CSRF tokens
    'CryptoManager',  # Class managing cryptographic operations
    'KeyManager',  # Class for key lifecycle management
    
    # Compliance Utilities exports
    'check_gdpr_compliance',  # Function to check GDPR compliance requirements
    'check_hipaa_compliance',  # Function to check HIPAA compliance requirements
    'check_pci_dss_compliance',  # Function to check PCI-DSS compliance requirements
    'audit_trail',  # Function to create audit trail records
    'generate_compliance_report',  # Function to generate compliance reports
    'DataPrivacyManager',  # Class for data privacy management
    'ComplianceAuditor',  # Class for compliance auditing operations
]