# CyberGuard/src/utils/__init__.py
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

# Version and metadata
__version__ = "1.0.0"
__author__ = "CyberGuard Security Team"

# Initialize package logger
import logging
logger = logging.getLogger(__name__)

# Export all public functions and classes
__all__ = [
    # Security Utilities
    'validate_url',
    'sanitize_input',
    'hash_data',
    'verify_hash',
    'check_xss_patterns',
    'detect_sql_injection',
    'validate_email',
    'validate_ip_address',
    'generate_secure_token',
    'SecurityValidator',
    'InputSanitizer',
    
    # Logging Utilities
    'setup_logger',
    'get_logger',
    'SecurityLogger',
    'AuditLogger',
    'PerformanceMonitor',
    'log_security_event',
    'log_threat_detection',
    'log_agent_activity',
    
    # Cryptography Utilities
    'encrypt_data',
    'decrypt_data',
    'generate_key_pair',
    'sign_data',
    'verify_signature',
    'generate_hmac',
    'verify_hmac',
    'generate_csrf_token',
    'verify_csrf_token',
    'CryptoManager',
    'KeyManager',
    
    # Compliance Utilities
    'check_gdpr_compliance',
    'check_hipaa_compliance',
    'check_pci_dss_compliance',
    'audit_trail',
    'generate_compliance_report',
    'DataPrivacyManager',
    'ComplianceAuditor',
]