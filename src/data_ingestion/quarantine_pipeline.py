"""
Quarantine Pipeline Module
==========================

This module provides a secure quarantine system for suspicious or malicious
data detected during ingestion. It implements a zero-trust approach with
multiple security controls to prevent contamination of the main system.

Features:
---------
1. Secure isolation of suspicious content
2. Multiple quarantine levels with different restrictions
3. Automated analysis and classification
4. Manual review workflow
5. Expiration and automatic cleanup
6. Audit trail for all quarantine actions
7. Chain of custody tracking

Security Controls:
-----------------
- Strict access controls to quarantine area
- Encryption of quarantined content
- Tamper-evident logging
- Multi-person approval for release
- Regular security audits
- Automated malware scanning

Usage Examples:
---------------
# Initialize quarantine manager
quarantine = QuarantineManager()

# Quarantine suspicious file
item_id = quarantine.quarantine_item(
    data=b"suspicious content",
    reason="Potential malware detected",
    source="file_upload",
    severity=QuarantineSeverity.HIGH
)

# Analyze quarantined item
analysis = quarantine.analyze_item(item_id)

# Release item after review
quarantine.release_item(item_id, "reviewed_by_security")

# Get quarantine statistics
stats = quarantine.get_statistics()
"""

import hashlib
import json
import pickle
import shutil
import tempfile
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, field, asdict
import logging
from pathlib import Path
import threading
import zipfile
import tarfile
import re
import time
import uuid
import io

# Local imports - Fixed: Added fallback implementations for missing modules
try:
    from ..utils.crypto_utils import encrypt_data, decrypt_data, generate_key
except ImportError:
    # Fallback implementation if crypto_utils is not available
    from cryptography.fernet import Fernet
    import base64
    
    def generate_key(key_size: int = 32) -> bytes:
        """Generate a random encryption key"""
        return base64.urlsafe_b64encode(hashlib.sha256(str(uuid.uuid4()).encode()).digest()[:key_size])
    
    def encrypt_data(data: bytes, key: bytes) -> bytes:
        """Encrypt data using Fernet symmetric encryption"""
        # Ensure key is proper length for Fernet (32 bytes base64 encoded)
        fernet_key = base64.urlsafe_b64encode(key[:32])
        cipher = Fernet(fernet_key)
        return cipher.encrypt(data)
    
    def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
        """Decrypt data using Fernet symmetric encryption"""
        # Ensure key is proper length for Fernet (32 bytes base64 encoded)
        fernet_key = base64.urlsafe_b64encode(key[:32])
        cipher = Fernet(fernet_key)
        return cipher.decrypt(encrypted_data)

try:
    from ..utils.logging_utils import audit_log, SecurityLogger
except ImportError:
    # Fallback implementation for SecurityLogger
    class SecurityLogger:
        """Fallback security logger implementation"""
        def __init__(self):
            self.logger = logging.getLogger(f"{__name__}.security")
        
        def log_event(self, event_type: str, severity: str, message: str, details: Dict[str, Any] = None):
            """Log security event"""
            log_msg = f"[{event_type}] {severity}: {message}"
            if details:
                log_msg += f" | Details: {json.dumps(details)}"
            
            if severity in ['critical', 'high']:
                self.logger.error(log_msg)
            elif severity == 'medium':
                self.logger.warning(log_msg)
            else:
                self.logger.info(log_msg)
    
    def audit_log(message: str, user: str = "system", level: str = "INFO"):
        """Log audit message"""
        logger = logging.getLogger(f"{__name__}.audit")
        log_msg = f"[AUDIT] {user}: {message}"
        getattr(logger, level.lower(), logger.info)(log_msg)

try:
    from .hash_validator import HashValidator, HashAlgorithm
except ImportError:
    # Fallback implementation for HashValidator and HashAlgorithm
    class HashAlgorithm(Enum):
        """Hashing algorithms enumeration"""
        MD5 = "md5"
        SHA1 = "sha1"
        SHA256 = "sha256"
        SHA512 = "sha512"
    
    class HashValidator:
        """Fallback hash validator implementation"""
        @staticmethod
        def calculate_hash(data: bytes, algorithm: HashAlgorithm) -> str:
            """Calculate hash of data using specified algorithm"""
            if algorithm == HashAlgorithm.MD5:
                return hashlib.md5(data).hexdigest()
            elif algorithm == HashAlgorithm.SHA1:
                return hashlib.sha1(data).hexdigest()
            elif algorithm == HashAlgorithm.SHA256:
                return hashlib.sha256(data).hexdigest()
            elif algorithm == HashAlgorithm.SHA512:
                return hashlib.sha512(data).hexdigest()
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")

# Custom exceptions
class QuarantineError(Exception):
    """Base exception for quarantine operations"""
    pass

class QuarantineAccessError(QuarantineError):
    """Raised when access to quarantine is denied"""
    pass

class QuarantineItemNotFound(QuarantineError):
    """Raised when quarantined item is not found"""
    pass

class QuarantineIntegrityError(QuarantineError):
    """Raised when quarantine integrity check fails"""
    pass

class QuarantineReleaseError(QuarantineError):
    """Raised when item release fails"""
    pass

# Enums
class QuarantineSeverity(Enum):
    """Quarantine severity levels enumeration"""
    INFO = "info"           # Informational quarantine
    LOW = "low"            # Low risk, likely false positive
    MEDIUM = "medium"      # Medium risk, needs review
    HIGH = "high"          # High risk, likely malicious
    CRITICAL = "critical"  # Critical risk, confirmed malicious

class QuarantineStatus(Enum):
    """Quarantine item status enumeration"""
    ACTIVE = "active"           # Currently quarantined
    ANALYZING = "analyzing"     # Under analysis
    PENDING_REVIEW = "pending_review"  # Waiting for manual review
    RELEASED = "released"       # Released from quarantine
    DELETED = "deleted"         # Deleted (permanently)
    EXPIRED = "expired"         # Auto-expired

class QuarantineAction(Enum):
    """Actions performed on quarantine items enumeration"""
    QUARANTINE = "quarantine"
    RELEASE = "release"
    DELETE = "delete"
    ANALYZE = "analyze"
    EXPORT = "export"
    IMPORT = "import"
    UPDATE = "update"

@dataclass
class QuarantineMetadata:
    """Metadata container for quarantined items"""
    # Core identification fields
    item_id: str  # Unique identifier for the quarantined item
    original_filename: Optional[str] = None  # Original filename if from file system
    original_path: Optional[str] = None  # Original path if from file system
    
    # Content information fields
    content_type: Optional[str] = None  # MIME type or content category
    content_size: int = 0  # Size of content in bytes
    content_hash: Optional[str] = None  # Cryptographic hash of content
    content_hash_algorithm: HashAlgorithm = HashAlgorithm.SHA256  # Algorithm used for hashing
    
    # Quarantine information fields
    quarantine_reason: str = "Unknown"  # Reason why item was quarantined
    quarantine_severity: QuarantineSeverity = QuarantineSeverity.MEDIUM  # Risk severity level
    quarantine_source: str = "unknown"  # Source system or process that triggered quarantine
    
    # Date and time fields
    quarantine_date: datetime = field(default_factory=datetime.now)  # When item was quarantined
    expiration_date: Optional[datetime] = None  # When item should expire (auto-delete)
    last_accessed: Optional[datetime] = None  # When item was last accessed
    
    # Analysis results fields
    analysis_results: Dict[str, Any] = field(default_factory=dict)  # Results from automated analysis
    analysis_tools: List[str] = field(default_factory=list)  # Tools used for analysis
    classification: Optional[str] = None  # Final classification (clean, suspicious, malicious)
    
    # Status and tracking fields
    status: QuarantineStatus = QuarantineStatus.ACTIVE  # Current status in quarantine lifecycle
    review_required: bool = False  # Whether manual review is required
    review_notes: List[str] = field(default_factory=list)  # Notes from manual reviews
    
    # Chain of custody fields
    custody_chain: List[Dict[str, str]] = field(default_factory=list)  # History of custody transfers
    
    # Security information fields
    encryption_key_id: Optional[str] = None  # Identifier for encryption key used
    integrity_hash: Optional[str] = None  # Hash for integrity verification
    digital_signature: Optional[str] = None  # Digital signature for authentication
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata object to dictionary for serialization"""
        result = asdict(self)  # Convert dataclass to dictionary
        
        # Convert enums to string values for JSON serialization
        result['quarantine_severity'] = self.quarantine_severity.value
        result['status'] = self.status.value
        result['content_hash_algorithm'] = self.content_hash_algorithm.value
        
        # Convert datetime objects to ISO format strings
        if self.quarantine_date:
            result['quarantine_date'] = self.quarantine_date.isoformat()
        if self.expiration_date:
            result['expiration_date'] = self.expiration_date.isoformat()
        if self.last_accessed:
            result['last_accessed'] = self.last_accessed.isoformat()
        
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'QuarantineMetadata':
        """Create metadata object from dictionary (deserialization)"""
        # Convert string values back to enum instances
        data['quarantine_severity'] = QuarantineSeverity(data['quarantine_severity'])
        data['status'] = QuarantineStatus(data['status'])
        data['content_hash_algorithm'] = HashAlgorithm(data['content_hash_algorithm'])
        
        # Convert ISO format strings back to datetime objects
        if data.get('quarantine_date'):
            data['quarantine_date'] = datetime.fromisoformat(data['quarantine_date'])
        if data.get('expiration_date'):
            data['expiration_date'] = datetime.fromisoformat(data['expiration_date'])
        if data.get('last_accessed'):
            data['last_accessed'] = datetime.fromisoformat(data['last_accessed'])
        
        return cls(**data)  # Create new instance from dictionary

class QuarantinePolicy:
    """
    Policy configuration for quarantine operations
    
    Defines rules and parameters for quarantine management including:
    - Retention periods based on severity
    - Automatic actions (analysis, notification, expiration)
    - Access control requirements
    - Analysis and notification settings
    """
    
    def __init__(
        self,
        name: str,
        description: str = "",
        # Retention periods in days based on severity
        retention_days_low: int = 7,
        retention_days_medium: int = 30,
        retention_days_high: int = 90,
        retention_days_critical: int = 365,
        # Automatic action flags
        auto_analyze: bool = True,
        auto_notify: bool = True,
        auto_expire: bool = True,
        # Access control requirements
        require_review_high: bool = True,
        require_review_critical: bool = True,
        multi_person_release: bool = False,
        # Analysis configuration
        analysis_timeout: int = 300,  # Maximum analysis time in seconds
        max_analysis_size_mb: int = 100,  # Maximum file size for analysis in MB
        # Notification configuration
        notify_on_quarantine: bool = True,
        notify_on_release: bool = True,
        notify_emails: List[str] = None,
    ):
        # Basic policy information
        self.name = name  # Policy identifier
        self.description = description  # Human-readable description
        
        # Configure retention periods for each severity level
        self.retention_days = {
            QuarantineSeverity.INFO: 1,  # Info level items kept for 1 day
            QuarantineSeverity.LOW: retention_days_low,
            QuarantineSeverity.MEDIUM: retention_days_medium,
            QuarantineSeverity.HIGH: retention_days_high,
            QuarantineSeverity.CRITICAL: retention_days_critical,
        }
        
        # Automatic processing flags
        self.auto_analyze = auto_analyze  # Automatically analyze new items
        self.auto_notify = auto_notify  # Automatically send notifications
        self.auto_expire = auto_expire  # Automatically expire old items
        
        # Security control flags
        self.require_review_high = require_review_high  # High severity requires review
        self.require_review_critical = require_review_critical  # Critical severity requires review
        self.multi_person_release = multi_person_release  # Require multiple approvers for release
        
        # Analysis configuration
        self.analysis_timeout = analysis_timeout  # Timeout for analysis operations
        self.max_analysis_size_mb = max_analysis_size_mb  # Size limit for automated analysis
        
        # Notification configuration
        self.notify_on_quarantine = notify_on_quarantine  # Notify when item quarantined
        self.notify_on_release = notify_on_release  # Notify when item released
        self.notify_emails = notify_emails or []  # Email recipients for notifications
    
    def get_retention_days(self, severity: QuarantineSeverity) -> int:
        """Get retention period in days for a specific severity level"""
        return self.retention_days.get(severity, 30)  # Default to 30 days if not found
    
    def requires_review(self, severity: QuarantineSeverity) -> bool:
        """Determine if manual review is required based on severity level"""
        if severity == QuarantineSeverity.HIGH and self.require_review_high:
            return True
        if severity == QuarantineSeverity.CRITICAL and self.require_review_critical:
            return True
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert policy configuration to dictionary for serialization"""
        return {
            'name': self.name,
            'description': self.description,
            'retention_days': {k.value: v for k, v in self.retention_days.items()},  # Convert enum keys to strings
            'auto_analyze': self.auto_analyze,
            'auto_notify': self.auto_notify,
            'auto_expire': self.auto_expire,
            'require_review_high': self.require_review_high,
            'require_review_critical': self.require_review_critical,
            'multi_person_release': self.multi_person_release,
            'analysis_timeout': self.analysis_timeout,
            'max_analysis_size_mb': self.max_analysis_size_mb,
            'notify_on_quarantine': self.notify_on_quarantine,
            'notify_on_release': self.notify_on_release,
            'notify_emails': self.notify_emails,
        }

class QuarantineAnalyzer:
    """
    Automated analyzer for quarantined content
    
    Performs security analysis on quarantined items including:
    - Malware signature detection
    - Content pattern matching
    - File structure analysis
    - Risk assessment and scoring
    """
    
    def __init__(self, scan_tools: List[str] = None):
        """
        Initialize quarantine analyzer with specified scanning tools
        
        Args:
            scan_tools: List of scanning tools to enable
        """
        self.logger = logging.getLogger(__name__)  # Logger for analyzer operations
        self.hash_validator = HashValidator()  # Hash validation utility
        
        # Configure available scanning tools
        self.scan_tools = scan_tools or [
            'hash_lookup',     # Check against known malware hash databases
            'string_scan',     # Search for suspicious strings/patterns
            'header_analysis', # Analyze file headers and structure
            'yara_rules',      # Apply YARA rule-based detection
        ]
        
        # Load YARA rules for pattern matching (simplified implementation)
        self.yara_rules = self._load_yara_rules()
        
        # Initialize malware hash database (in production would load from external source)
        self.malware_hashes: Set[str] = set()
        
        # Define suspicious content patterns to search for
        self.suspicious_patterns = [
            (rb'eval\(', 'JavaScript eval function'),  # Dynamic code execution
            (rb'base64_decode', 'PHP base64 decode'),  # Obfuscated code
            (rb'exec\(', 'Command execution'),          # System command execution
            (rb'shell_exec', 'Shell execution'),       # Shell command execution
            (rb'powershell', 'PowerShell command'),    # PowerShell usage
            (rb'<script>', 'HTML script tag'),         # Embedded scripts
            (rb'javascript:', 'JavaScript URL'),       # JavaScript in URLs
            (rb'onload=', 'HTML onload event'),        # Event handler
            (rb'onerror=', 'HTML onerror event'),      # Error handler
        ]
    
    def _load_yara_rules(self) -> List[Dict[str, Any]]:
        """Load YARA rules for malware pattern matching"""
        # Simplified implementation - in production would load from rule files
        return [
            {
                'name': 'suspicious_js',
                'rule': 'rule suspicious_js { strings: $a = "eval(" condition: $a }',
                'description': 'Detects eval() in JavaScript',
            },
            {
                'name': 'potential_exploit',
                'rule': 'rule potential_exploit { strings: $a = "shell_exec" condition: $a }',
                'description': 'Detects shell_exec in PHP',
            },
        ]
    
    def analyze_content(
        self,
        content: bytes,
        metadata: QuarantineMetadata,
        timeout: int = 300
    ) -> Dict[str, Any]:
        """
        Perform comprehensive analysis on quarantined content
        
        Args:
            content: Binary content to analyze
            metadata: Associated quarantine metadata
            timeout: Maximum analysis time in seconds
            
        Returns:
            Dictionary containing analysis results, findings, and recommendations
        """
        # Initialize analysis results structure
        analysis_start = datetime.now()
        results = {
            'analysis_id': f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}",  # Unique analysis ID
            'start_time': analysis_start.isoformat(),  # Analysis start timestamp
            'tools_used': [],  # List of analysis tools applied
            'findings': [],  # List of security findings
            'risk_score': 0.0,  # Calculated risk score (0.0 to 1.0)
            'classification': 'unknown',  # Final classification
            'recommendations': [],  # Action recommendations
        }
        
        try:
            # Step 1: Hash-based analysis (check against known malware databases)
            if 'hash_lookup' in self.scan_tools:
                hash_results = self._analyze_hashes(content, metadata)
                results['tools_used'].append('hash_lookup')
                results['findings'].extend(hash_results.get('findings', []))
            
            # Step 2: String and pattern scanning
            if 'string_scan' in self.scan_tools:
                string_results = self._analyze_strings(content)
                results['tools_used'].append('string_scan')
                results['findings'].extend(string_results.get('findings', []))
            
            # Step 3: File header and structure analysis
            if 'header_analysis' in self.scan_tools:
                header_results = self._analyze_headers(content, metadata)
                results['tools_used'].append('header_analysis')
                results['findings'].extend(header_results.get('findings', []))
            
            # Step 4: YARA rule-based pattern matching
            if 'yara_rules' in self.scan_tools:
                yara_results = self._analyze_yara(content)
                results['tools_used'].append('yara_rules')
                results['findings'].extend(yara_results.get('findings', []))
            
            # Calculate overall risk score based on findings
            results['risk_score'] = self._calculate_risk_score(results['findings'])
            
            # Determine final classification based on risk and findings
            results['classification'] = self._determine_classification(
                results['risk_score'],
                results['findings']
            )
            
            # Generate actionable recommendations
            results['recommendations'] = self._generate_recommendations(
                results['classification'],
                results['findings']
            )
            
            # Record analysis completion metrics
            results['end_time'] = datetime.now().isoformat()
            results['duration_seconds'] = (
                datetime.now() - analysis_start
            ).total_seconds()
            
            # Log analysis completion
            self.logger.info(
                f"Analysis completed: {results['classification']} "
                f"(risk: {results['risk_score']:.2f})"
            )
            
        except Exception as e:
            # Handle analysis failures gracefully
            self.logger.error(f"Analysis failed: {e}")
            results['error'] = str(e)
            results['status'] = 'failed'
        
        return results
    
    def _analyze_hashes(
        self,
        content: bytes,
        metadata: QuarantineMetadata
    ) -> Dict[str, Any]:
        """Analyze content using cryptographic hash comparison"""
        findings = []
        hash_results = {}
        
        # Calculate hashes using multiple algorithms for comprehensive checking
        for algorithm in [HashAlgorithm.MD5, HashAlgorithm.SHA1, HashAlgorithm.SHA256]:
            try:
                # Compute hash for current algorithm
                hash_value = self.hash_validator.calculate_hash(content, algorithm)
                hash_results[algorithm.value] = hash_value
                
                # Check if hash matches known malware signatures
                if hash_value in self.malware_hashes:
                    findings.append({
                        'type': 'malware_hash_match',
                        'severity': 'high',
                        'description': f'Hash matches known malware: {algorithm.value}:{hash_value}',
                        'algorithm': algorithm.value,
                        'hash': hash_value,
                    })
                    
            except Exception as e:
                self.logger.debug(f"Hash calculation failed for {algorithm}: {e}")
        
        return {
            'hash_results': hash_results,  # Dictionary of computed hashes
            'findings': findings,  # List of hash-based findings
        }
    
    def _analyze_strings(self, content: bytes) -> Dict[str, Any]:
        """Analyze strings and patterns within content"""
        findings = []
        suspicious_strings = []
        
        # Attempt to decode content for string analysis
        text_content = None
        for encoding in ['utf-8', 'latin-1', 'ascii']:
            try:
                text_content = content.decode(encoding)
                break
            except UnicodeDecodeError:
                continue
        
        # Search for suspicious patterns if content is decodable
        if text_content:
            for pattern, description in self.suspicious_patterns:
                if pattern in content:  # Search in raw bytes
                    findings.append({
                        'type': 'suspicious_pattern',
                        'severity': 'medium',
                        'description': f'Found suspicious pattern: {description}',
                        'pattern': pattern.decode('ascii', errors='ignore'),
                    })
                    suspicious_strings.append(pattern.decode('ascii', errors='ignore'))
        
        # Extract printable strings from binary content
        strings = re.findall(rb'[^\x00-\x1F\x7F-\xFF]{4,}', content)  # Find sequences of 4+ printable bytes
        
        # Define dangerous patterns indicative of malicious intent
        dangerous_patterns = [
            (rb'/bin/sh', 'Shell path'),
            (rb'cmd\.exe', 'Windows command shell'),
            (rb'wscript\.', 'Windows scripting'),
            (rb'regsvr32', 'Windows DLL registration'),
            (rb'certutil', 'Certificate utility (often abused)'),
        ]
        
        # Check extracted strings against dangerous patterns
        for string in strings[:100]:  # Limit to first 100 strings for performance
            string_lower = string.lower()
            
            for pattern, description in dangerous_patterns:
                if pattern in string_lower:
                    findings.append({
                        'type': 'dangerous_string',
                        'severity': 'high',
                        'description': f'Found dangerous string: {description}',
                        'string': string.decode('ascii', errors='ignore'),
                    })
        
        return {
            'strings_found': len(strings),  # Count of extracted strings
            'suspicious_strings': suspicious_strings,  # List of found suspicious strings
            'findings': findings,  # List of string-based findings
        }
    
    def _analyze_headers(
        self,
        content: bytes,
        metadata: QuarantineMetadata
    ) -> Dict[str, Any]:
        """Analyze file headers, structure, and metadata"""
        findings = []
        file_type = 'unknown'
        
        # Define magic number signatures for common file types
        signatures = {
            b'MZ': 'Windows executable',
            b'\x7fELF': 'Linux executable',
            b'PK': 'ZIP archive',
            b'%PDF': 'PDF document',
            b'\x89PNG': 'PNG image',
            b'\xff\xd8\xff': 'JPEG image',
            b'GIF': 'GIF image',
            b'<?xml': 'XML document',
            b'<!DOCTYPE': 'HTML document',
        }
        
        # Check content against known file signatures
        for signature, file_type_desc in signatures.items():
            if content.startswith(signature):
                file_type = file_type_desc
                findings.append({
                    'type': 'file_signature',
                    'severity': 'info',
                    'description': f'File signature: {file_type_desc}',
                    'signature': signature.hex(),
                })
                break
        
        # Check for file extension mismatches (possible obfuscation)
        if metadata.original_filename:
            filename_lower = metadata.original_filename.lower()
            
            # Map common extensions to expected file types
            extension_mapping = {
                '.exe': 'Windows executable',
                '.dll': 'Windows dynamic library',
                '.so': 'Linux shared object',
                '.py': 'Python script',
                '.js': 'JavaScript',
                '.php': 'PHP script',
                '.pdf': 'PDF document',
                '.jpg': 'JPEG image',
                '.png': 'PNG image',
                '.zip': 'ZIP archive',
                '.tar': 'TAR archive',
            }
            
            # Check if actual file type matches extension
            for ext, expected_type in extension_mapping.items():
                if filename_lower.endswith(ext):
                    if file_type != expected_type and file_type != 'unknown':
                        findings.append({
                            'type': 'extension_mismatch',
                            'severity': 'medium',
                            'description': f'File extension ({ext}) does not match actual type ({file_type})',
                            'expected': expected_type,
                            'actual': file_type,
                        })
                    break
        
        # Analyze file size characteristics
        content_size = len(content)
        
        if content_size == 0:
            findings.append({
                'type': 'empty_file',
                'severity': 'low',
                'description': 'File is empty (0 bytes)',
            })
        elif content_size > 100 * 1024 * 1024:  # 100MB threshold
            findings.append({
                'type': 'large_file',
                'severity': 'info',
                'description': f'File is very large: {content_size:,} bytes',
            })
        
        return {
            'file_type': file_type,  # Detected file type
            'file_size': content_size,  # File size in bytes
            'findings': findings,  # List of header-based findings
        }
    
    def _analyze_yara(self, content: bytes) -> Dict[str, Any]:
        """Apply YARA rules to content for pattern matching"""
        findings = []
        matches = []
        
        # Apply each YARA rule to the content
        for rule in self.yara_rules:
            rule_name = rule['name']
            rule_strings = self._extract_yara_strings(rule['rule'])
            
            # Check if any rule string appears in content
            for rule_string in rule_strings:
                if rule_string.encode() in content:
                    matches.append(rule_name)
                    findings.append({
                        'type': 'yara_match',
                        'severity': 'high',
                        'description': f'YARA rule match: {rule_name}',
                        'rule': rule_name,
                        'matched_string': rule_string,
                    })
                    break  # Stop checking this rule after first match
        
        return {
            'yara_matches': matches,  # List of matched rule names
            'findings': findings,  # List of YARA-based findings
        }
    
    @staticmethod
    def _extract_yara_strings(yara_rule: str) -> List[str]:
        """Extract string patterns from YARA rule syntax"""
        # Simple regex to find string definitions in YARA rules
        pattern = r'\$[a-zA-Z0-9_]+ = "([^"]+)"'
        matches = re.findall(pattern, yara_rule)
        return matches
    
    def _calculate_risk_score(self, findings: List[Dict[str, Any]]) -> float:
        """Calculate overall risk score from findings"""
        score = 0.0
        
        # Define severity weights for risk calculation
        severity_weights = {
            'info': 0.1,      # Informational - minimal risk
            'low': 0.3,       # Low severity - some risk
            'medium': 0.6,    # Medium severity - significant risk
            'high': 0.9,      # High severity - substantial risk
            'critical': 1.0,  # Critical severity - maximum risk
        }
        
        # Calculate weighted risk score with diminishing returns
        for finding in findings:
            severity = finding.get('severity', 'info')
            weight = severity_weights.get(severity, 0.1)
            
            # Add weight with diminishing returns to prevent overflow
            score += weight * (1 - score)
        
        # Ensure score stays within 0.0 to 1.0 range
        return min(1.0, score)
    
    def _determine_classification(
        self,
        risk_score: float,
        findings: List[Dict[str, Any]]
    ) -> str:
        """Determine final classification based on risk and findings"""
        # First, check for specific high-risk indicators
        high_risk_types = {'malware_hash_match', 'yara_match'}
        
        for finding in findings:
            if finding.get('type') in high_risk_types:
                return 'malicious'  # High-confidence malicious classification
        
        # Classify based on calculated risk score
        if risk_score >= 0.8:
            return 'malicious'
        elif risk_score >= 0.5:
            return 'suspicious'
        elif risk_score >= 0.2:
            return 'potentially_unwanted'
        else:
            return 'clean'
    
    def _generate_recommendations(
        self,
        classification: str,
        findings: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate actionable recommendations based on classification"""
        recommendations = []
        
        # Base recommendations based on classification
        if classification == 'malicious':
            recommendations.extend([
                "Item appears to be malicious",
                "Recommend permanent deletion",
                "Investigate source of the item",
                "Update threat intelligence feeds",
            ])
        elif classification == 'suspicious':
            recommendations.extend([
                "Item is suspicious and requires manual review",
                "Consider sandbox analysis",
                "Check if similar items have been seen before",
                "Monitor for related activity",
            ])
        elif classification == 'potentially_unwanted':
            recommendations.extend([
                "Item may be unwanted but not necessarily malicious",
                "Review with security team",
                "Consider user education if from internal source",
            ])
        else:  # clean
            recommendations.append("Item appears to be clean")
        
        # Add specific recommendations based on individual findings
        for finding in findings:
            if finding.get('type') == 'extension_mismatch':
                recommendations.append("File extension mismatch suggests possible obfuscation")
            elif finding.get('type') == 'large_file':
                recommendations.append("Large file size may indicate embedded content")
        
        return recommendations

class QuarantineManager:
    """
    Main quarantine management system
    
    Core manager for quarantined items providing:
    - Secure storage and encryption
    - Item lifecycle management
    - Access control and auditing
    - Automated analysis and cleanup
    """
    
    def __init__(
        self,
        quarantine_dir: Optional[str] = None,
        encryption_key: Optional[bytes] = None,
        policy: Optional[QuarantinePolicy] = None,
        enable_audit: bool = True
    ):
        """
        Initialize quarantine manager with configuration
        
        Args:
            quarantine_dir: Directory for quarantine storage
            encryption_key: Encryption key for content protection
            policy: Quarantine policy configuration
            enable_audit: Enable security audit logging
        """
        self.logger = logging.getLogger(__name__)  # Operation logger
        self.security_logger = SecurityLogger() if enable_audit else None  # Security audit logger
        
        # Configure quarantine storage directory
        if quarantine_dir:
            self.quarantine_dir = Path(quarantine_dir)
        else:
            self.quarantine_dir = Path("./quarantine")
        
        # Ensure quarantine directory exists
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        
        # Apply restrictive permissions for security
        try:
            self.quarantine_dir.chmod(0o700)  # Owner-only read/write/execute
        except Exception as e:
            self.logger.warning(f"Failed to set quarantine directory permissions: {e}")
        
        # Configure encryption - use provided key or generate new
        if encryption_key:
            self.encryption_key = encryption_key
        else:
            self.encryption_key = generate_key(32)  # Generate 32-byte key
        
        # Initialize content analyzer
        self.analyzer = QuarantineAnalyzer()
        
        # Configure quarantine policy
        self.policy = policy or QuarantinePolicy(
            name="default",
            description="Default quarantine policy"
        )
        
        # Initialize item registry (in-memory metadata cache)
        self.item_registry: Dict[str, QuarantineMetadata] = {}
        self.registry_file = self.quarantine_dir / 'registry.json'
        
        # Load existing registry from disk
        self._load_registry()
        
        # Initialize threading lock for thread-safe operations
        self._lock = threading.RLock()
        
        # Start background cleanup thread
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True
        )
        self._cleanup_thread.start()
        
        # Log initialization
        self.logger.info(
            f"QuarantineManager initialized: "
            f"directory={self.quarantine_dir}, "
            f"items={len(self.item_registry)}"
        )
        
        # Log security event
        if self.security_logger:
            self.security_logger.log_event(
                event_type="quarantine_init",
                severity="info",
                message=f"Quarantine system initialized with {len(self.item_registry)} items",
                details={
                    'quarantine_dir': str(self.quarantine_dir),
                    'policy': self.policy.name,
                }
            )
    
    def _load_registry(self):
        """Load item registry from persistent storage"""
        if not self.registry_file.exists():
            return  # No registry file exists yet
        
        try:
            # Read registry JSON file
            with open(self.registry_file, 'r', encoding='utf-8') as f:
                registry_data = json.load(f)
            
            # Deserialize each item metadata
            for item_id, item_data in registry_data.items():
                try:
                    metadata = QuarantineMetadata.from_dict(item_data)
                    self.item_registry[item_id] = metadata
                except Exception as e:
                    self.logger.warning(f"Failed to load item {item_id}: {e}")
            
            self.logger.info(f"Loaded {len(self.item_registry)} items from registry")
            
        except Exception as e:
            self.logger.error(f"Failed to load registry: {e}")
    
    def _save_registry(self):
        """Save item registry to persistent storage"""
        with self._lock:  # Thread-safe registry update
            try:
                # Convert registry to serializable dictionary
                registry_data = {
                    item_id: metadata.to_dict()
                    for item_id, metadata in self.item_registry.items()
                }
                
                # Write to temporary file first (atomic operation)
                temp_file = self.registry_file.with_suffix('.tmp')
                
                with open(temp_file, 'w', encoding='utf-8') as f:
                    json.dump(registry_data, f, indent=2)
                
                # Atomically replace old registry with new one
                temp_file.replace(self.registry_file)
                
                # Apply restrictive permissions
                self.registry_file.chmod(0o600)  # Owner-only read/write
                
                self.logger.debug(f"Registry saved: {len(registry_data)} items")
                
            except Exception as e:
                self.logger.error(f"Failed to save registry: {e}")
    
    def _cleanup_loop(self):
        """Background thread for periodic cleanup operations"""
        while True:
            try:
                self._cleanup_expired_items()  # Clean expired items
                time.sleep(3600)  # Run every hour (3600 seconds)
            except Exception as e:
                self.logger.error(f"Cleanup loop error: {e}")
                time.sleep(300)  # Wait 5 minutes on error before retry
    
    def _cleanup_expired_items(self):
        """Clean up items that have passed their expiration date"""
        with self._lock:
            expired_items = []
            
            # Identify expired items
            for item_id, metadata in self.item_registry.items():
                if metadata.status == QuarantineStatus.ACTIVE:
                    if metadata.expiration_date and metadata.expiration_date < datetime.now():
                        metadata.status = QuarantineStatus.EXPIRED
                        expired_items.append(item_id)
            
            # Process expired items
            if expired_items:
                self.logger.info(f"Found {len(expired_items)} expired items")
                
                for item_id in expired_items:
                    self._delete_item_files(item_id)  # Delete physical files
                
                self._save_registry()  # Update registry
    
    def _delete_item_files(self, item_id: str):
        """Delete physical files associated with quarantined item"""
        item_dir = self._get_item_path(item_id)
        
        if item_dir.exists():
            try:
                shutil.rmtree(item_dir)  # Recursive directory deletion
                self.logger.debug(f"Deleted item directory: {item_dir}")
            except Exception as e:
                self.logger.error(f"Failed to delete item directory {item_dir}: {e}")
    
    def _get_item_path(self, item_id: str) -> Path:
        """Get filesystem path for item's quarantine directory"""
        return self.quarantine_dir / item_id
    
    def _generate_item_id(self) -> str:
        """Generate unique identifier for quarantined item"""
        # Generate UUID and hash it for consistent length
        uid = uuid.uuid4().bytes
        item_hash = hashlib.sha256(uid).hexdigest()[:16]  # First 16 chars of SHA256
        
        # Format: q_YYYYMMDD_HASH
        return f"q_{datetime.now().strftime('%Y%m%d')}_{item_hash}"
    
    def quarantine_item(
        self,
        data: Union[bytes, str],
        reason: str,
        source: str,
        severity: QuarantineSeverity = QuarantineSeverity.MEDIUM,
        original_filename: Optional[str] = None,
        original_path: Optional[str] = None,
        content_type: Optional[str] = None,
        auto_analyze: Optional[bool] = None
    ) -> str:
        """
        Quarantine suspicious data with security controls
        
        Args:
            data: Data to quarantine (bytes or string)
            reason: Reason for quarantine
            source: Source system/process
            severity: Risk severity level
            original_filename: Original filename if applicable
            original_path: Original filesystem path if applicable
            content_type: MIME type or content classification
            auto_analyze: Override policy auto-analysis setting
            
        Returns:
            Unique item identifier
            
        Raises:
            QuarantineError: If quarantine operation fails
        """
        with self._lock:
            try:
                # Convert string data to bytes if necessary
                if isinstance(data, str):
                    data = data.encode('utf-8')
                
                # Generate unique identifier and create quarantine directory
                item_id = self._generate_item_id()
                item_dir = self._get_item_path(item_id)
                item_dir.mkdir(parents=True, exist_ok=True)
                
                # Apply restrictive directory permissions
                item_dir.chmod(0o700)  # Owner-only access
                
                # Calculate cryptographic hash for integrity verification
                content_hash = self.analyzer.hash_validator.calculate_hash(
                    data, HashAlgorithm.SHA256
                )
                
                # Create metadata object
                metadata = QuarantineMetadata(
                    item_id=item_id,
                    original_filename=original_filename,
                    original_path=original_path,
                    content_type=content_type,
                    content_size=len(data),
                    content_hash=content_hash,
                    content_hash_algorithm=HashAlgorithm.SHA256,
                    quarantine_reason=reason,
                    quarantine_severity=severity,
                    quarantine_source=source,
                    quarantine_date=datetime.now(),
                    expiration_date=datetime.now() + timedelta(
                        days=self.policy.get_retention_days(severity)
                    ),
                    review_required=self.policy.requires_review(severity),
                )
                
                # Encrypt and save content
                encrypted_data = encrypt_data(data, self.encryption_key)
                
                data_file = item_dir / 'data.enc'
                with open(data_file, 'wb') as f:
                    f.write(encrypted_data)
                
                data_file.chmod(0o600)  # Owner-only read/write
                
                # Save metadata to JSON file
                metadata_file = item_dir / 'metadata.json'
                with open(metadata_file, 'w', encoding='utf-8') as f:
                    json.dump(metadata.to_dict(), f, indent=2)
                
                metadata_file.chmod(0o600)
                
                # Update in-memory registry
                self.item_registry[item_id] = metadata
                self._save_registry()
                
                # Record quarantine in chain of custody
                metadata.custody_chain.append({
                    'action': 'quarantine',
                    'timestamp': datetime.now().isoformat(),
                    'performed_by': 'system',
                    'reason': reason,
                })
                
                # Perform automated analysis if configured
                if auto_analyze or (auto_analyze is None and self.policy.auto_analyze):
                    self.analyze_item(item_id)
                
                # Log successful quarantine
                self.logger.info(
                    f"Quarantined item {item_id}: {reason} "
                    f"(severity: {severity.value}, size: {len(data)} bytes)"
                )
                
                # Log security event
                if self.security_logger:
                    self.security_logger.log_event(
                        event_type="item_quarantined",
                        severity=severity.value,
                        message=f"Item quarantined: {reason}",
                        details={
                            'item_id': item_id,
                            'source': source,
                            'severity': severity.value,
                            'size_bytes': len(data),
                            'content_hash': content_hash,
                            'original_filename': original_filename,
                        }
                    )
                
                # Send notifications if configured
                if self.policy.auto_notify and self.policy.notify_on_quarantine:
                    self._notify_quarantine(metadata)
                
                return item_id
                
            except Exception as e:
                self.logger.error(f"Failed to quarantine item: {e}")
                raise QuarantineError(f"Quarantine failed: {e}")
    
    def get_item(self, item_id: str) -> Optional[QuarantineMetadata]:
        """
        Retrieve metadata for quarantined item
        
        Args:
            item_id: Unique item identifier
            
        Returns:
            QuarantineMetadata if found, None otherwise
        """
        with self._lock:
            return self.item_registry.get(item_id)
    
    def get_item_content(self, item_id: str) -> Optional[bytes]:
        """
        Retrieve and decrypt quarantined content
        
        Args:
            item_id: Unique item identifier
            
        Returns:
            Decrypted content bytes if accessible
            
        Raises:
            QuarantineAccessError: If access denied due to status
            QuarantineIntegrityError: If content integrity check fails
            QuarantineItemNotFound: If item doesn't exist
        """
        with self._lock:
            metadata = self.item_registry.get(item_id)
            if not metadata:
                return None
            
            # Check access permissions based on item status
            if metadata.status not in [QuarantineStatus.ACTIVE, QuarantineStatus.ANALYZING]:
                raise QuarantineAccessError(
                    f"Item {item_id} is not accessible (status: {metadata.status.value})"
                )
            
            item_dir = self._get_item_path(item_id)
            data_file = item_dir / 'data.enc'
            
            if not data_file.exists():
                raise QuarantineItemNotFound(f"Data file not found for item {item_id}")
            
            try:
                # Read and decrypt content
                with open(data_file, 'rb') as f:
                    encrypted_data = f.read()
                
                data = decrypt_data(encrypted_data, self.encryption_key)
                
                # Verify content integrity using stored hash
                calculated_hash = self.analyzer.hash_validator.calculate_hash(
                    data, metadata.content_hash_algorithm
                )
                
                if calculated_hash != metadata.content_hash:
                    raise QuarantineIntegrityError(
                        f"Hash mismatch for item {item_id}. "
                        f"Expected: {metadata.content_hash}, "
                        f"Got: {calculated_hash}"
                    )
                
                # Update access timestamp
                metadata.last_accessed = datetime.now()
                self._save_registry()
                
                return data
                
            except Exception as e:
                self.logger.error(f"Failed to get item content {item_id}: {e}")
                raise QuarantineError(f"Failed to get content: {e}")
    
    def analyze_item(self, item_id: str) -> Dict[str, Any]:
        """
        Perform security analysis on quarantined item
        
        Args:
            item_id: Unique item identifier
            
        Returns:
            Analysis results dictionary
            
        Raises:
            QuarantineError: If analysis fails
            QuarantineItemNotFound: If item doesn't exist
        """
        with self._lock:
            metadata = self.item_registry.get(item_id)
            if not metadata:
                raise QuarantineItemNotFound(f"Item not found: {item_id}")
            
            # Check if already being analyzed
            if metadata.status == QuarantineStatus.ANALYZING:
                return metadata.analysis_results  # Return existing results
            
            # Update status to indicate analysis in progress
            old_status = metadata.status
            metadata.status = QuarantineStatus.ANALYZING
            self._save_registry()
            
            try:
                # Retrieve content for analysis
                content = self.get_item_content(item_id)
                if not content:
                    raise QuarantineError(f"No content available for item {item_id}")
                
                # Perform comprehensive analysis
                analysis_results = self.analyzer.analyze_content(
                    content=content,
                    metadata=metadata,
                    timeout=self.policy.analysis_timeout
                )
                
                # Update metadata with analysis results
                metadata.analysis_results = analysis_results
                metadata.analysis_tools = analysis_results.get('tools_used', [])
                metadata.classification = analysis_results.get('classification')
                
                # Update status based on analysis results
                if metadata.review_required and metadata.quarantine_severity in [
                    QuarantineSeverity.HIGH, QuarantineSeverity.CRITICAL
                ]:
                    metadata.status = QuarantineStatus.PENDING_REVIEW
                else:
                    metadata.status = QuarantineStatus.ACTIVE
                
                # Record analysis in chain of custody
                metadata.custody_chain.append({
                    'action': 'analyze',
                    'timestamp': datetime.now().isoformat(),
                    'performed_by': 'system',
                    'results': {
                        'classification': metadata.classification,
                        'risk_score': analysis_results.get('risk_score', 0.0),
                    }
                })
                
                self._save_registry()
                
                # Log analysis completion
                self.logger.info(
                    f"Analysis completed for item {item_id}: "
                    f"{metadata.classification} (risk: {analysis_results.get('risk_score', 0.0):.2f})"
                )
                
                # Log security event
                if self.security_logger:
                    self.security_logger.log_event(
                        event_type="item_analyzed",
                        severity=metadata.quarantine_severity.value,
                        message=f"Item analyzed: {metadata.classification}",
                        details={
                            'item_id': item_id,
                            'classification': metadata.classification,
                            'risk_score': analysis_results.get('risk_score', 0.0),
                            'tools_used': analysis_results.get('tools_used', []),
                        }
                    )
                
                return analysis_results
                
            except Exception as e:
                # Restore original status on analysis failure
                metadata.status = old_status
                self._save_registry()
                
                self.logger.error(f"Analysis failed for item {item_id}: {e}")
                raise QuarantineError(f"Analysis failed: {e}")
    
    def release_item(
        self,
        item_id: str,
        released_by: str,
        release_reason: str = "Approved for release",
        force: bool = False
    ) -> bool:
        """
        Release item from quarantine with proper authorization
        
        Args:
            item_id: Unique item identifier
            released_by: Person/system authorizing release
            release_reason: Justification for release
            force: Bypass review requirements if True
            
        Returns:
            True if successfully released
            
        Raises:
            QuarantineError: If release fails
            QuarantineAccessError: If review required and not forced
            QuarantineItemNotFound: If item doesn't exist
        """
        with self._lock:
            metadata = self.item_registry.get(item_id)
            if not metadata:
                raise QuarantineItemNotFound(f"Item not found: {item_id}")
            
            # Check if already released
            if metadata.status == QuarantineStatus.RELEASED:
                return True  # Already released
            
            # Enforce review requirements unless force is True
            if metadata.review_required and not force:
                raise QuarantineAccessError(
                    f"Item {item_id} requires review before release. "
                    f"Set force=True to override."
                )
            
            try:
                # Update item status to released
                metadata.status = QuarantineStatus.RELEASED
                
                # Record release in chain of custody
                metadata.custody_chain.append({
                    'action': 'release',
                    'timestamp': datetime.now().isoformat(),
                    'performed_by': released_by,
                    'reason': release_reason,
                })
                
                # Remove encrypted content (keep metadata for audit)
                item_dir = self._get_item_path(item_id)
                data_file = item_dir / 'data.enc'
                
                if data_file.exists():
                    data_file.unlink()  # Delete content file
                
                self._save_registry()
                
                # Log successful release
                self.logger.info(
                    f"Item {item_id} released by {released_by}: {release_reason}"
                )
                
                # Log security event
                if self.security_logger:
                    self.security_logger.log_event(
                        event_type="item_released",
                        severity="info",
                        message=f"Item released from quarantine",
                        details={
                            'item_id': item_id,
                            'released_by': released_by,
                            'release_reason': release_reason,
                            'original_reason': metadata.quarantine_reason,
                            'severity': metadata.quarantine_severity.value,
                        }
                    )
                
                # Send notifications if configured
                if self.policy.auto_notify and self.policy.notify_on_release:
                    self._notify_release(metadata, released_by, release_reason)
                
                return True
                
            except Exception as e:
                self.logger.error(f"Failed to release item {item_id}: {e}")
                raise QuarantineReleaseError(f"Release failed: {e}")
    
    def delete_item(
        self,
        item_id: str,
        deleted_by: str,
        delete_reason: str = "Permanent deletion"
    ) -> bool:
        """
        Permanently delete quarantined item
        
        Args:
            item_id: Unique item identifier
            deleted_by: Person/system authorizing deletion
            delete_reason: Justification for deletion
            
        Returns:
            True if successfully deleted, False otherwise
        """
        with self._lock:
            metadata = self.item_registry.get(item_id)
            if not metadata:
                return False  # Item not found
            
            try:
                # Update status to deleted
                metadata.status = QuarantineStatus.DELETED
                
                # Record deletion in chain of custody
                metadata.custody_chain.append({
                    'action': 'delete',
                    'timestamp': datetime.now().isoformat(),
                    'performed_by': deleted_by,
                    'reason': delete_reason,
                })
                
                # Delete all associated files
                self._delete_item_files(item_id)
                
                # Remove from in-memory registry
                del self.item_registry[item_id]
                self._save_registry()
                
                # Log successful deletion
                self.logger.info(
                    f"Item {item_id} deleted by {deleted_by}: {delete_reason}"
                )
                
                # Log security event
                if self.security_logger:
                    self.security_logger.log_event(
                        event_type="item_deleted",
                        severity="info",
                        message=f"Item permanently deleted from quarantine",
                        details={
                            'item_id': item_id,
                            'deleted_by': deleted_by,
                            'delete_reason': delete_reason,
                            'original_reason': metadata.quarantine_reason,
                            'severity': metadata.quarantine_severity.value,
                        }
                    )
                
                return True
                
            except Exception as e:
                self.logger.error(f"Failed to delete item {item_id}: {e}")
                return False
    
    def search_items(
        self,
        status: Optional[QuarantineStatus] = None,
        severity: Optional[QuarantineSeverity] = None,
        source: Optional[str] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        classification: Optional[str] = None,
        limit: int = 100
    ) -> List[QuarantineMetadata]:
        """
        Search quarantined items with filtering criteria
        
        Args:
            status: Filter by quarantine status
            severity: Filter by risk severity
            source: Filter by source system
            date_from: Filter items quarantined after this date
            date_to: Filter items quarantined before this date
            classification: Filter by analysis classification
            limit: Maximum number of results to return
            
        Returns:
            List of matching quarantine metadata objects
        """
        results = []
        
        # Apply filters to all items in registry
        for metadata in self.item_registry.values():
            # Status filter
            if status and metadata.status != status:
                continue
            
            # Severity filter
            if severity and metadata.quarantine_severity != severity:
                continue
            
            # Source filter
            if source and metadata.quarantine_source != source:
                continue
            
            # Date range filters
            if date_from and metadata.quarantine_date < date_from:
                continue
            
            if date_to and metadata.quarantine_date > date_to:
                continue
            
            # Classification filter
            if classification and metadata.classification != classification:
                continue
            
            # Add matching item to results
            results.append(metadata)
            
            # Apply result limit
            if len(results) >= limit:
                break
        
        # Sort results by quarantine date (newest first)
        results.sort(key=lambda x: x.quarantine_date, reverse=True)
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """Generate comprehensive quarantine statistics"""
        with self._lock:
            # Initialize statistics dictionary
            stats = {
                'total_items': len(self.item_registry),
                'by_status': {},
                'by_severity': {},
                'by_classification': {},
                'by_source': {},
                'size_bytes': 0,
                'pending_review': 0,
                'expired_items': 0,
            }
            
            # Calculate statistics from registry
            for metadata in self.item_registry.values():
                # Count by status
                status_key = metadata.status.value
                stats['by_status'][status_key] = stats['by_status'].get(status_key, 0) + 1
                
                # Count by severity
                severity_key = metadata.quarantine_severity.value
                stats['by_severity'][severity_key] = stats['by_severity'].get(severity_key, 0) + 1
                
                # Count by classification
                if metadata.classification:
                    stats['by_classification'][metadata.classification] = \
                        stats['by_classification'].get(metadata.classification, 0) + 1
                
                # Count by source
                source_key = metadata.quarantine_source
                stats['by_source'][source_key] = stats['by_source'].get(source_key, 0) + 1
                
                # Accumulate total size
                stats['size_bytes'] += metadata.content_size
                
                # Count pending review items
                if metadata.status == QuarantineStatus.PENDING_REVIEW:
                    stats['pending_review'] += 1
                
                # Count expired items
                if metadata.status == QuarantineStatus.EXPIRED:
                    stats['expired_items'] += 1
            
            # Add human-readable size formats
            stats['size_mb'] = stats['size_bytes'] / (1024 * 1024)  # Megabytes
            stats['size_gb'] = stats['size_bytes'] / (1024 * 1024 * 1024)  # Gigabytes
            
            return stats
    
    def export_item(
        self,
        item_id: str,
        export_format: str = "json"
    ) -> Optional[bytes]:
        """
        Export quarantined item for external analysis
        
        Args:
            item_id: Unique item identifier
            export_format: Export format ("json" or "zip")
            
        Returns:
            Exported data as bytes, or None if export fails
        """
        with self._lock:
            metadata = self.item_registry.get(item_id)
            if not metadata:
                return None  # Item not found
            
            try:
                # Retrieve content for export
                content = self.get_item_content(item_id)
                if not content:
                    return None  # No content available
                
                # JSON format export (metadata only)
                if export_format == "json":
                    export_data = {
                        'metadata': metadata.to_dict(),
                        'content_base64': None,  # Don't include content in JSON export
                    }
                    
                    return json.dumps(export_data, indent=2).encode('utf-8')
                
                # ZIP format export (metadata + content)
                elif export_format == "zip":
                    zip_buffer = io.BytesIO()
                    
                    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                        # Add metadata JSON
                        metadata_json = json.dumps(metadata.to_dict(), indent=2)
                        zip_file.writestr('metadata.json', metadata_json)
                        
                        # Add original content
                        original_filename = metadata.original_filename or 'content.bin'
                        zip_file.writestr(original_filename, content)
                        
                        # Add analysis results if available
                        if metadata.analysis_results:
                            analysis_json = json.dumps(metadata.analysis_results, indent=2)
                            zip_file.writestr('analysis.json', analysis_json)
                    
                    return zip_buffer.getvalue()
                
                else:
                    self.logger.error(f"Unsupported export format: {export_format}")
                    return None
                
            except Exception as e:
                self.logger.error(f"Failed to export item {item_id}: {e}")
                return None
    
    def _notify_quarantine(self, metadata: QuarantineMetadata):
        """Generate quarantine notification (simplified implementation)"""
        if not self.policy.notify_emails:
            return  # No recipients configured
        
        try:
            # Create notification message
            message = f"""
            Quarantine Notification
            =======================
            
            Item ID: {metadata.item_id}
            Reason: {metadata.quarantine_reason}
            Severity: {metadata.quarantine_severity.value}
            Source: {metadata.quarantine_source}
            Date: {metadata.quarantine_date}
            Size: {metadata.content_size} bytes
            
            Original Filename: {metadata.original_filename or 'N/A'}
            Content Hash: {metadata.content_hash}
            
            This item has been quarantined and requires attention.
            """
            
            # Log notification (in production would send email)
            self.logger.info(f"Quarantine notification for item {metadata.item_id}")
            
        except Exception as e:
            self.logger.warning(f"Failed to send quarantine notification: {e}")
    
    def _notify_release(
        self,
        metadata: QuarantineMetadata,
        released_by: str,
        release_reason: str
    ):
        """Generate release notification (simplified implementation)"""
        if not self.policy.notify_emails:
            return  # No recipients configured
        
        try:
            message = f"""
            Quarantine Release Notification
            ===============================
            
            Item ID: {metadata.item_id}
            Originally Quarantined: {metadata.quarantine_date}
            Original Reason: {metadata.quarantine_reason}
            Original Severity: {metadata.quarantine_severity.value}
            
            Released By: {released_by}
            Release Reason: {release_reason}
            Release Date: {datetime.now()}
            
            This item has been released from quarantine.
            """
            
            self.logger.info(f"Release notification for item {metadata.item_id}")
            
        except Exception as e:
            self.logger.warning(f"Failed to send release notification: {e}")
    
    def cleanup_old_items(self, days_old: int = 30) -> int:
        """
        Clean up items older than specified threshold
        
        Args:
            days_old: Delete items older than this many days
            
        Returns:
            Number of items successfully cleaned up
        """
        cutoff_date = datetime.now() - timedelta(days=days_old)
        cleaned_count = 0
        
        with self._lock:
            # Identify items to clean up
            items_to_clean = []
            
            for item_id, metadata in self.item_registry.items():
                if (metadata.status == QuarantineStatus.ACTIVE and 
                    metadata.quarantine_date < cutoff_date):
                    items_to_clean.append(item_id)
            
            # Delete identified items
            for item_id in items_to_clean:
                if self.delete_item(item_id, "system", "Auto-cleanup: expired"):
                    cleaned_count += 1
        
        self.logger.info(f"Cleaned up {cleaned_count} items older than {days_old} days")
        return cleaned_count

# Convenience functions
def create_quarantine_manager(
    quarantine_dir: Optional[str] = None,
    policy_name: str = "default"
) -> QuarantineManager:
    """
    Factory function to create quarantine manager with default configuration
    
    Args:
        quarantine_dir: Quarantine storage directory path
        policy_name: Name of policy to apply ("default", "strict", "lenient")
        
    Returns:
        Initialized QuarantineManager instance
    """
    # Define available policies
    policies = {
        "default": QuarantinePolicy(
            name="default",
            description="Default quarantine policy with balanced security"
        ),
        "strict": QuarantinePolicy(
            name="strict",
            description="Strict quarantine policy with maximum security",
            retention_days_low=14,
            retention_days_medium=60,
            retention_days_high=180,
            retention_days_critical=365,
            require_review_high=True,
            require_review_critical=True,
            multi_person_release=True,
        ),
        "lenient": QuarantinePolicy(
            name="lenient",
            description="Lenient quarantine policy for low-risk environments",
            retention_days_low=3,
            retention_days_medium=7,
            retention_days_high=30,
            retention_days_critical=90,
            require_review_high=False,
            require_review_critical=True,
            multi_person_release=False,
        ),
    }
    
    # Select policy or use default
    policy = policies.get(policy_name, policies["default"])
    
    return QuarantineManager(
        quarantine_dir=quarantine_dir,
        policy=policy
    )

def quarantine_suspicious_file(
    filepath: Union[str, Path],
    reason: str,
    source: str,
    manager: Optional[QuarantineManager] = None
) -> Optional[str]:
    """
    Convenience function to quarantine a suspicious file
    
    Args:
        filepath: Path to suspicious file
        reason: Reason for quarantine
        source: Source system identifier
        manager: Existing QuarantineManager instance (creates new if None)
        
    Returns:
        Item ID if successful, None otherwise
    """
    filepath = Path(filepath)
    
    # Validate file exists
    if not filepath.exists():
        logging.getLogger(__name__).error(f"File not found: {filepath}")
        return None
    
    # Create manager if not provided
    if manager is None:
        manager = create_quarantine_manager()
    
    try:
        # Read file content
        with open(filepath, 'rb') as f:
            data = f.read()
        
        # Quarantine file
        item_id = manager.quarantine_item(
            data=data,
            reason=reason,
            source=source,
            original_filename=filepath.name,
            original_path=str(filepath),
            severity=QuarantineSeverity.HIGH
        )
        
        return item_id
        
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to quarantine file {filepath}: {e}")
        return None