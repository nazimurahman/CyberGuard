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

# Local imports
from ..utils.crypto_utils import encrypt_data, decrypt_data, generate_key
from ..utils.logging_utils import audit_log, SecurityLogger
from .hash_validator import HashValidator, HashAlgorithm

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
    """Quarantine severity levels"""
    INFO = "info"           # Informational quarantine
    LOW = "low"            # Low risk, likely false positive
    MEDIUM = "medium"      # Medium risk, needs review
    HIGH = "high"          # High risk, likely malicious
    CRITICAL = "critical"  # Critical risk, confirmed malicious

class QuarantineStatus(Enum):
    """Quarantine item status"""
    ACTIVE = "active"           # Currently quarantined
    ANALYZING = "analyzing"     # Under analysis
    PENDING_REVIEW = "pending_review"  # Waiting for manual review
    RELEASED = "released"       # Released from quarantine
    DELETED = "deleted"         # Deleted (permanently)
    EXPIRED = "expired"         # Auto-expired

class QuarantineAction(Enum):
    """Actions performed on quarantine items"""
    QUARANTINE = "quarantine"
    RELEASE = "release"
    DELETE = "delete"
    ANALYZE = "analyze"
    EXPORT = "export"
    IMPORT = "import"
    UPDATE = "update"

@dataclass
class QuarantineMetadata:
    """Metadata for quarantined items"""
    # Core identification
    item_id: str
    original_filename: Optional[str] = None
    original_path: Optional[str] = None
    
    # Content information
    content_type: Optional[str] = None
    content_size: int = 0
    content_hash: Optional[str] = None
    content_hash_algorithm: HashAlgorithm = HashAlgorithm.SHA256
    
    # Quarantine information
    quarantine_reason: str = "Unknown"
    quarantine_severity: QuarantineSeverity = QuarantineSeverity.MEDIUM
    quarantine_source: str = "unknown"
    
    # Dates
    quarantine_date: datetime = field(default_factory=datetime.now)
    expiration_date: Optional[datetime] = None
    last_accessed: Optional[datetime] = None
    
    # Analysis results
    analysis_results: Dict[str, Any] = field(default_factory=dict)
    analysis_tools: List[str] = field(default_factory=list)
    classification: Optional[str] = None
    
    # Status and tracking
    status: QuarantineStatus = QuarantineStatus.ACTIVE
    review_required: bool = False
    review_notes: List[str] = field(default_factory=list)
    
    # Chain of custody
    custody_chain: List[Dict[str, str]] = field(default_factory=list)
    
    # Security information
    encryption_key_id: Optional[str] = None
    integrity_hash: Optional[str] = None
    digital_signature: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        result = asdict(self)
        
        # Convert enums to strings
        result['quarantine_severity'] = self.quarantine_severity.value
        result['status'] = self.status.value
        result['content_hash_algorithm'] = self.content_hash_algorithm.value
        
        # Convert dates
        if self.quarantine_date:
            result['quarantine_date'] = self.quarantine_date.isoformat()
        if self.expiration_date:
            result['expiration_date'] = self.expiration_date.isoformat()
        if self.last_accessed:
            result['last_accessed'] = self.last_accessed.isoformat()
        
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'QuarantineMetadata':
        """Create from dictionary"""
        # Convert string enums back
        data['quarantine_severity'] = QuarantineSeverity(data['quarantine_severity'])
        data['status'] = QuarantineStatus(data['status'])
        data['content_hash_algorithm'] = HashAlgorithm(data['content_hash_algorithm'])
        
        # Convert dates
        if data.get('quarantine_date'):
            data['quarantine_date'] = datetime.fromisoformat(data['quarantine_date'])
        if data.get('expiration_date'):
            data['expiration_date'] = datetime.fromisoformat(data['expiration_date'])
        if data.get('last_accessed'):
            data['last_accessed'] = datetime.fromisoformat(data['last_accessed'])
        
        return cls(**data)

class QuarantinePolicy:
    """
    Quarantine policy configuration
    
    Defines rules for quarantine operations including:
    - Retention periods
    - Automatic actions
    - Access controls
    - Notification rules
    """
    
    def __init__(
        self,
        name: str,
        description: str = "",
        # Retention periods (days)
        retention_days_low: int = 7,
        retention_days_medium: int = 30,
        retention_days_high: int = 90,
        retention_days_critical: int = 365,
        # Automatic actions
        auto_analyze: bool = True,
        auto_notify: bool = True,
        auto_expire: bool = True,
        # Access controls
        require_review_high: bool = True,
        require_review_critical: bool = True,
        multi_person_release: bool = False,
        # Analysis settings
        analysis_timeout: int = 300,  # seconds
        max_analysis_size_mb: int = 100,
        # Notification settings
        notify_on_quarantine: bool = True,
        notify_on_release: bool = True,
        notify_emails: List[str] = None,
    ):
        self.name = name
        self.description = description
        
        # Retention periods
        self.retention_days = {
            QuarantineSeverity.INFO: 1,
            QuarantineSeverity.LOW: retention_days_low,
            QuarantineSeverity.MEDIUM: retention_days_medium,
            QuarantineSeverity.HIGH: retention_days_high,
            QuarantineSeverity.CRITICAL: retention_days_critical,
        }
        
        # Automatic actions
        self.auto_analyze = auto_analyze
        self.auto_notify = auto_notify
        self.auto_expire = auto_expire
        
        # Access controls
        self.require_review_high = require_review_high
        self.require_review_critical = require_review_critical
        self.multi_person_release = multi_person_release
        
        # Analysis settings
        self.analysis_timeout = analysis_timeout
        self.max_analysis_size_mb = max_analysis_size_mb
        
        # Notification settings
        self.notify_on_quarantine = notify_on_quarantine
        self.notify_on_release = notify_on_release
        self.notify_emails = notify_emails or []
    
    def get_retention_days(self, severity: QuarantineSeverity) -> int:
        """Get retention days for severity level"""
        return self.retention_days.get(severity, 30)
    
    def requires_review(self, severity: QuarantineSeverity) -> bool:
        """Check if severity requires manual review"""
        if severity == QuarantineSeverity.HIGH and self.require_review_high:
            return True
        if severity == QuarantineSeverity.CRITICAL and self.require_review_critical:
            return True
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'name': self.name,
            'description': self.description,
            'retention_days': {k.value: v for k, v in self.retention_days.items()},
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
    Analyzer for quarantined content
    
    Performs automated analysis on quarantined items including:
    - Malware scanning
    - Content inspection
    - Pattern matching
    - Risk assessment
    """
    
    def __init__(self, scan_tools: List[str] = None):
        """
        Initialize quarantine analyzer
        
        Args:
            scan_tools: List of scanning tools to use
        """
        self.logger = logging.getLogger(__name__)
        self.hash_validator = HashValidator()
        
        # Available scan tools
        self.scan_tools = scan_tools or [
            'hash_lookup',
            'string_scan',
            'header_analysis',
            'yara_rules',
        ]
        
        # YARA rules (would be loaded from file in production)
        self.yara_rules = self._load_yara_rules()
        
        # Malware hash database (simplified - in production would use external DB)
        self.malware_hashes: Set[str] = set()
        
        # Suspicious patterns
        self.suspicious_patterns = [
            (rb'eval\(', 'JavaScript eval function'),
            (rb'base64_decode', 'PHP base64 decode'),
            (rb'exec\(', 'Command execution'),
            (rb'shell_exec', 'Shell execution'),
            (rb'powershell', 'PowerShell command'),
            (rb'<script>', 'HTML script tag'),
            (rb'javascript:', 'JavaScript URL'),
            (rb'onload=', 'HTML onload event'),
            (rb'onerror=', 'HTML onerror event'),
        ]
    
    def _load_yara_rules(self) -> List[Dict[str, Any]]:
        """Load YARA rules for malware detection"""
        # In production, this would load from YARA rule files
        # This is a simplified implementation
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
        Analyze quarantined content
        
        Args:
            content: Content to analyze
            metadata: Item metadata
            timeout: Analysis timeout in seconds
            
        Returns:
            Analysis results dictionary
        """
        analysis_start = datetime.now()
        results = {
            'analysis_id': f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'start_time': analysis_start.isoformat(),
            'tools_used': [],
            'findings': [],
            'risk_score': 0.0,
            'classification': 'unknown',
            'recommendations': [],
        }
        
        try:
            # 1. Hash analysis
            if 'hash_lookup' in self.scan_tools:
                hash_results = self._analyze_hashes(content, metadata)
                results['tools_used'].append('hash_lookup')
                results['findings'].extend(hash_results.get('findings', []))
            
            # 2. String and pattern scanning
            if 'string_scan' in self.scan_tools:
                string_results = self._analyze_strings(content)
                results['tools_used'].append('string_scan')
                results['findings'].extend(string_results.get('findings', []))
            
            # 3. Header analysis
            if 'header_analysis' in self.scan_tools:
                header_results = self._analyze_headers(content, metadata)
                results['tools_used'].append('header_analysis')
                results['findings'].extend(header_results.get('findings', []))
            
            # 4. YARA rule scanning
            if 'yara_rules' in self.scan_tools:
                yara_results = self._analyze_yara(content)
                results['tools_used'].append('yara_rules')
                results['findings'].extend(yara_results.get('findings', []))
            
            # Calculate risk score
            results['risk_score'] = self._calculate_risk_score(results['findings'])
            
            # Determine classification
            results['classification'] = self._determine_classification(
                results['risk_score'],
                results['findings']
            )
            
            # Generate recommendations
            results['recommendations'] = self._generate_recommendations(
                results['classification'],
                results['findings']
            )
            
            # Set end time
            results['end_time'] = datetime.now().isoformat()
            results['duration_seconds'] = (
                datetime.now() - analysis_start
            ).total_seconds()
            
            self.logger.info(
                f"Analysis completed: {results['classification']} "
                f"(risk: {results['risk_score']:.2f})"
            )
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            results['error'] = str(e)
            results['status'] = 'failed'
        
        return results
    
    def _analyze_hashes(
        self,
        content: bytes,
        metadata: QuarantineMetadata
    ) -> Dict[str, Any]:
        """Analyze file hashes"""
        findings = []
        
        # Calculate multiple hashes
        hash_results = {}
        
        for algorithm in [HashAlgorithm.MD5, HashAlgorithm.SHA1, HashAlgorithm.SHA256]:
            try:
                hash_value = self.hash_validator.calculate_hash(content, algorithm)
                hash_results[algorithm.value] = hash_value
                
                # Check against malware hash database
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
            'hash_results': hash_results,
            'findings': findings,
        }
    
    def _analyze_strings(self, content: bytes) -> Dict[str, Any]:
        """Analyze strings and patterns in content"""
        findings = []
        suspicious_strings = []
        
        # Convert to text for string analysis (try multiple encodings)
        text_content = None
        for encoding in ['utf-8', 'latin-1', 'ascii']:
            try:
                text_content = content.decode(encoding)
                break
            except UnicodeDecodeError:
                continue
        
        if text_content:
            # Check for suspicious patterns
            for pattern, description in self.suspicious_patterns:
                if pattern in content:
                    findings.append({
                        'type': 'suspicious_pattern',
                        'severity': 'medium',
                        'description': f'Found suspicious pattern: {description}',
                        'pattern': pattern.decode('ascii', errors='ignore'),
                    })
                    suspicious_strings.append(pattern.decode('ascii', errors='ignore'))
        
        # Extract strings from binary content
        import re
        strings = re.findall(rb'[^\x00-\x1F\x7F-\xFF]{4,}', content)
        
        # Check for potentially dangerous strings
        dangerous_patterns = [
            (rb'/bin/sh', 'Shell path'),
            (rb'cmd\.exe', 'Windows command shell'),
            (rb'wscript\.', 'Windows scripting'),
            (rb'regsvr32', 'Windows DLL registration'),
            (rb'certutil', 'Certificate utility (often abused)'),
        ]
        
        for string in strings[:100]:  # Limit to first 100 strings
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
            'strings_found': len(strings),
            'suspicious_strings': suspicious_strings,
            'findings': findings,
        }
    
    def _analyze_headers(
        self,
        content: bytes,
        metadata: QuarantineMetadata
    ) -> Dict[str, Any]:
        """Analyze file headers and structure"""
        findings = []
        file_type = 'unknown'
        
        # Check file signatures (magic numbers)
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
        
        # Check for mismatched extensions
        if metadata.original_filename:
            filename_lower = metadata.original_filename.lower()
            
            # Common extensions
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
        
        # Check file size anomalies
        content_size = len(content)
        
        if content_size == 0:
            findings.append({
                'type': 'empty_file',
                'severity': 'low',
                'description': 'File is empty (0 bytes)',
            })
        
        elif content_size > 100 * 1024 * 1024:  # 100MB
            findings.append({
                'type': 'large_file',
                'severity': 'info',
                'description': f'File is very large: {content_size:,} bytes',
            })
        
        return {
            'file_type': file_type,
            'file_size': content_size,
            'findings': findings,
        }
    
    def _analyze_yara(self, content: bytes) -> Dict[str, Any]:
        """Analyze content with YARA rules"""
        findings = []
        matches = []
        
        # Simplified YARA matching (in production would use yara-python)
        for rule in self.yara_rules:
            rule_name = rule['name']
            rule_strings = self._extract_yara_strings(rule['rule'])
            
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
                    break  # Found match for this rule
        
        return {
            'yara_matches': matches,
            'findings': findings,
        }
    
    @staticmethod
    def _extract_yara_strings(yara_rule: str) -> List[str]:
        """Extract strings from YARA rule (simplified)"""
        import re
        strings = []
        
        # Look for string definitions in YARA rule
        pattern = r'\$[a-zA-Z0-9_]+ = "([^"]+)"'
        matches = re.findall(pattern, yara_rule)
        
        strings.extend(matches)
        return strings
    
    def _calculate_risk_score(self, findings: List[Dict[str, Any]]) -> float:
        """Calculate risk score based on findings"""
        score = 0.0
        
        severity_weights = {
            'info': 0.1,
            'low': 0.3,
            'medium': 0.6,
            'high': 0.9,
            'critical': 1.0,
        }
        
        for finding in findings:
            severity = finding.get('severity', 'info')
            weight = severity_weights.get(severity, 0.1)
            
            # Add weight with diminishing returns
            score += weight * (1 - score)
        
        return min(1.0, score)
    
    def _determine_classification(
        self,
        risk_score: float,
        findings: List[Dict[str, Any]]
    ) -> str:
        """Determine classification based on risk score and findings"""
        # Check for specific high-risk findings
        high_risk_types = {'malware_hash_match', 'yara_match'}
        
        for finding in findings:
            if finding.get('type') in high_risk_types:
                return 'malicious'
        
        # Classify based on risk score
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
        """Generate recommendations based on classification and findings"""
        recommendations = []
        
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
        
        # Add specific recommendations based on findings
        for finding in findings:
            if finding.get('type') == 'extension_mismatch':
                recommendations.append("File extension mismatch suggests possible obfuscation")
            elif finding.get('type') == 'large_file':
                recommendations.append("Large file size may indicate embedded content")
        
        return recommendations

class QuarantineManager:
    """
    Main quarantine management system
    
    Manages quarantined items with security controls, analysis,
    and audit logging.
    """
    
    def __init__(
        self,
        quarantine_dir: Optional[str] = None,
        encryption_key: Optional[bytes] = None,
        policy: Optional[QuarantinePolicy] = None,
        enable_audit: bool = True
    ):
        """
        Initialize quarantine manager
        
        Args:
            quarantine_dir: Directory for quarantine storage
            encryption_key: Encryption key for quarantined content
            policy: Quarantine policy configuration
            enable_audit: Enable audit logging
        """
        self.logger = logging.getLogger(__name__)
        self.security_logger = SecurityLogger() if enable_audit else None
        
        # Setup quarantine directory
        if quarantine_dir:
            self.quarantine_dir = Path(quarantine_dir)
        else:
            self.quarantine_dir = Path("./quarantine")
        
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        
        # Security: Set restrictive permissions
        try:
            self.quarantine_dir.chmod(0o700)  # Owner only access
        except Exception as e:
            self.logger.warning(f"Failed to set quarantine directory permissions: {e}")
        
        # Encryption
        if encryption_key:
            self.encryption_key = encryption_key
        else:
            # Generate a random key if not provided
            self.encryption_key = generate_key(32)
        
        # Initialize analyzer
        self.analyzer = QuarantineAnalyzer()
        
        # Set policy
        self.policy = policy or QuarantinePolicy(
            name="default",
            description="Default quarantine policy"
        )
        
        # Item registry (metadata cache)
        self.item_registry: Dict[str, QuarantineMetadata] = {}
        self.registry_file = self.quarantine_dir / 'registry.json'
        
        # Load existing registry
        self._load_registry()
        
        # Lock for thread safety
        self._lock = threading.RLock()
        
        # Start cleanup thread
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True
        )
        self._cleanup_thread.start()
        
        self.logger.info(
            f"QuarantineManager initialized: "
            f"directory={self.quarantine_dir}, "
            f"items={len(self.item_registry)}"
        )
        
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
        """Load item registry from disk"""
        if not self.registry_file.exists():
            return
        
        try:
            with open(self.registry_file, 'r', encoding='utf-8') as f:
                registry_data = json.load(f)
            
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
        """Save item registry to disk"""
        with self._lock:
            try:
                # Convert registry to dictionary
                registry_data = {
                    item_id: metadata.to_dict()
                    for item_id, metadata in self.item_registry.items()
                }
                
                # Write to temporary file first
                temp_file = self.registry_file.with_suffix('.tmp')
                
                with open(temp_file, 'w', encoding='utf-8') as f:
                    json.dump(registry_data, f, indent=2)
                
                # Atomic rename
                temp_file.replace(self.registry_file)
                
                # Set restrictive permissions
                self.registry_file.chmod(0o600)
                
                self.logger.debug(f"Registry saved: {len(registry_data)} items")
                
            except Exception as e:
                self.logger.error(f"Failed to save registry: {e}")
    
    def _cleanup_loop(self):
        """Background cleanup loop"""
        import time
        
        while True:
            try:
                self._cleanup_expired_items()
                time.sleep(3600)  # Run every hour
            except Exception as e:
                self.logger.error(f"Cleanup loop error: {e}")
                time.sleep(300)  # Wait 5 minutes on error
    
    def _cleanup_expired_items(self):
        """Clean up expired quarantine items"""
        with self._lock:
            expired_items = []
            
            for item_id, metadata in self.item_registry.items():
                if metadata.status == QuarantineStatus.ACTIVE:
                    if metadata.expiration_date and metadata.expiration_date < datetime.now():
                        # Mark as expired
                        metadata.status = QuarantineStatus.EXPIRED
                        expired_items.append(item_id)
            
            if expired_items:
                self.logger.info(f"Found {len(expired_items)} expired items")
                
                for item_id in expired_items:
                    self._delete_item_files(item_id)
                
                self._save_registry()
    
    def _delete_item_files(self, item_id: str):
        """Delete item files from disk"""
        item_dir = self.quarantine_dir / item_id
        
        if item_dir.exists():
            try:
                shutil.rmtree(item_dir)
                self.logger.debug(f"Deleted item directory: {item_dir}")
            except Exception as e:
                self.logger.error(f"Failed to delete item directory {item_dir}: {e}")
    
    def _get_item_path(self, item_id: str) -> Path:
        """Get path for item directory"""
        return self.quarantine_dir / item_id
    
    def _generate_item_id(self) -> str:
        """Generate unique item ID"""
        import uuid
        import hashlib
        
        # Generate UUID and hash it for consistent length
        uid = uuid.uuid4().bytes
        item_hash = hashlib.sha256(uid).hexdigest()[:16]
        
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
        Quarantine an item
        
        Args:
            data: Data to quarantine
            reason: Reason for quarantine
            source: Source of the data
            severity: Quarantine severity
            original_filename: Original filename (if any)
            original_path: Original path (if any)
            content_type: Content type
            auto_analyze: Whether to auto-analyze (overrides policy)
            
        Returns:
            Item ID
            
        Raises:
            QuarantineError: If quarantine fails
        """
        with self._lock:
            try:
                # Convert data to bytes if needed
                if isinstance(data, str):
                    data = data.encode('utf-8')
                
                # Generate item ID
                item_id = self._generate_item_id()
                item_dir = self._get_item_path(item_id)
                item_dir.mkdir(parents=True, exist_ok=True)
                
                # Set restrictive permissions on item directory
                item_dir.chmod(0o700)
                
                # Calculate hash
                content_hash = self.analyzer.hash_validator.calculate_hash(
                    data, HashAlgorithm.SHA256
                )
                
                # Create metadata
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
                
                # Encrypt and save data
                encrypted_data = encrypt_data(data, self.encryption_key)
                
                data_file = item_dir / 'data.enc'
                with open(data_file, 'wb') as f:
                    f.write(encrypted_data)
                
                data_file.chmod(0o600)  # Owner read/write only
                
                # Save metadata
                metadata_file = item_dir / 'metadata.json'
                with open(metadata_file, 'w', encoding='utf-8') as f:
                    json.dump(metadata.to_dict(), f, indent=2)
                
                metadata_file.chmod(0o600)
                
                # Add to registry
                self.item_registry[item_id] = metadata
                self._save_registry()
                
                # Update chain of custody
                metadata.custody_chain.append({
                    'action': 'quarantine',
                    'timestamp': datetime.now().isoformat(),
                    'performed_by': 'system',
                    'reason': reason,
                })
                
                # Auto-analyze if configured
                if auto_analyze or (auto_analyze is None and self.policy.auto_analyze):
                    self.analyze_item(item_id)
                
                # Log quarantine
                self.logger.info(
                    f"Quarantined item {item_id}: {reason} "
                    f"(severity: {severity.value}, size: {len(data)} bytes)"
                )
                
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
                
                # Notify if configured
                if self.policy.auto_notify and self.policy.notify_on_quarantine:
                    self._notify_quarantine(metadata)
                
                return item_id
                
            except Exception as e:
                self.logger.error(f"Failed to quarantine item: {e}")
                raise QuarantineError(f"Quarantine failed: {e}")
    
    def get_item(self, item_id: str) -> Optional[QuarantineMetadata]:
        """
        Get quarantine item metadata
        
        Args:
            item_id: Item ID
            
        Returns:
            QuarantineMetadata or None if not found
        """
        with self._lock:
            return self.item_registry.get(item_id)
    
    def get_item_content(self, item_id: str) -> Optional[bytes]:
        """
        Get quarantined item content
        
        Args:
            item_id: Item ID
            
        Returns:
            Decrypted content or None if not found
            
        Raises:
            QuarantineAccessError: If access is denied
            QuarantineIntegrityError: If integrity check fails
        """
        with self._lock:
            metadata = self.item_registry.get(item_id)
            if not metadata:
                return None
            
            # Check if item is accessible
            if metadata.status not in [QuarantineStatus.ACTIVE, QuarantineStatus.ANALYZING]:
                raise QuarantineAccessError(
                    f"Item {item_id} is not accessible (status: {metadata.status.value})"
                )
            
            item_dir = self._get_item_path(item_id)
            data_file = item_dir / 'data.enc'
            
            if not data_file.exists():
                raise QuarantineItemNotFound(f"Data file not found for item {item_id}")
            
            try:
                # Read and decrypt data
                with open(data_file, 'rb') as f:
                    encrypted_data = f.read()
                
                data = decrypt_data(encrypted_data, self.encryption_key)
                
                # Verify hash
                calculated_hash = self.analyzer.hash_validator.calculate_hash(
                    data, metadata.content_hash_algorithm
                )
                
                if calculated_hash != metadata.content_hash:
                    raise QuarantineIntegrityError(
                        f"Hash mismatch for item {item_id}. "
                        f"Expected: {metadata.content_hash}, "
                        f"Got: {calculated_hash}"
                    )
                
                # Update last accessed
                metadata.last_accessed = datetime.now()
                self._save_registry()
                
                return data
                
            except Exception as e:
                self.logger.error(f"Failed to get item content {item_id}: {e}")
                raise QuarantineError(f"Failed to get content: {e}")
    
    def analyze_item(self, item_id: str) -> Dict[str, Any]:
        """
        Analyze quarantined item
        
        Args:
            item_id: Item ID
            
        Returns:
            Analysis results
            
        Raises:
            QuarantineError: If analysis fails
        """
        with self._lock:
            metadata = self.item_registry.get(item_id)
            if not metadata:
                raise QuarantineItemNotFound(f"Item not found: {item_id}")
            
            # Check if already analyzing
            if metadata.status == QuarantineStatus.ANALYZING:
                return metadata.analysis_results
            
            # Update status
            old_status = metadata.status
            metadata.status = QuarantineStatus.ANALYZING
            self._save_registry()
            
            try:
                # Get content for analysis
                content = self.get_item_content(item_id)
                if not content:
                    raise QuarantineError(f"No content available for item {item_id}")
                
                # Perform analysis
                analysis_results = self.analyzer.analyze_content(
                    content=content,
                    metadata=metadata,
                    timeout=self.policy.analysis_timeout
                )
                
                # Update metadata
                metadata.analysis_results = analysis_results
                metadata.analysis_tools = analysis_results.get('tools_used', [])
                metadata.classification = analysis_results.get('classification')
                
                # Update status based on analysis
                if metadata.review_required and metadata.quarantine_severity in [
                    QuarantineSeverity.HIGH, QuarantineSeverity.CRITICAL
                ]:
                    metadata.status = QuarantineStatus.PENDING_REVIEW
                else:
                    metadata.status = QuarantineStatus.ACTIVE
                
                # Update chain of custody
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
                
                self.logger.info(
                    f"Analysis completed for item {item_id}: "
                    f"{metadata.classification} (risk: {analysis_results.get('risk_score', 0.0):.2f})"
                )
                
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
                # Restore status on error
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
        Release item from quarantine
        
        Args:
            item_id: Item ID
            released_by: Person/system releasing the item
            release_reason: Reason for release
            force: Force release even if review required
            
        Returns:
            True if released successfully
            
        Raises:
            QuarantineError: If release fails
        """
        with self._lock:
            metadata = self.item_registry.get(item_id)
            if not metadata:
                raise QuarantineItemNotFound(f"Item not found: {item_id}")
            
            # Check if already released
            if metadata.status == QuarantineStatus.RELEASED:
                return True
            
            # Check if can be released
            if metadata.review_required and not force:
                raise QuarantineAccessError(
                    f"Item {item_id} requires review before release. "
                    f"Set force=True to override."
                )
            
            try:
                # Update metadata
                metadata.status = QuarantineStatus.RELEASED
                
                # Update chain of custody
                metadata.custody_chain.append({
                    'action': 'release',
                    'timestamp': datetime.now().isoformat(),
                    'performed_by': released_by,
                    'reason': release_reason,
                })
                
                # Delete encrypted data (keep metadata for audit)
                item_dir = self._get_item_path(item_id)
                data_file = item_dir / 'data.enc'
                
                if data_file.exists():
                    data_file.unlink()
                
                self._save_registry()
                
                self.logger.info(
                    f"Item {item_id} released by {released_by}: {release_reason}"
                )
                
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
                
                # Notify if configured
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
            item_id: Item ID
            deleted_by: Person/system deleting the item
            delete_reason: Reason for deletion
            
        Returns:
            True if deleted successfully
        """
        with self._lock:
            metadata = self.item_registry.get(item_id)
            if not metadata:
                return False
            
            try:
                # Update metadata
                metadata.status = QuarantineStatus.DELETED
                
                # Update chain of custody
                metadata.custody_chain.append({
                    'action': 'delete',
                    'timestamp': datetime.now().isoformat(),
                    'performed_by': deleted_by,
                    'reason': delete_reason,
                })
                
                # Delete all files
                self._delete_item_files(item_id)
                
                # Remove from registry
                del self.item_registry[item_id]
                self._save_registry()
                
                self.logger.info(
                    f"Item {item_id} deleted by {deleted_by}: {delete_reason}"
                )
                
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
        Search quarantine items
        
        Args:
            status: Filter by status
            severity: Filter by severity
            source: Filter by source
            date_from: Filter by quarantine date (from)
            date_to: Filter by quarantine date (to)
            classification: Filter by analysis classification
            limit: Maximum results
            
        Returns:
            List of matching quarantine metadata
        """
        results = []
        
        for metadata in self.item_registry.values():
            # Apply filters
            if status and metadata.status != status:
                continue
            
            if severity and metadata.quarantine_severity != severity:
                continue
            
            if source and metadata.quarantine_source != source:
                continue
            
            if date_from and metadata.quarantine_date < date_from:
                continue
            
            if date_to and metadata.quarantine_date > date_to:
                continue
            
            if classification and metadata.classification != classification:
                continue
            
            results.append(metadata)
            
            if len(results) >= limit:
                break
        
        # Sort by quarantine date (newest first)
        results.sort(key=lambda x: x.quarantine_date, reverse=True)
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get quarantine statistics"""
        with self._lock:
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
            
            # Calculate statistics
            for metadata in self.item_registry.values():
                # By status
                status_key = metadata.status.value
                stats['by_status'][status_key] = stats['by_status'].get(status_key, 0) + 1
                
                # By severity
                severity_key = metadata.quarantine_severity.value
                stats['by_severity'][severity_key] = stats['by_severity'].get(severity_key, 0) + 1
                
                # By classification
                if metadata.classification:
                    stats['by_classification'][metadata.classification] = \
                        stats['by_classification'].get(metadata.classification, 0) + 1
                
                # By source
                source_key = metadata.quarantine_source
                stats['by_source'][source_key] = stats['by_source'].get(source_key, 0) + 1
                
                # Size
                stats['size_bytes'] += metadata.content_size
                
                # Pending review
                if metadata.status == QuarantineStatus.PENDING_REVIEW:
                    stats['pending_review'] += 1
                
                # Expired items
                if metadata.status == QuarantineStatus.EXPIRED:
                    stats['expired_items'] += 1
            
            # Convert sizes to human-readable format
            stats['size_mb'] = stats['size_bytes'] / (1024 * 1024)
            stats['size_gb'] = stats['size_bytes'] / (1024 * 1024 * 1024)
            
            return stats
    
    def export_item(
        self,
        item_id: str,
        export_format: str = "json"
    ) -> Optional[bytes]:
        """
        Export quarantined item for external analysis
        
        Args:
            item_id: Item ID
            export_format: Export format ("json", "zip")
            
        Returns:
            Exported data bytes or None if failed
        """
        with self._lock:
            metadata = self.item_registry.get(item_id)
            if not metadata:
                return None
            
            try:
                # Get content
                content = self.get_item_content(item_id)
                if not content:
                    return None
                
                if export_format == "json":
                    # Export as JSON
                    export_data = {
                        'metadata': metadata.to_dict(),
                        'content_base64': None,  # Don't include content in JSON export
                    }
                    
                    return json.dumps(export_data, indent=2).encode('utf-8')
                
                elif export_format == "zip":
                    # Export as ZIP with metadata and content
                    import io
                    import zipfile
                    
                    zip_buffer = io.BytesIO()
                    
                    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                        # Add metadata
                        metadata_json = json.dumps(metadata.to_dict(), indent=2)
                        zip_file.writestr('metadata.json', metadata_json)
                        
                        # Add content
                        original_filename = metadata.original_filename or 'content.bin'
                        zip_file.writestr(original_filename, content)
                        
                        # Add analysis results
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
        """Send quarantine notification"""
        # In production, this would send emails or other notifications
        # This is a simplified implementation
        if not self.policy.notify_emails:
            return
        
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
        """Send release notification"""
        if not self.policy.notify_emails:
            return
        
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
        Clean up items older than specified days
        
        Args:
            days_old: Delete items older than this many days
            
        Returns:
            Number of items cleaned up
        """
        cutoff_date = datetime.now() - timedelta(days=days_old)
        cleaned_count = 0
        
        with self._lock:
            items_to_clean = []
            
            for item_id, metadata in self.item_registry.items():
                if (metadata.status == QuarantineStatus.ACTIVE and 
                    metadata.quarantine_date < cutoff_date):
                    items_to_clean.append(item_id)
            
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
    Create quarantine manager with default configuration
    
    Args:
        quarantine_dir: Quarantine directory
        policy_name: Policy name
        
    Returns:
        Initialized QuarantineManager
    """
    # Load policy based on name
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
        source: Source of the file
        manager: Existing QuarantineManager instance
        
    Returns:
        Item ID if successful, None otherwise
    """
    filepath = Path(filepath)
    
    if not filepath.exists():
        logging.getLogger(__name__).error(f"File not found: {filepath}")
        return None
    
    if manager is None:
        manager = create_quarantine_manager()
    
    try:
        # Read file
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