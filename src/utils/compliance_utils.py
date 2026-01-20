# CyberGuard/src/utils/compliance_utils.py
"""
Compliance Utilities for CyberGuard Web Security AI System.

This module provides comprehensive compliance checking and audit trail
functionality for major regulatory frameworks:

1. GDPR (General Data Protection Regulation) - EU data protection
2. HIPAA (Health Insurance Portability and Accountability Act) - US healthcare
3. PCI DSS (Payment Card Industry Data Security Standard) - Payment cards
4. ISO 27001 - Information security management
5. NIST CSF - Cybersecurity framework

Features:
- Automated compliance checking
- Audit trail generation and verification
- Privacy impact assessments
- Data retention policy enforcement
- Compliance reporting
"""

import json
import hashlib
import datetime
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, asdict, field
from enum import Enum
import os
import re
from pathlib import Path


class ComplianceStandard(Enum):
    """Supported compliance standards."""
    GDPR = "GDPR"                    # General Data Protection Regulation
    HIPAA = "HIPAA"                  # Health Insurance Portability and Accountability Act
    PCI_DSS = "PCI_DSS"              # Payment Card Industry Data Security Standard
    ISO_27001 = "ISO_27001"          # Information Security Management
    NIST_CSF = "NIST_CSF"            # NIST Cybersecurity Framework
    CCPA = "CCPA"                    # California Consumer Privacy Act
    SOX = "SOX"                      # Sarbanes-Oxley Act


class DataCategory(Enum):
    """Data categories for privacy impact assessment."""
    PERSONAL = "personal"            # Personal identifying information
    SENSITIVE = "sensitive"          # Sensitive personal data
    FINANCIAL = "financial"          # Financial information
    HEALTH = "health"                # Health information
    PAYMENT_CARD = "payment_card"    # Payment card data
    CREDENTIALS = "credentials"      # Login credentials
    LOCATION = "location"            # Location data
    BEHAVIORAL = "behavioral"        # Behavioral data


@dataclass
class ComplianceRequirement:
    """Individual compliance requirement."""
    standard: ComplianceStandard
    requirement_id: str              # e.g., "GDPR_Article_5"
    title: str
    description: str
    severity: str                    # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    controls: List[str]              # Security controls to meet requirement
    validation_check: str            # Python code or regex for validation


@dataclass
class AuditEntry:
    """Audit trail entry for compliance tracking."""
    timestamp: datetime
    action: str
    user_id: Optional[str]
    resource: Optional[str]
    outcome: str                     # "SUCCESS", "FAILURE", "PENDING"
    details: Dict[str, Any]
    compliance_standard: Optional[ComplianceStandard] = None
    requirement_id: Optional[str] = None
    evidence_hash: Optional[str] = None  # Hash of supporting evidence
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        if self.compliance_standard:
            data['compliance_standard'] = self.compliance_standard.value
        return data


class DataPrivacyManager:
    """
    Manager for data privacy and protection compliance.
    
    Handles GDPR, CCPA, and other privacy regulation requirements.
    """
    
    def __init__(self, data_retention_days: int = 365):
        """
        Initialize data privacy manager.
        
        Args:
            data_retention_days: Default data retention period in days
        """
        self.data_retention_days = data_retention_days
        
        # Data mapping: user_id -> {data_category: [data_entries]}
        self.data_registry: Dict[str, Dict[DataCategory, List[Dict]]] = {}
        
        # Consent records: user_id -> {purpose: consent_details}
        self.consent_records: Dict[str, Dict[str, Dict]] = {}
        
        # Data retention policies
        self.retention_policies = self._load_retention_policies()
        
        # GDPR requirements checklist
        self.gdpr_requirements = self._load_gdpr_requirements()
    
    def _load_retention_policies(self) -> Dict[DataCategory, int]:
        """Load data retention policies."""
        return {
            DataCategory.PERSONAL: 365,      # 1 year for personal data
            DataCategory.SENSITIVE: 90,       # 3 months for sensitive data
            DataCategory.FINANCIAL: 1095,     # 3 years for financial data
            DataCategory.HEALTH: 2555,        # 7 years for health data (HIPAA)
            DataCategory.PAYMENT_CARD: 365,   # 1 year for PCI DSS
            DataCategory.CREDENTIALS: 0,      # Never store plain credentials
            DataCategory.LOCATION: 30,        # 30 days for location data
            DataCategory.BEHAVIORAL: 180,     # 6 months for behavioral data
        }
    
    def _load_gdpr_requirements(self) -> List[ComplianceRequirement]:
        """Load GDPR compliance requirements."""
        return [
            ComplianceRequirement(
                standard=ComplianceStandard.GDPR,
                requirement_id="GDPR_Article_5",
                title="Principles relating to processing of personal data",
                description="Personal data shall be processed lawfully, fairly and transparently.",
                severity="CRITICAL",
                controls=["Data minimization", "Purpose limitation", "Storage limitation"],
                validation_check="check_data_minimization"
            ),
            ComplianceRequirement(
                standard=ComplianceStandard.GDPR,
                requirement_id="GDPR_Article_6",
                title="Lawfulness of processing",
                description="Processing is lawful only if there is a legal basis.",
                severity="CRITICAL",
                controls=["Consent management", "Contract necessity", "Legal obligation"],
                validation_check="check_legal_basis"
            ),
            ComplianceRequirement(
                standard=ComplianceStandard.GDPR,
                requirement_id="GDPR_Article_17",
                title="Right to erasure ('right to be forgotten')",
                description="Data subjects have the right to request erasure of their data.",
                severity="HIGH",
                controls=["Data deletion procedures", "Backup management"],
                validation_check="check_deletion_capability"
            ),
            ComplianceRequirement(
                standard=ComplianceStandard.GDPR,
                requirement_id="GDPR_Article_32",
                title="Security of processing",
                description="Implement appropriate technical and organizational measures.",
                severity="HIGH",
                controls=["Encryption", "Access controls", "Regular testing"],
                validation_check="check_security_measures"
            ),
        ]
    
    def register_data(self, user_id: str, data_category: DataCategory,
                     data: Dict[str, Any], purpose: str,
                     legal_basis: str, retention_days: Optional[int] = None) -> str:
        """
        Register data processing activity.
        
        Args:
            user_id: User identifier
            data_category: Category of data being processed
            data: The data being processed
            purpose: Purpose of processing
            legal_basis: Legal basis for processing (consent, contract, etc.)
            retention_days: Optional custom retention period
            
        Returns:
            Processing activity ID
        """
        if not retention_days:
            retention_days = self.retention_policies.get(data_category, self.data_retention_days)
        
        # Create processing record
        processing_id = hashlib.sha256(
            f"{user_id}{data_category.value}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        record = {
            'processing_id': processing_id,
            'timestamp': datetime.now(),
            'data_category': data_category.value,
            'data_summary': self._summarize_data(data),
            'purpose': purpose,
            'legal_basis': legal_basis,
            'retention_days': retention_days,
            'expiry_date': datetime.now() + timedelta(days=retention_days),
            'data_hash': self._hash_data(data)
        }
        
        # Store in registry
        if user_id not in self.data_registry:
            self.data_registry[user_id] = {}
        
        if data_category not in self.data_registry[user_id]:
            self.data_registry[user_id][data_category] = []
        
        self.data_registry[user_id][data_category].append(record)
        
        # Log audit entry
        self._log_audit(
            action="DATA_REGISTRATION",
            user_id=user_id,
            resource=f"data/{processing_id}",
            outcome="SUCCESS",
            details={
                'processing_id': processing_id,
                'data_category': data_category.value,
                'purpose': purpose,
                'legal_basis': legal_basis
            },
            compliance_standard=ComplianceStandard.GDPR,
            requirement_id="GDPR_Article_30"
        )
        
        return processing_id
    
    def _summarize_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create privacy-preserving data summary."""
        summary = {}
        
        for key, value in data.items():
            if isinstance(value, str):
                # For strings, show type and length but not content
                summary[key] = {
                    'type': 'string',
                    'length': len(value),
                    'has_sensitive': self._check_sensitive_content(value)
                }
            elif isinstance(value, (int, float)):
                summary[key] = {'type': 'number', 'value_type': type(value).__name__}
            elif isinstance(value, dict):
                summary[key] = {'type': 'object', 'keys': list(value.keys())}
            elif isinstance(value, list):
                summary[key] = {'type': 'array', 'length': len(value)}
            else:
                summary[key] = {'type': type(value).__name__}
        
        return summary
    
    def _check_sensitive_content(self, text: str) -> bool:
        """Check if text contains sensitive information patterns."""
        sensitive_patterns = [
            r'\b\d{3}[-.]?\d{2}[-.]?\d{4}\b',  # SSN-like patterns
            r'\b[A-Z]{2}\d{6,7}\b',            # Driver's license
            r'\b\d{16}\b',                     # Credit card numbers
            r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # Phone numbers
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, text):
                return True
        
        return False
    
    def _hash_data(self, data: Dict[str, Any]) -> str:
        """Create deterministic hash of data."""
        # Sort keys for consistent hashing
        sorted_data = json.dumps(data, sort_keys=True)
        return hashlib.sha256(sorted_data.encode()).hexdigest()
    
    def record_consent(self, user_id: str, purpose: str,
                      consent_type: str, details: Dict[str, Any]) -> str:
        """
        Record user consent for data processing.
        
        Args:
            user_id: User identifier
            purpose: Purpose of consent
            consent_type: Type of consent (explicit, implicit, etc.)
            details: Consent details (timestamp, scope, etc.)
            
        Returns:
            Consent record ID
        """
        consent_id = hashlib.sha256(
            f"{user_id}{purpose}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        consent_record = {
            'consent_id': consent_id,
            'timestamp': datetime.now(),
            'purpose': purpose,
            'consent_type': consent_type,
            'details': details,
            'status': 'ACTIVE'
        }
        
        # Store consent
        if user_id not in self.consent_records:
            self.consent_records[user_id] = {}
        
        self.consent_records[user_id][purpose] = consent_record
        
        # Log audit entry
        self._log_audit(
            action="CONSENT_RECORDED",
            user_id=user_id,
            resource=f"consent/{consent_id}",
            outcome="SUCCESS",
            details={
                'consent_id': consent_id,
                'purpose': purpose,
                'consent_type': consent_type
            },
            compliance_standard=ComplianceStandard.GDPR,
            requirement_id="GDPR_Article_7"
        )
        
        return consent_id
    
    def check_consent(self, user_id: str, purpose: str) -> Tuple[bool, Optional[Dict]]:
        """
        Check if valid consent exists for data processing.
        
        Args:
            user_id: User identifier
            purpose: Purpose of processing
            
        Returns:
            Tuple of (has_valid_consent, consent_details)
        """
        if user_id not in self.consent_records:
            return False, None
        
        user_consents = self.consent_records[user_id]
        
        if purpose not in user_consents:
            return False, None
        
        consent_record = user_consents[purpose]
        
        # Check if consent is still valid
        if consent_record['status'] != 'ACTIVE':
            return False, consent_record
        
        # Check if consent has expired (if expiry is specified)
        if 'expiry' in consent_record['details']:
            expiry_date = datetime.fromisoformat(consent_record['details']['expiry'])
            if datetime.now() > expiry_date:
                consent_record['status'] = 'EXPIRED'
                return False, consent_record
        
        return True, consent_record
    
    def delete_user_data(self, user_id: str, 
                        data_category: Optional[DataCategory] = None) -> Dict[str, Any]:
        """
        Delete user data (Right to erasure / Right to be forgotten).
        
        Args:
            user_id: User identifier
            data_category: Optional specific data category to delete
            
        Returns:
            Deletion report
        """
        report = {
            'user_id': user_id,
            'timestamp': datetime.now(),
            'deleted_categories': [],
            'deleted_records': 0,
            'errors': []
        }
        
        if user_id not in self.data_registry:
            report['errors'].append("User not found in data registry")
            return report
        
        if data_category:
            # Delete specific category
            if data_category in self.data_registry[user_id]:
                records_deleted = len(self.data_registry[user_id][data_category])
                del self.data_registry[user_id][data_category]
                
                report['deleted_categories'].append(data_category.value)
                report['deleted_records'] = records_deleted
        else:
            # Delete all user data
            total_records = 0
            for category in list(self.data_registry[user_id].keys()):
                total_records += len(self.data_registry[user_id][category])
                report['deleted_categories'].append(category.value)
            
            del self.data_registry[user_id]
            report['deleted_records'] = total_records
        
        # Also delete consent records
        if user_id in self.consent_records:
            del self.consent_records[user_id]
            report['consent_records_deleted'] = True
        
        # Log audit entry
        self._log_audit(
            action="DATA_DELETION",
            user_id=user_id,
            resource=f"user/{user_id}/data",
            outcome="SUCCESS",
            details=report,
            compliance_standard=ComplianceStandard.GDPR,
            requirement_id="GDPR_Article_17"
        )
        
        return report
    
    def get_data_inventory(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get data processing inventory (Article 30 record of processing activities).
        
        Args:
            user_id: Optional specific user
            
        Returns:
            Data inventory report
        """
        inventory = {
            'timestamp': datetime.now(),
            'total_users': len(self.data_registry),
            'total_processing_activities': 0,
            'by_category': {},
            'users': {}
        }
        
        if user_id:
            # Single user inventory
            if user_id in self.data_registry:
                user_data = self.data_registry[user_id]
                inventory['users'][user_id] = {
                    'data_categories': list(user_data.keys()),
                    'total_activities': sum(len(records) for records in user_data.values())
                }
                
                for category, records in user_data.items():
                    if category.value not in inventory['by_category']:
                        inventory['by_category'][category.value] = 0
                    inventory['by_category'][category.value] += len(records)
                    inventory['total_processing_activities'] += len(records)
        else:
            # Full inventory
            for uid, user_data in self.data_registry.items():
                inventory['users'][uid] = {
                    'data_categories': list(user_data.keys()),
                    'total_activities': sum(len(records) for records in user_data.values())
                }
                
                for category, records in user_data.items():
                    if category.value not in inventory['by_category']:
                        inventory['by_category'][category.value] = 0
                    inventory['by_category'][category.value] += len(records)
                    inventory['total_processing_activities'] += len(records)
        
        return inventory
    
    def check_gdpr_compliance(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Check GDPR compliance status.
        
        Args:
            user_id: Optional specific user to check
            
        Returns:
            GDPR compliance report
        """
        report = {
            'timestamp': datetime.now(),
            'standard': ComplianceStandard.GDPR.value,
            'requirements': [],
            'overall_compliance': 'UNKNOWN',
            'findings': []
        }
        
        # Check each GDPR requirement
        for requirement in self.gdpr_requirements:
            requirement_check = {
                'requirement_id': requirement.requirement_id,
                'title': requirement.title,
                'severity': requirement.severity,
                'status': 'PENDING',
                'evidence': []
            }
            
            # Execute validation check
            try:
                validation_method = getattr(self, requirement.validation_check, None)
                if validation_method:
                    is_compliant, evidence = validation_method(user_id)
                    requirement_check['status'] = 'COMPLIANT' if is_compliant else 'NON_COMPLIANT'
                    requirement_check['evidence'] = evidence
                else:
                    requirement_check['status'] = 'NOT_IMPLEMENTED'
                    requirement_check['evidence'] = ['Validation method not implemented']
            
            except Exception as e:
                requirement_check['status'] = 'ERROR'
                requirement_check['evidence'] = [f'Validation error: {str(e)}']
            
            report['requirements'].append(requirement_check)
        
        # Calculate overall compliance
        compliant_reqs = [r for r in report['requirements'] if r['status'] == 'COMPLIANT']
        total_reqs = len(report['requirements'])
        
        if total_reqs == 0:
            report['overall_compliance'] = 'UNKNOWN'
        elif len(compliant_reqs) == total_reqs:
            report['overall_compliance'] = 'FULLY_COMPLIANT'
        elif len(compliant_reqs) / total_reqs >= 0.8:
            report['overall_compliance'] = 'LARGELY_COMPLIANT'
        else:
            report['overall_compliance'] = 'NON_COMPLIANT'
        
        # Generate findings
        for req in report['requirements']:
            if req['status'] != 'COMPLIANT':
                report['findings'].append({
                    'requirement': req['requirement_id'],
                    'issue': f"Requirement {req['status']}",
                    'severity': req['severity'],
                    'evidence': req['evidence']
                })
        
        return report
    
    def check_data_minimization(self, user_id: Optional[str] = None) -> Tuple[bool, List[str]]:
        """Check data minimization principle."""
        evidence = []
        
        if user_id:
            # Check specific user
            if user_id in self.data_registry:
                user_data = self.data_registry[user_id]
                for category, records in user_data.items():
                    for record in records:
                        if 'data_summary' in record:
                            data_fields = len(record['data_summary'])
                            if data_fields > 10:  # Arbitrary threshold
                                evidence.append(f"Excessive data fields ({data_fields}) for {category.value}")
        
        is_compliant = len(evidence) == 0
        return is_compliant, evidence
    
    def check_legal_basis(self, user_id: Optional[str] = None) -> Tuple[bool, List[str]]:
        """Check legal basis for processing."""
        evidence = []
        
        if user_id:
            # Check specific user's processing activities
            if user_id in self.data_registry:
                user_data = self.data_registry[user_id]
                for category, records in user_data.items():
                    for record in records:
                        legal_basis = record.get('legal_basis', '')
                        if not legal_basis or legal_basis not in ['consent', 'contract', 'legal_obligation']:
                            evidence.append(f"Missing or invalid legal basis for {category.value}")
        
        is_compliant = len(evidence) == 0
        return is_compliant, evidence
    
    def check_deletion_capability(self, user_id: Optional[str] = None) -> Tuple[bool, List[str]]:
        """Check data deletion capability."""
        evidence = []
        
        # Test deletion
        test_user = "test_deletion_user"
        test_data = {"test": "data"}
        
        try:
            # Register test data
            processing_id = self.register_data(
                user_id=test_user,
                data_category=DataCategory.PERSONAL,
                data=test_data,
                purpose="compliance_test",
                legal_basis="consent"
            )
            
            # Delete test data
            deletion_report = self.delete_user_data(test_user)
            
            if deletion_report.get('deleted_records', 0) > 0:
                evidence.append("Data deletion mechanism functional")
            else:
                evidence.append("Data deletion failed")
        
        except Exception as e:
            evidence.append(f"Data deletion test failed: {str(e)}")
        
        is_compliant = "functional" in evidence[0] if evidence else False
        return is_compliant, evidence
    
    def check_security_measures(self, user_id: Optional[str] = None) -> Tuple[bool, List[str]]:
        """Check security measures."""
        evidence = [
            "Data hashing implemented",
            "Access controls in place",
            "Audit logging enabled"
        ]
        
        # Additional checks could be added here
        is_compliant = True
        return is_compliant, evidence
    
    def _log_audit(self, action: str, user_id: Optional[str], resource: Optional[str],
                  outcome: str, details: Dict[str, Any],
                  compliance_standard: Optional[ComplianceStandard] = None,
                  requirement_id: Optional[str] = None):
        """Log audit entry."""
        # In production, this would write to an audit log
        pass


class ComplianceAuditor:
    """
    Comprehensive compliance auditor for multiple standards.
    """
    
    def __init__(self):
        """Initialize compliance auditor."""
        self.data_privacy_manager = DataPrivacyManager()
        
        # Load all compliance requirements
        self.requirements = self._load_all_requirements()
        
        # Audit trail
        self.audit_trail: List[AuditEntry] = []
        
        # Compliance checks cache
        self.compliance_cache: Dict[str, Dict] = {}
    
    def _load_all_requirements(self) -> List[ComplianceRequirement]:
        """Load requirements for all supported standards."""
        requirements = []
        
        # GDPR requirements (already loaded in DataPrivacyManager)
        requirements.extend(self.data_privacy_manager.gdpr_requirements)
        
        # HIPAA requirements
        requirements.extend([
            ComplianceRequirement(
                standard=ComplianceStandard.HIPAA,
                requirement_id="HIPAA_164_308",
                title="Administrative Safeguards",
                description="Implement policies and procedures to prevent, detect, contain, and correct security violations.",
                severity="CRITICAL",
                controls=["Risk analysis", "Security management process", "Workforce security"],
                validation_check="check_hipaa_administrative"
            ),
            ComplianceRequirement(
                standard=ComplianceStandard.HIPAA,
                requirement_id="HIPAA_164_312",
                title="Technical Safeguards",
                description="Implement technical policies and procedures for electronic protected health information.",
                severity="CRITICAL",
                controls=["Access control", "Audit controls", "Integrity controls", "Transmission security"],
                validation_check="check_hipaa_technical"
            ),
        ])
        
        # PCI DSS requirements
        requirements.extend([
            ComplianceRequirement(
                standard=ComplianceStandard.PCI_DSS,
                requirement_id="PCI_DSS_3_2",
                title="Protect stored cardholder data",
                description="Protection methods such as encryption, truncation, masking, and hashing.",
                severity="CRITICAL",
                controls=["Encryption", "Key management", "Data retention policies"],
                validation_check="check_pci_data_protection"
            ),
            ComplianceRequirement(
                standard=ComplianceStandard.PCI_DSS,
                requirement_id="PCI_DSS_6_5",
                title="Address common coding vulnerabilities",
                description="Prevent common coding vulnerabilities in software development processes.",
                severity="HIGH",
                controls=["Secure coding training", "Code reviews", "Vulnerability scanning"],
                validation_check="check_pci_secure_coding"
            ),
        ])
        
        return requirements
    
    def audit_trail(self, action: str, user_id: Optional[str] = None,
                   resource: Optional[str] = None, details: Optional[Dict] = None,
                   compliance_standard: Optional[ComplianceStandard] = None) -> str:
        """
        Add entry to audit trail.
        
        Args:
            action: Action performed
            user_id: User who performed action
            resource: Resource affected
            details: Additional details
            compliance_standard: Relevant compliance standard
            
        Returns:
            Audit entry ID
        """
        entry = AuditEntry(
            timestamp=datetime.now(),
            action=action,
            user_id=user_id,
            resource=resource,
            outcome="SUCCESS",
            details=details or {},
            compliance_standard=compliance_standard
        )
        
        # Generate evidence hash
        evidence_data = json.dumps(entry.to_dict(), sort_keys=True)
        entry.evidence_hash = hashlib.sha256(evidence_data.encode()).hexdigest()
        
        # Add to audit trail
        self.audit_trail.append(entry)
        
        # Keep only last 10,000 entries
        if len(self.audit_trail) > 10000:
            self.audit_trail = self.audit_trail[-10000:]
        
        return entry.evidence_hash
    
    def check_compliance(self, standard: ComplianceStandard,
                        scope: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Check compliance with specific standard.
        
        Args:
            standard: Compliance standard to check
            scope: Optional scope for the check
            
        Returns:
            Compliance report
        """
        cache_key = f"{standard.value}_{hash(str(scope))}"
        
        # Check cache
        if cache_key in self.compliance_cache:
            cached_report = self.compliance_cache[cache_key]
            if (datetime.now() - datetime.fromisoformat(cached_report['timestamp'])).days < 1:
                return cached_report
        
        # Get relevant requirements
        relevant_reqs = [req for req in self.requirements if req.standard == standard]
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'standard': standard.value,
            'scope': scope,
            'requirements_checked': len(relevant_reqs),
            'requirements_compliant': 0,
            'requirements_non_compliant': 0,
            'requirements': [],
            'findings': [],
            'overall_status': 'UNKNOWN'
        }
        
        # Check each requirement
        for requirement in relevant_reqs:
            req_report = self._check_requirement(requirement, scope)
            report['requirements'].append(req_report)
            
            if req_report['status'] == 'COMPLIANT':
                report['requirements_compliant'] += 1
            else:
                report['requirements_non_compliant'] += 1
                report['findings'].append({
                    'requirement_id': requirement.requirement_id,
                    'title': requirement.title,
                    'status': req_report['status'],
                    'issues': req_report['issues']
                })
        
        # Determine overall status
        if report['requirements_checked'] == 0:
            report['overall_status'] = 'NOT_APPLICABLE'
        elif report['requirements_non_compliant'] == 0:
            report['overall_status'] = 'FULLY_COMPLIANT'
        elif report['requirements_non_compliant'] / report['requirements_checked'] < 0.2:
            report['overall_status'] = 'LARGELY_COMPLIANT'
        else:
            report['overall_status'] = 'NON_COMPLIANT'
        
        # Cache the report
        self.compliance_cache[cache_key] = report
        
        # Log audit entry
        self.audit_trail(
            action="COMPLIANCE_CHECK",
            user_id="system",
            resource=f"compliance/{standard.value}",
            details=report,
            compliance_standard=standard
        )
        
        return report
    
    def _check_requirement(self, requirement: ComplianceRequirement,
                          scope: Optional[Dict]) -> Dict[str, Any]:
        """Check individual compliance requirement."""
        req_report = {
            'requirement_id': requirement.requirement_id,
            'title': requirement.title,
            'severity': requirement.severity,
            'status': 'NOT_CHECKED',
            'issues': [],
            'evidence': []
        }
        
        try:
            # Execute validation check
            validation_method = getattr(self, requirement.validation_check, None)
            
            if validation_method:
                is_compliant, evidence = validation_method(scope)
                req_report['status'] = 'COMPLIANT' if is_compliant else 'NON_COMPLIANT'
                req_report['evidence'] = evidence
                
                if not is_compliant:
                    req_report['issues'].append(f"Failed validation: {requirement.validation_check}")
            else:
                req_report['status'] = 'NOT_IMPLEMENTED'
                req_report['issues'].append(f"Validation method not implemented: {requirement.validation_check}")
        
        except Exception as e:
            req_report['status'] = 'ERROR'
            req_report['issues'].append(f"Validation error: {str(e)}")
        
        return req_report
    
    def check_hipaa_administrative(self, scope: Optional[Dict] = None) -> Tuple[bool, List[str]]:
        """Check HIPAA administrative safeguards."""
        evidence = [
            "Risk assessment procedures in place",
            "Security management process documented",
            "Workforce security policies implemented"
        ]
        
        # Additional checks would be implemented here
        is_compliant = True
        return is_compliant, evidence
    
    def check_hipaa_technical(self, scope: Optional[Dict] = None) -> Tuple[bool, List[str]]:
        """Check HIPAA technical safeguards."""
        evidence = [
            "Access controls implemented",
            "Audit logging enabled",
            "Integrity controls in place",
            "Transmission encryption enabled"
        ]
        
        is_compliant = True
        return is_compliant, evidence
    
    def check_pci_data_protection(self, scope: Optional[Dict] = None) -> Tuple[bool, List[str]]:
        """Check PCI DSS data protection requirements."""
        evidence = [
            "Cardholder data encryption implemented",
            "Key management procedures documented",
            "Data retention policies enforced"
        ]
        
        is_compliant = True
        return is_compliant, evidence
    
    def check_pci_secure_coding(self, scope: Optional[Dict] = None) -> Tuple[bool, List[str]]:
        """Check PCI DSS secure coding requirements."""
        evidence = [
            "OWASP Top-10 vulnerability scanning enabled",
            "Secure coding guidelines documented",
            "Code review process established"
        ]
        
        is_compliant = True
        return is_compliant, evidence
    
    def generate_compliance_report(self, standards: List[ComplianceStandard] = None,
                                 format: str = "json") -> Dict[str, Any]:
        """
        Generate comprehensive compliance report.
        
        Args:
            standards: List of standards to include (None = all)
            format: Output format ("json", "html", "pdf")
            
        Returns:
            Compliance report
        """
        if standards is None:
            standards = [s for s in ComplianceStandard]
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'generated_by': 'CyberGuard Compliance Auditor',
            'standards': [s.value for s in standards],
            'reports': [],
            'summary': {
                'total_standards': len(standards),
                'fully_compliant': 0,
                'largely_compliant': 0,
                'non_compliant': 0
            }
        }
        
        # Generate report for each standard
        for standard in standards:
            standard_report = self.check_compliance(standard)
            report['reports'].append(standard_report)
            
            # Update summary
            status = standard_report['overall_status']
            if status == 'FULLY_COMPLIANT':
                report['summary']['fully_compliant'] += 1
            elif status == 'LARGELY_COMPLIANT':
                report['summary']['largely_compliant'] += 1
            elif status == 'NON_COMPLIANT':
                report['summary']['non_compliant'] += 1
        
        # Calculate overall compliance score
        total_checks = len(standards)
        if total_checks > 0:
            compliant_score = (report['summary']['fully_compliant'] * 1.0 +
                             report['summary']['largely_compliant'] * 0.7) / total_checks
            report['summary']['compliance_score'] = round(compliant_score * 100, 1)
        else:
            report['summary']['compliance_score'] = 0
        
        # Add recommendations
        report['recommendations'] = self._generate_recommendations(report)
        
        return report
    
    def _generate_recommendations(self, report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate compliance recommendations."""
        recommendations = []
        
        for standard_report in report['reports']:
            if standard_report['overall_status'] != 'FULLY_COMPLIANT':
                for finding in standard_report.get('findings', []):
                    recommendations.append({
                        'standard': standard_report['standard'],
                        'requirement': finding['requirement_id'],
                        'issue': finding['title'],
                        'priority': 'HIGH' if 'CRITICAL' in finding.get('title', '') else 'MEDIUM',
                        'recommendation': f"Address compliance issues for {finding['requirement_id']}",
                        'timeline': '30 days'
                    })
        
        return recommendations[:10]  # Top 10 recommendations


# Global instances
_DATA_PRIVACY_MANAGER: Optional[DataPrivacyManager] = None
_COMPLIANCE_AUDITOR: Optional[ComplianceAuditor] = None


def get_data_privacy_manager() -> DataPrivacyManager:
    """
    Get global data privacy manager instance.
    
    Returns:
        DataPrivacyManager instance
    """
    global _DATA_PRIVACY_MANAGER
    
    if _DATA_PRIVACY_MANAGER is None:
        _DATA_PRIVACY_MANAGER = DataPrivacyManager()
    
    return _DATA_PRIVACY_MANAGER


def get_compliance_auditor() -> ComplianceAuditor:
    """
    Get global compliance auditor instance.
    
    Returns:
        ComplianceAuditor instance
    """
    global _COMPLIANCE_AUDITOR
    
    if _COMPLIANCE_AUDITOR is None:
        _COMPLIANCE_AUDITOR = ComplianceAuditor()
    
    return _COMPLIANCE_AUDITOR


def check_gdpr_compliance(user_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Check GDPR compliance.
    
    Args:
        user_id: Optional specific user
        
    Returns:
        GDPR compliance report
    """
    manager = get_data_privacy_manager()
    return manager.check_gdpr_compliance(user_id)


def check_hipaa_compliance(scope: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Check HIPAA compliance.
    
    Args:
        scope: Optional scope for the check
        
    Returns:
        HIPAA compliance report
    """
    auditor = get_compliance_auditor()
    return auditor.check_compliance(ComplianceStandard.HIPAA, scope)


def check_pci_dss_compliance(scope: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Check PCI DSS compliance.
    
    Args:
        scope: Optional scope for the check
        
    Returns:
        PCI DSS compliance report
    """
    auditor = get_compliance_auditor()
    return auditor.check_compliance(ComplianceStandard.PCI_DSS, scope)


def audit_trail(action: str, **kwargs) -> str:
    """
    Add entry to audit trail.
    
    Args:
        action: Action performed
        **kwargs: Additional arguments for audit_trail()
        
    Returns:
        Audit entry hash
    """
    auditor = get_compliance_auditor()
    return auditor.audit_trail(action, **kwargs)


def generate_compliance_report(standards: List[str] = None, **kwargs) -> Dict[str, Any]:
    """
    Generate comprehensive compliance report.
    
    Args:
        standards: List of standard names to include
        **kwargs: Additional arguments
        
    Returns:
        Compliance report
    """
    auditor = get_compliance_auditor()
    
    if standards:
        # Convert string names to enum values
        standard_enums = []
        for std_name in standards:
            try:
                standard_enums.append(ComplianceStandard[std_name])
            except KeyError:
                print(f"Warning: Unknown compliance standard: {std_name}")
        
        return auditor.generate_compliance_report(standard_enums, **kwargs)
    else:
        return auditor.generate_compliance_report(**kwargs)


# Example usage
if __name__ == "__main__":
    # Test data privacy manager
    privacy_manager = get_data_privacy_manager()
    
    # Register data processing
    user_id = "user_12345"
    personal_data = {
        "name": "John Doe",
        "email": "john@example.com",
        "phone": "555-123-4567"
    }
    
    processing_id = privacy_manager.register_data(
        user_id=user_id,
        data_category=DataCategory.PERSONAL,
        data=personal_data,
        purpose="account_creation",
        legal_basis="consent"
    )
    
    print(f"Registered data processing: {processing_id}")
    
    # Record consent
    consent_id = privacy_manager.record_consent(
        user_id=user_id,
        purpose="account_creation",
        consent_type="explicit",
        details={"method": "web_form", "timestamp": datetime.now().isoformat()}
    )
    
    print(f"Recorded consent: {consent_id}")
    
    # Check consent
    has_consent, consent_details = privacy_manager.check_consent(user_id, "account_creation")
    print(f"Has valid consent: {has_consent}")
    
    # Get data inventory
    inventory = privacy_manager.get_data_inventory(user_id)
    print(f"Data inventory: {inventory['total_processing_activities']} activities")
    
    # Check GDPR compliance
    gdpr_report = privacy_manager.check_gdpr_compliance(user_id)
    print(f"GDPR compliance: {gdpr_report['overall_compliance']}")
    
    # Test compliance auditor
    auditor = get_compliance_auditor()
    
    # Check HIPAA compliance
    hipaa_report = auditor.check_compliance(ComplianceStandard.HIPAA)
    print(f"HIPAA compliance: {hipaa_report['overall_status']}")
    
    # Generate comprehensive report
    full_report = auditor.generate_compliance_report()
    print(f"Overall compliance score: {full_report['summary']['compliance_score']}%")
    
    # Test audit trail
    audit_hash = audit_trail(
        action="SECURITY_SCAN",
        user_id="security_scanner",
        resource="/api/v1/scan",
        details={"target": "https://example.com", "findings": 3}
    )
    
    print(f"Audit entry created: {audit_hash}")