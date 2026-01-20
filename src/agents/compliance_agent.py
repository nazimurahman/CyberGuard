# src/agents/compliance_agent.py
"""
Compliance & Privacy Agent
Specialized agent for security compliance validation and privacy regulation enforcement
Supports GDPR, HIPAA, PCI-DSS, ISO 27001, NIST, and other frameworks
"""

import torch
import re
import hashlib
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
from enum import Enum
import json
from dataclasses import dataclass, asdict

# Enum for compliance frameworks
class ComplianceFramework(Enum):
    """Major compliance frameworks and regulations"""
    GDPR = "gdpr"              # General Data Protection Regulation (EU)
    HIPAA = "hipaa"            # Health Insurance Portability and Accountability Act
    PCI_DSS = "pci_dss"        # Payment Card Industry Data Security Standard
    ISO_27001 = "iso_27001"    # Information Security Management
    NIST_CSF = "nist_csf"      # NIST Cybersecurity Framework
    SOC2 = "soc2"              # Service Organization Control 2
    CCPA = "ccpa"              # California Consumer Privacy Act
    FERPA = "ferpa"            # Family Educational Rights and Privacy Act
    GLBA = "glba"              # Gramm-Leach-Bliley Act
    SOX = "sox"                # Sarbanes-Oxley Act

# Enum for compliance status
class ComplianceStatus(Enum):
    """Compliance validation status"""
    COMPLIANT = "compliant"           # Fully compliant
    PARTIALLY_COMPLIANT = "partial"   # Some requirements missing
    NON_COMPLIANT = "non_compliant"   # Major requirements missing
    UNKNOWN = "unknown"               # Unable to determine
    EXEMPT = "exempt"                 # Not applicable

# Data class for compliance requirement
@dataclass
class ComplianceRequirement:
    """Individual compliance requirement"""
    framework: ComplianceFramework    # Which framework
    requirement_id: str               # Framework-specific ID (e.g., "GDPR-Art-32")
    description: str                  # Human-readable description
    category: str                     # Category (e.g., "Data Protection", "Access Control")
    severity: str                     # Critical, High, Medium, Low
    evidence_required: List[str]      # What evidence is needed
    automated_check: bool            # Can be checked automatically
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['framework'] = self.framework.value
        return data

# Data class for compliance finding
@dataclass
class ComplianceFinding:
    """Individual compliance finding/violation"""
    requirement: ComplianceRequirement
    status: ComplianceStatus
    evidence: List[str]               # Evidence collected
    findings: List[str]               # Specific findings
    recommendation: str               # How to become compliant
    risk_score: float                # 0.0 to 1.0
    last_check: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['requirement'] = self.requirement.to_dict()
        data['status'] = self.status.value
        data['last_check'] = self.last_check.isoformat()
        return data

class CompliancePrivacyAgent:
    """
    Compliance & Privacy Agent
    Validates security controls against regulatory frameworks
    Ensures privacy requirements are met
    """
    
    def __init__(self, agent_id: str = "compliance_agent_001"):
        """
        Initialize Compliance & Privacy Agent
        
        Args:
            agent_id: Unique identifier for this agent instance
        """
        self.agent_id = agent_id
        self.name = "Compliance & Privacy Agent"
        
        # Compliance framework configurations
        self.frameworks: Set[ComplianceFramework] = set()
        
        # Load compliance requirements database
        self.requirements = self._load_compliance_requirements()
        
        # Privacy-sensitive data patterns
        self.pii_patterns = self._load_pii_patterns()
        
        # Compliance check history
        self.compliance_history: List[Dict[str, Any]] = []
        self.max_history = 100
        
        # Agent confidence and performance
        self.confidence = 0.8
        self.checks_performed = 0
        self.compliance_rate = 0.0
        
        # Framework-specific checkers
        self.checkers = {
            ComplianceFramework.GDPR: self._check_gdpr_compliance,
            ComplianceFramework.HIPAA: self._check_hipaa_compliance,
            ComplianceFramework.PCI_DSS: self._check_pci_dss_compliance,
            ComplianceFramework.ISO_27001: self._check_iso_27001_compliance,
            ComplianceFramework.NIST_CSF: self._check_nist_csf_compliance
        }
    
    def _load_compliance_requirements(self) -> Dict[ComplianceFramework, List[ComplianceRequirement]]:
        """
        Load compliance requirements for each framework
        
        Returns:
            Dictionary mapping frameworks to their requirements
        """
        requirements = {}
        
        # GDPR Requirements (General Data Protection Regulation)
        requirements[ComplianceFramework.GDPR] = [
            ComplianceRequirement(
                framework=ComplianceFramework.GDPR,
                requirement_id="GDPR-Art-5",
                description="Principles relating to processing of personal data",
                category="Data Protection",
                severity="Critical",
                evidence_required=["Data processing policies", "Consent mechanisms"],
                automated_check=True
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.GDPR,
                requirement_id="GDPR-Art-32",
                description="Security of processing (encryption, confidentiality)",
                category="Technical Security",
                severity="Critical",
                evidence_required=["Encryption implementation", "Access logs"],
                automated_check=True
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.GDPR,
                requirement_id="GDPR-Art-33",
                description="Notification of personal data breach to supervisory authority",
                category="Incident Response",
                severity="High",
                evidence_required=["Breach notification procedures", "Contact lists"],
                automated_check=False
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.GDPR,
                requirement_id="GDPR-Art-25",
                description="Data protection by design and by default",
                category="Privacy Design",
                severity="High",
                evidence_required=["Privacy impact assessments", "Default settings"],
                automated_check=True
            )
        ]
        
        # HIPAA Requirements (Health Information)
        requirements[ComplianceFramework.HIPAA] = [
            ComplianceRequirement(
                framework=ComplianceFramework.HIPAA,
                requirement_id="HIPAA-164.308",
                description="Administrative safeguards",
                category="Administrative",
                severity="Critical",
                evidence_required=["Risk analysis", "Security management process"],
                automated_check=True
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.HIPAA,
                requirement_id="HIPAA-164.312",
                description="Technical safeguards",
                category="Technical Security",
                severity="Critical",
                evidence_required=["Access control", "Audit controls", "Integrity controls"],
                automated_check=True
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.HIPAA,
                requirement_id="HIPAA-164.314",
                description="Organizational requirements",
                category="Organizational",
                severity="High",
                evidence_required=["Business associate contracts", "Policies"],
                automated_check=False
            )
        ]
        
        # PCI-DSS Requirements (Payment Card Data)
        requirements[ComplianceFramework.PCI_DSS] = [
            ComplianceRequirement(
                framework=ComplianceFramework.PCI_DSS,
                requirement_id="PCI-DSS-1",
                description="Install and maintain network security controls",
                category="Network Security",
                severity="Critical",
                evidence_required=["Firewall configurations", "Network diagrams"],
                automated_check=True
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.PCI_DSS,
                requirement_id="PCI-DSS-3",
                description="Protect stored cardholder data",
                category="Data Protection",
                severity="Critical",
                evidence_required=["Encryption implementation", "Data retention policies"],
                automated_check=True
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.PCI_DSS,
                requirement_id="PCI-DSS-6",
                description="Develop and maintain secure systems",
                category="System Security",
                severity="High",
                evidence_required=["Patch management", "Vulnerability scanning"],
                automated_check=True
            )
        ]
        
        # ISO 27001 Requirements
        requirements[ComplianceFramework.ISO_27001] = [
            ComplianceRequirement(
                framework=ComplianceFramework.ISO_27001,
                requirement_id="ISO-A.9",
                description="Access control",
                category="Access Control",
                severity="Critical",
                evidence_required=["Access control policies", "User access reviews"],
                automated_check=True
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.ISO_27001,
                requirement_id="ISO-A.12",
                description="Operations security",
                category="Operations",
                severity="High",
                evidence_required=["Change management", "Malware protection"],
                automated_check=True
            ),
            ComplianceRequirement(
                framework=ComplianceFramework.ISO_27001,
                requirement_id="ISO-A.18",
                description="Compliance",
                category="Compliance",
                severity="Medium",
                evidence_required=["Legal compliance checks", "Privacy protection"],
                automated_check=True
            )
        ]
        
        return requirements
    
    def _load_pii_patterns(self) -> Dict[str, List[str]]:
        """
        Load Personally Identifiable Information (PII) detection patterns
        
        Returns:
            Dictionary of PII types and their regex patterns
        """
        return {
            "email": [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            ],
            "ssn": [
                r'\b\d{3}-\d{2}-\d{4}\b',  # 123-45-6789
                r'\b\d{9}\b'                # 123456789
            ],
            "credit_card": [
                r'\b(?:\d[ -]*?){13,16}\b',  # Basic card number pattern
                r'\b4[0-9]{12}(?:[0-9]{3})?\b',  # Visa
                r'\b5[1-5][0-9]{14}\b',      # MasterCard
                r'\b3[47][0-9]{13}\b',       # American Express
                r'\b6(?:011|5[0-9]{2})[0-9]{12}\b'  # Discover
            ],
            "phone": [
                r'\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'
            ],
            "ip_address": [
                r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            ],
            "date_of_birth": [
                r'\b\d{1,2}/\d{1,2}/\d{4}\b',
                r'\b\d{4}-\d{1,2}-\d{1,2}\b'
            ],
            "address": [
                r'\b\d+\s+[A-Za-z]+\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd)\b',
                r'\bPO Box \d+\b'
            ]
        }
    
    def enable_framework(self, framework: ComplianceFramework):
        """
        Enable a specific compliance framework for checking
        
        Args:
            framework: Compliance framework to enable
        """
        self.frameworks.add(framework)
        print(f"✅ Enabled compliance framework: {framework.value.upper()}")
    
    def disable_framework(self, framework: ComplianceFramework):
        """
        Disable a compliance framework
        
        Args:
            framework: Compliance framework to disable
        """
        if framework in self.frameworks:
            self.frameworks.remove(framework)
            print(f"⚠️ Disabled compliance framework: {framework.value.upper()}")
    
    def analyze(self, security_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze security data for compliance violations
        
        Args:
            security_data: Dictionary containing:
                - url: Target URL/application
                - headers: HTTP headers
                - body: Request/response body
                - configuration: System configuration
                - logs: Access/security logs
                
        Returns:
            Dictionary with compliance analysis results
        """
        import time
        start_time = time.time()
        
        # Extract data to analyze
        url = security_data.get('url', '')
        headers = security_data.get('headers', {})
        body = security_data.get('body', '')
        config = security_data.get('configuration', {})
        logs = security_data.get('logs', [])
        
        all_findings = []
        framework_results = {}
        pii_findings = []
        
        # Step 1: Check PII exposure
        pii_findings = self._check_pii_exposure(body, headers, logs)
        
        # Step 2: Run framework-specific checks
        for framework in self.frameworks:
            if framework in self.checkers:
                try:
                    framework_result = self.checkers[framework](
                        url=url,
                        headers=headers,
                        config=config,
                        logs=logs,
                        pii_findings=pii_findings
                    )
                    framework_results[framework.value] = framework_result
                    all_findings.extend(framework_result.get('findings', []))
                except Exception as e:
                    print(f"❌ Error checking {framework.value}: {e}")
        
        # Step 3: Calculate overall compliance score
        compliance_score = self._calculate_compliance_score(framework_results)
        
        # Step 4: Generate compliance report
        compliance_report = self._generate_compliance_report(framework_results, compliance_score)
        
        # Step 5: Update metrics
        self.checks_performed += 1
        if compliance_score >= 0.9:
            self.compliance_rate = (self.compliance_rate * 0.9) + (0.1 * 1.0)
        else:
            self.compliance_rate = (self.compliance_rate * 0.9) + (0.1 * 0.0)
        
        # Update confidence based on findings
        self._update_confidence(compliance_score, len(all_findings))
        
        processing_time = time.time() - start_time
        
        return {
            'agent_id': self.agent_id,
            'agent_name': self.name,
            'compliance_score': compliance_score,
            'compliance_status': self._get_overall_status(compliance_score),
            'frameworks_checked': [f.value for f in self.frameworks],
            'framework_results': framework_results,
            'pii_findings': pii_findings,
            'total_findings': len(all_findings),
            'critical_findings': len([f for f in all_findings 
                                    if f.get('severity') == 'Critical']),
            'recommendations': compliance_report['recommendations'],
            'processing_time': processing_time,
            'confidence': self.confidence,
            'reasoning_state': self._get_reasoning_state(),
            'decision': {
                'compliance_level': compliance_score,
                'confidence': self.confidence,
                'evidence': compliance_report['summary']
            }
        }
    
    def _check_pii_exposure(self, body: Any, headers: Dict, 
                          logs: List[Dict]) -> List[Dict[str, Any]]:
        """
        Check for Personally Identifiable Information (PII) exposure
        
        Args:
            body: Request/response body
            headers: HTTP headers
            logs: System logs
            
        Returns:
            List of PII findings
        """
        findings = []
        
        # Convert body to string for pattern matching
        body_str = str(body)
        
        # Check each PII type
        for pii_type, patterns in self.pii_patterns.items():
            for pattern in patterns:
                try:
                    matches = re.findall(pattern, body_str, re.IGNORECASE)
                    if matches:
                        # Mask matches for logging
                        masked_matches = []
                        for match in matches[:3]:  # Limit to 3 examples
                            if len(match) > 4:
                                masked = match[:2] + "***" + match[-2:]
                            else:
                                masked = "***"
                            masked_matches.append(masked)
                        
                        findings.append({
                            'type': 'PII_EXPOSURE',
                            'pii_type': pii_type,
                            'severity': self._get_pii_severity(pii_type),
                            'location': 'Response Body',
                            'matches_found': len(matches),
                            'examples': masked_matches,
                            'recommendation': f"Remove or encrypt {pii_type} data",
                            'regulation': "GDPR/HIPAA/CCPA"
                        })
                except re.error:
                    continue
        
        # Check headers for sensitive information
        sensitive_headers = ['Authorization', 'Cookie', 'X-API-Key', 'X-Auth-Token']
        for header in sensitive_headers:
            if header in headers:
                header_value = str(headers[header])
                if len(header_value) > 20:  # Likely contains sensitive data
                    findings.append({
                        'type': 'SENSITIVE_HEADER_EXPOSURE',
                        'header': header,
                        'severity': 'High',
                        'location': 'HTTP Headers',
                        'recommendation': f'Do not expose {header} in responses',
                        'regulation': 'PCI-DSS/ISO-27001'
                    })
        
        return findings
    
    def _get_pii_severity(self, pii_type: str) -> str:
        """Get severity level for PII type"""
        severity_map = {
            'ssn': 'Critical',
            'credit_card': 'Critical',
            'email': 'Medium',
            'phone': 'Medium',
            'ip_address': 'Low',
            'date_of_birth': 'High',
            'address': 'Medium'
        }
        return severity_map.get(pii_type, 'Medium')
    
    def _check_gdpr_compliance(self, url: str, headers: Dict, 
                             config: Dict, logs: List, 
                             pii_findings: List) -> Dict[str, Any]:
        """
        Check GDPR compliance requirements
        
        Args:
            url: Target URL
            headers: HTTP headers
            config: System configuration
            logs: Access logs
            pii_findings: PII exposure findings
            
        Returns:
            GDPR compliance results
        """
        findings = []
        evidence = []
        
        # Check 1: Data Protection (GDPR Article 32)
        security_headers = self._check_security_headers(headers)
        if not security_headers.get('encryption_enabled', False):
            findings.append({
                'requirement': 'GDPR-Art-32',
                'type': 'ENCRYPTION_MISSING',
                'severity': 'Critical',
                'description': 'No encryption detected for data transmission',
                'recommendation': 'Enable HTTPS/TLS encryption'
            })
        
        # Check 2: Privacy by Design (GDPR Article 25)
        privacy_headers = ['Privacy-Policy', 'Terms-of-Service']
        if not any(h in headers for h in privacy_headers):
            findings.append({
                'requirement': 'GDPR-Art-25',
                'type': 'PRIVACY_NOTICE_MISSING',
                'severity': 'High',
                'description': 'No privacy policy or terms of service headers',
                'recommendation': 'Add privacy policy and terms links'
            })
        
        # Check 3: Data Minimization
        if pii_findings:
            findings.extend([
                {
                    'requirement': 'GDPR-Art-5',
                    'type': 'PII_EXCESSIVE_COLLECTION',
                    'severity': f['severity'],
                    'description': f"Exposed {f['pii_type']} data",
                    'recommendation': f['recommendation']
                }
                for f in pii_findings if f['severity'] in ['Critical', 'High']
            ])
        
        # Check 4: Consent Management
        consent_indicators = ['consent', 'cookie', 'opt-in', 'gdpr']
        body_lower = str(config.get('body', '')).lower()
        if not any(indicator in body_lower for indicator in consent_indicators):
            findings.append({
                'requirement': 'GDPR-Art-7',
                'type': 'CONSENT_MECHANISM_MISSING',
                'severity': 'High',
                'description': 'No visible consent management mechanism',
                'recommendation': 'Implement cookie consent banner and preferences'
            })
        
        # Calculate GDPR compliance score
        total_requirements = len(self.requirements[ComplianceFramework.GDPR])
        failed_requirements = len([f for f in findings 
                                 if f['severity'] in ['Critical', 'High']])
        compliance_score = 1.0 - (failed_requirements / total_requirements)
        
        return {
            'framework': 'GDPR',
            'compliance_score': max(0.0, compliance_score),
            'status': self._get_framework_status(compliance_score),
            'findings': findings,
            'requirements_checked': total_requirements,
            'requirements_failed': failed_requirements,
            'evidence_collected': evidence
        }
    
    def _check_hipaa_compliance(self, url: str, headers: Dict,
                              config: Dict, logs: List,
                              pii_findings: List) -> Dict[str, Any]:
        """
        Check HIPAA compliance requirements
        
        Args:
            url: Target URL
            headers: HTTP headers
            config: System configuration
            logs: Access logs
            pii_findings: PII exposure findings
            
        Returns:
            HIPAA compliance results
        """
        findings = []
        evidence = []
        
        # Check 1: Access Control (HIPAA 164.312)
        access_control_headers = ['WWW-Authenticate', 'Authorization']
        if not any(h in headers for h in access_control_headers):
            findings.append({
                'requirement': 'HIPAA-164.312',
                'type': 'ACCESS_CONTROL_MISSING',
                'severity': 'Critical',
                'description': 'No access control mechanisms detected',
                'recommendation': 'Implement authentication and authorization'
            })
        
        # Check 2: Audit Controls (HIPAA 164.312)
        if not logs or len(logs) < 10:  # Arbitrary threshold
            findings.append({
                'requirement': 'HIPAA-164.312',
                'type': 'AUDIT_LOGS_INSUFFICIENT',
                'severity': 'High',
                'description': 'Insufficient audit logging detected',
                'recommendation': 'Enable comprehensive access logging'
            })
        
        # Check 3: Integrity Controls
        security_headers = self._check_security_headers(headers)
        if not security_headers.get('integrity_protection', False):
            findings.append({
                'requirement': 'HIPAA-164.312',
                'type': 'INTEGRITY_CONTROLS_MISSING',
                'severity': 'High',
                'description': 'No integrity protection (e.g., checksums, hashing)',
                'recommendation': 'Implement data integrity verification'
            })
        
        # Check 4: Transmission Security
        if not security_headers.get('encryption_enabled', False):
            findings.append({
                'requirement': 'HIPAA-164.312',
                'type': 'ENCRYPTION_MISSING',
                'severity': 'Critical',
                'description': 'No encryption for data transmission',
                'recommendation': 'Enable TLS 1.2 or higher'
            })
        
        # Calculate HIPAA compliance score
        total_requirements = len(self.requirements[ComplianceFramework.HIPAA])
        failed_requirements = len([f for f in findings 
                                 if f['severity'] in ['Critical', 'High']])
        compliance_score = 1.0 - (failed_requirements / total_requirements)
        
        return {
            'framework': 'HIPAA',
            'compliance_score': max(0.0, compliance_score),
            'status': self._get_framework_status(compliance_score),
            'findings': findings,
            'requirements_checked': total_requirements,
            'requirements_failed': failed_requirements,
            'evidence_collected': evidence
        }
    
    def _check_pci_dss_compliance(self, url: str, headers: Dict,
                                config: Dict, logs: List,
                                pii_findings: List) -> Dict[str, Any]:
        """
        Check PCI-DSS compliance requirements
        
        Args:
            url: Target URL
            headers: HTTP headers
            config: System configuration
            logs: Access logs
            pii_findings: PII exposure findings
            
        Returns:
            PCI-DSS compliance results
        """
        findings = []
        evidence = []
        
        # Check 1: Network Security (PCI-DSS 1)
        security_headers = self._check_security_headers(headers)
        if not security_headers.get('encryption_enabled', False):
            findings.append({
                'requirement': 'PCI-DSS-1',
                'type': 'INSECURE_TRANSMISSION',
                'severity': 'Critical',
                'description': 'Data transmitted without encryption',
                'recommendation': 'Enable TLS 1.2+ with strong ciphers'
            })
        
        # Check 2: Protect Cardholder Data (PCI-DSS 3)
        card_data_found = any(f['pii_type'] == 'credit_card' 
                            for f in pii_findings)
        if card_data_found:
            findings.append({
                'requirement': 'PCI-DSS-3',
                'type': 'CARDHOLDER_DATA_EXPOSED',
                'severity': 'Critical',
                'description': 'Credit card data detected in responses',
                'recommendation': 'Never store or transmit full card numbers'
            })
        
        # Check 3: Vulnerability Management (PCI-DSS 6)
        # This would normally check for security headers, patching, etc.
        required_headers = ['X-Content-Type-Options', 'X-Frame-Options']
        missing_headers = [h for h in required_headers if h not in headers]
        if missing_headers:
            findings.append({
                'requirement': 'PCI-DSS-6',
                'type': 'SECURITY_HEADERS_MISSING',
                'severity': 'High',
                'description': f'Missing security headers: {", ".join(missing_headers)}',
                'recommendation': 'Add missing security headers'
            })
        
        # Calculate PCI-DSS compliance score
        total_requirements = len(self.requirements[ComplianceFramework.PCI_DSS])
        failed_requirements = len([f for f in findings 
                                 if f['severity'] in ['Critical', 'High']])
        compliance_score = 1.0 - (failed_requirements / total_requirements)
        
        return {
            'framework': 'PCI-DSS',
            'compliance_score': max(0.0, compliance_score),
            'status': self._get_framework_status(compliance_score),
            'findings': findings,
            'requirements_checked': total_requirements,
            'requirements_failed': failed_requirements,
            'evidence_collected': evidence
        }
    
    def _check_iso_27001_compliance(self, url: str, headers: Dict,
                                  config: Dict, logs: List,
                                  pii_findings: List) -> Dict[str, Any]:
        """
        Check ISO 27001 compliance requirements
        
        Args:
            url: Target URL
            headers: HTTP headers
            config: System configuration
            logs: Access logs
            pii_findings: PII exposure findings
            
        Returns:
            ISO 27001 compliance results
        """
        findings = []
        evidence = []
        
        # Check 1: Access Control (ISO A.9)
        if 'Authorization' not in headers and 'WWW-Authenticate' not in headers:
            findings.append({
                'requirement': 'ISO-A.9',
                'type': 'ACCESS_CONTROL_MISSING',
                'severity': 'Critical',
                'description': 'No access control mechanisms in place',
                'recommendation': 'Implement proper authentication'
            })
        
        # Check 2: Cryptography (ISO A.10)
        security_headers = self._check_security_headers(headers)
        if not security_headers.get('encryption_enabled', False):
            findings.append({
                'requirement': 'ISO-A.10',
                'type': 'CRYPTOGRAPHY_MISSING',
                'severity': 'Critical',
                'description': 'No cryptographic protection for data',
                'recommendation': 'Implement encryption for data at rest and in transit'
            })
        
        # Check 3: Operations Security (ISO A.12)
        if not logs or len(logs) < 5:
            findings.append({
                'requirement': 'ISO-A.12',
                'type': 'OPERATIONAL_LOGGING_INSUFFICIENT',
                'severity': 'High',
                'description': 'Insufficient operational logging',
                'recommendation': 'Enable comprehensive system logging'
            })
        
        # Calculate ISO 27001 compliance score
        total_requirements = len(self.requirements[ComplianceFramework.ISO_27001])
        failed_requirements = len([f for f in findings 
                                 if f['severity'] in ['Critical', 'High']])
        compliance_score = 1.0 - (failed_requirements / total_requirements)
        
        return {
            'framework': 'ISO-27001',
            'compliance_score': max(0.0, compliance_score),
            'status': self._get_framework_status(compliance_score),
            'findings': findings,
            'requirements_checked': total_requirements,
            'requirements_failed': failed_requirements,
            'evidence_collected': evidence
        }
    
    def _check_nist_csf_compliance(self, url: str, headers: Dict,
                                 config: Dict, logs: List,
                                 pii_findings: List) -> Dict[str, Any]:
        """
        Check NIST Cybersecurity Framework compliance
        
        Args:
            url: Target URL
            headers: HTTP headers
            config: System configuration
            logs: Access logs
            pii_findings: PII exposure findings
            
        Returns:
            NIST CSF compliance results
        """
        findings = []
        evidence = []
        
        # NIST CSF Core Functions: Identify, Protect, Detect, Respond, Recover
        
        # Check: Protect Function
        security_headers = self._check_security_headers(headers)
        protection_score = 0.0
        if security_headers.get('encryption_enabled', False):
            protection_score += 0.25
        if 'Authorization' in headers:
            protection_score += 0.25
        if 'X-Content-Type-Options' in headers:
            protection_score += 0.25
        if 'X-Frame-Options' in headers:
            protection_score += 0.25
        
        if protection_score < 0.5:
            findings.append({
                'requirement': 'NIST-PROTECT',
                'type': 'PROTECTION_CONTROLS_WEAK',
                'severity': 'High',
                'description': f'Protection controls score: {protection_score:.2f}/1.0',
                'recommendation': 'Implement stronger security controls'
            })
        
        # Check: Detect Function
        detect_score = 0.0
        if logs and len(logs) >= 10:
            detect_score += 0.5
        if any('monitor' in str(log).lower() for log in logs[:5]):
            detect_score += 0.5
        
        if detect_score < 0.5:
            findings.append({
                'requirement': 'NIST-DETECT',
                'type': 'DETECTION_CAPABILITIES_WEAK',
                'severity': 'Medium',
                'description': f'Detection capabilities score: {detect_score:.2f}/1.0',
                'recommendation': 'Enhance monitoring and detection capabilities'
            })
        
        # Calculate NIST CSF compliance score
        total_requirements = 5  # NIST CSF has 5 core functions
        compliance_score = (protection_score + detect_score) / 2  # Average of checked functions
        
        return {
            'framework': 'NIST-CSF',
            'compliance_score': max(0.0, compliance_score),
            'status': self._get_framework_status(compliance_score),
            'findings': findings,
            'requirements_checked': total_requirements,
            'requirements_failed': len(findings),
            'evidence_collected': evidence
        }
    
    def _check_security_headers(self, headers: Dict) -> Dict[str, bool]:
        """
        Analyze security headers
        
        Args:
            headers: HTTP headers dictionary
            
        Returns:
            Dictionary with security header analysis
        """
        analysis = {
            'encryption_enabled': False,
            'integrity_protection': False,
            'content_security': False
        }
        
        # Check for HTTPS/TLS indicators
        if any(key.lower() in ['https', 'ssl', 'tls'] 
               for key in headers.keys()):
            analysis['encryption_enabled'] = True
        
        # Check for security headers
        security_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection'
        ]
        
        present_headers = [h for h in security_headers if h in headers]
        analysis['security_headers_present'] = present_headers
        analysis['security_headers_count'] = len(present_headers)
        
        # Check for integrity protection
        if 'Content-Security-Policy' in headers:
            csp = headers['Content-Security-Policy']
            if 'unsafe-inline' not in csp and 'unsafe-eval' not in csp:
                analysis['integrity_protection'] = True
        
        return analysis
    
    def _get_framework_status(self, compliance_score: float) -> str:
        """
        Get compliance status based on score
        
        Args:
            compliance_score: Score from 0.0 to 1.0
            
        Returns:
            Compliance status string
        """
        if compliance_score >= 0.9:
            return ComplianceStatus.COMPLIANT.value
        elif compliance_score >= 0.7:
            return ComplianceStatus.PARTIALLY_COMPLIANT.value
        elif compliance_score >= 0.4:
            return ComplianceStatus.NON_COMPLIANT.value
        else:
            return ComplianceStatus.UNKNOWN.value
    
    def _get_overall_status(self, compliance_score: float) -> str:
        """
        Get overall compliance status
        
        Args:
            compliance_score: Overall compliance score
            
        Returns:
            Human-readable status
        """
        if compliance_score >= 0.9:
            return "✅ FULLY COMPLIANT"
        elif compliance_score >= 0.7:
            return "⚠️  PARTIALLY COMPLIANT"
        elif compliance_score >= 0.5:
            return "❌ NON-COMPLIANT (Needs Attention)"
        else:
            return "🚨 SIGNIFICANT COMPLIANCE ISSUES"
    
    def _calculate_compliance_score(self, 
                                  framework_results: Dict[str, Dict]) -> float:
        """
        Calculate overall compliance score across all frameworks
        
        Args:
            framework_results: Results from each framework check
            
        Returns:
            Overall compliance score (0.0 to 1.0)
        """
        if not framework_results:
            return 0.0
        
        total_score = 0.0
        weight_sum = 0.0
        
        # Weight frameworks by importance
        framework_weights = {
            'gdpr': 1.0,
            'hipaa': 1.0,
            'pci_dss': 1.0,
            'iso_27001': 0.8,
            'nist_csf': 0.8
        }
        
        for framework, results in framework_results.items():
            weight = framework_weights.get(framework, 0.5)
            score = results.get('compliance_score', 0.0)
            
            total_score += score * weight
            weight_sum += weight
        
        return total_score / weight_sum if weight_sum > 0 else 0.0
    
    def _generate_compliance_report(self, 
                                  framework_results: Dict[str, Dict],
                                  overall_score: float) -> Dict[str, Any]:
        """
        Generate comprehensive compliance report
        
        Args:
            framework_results: Results from each framework
            overall_score: Overall compliance score
            
        Returns:
            Compliance report dictionary
        """
        # Compile all findings
        all_findings = []
        for framework, results in framework_results.items():
            for finding in results.get('findings', []):
                finding['framework'] = framework
                all_findings.append(finding)
        
        # Categorize findings by severity
        critical_findings = [f for f in all_findings if f.get('severity') == 'Critical']
        high_findings = [f for f in all_findings if f.get('severity') == 'High']
        medium_findings = [f for f in all_findings if f.get('severity') == 'Medium']
        low_findings = [f for f in all_findings if f.get('severity') == 'Low']
        
        # Generate recommendations
        recommendations = []
        
        if critical_findings:
            recommendations.append("🚨 Address critical findings immediately")
            for finding in critical_findings[:2]:  # Top 2 critical
                recommendations.append(f"- {finding.get('recommendation', '')}")
        
        if high_findings:
            recommendations.append("⚠️  Address high-priority findings within 30 days")
            for finding in high_findings[:2]:  # Top 2 high
                recommendations.append(f"- {finding.get('recommendation', '')}")
        
        if overall_score < 0.7:
            recommendations.append("📋 Conduct comprehensive security assessment")
            recommendations.append("🔧 Implement missing security controls")
            recommendations.append("📚 Review and update security policies")
        
        if overall_score >= 0.9:
            recommendations.append("✅ Maintain current security controls")
            recommendations.append("🔍 Continue regular compliance monitoring")
            recommendations.append("📈 Consider security maturity improvements")
        
        # Summary
        summary = [
            f"Overall Compliance Score: {overall_score:.2%}",
            f"Frameworks Checked: {len(framework_results)}",
            f"Critical Findings: {len(critical_findings)}",
            f"High Findings: {len(high_findings)}",
            f"Medium Findings: {len(medium_findings)}",
            f"Low Findings: {len(low_findings)}"
        ]
        
        # Add framework-specific summaries
        for framework, results in framework_results.items():
            score = results.get('compliance_score', 0.0)
            status = results.get('status', 'unknown')
            summary.append(f"{framework.upper()}: {score:.2%} ({status})")
        
        return {
            'summary': summary,
            'findings_by_severity': {
                'critical': len(critical_findings),
                'high': len(high_findings),
                'medium': len(medium_findings),
                'low': len(low_findings)
            },
            'recommendations': recommendations,
            'timestamp': datetime.now().isoformat(),
            'next_review_date': (datetime.now() + timedelta(days=90)).isoformat()
        }
    
    def _update_confidence(self, compliance_score: float, 
                          total_findings: int):
        """
        Update agent confidence based on performance
        
        Args:
            compliance_score: Overall compliance score
            total_findings: Total number of findings
        """
        # Confidence increases with comprehensive checking
        if total_findings > 0:
            # Found issues (good detection)
            self.confidence = min(1.0, self.confidence * 1.05)
        elif compliance_score >= 0.9:
            # High compliance with no findings (good system)
            self.confidence = min(1.0, self.confidence * 1.02)
        else:
            # Low compliance but no findings (potentially missed issues)
            self.confidence = max(0.1, self.confidence * 0.95)
    
    def _get_reasoning_state(self) -> torch.Tensor:
        """
        Get current reasoning state for mHC coordination
        
        Returns:
            Tensor representing current reasoning state
        """
        # Create feature vector from current state
        features = []
        
        # Framework status features
        framework_count = len(self.frameworks)
        features.append(framework_count / 10.0)  # Normalized
        
        # Compliance rate feature
        features.append(self.compliance_rate)
        
        # Confidence feature
        features.append(self.confidence)
        
        # Recent findings density (from last 10 checks)
        recent_checks = self.compliance_history[-10:] if self.compliance_history else []
        if recent_checks:
            avg_findings = sum(c.get('total_findings', 0) for c in recent_checks) / len(recent_checks)
            features.append(avg_findings / 20.0)  # Normalized
        else:
            features.append(0.0)
        
        # PII detection rate (placeholder)
        features.append(0.5)  # Default
        
        # Pad to 512 dimensions
        while len(features) < 512:
            features.append(0.0)
        
        return torch.tensor(features[:512], dtype=torch.float32)
    
    def get_agent_status(self) -> Dict[str, Any]:
        """Get current agent status and metrics"""
        return {
            'agent_id': self.agent_id,
            'agent_name': self.name,
            'confidence': self.confidence,
            'active_frameworks': [f.value for f in self.frameworks],
            'total_frameworks_available': len(self.requirements),
            'checks_performed': self.checks_performed,
            'compliance_rate': self.compliance_rate,
            'pii_patterns_loaded': len(self.pii_patterns),
            'requirements_loaded': sum(len(reqs) for reqs in self.requirements.values())
        }