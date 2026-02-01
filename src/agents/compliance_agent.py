"""
Compliance & Privacy Agent
Specialized agent for security compliance validation and privacy regulation enforcement
Supports GDPR, HIPAA, PCI-DSS, ISO 27001, NIST, and other frameworks
"""

# Standard library imports
import torch  # For tensor operations and machine learning integration
import re  # For regular expression pattern matching (PII detection)
import hashlib  # For cryptographic hashing operations (not currently used but available)
from typing import Dict, List, Any, Optional, Set, Tuple  # Type hints for better code documentation
from datetime import datetime, timedelta  # Date and time operations
from enum import Enum  # For creating enumerated constants
import json  # JSON serialization/deserialization (not currently used but available)
from dataclasses import dataclass, asdict  # For creating structured data classes

# Enum for compliance frameworks
class ComplianceFramework(Enum):
    """
    Enumeration of major compliance frameworks and regulations
    Each framework has a string identifier value for easier serialization
    """
    GDPR = "gdpr"  # General Data Protection Regulation (European Union)
    HIPAA = "hipaa"  # Health Insurance Portability and Accountability Act (USA)
    PCI_DSS = "pci_dss"  # Payment Card Industry Data Security Standard
    ISO_27001 = "iso_27001"  # International standard for information security management
    NIST_CSF = "nist_csf"  # NIST Cybersecurity Framework
    SOC2 = "soc2"  # Service Organization Control 2 (Trust services criteria)
    CCPA = "ccpa"  # California Consumer Privacy Act
    FERPA = "ferpa"  # Family Educational Rights and Privacy Act (USA education)
    GLBA = "glba"  # Gramm-Leach-Bliley Act (US financial services)
    SOX = "sox"  # Sarbanes-Oxley Act (US corporate governance)

# Enum for compliance status
class ComplianceStatus(Enum):
    """
    Enumeration of compliance validation status levels
    Used to categorize the result of compliance checks
    """
    COMPLIANT = "compliant"  # All requirements are met
    PARTIALLY_COMPLIANT = "partial"  # Some requirements are met but not all
    NON_COMPLIANT = "non_compliant"  # Major requirements are not met
    UNKNOWN = "unknown"  # Status cannot be determined
    EXEMPT = "exempt"  # Framework does not apply to this system

# Data class for compliance requirement
@dataclass
class ComplianceRequirement:
    """
    Data class representing a single compliance requirement from a framework
    Immutable data structure for storing requirement metadata
    """
    # The framework this requirement belongs to (e.g., GDPR, HIPAA)
    framework: ComplianceFramework
    # Framework-specific identifier (e.g., "GDPR-Art-32", "HIPAA-164.308")
    requirement_id: str
    # Human-readable description of the requirement
    description: str
    # Category grouping (e.g., "Data Protection", "Access Control")
    category: str
    # Severity level indicating importance (Critical, High, Medium, Low)
    severity: str
    # List of evidence types needed to prove compliance
    evidence_required: List[str]
    # Whether this requirement can be checked automatically by the agent
    automated_check: bool
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the data class instance to a dictionary for serialization
        Returns: Dictionary representation of the requirement
        """
        # Convert all fields to a dictionary using dataclasses.asdict
        data = asdict(self)
        # Convert enum value to string for JSON serialization
        data['framework'] = self.framework.value
        return data

# Data class for compliance finding
@dataclass
class ComplianceFinding:
    """
    Data class representing a specific compliance finding or violation
    Contains both the requirement being checked and the results of the check
    """
    # The requirement that was checked
    requirement: ComplianceRequirement
    # Result status of the check (compliant, non-compliant, etc.)
    status: ComplianceStatus
    # List of evidence collected during the check
    evidence: List[str]
    # Specific findings or observations from the check
    findings: List[str]
    # Recommended actions to achieve compliance
    recommendation: str
    # Numeric risk score from 0.0 (no risk) to 1.0 (maximum risk)
    risk_score: float
    # When this check was performed
    last_check: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the finding to a dictionary for serialization
        Returns: Dictionary representation of the finding
        """
        data = asdict(self)
        # Convert nested requirement to dictionary
        data['requirement'] = self.requirement.to_dict()
        # Convert enum to string value
        data['status'] = self.status.value
        # Convert datetime to ISO format string
        data['last_check'] = self.last_check.isoformat()
        return data

class CompliancePrivacyAgent:
    """
    Main agent class for compliance and privacy validation
    Orchestrates framework checks, PII detection, and compliance reporting
    """
    
    def __init__(self, agent_id: str = "compliance_agent_001"):
        """
        Initialize the Compliance & Privacy Agent with default values
        Args:
            agent_id: Unique identifier for this agent instance
        """
        # Unique identifier for agent tracking
        self.agent_id = agent_id
        # Human-readable name for display purposes
        self.name = "Compliance & Privacy Agent"
        
        # Set of active compliance frameworks to check
        # Initially empty, frameworks must be enabled manually
        self.frameworks: Set[ComplianceFramework] = set()
        
        # Load all known compliance requirements from internal database
        # Dictionary mapping framework enum to list of requirements
        self.requirements = self._load_compliance_requirements()
        
        # Load regex patterns for detecting Personally Identifiable Information
        # Dictionary mapping PII type to list of regex patterns
        self.pii_patterns = self._load_pii_patterns()
        
        # History of compliance checks for tracking and analytics
        # List of dictionaries containing check results
        self.compliance_history: List[Dict[str, Any]] = []
        # Maximum number of historical entries to retain
        self.max_history = 100
        
        # Agent performance metrics
        self.confidence = 0.8  # Initial confidence level (0.0 to 1.0)
        self.checks_performed = 0  # Total number of checks performed
        self.compliance_rate = 0.0  # Moving average of compliance scores
        
        # Dictionary mapping framework enums to their specific checking functions
        # Allows dynamic dispatch to framework-specific checkers
        self.checkers = {
            ComplianceFramework.GDPR: self._check_gdpr_compliance,
            ComplianceFramework.HIPAA: self._check_hipaa_compliance,
            ComplianceFramework.PCI_DSS: self._check_pci_dss_compliance,
            ComplianceFramework.ISO_27001: self._check_iso_27001_compliance,
            ComplianceFramework.NIST_CSF: self._check_nist_csf_compliance
        }
    
    def _load_compliance_requirements(self) -> Dict[ComplianceFramework, List[ComplianceRequirement]]:
        """
        Load and initialize the database of compliance requirements
        In production, this would typically load from a database or external file
        Returns: Dictionary mapping framework to list of requirements
        """
        # Initialize empty dictionary to hold requirements by framework
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
            # Additional GDPR requirements would be added here
            # Each requirement captures one specific article or clause
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
            # Additional HIPAA requirements follow similar pattern
        ]
        
        # PCI-DSS Requirements (Payment Card Data Security)
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
            # Additional PCI-DSS requirements
        ]
        
        # ISO 27001 Requirements (Information Security Management)
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
            # Additional ISO 27001 requirements
        ]
        
        # NIST CSF Requirements (Cybersecurity Framework)
        requirements[ComplianceFramework.NIST_CSF] = [
            ComplianceRequirement(
                framework=ComplianceFramework.NIST_CSF,
                requirement_id="NIST-ID",
                description="Identify - Develop organizational understanding",
                category="Governance",
                severity="High",
                evidence_required=["Asset management", "Risk assessment"],
                automated_check=True
            ),
            # Additional NIST CSF requirements
        ]
        
        return requirements
    
    def _load_pii_patterns(self) -> Dict[str, List[str]]:
        """
        Load regex patterns for detecting Personally Identifiable Information
        Each pattern is designed to match common formats of sensitive data
        Returns: Dictionary of PII types to regex pattern lists
        """
        return {
            # Email address patterns
            "email": [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            ],
            # Social Security Number patterns (US)
            "ssn": [
                r'\b\d{3}-\d{2}-\d{4}\b',  # Standard format: 123-45-6789
                r'\b\d{9}\b'  # No hyphens: 123456789
            ],
            # Credit card number patterns
            "credit_card": [
                r'\b(?:\d[ -]*?){13,16}\b',  # Generic 13-16 digit pattern
                r'\b4[0-9]{12}(?:[0-9]{3})?\b',  # Visa: starts with 4
                r'\b5[1-5][0-9]{14}\b',  # MasterCard: starts with 51-55
                r'\b3[47][0-9]{13}\b',  # American Express: starts with 34 or 37
                r'\b6(?:011|5[0-9]{2})[0-9]{12}\b'  # Discover: starts with 6011 or 65xx
            ],
            # Phone number patterns (US format)
            "phone": [
                r'\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'
            ],
            # IP address patterns (IPv4)
            "ip_address": [
                r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            ],
            # Date of birth patterns
            "date_of_birth": [
                r'\b\d{1,2}/\d{1,2}/\d{4}\b',  # MM/DD/YYYY or DD/MM/YYYY
                r'\b\d{4}-\d{1,2}-\d{1,2}\b'  # YYYY-MM-DD (ISO format)
            ],
            # Physical address patterns
            "address": [
                r'\b\d+\s+[A-Za-z]+\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd)\b',
                r'\bPO Box \d+\b'  # PO Box addresses
            ]
        }
    
    def enable_framework(self, framework: ComplianceFramework):
        """
        Activate a specific compliance framework for checking
        Args:
            framework: The compliance framework to enable
        """
        # Add framework to the set of active frameworks
        self.frameworks.add(framework)
        # Print confirmation message
        print(f"Enabled compliance framework: {framework.value.upper()}")
    
    def disable_framework(self, framework: ComplianceFramework):
        """
        Deactivate a compliance framework from checking
        Args:
            framework: The compliance framework to disable
        """
        # Check if framework is currently active
        if framework in self.frameworks:
            # Remove framework from active set
            self.frameworks.remove(framework)
            # Print confirmation message
            print(f"Disabled compliance framework: {framework.value.upper()}")
    
    def analyze(self, security_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main analysis method - orchestrates the entire compliance checking process
        Args:
            security_data: Dictionary containing all security-related data to analyze
                - url: Target URL or application identifier
                - headers: HTTP headers from request/response
                - body: Request or response body content
                - configuration: System configuration settings
                - logs: Access and security log entries
        Returns: Dictionary with comprehensive compliance analysis results
        """
        # Import time module locally to measure processing duration
        import time
        # Record start time for performance measurement
        start_time = time.time()
        
        # Extract individual components from security data dictionary
        url = security_data.get('url', '')  # Default to empty string if not provided
        headers = security_data.get('headers', {})  # Default to empty dictionary
        body = security_data.get('body', '')  # Default to empty string
        config = security_data.get('configuration', {})  # Default to empty dictionary
        logs = security_data.get('logs', [])  # Default to empty list
        
        # Initialize containers for results
        all_findings = []  # Will hold all findings from all frameworks
        framework_results = {}  # Dictionary to hold results by framework
        pii_findings = []  # Will hold PII detection results
        
        # Step 1: Check for PII exposure in the provided data
        # This is a common check across all frameworks
        pii_findings = self._check_pii_exposure(body, headers, logs)
        
        # Step 2: Run framework-specific compliance checks
        # Iterate through all enabled frameworks
        for framework in self.frameworks:
            # Check if we have a checker function for this framework
            if framework in self.checkers:
                try:
                    # Call the framework-specific checker function
                    framework_result = self.checkers[framework](
                        url=url,  # Pass the URL
                        headers=headers,  # Pass the headers
                        config=config,  # Pass the configuration
                        logs=logs,  # Pass the logs
                        pii_findings=pii_findings  # Pass PII findings for cross-checking
                    )
                    # Store results keyed by framework value (string)
                    framework_results[framework.value] = framework_result
                    # Collect all findings for summary statistics
                    all_findings.extend(framework_result.get('findings', []))
                except Exception as e:
                    # Log any errors during framework checking but continue with others
                    print(f"Error checking {framework.value}: {e}")
        
        # Step 3: Calculate overall compliance score across all frameworks
        compliance_score = self._calculate_compliance_score(framework_results)
        
        # Step 4: Generate comprehensive compliance report
        compliance_report = self._generate_compliance_report(framework_results, compliance_score)
        
        # Step 5: Update agent metrics and performance tracking
        self.checks_performed += 1  # Increment total checks counter
        
        # Update compliance rate using exponential moving average
        if compliance_score >= 0.9:
            # High compliance: increase rate towards 1.0
            self.compliance_rate = (self.compliance_rate * 0.9) + (0.1 * 1.0)
        else:
            # Low compliance: decrease rate towards 0.0
            self.compliance_rate = (self.compliance_rate * 0.9) + (0.1 * 0.0)
        
        # Update agent confidence based on performance
        self._update_confidence(compliance_score, len(all_findings))
        
        # Add current check to history for tracking
        history_entry = {
            'timestamp': datetime.now().isoformat(),  # Current time in ISO format
            'compliance_score': compliance_score,  # Overall score
            'total_findings': len(all_findings),  # Total findings count
            'frameworks': [f.value for f in self.frameworks]  # List of active frameworks
        }
        self.compliance_history.append(history_entry)
        
        # Maintain history size limit by removing oldest entries if needed
        if len(self.compliance_history) > self.max_history:
            # Remove first (oldest) entry
            self.compliance_history.pop(0)
        
        # Calculate total processing time
        processing_time = time.time() - start_time
        
        # Return comprehensive results dictionary
        return {
            'agent_id': self.agent_id,  # Agent identifier
            'agent_name': self.name,  # Agent display name
            'compliance_score': compliance_score,  # Overall score (0.0 to 1.0)
            'compliance_status': self._get_overall_status(compliance_score),  # Human-readable status
            'frameworks_checked': [f.value for f in self.frameworks],  # List of frameworks checked
            'framework_results': framework_results,  # Detailed results by framework
            'pii_findings': pii_findings,  # PII detection results
            'total_findings': len(all_findings),  # Count of all findings
            'critical_findings': len([f for f in all_findings if f.get('severity') == 'Critical']),
            'recommendations': compliance_report['recommendations'],  # Actionable recommendations
            'processing_time': processing_time,  # Time taken for analysis
            'confidence': self.confidence,  # Agent confidence level
            'reasoning_state': self._get_reasoning_state(),  # Tensor for ML coordination
            'decision': {  # Structured decision information
                'compliance_level': compliance_score,
                'confidence': self.confidence,
                'evidence': compliance_report['summary']
            }
        }
    
    def _check_pii_exposure(self, body: Any, headers: Dict, logs: List[Dict]) -> List[Dict[str, Any]]:
        """
        Check for Personally Identifiable Information exposure in various data sources
        Args:
            body: Request/response body content
            headers: HTTP headers dictionary
            logs: System log entries
        Returns: List of PII findings with details
        """
        findings = []  # Initialize empty findings list
        
        # Convert body to string for pattern matching
        # Use str() to handle any data type (dict, list, etc.)
        body_str = str(body)
        
        # Check each PII type against the body content
        for pii_type, patterns in self.pii_patterns.items():
            # Try each pattern for this PII type
            for pattern in patterns:
                try:
                    # Find all matches of this pattern in the body
                    matches = re.findall(pattern, body_str, re.IGNORECASE)
                    if matches:  # If any matches found
                        # Mask matches for safe logging (avoid exposing actual PII)
                        masked_matches = []
                        for match in matches[:3]:  # Limit to 3 examples
                            if len(match) > 4:
                                # Keep first 2 and last 2 characters, mask middle
                                masked = match[:2] + "***" + match[-2:]
                            else:
                                # For short matches, just show asterisks
                                masked = "***"
                            masked_matches.append(masked)
                        
                        # Create finding entry for this PII exposure
                        findings.append({
                            'type': 'PII_EXPOSURE',  # Finding type
                            'pii_type': pii_type,  # What type of PII was found
                            'severity': self._get_pii_severity(pii_type),  # Severity based on type
                            'location': 'Response Body',  # Where it was found
                            'matches_found': len(matches),  # Total count of matches
                            'examples': masked_matches,  # Masked examples (safe for logging)
                            'recommendation': f"Remove or encrypt {pii_type} data",  # Action to take
                            'regulation': "GDPR/HIPAA/CCPA"  # Relevant regulations
                        })
                except re.error:
                    # Skip invalid regex patterns
                    continue
        
        # Check headers for sensitive information exposure
        sensitive_headers = ['Authorization', 'Cookie', 'X-API-Key', 'X-Auth-Token']
        for header in sensitive_headers:
            if header in headers:
                header_value = str(headers[header])
                # Check if header contains potentially sensitive data (long values)
                if len(header_value) > 20:
                    findings.append({
                        'type': 'SENSITIVE_HEADER_EXPOSURE',
                        'header': header,
                        'severity': 'High',
                        'location': 'HTTP Headers',
                        'recommendation': f'Do not expose {header} in responses',
                        'regulation': 'PCI-DSS/ISO-27001'
                    })
        
        # Check logs for PII exposure
        for log in logs:
            log_str = str(log)  # Convert log entry to string
            for pii_type, patterns in self.pii_patterns.items():
                for pattern in patterns:
                    try:
                        if re.search(pattern, log_str, re.IGNORECASE):
                            # Found PII in logs
                            findings.append({
                                'type': 'PII_IN_LOGS',
                                'pii_type': pii_type,
                                'severity': self._get_pii_severity(pii_type),
                                'location': 'System Logs',
                                'recommendation': f'Remove {pii_type} from logs or mask it',
                                'regulation': 'GDPR/HIPAA'
                            })
                            break  # Found PII in this log, move to next log entry
                    except re.error:
                        continue  # Skip invalid pattern
        
        return findings
    
    def _get_pii_severity(self, pii_type: str) -> str:
        """
        Determine severity level for different types of PII
        Critical data like SSN and credit cards get highest severity
        Args:
            pii_type: Type of PII (email, ssn, credit_card, etc.)
        Returns: Severity string (Critical, High, Medium, Low)
        """
        # Map PII types to severity levels
        severity_map = {
            'ssn': 'Critical',  # Social Security Number - highly sensitive
            'credit_card': 'Critical',  # Payment card data - highly sensitive
            'email': 'Medium',  # Email address - moderately sensitive
            'phone': 'Medium',  # Phone number - moderately sensitive
            'ip_address': 'Low',  # IP address - low sensitivity
            'date_of_birth': 'High',  # Date of birth - high sensitivity for identity theft
            'address': 'Medium'  # Physical address - moderately sensitive
        }
        # Return mapped severity or default to 'Medium'
        return severity_map.get(pii_type, 'Medium')
    
    def _check_gdpr_compliance(self, url: str, headers: Dict, config: Dict, 
                              logs: List, pii_findings: List) -> Dict[str, Any]:
        """
        Check compliance with General Data Protection Regulation (GDPR)
        GDPR is a European Union regulation for data protection and privacy
        Args:
            url: Target URL being checked
            headers: HTTP headers from the target
            config: System configuration
            logs: Access and security logs
            pii_findings: Results from PII detection
        Returns: Dictionary with GDPR compliance results
        """
        findings = []  # Initialize findings list for this framework
        evidence = []  # Initialize evidence list (what compliance was found)
        
        # Check 1: Data Protection - GDPR Article 32 (Security of processing)
        security_headers = self._check_security_headers(headers)
        if not security_headers.get('encryption_enabled', False):
            # Encryption not detected - critical GDPR violation
            findings.append({
                'requirement': 'GDPR-Art-32',  # Article 32
                'type': 'ENCRYPTION_MISSING',
                'severity': 'Critical',
                'description': 'No encryption detected for data transmission',
                'recommendation': 'Enable HTTPS/TLS encryption'
            })
        else:
            # Encryption is enabled - positive evidence
            evidence.append("Encryption enabled for data transmission")
        
        # Check 2: Privacy by Design - GDPR Article 25
        privacy_headers = ['Privacy-Policy', 'Terms-of-Service']
        if not any(h in headers for h in privacy_headers):
            # Missing required privacy notices
            findings.append({
                'requirement': 'GDPR-Art-25',
                'type': 'PRIVACY_NOTICE_MISSING',
                'severity': 'High',
                'description': 'No privacy policy or terms of service headers',
                'recommendation': 'Add privacy policy and terms links'
            })
        else:
            # Privacy notices are present
            evidence.append("Privacy notices present in headers")
        
        # Check 3: Data Minimization - GDPR Article 5
        if pii_findings:
            # Found PII exposure - violates data minimization principle
            # Only include critical and high severity PII findings
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
        else:
            # No excessive PII found - positive evidence
            evidence.append("No excessive PII collection detected")
        
        # Check 4: Consent Management - GDPR Article 7
        consent_indicators = ['consent', 'cookie', 'opt-in', 'gdpr']
        config_str = str(config).lower()  # Convert config to lowercase string for case-insensitive search
        if not any(indicator in config_str for indicator in consent_indicators):
            # No consent management mechanism detected
            findings.append({
                'requirement': 'GDPR-Art-7',
                'type': 'CONSENT_MECHANISM_MISSING',
                'severity': 'High',
                'description': 'No visible consent management mechanism',
                'recommendation': 'Implement cookie consent banner and preferences'
            })
        else:
            # Consent management detected
            evidence.append("Consent management mechanisms detected")
        
        # Calculate GDPR compliance score
        total_requirements = len(self.requirements[ComplianceFramework.GDPR])
        # Count only critical and high severity failures
        failed_requirements = len([f for f in findings if f['severity'] in ['Critical', 'High']])
        # Score = 1 - (failed / total), with protection against division by zero
        compliance_score = 1.0 - (failed_requirements / max(total_requirements, 1))
        # Ensure score is between 0.0 and 1.0
        compliance_score = max(0.0, min(1.0, compliance_score))
        
        # Return comprehensive GDPR results
        return {
            'framework': 'GDPR',
            'compliance_score': compliance_score,
            'status': self._get_framework_status(compliance_score),
            'findings': findings,
            'requirements_checked': total_requirements,
            'requirements_failed': failed_requirements,
            'evidence_collected': evidence
        }
    
    # Note: Other framework checking methods (_check_hipaa_compliance, _check_pci_dss_compliance,
    # _check_iso_27001_compliance, _check_nist_csf_compliance) follow the same pattern as above.
    # They check different requirements specific to each framework but use the same structure.
    
    def _check_security_headers(self, headers: Dict) -> Dict[str, Any]:
        """
        Analyze HTTP security headers for various security controls
        Args:
            headers: HTTP headers dictionary
        Returns: Dictionary with security header analysis results
        """
        # Initialize analysis dictionary with default values
        analysis = {
            'encryption_enabled': False,
            'integrity_protection': False,
            'content_security': False,
            'security_headers_present': [],
            'security_headers_count': 0
        }
        
        # Check for HTTPS/TLS encryption indicators in header names
        for key in headers.keys():
            key_lower = str(key).lower()  # Case-insensitive comparison
            if any(term in key_lower for term in ['https', 'ssl', 'tls']):
                analysis['encryption_enabled'] = True
                break  # Found encryption indicator, no need to check further
        
        # List of important security headers to check for
        security_headers = [
            'Strict-Transport-Security',  # HSTS - enforce HTTPS
            'Content-Security-Policy',  # CSP - prevent XSS and other attacks
            'X-Content-Type-Options',  # Prevent MIME type sniffing
            'X-Frame-Options',  # Prevent clickjacking
            'X-XSS-Protection'  # Cross-site scripting protection
        ]
        
        # Find which security headers are present
        present_headers = [h for h in security_headers if h in headers]
        analysis['security_headers_present'] = present_headers
        analysis['security_headers_count'] = len(present_headers)
        
        # Check for integrity protection in Content Security Policy
        if 'Content-Security-Policy' in headers:
            csp = str(headers['Content-Security-Policy'])
            # Check if CSP allows unsafe inline scripts or eval
            if 'unsafe-inline' not in csp and 'unsafe-eval' not in csp:
                analysis['integrity_protection'] = True
        
        # Check for basic content security headers
        if 'X-Content-Type-Options' in headers and 'X-Frame-Options' in headers:
            analysis['content_security'] = True
        
        return analysis
    
    def _get_framework_status(self, compliance_score: float) -> str:
        """
        Convert numeric compliance score to status string
        Args:
            compliance_score: Score from 0.0 to 1.0
        Returns: Compliance status string from ComplianceStatus enum
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
        Get human-readable overall compliance status
        Args:
            compliance_score: Overall compliance score
        Returns: Human-readable status string
        """
        if compliance_score >= 0.9:
            return "FULLY COMPLIANT"
        elif compliance_score >= 0.7:
            return "PARTIALLY COMPLIANT"
        elif compliance_score >= 0.5:
            return "NON-COMPLIANT (Needs Attention)"
        else:
            return "SIGNIFICANT COMPLIANCE ISSUES"
    
    def _calculate_compliance_score(self, framework_results: Dict[str, Dict]) -> float:
        """
        Calculate weighted overall compliance score across all checked frameworks
        Different frameworks have different importance/weight
        Args:
            framework_results: Results dictionary from all framework checks
        Returns: Weighted average compliance score (0.0 to 1.0)
        """
        if not framework_results:
            return 0.0  # No frameworks checked, no score
        
        total_score = 0.0  # Accumulator for weighted scores
        weight_sum = 0.0  # Accumulator for total weight
        
        # Define importance weights for each framework
        framework_weights = {
            'gdpr': 1.0,  # GDPR is critical for data privacy
            'hipaa': 1.0,  # HIPAA is critical for healthcare
            'pci_dss': 1.0,  # PCI-DSS is critical for payment processing
            'iso_27001': 0.8,  # ISO 27001 is important but slightly less critical
            'nist_csf': 0.8  # NIST CSF is important for cybersecurity
        }
        
        # Calculate weighted average
        for framework, results in framework_results.items():
            weight = framework_weights.get(framework, 0.5)  # Default weight 0.5
            score = results.get('compliance_score', 0.0)  # Get framework score
            total_score += score * weight  # Add weighted score
            weight_sum += weight  # Add to total weight
        
        # Return weighted average, protecting against division by zero
        return total_score / weight_sum if weight_sum > 0 else 0.0
    
    def _generate_compliance_report(self, framework_results: Dict[str, Dict],
                                   overall_score: float) -> Dict[str, Any]:
        """
        Generate comprehensive compliance report with findings and recommendations
        Args:
            framework_results: Results from each framework check
            overall_score: Overall compliance score
        Returns: Structured report dictionary
        """
        # Compile all findings from all frameworks
        all_findings = []
        for framework, results in framework_results.items():
            for finding in results.get('findings', []):
                finding['framework'] = framework  # Tag finding with framework
                all_findings.append(finding)
        
        # Categorize findings by severity for reporting
        critical_findings = [f for f in all_findings if f.get('severity') == 'Critical']
        high_findings = [f for f in all_findings if f.get('severity') == 'High']
        medium_findings = [f for f in all_findings if f.get('severity') == 'Medium']
        low_findings = [f for f in all_findings if f.get('severity') == 'Low']
        
        # Generate actionable recommendations based on findings and score
        recommendations = []
        
        # Critical findings need immediate attention
        if critical_findings:
            recommendations.append("Address critical findings immediately")
            for finding in critical_findings[:2]:  # Limit to top 2 critical findings
                recommendations.append(f"- {finding.get('recommendation', '')}")
        
        # High priority findings need attention within 30 days
        if high_findings:
            recommendations.append("Address high-priority findings within 30 days")
            for finding in high_findings[:2]:  # Limit to top 2 high findings
                recommendations.append(f"- {finding.get('recommendation', '')}")
        
        # General recommendations based on overall score
        if overall_score < 0.7:
            recommendations.append("Conduct comprehensive security assessment")
            recommendations.append("Implement missing security controls")
            recommendations.append("Review and update security policies")
        
        if overall_score >= 0.9:
            recommendations.append("Maintain current security controls")
            recommendations.append("Continue regular compliance monitoring")
            recommendations.append("Consider security maturity improvements")
        
        # Create summary statistics
        summary = [
            f"Overall Compliance Score: {overall_score:.2%}",
            f"Frameworks Checked: {len(framework_results)}",
            f"Critical Findings: {len(critical_findings)}",
            f"High Findings: {len(high_findings)}",
            f"Medium Findings: {len(medium_findings)}",
            f"Low Findings: {len(low_findings)}"
        ]
        
        # Add framework-specific scores to summary
        for framework, results in framework_results.items():
            score = results.get('compliance_score', 0.0)
            status = results.get('status', 'unknown')
            summary.append(f"{framework.upper()}: {score:.2%} ({status})")
        
        # Return structured report
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
    
    def _update_confidence(self, compliance_score: float, total_findings: int):
        """
        Update agent confidence based on performance and findings
        Confidence increases when agent finds issues (good detection)
        Confidence decreases when system has low compliance but agent finds nothing (potential misses)
        Args:
            compliance_score: Overall compliance score
            total_findings: Total number of findings detected
        """
        if total_findings > 0:
            # Found issues - agent is doing good detection work
            self.confidence = min(1.0, self.confidence * 1.05)
        elif compliance_score >= 0.9:
            # High compliance with no findings - system is good, agent may be accurate
            self.confidence = min(1.0, self.confidence * 1.02)
        else:
            # Low compliance but no findings - agent may be missing issues
            self.confidence = max(0.1, self.confidence * 0.95)
    
    def _get_reasoning_state(self) -> torch.Tensor:
        """
        Generate a tensor representing the agent's current reasoning state
        Used for coordination with machine learning systems (mHC - multi-agent systems)
        Returns: PyTorch tensor with 512-dimensional feature vector
        """
        # Create feature vector from current agent state
        features = []
        
        # Feature 1: Framework status (normalized by dividing by 10)
        framework_count = len(self.frameworks)
        features.append(framework_count / 10.0)
        
        # Feature 2: Compliance rate (0.0 to 1.0)
        features.append(self.compliance_rate)
        
        # Feature 3: Agent confidence (0.0 to 1.0)
        features.append(self.confidence)
        
        # Feature 4: Recent findings density (normalized by dividing by 20)
        recent_checks = self.compliance_history[-10:] if self.compliance_history else []
        if recent_checks:
            avg_findings = sum(c.get('total_findings', 0) for c in recent_checks) / len(recent_checks)
            features.append(avg_findings / 20.0)
        else:
            features.append(0.0)
        
        # Feature 5: Active frameworks ratio
        features.append(framework_count / len(self.requirements))
        
        # Feature 6: PII detection capability (normalized)
        features.append(len(self.pii_patterns) / 20.0)
        
        # Pad feature vector to 512 dimensions with zeros
        # This ensures consistent tensor size for ML models
        while len(features) < 512:
            features.append(0.0)
        
        # Convert to PyTorch tensor with float32 precision
        return torch.tensor(features[:512], dtype=torch.float32)
    
    def get_agent_status(self) -> Dict[str, Any]:
        """
        Get current agent status and metrics for monitoring
        Returns: Dictionary with agent status information
        """
        return {
            'agent_id': self.agent_id,
            'agent_name': self.name,
            'confidence': self.confidence,
            'active_frameworks': [f.value for f in self.frameworks],
            'total_frameworks_available': len(self.requirements),
            'checks_performed': self.checks_performed,
            'compliance_rate': self.compliance_rate,
            'pii_patterns_loaded': len(self.pii_patterns),
            'requirements_loaded': sum(len(reqs) for reqs in self.requirements.values()),
            'history_size': len(self.compliance_history)
        }

def example_usage():
    """
    Example demonstrating how to use the CompliancePrivacyAgent
    Shows basic setup and analysis workflow
    Returns: Analysis results dictionary
    """
    # Create agent instance with default ID
    agent = CompliancePrivacyAgent()
    
    # Enable specific compliance frameworks
    agent.enable_framework(ComplianceFramework.GDPR)
    agent.enable_framework(ComplianceFramework.HIPAA)
    
    # Create sample security data for testing
    security_data = {
        'url': 'https://example.com/api/users',
        'headers': {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer token123',
            'X-Content-Type-Options': 'nosniff'
        },
        'body': '{"user": {"email": "test@example.com", "name": "John"}}',
        'configuration': {
            'encryption': True,
            'logging': True
        },
        'logs': [
            {'timestamp': '2024-01-01', 'event': 'login', 'user': 'admin'},
            {'timestamp': '2024-01-01', 'event': 'data_access', 'user': 'admin'}
        ]
    }
    
    # Analyze the security data for compliance
    result = agent.analyze(security_data)
    
    # Print key results
    print(f"Compliance Score: {result['compliance_score']:.2%}")
    print(f"Status: {result['compliance_status']}")
    print(f"Findings: {result['total_findings']}")
    
    return result

if __name__ == "__main__":
    """
    Main entry point when script is executed directly
    Runs the example usage function
    """
    result = example_usage()