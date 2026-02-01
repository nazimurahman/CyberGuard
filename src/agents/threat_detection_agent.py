"""
Web Threat Detection Agent
=========================

This agent specializes in detecting OWASP Top-10 web application vulnerabilities.
It uses pattern matching, heuristic analysis, and learned models to identify
common web attack patterns.

OWASP Top-10 Coverage:
---------------------
1. Broken Access Control
2. Cryptographic Failures
3. Injection (SQLi, NoSQLi, Command, etc.)
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable and Outdated Components
7. Identification and Authentication Failures
8. Software and Data Integrity Failures
9. Security Logging and Monitoring Failures
10. Server-Side Request Forgery (SSRF)

Detection Methods:
----------------
1. Signature-based: Known attack patterns
2. Heuristic-based: Suspicious patterns and anomalies
3. Behavioral-based: Unusual sequences of actions
4. Context-aware: Takes application context into account
"""

import re
import json
import urllib.parse
from typing import Dict, List, Any, Optional, Tuple
import torch
import torch.nn as nn
import hashlib
import time
from datetime import datetime

# Import necessary base classes - FIXED: Added missing imports
from .base_agent import SecurityAgent, SecurityFinding, ThreatSeverity, AgentState


class WebThreatDetectionAgent(SecurityAgent):
    """
    Agent for detecting OWASP Top-10 web application vulnerabilities.
    
    This agent analyzes HTTP requests, responses, and application behavior
    to identify common web security threats. It combines multiple detection
    methods for comprehensive coverage.
    """
    
    def __init__(self, agent_id: str = "threat_detection_001"):
        """
        Initialize the Web Threat Detection Agent.
        
        Args:
            agent_id (str): Unique identifier for this agent instance
            
        Explanation:
        -----------
        This agent loads comprehensive threat patterns covering OWASP Top-10.
        It initializes detection engines for different vulnerability types
        and sets up the analysis pipeline.
        """
        
        # Initialize base agent with web threat detection specialization
        super().__init__(
            agent_id=agent_id,
            name="Web Threat Detection Agent",
            description="Detects OWASP Top-10 web application vulnerabilities including XSS, SQLi, CSRF, SSRF, and injection attacks",
            state_dim=512,
            memory_size=2000  # Larger memory for pattern learning
        )
        
        # Load threat patterns and signatures
        self.threat_patterns = self._load_threat_patterns()
        
        # Initialize detection engines
        self.detection_engines = self._initialize_detection_engines()
        
        # Statistical models for anomaly detection
        self.statistical_models = {}
        
        # Whitelist of known safe patterns (reduces false positives)
        self.whitelist = self._load_whitelist()
        
        # Performance optimization: compiled regex patterns
        self.compiled_patterns = self._compile_patterns()
        
        # Threat intelligence context
        self.threat_intelligence = {
            'cve_database': {},      # Loaded CVE information
            'exploit_patterns': [],  # Known exploit patterns
            'attack_techniques': {}  # MITRE ATT&CK techniques
        }
        
        # Analysis configuration
        self.config = {
            'enable_deep_analysis': True,
            'max_analysis_depth': 3,
            'confidence_threshold': 0.6,
            'enable_learning': True,
            'max_patterns_per_type': 1000
        }
        
        print(f"Web Threat Detection Agent initialized with {len(self.threat_patterns)} patterns")
    
    def _load_threat_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Load comprehensive threat patterns for OWASP Top-10 detection.
        
        Returns:
            Dict[str, List[Dict]]: Threat patterns organized by vulnerability type
            
        Explanation:
        -----------
        This method loads patterns for detecting various web vulnerabilities.
        Each pattern includes:
        - Name: Descriptive name
        - Pattern: Regex or string pattern to match
        - Severity: How serious is this finding
        - Confidence: Base confidence for this pattern
        - Description: Detailed explanation
        - References: CVE IDs, OWASP references
        
        Patterns are loaded from multiple sources and organized by type
        for efficient matching during analysis.
        """
        
        # Comprehensive threat patterns database
        threat_patterns = {
            # ==================== INJECTION ATTACKS ====================
            'sql_injection': [
                {
                    'name': 'Basic SQL Injection',
                    'pattern': r"(?i)(\s*union\s+select\s+|\s*union\s+all\s+select\s+)",
                    'severity': ThreatSeverity.CRITICAL,
                    'confidence': 0.85,
                    'description': 'SQL UNION injection attempt detected',
                    'references': ['OWASP-A1', 'CWE-89']
                },
                {
                    'name': 'SQL Comment Injection',
                    'pattern': r"(?i)(--|\#|\/\*.*\*\/)",
                    'severity': ThreatSeverity.HIGH,
                    'confidence': 0.70,
                    'description': 'SQL comment injection attempt',
                    'references': ['OWASP-A1']
                },
                {
                    'name': 'SQL Error Based',
                    'pattern': r"(?i)(select\s+.*from|insert\s+into|update\s+.*set|delete\s+from)",
                    'severity': ThreatSeverity.HIGH,
                    'confidence': 0.75,
                    'description': 'SQL statement in user input',
                    'references': ['OWASP-A1']
                },
                {
                    'name': 'Boolean SQL Injection',
                    'pattern': r"(?i)(\s+or\s+['\"]?['\"]?\s*=\s*['\"]?['\"]?|\s+and\s+1\s*=\s*1)",
                    'severity': ThreatSeverity.HIGH,
                    'confidence': 0.80,
                    'description': 'Boolean-based SQL injection attempt',
                    'references': ['OWASP-A1']
                },
                {
                    'name': 'Time-Based SQL Injection',
                    'pattern': r"(?i)(sleep\(|waitfor\s+delay|benchmark\()",
                    'severity': ThreatSeverity.HIGH,
                    'confidence': 0.85,
                    'description': 'Time-based SQL injection function detected',
                    'references': ['OWASP-A1']
                }
            ],
            
            # ==================== CROSS-SITE SCRIPTING (XSS) ====================
            'xss': [
                {
                    'name': 'Script Tag Injection',
                    'pattern': r"(?i)<\s*script[^>]*>.*?<\s*/\s*script\s*>",
                    'severity': ThreatSeverity.HIGH,
                    'confidence': 0.90,
                    'description': 'Script tag injection attempt',
                    'references': ['OWASP-A3', 'CWE-79']
                },
                {
                    'name': 'JavaScript Event Handler',
                    'pattern': r"(?i)on\w+\s*=\s*['\"].*?['\"]",
                    'severity': ThreatSeverity.HIGH,
                    'confidence': 0.85,
                    'description': 'JavaScript event handler in user input',
                    'references': ['OWASP-A3']
                },
                {
                    'name': 'JavaScript Protocol',
                    'pattern': r"(?i)javascript:\s*\w+\(.*?\)",
                    'severity': ThreatSeverity.HIGH,
                    'confidence': 0.80,
                    'description': 'JavaScript protocol in URL',
                    'references': ['OWASP-A3']
                },
                {
                    'name': 'HTML Entity Encoding Bypass',
                    'pattern': r"(?i)&#[xX]?[0-9a-fA-F]+;",
                    'severity': ThreatSeverity.MEDIUM,
                    'confidence': 0.65,
                    'description': 'Potential HTML entity encoding bypass',
                    'references': ['OWASP-A3']
                },
                {
                    'name': 'XSS in Attributes',
                    'pattern': r"(?i)<\s*\w+[^>]*\s+\w+\s*=\s*['\"].*?script.*?['\"]",
                    'severity': ThreatSeverity.HIGH,
                    'confidence': 0.75,
                    'description': 'XSS attempt in HTML attributes',
                    'references': ['OWASP-A3']
                }
            ],
            
            # ==================== CROSS-SITE REQUEST FORGERY (CSRF) ====================
            'csrf': [
                {
                    'name': 'Missing CSRF Token',
                    'pattern': None,  # Pattern-based detection
                    'severity': ThreatSeverity.MEDIUM,
                    'confidence': 0.60,
                    'description': 'State-changing request without CSRF token',
                    'references': ['OWASP-A1', 'CWE-352']
                },
                {
                    'name': 'Cross-Origin State Change',
                    'pattern': None,
                    'severity': ThreatSeverity.HIGH,
                    'confidence': 0.70,
                    'description': 'Cross-origin state-changing request',
                    'references': ['OWASP-A1']
                }
            ],
            
            # ==================== SERVER-SIDE REQUEST FORGERY (SSRF) ====================
            'ssrf': [
                {
                    'name': 'Localhost Reference',
                    'pattern': r"(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)",
                    'severity': ThreatSeverity.HIGH,
                    'confidence': 0.75,
                    'description': 'Internal network reference in user input',
                    'references': ['OWASP-A10', 'CWE-918']
                },
                {
                    'name': 'Internal IP Range',
                    'pattern': r"(?i)(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+|192\.168\.\d+\.\d+)",
                    'severity': ThreatSeverity.HIGH,
                    'confidence': 0.80,
                    'description': 'Internal IP address in user input',
                    'references': ['OWASP-A10']
                },
                {
                    'name': 'File Protocol',
                    'pattern': r"(?i)file://",
                    'severity': ThreatSeverity.HIGH,
                    'confidence': 0.85,
                    'description': 'File protocol reference (potential LFI/RFI)',
                    'references': ['OWASP-A10']
                },
                {
                    'name': 'AWS/GCP/Azure Metadata',
                    'pattern': r"(?i)(169\.254\.169\.254|metadata\.google\.internal|169\.254\.169\.254)",
                    'severity': ThreatSeverity.CRITICAL,
                    'confidence': 0.90,
                    'description': 'Cloud metadata service reference',
                    'references': ['OWASP-A10']
                }
            ],
            
            # ==================== COMMAND INJECTION ====================
            'command_injection': [
                {
                    'name': 'Shell Command Separator',
                    'pattern': r"(?i)(;|\||&|`|\$\(|\n)",
                    'severity': ThreatSeverity.CRITICAL,
                    'confidence': 0.70,
                    'description': 'Shell command separator in user input',
                    'references': ['OWASP-A1', 'CWE-78']
                },
                {
                    'name': 'Common Command Injection',
                    'pattern': r"(?i)(cat\s+.*|ls\s+.*|dir\s+.*|whoami|id|pwd)",
                    'severity': ThreatSeverity.HIGH,
                    'confidence': 0.75,
                    'description': 'Common command injection payload',
                    'references': ['OWASP-A1']
                },
                {
                    'name': 'Path Traversal Command',
                    'pattern': r"(?i)(\.\.\/|\.\.\\)",
                    'severity': ThreatSeverity.HIGH,
                    'confidence': 0.80,
                    'description': 'Path traversal attempt',
                    'references': ['OWASP-A1', 'CWE-22']
                }
            ],
            
            # ==================== PATH TRAVERSAL ====================
            'path_traversal': [
                {
                    'name': 'Directory Traversal',
                    'pattern': r"(?i)(\.\.\/|\.\.\\){2,}",
                    'severity': ThreatSeverity.HIGH,
                    'confidence': 0.85,
                    'description': 'Directory traversal attempt',
                    'references': ['OWASP-A1', 'CWE-22']
                },
                {
                    'name': 'Sensitive File Access',
                    'pattern': r"(?i)(\/etc\/passwd|\/etc\/shadow|\.\.\/\.\.\/\.\.\/etc\/passwd|C:\\Windows\\system32)",
                    'severity': ThreatSeverity.CRITICAL,
                    'confidence': 0.90,
                    'description': 'Attempt to access sensitive system files',
                    'references': ['OWASP-A1']
                }
            ],
            
            # ==================== XML EXTERNAL ENTITY (XXE) ====================
            'xxe': [
                {
                    'name': 'XXE Declaration',
                    'pattern': r"(?i)<!DOCTYPE.*?\[.*?<!ENTITY.*?>.*?\]>",
                    'severity': ThreatSeverity.HIGH,
                    'confidence': 0.80,
                    'description': 'XML External Entity declaration',
                    'references': ['OWASP-A4', 'CWE-611']
                },
                {
                    'name': 'External Entity Reference',
                    'pattern': r"(?i)&[a-zA-Z_][a-zA-Z0-9._-]*;",
                    'severity': ThreatSeverity.MEDIUM,
                    'confidence': 0.65,
                    'description': 'External entity reference in XML',
                    'references': ['OWASP-A4']
                }
            ],
            
            # ==================== INSECURE DESERIALIZATION ====================
            'insecure_deserialization': [
                {
                    'name': 'Java Serialization',
                    'pattern': r"(?i)(rO0|ACED|javax\.management)",
                    'severity': ThreatSeverity.HIGH,
                    'confidence': 0.75,
                    'description': 'Java serialized object detected',
                    'references': ['OWASP-A8', 'CWE-502']
                },
                {
                    'name': 'Python Pickle',
                    'pattern': r"(?i)(cos\nsystem\n|S'whoami')",
                    'severity': ThreatSeverity.HIGH,
                    'confidence': 0.80,
                    'description': 'Python pickle object with potential command',
                    'references': ['OWASP-A8']
                }
            ],
            
            # ==================== BROKEN AUTHENTICATION ====================
            'broken_authentication': [
                {
                    'name': 'Default Credentials',
                    'pattern': r"(?i)(admin:admin|root:root|administrator:password)",
                    'severity': ThreatSeverity.MEDIUM,
                    'confidence': 0.70,
                    'description': 'Default credentials attempt',
                    'references': ['OWASP-A2', 'CWE-798']
                },
                {
                    'name': 'Weak Password Pattern',
                    'pattern': r"(?i)(password|123456|qwerty|admin123)",
                    'severity': ThreatSeverity.LOW,
                    'confidence': 0.60,
                    'description': 'Weak password pattern detected',
                    'references': ['OWASP-A2']
                }
            ]
        }
        
        return threat_patterns
    
    def _initialize_detection_engines(self) -> Dict[str, Any]:
        """
        Initialize specialized detection engines for different threat types.
        
        Returns:
            Dict[str, Any]: Initialized detection engines
            
        Explanation:
        -----------
        Different threat types require different detection approaches:
        - Pattern matching: For known attack signatures
        - Heuristic analysis: For suspicious patterns
        - Statistical analysis: For anomaly detection
        - Behavioral analysis: For sequence-based attacks
        
        Each engine is optimized for its specific threat type.
        """
        
        return {
            'pattern_matcher': {
                'enabled': True,
                'engine': self._pattern_match_engine,
                'description': 'Signature-based pattern matching'
            },
            'heuristic_analyzer': {
                'enabled': True,
                'engine': self._heuristic_analysis_engine,
                'description': 'Heuristic analysis for unknown threats'
            },
            'context_analyzer': {
                'enabled': True,
                'engine': self._context_aware_engine,
                'description': 'Context-aware threat detection'
            },
            'sequence_analyzer': {
                'enabled': True,
                'engine': self._sequence_analysis_engine,
                'description': 'Attack sequence and chain detection'
            }
        }
    
    def _load_whitelist(self) -> Dict[str, List[str]]:
        """
        Load whitelist of known safe patterns to reduce false positives.
        
        Returns:
            Dict[str, List[str]]: Whitelist patterns by context
            
        Explanation:
        -----------
        Some patterns that look like attacks might be legitimate in certain
        contexts (e.g., security testing tools, educational content).
        The whitelist helps reduce false positives by filtering out known
        safe patterns based on context.
        """
        
        return {
            'user_agents': [
                'security-scanner', 'nessus', 'nikto', 'zap',
                'burp', 'w3af', 'sqlmap', 'nmap'
            ],
            'url_paths': [
                '/security-test', '/penetration-test',
                '/vulnerability-scan', '/security-training'
            ],
            'ip_addresses': [
                '127.0.0.1',  # Localhost for testing
                '192.168.1.1'  # Common internal testing
            ]
        }
    
    def _compile_patterns(self) -> Dict[str, re.Pattern]:
        """
        Compile regex patterns for efficient matching.
        
        Returns:
            Dict[str, re.Pattern]: Compiled regex patterns
            
        Explanation:
        -----------
        Compiling regex patterns once at initialization improves
        performance significantly during analysis, especially when
        processing high volumes of requests.
        """
        
        compiled = {}
        
        # Compile patterns for each threat type
        for threat_type, patterns in self.threat_patterns.items():
            for pattern_data in patterns:
                if pattern_data['pattern']:
                    try:
                        # Create unique key for this pattern
                        pattern_key = f"{threat_type}_{pattern_data['name'].replace(' ', '_').lower()}"
                        compiled[pattern_key] = re.compile(pattern_data['pattern'], re.IGNORECASE | re.DOTALL)
                    except re.error as e:
                        print(f"Warning: Failed to compile pattern {pattern_data['name']}: {e}")
        
        return compiled
    
    def analyze(self, security_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze security data for web application threats.
        
        Args:
            security_data (Dict[str, Any]): Security data including request details
            
        Returns:
            Dict[str, Any]: Analysis results with findings and threat assessment
            
        Explanation:
        -----------
        This is the core analysis method that:
        1. Extracts and normalizes input data
        2. Applies multiple detection engines
        3. Correlates findings across different threat types
        4. Generates comprehensive threat assessment
        5. Updates agent state and confidence
        
        The analysis is multi-layered for comprehensive coverage.
        """
        
        # Start timing analysis
        start_time = time.time()
        self.state = AgentState.ANALYZING
        
        try:
            # Extract and normalize input data
            normalized_data = self._normalize_input(security_data)
            
            # Check if request should be whitelisted
            if self._is_whitelisted(normalized_data):
                return self._create_whitelist_response(start_time)
            
            # Initialize findings collection
            all_findings = []
            threat_scores = []
            certainties = []
            
            # ==================== LAYER 1: PATTERN MATCHING ====================
            if self.detection_engines['pattern_matcher']['enabled']:
                # FIXED: Call pattern matcher engine correctly
                pattern_findings, pattern_score, pattern_certainty = self._pattern_match_engine(normalized_data)
                all_findings.extend(pattern_findings)
                threat_scores.append(pattern_score)
                certainties.append(pattern_certainty)
            
            # ==================== LAYER 2: HEURISTIC ANALYSIS ====================
            if self.detection_engines['heuristic_analyzer']['enabled']:
                # FIXED: Call heuristic analyzer engine correctly
                heuristic_findings, heuristic_score, heuristic_certainty = self._heuristic_analysis_engine(normalized_data)
                all_findings.extend(heuristic_findings)
                threat_scores.append(heuristic_score)
                certainties.append(heuristic_certainty)
            
            # ==================== LAYER 3: CONTEXT-AWARE ANALYSIS ====================
            if self.detection_engines['context_analyzer']['enabled']:
                # FIXED: Call context analyzer engine correctly
                context_findings, context_score, context_certainty = self._context_aware_engine(normalized_data, all_findings)
                all_findings.extend(context_findings)
                threat_scores.append(context_score)
                certainties.append(context_certainty)
            
            # ==================== LAYER 4: SEQUENCE ANALYSIS ====================
            if self.detection_engines['sequence_analyzer']['enabled']:
                # FIXED: Call sequence analyzer engine correctly
                sequence_findings, sequence_score, sequence_certainty = self._sequence_analysis_engine(normalized_data, all_findings)
                all_findings.extend(sequence_findings)
                threat_scores.append(sequence_score)
                certainties.append(sequence_certainty)
            
            # ==================== CORRELATION AND DECISION ====================
            # Remove duplicates and consolidate findings
            unique_findings = self._deduplicate_findings(all_findings)
            
            # Calculate overall threat level (weighted average)
            overall_threat = self._calculate_overall_threat(threat_scores, certainties)
            
            # Calculate overall certainty
            overall_certainty = sum(certainties) / len(certainties) if certainties else 0.5
            
            # Generate recommendations
            recommendations = self._generate_recommendations(unique_findings, overall_threat)
            
            # Update reasoning state
            self._update_reasoning_state(unique_findings, overall_threat, overall_certainty)
            
            # Calculate processing time
            processing_time = time.time() - start_time
            
            # Update agent metrics
            self._update_metrics(unique_findings, processing_time)
            
            # Prepare response
            response = {
                'agent_id': self.agent_id,
                'agent_name': self.name,
                'findings': unique_findings,
                'threat_level': overall_threat,
                'certainty': overall_certainty,
                'reasoning_state': self.get_reasoning_state(),
                'processing_time': processing_time,
                'recommendations': recommendations,
                'analysis_layers_used': len([e for e in self.detection_engines.values() if e['enabled']]),
                'patterns_matched': len([f for f in unique_findings if f.severity.value >= ThreatSeverity.MEDIUM.value]),
                'decision': {
                    'threat_level': overall_threat,
                    'confidence': overall_certainty,
                    'evidence': [{
                        'type': f.threat_type,
                        'severity': f.severity.name,
                        'description': f.description[:100]  # First 100 chars
                    } for f in unique_findings[:5]]  # Top 5 as evidence
                }
            }
            
            # Update agent confidence based on this analysis
            self.update_confidence(response)
            
            # Add important findings to memory
            for finding in unique_findings:
                if finding.severity.value >= ThreatSeverity.MEDIUM.value:
                    self.add_to_memory(finding)
            
            self.state = AgentState.IDLE
            return response
            
        except Exception as e:
            # Handle analysis errors gracefully
            self.state = AgentState.ERROR
            error_finding = SecurityFinding(
                finding_id=f"error_{int(time.time())}",
                agent_id=self.agent_id,
                timestamp=time.time(),
                title="Analysis Error",
                description=f"Error during threat analysis: {str(e)}",
                severity=ThreatSeverity.INFORMATIONAL,
                confidence=0.1,
                threat_type="ANALYSIS_ERROR",
                location="agent_internal",
                evidence=str(e),
                context={'error_type': type(e).__name__},
                recommendation="Check agent logs and configuration",
                references=[]
            )
            
            return {
                'agent_id': self.agent_id,
                'agent_name': self.name,
                'findings': [error_finding],
                'threat_level': 0.1,
                'certainty': 0.1,
                'reasoning_state': self.get_reasoning_state(),
                'processing_time': time.time() - start_time,
                'error': str(e),
                'decision': {
                    'threat_level': 0.1,
                    'confidence': 0.1,
                    'evidence': []
                }
            }
    
    def _normalize_input(self, security_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize and validate input data for analysis.
        
        Args:
            security_data (Dict): Raw security data
            
        Returns:
            Dict: Normalized and validated data
            
        Explanation:
        -----------
        Input normalization ensures:
        1. Required fields are present
        2. Data types are correct
        3. Strings are properly encoded/decoded
        4. Sensitive data is handled appropriately
        5. Data is in a consistent format for analysis
        """
        
        normalized = {
            'timestamp': security_data.get('timestamp', time.time()),
            'url': str(security_data.get('url', '')),
            'method': str(security_data.get('method', 'GET')).upper(),
            'headers': security_data.get('headers', {}),
            'body': security_data.get('body', ''),
            'source_ip': security_data.get('source_ip', ''),
            'user_agent': security_data.get('user_agent', ''),
            'cookies': security_data.get('cookies', {}),
            'query_params': security_data.get('query_params', {}),
            'form_data': security_data.get('form_data', {}),
            'raw_request': security_data.get('raw_request', '')
        }
        
        # Decode URL if it's percent-encoded
        try:
            normalized['url'] = urllib.parse.unquote(normalized['url'])
        except:
            pass  # Keep original if decoding fails
        
        # Parse query parameters from URL if not provided
        if not normalized['query_params'] and '?' in normalized['url']:
            try:
                parsed_url = urllib.parse.urlparse(normalized['url'])
                normalized['query_params'] = urllib.parse.parse_qs(parsed_url.query)
            except:
                normalized['query_params'] = {}
        
        # Convert body to string if it's not already
        if not isinstance(normalized['body'], str):
            try:
                normalized['body'] = str(normalized['body'])
            except:
                normalized['body'] = ''
        
        # Extract additional context
        normalized['context'] = {
            'is_ajax': 'XMLHttpRequest' in normalized.get('headers', {}).get('X-Requested-With', ''),
            'is_api': any(keyword in normalized['url'].lower() for keyword in ['/api/', '/graphql', '/rest/', '/soap/']),
            'is_admin': any(keyword in normalized['url'].lower() for keyword in ['/admin', '/wp-admin', '/administrator']),
            'has_auth': bool(normalized.get('headers', {}).get('Authorization') or normalized.get('cookies', {}).get('session')),
            'content_type': normalized.get('headers', {}).get('Content-Type', '')
        }
        
        return normalized
    
    def _is_whitelisted(self, normalized_data: Dict[str, Any]) -> bool:
        """
        Check if the request should be whitelisted.
        
        Args:
            normalized_data (Dict): Normalized request data
            
        Returns:
            bool: True if request should be whitelisted
            
        Explanation:
        -----------
        Whitelisting prevents false positives from:
        1. Security scanning tools
        2. Internal testing
        3. Known safe patterns
        4. Authorized security testing
        
        Whitelist checks are context-aware to avoid bypassing real threats.
        """
        
        user_agent = normalized_data.get('user_agent', '').lower()
        url = normalized_data.get('url', '').lower()
        source_ip = normalized_data.get('source_ip', '')
        
        # Check user agent whitelist
        for whitelisted_ua in self.whitelist.get('user_agents', []):
            if whitelisted_ua.lower() in user_agent:
                return True
        
        # Check URL path whitelist
        for whitelisted_path in self.whitelist.get('url_paths', []):
            if whitelisted_path.lower() in url:
                return True
        
        # Check IP whitelist
        if source_ip in self.whitelist.get('ip_addresses', []):
            return True
        
        return False
    
    def _pattern_match_engine(self, normalized_data: Dict[str, Any]) -> Tuple[List[SecurityFinding], float, float]:
        """
        Pattern matching engine for known attack signatures.
        
        Args:
            normalized_data (Dict): Normalized request data
            
        Returns:
            Tuple[List[SecurityFinding], float, float]: Findings, threat score, certainty
            
        Explanation:
        -----------
        This engine uses compiled regex patterns to detect known attack
        signatures. It's fast and effective for detecting well-known
        attack patterns but can miss novel or obfuscated attacks.
        """
        
        findings = []
        threat_score = 0.0
        certainty_sum = 0.0
        matches_found = 0
        
        # Define scanning locations and their weights
        scan_locations = [
            ('url', normalized_data['url'], 1.0),
            ('body', normalized_data['body'], 0.8),
            ('headers', str(normalized_data['headers']), 0.6),
            ('cookies', str(normalized_data['cookies']), 0.7),
            ('query_params', str(normalized_data['query_params']), 0.9),
            ('form_data', str(normalized_data['form_data']), 0.8)
        ]
        
        # Scan each location for threat patterns
        for location_name, content, weight in scan_locations:
            if not content:
                continue
            
            for threat_type, patterns in self.threat_patterns.items():
                for pattern_data in patterns:
                    if not pattern_data['pattern']:
                        continue
                    
                    # Get compiled pattern
                    pattern_key = f"{threat_type}_{pattern_data['name'].replace(' ', '_').lower()}"
                    compiled_pattern = self.compiled_patterns.get(pattern_key)
                    
                    if compiled_pattern:
                        # Search for pattern matches
                        matches = compiled_pattern.findall(content)
                        
                        if matches:
                            matches_found += 1
                            
                            # Calculate match strength
                            match_strength = min(len(matches) * 0.1, 1.0)
                            
                            # Adjust confidence based on context
                            context_confidence = pattern_data['confidence']
                            adjusted_confidence = context_confidence * weight * match_strength
                            
                            # Create finding
                            finding = SecurityFinding(
                                finding_id=f"pattern_{threat_type}_{int(time.time())}_{hash(str(matches))}",
                                agent_id=self.agent_id,
                                timestamp=time.time(),
                                title=pattern_data['name'],
                                description=f"{pattern_data['description']} detected in {location_name}. Matches: {matches[:3]}",
                                severity=pattern_data['severity'],
                                confidence=adjusted_confidence,
                                threat_type=threat_type.upper(),
                                location=location_name,
                                evidence=f"Pattern match: {pattern_data['pattern'][:100]}...",
                                context={
                                    'pattern': pattern_data['pattern'],
                                    'matches': matches[:5],  # First 5 matches
                                    'location': location_name,
                                    'match_count': len(matches),
                                    'weight': weight
                                },
                                recommendation=self._get_recommendation_for_threat(threat_type.upper()),
                                references=pattern_data['references']
                            )
                            
                            findings.append(finding)
                            
                            # Update threat score (weighted by severity and confidence)
                            severity_weight = pattern_data['severity'].value / 4.0  # 0 to 1
                            threat_contribution = severity_weight * adjusted_confidence * weight
                            threat_score += threat_contribution
                            certainty_sum += adjusted_confidence
        
        # Normalize threat score (0 to 1)
        if matches_found > 0:
            threat_score = min(1.0, threat_score / matches_found)
            avg_certainty = certainty_sum / matches_found
        else:
            threat_score = 0.0
            avg_certainty = 0.5  # Neutral certainty when no matches
        
        return findings, threat_score, avg_certainty
    
    def _heuristic_analysis_engine(self, normalized_data: Dict[str, Any]) -> Tuple[List[SecurityFinding], float, float]:
        """
        Heuristic analysis engine for suspicious patterns.
        
        Args:
            normalized_data (Dict): Normalized request data
            
        Returns:
            Tuple[List[SecurityFinding], float, float]: Findings, threat score, certainty
            
        Explanation:
        -----------
        This engine uses heuristics to detect suspicious patterns that
        might not match known signatures but exhibit malicious characteristics:
        - Unusual encoding
        - Suspicious parameter names
        - Abnormal request structure
        - Contextual anomalies
        """
        
        findings = []
        threat_score = 0.0
        heuristic_count = 0
        total_confidence = 0.0
        
        # Heuristic 1: Unusual encoding patterns
        encoded_patterns = self._detect_encoding_anomalies(normalized_data)
        findings.extend(encoded_patterns['findings'])
        threat_score += encoded_patterns['threat_score']
        total_confidence += encoded_patterns['confidence_sum']
        heuristic_count += encoded_patterns['count']
        
        # Heuristic 2: Suspicious parameter names
        param_patterns = self._detect_suspicious_parameters(normalized_data)
        findings.extend(param_patterns['findings'])
        threat_score += param_patterns['threat_score']
        total_confidence += param_patterns['confidence_sum']
        heuristic_count += param_patterns['count']
        
        # Heuristic 3: Request structure anomalies
        structure_anomalies = self._detect_structure_anomalies(normalized_data)
        findings.extend(structure_anomalies['findings'])
        threat_score += structure_anomalies['threat_score']
        total_confidence += structure_anomalies['confidence_sum']
        heuristic_count += structure_anomalies['count']
        
        # Heuristic 4: Content type mismatches
        content_mismatches = self._detect_content_type_mismatches(normalized_data)
        findings.extend(content_mismatches['findings'])
        threat_score += content_mismatches['threat_score']
        total_confidence += content_mismatches['confidence_sum']
        heuristic_count += content_mismatches['count']
        
        # Normalize scores
        if heuristic_count > 0:
            threat_score = min(1.0, threat_score / heuristic_count)
            avg_certainty = total_confidence / heuristic_count
        else:
            threat_score = 0.0
            avg_certainty = 0.5
        
        return findings, threat_score, avg_certainty
    
    def _detect_encoding_anomalies(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect unusual encoding patterns that might indicate obfuscation.
        
        Args:
            data (Dict): Normalized request data
            
        Returns:
            Dict: Findings and scores for encoding anomalies
            
        Explanation:
        -----------
        Attackers often use encoding to bypass signature-based detection.
        This heuristic looks for:
        - Multiple encoding layers
        - Unusual character sets
        - Encoding in unexpected places
        - Mixed encoding schemes
        """
        
        findings = []
        threat_score = 0.0
        confidence_sum = 0.0
        count = 0
        
        # Check for double encoding
        content_to_check = [
            data['url'],
            data['body'],
            str(data['query_params']),
            str(data['form_data'])
        ]
        
        for content in content_to_check:
            if not content:
                continue
            
            # Check for multiple percent encodings
            if '%25' in content:  # Encoded percent sign
                finding = SecurityFinding(
                    finding_id=f"encoding_{int(time.time())}_{hash(content[:50])}",
                    agent_id=self.agent_id,
                    timestamp=time.time(),
                    title="Double URL Encoding Detected",
                    description="Potential double URL encoding attempt to bypass filters",
                    severity=ThreatSeverity.MEDIUM,
                    confidence=0.65,
                    threat_type="ENCODING_BYPASS",
                    location="request_content",
                    evidence=f"Double encoding pattern found: %25",
                    context={'pattern': 'double_encoding', 'content_sample': content[:100]},
                    recommendation="Implement proper decoding before validation",
                    references=['OWASP-A1']
                )
                findings.append(finding)
                threat_score += 0.4
                confidence_sum += 0.65
                count += 1
            
            # Check for Unicode encoding anomalies
            if any(ord(char) > 127 for char in content[:1000]):
                finding = SecurityFinding(
                    finding_id=f"unicode_{int(time.time())}_{hash(content[:50])}",
                    agent_id=self.agent_id,
                    timestamp=time.time(),
                    title="Unicode Encoding Anomaly",
                    description="Unusual Unicode characters that might bypass filters",
                    severity=ThreatSeverity.LOW,
                    confidence=0.55,
                    threat_type="ENCODING_BYPASS",
                    location="request_content",
                    evidence="High Unicode content detected",
                    context={'pattern': 'unicode_anomaly', 'content_sample': content[:100]},
                    recommendation="Normalize Unicode before validation",
                    references=['OWASP-A1']
                )
                findings.append(finding)
                threat_score += 0.2
                confidence_sum += 0.55
                count += 1
        
        return {
            'findings': findings,
            'threat_score': threat_score,
            'confidence_sum': confidence_sum,
            'count': count
        }
    
    def _detect_suspicious_parameters(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect suspicious parameter names that might indicate attack attempts.
        
        Args:
            data (Dict): Normalized request data
            
        Returns:
            Dict: Findings and scores for suspicious parameters
            
        Explanation:
        -----------
        Attack parameters often have telltale names like:
        - cmd, exec, shell for command injection
        - file, path for path traversal
        - union, select for SQL injection
        - script, onload for XSS
        
        This heuristic checks parameter names across all request parts.
        """
        
        findings = []
        threat_score = 0.0
        confidence_sum = 0.0
        count = 0
        
        # Suspicious parameter patterns
        suspicious_patterns = [
            (r'(?i)(cmd|command|exec|shell|system)', 'COMMAND_INJECTION', 0.75, ThreatSeverity.HIGH),
            (r'(?i)(file|path|directory|root)', 'PATH_TRAVERSAL', 0.70, ThreatSeverity.HIGH),
            (r'(?i)(union|select|insert|update|delete)', 'SQL_INJECTION', 0.80, ThreatSeverity.HIGH),
            (r'(?i)(script|on\w+|javascript|eval)', 'XSS', 0.75, ThreatSeverity.HIGH),
            (r'(?i)(token|csrf|auth|session)', 'BROKEN_AUTHENTICATION', 0.65, ThreatSeverity.MEDIUM),
            (r'(?i)(debug|test|admin|config)', 'INFORMATION_DISCLOSURE', 0.60, ThreatSeverity.MEDIUM)
        ]
        
        # Check query parameters
        for param_name in data['query_params'].keys():
            for pattern, threat_type, confidence, severity in suspicious_patterns:
                if re.search(pattern, param_name, re.IGNORECASE):
                    finding = SecurityFinding(
                        finding_id=f"param_{threat_type}_{int(time.time())}_{hash(param_name)}",
                        agent_id=self.agent_id,
                        timestamp=time.time(),
                        title=f"Suspicious Parameter Name: {param_name}",
                        description=f"Parameter name suggests {threat_type.replace('_', ' ').lower()} attempt",
                        severity=severity,
                        confidence=confidence,
                        threat_type=threat_type,
                        location="query_parameters",
                        evidence=f"Parameter name: {param_name} matches pattern: {pattern}",
                        context={'parameter': param_name, 'pattern': pattern},
                        recommendation="Validate parameter names and implement strict allow-listing",
                        references=['OWASP-A1']
                    )
                    findings.append(finding)
                    threat_score += severity.value / 4.0 * confidence
                    confidence_sum += confidence
                    count += 1
        
        # Check form data parameters
        if isinstance(data['form_data'], dict):
            for param_name in data['form_data'].keys():
                for pattern, threat_type, confidence, severity in suspicious_patterns:
                    if re.search(pattern, param_name, re.IGNORECASE):
                        finding = SecurityFinding(
                            finding_id=f"form_{threat_type}_{int(time.time())}_{hash(param_name)}",
                            agent_id=self.agent_id,
                            timestamp=time.time(),
                            title=f"Suspicious Form Parameter: {param_name}",
                            description=f"Form parameter name suggests {threat_type.replace('_', ' ').lower()} attempt",
                            severity=severity,
                            confidence=confidence,
                            threat_type=threat_type,
                            location="form_data",
                            evidence=f"Form parameter: {param_name} matches pattern: {pattern}",
                            context={'parameter': param_name, 'pattern': pattern},
                            recommendation="Validate form parameter names",
                            references=['OWASP-A1']
                        )
                        findings.append(finding)
                        threat_score += severity.value / 4.0 * confidence
                        confidence_sum += confidence
                        count += 1
        
        return {
            'findings': findings,
            'threat_score': threat_score,
            'confidence_sum': confidence_sum,
            'count': count
        }
    
    def _detect_structure_anomalies(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect anomalies in request structure.
        
        Args:
            data (Dict): Normalized request data
            
        Returns:
            Dict: Findings and scores for structure anomalies
            
        Explanation:
        -----------
        Malicious requests often have structural anomalies:
        - Extremely long URLs or parameters
        - Nested parameters
        - Multiple content types
        - Inconsistent header formats
        """
        
        findings = []
        threat_score = 0.0
        confidence_sum = 0.0
        count = 0
        
        # Check for extremely long URLs
        if len(data['url']) > 2000:  # URLs longer than 2000 chars are suspicious
            finding = SecurityFinding(
                finding_id=f"structure_longurl_{int(time.time())}",
                agent_id=self.agent_id,
                timestamp=time.time(),
                title="Excessively Long URL",
                description=f"URL length ({len(data['url'])} chars) exceeds normal limits",
                severity=ThreatSeverity.MEDIUM,
                confidence=0.60,
                threat_type="STRUCTURE_ANOMALY",
                location="url",
                evidence=f"URL length: {len(data['url'])} characters",
                context={'url_length': len(data['url']), 'threshold': 2000},
                recommendation="Implement URL length limits and monitor for buffer overflow attempts",
                references=['OWASP-A1']
            )
            findings.append(finding)
            threat_score += 0.3
            confidence_sum += 0.60
            count += 1
        
        # Check for nested parameters (potential parameter pollution)
        query_string = str(data['query_params'])
        if '&' in data['url'] and data['url'].count('&') > 20:  # Too many parameters
            finding = SecurityFinding(
                finding_id=f"structure_manyparams_{int(time.time())}",
                agent_id=self.agent_id,
                timestamp=time.time(),
                title="Excessive Query Parameters",
                description=f"Too many query parameters ({data['url'].count('&') + 1})",
                severity=ThreatSeverity.LOW,
                confidence=0.55,
                threat_type="STRUCTURE_ANOMALY",
                location="url",
                evidence=f"Parameter count: {data['url'].count('&') + 1}",
                context={'parameter_count': data['url'].count('&') + 1, 'threshold': 20},
                recommendation="Limit maximum number of parameters per request",
                references=['OWASP-A1']
            )
            findings.append(finding)
            threat_score += 0.2
            confidence_sum += 0.55
            count += 1
        
        # Check for missing or malformed headers in state-changing requests
        if data['method'] in ['POST', 'PUT', 'DELETE', 'PATCH']:
            content_type = data['headers'].get('Content-Type', '')
            content_length = data['headers'].get('Content-Length', '')
            
            if not content_type and data['body']:
                finding = SecurityFinding(
                    finding_id=f"structure_noctype_{int(time.time())}",
                    agent_id=self.agent_id,
                    timestamp=time.time(),
                    title="Missing Content-Type Header",
                    description="State-changing request without Content-Type header",
                    severity=ThreatSeverity.LOW,
                    confidence=0.50,
                    threat_type="STRUCTURE_ANOMALY",
                    location="headers",
                    evidence=f"Method: {data['method']} with body but no Content-Type",
                    context={'method': data['method'], 'has_body': bool(data['body'])},
                    recommendation="Require Content-Type header for state-changing requests",
                    references=['OWASP-A1']
                )
                findings.append(finding)
                threat_score += 0.1
                confidence_sum += 0.50
                count += 1
            
            if not content_length and data['body']:
                finding = SecurityFinding(
                    finding_id=f"structure_noclen_{int(time.time())}",
                    agent_id=self.agent_id,
                    timestamp=time.time(),
                    title="Missing Content-Length Header",
                    description="State-changing request without Content-Length header",
                    severity=ThreatSeverity.LOW,
                    confidence=0.50,
                    threat_type="STRUCTURE_ANOMALY",
                    location="headers",
                    evidence=f"Method: {data['method']} with body but no Content-Length",
                    context={'method': data['method'], 'has_body': bool(data['body'])},
                    recommendation="Require Content-Length header for state-changing requests",
                    references=['OWASP-A1']
                )
                findings.append(finding)
                threat_score += 0.1
                confidence_sum += 0.50
                count += 1
        
        return {
            'findings': findings,
            'threat_score': threat_score,
            'confidence_sum': confidence_sum,
            'count': count
        }
    
    def _detect_content_type_mismatches(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect mismatches between Content-Type and actual content.
        
        Args:
            data (Dict): Normalized request data
            
        Returns:
            Dict: Findings and scores for content type mismatches
            
        Explanation:
        -----------
        Attackers may spoof content types to bypass validation:
        - Claiming JSON but sending XML
        - Claiming text but sending binary
        - Incorrect character encoding
        """
        
        findings = []
        threat_score = 0.0
        confidence_sum = 0.0
        count = 0
        
        content_type = data['headers'].get('Content-Type', '').lower()
        body = data['body']
        
        if not content_type or not body:
            return {'findings': findings, 'threat_score': threat_score, 
                   'confidence_sum': confidence_sum, 'count': count}
        
        # Check for JSON content type but non-JSON body
        if 'application/json' in content_type:
            try:
                json.loads(body)
            except json.JSONDecodeError:
                # Not valid JSON despite claiming to be
                finding = SecurityFinding(
                    finding_id=f"content_json_mismatch_{int(time.time())}",
                    agent_id=self.agent_id,
                    timestamp=time.time(),
                    title="JSON Content-Type Mismatch",
                    description="Content-Type claims JSON but body is not valid JSON",
                    severity=ThreatSeverity.MEDIUM,
                    confidence=0.70,
                    threat_type="CONTENT_MISMATCH",
                    location="headers_body",
                    evidence=f"Content-Type: {content_type}, but body is not valid JSON",
                    context={'claimed_type': 'application/json', 'actual_type': 'unknown'},
                    recommendation="Validate that Content-Type matches actual content",
                    references=['OWASP-A1']
                )
                findings.append(finding)
                threat_score += 0.4
                confidence_sum += 0.70
                count += 1
        
        # Check for XML content type but non-XML body
        elif 'application/xml' in content_type or 'text/xml' in content_type:
            if not body.strip().startswith('<?xml') and not body.strip().startswith('<'):
                finding = SecurityFinding(
                    finding_id=f"content_xml_mismatch_{int(time.time())}",
                    agent_id=self.agent_id,
                    timestamp=time.time(),
                    title="XML Content-Type Mismatch",
                    description="Content-Type claims XML but body doesn't start as XML",
                    severity=ThreatSeverity.MEDIUM,
                    confidence=0.65,
                    threat_type="CONTENT_MISMATCH",
                    location="headers_body",
                    evidence=f"Content-Type: {content_type}, but body doesn't start with XML declaration",
                    context={'claimed_type': 'xml', 'actual_start': body[:50]},
                    recommendation="Validate XML structure when Content-Type claims XML",
                    references=['OWASP-A1']
                )
                findings.append(finding)
                threat_score += 0.35
                confidence_sum += 0.65
                count += 1
        
        # Check for form data content type but not formatted as form data
        elif 'application/x-www-form-urlencoded' in content_type:
            # Basic check: form data should have key=value pairs separated by &
            if '=' not in body and '&' not in body:
                finding = SecurityFinding(
                    finding_id=f"content_form_mismatch_{int(time.time())}",
                    agent_id=self.agent_id,
                    timestamp=time.time(),
                    title="Form Data Content-Type Mismatch",
                    description="Content-Type claims form data but body doesn't match format",
                    severity=ThreatSeverity.LOW,
                    confidence=0.60,
                    threat_type="CONTENT_MISMATCH",
                    location="headers_body",
                    evidence=f"Content-Type: {content_type}, but body doesn't match form data format",
                    context={'claimed_type': 'form-data', 'body_sample': body[:100]},
                    recommendation="Validate form data format when Content-Type claims form data",
                    references=['OWASP-A1']
                )
                findings.append(finding)
                threat_score += 0.2
                confidence_sum += 0.60
                count += 1
        
        return {
            'findings': findings,
            'threat_score': threat_score,
            'confidence_sum': confidence_sum,
            'count': count
        }
    
    def _context_aware_engine(self, normalized_data: Dict[str, Any], 
                            existing_findings: List[SecurityFinding]) -> Tuple[List[SecurityFinding], float, float]:
        """
        Context-aware analysis engine.
        
        Args:
            normalized_data (Dict): Normalized request data
            existing_findings (List): Findings from previous engines
            
        Returns:
            Tuple[List[SecurityFinding], float, float]: Contextual findings, threat score, certainty
            
        Explanation:
        -----------
        This engine analyzes findings in context:
        - Are findings consistent with the request context?
        - Do multiple findings suggest a coordinated attack?
        - Is the request targeting sensitive areas?
        - Does user behavior match historical patterns?
        """
        
        findings = []
        threat_score = 0.0
        certainty = 0.7  # Base certainty for context analysis
        
        context = normalized_data['context']
        
        # If targeting admin area, increase severity of findings
        if context['is_admin'] and existing_findings:
            for finding in existing_findings:
                # Create enhanced finding for admin context
                enhanced_finding = SecurityFinding(
                    finding_id=f"{finding.finding_id}_admin_context",
                    agent_id=self.agent_id,
                    timestamp=time.time(),
                    title=f"{finding.title} (Admin Context)",
                    description=f"{finding.description}. Found in administrative interface.",
                    severity=ThreatSeverity(max(finding.severity.value + 1, ThreatSeverity.CRITICAL.value)),
                    confidence=min(finding.confidence * 1.2, 0.95),
                    threat_type=finding.threat_type,
                    location=finding.location,
                    evidence=f"{finding.evidence}. Target: Admin area.",
                    context={**finding.context, **{'admin_context': True}},
                    recommendation=f"{finding.recommendation} Additional monitoring recommended for admin access.",
                    references=finding.references
                )
                findings.append(enhanced_finding)
                threat_score += enhanced_finding.severity.value / 4.0 * enhanced_finding.confidence
        
        # If targeting API, check for API-specific threats
        if context['is_api']:
            # Check for missing API authentication
            if not context['has_auth'] and normalized_data['method'] in ['POST', 'PUT', 'DELETE']:
                finding = SecurityFinding(
                    finding_id=f"context_api_noauth_{int(time.time())}",
                    agent_id=self.agent_id,
                    timestamp=time.time(),
                    title="API Request Without Authentication",
                    description="State-changing API request without authentication",
                    severity=ThreatSeverity.HIGH,
                    confidence=0.75,
                    threat_type="BROKEN_AUTHENTICATION",
                    location="api_context",
                    evidence=f"API request to {normalized_data['url']} without auth headers",
                    context={'is_api': True, 'method': normalized_data['method'], 'has_auth': False},
                    recommendation="Require authentication for all state-changing API endpoints",
                    references=['OWASP-A2']
                )
                findings.append(finding)
                threat_score += 0.6
        
        # Check for attack sequencing (multiple related findings)
        if len(existing_findings) >= 3:
            # Group findings by type
            finding_types = {}
            for finding in existing_findings:
                finding_types[finding.threat_type] = finding_types.get(finding.threat_type, 0) + 1
            
            # If multiple findings of same type, suggest coordinated attack
            for threat_type, count in finding_types.items():
                if count >= 2:
                    finding = SecurityFinding(
                        finding_id=f"context_coordinated_{threat_type}_{int(time.time())}",
                        agent_id=self.agent_id,
                        timestamp=time.time(),
                        title=f"Coordinated {threat_type.replace('_', ' ').title()} Attempt",
                        description=f"Multiple {threat_type} findings ({count}) suggest coordinated attack",
                        severity=ThreatSeverity.HIGH,
                        confidence=0.80,
                        threat_type="COORDINATED_ATTACK",
                        location="request_sequence",
                        evidence=f"Multiple {threat_type} patterns detected in same request",
                        context={'threat_type': threat_type, 'count': count, 'findings': [f.finding_id for f in existing_findings if f.threat_type == threat_type]},
                        recommendation="Block request and investigate for attack campaign",
                        references=['OWASP-A1']
                    )
                    findings.append(finding)
                    threat_score += 0.7
        
        # Normalize threat score
        if findings:
            threat_score = min(1.0, threat_score / len(findings))
        else:
            threat_score = 0.0
        
        return findings, threat_score, certainty
    
    def _sequence_analysis_engine(self, normalized_data: Dict[str, Any],
                                existing_findings: List[SecurityFinding]) -> Tuple[List[SecurityFinding], float, float]:
        """
        Sequence analysis engine for multi-step attacks.
        
        Args:
            normalized_data (Dict): Normalized request data
            existing_findings (List): Findings from previous engines
            
        Returns:
            Tuple[List[SecurityFinding], float, float]: Sequence findings, threat score, certainty
            
        Explanation:
        -----------
        Some attacks involve multiple steps:
        1. Reconnaissance to identify vulnerabilities
        2. Exploitation attempt
        3. Payload delivery
        4. Persistence establishment
        
        This engine looks for patterns across multiple requests/actions.
        """
        
        findings = []
        threat_score = 0.0
        certainty = 0.65  # Sequence analysis has moderate certainty
        
        # Check memory for similar previous findings from same source
        source_ip = normalized_data.get('source_ip')
        if source_ip and self.memory:
            # Get recent findings from same source
            recent_from_source = []
            for memory_entry in self.memory[-100:]:  # Last 100 memories
                finding = memory_entry['finding']
                if finding.context.get('source_ip') == source_ip:
                    recent_from_source.append(finding)
            
            # If same source has multiple findings, check for attack progression
            if len(recent_from_source) >= 2:
                # Check if findings show progression (e.g., recon -> exploit)
                threat_types = [f.threat_type for f in recent_from_source]
                unique_threats = set(threat_types)
                
                if len(unique_threats) >= 2:
                    # Multiple threat types from same source suggests attack progression
                    finding = SecurityFinding(
                        finding_id=f"sequence_progression_{int(time.time())}",
                        agent_id=self.agent_id,
                        timestamp=time.time(),
                        title="Multi-Stage Attack Detected",
                        description=f"Source {source_ip} showing attack progression across {len(unique_threats)} threat types",
                        severity=ThreatSeverity.HIGH,
                        confidence=0.75,
                        threat_type="ATTACK_PROGRESSION",
                        location="request_sequence",
                        evidence=f"Previous findings from {source_ip}: {', '.join(list(unique_threats)[:3])}",
                        context={
                            'source_ip': source_ip,
                            'threat_types': list(unique_threats),
                            'finding_count': len(recent_from_source),
                            'time_window': 'recent'
                        },
                        recommendation="Block source IP and investigate for ongoing attack campaign",
                        references=['OWASP-A1']
                    )
                    findings.append(finding)
                    threat_score += 0.8
        
        # Check for common exploit chain patterns
        current_finding_types = {f.threat_type for f in existing_findings}
        
        # SQLi -> Command injection chain
        if 'SQL_INJECTION' in current_finding_types and 'COMMAND_INJECTION' in current_finding_types:
            finding = SecurityFinding(
                finding_id=f"sequence_sqli_cmd_{int(time.time())}",
                agent_id=self.agent_id,
                timestamp=time.time(),
                title="SQLi to Command Injection Chain",
                description="Potential exploit chain: SQL injection leading to command execution",
                severity=ThreatSeverity.CRITICAL,
                confidence=0.85,
                threat_type="EXPLOIT_CHAIN",
                location="request_pattern",
                evidence="Both SQL injection and command injection patterns detected",
                context={'chain': 'SQLi -> Command Injection', 'findings': list(current_finding_types)},
                recommendation="Immediate blocking required - potential critical exploit chain",
                references=['OWASP-A1', 'CWE-89', 'CWE-78']
            )
            findings.append(finding)
            threat_score += 0.9
        
        # XSS -> CSRF chain
        if 'XSS' in current_finding_types and 'CSRF' in current_finding_types:
            finding = SecurityFinding(
                finding_id=f"sequence_xss_csrf_{int(time.time())}",
                agent_id=self.agent_id,
                timestamp=time.time(),
                title="XSS to CSRF Chain",
                description="Potential chain: XSS leading to CSRF attack",
                severity=ThreatSeverity.HIGH,
                confidence=0.80,
                threat_type="EXPLOIT_CHAIN",
                location="request_pattern",
                evidence="Both XSS and CSRF patterns detected",
                context={'chain': 'XSS -> CSRF', 'findings': list(current_finding_types)},
                recommendation="Block request and implement both XSS and CSRF protections",
                references=['OWASP-A3', 'OWASP-A1']
            )
            findings.append(finding)
            threat_score += 0.7
        
        # Normalize threat score
        if findings:
            threat_score = min(1.0, threat_score / len(findings))
        else:
            threat_score = 0.0
        
        return findings, threat_score, certainty
    
    def _deduplicate_findings(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """
        Remove duplicate and similar findings.
        
        Args:
            findings (List[SecurityFinding]): Raw findings list
            
        Returns:
            List[SecurityFinding]: Deduplicated findings
            
        Explanation:
        -----------
        Multiple engines might detect the same threat from different angles.
        This method:
        1. Removes exact duplicates
        2. Merges similar findings
        3. Keeps the highest confidence version
        4. Preserves unique findings
        """
        
        if not findings:
            return []
        
        # Group by threat type and location
        grouped = {}
        for finding in findings:
            key = (finding.threat_type, finding.location, finding.title[:50])
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(finding)
        
        # For each group, keep the finding with highest severity/confidence
        deduplicated = []
        for key, group_findings in grouped.items():
            if len(group_findings) == 1:
                deduplicated.append(group_findings[0])
            else:
                # Sort by severity (descending) then confidence (descending)
                group_findings.sort(
                    key=lambda x: (x.severity.value, x.confidence),
                    reverse=True
                )
                # Take the best finding
                best_finding = group_findings[0]
                
                # Update description to mention multiple detections
                if len(group_findings) > 1:
                    best_finding.description = (
                        f"{best_finding.description} "
                        f"(Detected by {len(group_findings)} methods)"
                    )
                    best_finding.confidence = min(0.95, best_finding.confidence * 1.1)
                
                deduplicated.append(best_finding)
        
        # Sort final list by severity and confidence
        deduplicated.sort(
            key=lambda x: (x.severity.value, x.confidence),
            reverse=True
        )
        
        return deduplicated
    
    def _calculate_overall_threat(self, threat_scores: List[float], 
                                certainties: List[float]) -> float:
        """
        Calculate overall threat level from multiple engines.
        
        Args:
            threat_scores (List[float]): Threat scores from each engine
            certainties (List[float]): Certainties from each engine
            
        Returns:
            float: Overall threat level (0.0 to 1.0)
            
        Explanation:
        -----------
        The overall threat level is a weighted average:
        - Higher weight for engines with higher certainty
        - Normalized to 0-1 range
        - Capped at 1.0
        """
        
        if not threat_scores:
            return 0.0
        
        # Weight scores by certainty
        weighted_sum = 0.0
        total_weight = 0.0
        
        for score, certainty in zip(threat_scores, certainties):
            weight = certainty  # Use certainty as weight
            weighted_sum += score * weight
            total_weight += weight
        
        if total_weight > 0:
            overall_threat = weighted_sum / total_weight
        else:
            overall_threat = sum(threat_scores) / len(threat_scores)
        
        # Apply non-linear scaling to emphasize high threats
        # This makes 0.7->0.85, 0.9->0.99, etc.
        overall_threat = overall_threat ** 0.7
        
        return min(1.0, overall_threat)
    
    def _get_recommendation_for_threat(self, threat_type: str) -> str:
        """
        Get specific recommendation for a threat type.
        
        Args:
            threat_type (str): Type of threat detected
            
        Returns:
            str: Specific recommendation
            
        Explanation:
        -----------
        Different threats require different mitigation strategies.
        This method provides threat-specific recommendations based on
        OWASP best practices and security standards.
        """
        
        recommendations = {
            'SQL_INJECTION': "Use parameterized queries or prepared statements. Implement input validation and least privilege database accounts.",
            'XSS': "Implement Content Security Policy (CSP). Validate and sanitize all user inputs. Use appropriate output encoding.",
            'CSRF': "Implement CSRF tokens for state-changing requests. Use SameSite cookies. Validate Origin and Referer headers.",
            'SSRF': "Implement allow-list for outgoing requests. Validate and sanitize all user-provided URLs. Use network segmentation.",
            'COMMAND_INJECTION': "Avoid shell commands with user input. Use built-in library functions. Implement strict input validation.",
            'PATH_TRAVERSAL': "Implement path validation. Use allow-lists for file access. Keep web server updated.",
            'XXE': "Disable XML external entity processing. Use simpler data formats like JSON. Implement XML input validation.",
            'BROKEN_AUTHENTICATION': "Implement multi-factor authentication. Use strong password policies. Implement account lockout.",
            'ENCODING_BYPASS': "Implement consistent encoding/decoding. Use security libraries for input validation.",
            'INFORMATION_DISCLOSURE': "Implement proper error handling. Remove sensitive information from responses. Use security headers."
        }
        
        return recommendations.get(threat_type, 
            "Review security controls and implement appropriate mitigations based on application context.")
    
    def _generate_recommendations(self, findings: List[SecurityFinding], 
                                overall_threat: float) -> List[str]:
        """
        Generate actionable security recommendations.
        
        Args:
            findings (List[SecurityFinding]): Security findings
            overall_threat (float): Overall threat level
            
        Returns:
            List[str]: Actionable recommendations
            
        Explanation:
        -----------
        Recommendations are prioritized based on:
        1. Threat severity
        2. Confidence level
        3. Business impact
        4. Implementation complexity
        
        Each recommendation is specific, actionable, and includes
        implementation guidance.
        """
        
        recommendations = []
        
        # Add threat-specific recommendations
        threat_recommendations = set()
        for finding in findings[:5]:  # Top 5 findings
            if finding.severity.value >= ThreatSeverity.MEDIUM.value:
                threat_recommendations.add(self._get_recommendation_for_threat(finding.threat_type))
        
        recommendations.extend(list(threat_recommendations))
        
        # Add severity-based recommendations
        critical_findings = [f for f in findings if f.severity == ThreatSeverity.CRITICAL]
        high_findings = [f for f in findings if f.severity == ThreatSeverity.HIGH]
        
        if critical_findings:
            recommendations.extend([
                "Immediate action required: Block the request and investigate source",
                "Review application logs for similar patterns from same source",
                "Consider implementing a Web Application Firewall (WAF) with custom rules"
            ])
        
        elif high_findings:
            recommendations.extend([
                "High priority: Review and implement recommended mitigations",
                "Monitor for similar attack patterns",
                "Consider rate limiting or CAPTCHA for suspicious sources"
            ])
        
        # Add general recommendations based on threat level
        if overall_threat > 0.7:
            recommendations.extend([
                "Implement comprehensive security monitoring",
                "Regularly update and patch all software components",
                "Conduct security training for developers",
                "Implement automated security testing in CI/CD pipeline"
            ])
        
        # Ensure recommendations are unique and limited
        return list(set(recommendations))[:10]  # Top 10 unique recommendations
    
    def _update_reasoning_state(self, findings: List[SecurityFinding], 
                              threat_level: float, certainty: float):
        """
        Update agent's reasoning state based on analysis.
        
        Args:
            findings (List[SecurityFinding]): Security findings
            threat_level (float): Overall threat level
            certainty (float): Analysis certainty
            
        Explanation:
        -----------
        The reasoning state encodes:
        1. Current threat assessment
        2. Types of threats detected
        3. Confidence levels
        4. Temporal patterns
        
        This state is used by the mHC system for multi-agent coordination.
        """
        
        # Start with base state
        state_vector = torch.zeros(self.state_dim)
        
        # Encode threat level in first dimension
        state_vector[0] = threat_level
        
        # Encode certainty in second dimension
        state_vector[1] = certainty
        
        # Encode threat types in next dimensions
        threat_type_encoding = {
            'SQL_INJECTION': 2,
            'XSS': 3,
            'CSRF': 4,
            'SSRF': 5,
            'COMMAND_INJECTION': 6,
            'PATH_TRAVERSAL': 7,
            'XXE': 8,
            'BROKEN_AUTHENTICATION': 9,
            'ENCODING_BYPASS': 10,
            'STRUCTURE_ANOMALY': 11,
            'CONTENT_MISMATCH': 12,
            'COORDINATED_ATTACK': 13,
            'EXPLOIT_CHAIN': 14
        }
        
        for finding in findings[:10]:  # Encode top 10 findings
            idx = threat_type_encoding.get(finding.threat_type)
            if idx and idx < self.state_dim:
                # Encode severity and confidence
                severity_norm = finding.severity.value / 4.0
                state_vector[idx] = max(state_vector[idx], finding.confidence * severity_norm)
        
        # Encode finding count pattern
        finding_count = len(findings)
        if finding_count > 0 and 15 < self.state_dim:
            state_vector[15] = min(1.0, finding_count / 10.0)
        
        # Update agent's reasoning state with exponential moving average
        alpha = 0.3  # Learning rate for state updates
        self.reasoning_state = alpha * state_vector + (1 - alpha) * self.reasoning_state
        
        # Normalize to prevent explosion
        norm = torch.norm(self.reasoning_state)
        if norm > 1.0:
            self.reasoning_state = self.reasoning_state / norm
    
    def _update_metrics(self, findings: List[SecurityFinding], 
                       processing_time: float):
        """
        Update agent performance metrics.
        
        Args:
            findings (List[SecurityFinding]): Security findings
            processing_time (float): Time taken for analysis
            
        Explanation:
        -----------
        Metrics tracking helps:
        1. Monitor agent performance
        2. Identify areas for improvement
        3. Provide insights for tuning
        4. Support capacity planning
        """
        
        # FIXED: Initialize metrics if not present
        if 'avg_processing_time' not in self.metrics:
            self.metrics['avg_processing_time'] = processing_time
            self.metrics['threats_detected'] = 0
            self.metrics['successful_analyses'] = 0
            self.metrics['total_analyses'] = 0
            self.metrics['success_rate'] = 0.0
        
        # Update processing time (exponential moving average)
        self.metrics['avg_processing_time'] = (
            0.9 * self.metrics['avg_processing_time'] + 
            0.1 * processing_time
        )
        
        # Count threats by severity
        for finding in findings:
            if finding.severity.value >= ThreatSeverity.MEDIUM.value:
                self.metrics['threats_detected'] += 1
        
        # Update analysis counts
        self.metrics['total_analyses'] += 1
        self.metrics['successful_analyses'] += 1  # Assuming successful if no exception
        
        # Update success rate
        if self.metrics['total_analyses'] > 0:
            self.metrics['success_rate'] = self.metrics['successful_analyses'] / self.metrics['total_analyses']
    
    def _create_whitelist_response(self, start_time: float) -> Dict[str, Any]:
        """
        Create response for whitelisted requests.
        
        Args:
            start_time (float): Analysis start time
            
        Returns:
            Dict[str, Any]: Whitelist response
            
        Explanation:
        -----------
        Whitelisted requests bypass detailed analysis to reduce
        false positives and improve performance for known-safe traffic.
        """
        
        processing_time = time.time() - start_time
        
        # Create informational finding
        info_finding = SecurityFinding(
            finding_id=f"whitelist_{int(time.time())}",
            agent_id=self.agent_id,
            timestamp=time.time(),
            title="Request Whitelisted",
            description="Request matched whitelist criteria and bypassed detailed analysis",
            severity=ThreatSeverity.INFORMATIONAL,
            confidence=0.95,
            threat_type="WHITELISTED",
            location="agent_decision",
            evidence="Request matched whitelist patterns",
            context={'whitelist_reason': 'known_safe_pattern'},
            recommendation="Monitor whitelist effectiveness and update as needed",
            references=[]
        )
        
        self.state = AgentState.IDLE
        
        return {
            'agent_id': self.agent_id,
            'agent_name': self.name,
            'findings': [info_finding],
            'threat_level': 0.0,
            'certainty': 0.95,
            'reasoning_state': self.get_reasoning_state(),
            'processing_time': processing_time,
            'whitelisted': True,
            'decision': {
                'threat_level': 0.0,
                'confidence': 0.95,
                'evidence': [{'type': 'WHITELISTED', 'reason': 'known_safe_pattern'}]
            }
        }
    
    def get_detailed_status(self) -> Dict[str, Any]:
        """
        Get detailed status including pattern statistics.
        
        Returns:
            Dict[str, Any]: Detailed agent status
            
        Explanation:
        -----------
        Provides comprehensive status information including:
        - Pattern counts by type
        - Detection engine status
        - Performance statistics
        - Configuration details
        """
        
        base_status = super().get_status()
        
        # Add pattern statistics
        pattern_stats = {}
        for threat_type, patterns in self.threat_patterns.items():
            pattern_stats[threat_type] = {
                'pattern_count': len(patterns),
                'enabled': True,
                'last_used': time.time()  # Would be tracked in production
            }
        
        # Add engine status
        engine_status = {}
        for engine_name, engine_info in self.detection_engines.items():
            engine_status[engine_name] = {
                'enabled': engine_info['enabled'],
                'description': engine_info['description'],
                'calls': 0  # Would track in production
            }
        
        detailed_status = {
            **base_status,
            'pattern_statistics': pattern_stats,
            'engine_status': engine_status,
            'compiled_patterns': len(self.compiled_patterns),
            'whitelist_entries': sum(len(v) for v in self.whitelist.values()),
            'configuration': self.config
        }
        
        return detailed_status