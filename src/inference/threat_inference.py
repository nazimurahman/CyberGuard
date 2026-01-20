# src/inference/threat_inference.py
"""
Threat Inference Module for CyberGuard

Specialized inference logic for different threat types:
1. XSS (Cross-Site Scripting) detection
2. SQL Injection pattern matching
3. CSRF (Cross-Site Request Forgery) validation
4. SSRF (Server-Side Request Forgery) detection
5. Command Injection analysis
6. Path Traversal detection
7. XXE (XML External Entity) detection
8. Deserialization vulnerabilities
9. IDOR (Insecure Direct Object Reference)
10. Broken Authentication detection

Uses rule-based, pattern-based, and ML-based approaches.
"""

import re
import json
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import base64
import urllib.parse
from collections import defaultdict
import numpy as np

# Local imports
from . import InferenceResult, SecurityRecommendation
from ..core.gqa_transformer import SecurityGQATransformer

# Configure logging
import logging
logger = logging.getLogger(__name__)

@dataclass
class ThreatPattern:
    """Pattern for detecting specific threat types"""
    name: str
    pattern: str
    threat_type: str
    severity: str
    confidence: float
    description: str
    mitigation: str
    regex_flags: int = re.IGNORECASE
    
    def match(self, text: str) -> Optional[re.Match]:
        """Check if pattern matches text"""
        try:
            return re.search(self.pattern, text, self.regex_flags)
        except re.error:
            logger.error(f"Invalid regex pattern for {self.name}: {self.pattern}")
            return None

class ThreatIntelligence:
    """Threat intelligence database with patterns and signatures"""
    
    def __init__(self):
        self.patterns: List[ThreatPattern] = []
        self._load_default_patterns()
    
    def _load_default_patterns(self):
        """Load default threat detection patterns"""
        
        # XSS Patterns
        self.patterns.extend([
            ThreatPattern(
                name="XSS_SCRIPT_TAG",
                pattern=r'<script[^>]*>.*?</script>',
                threat_type="XSS",
                severity="HIGH",
                confidence=0.9,
                description="Script tag injection attempt",
                mitigation="Implement Content Security Policy and input sanitization"
            ),
            ThreatPattern(
                name="XSS_JAVASCRIPT_URI",
                pattern=r'javascript:[^\)\s]*',
                threat_type="XSS",
                severity="HIGH",
                confidence=0.85,
                description="JavaScript URI scheme detected",
                mitigation="Validate and sanitize all URLs and redirects"
            ),
            ThreatPattern(
                name="XSS_EVENT_HANDLER",
                pattern=r'on\w+\s*=\s*["\'][^"\']*["\']',
                threat_type="XSS",
                severity="MEDIUM",
                confidence=0.8,
                description="HTML event handler injection",
                mitigation="Sanitize HTML attributes and use safe DOM APIs"
            )
        ])
        
        # SQL Injection Patterns
        self.patterns.extend([
            ThreatPattern(
                name="SQL_UNION",
                pattern=r'union\s+select',
                threat_type="SQL_INJECTION",
                severity="CRITICAL",
                confidence=0.95,
                description="SQL UNION injection attempt",
                mitigation="Use parameterized queries or prepared statements"
            ),
            ThreatPattern(
                name="SQL_COMMENT",
                pattern=r'--\s*$',
                threat_type="SQL_INJECTION",
                severity="MEDIUM",
                confidence=0.7,
                description="SQL comment injection",
                mitigation="Validate input and use proper SQL escaping"
            ),
            ThreatPattern(
                name="SQL_OR_CONDITION",
                pattern=r"'\s+or\s+['\d]",
                threat_type="SQL_INJECTION",
                severity="HIGH",
                confidence=0.85,
                description="SQL OR condition injection",
                mitigation="Implement proper input validation and escaping"
            )
        ])
        
        # Command Injection Patterns
        self.patterns.extend([
            ThreatPattern(
                name="CMD_SEMICOLON",
                pattern=r';\s*\w+',
                threat_type="COMMAND_INJECTION",
                severity="HIGH",
                confidence=0.8,
                description="Command separator injection",
                mitigation="Use command whitelisting and parameterization"
            ),
            ThreatPattern(
                name="CMD_PIPE",
                pattern=r'\|\s*\w+',
                threat_type="COMMAND_INJECTION",
                severity="HIGH",
                confidence=0.8,
                description="Command pipe injection",
                mitigation="Validate and sanitize all command inputs"
            ),
            ThreatPattern(
                name="CMD_BACKTICK",
                pattern=r'`[^`]+`',
                threat_type="COMMAND_INJECTION",
                severity="HIGH",
                confidence=0.85,
                description="Command substitution injection",
                mitigation="Avoid shell command execution with user input"
            )
        ])
        
        # Path Traversal Patterns
        self.patterns.extend([
            ThreatPattern(
                name="PATH_DOT_DOT",
                pattern=r'\.\./',
                threat_type="PATH_TRAVERSAL",
                severity="HIGH",
                confidence=0.9,
                description="Directory traversal attempt",
                mitigation="Implement path validation and normalization"
            ),
            ThreatPattern(
                name="PATH_ABSOLUTE",
                pattern=r'^/(etc|bin|usr|var|home|root)/',
                threat_type="PATH_TRAVERSAL",
                severity="HIGH",
                confidence=0.85,
                description="Absolute path access attempt",
                mitigation="Restrict file system access to safe directories"
            )
        ])
        
        # XXE Patterns
        self.patterns.extend([
            ThreatPattern(
                name="XXE_DOCTYPE",
                pattern=r'<!DOCTYPE[^>]*SYSTEM',
                threat_type="XXE",
                severity="HIGH",
                confidence=0.9,
                description="XML external entity declaration",
                mitigation="Disable XML external entity processing"
            ),
            ThreatPattern(
                name="XXE_ENTITY",
                pattern=r'<!ENTITY[^>]*>',
                threat_type="XXE",
                severity="MEDIUM",
                confidence=0.8,
                description="XML entity declaration",
                mitigation="Use safe XML parsers with DTD disabled"
            )
        ])
        
        # CSRF Detection
        self.patterns.extend([
            ThreatPattern(
                name="CSRF_TOKEN_MISSING",
                pattern=r'',  # Special case, handled separately
                threat_type="CSRF",
                severity="MEDIUM",
                confidence=0.7,
                description="Missing CSRF token in state-changing request",
                mitigation="Implement CSRF tokens for all state-changing operations"
            )
        ])
        
        logger.info(f"Loaded {len(self.patterns)} threat patterns")
    
    def detect_threats(self, text: str, context: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Detect threats in text using pattern matching.
        
        Args:
            text: Text to analyze
            context: Additional context for detection
        
        Returns:
            List of detected threats
        """
        threats = []
        
        if not text or not isinstance(text, str):
            return threats
        
        # Convert to lowercase for case-insensitive matching
        text_lower = text.lower()
        
        for pattern in self.patterns:
            # Skip special patterns
            if pattern.name == "CSRF_TOKEN_MISSING":
                continue
            
            match = pattern.match(text)
            if match:
                threats.append({
                    'type': pattern.threat_type,
                    'pattern': pattern.name,
                    'severity': pattern.severity,
                    'confidence': pattern.confidence,
                    'description': pattern.description,
                    'match': match.group()[:100],  # Truncate match
                    'position': match.start(),
                    'mitigation': pattern.mitigation
                })
        
        return threats
    
    def detect_csrf(self, request_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detect CSRF vulnerabilities in request.
        
        Args:
            request_data: HTTP request data
        
        Returns:
            List of CSRF-related threats
        """
        threats = []
        
        # Check for state-changing methods
        method = request_data.get('method', 'GET').upper()
        state_changing_methods = {'POST', 'PUT', 'DELETE', 'PATCH'}
        
        if method in state_changing_methods:
            # Check for CSRF tokens
            headers = request_data.get('headers', {})
            body = request_data.get('body', '')
            
            csrf_tokens_present = False
            
            # Check headers for CSRF tokens
            csrf_header_patterns = ['x-csrf-token', 'x-xsrf-token', 'csrf-token']
            for header in csrf_header_patterns:
                if header in headers or header.replace('-', '_') in headers:
                    csrf_tokens_present = True
                    break
            
            # Check body for CSRF tokens
            if isinstance(body, str):
                csrf_body_patterns = ['csrf_token', 'csrf-token', '_csrf', 'authenticity_token']
                for pattern in csrf_body_patterns:
                    if pattern in body.lower():
                        csrf_tokens_present = True
                        break
            
            # If no CSRF tokens found, flag as potential vulnerability
            if not csrf_tokens_present:
                csrf_pattern = next(p for p in self.patterns if p.name == "CSRF_TOKEN_MISSING")
                threats.append({
                    'type': csrf_pattern.threat_type,
                    'pattern': csrf_pattern.name,
                    'severity': csrf_pattern.severity,
                    'confidence': csrf_pattern.confidence,
                    'description': csrf_pattern.description,
                    'mitigation': csrf_pattern.mitigation,
                    'context': {
                        'method': method,
                        'state_changing': True
                    }
                })
        
        return threats

class ThreatInference:
    """
    Main threat inference engine.
    
    Combines pattern matching, heuristic analysis, and ML-based approaches
    to detect web security threats with high accuracy.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize threat inference engine.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        
        # Initialize components
        self.threat_intel = ThreatIntelligence()
        
        # Threat-specific analyzers
        self.analyzers = {
            'XSS': self._analyze_xss,
            'SQL_INJECTION': self._analyze_sqli,
            'CSRF': self._analyze_csrf,
            'SSRF': self._analyze_ssrf,
            'COMMAND_INJECTION': self._analyze_command_injection,
            'PATH_TRAVERSAL': self._analyze_path_traversal,
            'XXE': self._analyze_xxe,
            'DESERIALIZATION': self._analyze_deserialization,
            'IDOR': self._analyze_idor,
            'BROKEN_AUTH': self._analyze_broken_auth
        }
        
        # Threat severity weights
        self.severity_weights = {
            'CRITICAL': 1.0,
            'HIGH': 0.8,
            'MEDIUM': 0.6,
            'LOW': 0.4,
            'INFO': 0.1
        }
        
        # Confidence calibration
        self.confidence_calibration = {
            'pattern_match': 0.7,
            'heuristic': 0.6,
            'context_aware': 0.8,
            'ml_based': 0.9
        }
        
        logger.info("ThreatInference initialized")
    
    def infer(self, features: Dict[str, Any]) -> InferenceResult:
        """
        Perform threat inference on extracted features.
        
        Args:
            features: Extracted security features
        
        Returns:
            InferenceResult with threat analysis
        """
        logger.debug(f"Starting threat inference with {len(features.get('patterns', {}))} patterns")
        
        # Extract text components for analysis
        text_components = self._extract_text_components(features)
        
        # Detect threats using pattern matching
        pattern_threats = []
        for component_name, text in text_components.items():
            if text:
                threats = self.threat_intel.detect_threats(text)
                for threat in threats:
                    threat['component'] = component_name
                    pattern_threats.append(threat)
        
        # Detect CSRF vulnerabilities
        if 'request_data' in self.config:
            csrf_threats = self.threat_intel.detect_csrf(self.config['request_data'])
            pattern_threats.extend(csrf_threats)
        
        # Group threats by type
        threats_by_type = defaultdict(list)
        for threat in pattern_threats:
            threats_by_type[threat['type']].append(threat)
        
        # Analyze each threat type with specialized analyzers
        analyzed_threats = []
        for threat_type, threats in threats_by_type.items():
            if threat_type in self.analyzers:
                analyzer_result = self.analyzers[threat_type](threats, features)
                analyzed_threats.extend(analyzer_result)
            else:
                # Use generic analysis for unknown threat types
                analyzed_threats.extend(self._analyze_generic(threats, features))
        
        # Calculate overall threat level
        threat_level = self._calculate_threat_level(analyzed_threats)
        
        # Calculate confidence
        confidence = self._calculate_confidence(analyzed_threats)
        
        # Determine primary threat type
        primary_threat = self._determine_primary_threat(analyzed_threats)
        
        # Generate evidence
        evidence = self._generate_evidence(analyzed_threats)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(analyzed_threats)
        
        # Determine severity
        severity = self._determine_severity(threat_level, confidence)
        
        return InferenceResult(
            threat_level=threat_level,
            confidence=confidence,
            threat_type=primary_threat,
            severity=severity,
            evidence=evidence,
            recommendations=recommendations,
            metadata={
                'threat_count': len(analyzed_threats),
                'threat_types': list(threats_by_type.keys()),
                'analysis_method': 'pattern_heuristic_ml'
            }
        )
    
    def _extract_text_components(self, features: Dict[str, Any]) -> Dict[str, str]:
        """Extract text components from features for analysis"""
        components = {}
        
        # URL components
        basic = features.get('basic', {})
        if 'url' in basic:
            components['url'] = basic['url']
        
        # Query parameters
        parameters = features.get('parameters', {})
        if 'query_params' in parameters:
            # Flatten query parameters
            query_text = ' '.join([
                f'{k}={v}' for k, vals in parameters['query_params'].items() 
                for v in vals
            ])
            components['query_params'] = query_text
        
        # Headers
        headers = features.get('headers', {})
        if headers:
            headers_text = ' '.join([f'{k}: {v}' for k, v in headers.items()])
            components['headers'] = headers_text
        
        # Request body (if provided in config)
        if 'request_data' in self.config:
            body = self.config['request_data'].get('body', '')
            if body:
                components['body'] = str(body)[:1000]  # Limit size
        
        return components
    
    def _analyze_xss(self, threats: List[Dict], features: Dict) -> List[Dict]:
        """Specialized XSS threat analysis"""
        analyzed = []
        
        for threat in threats:
            # Enhance XSS analysis with context
            enhanced_threat = threat.copy()
            
            # Check for reflection context
            component = threat.get('component', '')
            if component in ['url', 'query_params']:
                # XSS in URL/parameters is more dangerous
                enhanced_threat['severity'] = 'HIGH'
                enhanced_threat['confidence'] *= 1.1
            
            # Check for encoding attempts
            match_text = threat.get('match', '')
            if any(enc in match_text for enc in ['%3C', '%3E', '\\x3c', '\\x3e']):
                enhanced_threat['description'] += ' (encoded payload)'
                enhanced_threat['confidence'] *= 1.05
            
            analyzed.append(enhanced_threat)
        
        return analyzed
    
    def _analyze_sqli(self, threats: List[Dict], features: Dict) -> List[Dict]:
        """Specialized SQL injection analysis"""
        analyzed = []
        
        for threat in threats:
            enhanced_threat = threat.copy()
            
            # Check for union-based vs error-based
            match_text = threat.get('match', '').lower()
            if 'union' in match_text:
                enhanced_threat['subtype'] = 'UNION_BASED'
                enhanced_threat['severity'] = 'CRITICAL'
            elif 'or' in match_text:
                enhanced_threat['subtype'] = 'BOOLEAN_BASED'
                enhanced_threat['severity'] = 'HIGH'
            elif '--' in match_text or '#' in match_text:
                enhanced_threat['subtype'] = 'COMMENT_BASED'
            
            # Check for database-specific patterns
            db_patterns = {
                'mysql': ['version()', 'user()', 'database()'],
                'mssql': ['@@version', '@@servername'],
                'oracle': ['v$version', 'user_tables'],
                'postgresql': ['version()', 'current_user']
            }
            
            for db, patterns in db_patterns.items():
                if any(pattern in match_text for pattern in patterns):
                    enhanced_threat['database'] = db
                    enhanced_threat['confidence'] *= 1.05
                    break
            
            analyzed.append(enhanced_threat)
        
        return analyzed
    
    def _analyze_csrf(self, threats: List[Dict], features: Dict) -> List[Dict]:
        """Specialized CSRF analysis"""
        analyzed = []
        
        for threat in threats:
            enhanced_threat = threat.copy()
            
            # Get request context
            request_data = self.config.get('request_data', {})
            method = request_data.get('method', 'GET')
            headers = request_data.get('headers', {})
            
            # Check for anti-CSRF headers
            if 'origin' in headers and 'host' in headers:
                origin = headers.get('origin', '')
                host = headers.get('host', '')
                
                if origin and host and origin != host:
                    enhanced_threat['description'] += ' (Origin-Host mismatch)'
                    enhanced_threat['confidence'] = min(enhanced_threat['confidence'] * 1.2, 0.95)
            
            analyzed.append(enhanced_threat)
        
        return analyzed
    
    def _analyze_ssrf(self, threats: List[Dict], features: Dict) -> List[Dict]:
        """Specialized SSRF analysis"""
        analyzed = []
        
        # SSRF requires URL/parameter analysis
        components = self._extract_text_components(features)
        
        ssrf_patterns = [
            (r'127\.0\.0\.1', 'localhost access'),
            (r'localhost', 'localhost access'),
            (r'0\.0\.0\.0', 'all interfaces'),
            (r'169\.254\.\d+\.\d+', 'link-local address'),
            (r'10\.\d+\.\d+\.\d+', 'private network'),
            (r'172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+', 'private network'),
            (r'192\.168\.\d+\.\d+', 'private network'),
            (r'file://', 'file scheme'),
            (r'gopher://', 'gopher scheme'),
            (r'dict://', 'dict scheme')
        ]
        
        for pattern, description in ssrf_patterns:
            for component_name, text in components.items():
                if re.search(pattern, text, re.IGNORECASE):
                    analyzed.append({
                        'type': 'SSRF',
                        'pattern': 'SSRF_PATTERN',
                        'severity': 'HIGH',
                        'confidence': 0.8,
                        'description': f'Potential SSRF: {description}',
                        'component': component_name,
                        'match': re.search(pattern, text, re.IGNORECASE).group(),
                        'mitigation': 'Implement URL validation and SSRF protections'
                    })
        
        return analyzed
    
    def _analyze_command_injection(self, threats: List[Dict], features: Dict) -> List[Dict]:
        """Specialized command injection analysis"""
        analyzed = []
        
        for threat in threats:
            enhanced_threat = threat.copy()
            
            # Check for specific dangerous commands
            match_text = threat.get('match', '').lower()
            dangerous_commands = [
                'rm ', 'del ', 'kill ', 'shutdown', 'format ',
                'wget ', 'curl ', 'nc ', 'netcat ', 'python ',
                'perl ', 'php ', 'ruby ', 'bash ', 'sh '
            ]
            
            for cmd in dangerous_commands:
                if cmd in match_text:
                    enhanced_threat['description'] += f' (contains {cmd.strip()})'
                    enhanced_threat['severity'] = 'CRITICAL'
                    enhanced_threat['confidence'] *= 1.1
                    break
            
            analyzed.append(enhanced_threat)
        
        return analyzed
    
    def _analyze_path_traversal(self, threats: List[Dict], features: Dict) -> List[Dict]:
        """Specialized path traversal analysis"""
        analyzed = []
        
        for threat in threats:
            enhanced_threat = threat.copy()
            
            # Count depth of traversal
            match_text = threat.get('match', '')
            depth = match_text.count('../') + match_text.count('..\\')
            
            if depth > 3:
                enhanced_threat['description'] += f' (deep traversal: {depth} levels)'
                enhanced_threat['severity'] = 'CRITICAL'
                enhanced_threat['confidence'] *= 1.05
            
            # Check for sensitive file patterns
            sensitive_files = [
                '/etc/passwd', '/etc/shadow', '/etc/hosts',
                '/windows/win.ini', '/windows/system32/',
                '.ssh/id_rsa', '.aws/credentials',
                'web.config', 'config.php', '.env'
            ]
            
            component_text = ''
            components = self._extract_text_components(features)
            component = threat.get('component', '')
            if component in components:
                component_text = components[component].lower()
            
            for file in sensitive_files:
                if file in component_text:
                    enhanced_threat['description'] += f' (targets {file})'
                    enhanced_threat['severity'] = 'CRITICAL'
                    enhanced_threat['confidence'] = min(enhanced_threat['confidence'] * 1.2, 0.95)
                    break
            
            analyzed.append(enhanced_threat)
        
        return analyzed
    
    def _analyze_xxe(self, threats: List[Dict], features: Dict) -> List[Dict]:
        """Specialized XXE analysis"""
        analyzed = []
        
        # Check for XML content in request
        request_data = self.config.get('request_data', {})
        headers = request_data.get('headers', {})
        body = request_data.get('body', '')
        
        content_type = headers.get('content-type', '').lower()
        is_xml = 'xml' in content_type or ('<' in str(body) and '?>' in str(body))
        
        for threat in threats:
            enhanced_threat = threat.copy()
            
            if is_xml:
                enhanced_threat['confidence'] *= 1.1
                enhanced_threat['description'] += ' (in XML content)'
            
            analyzed.append(enhanced_threat)
        
        return analyzed
    
    def _analyze_deserialization(self, threats: List[Dict], features: Dict) -> List[Dict]:
        """Specialized deserialization analysis"""
        analyzed = []
        
        # Check for serialized data patterns
        components = self._extract_text_components(features)
        
        deserialization_patterns = [
            (r'O:\d+:"', 'PHP object serialization'),
            (r'\{s:\d+:".*?";', 'PHP serialize() output'),
            (r'rO0AB', 'Java serialized object'),
            (r'aced0005', 'Java serialized object (hex)'),
            (r'__reduce__', 'Python pickle'),
            (r'!!python/object', 'YAML Python object'),
            (r'type="System\.', '.NET serialization')
        ]
        
        for pattern, description in deserialization_patterns:
            for component_name, text in components.items():
                if re.search(pattern, text):
                    analyzed.append({
                        'type': 'DESERIALIZATION',
                        'pattern': 'DESERIALIZATION_PATTERN',
                        'severity': 'HIGH',
                        'confidence': 0.85,
                        'description': f'Potential deserialization: {description}',
                        'component': component_name,
                        'match': re.search(pattern, text).group()[:50],
                        'mitigation': 'Avoid deserializing untrusted data; use safe formats like JSON'
                    })
        
        return analyzed
    
    def _analyze_idor(self, threats: List[Dict], features: Dict) -> List[Dict]:
        """Specialized IDOR analysis"""
        analyzed = []
        
        # IDOR requires analyzing URL patterns and parameters
        basic = features.get('basic', {})
        parameters = features.get('parameters', {})
        
        url = basic.get('url', '')
        query_params = parameters.get('query_params', {})
        
        # Look for ID-like parameters
        id_patterns = ['id=', 'user_id=', 'account_id=', 'uid=', 'userId=']
        
        for param_name, param_values in query_params.items():
            param_lower = param_name.lower()
            
            for pattern in id_patterns:
                if pattern in param_lower:
                    # Check if value looks like an ID
                    for value in param_values:
                        if value.isdigit() or (len(value) > 5 and any(c.isdigit() for c in value)):
                            analyzed.append({
                                'type': 'IDOR',
                                'pattern': 'ID_PARAMETER',
                                'severity': 'MEDIUM',
                                'confidence': 0.6,
                                'description': f'Potential IDOR: {param_name} parameter with value {value[:20]}...',
                                'component': 'query_params',
                                'match': f'{param_name}={value[:20]}',
                                'mitigation': 'Implement proper authorization checks for all object accesses'
                            })
        
        return analyzed
    
    def _analyze_broken_auth(self, threats: List[Dict], features: Dict) -> List[Dict]:
        """Specialized broken authentication analysis"""
        analyzed = []
        
        # Check for authentication-related issues
        headers = features.get('headers', {})
        basic = features.get('basic', {})
        
        url = basic.get('url', '')
        method = basic.get('method', 'GET')
        
        # Check for sensitive endpoints without authentication
        sensitive_endpoints = [
            '/admin', '/dashboard', '/api/admin', '/manage',
            '/config', '/settings', '/users', '/accounts'
        ]
        
        if any(endpoint in url.lower() for endpoint in sensitive_endpoints):
            # Check for authentication headers
            auth_headers = ['authorization', 'x-api-key', 'x-auth-token']
            has_auth = any(h.lower() in headers for h in auth_headers)
            
            if not has_auth and method in ['POST', 'PUT', 'DELETE', 'PATCH']:
                analyzed.append({
                    'type': 'BROKEN_AUTH',
                    'pattern': 'MISSING_AUTH',
                    'severity': 'HIGH',
                    'confidence': 0.7,
                    'description': 'Sensitive endpoint accessed without authentication',
                    'component': 'headers',
                    'match': 'No authentication headers',
                    'mitigation': 'Implement proper authentication for all sensitive endpoints'
                })
        
        return analyzed
    
    def _analyze_generic(self, threats: List[Dict], features: Dict) -> List[Dict]:
        """Generic threat analysis for unknown threat types"""
        return threats  # Return as-is for generic threats
    
    def _calculate_threat_level(self, threats: List[Dict]) -> float:
        """Calculate overall threat level from detected threats"""
        if not threats:
            return 0.0
        
        # Calculate weighted sum based on severity and confidence
        weighted_sum = 0.0
        total_weight = 0.0
        
        for threat in threats:
            severity = threat.get('severity', 'MEDIUM')
            confidence = threat.get('confidence', 0.5)
            
            severity_weight = self.severity_weights.get(severity, 0.5)
            threat_weight = severity_weight * confidence
            
            weighted_sum += threat_weight
            total_weight += severity_weight
        
        if total_weight == 0:
            return 0.0
        
        # Normalize to [0, 1]
        threat_level = weighted_sum / total_weight
        
        # Apply non-linear scaling (more sensitive to high threats)
        threat_level = threat_level ** 0.7
        
        return min(1.0, threat_level)
    
    def _calculate_confidence(self, threats: List[Dict]) -> float:
        """Calculate overall confidence from detected threats"""
        if not threats:
            return 0.0
        
        # Average confidence of all threats
        confidences = [t.get('confidence', 0.5) for t in threats]
        
        # Weight by severity
        weights = []
        for threat in threats:
            severity = threat.get('severity', 'MEDIUM')
            weights.append(self.severity_weights.get(severity, 0.5))
        
        # Calculate weighted average
        total_weight = sum(weights)
        if total_weight == 0:
            return np.mean(confidences)
        
        weighted_sum = sum(c * w for c, w in zip(confidences, weights))
        confidence = weighted_sum / total_weight
        
        # Adjust based on number of threats (more threats = higher confidence)
        if len(threats) > 1:
            confidence = min(1.0, confidence * (1 + 0.1 * len(threats)))
        
        return confidence
    
    def _determine_primary_threat(self, threats: List[Dict]) -> str:
        """Determine primary threat type from detected threats"""
        if not threats:
            return 'UNKNOWN'
        
        # Count threats by type
        threat_counts = defaultdict(int)
        for threat in threats:
            threat_type = threat.get('type', 'UNKNOWN')
            threat_counts[threat_type] += 1
        
        # Get most common threat type
        if threat_counts:
            primary = max(threat_counts.items(), key=lambda x: x[1])[0]
            return primary
        
        return 'UNKNOWN'
    
    def _generate_evidence(self, threats: List[Dict]) -> List[Dict[str, Any]]:
        """Generate evidence from detected threats"""
        evidence = []
        
        for threat in threats[:10]:  # Limit to 10 threats
            evidence.append({
                'type': threat.get('type', 'UNKNOWN'),
                'description': threat.get('description', 'Unknown threat'),
                'severity': threat.get('severity', 'MEDIUM'),
                'confidence': threat.get('confidence', 0.5),
                'component': threat.get('component', 'unknown'),
                'pattern': threat.get('pattern', 'unknown'),
                'match_preview': threat.get('match', '')[:50]
            })
        
        return evidence
    
    def _generate_recommendations(self, threats: List[Dict]) -> List[SecurityRecommendation]:
        """Generate security recommendations from detected threats"""
        from .response_parser import SecurityRecommendation
        
        recommendations = []
        added_mitigations = set()
        
        for threat in threats[:5]:  # Limit to top 5 threats
            mitigation = threat.get('mitigation', '')
            threat_type = threat.get('type', '')
            
            if mitigation and mitigation not in added_mitigations:
                recommendations.append(
                    SecurityRecommendation(
                        title=f"Mitigate {threat_type}",
                        description=mitigation,
                        priority=threat.get('severity', 'MEDIUM'),
                        category=threat_type.lower(),
                        action_items=[
                            "Review affected code",
                            "Implement suggested controls",
                            "Test mitigation effectiveness"
                        ]
                    )
                )
                added_mitigations.add(mitigation)
        
        # Add general recommendations
        if threats:
            recommendations.append(
                SecurityRecommendation(
                    title="General Security Hardening",
                    description="Implement defense-in-depth security controls",
                    priority="MEDIUM",
                    category="general",
                    action_items=[
                        "Enable WAF rules",
                        "Implement rate limiting",
                        "Enable security logging",
                        "Conduct regular security testing"
                    ]
                )
            )
        
        return recommendations
    
    def _determine_severity(self, threat_level: float, confidence: float) -> str:
        """Determine overall severity based on threat level and confidence"""
        adjusted_threat = threat_level * confidence
        
        if adjusted_threat >= 0.9:
            return 'CRITICAL'
        elif adjusted_threat >= 0.7:
            return 'HIGH'
        elif adjusted_threat >= 0.5:
            return 'MEDIUM'
        elif adjusted_threat >= 0.3:
            return 'LOW'
        else:
            return 'INFO'
    
    def get_threat_statistics(self) -> Dict[str, Any]:
        """Get statistics about detected threats"""
        # This would track statistics over time
        # For now, return basic info
        return {
            'pattern_count': len(self.threat_intel.patterns),
            'analyzers_available': list(self.analyzers.keys()),
            'severity_weights': self.severity_weights,
            'confidence_calibration': self.confidence_calibration
        }