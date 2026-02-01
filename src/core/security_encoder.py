# src/core/security_encoder.py
"""
Security Feature Encoder for CyberGuard

This module converts raw security data (HTTP requests, logs, headers) into
numerical feature vectors that can be processed by the GQA Transformer.

Key capabilities:
1. HTTP request/response parsing and feature extraction
2. Attack pattern encoding (OWASP Top-10, CWE, CAPEC)
3. Behavioral feature extraction from traffic logs
4. Real-time encoding for streaming security data

Security importance:
- Converts diverse security data types into unified numerical representation
- Preserves critical security context during encoding
- Handles both structured and unstructured security data
- Supports real-time encoding for live traffic analysis
"""

import re
import json
import hashlib
import urllib.parse
from typing import Dict, List, Any, Optional, Tuple, Union
import numpy as np
import torch
import torch.nn as nn
from collections import defaultdict, Counter
import base64
import zlib
import ipaddress
import pickle  # Added missing import for save/load vocabulary


class SecurityFeatureEncoder:
    """
    Main encoder for converting security data to feature vectors
    
    Processing pipeline:
    1. Raw security data (HTTP, logs, headers) → Parsing
    2. Parsed data → Feature extraction
    3. Features → Numerical encoding
    4. Encoded features → Transformer input
    
    Security features encoded:
    - Request methods, paths, parameters
    - Headers and their values
    - Body content and structure
    - Attack patterns and signatures
    - Behavioral anomalies
    - Compliance violations
    """
    
    def __init__(self, vocab_size: int = 10000, max_seq_len: int = 512,
                 feature_dim: int = 512, use_embedding: bool = True):
        """
        Initialize security feature encoder
        
        Args:
            vocab_size: Size of feature vocabulary
            max_seq_len: Maximum sequence length for encoding
            feature_dim: Dimension of output feature vectors
            use_embedding: Whether to use learnable embeddings
        
        Example:
            >>> encoder = SecurityFeatureEncoder(vocab_size=10000)
        """
        self.vocab_size = vocab_size
        self.max_seq_len = max_seq_len
        self.feature_dim = feature_dim
        
        # Attack pattern database - loads regex patterns for different attack types
        self.attack_patterns = self._load_attack_patterns()
        
        # Feature vocabulary - maps feature strings to integer IDs
        self.feature_vocab = {}
        # Reverse vocabulary - maps integer IDs back to feature strings
        self.reverse_vocab = {}
        self.next_vocab_id = 0  # Tracks next available ID for new features
        
        # Initialize with common security features (HTTP methods, headers, etc.)
        self._initialize_vocabulary()
        
        # Learnable embeddings if enabled - converts integer IDs to dense vectors
        if use_embedding:
            self.embedding = nn.Embedding(vocab_size, feature_dim)
            # Initialize embedding weights with normal distribution
            nn.init.normal_(self.embedding.weight, mean=0.0, std=0.02)
        else:
            self.embedding = None
        
        # Feature extractors for different data types - maps data type to extraction function
        self.extractors = {
            'http_request': self._extract_http_features,
            'http_response': self._extract_response_features,
            'headers': self._extract_header_features,
            'parameters': self._extract_parameter_features,
            'body': self._extract_body_features,
            'traffic_log': self._extract_traffic_features,
            'javascript': self._extract_javascript_features,
        }
        
        # Feature normalization statistics - tracks mean/std for numerical features
        self.feature_stats = defaultdict(lambda: {'mean': 0.0, 'std': 1.0, 'count': 0})
        
        # Cache for performance - stores recently computed feature vectors
        self.feature_cache = {}
        self.cache_max_size = 1000  # Maximum number of entries to cache
        
    def _load_attack_patterns(self) -> Dict[str, List[str]]:
        """
        Load common attack patterns and signatures
        
        Returns:
            Dictionary of attack patterns by category
        
        Security note: These patterns should be regularly updated from
        threat intelligence feeds (CVE, CAPEC, OWASP)
        """
        return {
            'xss': [
                r'<script[^>]*>.*?</script>',  # Basic script tag patterns
                r'javascript:',  # JavaScript protocol in URLs
                r'onload\s*=',  # Event handler attributes
                r'onerror\s*=',
                r'onclick\s*=',
                r'eval\s*\(',  # JavaScript eval function
                r'alert\s*\(',  # Alert function often used in XSS tests
                r'document\.cookie',  # Cookie access attempts
                r'window\.location',  # Page redirection attempts
                r'innerHTML\s*=',  # Direct DOM manipulation
            ],
            'sql_injection': [
                r"'\s+OR\s+'.*'='",  # Basic SQL injection pattern
                r"UNION\s+SELECT",  # UNION-based SQL injection
                r";\s*DROP\s+TABLE",  # Table deletion attempts
                r"--\s*$",  # SQL comment to truncate query
                r"'\s+AND\s+'.*'='",
                r"EXEC\s*\(",  # Stored procedure execution
                r"xp_cmdshell",  # MSSQL command execution
                r"SELECT\s+\*\s+FROM",  # Generic SELECT statements
                r"INSERT\s+INTO",
                r"DELETE\s+FROM",
            ],
            'command_injection': [
                r";\s*(ls|dir|cat|type)\s+",  # Command chaining with file operations
                r"\|\s*(ls|dir|cat|type)\s+",  # Pipe operators with commands
                r"`.*`",  # Backticks for command substitution
                r"\$\(.*\)",  # Command substitution in bash
                r"exec\(.*\)",  # Python/Ruby exec functions
                r"system\(.*\)",  # System command execution
                r"popen\(.*\)",  # Pipe opening for commands
                r"shell_exec\(.*\)",  # PHP shell execution
            ],
            'path_traversal': [
                r"\.\./",  # Directory traversal patterns
                r"\.\.\\",  # Windows directory traversal
                r"/etc/passwd",  # Sensitive Unix file
                r"C:\\Windows\\",  # Windows system directory
                r"/proc/self/",  # Linux proc filesystem
                r"file://",  # File protocol URLs
                r"\\..\\",  # Alternative Windows traversal
            ],
            'csrf': [
                r"cross-site request",  # CSRF attack descriptions
                r"state-changing.*without.*token",  # Token bypass patterns
                r"missing.*referer",  # Missing referer header
                r"origin.*mismatch",  # Origin header mismatch
            ],
            'ssrf': [
                r"localhost",  # Localhost references
                r"127\.0\.0\.1",  # Loopback IP addresses
                r"192\.168\.",  # Private network ranges
                r"10\.\.",
                r"172\.(1[6-9]|2[0-9]|3[0-1])\.",
                r"internal",  # Internal domain references
                r"private",
                r"metadata\.google\.internal",  # Cloud metadata endpoints
                r"169\.254\.169\.254",  # AWS metadata endpoint
            ],
            'xxe': [
                r"<!ENTITY",  # XML entity declarations
                r"SYSTEM",  # External entity references
                r"PUBLIC",
                r"]>",  # DTD closing
                r"xmlns:",  # XML namespace declarations
                r"<!DOCTYPE",  # Document type declarations
            ],
        }
    
    def _initialize_vocabulary(self):
        """
        Initialize vocabulary with common security features
        
        This creates a mapping from security features to numerical IDs
        """
        # Common HTTP methods - each gets a unique feature ID
        http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE']
        for method in http_methods:
            self._add_to_vocab(f'HTTP_METHOD_{method}')
        
        # Common HTTP status codes
        status_codes = ['200', '301', '302', '400', '401', '403', '404', '500', '503']
        for code in status_codes:
            self._add_to_vocab(f'STATUS_{code}')
        
        # Security headers - important for security posture analysis
        security_headers = [
            'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options',
            'X-XSS-Protection', 'Strict-Transport-Security', 'Referrer-Policy',
            'Permissions-Policy', 'Cross-Origin-Opener-Policy',
            'Cross-Origin-Embedder-Policy', 'Cross-Origin-Resource-Policy',
        ]
        for header in security_headers:
            # Convert header names to consistent format (uppercase with underscores)
            self._add_to_vocab(f'HEADER_{header.upper().replace("-", "_")}')
        
        # Attack types - for labeling detected attacks
        attack_types = [
            'XSS', 'SQL_INJECTION', 'COMMAND_INJECTION', 'PATH_TRAVERSAL',
            'CSRF', 'SSRF', 'XXE', 'IDOR', 'RCE', 'LFI', 'RFI',
            'DESERIALIZATION', 'AUTH_BYPASS', 'SESSION_HIJACKING',
            'CREDENTIAL_STUFFING', 'BRUTE_FORCE', 'DOS', 'DDOS',
        ]
        for attack in attack_types:
            self._add_to_vocab(f'ATTACK_{attack}')
        
        # Common file extensions - can indicate attack targets or file uploads
        extensions = [
            '.php', '.asp', '.aspx', '.jsp', '.js', '.html', '.htm',
            '.xml', '.json', '.txt', '.log', '.config', '.env',
            '.sql', '.bak', '.old', '.tmp', '.swp',
        ]
        for ext in extensions:
            self._add_to_vocab(f'EXT_{ext.upper().replace(".", "")}')
        
        # Special tokens - for sequence processing
        special_tokens = ['[PAD]', '[UNK]', '[CLS]', '[SEP]', '[MASK]']
        for token in special_tokens:
            self._add_to_vocab(token)
    
    def _add_to_vocab(self, feature: str) -> int:
        """
        Add a feature to vocabulary
        
        Args:
            feature: Feature string to add
        
        Returns:
            int: Assigned vocabulary ID
        """
        if feature not in self.feature_vocab:
            # Assign new ID and update both forward and reverse mappings
            self.feature_vocab[feature] = self.next_vocab_id
            self.reverse_vocab[self.next_vocab_id] = feature
            self.next_vocab_id += 1
        return self.feature_vocab[feature]
    
    def encode_http_request(self, request_data: Dict[str, Any]) -> torch.Tensor:
        """
        Encode HTTP request data into feature tensor
        
        Args:
            request_data: Dictionary containing HTTP request information
        
        Returns:
            torch.Tensor: Encoded features [max_seq_len]
        
        Example:
            >>> request = {
            ...     'method': 'POST',
            ...     'url': 'https://example.com/login',
            ...     'headers': {'Content-Type': 'application/json'},
            ...     'body': '{"username": "admin", "password": "test"}'
            ... }
            >>> features = encoder.encode_http_request(request)
        """
        # Generate cache key based on request content
        cache_key = self._generate_cache_key(request_data)
        
        # Check cache for previously computed features
        if cache_key in self.feature_cache:
            return self.feature_cache[cache_key]
        
        # Extract features - each function returns a list of feature IDs
        feature_ids = []
        
        # 1. HTTP method - basic request type
        method = request_data.get('method', 'GET').upper()
        method_id = self._add_to_vocab(f'HTTP_METHOD_{method}')
        feature_ids.append(method_id)
        
        # 2. URL path features - extract domain, path, parameters
        url = request_data.get('url', '')
        url_features = self._extract_url_features(url)
        feature_ids.extend(url_features)
        
        # 3. Header features - security headers, suspicious values
        headers = request_data.get('headers', {})
        header_features = self._extract_header_features(headers)
        feature_ids.extend(header_features)
        
        # 4. Parameter features - query and form parameters
        params = request_data.get('parameters', {})
        param_features = self._extract_parameter_features(params)
        feature_ids.extend(param_features)
        
        # 5. Body features - request payload analysis
        body = request_data.get('body', '')
        body_features = self._extract_body_features(body)
        feature_ids.extend(body_features)
        
        # 6. Attack pattern detection - check for known attack signatures
        attack_features = self._detect_attack_patterns(request_data)
        feature_ids.extend(attack_features)
        
        # 7. Behavioral features - IP, timing, frequency patterns
        behavioral_features = self._extract_behavioral_features(request_data)
        feature_ids.extend(behavioral_features)
        
        # 8. Add special tokens for transformer processing
        # [CLS] at beginning, [SEP] at end for sequence classification
        feature_ids = [self.feature_vocab['[CLS]']] + feature_ids + [self.feature_vocab['[SEP]']]
        
        # Truncate or pad to max_seq_len for consistent tensor size
        if len(feature_ids) > self.max_seq_len:
            feature_ids = feature_ids[:self.max_seq_len]
        else:
            padding_needed = self.max_seq_len - len(feature_ids)
            # Pad with [PAD] tokens to reach max_seq_len
            feature_ids = feature_ids + [self.feature_vocab['[PAD]']] * padding_needed
        
        # Convert list of IDs to PyTorch tensor
        feature_tensor = torch.tensor(feature_ids, dtype=torch.long)
        
        # Cache result for future identical requests
        self._update_cache(cache_key, feature_tensor)
        
        return feature_tensor
    
    def _extract_url_features(self, url: str) -> List[int]:
        """
        Extract features from URL
        
        Args:
            url: URL string
        
        Returns:
            List of feature IDs
        """
        features = []
        
        try:
            # Parse URL into components using standard library
            parsed = urllib.parse.urlparse(url)
            
            # Scheme (http, https, ftp, etc.)
            scheme_id = self._add_to_vocab(f'SCHEME_{parsed.scheme.upper()}')
            features.append(scheme_id)
            
            # Netloc (domain) - extract domain and TLD
            domain_parts = parsed.netloc.split('.')
            for part in domain_parts[-2:]:  # Last two parts (domain and TLD)
                if part:
                    domain_id = self._add_to_vocab(f'DOMAIN_{part.upper()}')
                    features.append(domain_id)
            
            # Path components - analyze directory structure
            path = parsed.path
            if path:
                # Split path and extract features from components
                path_parts = [p for p in path.split('/') if p]
                for part in path_parts[:5]:  # First 5 path components
                    # Check for alphanumeric path components
                    if re.match(r'^[a-zA-Z0-9_\-]+$', part):
                        path_id = self._add_to_vocab(f'PATH_{part.upper()}')
                        features.append(path_id)
                    
                    # Check for file extensions in path
                    if '.' in part:
                        ext = part.split('.')[-1].lower()
                        if len(ext) <= 5:  # Reasonable extension length
                            ext_id = self._add_to_vocab(f'EXT_{ext.upper()}')
                            features.append(ext_id)
            
            # Query parameters - analyze URL parameters
            query = parsed.query
            if query:
                # Count number of parameters
                param_count = len(urllib.parse.parse_qs(query))
                if param_count > 10:
                    features.append(self._add_to_vocab('MANY_PARAMS'))
                elif param_count > 0:
                    features.append(self._add_to_vocab('HAS_PARAMS'))
                
                # Check for sensitive parameter names
                sensitive_params = ['password', 'token', 'key', 'secret', 'auth']
                for param in sensitive_params:
                    if param in query.lower():
                        features.append(self._add_to_vocab(f'SENSITIVE_PARAM_{param.upper()}'))
            
            # Fragment identifier
            if parsed.fragment:
                features.append(self._add_to_vocab('HAS_FRAGMENT'))
        
        except Exception as e:
            # If URL parsing fails, add error feature
            features.append(self._add_to_vocab('URL_PARSE_ERROR'))
        
        return features
    
    def _extract_header_features(self, headers: Dict[str, str]) -> List[int]:
        """
        Extract features from HTTP headers
        
        Args:
            headers: Dictionary of HTTP headers
        
        Returns:
            List of feature IDs
        """
        features = []
        
        # Track security headers for summary feature
        security_headers_present = []
        for header, value in headers.items():
            # Normalize header name for consistent feature naming
            header_upper = header.upper().replace('-', '_')
            
            # Add header presence feature
            header_id = self._add_to_vocab(f'HEADER_{header_upper}')
            features.append(header_id)
            
            # Check for important security headers
            if header.lower() in [
                'content-security-policy',
                'x-frame-options',
                'x-content-type-options',
                'strict-transport-security',
            ]:
                security_headers_present.append(header_upper)
            
            # Check for suspicious values in specific headers
            self._check_suspicious_header_value(header, value, features)
        
        # Security header summary features
        if len(security_headers_present) >= 3:
            features.append(self._add_to_vocab('GOOD_SECURITY_HEADERS'))
        elif len(security_headers_present) == 0:
            features.append(self._add_to_vocab('NO_SECURITY_HEADERS'))
        
        # Check for missing important headers
        important_headers = ['content-type', 'cache-control', 'pragma']
        for header in important_headers:
            if header not in headers:
                features.append(self._add_to_vocab(f'MISSING_{header.upper().replace("-", "_")}'))
        
        return features
    
    def _check_suspicious_header_value(self, header: str, value: str, features: List[int]):
        """
        Check for suspicious header values
        
        Args:
            header: Header name
            value: Header value
            features: List to add suspicious features to
        """
        header_lower = header.lower()
        value_lower = value.lower()
        
        # User-Agent anomalies - check for scanning tools or unusual agents
        if header_lower == 'user-agent':
            suspicious_agents = [
                'curl', 'wget', 'python', 'scanner', 'nmap',
                'sqlmap', 'nikto', 'burp', 'zap', 'dirbuster',
            ]
            for agent in suspicious_agents:
                if agent in value_lower:
                    features.append(self._add_to_vocab(f'SUSPICIOUS_UA_{agent.upper()}'))
        
        # Content-Type anomalies
        elif header_lower == 'content-type':
            if 'text/html' in value_lower and 'charset' not in value_lower:
                features.append(self._add_to_vocab('HTML_NO_CHARSET'))
        
        # Referer anomalies - check for malformed referers
        elif header_lower == 'referer':
            if not value_lower.startswith(('http://', 'https://')):
                features.append(self._add_to_vocab('SUSPICIOUS_REFERER'))
        
        # Origin anomalies - check for dangerous origins
        elif header_lower == 'origin':
            suspicious_origins = ['null', 'file://', 'data:', 'javascript:']
            if any(origin in value_lower for origin in suspicious_origins):
                features.append(self._add_to_vocab('SUSPICIOUS_ORIGIN'))
    
    def _extract_parameter_features(self, parameters: Dict[str, Any]) -> List[int]:
        """
        Extract features from request parameters
        
        Args:
            parameters: Dictionary of request parameters
        
        Returns:
            List of feature IDs
        """
        features = []
        
        if not parameters:
            features.append(self._add_to_vocab('NO_PARAMS'))
            return features
        
        # Parameter count feature - helps detect parameter flooding
        param_count = len(parameters)
        if param_count > 20:
            features.append(self._add_to_vocab('VERY_MANY_PARAMS'))
        elif param_count > 10:
            features.append(self._add_to_vocab('MANY_PARAMS'))
        elif param_count > 0:
            features.append(self._add_to_vocab('HAS_PARAMS'))
        
        # Check individual parameters for sensitive data and attacks
        for param_name, param_value in parameters.items():
            param_name_lower = param_name.lower()
            
            # Sensitive parameter names - check for credential parameters
            sensitive_patterns = [
                'pass', 'token', 'key', 'secret', 'auth',
                'credit', 'ssn', 'social', 'security',
                'card', 'cvv', 'expiry', 'dob', 'birth',
            ]
            
            for pattern in sensitive_patterns:
                if pattern in param_name_lower:
                    features.append(self._add_to_vocab(f'SENSITIVE_PARAM_{pattern.upper()}'))
                    break
            
            # Check parameter values for attack patterns
            if isinstance(param_value, str):
                # Length anomaly - very long parameter values
                if len(param_value) > 1000:
                    features.append(self._add_to_vocab('LONG_PARAM_VALUE'))
                
                # Check for specific attack patterns in parameter values
                attack_features = self._check_parameter_value(param_value)
                features.extend(attack_features)
        
        return features
    
    def _check_parameter_value(self, value: str) -> List[int]:
        """
        Check parameter value for attack patterns
        
        Args:
            value: Parameter value string
        
        Returns:
            List of attack feature IDs
        """
        features = []
        value_lower = value.lower()
        
        # Check each attack pattern category against the parameter value
        for attack_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                if re.search(pattern, value_lower, re.IGNORECASE):
                    feature_name = f'ATTACK_{attack_type.upper()}'
                    features.append(self._add_to_vocab(feature_name))
                    break  # Found one pattern in this category
        
        # Check for encoded/obfuscated attacks
        encoded_patterns = [
            (r'%3Cscript%3E', 'URLENCODED_XSS'),  # URL-encoded <script>
            (r'%27OR%27', 'URLENCODED_SQL'),  # URL-encoded SQL OR
            (r'PHNjcmlwdD4=', 'BASE64_XSS'),  # Base64 encoded <script>
        ]
        
        for pattern, feature in encoded_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                features.append(self._add_to_vocab(feature))
        
        # Check for high frequency of suspicious characters
        suspicious_chars = ['<', '>', "'", '"', ';', '|', '&', '$', '`']
        char_count = sum(1 for char in value if char in suspicious_chars)
        if char_count > 5:
            features.append(self._add_to_vocab('MANY_SUSPICIOUS_CHARS'))
        
        return features
    
    def _extract_body_features(self, body: Union[str, Dict, bytes]) -> List[int]:
        """
        Extract features from request body
        
        Args:
            body: Request body (string, dict, or bytes)
        
        Returns:
            List of feature IDs
        """
        features = []
        
        if not body:
            features.append(self._add_to_vocab('EMPTY_BODY'))
            return features
        
        # Convert body to string for consistent analysis
        body_str = ''
        if isinstance(body, bytes):
            try:
                # Attempt UTF-8 decoding, ignore errors for binary data
                body_str = body.decode('utf-8', errors='ignore')
            except:
                # Fallback to string representation
                body_str = str(body)[:1000]  # Truncate if decoding fails
        elif isinstance(body, dict):
            # Convert dictionary to JSON string
            body_str = json.dumps(body)
        else:
            # Already string or string-convertible
            body_str = str(body)
        
        # Length features - detect unusually large requests
        body_length = len(body_str)
        if body_length > 1000000:  # 1MB
            features.append(self._add_to_vocab('VERY_LARGE_BODY'))
        elif body_length > 100000:  # 100KB
            features.append(self._add_to_vocab('LARGE_BODY'))
        elif body_length > 0:
            features.append(self._add_to_vocab('HAS_BODY'))
        
        # Content type detection based on structure
        stripped_body = body_str.strip()
        if stripped_body.startswith('{') and stripped_body.endswith('}'):
            features.append(self._add_to_vocab('JSON_BODY'))
            # Check for deeply nested JSON (potential for parser attacks)
            if body_str.count('{') > 5:
                features.append(self._add_to_vocab('DEEP_JSON'))
        
        elif stripped_body.startswith('<') and stripped_body.endswith('>'):
            features.append(self._add_to_vocab('XML_BODY'))
        
        elif '=' in body_str and '&' in body_str:
            features.append(self._add_to_vocab('FORM_URLENCODED'))
        
        # Check for attack patterns in body content
        body_lower = body_str.lower()
        for attack_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                if re.search(pattern, body_lower, re.IGNORECASE):
                    feature_name = f'BODY_ATTACK_{attack_type.upper()}'
                    features.append(self._add_to_vocab(feature_name))
                    break
        
        # Check for file upload patterns (multipart form data)
        file_patterns = [
            r'Content-Disposition.*filename',
            r'------WebKitFormBoundary',
            r'multipart/form-data',
        ]
        for pattern in file_patterns:
            if re.search(pattern, body_str, re.IGNORECASE):
                features.append(self._add_to_vocab('FILE_UPLOAD'))
                break
        
        return features
    
    def _detect_attack_patterns(self, request_data: Dict[str, Any]) -> List[int]:
        """
        Detect attack patterns across the entire request
        
        Args:
            request_data: Complete request data
        
        Returns:
            List of attack feature IDs
        """
        features = []
        
        # Combine all text components for comprehensive pattern matching
        all_text = []
        
        # URL
        url = request_data.get('url', '')
        all_text.append(url)
        
        # Headers as key:value pairs
        headers = request_data.get('headers', {})
        for header, value in headers.items():
            all_text.append(f"{header}: {value}")
        
        # Parameters
        params = request_data.get('parameters', {})
        for param, value in params.items():
            all_text.append(f"{param}={value}")
        
        # Body content
        body = request_data.get('body', '')
        if isinstance(body, (str, bytes)):
            all_text.append(str(body))
        
        # Join all text for pattern matching
        combined_text = ' '.join(all_text).lower()
        
        # Check combined text against all attack patterns
        for attack_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    feature_name = f'DETECTED_{attack_type.upper()}'
                    features.append(self._add_to_vocab(feature_name))
                    break  # Found one pattern in this category
        
        return features
    
    def _extract_behavioral_features(self, request_data: Dict[str, Any]) -> List[int]:
        """
        Extract behavioral features from request
        
        Args:
            request_data: Request data dictionary
        
        Returns:
            List of behavioral feature IDs
        """
        features = []
        
        # Request timing analysis (requires timestamp data)
        timestamp = request_data.get('timestamp')
        if timestamp:
            # This would require request history context for time-based analysis
            # Placeholder for time-based anomaly detection
            pass
        
        # IP address analysis
        ip = request_data.get('ip_address')
        if ip:
            try:
                # Parse IP address to determine its properties
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_private:
                    features.append(self._add_to_vocab('PRIVATE_IP'))
                if ip_obj.is_loopback:
                    features.append(self._add_to_vocab('LOOPBACK_IP'))
                if ip_obj.is_multicast:
                    features.append(self._add_to_vocab('MULTICAST_IP'))
            except ValueError:
                # Invalid IP address format
                pass
        
        # User agent analysis
        user_agent = request_data.get('headers', {}).get('User-Agent', '')
        if user_agent:
            # Very short user agents are suspicious
            if len(user_agent) < 10:
                features.append(self._add_to_vocab('SHORT_USER_AGENT'))
            # Non-standard user agents (not containing Mozilla)
            if 'mozilla' not in user_agent.lower():
                features.append(self._add_to_vocab('NON_STANDARD_UA'))
        
        # Referer analysis for CSRF detection
        referer = request_data.get('headers', {}).get('Referer', '')
        if referer:
            url = request_data.get('url', '')
            if referer and url:
                # Check if referer is valid for the target URL
                if not self._is_valid_referer(referer, url):
                    features.append(self._add_to_vocab('SUSPICIOUS_REFERER'))
        
        return features
    
    def _is_valid_referer(self, referer: str, current_url: str) -> bool:
        """
        Check if referer is valid for current URL
        
        Args:
            referer: Referer URL
            current_url: Current request URL
        
        Returns:
            bool: True if referer appears valid
        """
        try:
            # Parse both URLs for comparison
            referer_parsed = urllib.parse.urlparse(referer)
            current_parsed = urllib.parse.urlparse(current_url)
            
            # Same origin - referer from same domain
            if referer_parsed.netloc == current_parsed.netloc:
                return True
            
            # Empty referer (direct navigation, bookmark)
            if not referer:
                return True
            
            # Check against common legitimate referers (search engines, social media)
            common_referers = [
                'google.com', 'bing.com', 'yahoo.com', 'duckduckgo.com',
                'facebook.com', 'twitter.com', 'linkedin.com', 'reddit.com',
            ]
            
            for domain in common_referers:
                if domain in referer_parsed.netloc:
                    return True
            
            # If none of the above, referer might be suspicious
            return False
        except:
            # If parsing fails, assume invalid
            return False
    
    def _generate_cache_key(self, data: Dict[str, Any]) -> str:
        """
        Generate cache key for request data
        
        Args:
            data: Request data dictionary
        
        Returns:
            str: Cache key
        """
        # Create deterministic string representation using MD5 hashes
        key_parts = []
        
        # URL hash (first 8 chars of MD5)
        url = data.get('url', '')
        key_parts.append(f"url:{hashlib.md5(url.encode()).hexdigest()[:8]}")
        
        # HTTP method
        method = data.get('method', 'GET')
        key_parts.append(f"method:{method}")
        
        # Headers hash (sorted for consistency)
        headers = data.get('headers', {})
        headers_str = json.dumps(sorted(headers.items()), sort_keys=True)
        key_parts.append(f"headers:{hashlib.md5(headers_str.encode()).hexdigest()[:8]}")
        
        # Body hash (truncated to first 100 chars for performance)
        body = data.get('body', '')
        if isinstance(body, (str, bytes)):
            body_str = str(body)[:100]  # First 100 chars
            key_parts.append(f"body:{hashlib.md5(body_str.encode()).hexdigest()[:8]}")
        
        # Join all parts with pipe separator
        return '|'.join(key_parts)
    
    def _update_cache(self, key: str, value: torch.Tensor):
        """
        Update feature cache with FIFO eviction
        
        Args:
            key: Cache key
            value: Cached value
        """
        # If cache is full, remove oldest entry (FIFO)
        if len(self.feature_cache) >= self.cache_max_size:
            # Get first key (oldest in Python 3.7+ dict maintains insertion order)
            oldest_key = next(iter(self.feature_cache))
            del self.feature_cache[oldest_key]
        
        # Add new entry to cache
        self.feature_cache[key] = value
    
    def get_embeddings(self, feature_ids: torch.Tensor) -> torch.Tensor:
        """
        Convert feature IDs to embeddings
        
        Args:
            feature_ids: Tensor of feature IDs [seq_len] or [batch_size, seq_len]
        
        Returns:
            torch.Tensor: Feature embeddings
        
        Example:
            >>> features = encoder.encode_http_request(request_data)
            >>> embeddings = encoder.get_embeddings(features)
        """
        if self.embedding is None:
            raise ValueError("Encoder was initialized with use_embedding=False")
        
        # Use embedding layer to convert integer IDs to dense vectors
        return self.embedding(feature_ids)
    
    def decode_features(self, feature_ids: List[int]) -> List[str]:
        """
        Convert feature IDs back to human-readable features
        
        Args:
            feature_ids: List of feature IDs
        
        Returns:
            List of feature strings
        
        Example:
            >>> ids = [1, 2, 3, 4]
            >>> features = encoder.decode_features(ids)
        """
        # Map each ID to its string representation, defaulting to [UNK:ID] for unknown IDs
        return [self.reverse_vocab.get(id, f'[UNK:{id}]') for id in feature_ids]
    
    def get_vocabulary_size(self) -> int:
        """
        Get current vocabulary size
        
        Returns:
            int: Number of features in vocabulary
        """
        return len(self.feature_vocab)
    
    def save_vocabulary(self, filepath: str):
        """
        Save vocabulary to file
        
        Args:
            filepath: Path to save vocabulary
        """
        # Use pickle to serialize vocabulary data
        with open(filepath, 'wb') as f:
            pickle.dump({
                'feature_vocab': self.feature_vocab,
                'reverse_vocab': self.reverse_vocab,
                'next_vocab_id': self.next_vocab_id,
            }, f)
    
    def load_vocabulary(self, filepath: str):
        """
        Load vocabulary from file
        
        Args:
            filepath: Path to vocabulary file
        """
        # Load and deserialize vocabulary data
        with open(filepath, 'rb') as f:
            data = pickle.load(f)
        
        # Restore vocabulary state
        self.feature_vocab = data['feature_vocab']
        self.reverse_vocab = data['reverse_vocab']
        self.next_vocab_id = data['next_vocab_id']


class StreamingSecurityEncoder(SecurityFeatureEncoder):
    """
    Streaming encoder for real-time security analysis
    
    Extends the base encoder with:
    1. Incremental feature extraction
    2. Sliding window processing
    3. Real-time attack detection
    4. Memory-efficient encoding for high-volume traffic
    """
    
    def __init__(self, window_size: int = 100, *args, **kwargs):
        """
        Initialize streaming encoder
        
        Args:
            window_size: Size of sliding window for feature aggregation
            *args, **kwargs: Passed to parent constructor
        """
        super().__init__(*args, **kwargs)
        self.window_size = window_size
        self.request_window = []  # Stores recent raw requests
        self.feature_window = []  # Stores recent feature tensors
        
        # Statistics for adaptive thresholding and anomaly detection
        self.request_stats = {
            'count': 0,           # Total request count
            'avg_features': 0.0,  # Exponential moving average of feature count
            'attack_rate': 0.0,   # Exponential moving average of attack probability
        }
    
    def encode_streaming(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Encode request in streaming mode with context
        
        Args:
            request_data: Request data dictionary
        
        Returns:
            Dict with encoded features and streaming context
        """
        # Encode current request using parent class method
        current_features = self.encode_http_request(request_data)
        
        # Update sliding windows with new data
        self.request_window.append(request_data)
        self.feature_window.append(current_features)
        
        # Maintain window size by removing oldest entries
        if len(self.request_window) > self.window_size:
            self.request_window.pop(0)
            self.feature_window.pop(0)
        
        # Update streaming statistics with exponential moving averages
        self._update_statistics(request_data)
        
        # Calculate context features from recent request window
        context_features = self._extract_context_features()
        
        # Return comprehensive streaming analysis
        return {
            'current_features': current_features,  # Features of current request
            'context_features': context_features,  # Aggregated window features
            'window_size': len(self.request_window),  # Current window size
            'stats': self.request_stats.copy(),  # Current statistics snapshot
            'anomaly_score': self._calculate_anomaly_score(request_data),  # Anomaly score 0-1
        }
    
    def _update_statistics(self, request_data: Dict[str, Any]):
        """Update streaming statistics with exponential moving averages"""
        self.request_stats['count'] += 1
        
        # Update average parameter count (90% old, 10% new)
        feature_count = len(request_data.get('parameters', {}))
        self.request_stats['avg_features'] = (
            self.request_stats['avg_features'] * 0.9 + feature_count * 0.1
        )
        
        # Update attack rate based on current request
        if self._has_attack_patterns(request_data):
            # Increase attack rate (95% old, 5% new)
            self.request_stats['attack_rate'] = (
                self.request_stats['attack_rate'] * 0.95 + 0.05
            )
        else:
            # Decrease attack rate (99% old, 1% new)
            self.request_stats['attack_rate'] = (
                self.request_stats['attack_rate'] * 0.99
            )
    
    def _has_attack_patterns(self, request_data: Dict[str, Any]) -> bool:
        """Check if request has attack patterns (simplified detection)"""
        all_text = []
        
        # Extract text from URL
        url = request_data.get('url', '')
        all_text.append(url)
        
        # Extract text from body (truncated)
        body = request_data.get('body', '')
        if body:
            all_text.append(str(body)[:1000])
        
        # Combine text for pattern matching
        combined_text = ' '.join(all_text).lower()
        
        # Check against all attack patterns
        for patterns in self.attack_patterns.values():
            for pattern in patterns:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    return True
        
        return False
    
    def _extract_context_features(self) -> torch.Tensor:
        """Extract features from current window context"""
        if not self.feature_window:
            # Return zeros if window is empty
            return torch.zeros(self.max_seq_len, dtype=torch.long)
        
        # Combine features from window by averaging
        # Stack all feature tensors in window
        stacked = torch.stack(self.feature_window)
        # Compute mean across window dimension
        context = stacked.mean(dim=0).long()
        
        return context
    
    def _calculate_anomaly_score(self, request_data: Dict[str, Any]) -> float:
        """Calculate anomaly score for current request (0.0 to 1.0)"""
        score = 0.0
        
        # Only calculate if we have enough historical data
        if len(self.request_window) > 10:
            # Check for parameter count anomaly
            param_count = len(request_data.get('parameters', {}))
            avg_params = self.request_stats['avg_features']
            
            # Parameter count significantly higher than average
            if param_count > avg_params * 3:
                score += 0.3
            elif param_count > avg_params * 2:
                score += 0.1
            
            # Attack rate anomaly: attack when attack rate is normally low
            current_has_attack = self._has_attack_patterns(request_data)
            if current_has_attack and self.request_stats['attack_rate'] < 0.1:
                score += 0.4
        
        # Request size anomaly - very large request bodies
        body_size = len(str(request_data.get('body', '')))
        if body_size > 100000:  # 100KB
            score += 0.2
        
        # Ensure score doesn't exceed 1.0
        return min(1.0, score)


def test_security_encoder():
    """
    Test security feature encoder with example malicious request
    """
    print("Testing Security Encoder...")
    
    # Create encoder instance
    encoder = SecurityFeatureEncoder(vocab_size=10000, max_seq_len=256)
    
    # Test request with SQL injection attempt
    test_request = {
        'method': 'POST',
        'url': 'https://example.com/login?redirect=/admin',
        'headers': {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'X-CSRF-Token': 'abc123',
        },
        'parameters': {
            'username': 'admin',
            'password': "' OR '1'='1",  # SQL injection payload
            'remember': 'true',
        },
        'body': '{"action": "login", "data": {"user": "admin"}}',
        'ip_address': '192.168.1.100',
    }
    
    # Encode request into feature tensor
    features = encoder.encode_http_request(test_request)
    
    # Verify tensor shape and type
    assert features.shape == (256,), f"Expected shape (256,), got {features.shape}"
    assert features.dtype == torch.long, f"Expected long dtype, got {features.dtype}"
    
    # Decode first 20 features for inspection
    decoded = encoder.decode_features(features.tolist()[:20])
    print(f"   First 10 features: {decoded[:10]}")
    
    # Check that SQL injection was detected in features
    sql_features = [f for f in decoded if 'SQL' in f or 'ATTACK' in f]
    assert len(sql_features) > 0, "SQL injection should have been detected!"
    
    print("Security Encoder tests passed!")
    print(f"   Vocabulary size: {encoder.get_vocabulary_size()}")
    print(f"   Features with attacks: {len(sql_features)}")
    
    # Test streaming encoder functionality
    streaming_encoder = StreamingSecurityEncoder(window_size=50)
    streaming_result = streaming_encoder.encode_streaming(test_request)
    
    # Verify streaming result structure
    assert 'current_features' in streaming_result
    assert 'context_features' in streaming_result
    assert 'anomaly_score' in streaming_result
    
    print("Streaming Encoder tests passed!")
    
    return True


if __name__ == "__main__":
    # Run tests when script is executed directly
    test_security_encoder()