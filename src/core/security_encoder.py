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
        
        # Attack pattern database
        self.attack_patterns = self._load_attack_patterns()
        
        # Feature vocabulary
        self.feature_vocab = {}
        self.reverse_vocab = {}
        self.next_vocab_id = 0
        
        # Initialize with common security features
        self._initialize_vocabulary()
        
        # Learnable embeddings if enabled
        if use_embedding:
            self.embedding = nn.Embedding(vocab_size, feature_dim)
            nn.init.normal_(self.embedding.weight, mean=0.0, std=0.02)
        else:
            self.embedding = None
        
        # Feature extractors for different data types
        self.extractors = {
            'http_request': self._extract_http_features,
            'http_response': self._extract_response_features,
            'headers': self._extract_header_features,
            'parameters': self._extract_parameter_features,
            'body': self._extract_body_features,
            'traffic_log': self._extract_traffic_features,
            'javascript': self._extract_javascript_features,
        }
        
        # Feature normalization statistics
        self.feature_stats = defaultdict(lambda: {'mean': 0.0, 'std': 1.0, 'count': 0})
        
        # Cache for performance
        self.feature_cache = {}
        self.cache_max_size = 1000
        
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
                r'<script[^>]*>.*?</script>',
                r'javascript:',
                r'onload\s*=',
                r'onerror\s*=',
                r'onclick\s*=',
                r'eval\s*\(',
                r'alert\s*\(',
                r'document\.cookie',
                r'window\.location',
                r'innerHTML\s*=',
            ],
            'sql_injection': [
                r"'\s+OR\s+'.*'='",
                r"UNION\s+SELECT",
                r";\s*DROP\s+TABLE",
                r"--\s*$",
                r"'\s+AND\s+'.*'='",
                r"EXEC\s*\(",
                r"xp_cmdshell",
                r"SELECT\s+\*\s+FROM",
                r"INSERT\s+INTO",
                r"DELETE\s+FROM",
            ],
            'command_injection': [
                r";\s*(ls|dir|cat|type)\s+",
                r"\|\s*(ls|dir|cat|type)\s+",
                r"`.*`",
                r"\$\(.*\)",
                r"exec\(.*\)",
                r"system\(.*\)",
                r"popen\(.*\)",
                r"shell_exec\(.*\)",
            ],
            'path_traversal': [
                r"\.\./",
                r"\.\.\\",
                r"/etc/passwd",
                r"C:\\Windows\\",
                r"/proc/self/",
                r"file://",
                r"\\..\\",
            ],
            'csrf': [
                r"cross-site request",
                r"state-changing.*without.*token",
                r"missing.*referer",
                r"origin.*mismatch",
            ],
            'ssrf': [
                r"localhost",
                r"127\.0\.0\.1",
                r"192\.168\.",
                r"10\.\.",
                r"172\.(1[6-9]|2[0-9]|3[0-1])\.",
                r"internal",
                r"private",
                r"metadata\.google\.internal",
                r"169\.254\.169\.254",
            ],
            'xxe': [
                r"<!ENTITY",
                r"SYSTEM",
                r"PUBLIC",
                r"]>",
                r"xmlns:",
                r"<!DOCTYPE",
            ],
        }
    
    def _initialize_vocabulary(self):
        """
        Initialize vocabulary with common security features
        
        This creates a mapping from security features to numerical IDs
        """
        # Common HTTP methods
        http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE']
        for method in http_methods:
            self._add_to_vocab(f'HTTP_METHOD_{method}')
        
        # Common HTTP status codes
        status_codes = ['200', '301', '302', '400', '401', '403', '404', '500', '503']
        for code in status_codes:
            self._add_to_vocab(f'STATUS_{code}')
        
        # Security headers
        security_headers = [
            'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options',
            'X-XSS-Protection', 'Strict-Transport-Security', 'Referrer-Policy',
            'Permissions-Policy', 'Cross-Origin-Opener-Policy',
            'Cross-Origin-Embedder-Policy', 'Cross-Origin-Resource-Policy',
        ]
        for header in security_headers:
            self._add_to_vocab(f'HEADER_{header.upper().replace("-", "_")}')
        
        # Attack types
        attack_types = [
            'XSS', 'SQL_INJECTION', 'COMMAND_INJECTION', 'PATH_TRAVERSAL',
            'CSRF', 'SSRF', 'XXE', 'IDOR', 'RCE', 'LFI', 'RFI',
            'DESERIALIZATION', 'AUTH_BYPASS', 'SESSION_HIJACKING',
            'CREDENTIAL_STUFFING', 'BRUTE_FORCE', 'DOS', 'DDOS',
        ]
        for attack in attack_types:
            self._add_to_vocab(f'ATTACK_{attack}')
        
        # Common file extensions
        extensions = [
            '.php', '.asp', '.aspx', '.jsp', '.js', '.html', '.htm',
            '.xml', '.json', '.txt', '.log', '.config', '.env',
            '.sql', '.bak', '.old', '.tmp', '.swp',
        ]
        for ext in extensions:
            self._add_to_vocab(f'EXT_{ext.upper().replace(".", "")}')
        
        # Special tokens
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
        # Generate cache key
        cache_key = self._generate_cache_key(request_data)
        
        # Check cache
        if cache_key in self.feature_cache:
            return self.feature_cache[cache_key]
        
        # Extract features
        feature_ids = []
        
        # 1. HTTP method
        method = request_data.get('method', 'GET').upper()
        method_id = self._add_to_vocab(f'HTTP_METHOD_{method}')
        feature_ids.append(method_id)
        
        # 2. URL path features
        url = request_data.get('url', '')
        url_features = self._extract_url_features(url)
        feature_ids.extend(url_features)
        
        # 3. Header features
        headers = request_data.get('headers', {})
        header_features = self._extract_header_features(headers)
        feature_ids.extend(header_features)
        
        # 4. Parameter features
        params = request_data.get('parameters', {})
        param_features = self._extract_parameter_features(params)
        feature_ids.extend(param_features)
        
        # 5. Body features
        body = request_data.get('body', '')
        body_features = self._extract_body_features(body)
        feature_ids.extend(body_features)
        
        # 6. Attack pattern detection
        attack_features = self._detect_attack_patterns(request_data)
        feature_ids.extend(attack_features)
        
        # 7. Behavioral features
        behavioral_features = self._extract_behavioral_features(request_data)
        feature_ids.extend(behavioral_features)
        
        # 8. Add special tokens
        feature_ids = [self.feature_vocab['[CLS]']] + feature_ids + [self.feature_vocab['[SEP]']]
        
        # Truncate or pad to max_seq_len
        if len(feature_ids) > self.max_seq_len:
            feature_ids = feature_ids[:self.max_seq_len]
        else:
            padding_needed = self.max_seq_len - len(feature_ids)
            feature_ids = feature_ids + [self.feature_vocab['[PAD]']] * padding_needed
        
        # Convert to tensor
        feature_tensor = torch.tensor(feature_ids, dtype=torch.long)
        
        # Cache result
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
            parsed = urllib.parse.urlparse(url)
            
            # Scheme
            scheme_id = self._add_to_vocab(f'SCHEME_{parsed.scheme.upper()}')
            features.append(scheme_id)
            
            # Netloc (domain)
            domain_parts = parsed.netloc.split('.')
            for part in domain_parts[-2:]:  # Last two parts (domain and TLD)
                if part:
                    domain_id = self._add_to_vocab(f'DOMAIN_{part.upper()}')
                    features.append(domain_id)
            
            # Path components
            path = parsed.path
            if path:
                # Split path and extract features
                path_parts = [p for p in path.split('/') if p]
                for part in path_parts[:5]:  # First 5 path components
                    # Check for common patterns
                    if re.match(r'^[a-zA-Z0-9_\-]+$', part):
                        path_id = self._add_to_vocab(f'PATH_{part.upper()}')
                        features.append(path_id)
                    
                    # Check for file extensions
                    if '.' in part:
                        ext = part.split('.')[-1].lower()
                        if len(ext) <= 5:  # Reasonable extension length
                            ext_id = self._add_to_vocab(f'EXT_{ext.upper()}')
                            features.append(ext_id)
            
            # Query parameters
            query = parsed.query
            if query:
                # Count parameters
                param_count = len(urllib.parse.parse_qs(query))
                if param_count > 10:
                    features.append(self._add_to_vocab('MANY_PARAMS'))
                elif param_count > 0:
                    features.append(self._add_to_vocab('HAS_PARAMS'))
                
                # Check for sensitive parameters
                sensitive_params = ['password', 'token', 'key', 'secret', 'auth']
                for param in sensitive_params:
                    if param in query.lower():
                        features.append(self._add_to_vocab(f'SENSITIVE_PARAM_{param.upper()}'))
            
            # Fragment
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
        
        # Security headers
        security_headers_present = []
        for header, value in headers.items():
            header_upper = header.upper().replace('-', '_')
            
            # Add header presence feature
            header_id = self._add_to_vocab(f'HEADER_{header_upper}')
            features.append(header_id)
            
            # Check for security headers
            if header.lower() in [
                'content-security-policy',
                'x-frame-options',
                'x-content-type-options',
                'strict-transport-security',
            ]:
                security_headers_present.append(header_upper)
            
            # Check for suspicious header values
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
        
        # User-Agent anomalies
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
        
        # Referer anomalies
        elif header_lower == 'referer':
            if not value_lower.startswith(('http://', 'https://')):
                features.append(self._add_to_vocab('SUSPICIOUS_REFERER'))
        
        # Origin anomalies
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
        
        # Parameter count feature
        param_count = len(parameters)
        if param_count > 20:
            features.append(self._add_to_vocab('VERY_MANY_PARAMS'))
        elif param_count > 10:
            features.append(self._add_to_vocab('MANY_PARAMS'))
        elif param_count > 0:
            features.append(self._add_to_vocab('HAS_PARAMS'))
        
        # Check individual parameters
        for param_name, param_value in parameters.items():
            param_name_lower = param_name.lower()
            
            # Sensitive parameter names
            sensitive_patterns = [
                'pass', 'token', 'key', 'secret', 'auth',
                'credit', 'ssn', 'social', 'security',
                'card', 'cvv', 'expiry', 'dob', 'birth',
            ]
            
            for pattern in sensitive_patterns:
                if pattern in param_name_lower:
                    features.append(self._add_to_vocab(f'SENSITIVE_PARAM_{pattern.upper()}'))
                    break
            
            # Check parameter values for attacks
            if isinstance(param_value, str):
                # Length anomaly
                if len(param_value) > 1000:
                    features.append(self._add_to_vocab('LONG_PARAM_VALUE'))
                
                # Check for attack patterns
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
        
        # Check each attack pattern category
        for attack_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                if re.search(pattern, value_lower, re.IGNORECASE):
                    feature_name = f'ATTACK_{attack_type.upper()}'
                    features.append(self._add_to_vocab(feature_name))
                    break  # Found one pattern in this category
        
        # Check for encoded attacks
        encoded_patterns = [
            (r'%3Cscript%3E', 'URLENCODED_XSS'),
            (r'%27OR%27', 'URLENCODED_SQL'),
            (r'PHNjcmlwdD4=', 'BASE64_XSS'),  # <script> in base64
        ]
        
        for pattern, feature in encoded_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                features.append(self._add_to_vocab(feature))
        
        # Check for suspicious characters
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
        
        # Convert to string for analysis
        body_str = ''
        if isinstance(body, bytes):
            try:
                body_str = body.decode('utf-8', errors='ignore')
            except:
                body_str = str(body)[:1000]  # Truncate if decoding fails
        elif isinstance(body, dict):
            body_str = json.dumps(body)
        else:
            body_str = str(body)
        
        # Length features
        body_length = len(body_str)
        if body_length > 1000000:  # 1MB
            features.append(self._add_to_vocab('VERY_LARGE_BODY'))
        elif body_length > 100000:  # 100KB
            features.append(self._add_to_vocab('LARGE_BODY'))
        elif body_length > 0:
            features.append(self._add_to_vocab('HAS_BODY'))
        
        # Content type detection
        if body_str.strip().startswith('{') and body_str.strip().endswith('}'):
            features.append(self._add_to_vocab('JSON_BODY'))
            # Check for nested JSON (potential for deep parsing attacks)
            if body_str.count('{') > 5:
                features.append(self._add_to_vocab('DEEP_JSON'))
        
        elif body_str.strip().startswith('<') and body_str.strip().endswith('>'):
            features.append(self._add_to_vocab('XML_BODY'))
        
        elif '=' in body_str and '&' in body_str:
            features.append(self._add_to_vocab('FORM_URLENCODED'))
        
        # Check for attack patterns in body
        body_lower = body_str.lower()
        for attack_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                if re.search(pattern, body_lower, re.IGNORECASE):
                    feature_name = f'BODY_ATTACK_{attack_type.upper()}'
                    features.append(self._add_to_vocab(feature_name))
                    break
        
        # Check for file upload patterns
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
        
        # Combine all text for pattern detection
        all_text = []
        
        # URL
        url = request_data.get('url', '')
        all_text.append(url)
        
        # Headers
        headers = request_data.get('headers', {})
        for header, value in headers.items():
            all_text.append(f"{header}: {value}")
        
        # Parameters
        params = request_data.get('parameters', {})
        for param, value in params.items():
            all_text.append(f"{param}={value}")
        
        # Body
        body = request_data.get('body', '')
        if isinstance(body, (str, bytes)):
            all_text.append(str(body))
        
        # Check combined text for attacks
        combined_text = ' '.join(all_text).lower()
        
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
        
        # Request timing (if available)
        timestamp = request_data.get('timestamp')
        if timestamp:
            # Check for rapid requests (potential DoS)
            # This would require request history context
            pass
        
        # IP address features (if available)
        ip = request_data.get('ip_address')
        if ip:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_private:
                    features.append(self._add_to_vocab('PRIVATE_IP'))
                if ip_obj.is_loopback:
                    features.append(self._add_to_vocab('LOOPBACK_IP'))
                if ip_obj.is_multicast:
                    features.append(self._add_to_vocab('MULTICAST_IP'))
            except:
                pass
        
        # Request frequency (would require context)
        # Unusual user agent patterns
        user_agent = request_data.get('headers', {}).get('User-Agent', '')
        if user_agent:
            if len(user_agent) < 10:
                features.append(self._add_to_vocab('SHORT_USER_AGENT'))
            if 'mozilla' not in user_agent.lower():
                features.append(self._add_to_vocab('NON_STANDARD_UA'))
        
        # Referer analysis
        referer = request_data.get('headers', {}).get('Referer', '')
        if referer:
            url = request_data.get('url', '')
            if referer and url:
                # Check if referer matches expected patterns
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
            referer_parsed = urllib.parse.urlparse(referer)
            current_parsed = urllib.parse.urlparse(current_url)
            
            # Same origin check
            if referer_parsed.netloc == current_parsed.netloc:
                return True
            
            # Empty referer (direct navigation, bookmark)
            if not referer:
                return True
            
            # Common legitimate referers
            common_referers = [
                'google.com', 'bing.com', 'yahoo.com', 'duckduckgo.com',
                'facebook.com', 'twitter.com', 'linkedin.com', 'reddit.com',
            ]
            
            for domain in common_referers:
                if domain in referer_parsed.netloc:
                    return True
            
            return False
        except:
            return False
    
    def _generate_cache_key(self, data: Dict[str, Any]) -> str:
        """
        Generate cache key for request data
        
        Args:
            data: Request data dictionary
        
        Returns:
            str: Cache key
        """
        # Create deterministic string representation
        key_parts = []
        
        # URL
        url = data.get('url', '')
        key_parts.append(f"url:{hashlib.md5(url.encode()).hexdigest()[:8]}")
        
        # Method
        method = data.get('method', 'GET')
        key_parts.append(f"method:{method}")
        
        # Headers hash
        headers = data.get('headers', {})
        headers_str = json.dumps(sorted(headers.items()), sort_keys=True)
        key_parts.append(f"headers:{hashlib.md5(headers_str.encode()).hexdigest()[:8]}")
        
        # Body hash (truncated)
        body = data.get('body', '')
        if isinstance(body, (str, bytes)):
            body_str = str(body)[:100]  # First 100 chars
            key_parts.append(f"body:{hashlib.md5(body_str.encode()).hexdigest()[:8]}")
        
        return '|'.join(key_parts)
    
    def _update_cache(self, key: str, value: torch.Tensor):
        """
        Update feature cache
        
        Args:
            key: Cache key
            value: Cached value
        """
        if len(self.feature_cache) >= self.cache_max_size:
            # Remove oldest entry (FIFO)
            oldest_key = next(iter(self.feature_cache))
            del self.feature_cache[oldest_key]
        
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
        import pickle
        
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
        import pickle
        
        with open(filepath, 'rb') as f:
            data = pickle.load(f)
        
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
        self.request_window = []
        self.feature_window = []
        
        # Statistics for adaptive thresholding
        self.request_stats = {
            'count': 0,
            'avg_features': 0.0,
            'attack_rate': 0.0,
        }
    
    def encode_streaming(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Encode request in streaming mode
        
        Args:
            request_data: Request data dictionary
        
        Returns:
            Dict with encoded features and streaming context
        """
        # Encode current request
        current_features = self.encode_http_request(request_data)
        
        # Update sliding windows
        self.request_window.append(request_data)
        self.feature_window.append(current_features)
        
        # Maintain window size
        if len(self.request_window) > self.window_size:
            self.request_window.pop(0)
            self.feature_window.pop(0)
        
        # Update statistics
        self._update_statistics(request_data)
        
        # Calculate context features from window
        context_features = self._extract_context_features()
        
        return {
            'current_features': current_features,
            'context_features': context_features,
            'window_size': len(self.request_window),
            'stats': self.request_stats.copy(),
            'anomaly_score': self._calculate_anomaly_score(request_data),
        }
    
    def _update_statistics(self, request_data: Dict[str, Any]):
        """Update streaming statistics"""
        self.request_stats['count'] += 1
        
        # Update average features
        feature_count = len(request_data.get('parameters', {}))
        self.request_stats['avg_features'] = (
            self.request_stats['avg_features'] * 0.9 + feature_count * 0.1
        )
        
        # Check for attacks in this request
        if self._has_attack_patterns(request_data):
            self.request_stats['attack_rate'] = (
                self.request_stats['attack_rate'] * 0.95 + 0.05
            )
        else:
            self.request_stats['attack_rate'] = (
                self.request_stats['attack_rate'] * 0.99
            )
    
    def _has_attack_patterns(self, request_data: Dict[str, Any]) -> bool:
        """Check if request has attack patterns"""
        all_text = []
        
        url = request_data.get('url', '')
        all_text.append(url)
        
        body = request_data.get('body', '')
        if body:
            all_text.append(str(body)[:1000])
        
        combined_text = ' '.join(all_text).lower()
        
        for patterns in self.attack_patterns.values():
            for pattern in patterns:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    return True
        
        return False
    
    def _extract_context_features(self) -> torch.Tensor:
        """Extract features from current window context"""
        if not self.feature_window:
            return torch.zeros(self.max_seq_len, dtype=torch.long)
        
        # Combine features from window
        # Simple approach: average the feature vectors
        stacked = torch.stack(self.feature_window)
        context = stacked.mean(dim=0).long()
        
        return context
    
    def _calculate_anomaly_score(self, request_data: Dict[str, Any]) -> float:
        """Calculate anomaly score for current request"""
        score = 0.0
        
        # Check against window statistics
        if len(self.request_window) > 10:
            # Check for parameter count anomaly
            param_count = len(request_data.get('parameters', {}))
            avg_params = self.request_stats['avg_features']
            
            if param_count > avg_params * 3:
                score += 0.3
            elif param_count > avg_params * 2:
                score += 0.1
            
            # Check for attack rate anomaly
            current_has_attack = self._has_attack_patterns(request_data)
            if current_has_attack and self.request_stats['attack_rate'] < 0.1:
                # Attack when attack rate is normally low
                score += 0.4
        
        # Request size anomaly
        body_size = len(str(request_data.get('body', '')))
        if body_size > 100000:  # 100KB
            score += 0.2
        
        return min(1.0, score)


def test_security_encoder():
    """
    Test security feature encoder
    """
    print("🧪 Testing Security Encoder...")
    
    # Create encoder
    encoder = SecurityFeatureEncoder(vocab_size=10000, max_seq_len=256)
    
    # Test request
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
            'password': "' OR '1'='1",
            'remember': 'true',
        },
        'body': '{"action": "login", "data": {"user": "admin"}}',
        'ip_address': '192.168.1.100',
    }
    
    # Encode request
    features = encoder.encode_http_request(test_request)
    
    # Verify
    assert features.shape == (256,), f"Expected shape (256,), got {features.shape}"
    assert features.dtype == torch.long, f"Expected long dtype, got {features.dtype}"
    
    # Decode and check for attack features
    decoded = encoder.decode_features(features.tolist()[:20])  # First 20 features
    print(f"   First 10 features: {decoded[:10]}")
    
    # Check that SQL injection was detected
    sql_features = [f for f in decoded if 'SQL' in f or 'ATTACK' in f]
    assert len(sql_features) > 0, "SQL injection should have been detected!"
    
    print("✅ Security Encoder tests passed!")
    print(f"   Vocabulary size: {encoder.get_vocabulary_size()}")
    print(f"   Features with attacks: {len(sql_features)}")
    
    # Test streaming encoder
    streaming_encoder = StreamingSecurityEncoder(window_size=50)
    streaming_result = streaming_encoder.encode_streaming(test_request)
    
    assert 'current_features' in streaming_result
    assert 'context_features' in streaming_result
    assert 'anomaly_score' in streaming_result
    
    print("✅ Streaming Encoder tests passed!")
    
    return True


if __name__ == "__main__":
    test_security_encoder()