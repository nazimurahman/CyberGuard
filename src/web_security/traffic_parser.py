# src/web_security/traffic_parser.py
"""
Advanced HTTP Traffic Parser for CyberGuard
Parses and analyzes HTTP/HTTPS traffic for security threats
Features: Protocol analysis, anomaly detection, pattern recognition, threat correlation
"""

import re
import json
import base64
import urllib.parse
import hashlib
import zlib
from typing import Dict, List, Any, Optional, Tuple, Set, Union
from dataclasses import dataclass
from datetime import datetime
import ipaddress

@dataclass
class HTTPRequest:
    """Structured representation of an HTTP request for security analysis"""
    method: str                    # HTTP method: GET, POST, PUT, DELETE, etc.
    url: str                       # Full URL including query parameters
    path: str                      # URL path without query string
    query_params: Dict[str, List[str]]  # Parsed query parameters
    headers: Dict[str, str]        # HTTP headers (case-insensitive keys)
    body: Optional[str]            # Request body (None for GET, HEAD, etc.)
    body_type: str                 # Content type of body: 'json', 'form', 'xml', 'text', 'binary'
    client_ip: str                 # Client IP address
    timestamp: datetime            # Request timestamp
    protocol: str                  # HTTP protocol version: 'HTTP/1.1', 'HTTP/2'
    cookies: Dict[str, str]        # Parsed cookies
    user_agent: str                # User-Agent header value
    content_length: int            # Content-Length header value
    referer: Optional[str]         # Referer header
    host: str                      # Host header

@dataclass
class HTTPResponse:
    """Structured representation of an HTTP response"""
    status_code: int               # HTTP status code: 200, 404, 500, etc.
    status_message: str            # Status message: 'OK', 'Not Found', etc.
    headers: Dict[str, str]        # Response headers
    body: Optional[str]            # Response body
    body_type: str                 # Response content type
    content_length: int            # Actual response length
    server_header: str             # Server header
    timestamp: datetime            # Response timestamp
    request_id: str                # Correlation ID to matching request
    latency_ms: int                # Response latency in milliseconds

class TrafficParser:
    """
    Advanced traffic parser that analyzes HTTP traffic for security threats
    Implements: Protocol validation, anomaly detection, attack pattern matching
    """
    
    # Common attack patterns (compiled regex for performance)
    XSS_PATTERNS = [
        re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
        re.compile(r'javascript:', re.IGNORECASE),
        re.compile(r'on\w+\s*=', re.IGNORECASE),  # onload=, onerror=, etc.
        re.compile(r'data:', re.IGNORECASE),      # data: URLs for XSS
        re.compile(r'vbscript:', re.IGNORECASE),
    ]
    
    SQL_INJECTION_PATTERNS = [
        re.compile(r'(\'|\"|;|--|\/\*|\*\/|@@|char|union|select|insert|update|delete|drop|create|alter|exec|execute)', re.IGNORECASE),
        re.compile(r'\b(OR|AND)\s+\d+\s*=\s*\d+', re.IGNORECASE),
        re.compile(r'(\'|")\s*(\+\s*|\|\|)\s*(\'|")', re.IGNORECASE),
    ]
    
    PATH_TRAVERSAL_PATTERNS = [
        re.compile(r'(\.\.\/|\.\.\\|\.\.\/\.\.)', re.IGNORECASE),
        re.compile(r'(\/etc\/|\/proc\/|C:\\Windows\\|\\boot\\.ini)', re.IGNORECASE),
        re.compile(r'(passwd|shadow|htaccess|config)', re.IGNORECASE),
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        re.compile(r'[;&|`]\s*(ls|cat|rm|del|mkdir|whoami|id|uname)', re.IGNORECASE),
        re.compile(r'\$(\(|\{).*?(\)|\})', re.IGNORECASE),  # $(command) or ${command}
        re.compile(r'`.*?`', re.IGNORECASE),                # `command`
    ]
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize traffic parser with configuration
        
        Args:
            config: Configuration dictionary containing parsing rules and thresholds
        """
        self.config = config
        
        # Compiled regex for common parsing tasks (performance optimization)
        self.header_splitter = re.compile(r':\s*')
        self.url_pattern = re.compile(
            r'^(https?):\/\/'                    # Protocol
            r'([\w\-\.]+)'                       # Domain
            r'(:\d+)?'                           # Optional port
            r'(\/[\w\-\.\/\?\%\&=\#]*)?$',       # Path and query
            re.IGNORECASE
        )
        
        # Suspicious parameter names
        self.suspicious_params = {
            'cmd', 'exec', 'command', 'eval', 'system', 'shell',
            'file', 'path', 'directory', 'root', 'admin',
            'password', 'passwd', 'pwd', 'secret', 'token', 'key',
            'redirect', 'return', 'next', 'url',
            'debug', 'test', 'dev', 'stage',
        }
        
        # Known malicious user agents
        self.malicious_user_agents = [
            'sqlmap', 'nikto', 'nmap', 'metasploit', 'w3af',
            'acunetix', 'appscan', 'nessus', 'openvas',
            'havij', 'zap', 'burpsuite',
        ]
        
        # Statistics tracking
        self.stats = {
            'requests_parsed': 0,
            'malicious_requests': 0,
            'attack_patterns_detected': 0,
            'parsing_errors': 0,
        }
        
    def parse_http_request(self, raw_request: str, client_ip: str = '0.0.0.0') -> Optional[HTTPRequest]:
        """
        Parse raw HTTP request string into structured format
        
        Args:
            raw_request: Raw HTTP request string including headers and body
            client_ip: Client IP address for logging and analysis
            
        Returns:
            HTTPRequest object or None if parsing fails
        """
        try:
            # Split request into lines using carriage return and newline
            lines = raw_request.strip().split('\r\n')
            if not lines:  # Check if request is empty
                self.stats['parsing_errors'] += 1
                return None
            
            # Parse request line (first line)
            # Format: METHOD URL PROTOCOL (e.g., "GET /index.html HTTP/1.1")
            request_line = lines[0]
            method, url, protocol = self._parse_request_line(request_line)
            
            # Parse headers (lines until empty line)
            headers = {}
            body_start_idx = 0
            for i, line in enumerate(lines[1:], start=1):
                if not line.strip():  # Empty line indicates end of headers
                    body_start_idx = i + 1
                    break
                key, value = self._parse_header_line(line)
                if key:
                    headers[key.lower()] = value  # Store headers in lowercase for consistency
            
            # Parse body (if present)
            body = None
            body_type = 'unknown'
            if body_start_idx < len(lines):
                body_lines = lines[body_start_idx:]
                body = '\r\n'.join(body_lines)  # Reconstruct body with original line endings
                
                # Determine body type from Content-Type header
                content_type = headers.get('content-type', '').lower()
                if 'application/json' in content_type:
                    body_type = 'json'
                elif 'application/x-www-form-urlencoded' in content_type:
                    body_type = 'form'
                elif 'application/xml' in content_type or 'text/xml' in content_type:
                    body_type = 'xml'
                elif 'text/' in content_type:
                    body_type = 'text'
                else:
                    body_type = 'binary'  # Default for binary or unknown content
            
            # Parse URL components using urllib
            parsed_url = urllib.parse.urlparse(url)
            path = parsed_url.path
            
            # Parse query parameters into dictionary with lists for multiple values
            query_params = {}
            if parsed_url.query:
                query_params = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
            
            # Parse cookies from Cookie header
            cookies = {}
            cookie_header = headers.get('cookie', '')
            if cookie_header:
                cookies = self._parse_cookies(cookie_header)
            
            # Extract important headers with default values
            user_agent = headers.get('user-agent', '')
            content_length = int(headers.get('content-length', 0))
            referer = headers.get('referer')
            host = headers.get('host', '')
            
            # Create HTTPRequest object with all parsed data
            request = HTTPRequest(
                method=method,
                url=url,
                path=path,
                query_params=query_params,
                headers=headers,
                body=body,
                body_type=body_type,
                client_ip=client_ip,
                timestamp=datetime.now(),
                protocol=protocol,
                cookies=cookies,
                user_agent=user_agent,
                content_length=content_length,
                referer=referer,
                host=host,
            )
            
            self.stats['requests_parsed'] += 1  # Update statistics
            return request
            
        except Exception as e:
            self.stats['parsing_errors'] += 1  # Track parsing errors
            print(f"Error parsing HTTP request: {e}")
            return None  # Return None on failure
    
    def parse_http_response(self, raw_response: str, request_id: str = '') -> Optional[HTTPResponse]:
        """
        Parse raw HTTP response string into structured format
        
        Args:
            raw_response: Raw HTTP response string including headers and body
            request_id: Correlation ID to match with request
            
        Returns:
            HTTPResponse object or None if parsing fails
        """
        try:
            # Split response into lines
            lines = raw_response.strip().split('\r\n')
            if not lines:  # Check if response is empty
                return None
            
            # Parse status line (first line)
            # Format: PROTOCOL STATUS_CODE STATUS_MESSAGE (e.g., "HTTP/1.1 200 OK")
            status_line = lines[0]
            protocol, status_code, status_message = self._parse_status_line(status_line)
            
            # Parse headers
            headers = {}
            body_start_idx = 0
            for i, line in enumerate(lines[1:], start=1):
                if not line.strip():  # Empty line indicates end of headers
                    body_start_idx = i + 1
                    break
                key, value = self._parse_header_line(line)
                if key:
                    headers[key.lower()] = value  # Store in lowercase
            
            # Parse body
            body = None
            body_type = 'unknown'
            if body_start_idx < len(lines):
                body_lines = lines[body_start_idx:]
                body = '\r\n'.join(body_lines)  # Reconstruct body
                
                # Determine body type from Content-Type header
                content_type = headers.get('content-type', '').lower()
                if 'application/json' in content_type:
                    body_type = 'json'
                elif 'text/html' in content_type:
                    body_type = 'html'
                elif 'text/' in content_type:
                    body_type = 'text'
                else:
                    body_type = 'binary'  # Default for other content types
            
            # Extract important headers with defaults
            server_header = headers.get('server', '')
            content_length = len(body) if body else 0  # Calculate actual body length
            
            # Create HTTPResponse object
            response = HTTPResponse(
                status_code=int(status_code),  # Convert status code to integer
                status_message=status_message,
                headers=headers,
                body=body,
                body_type=body_type,
                content_length=content_length,
                server_header=server_header,
                timestamp=datetime.now(),
                request_id=request_id,
                latency_ms=0,  # Would be calculated from timing data in real implementation
            )
            
            return response
            
        except Exception as e:
            print(f"Error parsing HTTP response: {e}")
            return None  # Return None on failure
    
    def _parse_request_line(self, request_line: str) -> Tuple[str, str, str]:
        """
        Parse HTTP request line into method, URL, and protocol
        
        Args:
            request_line: Raw request line (e.g., "GET /index.html HTTP/1.1")
            
        Returns:
            Tuple of (method, url, protocol)
            
        Raises:
            ValueError: If request line is malformed
        """
        parts = request_line.strip().split()  # Split by whitespace
        if len(parts) != 3:  # Must have exactly 3 parts: method, url, protocol
            raise ValueError(f"Invalid request line format: {request_line}")
        
        method, url, protocol = parts  # Unpack the three parts
        method = method.upper()  # Convert method to uppercase for consistency
        
        # Validate HTTP method against standard methods
        valid_methods = {'GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 
                        'PATCH', 'TRACE', 'CONNECT'}
        if method not in valid_methods:
            raise ValueError(f"Invalid HTTP method: {method}")
        
        return method, url, protocol  # Return parsed components
    
    def _parse_status_line(self, status_line: str) -> Tuple[str, str, str]:
        """
        Parse HTTP status line into protocol, status code, and message
        
        Args:
            status_line: Raw status line (e.g., "HTTP/1.1 200 OK")
            
        Returns:
            Tuple of (protocol, status_code, status_message)
            
        Raises:
            ValueError: If status line is malformed
        """
        parts = status_line.strip().split(' ', 2)  # Split into max 3 parts
        if len(parts) < 3:  # Must have at least protocol, code, and message
            raise ValueError(f"Invalid status line format: {status_line}")
        
        protocol = parts[0]  # First part is protocol (HTTP/1.1, etc.)
        status_code = parts[1]  # Second part is status code
        status_message = parts[2] if len(parts) > 2 else ''  # Third part is message
        
        # Validate status code is numeric (200, 404, etc.)
        if not status_code.isdigit():
            raise ValueError(f"Invalid status code: {status_code}")
        
        return protocol, status_code, status_message  # Return parsed components
    
    def _parse_header_line(self, header_line: str) -> Tuple[str, str]:
        """
        Parse a single HTTP header line into key-value pair
        
        Args:
            header_line: Raw header line (e.g., "Content-Type: application/json")
            
        Returns:
            Tuple of (header_key, header_value)
        """
        # Use regex to split on first colon followed by optional whitespace
        match = self.header_splitter.split(header_line, 1)
        if len(match) != 2:  # Must have exactly key and value
            return '', ''  # Return empty tuple for malformed headers
        
        key = match[0].strip()  # Remove whitespace from key
        value = match[1].strip()  # Remove whitespace from value
        
        return key, value  # Return parsed header
    
    def _parse_cookies(self, cookie_header: str) -> Dict[str, str]:
        """
        Parse Cookie header into dictionary of name-value pairs
        
        Args:
            cookie_header: Raw Cookie header value
            
        Returns:
            Dictionary of cookie names to values
        """
        cookies = {}
        
        # Split by semicolon to get individual cookies
        cookie_parts = cookie_header.split(';')
        for part in cookie_parts:
            part = part.strip()  # Remove leading/trailing whitespace
            if '=' in part:  # Check if part contains name=value
                name, value = part.split('=', 1)  # Split on first equals sign
                cookies[name.strip()] = value.strip()  # Store in dictionary
        
        return cookies  # Return parsed cookies dictionary
    
    def analyze_request(self, request: HTTPRequest) -> Dict[str, Any]:
        """
        Analyze HTTP request for security threats and anomalies
        
        Args:
            request: Parsed HTTPRequest object
            
        Returns:
            Dictionary containing analysis results and detected threats
        """
        threats = []  # List to store detected threats
        anomalies = []  # List to store anomalies (less severe issues)
        security_metrics = {}  # Dictionary for security metrics
        
        # 1. Check for malicious patterns in URL and query parameters
        url_threats = self._analyze_url_patterns(request.url, request.query_params)
        threats.extend(url_threats)  # Add URL threats to main list
        
        # 2. Check for suspicious headers
        header_threats = self._analyze_headers(request.headers)
        threats.extend(header_threats)  # Add header threats
        
        # 3. Check for malicious user agent
        if self._is_malicious_user_agent(request.user_agent):
            threats.append({
                'type': 'MALICIOUS_USER_AGENT',
                'severity': 'HIGH',
                'description': f'Request from known security scanner: {request.user_agent}',
                'location': 'User-Agent header'
            })
        
        # 4. Check for suspicious cookies
        cookie_threats = self._analyze_cookies(request.cookies)
        threats.extend(cookie_threats)  # Add cookie threats
        
        # 5. Analyze request body if present and analyzable
        if request.body and request.body_type in ['json', 'form', 'text']:
            body_threats = self._analyze_request_body(request.body, request.body_type)
            threats.extend(body_threats)  # Add body threats
        
        # 6. Check for protocol anomalies
        protocol_threats = self._analyze_protocol_anomalies(request)
        anomalies.extend(protocol_threats)  # Add protocol anomalies
        
        # 7. Check for suspicious parameter names
        param_threats = self._analyze_parameter_names(request.query_params)
        threats.extend(param_threats)  # Add parameter name threats
        
        # 8. Calculate request complexity score
        complexity_score = self._calculate_request_complexity(request)
        security_metrics['request_complexity'] = complexity_score  # Store metric
        
        # 9. Check for encoding anomalies
        encoding_threats = self._detect_encoding_anomalies(request)
        threats.extend(encoding_threats)  # Add encoding threats
        
        # 10. Check for path traversal attempts
        path_threats = self._detect_path_traversal(request.path)
        threats.extend(path_threats)  # Add path traversal threats
        
        # Calculate overall threat score based on all detected threats
        threat_score = self._calculate_threat_score(threats)
        
        # Update statistics if threats were found
        if threats:
            self.stats['malicious_requests'] += 1
            self.stats['attack_patterns_detected'] += len(threats)
        
        # Return comprehensive analysis results
        return {
            'threats': threats,  # List of all detected threats
            'anomalies': anomalies,  # List of anomalies
            'security_metrics': security_metrics,  # Security metrics
            'threat_score': threat_score,  # Overall threat score (0.0 to 1.0)
            'recommended_action': self._get_recommended_action(threat_score, threats),  # Action recommendation
            'analysis_timestamp': datetime.now().isoformat(),  # Analysis timestamp
            'request_id': self._generate_request_id(request),  # Unique request ID
        }
    
    def _analyze_url_patterns(self, url: str, query_params: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """
        Analyze URL and query parameters for attack patterns
        
        Args:
            url: Full URL string
            query_params: Parsed query parameters
            
        Returns:
            List of detected threats
        """
        threats = []  # List to store URL threats
        
        # Decode URL to check for encoded attacks (URL decoding)
        try:
            decoded_url = urllib.parse.unquote(url)  # Decode percent-encoded characters
        except:
            decoded_url = url  # Use original if decoding fails
        
        # Check for XSS patterns in URL using compiled regex patterns
        for pattern in self.XSS_PATTERNS:
            match = pattern.search(decoded_url)  # Search for pattern in decoded URL
            if match:
                threats.append({
                    'type': 'XSS_IN_URL',
                    'severity': 'HIGH',
                    'description': f'Cross-site scripting pattern detected in URL: {pattern.pattern}',
                    'location': 'URL',
                    'pattern': pattern.pattern,
                    'matched_content': match.group()[:50]  # First 50 chars of matched content
                })
        
        # Check for SQL injection patterns in URL
        for pattern in self.SQL_INJECTION_PATTERNS:
            match = pattern.search(decoded_url)  # Search for SQL injection patterns
            if match:
                threats.append({
                    'type': 'SQL_INJECTION_IN_URL',
                    'severity': 'CRITICAL',
                    'description': 'SQL injection pattern detected in URL',
                    'location': 'URL',
                    'pattern': pattern.pattern,
                    'matched_content': match.group()[:50]  # First 50 chars
                })
        
        # Check query parameters for attacks (iterate through all parameters)
        for param_name, param_values in query_params.items():
            for value in param_values:  # Handle multiple values for same parameter
                if not value:  # Skip empty values
                    continue
                
                # Check for XSS in parameter values
                for pattern in self.XSS_PATTERNS:
                    match = pattern.search(value)  # Search in parameter value
                    if match:
                        threats.append({
                            'type': 'XSS_IN_PARAMETER',
                            'severity': 'HIGH',
                            'description': f'XSS pattern in parameter "{param_name}"',
                            'location': f'Query parameter: {param_name}',
                            'pattern': pattern.pattern,
                            'matched_content': match.group()[:50]  # First 50 chars
                        })
                
                # Check for SQL injection in parameter values
                for pattern in self.SQL_INJECTION_PATTERNS:
                    match = pattern.search(value)  # Search for SQL injection
                    if match:
                        threats.append({
                            'type': 'SQL_INJECTION_IN_PARAMETER',
                            'severity': 'CRITICAL',
                            'description': f'SQL injection in parameter "{param_name}"',
                            'location': f'Query parameter: {param_name}',
                            'pattern': pattern.pattern,
                            'matched_content': match.group()[:50]  # First 50 chars
                        })
                
                # Check for command injection in parameter values
                for pattern in self.COMMAND_INJECTION_PATTERNS:
                    match = pattern.search(value)  # Search for command injection
                    if match:
                        threats.append({
                            'type': 'COMMAND_INJECTION',
                            'severity': 'CRITICAL',
                            'description': f'Command injection in parameter "{param_name}"',
                            'location': f'Query parameter: {param_name}',
                            'pattern': pattern.pattern,
                            'matched_content': match.group()[:50]  # First 50 chars
                        })
        
        return threats  # Return all detected URL threats
    
    def _analyze_headers(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Analyze HTTP headers for security issues
        
        Args:
            headers: HTTP headers dictionary
            
        Returns:
            List of header-related threats
        """
        threats = []  # List to store header threats
        
        # Check for missing security headers that should be present
        security_headers = {
            'content-security-policy': 'MEDIUM',  # CSP helps prevent XSS
            'x-frame-options': 'MEDIUM',  # Prevents clickjacking
            'x-content-type-options': 'LOW',  # Prevents MIME type sniffing
            'strict-transport-security': 'HIGH',  # Enforces HTTPS
        }
        
        # Check each security header and flag if missing
        for header, severity in security_headers.items():
            if header not in headers:
                threats.append({
                    'type': 'MISSING_SECURITY_HEADER',
                    'severity': severity,
                    'description': f'Missing security header: {header}',
                    'location': 'Request headers',
                    'recommendation': f'Add {header} header to improve security'
                })
        
        # Check for suspicious header values (potential attacks in headers)
        for header_name, header_value in headers.items():
            header_value_lower = header_value.lower()  # Convert to lowercase for case-insensitive matching
            
            # Check for XSS patterns in headers
            for pattern in self.XSS_PATTERNS:
                match = pattern.search(header_value_lower)  # Search for XSS
                if match:
                    threats.append({
                        'type': 'XSS_IN_HEADER',
                        'severity': 'HIGH',
                        'description': f'XSS pattern in header "{header_name}"',
                        'location': f'Header: {header_name}',
                        'pattern': pattern.pattern,
                        'matched_content': match.group()[:50]  # First 50 chars
                    })
            
            # Check for SQL injection patterns in headers
            for pattern in self.SQL_INJECTION_PATTERNS:
                match = pattern.search(header_value_lower)  # Search for SQL injection
                if match:
                    threats.append({
                        'type': 'SQL_INJECTION_IN_HEADER',
                        'severity': 'CRITICAL',
                        'description': f'SQL injection in header "{header_name}"',
                        'location': f'Header: {header_name}',
                        'pattern': pattern.pattern,
                        'matched_content': match.group()[:50]  # First 50 chars
                    })
        
        # Check for overly large headers (potential buffer overflow attack)
        total_header_size = sum(len(k) + len(v) for k, v in headers.items())
        if total_header_size > 8192:  # 8KB limit (common buffer size)
            threats.append({
                'type': 'OVERSIZED_HEADERS',
                'severity': 'MEDIUM',
                'description': f'Total header size ({total_header_size} bytes) exceeds safe limit',
                'location': 'Request headers',
                'recommendation': 'Limit total header size to 8KB'
            })
        
        return threats  # Return all header threats
    
    def _is_malicious_user_agent(self, user_agent: str) -> bool:
        """
        Check if user agent is known to be malicious (security scanners, bots)
        
        Args:
            user_agent: User-Agent header value
            
        Returns:
            True if user agent is malicious, False otherwise
        """
        if not user_agent:  # Empty user agent
            return False
        
        user_agent_lower = user_agent.lower()  # Convert to lowercase for case-insensitive matching
        
        # Check if user agent contains any known malicious substring
        for malicious_ua in self.malicious_user_agents:
            if malicious_ua in user_agent_lower:
                return True  # Found malicious user agent
        
        return False  # No malicious user agent detected
    
    def _analyze_cookies(self, cookies: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Analyze cookies for security issues
        
        Args:
            cookies: Dictionary of cookie names and values
            
        Returns:
            List of cookie-related threats
        """
        threats = []  # List to store cookie threats
        
        # Iterate through all cookies
        for cookie_name, cookie_value in cookies.items():
            # Check for sensitive data in cookies (session tokens, passwords, etc.)
            sensitive_patterns = [
                ('session', 'SESSION_DATA_IN_COOKIE'),  # Session data
                ('token', 'TOKEN_IN_COOKIE'),  # Authentication tokens
                ('password', 'PASSWORD_IN_COOKIE'),  # Passwords
                ('secret', 'SECRET_IN_COOKIE'),  # Secrets
            ]
            
            # Check each sensitive pattern against cookie name
            for pattern, threat_type in sensitive_patterns:
                if pattern in cookie_name.lower() and cookie_value:  # Case-insensitive check
                    threats.append({
                        'type': threat_type,
                        'severity': 'HIGH',
                        'description': f'Sensitive data "{pattern}" found in cookie',
                        'location': f'Cookie: {cookie_name}',
                        'recommendation': 'Use HTTP-only, secure cookies for sensitive data'
                    })
            
            # Check for XSS patterns in cookie values
            for pattern in self.XSS_PATTERNS:
                match = pattern.search(cookie_value)  # Search for XSS in cookie value
                if match:
                    threats.append({
                        'type': 'XSS_IN_COOKIE',
                        'severity': 'HIGH',
                        'description': f'XSS pattern in cookie "{cookie_name}"',
                        'location': f'Cookie: {cookie_name}',
                        'pattern': pattern.pattern,
                        'matched_content': match.group()[:50]  # First 50 chars
                    })
        
        return threats  # Return all cookie threats
    
    def _analyze_request_body(self, body: str, body_type: str) -> List[Dict[str, Any]]:
        """
        Analyze request body for security threats
        
        Args:
            body: Request body string
            body_type: Type of body content (json, form, xml, text)
            
        Returns:
            List of body-related threats
        """
        threats = []  # List to store body threats
        
        if not body:  # Empty body
            return threats
        
        try:
            if body_type == 'json':
                # Parse JSON and analyze structure
                try:
                    parsed = json.loads(body)  # Parse JSON string
                    threats.extend(self._analyze_json_structure(parsed))  # Analyze JSON structure
                except json.JSONDecodeError:
                    # Malformed JSON could be an attack attempt
                    threats.append({
                        'type': 'MALFORMED_JSON',
                        'severity': 'MEDIUM',
                        'description': 'Request body contains malformed JSON',
                        'location': 'Request body',
                        'recommendation': 'Validate JSON structure before processing'
                    })
            
            elif body_type == 'form':
                # Parse form data (application/x-www-form-urlencoded)
                parsed = urllib.parse.parse_qs(body, keep_blank_values=True)  # Parse form data
                for param_name, param_values in parsed.items():
                    for value in param_values:  # Handle multiple values
                        # Check for attack patterns in form data
                        for pattern in self.XSS_PATTERNS + self.SQL_INJECTION_PATTERNS:
                            match = pattern.search(value)  # Search for attack patterns
                            if match:
                                threats.append({
                                    'type': f'ATTACK_IN_FORM_DATA',
                                    'severity': 'HIGH',
                                    'description': f'Attack pattern in form field "{param_name}"',
                                    'location': f'Form field: {param_name}',
                                    'pattern': pattern.pattern,
                                    'matched_content': match.group()[:50]  # First 50 chars
                                })
            
            elif body_type == 'xml':
                # Check for XXE (XML External Entity) attacks
                if '<!ENTITY' in body.upper() or '<!DOCTYPE' in body.upper():  # Case-insensitive check
                    threats.append({
                        'type': 'POTENTIAL_XXE',
                        'severity': 'CRITICAL',
                        'description': 'Potential XML External Entity attack',
                        'location': 'Request body',
                        'recommendation': 'Disable XML external entity processing'
                    })
            
            # General body analysis (applies to all content types)
            body_lower = body.lower()  # Convert to lowercase for case-insensitive matching
            
            # Check for XSS patterns in body
            for pattern in self.XSS_PATTERNS:
                match = pattern.search(body_lower)  # Search for XSS
                if match:
                    threats.append({
                        'type': 'XSS_IN_BODY',
                        'severity': 'HIGH',
                        'description': 'XSS pattern in request body',
                        'location': 'Request body',
                        'pattern': pattern.pattern,
                        'matched_content': match.group()[:50]  # First 50 chars
                    })
            
            # Check for SQL injection patterns in body
            for pattern in self.SQL_INJECTION_PATTERNS:
                match = pattern.search(body_lower)  # Search for SQL injection
                if match:
                    threats.append({
                        'type': 'SQL_INJECTION_IN_BODY',
                        'severity': 'CRITICAL',
                        'description': 'SQL injection pattern in request body',
                        'location': 'Request body',
                        'pattern': pattern.pattern,
                        'matched_content': match.group()[:50]  # First 50 chars
                    })
            
            # Check for command injection patterns in body
            for pattern in self.COMMAND_INJECTION_PATTERNS:
                match = pattern.search(body_lower)  # Search for command injection
                if match:
                    threats.append({
                        'type': 'COMMAND_INJECTION_IN_BODY',
                        'severity': 'CRITICAL',
                        'description': 'Command injection pattern in request body',
                        'location': 'Request body',
                        'pattern': pattern.pattern,
                        'matched_content': match.group()[:50]  # First 50 chars
                    })
            
        except Exception as e:
            # Log but don't fail on analysis errors (fail-safe)
            print(f"Error analyzing request body: {e}")
        
        return threats  # Return all body threats
    
    def _analyze_json_structure(self, json_data: Any, path: str = '') -> List[Dict[str, Any]]:
        """
        Recursively analyze JSON structure for security issues
        
        Args:
            json_data: Parsed JSON data (dict, list, or primitive)
            path: Current path in JSON structure (for nested elements)
            
        Returns:
            List of JSON-related threats
        """
        threats = []  # List to store JSON threats
        
        if isinstance(json_data, dict):  # JSON object
            for key, value in json_data.items():
                current_path = f"{path}.{key}" if path else key  # Build path for nested elements
                
                # Check key for suspicious patterns (like 'cmd', 'exec', etc.)
                if key.lower() in self.suspicious_params:
                    threats.append({
                        'type': 'SUSPICIOUS_JSON_KEY',
                        'severity': 'MEDIUM',
                        'description': f'Suspicious parameter name in JSON: {key}',
                        'location': f'JSON path: {current_path}',
                        'recommendation': 'Validate and sanitize JSON input'
                    })
                
                # Recursively analyze value (handle nested objects/arrays)
                threats.extend(self._analyze_json_structure(value, current_path))
        
        elif isinstance(json_data, list):  # JSON array
            for i, item in enumerate(json_data):
                current_path = f"{path}[{i}]"  # Build path with array index
                threats.extend(self._analyze_json_structure(item, current_path))
        
        elif isinstance(json_data, str):  # JSON string value
            # Check string values for attack patterns
            for pattern in self.XSS_PATTERNS + self.SQL_INJECTION_PATTERNS:
                match = pattern.search(json_data)  # Search for attack patterns
                if match:
                    threats.append({
                        'type': 'ATTACK_IN_JSON_VALUE',
                        'severity': 'HIGH',
                        'description': f'Attack pattern in JSON value at path: {path}',
                        'location': f'JSON path: {path}',
                        'pattern': pattern.pattern,
                        'matched_content': match.group()[:50]  # First 50 chars
                    })
        
        return threats  # Return all JSON threats
    
    def _analyze_protocol_anomalies(self, request: HTTPRequest) -> List[Dict[str, Any]]:
        """
        Detect HTTP protocol anomalies and violations
        
        Args:
            request: Parsed HTTP request
            
        Returns:
            List of protocol anomalies
        """
        anomalies = []  # List to store protocol anomalies
        
        # Check for invalid HTTP methods (non-standard methods)
        if request.method not in {'GET', 'POST', 'PUT', 'DELETE', 'HEAD', 
                                 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT'}:
            anomalies.append({
                'type': 'INVALID_HTTP_METHOD',
                'severity': 'MEDIUM',
                'description': f'Invalid or unusual HTTP method: {request.method}',
                'location': 'Request line',
                'recommendation': 'Reject invalid HTTP methods'
            })
        
        # Check for excessively long URL (potential buffer overflow)
        if len(request.url) > 2048:  # Common limit for URL length
            anomalies.append({
                'type': 'OVERSIZED_URL',
                'severity': 'LOW',
                'description': f'URL length ({len(request.url)} chars) exceeds safe limit',
                'location': 'URL',
                'recommendation': 'Limit URL length to 2048 characters'
            })
        
        # Check for missing Host header (required in HTTP/1.1)
        if request.protocol == 'HTTP/1.1' and not request.host:
            anomalies.append({
                'type': 'MISSING_HOST_HEADER',
                'severity': 'MEDIUM',
                'description': 'Missing Host header in HTTP/1.1 request',
                'location': 'Headers',
                'recommendation': 'Require Host header for HTTP/1.1 requests'
            })
        
        # Check for inconsistent Content-Length (header says one thing, body is another)
        if request.content_length > 0 and not request.body:
            anomalies.append({
                'type': 'CONTENT_LENGTH_MISMATCH',
                'severity': 'LOW',
                'description': f'Content-Length header ({request.content_length}) but no body',
                'location': 'Headers',
                'recommendation': 'Verify Content-Length matches actual body size'
            })
        
        return anomalies  # Return all protocol anomalies
    
    def _analyze_parameter_names(self, query_params: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """
        Analyze query parameter names for suspicious patterns
        
        Args:
            query_params: Dictionary of query parameters
            
        Returns:
            List of suspicious parameter threats
        """
        threats = []  # List to store parameter name threats
        
        # Iterate through all parameter names
        for param_name in query_params.keys():
            param_lower = param_name.lower()  # Convert to lowercase for case-insensitive matching
            
            # Check for suspicious parameter names (like 'cmd', 'exec', etc.)
            if param_lower in self.suspicious_params:
                threats.append({
                    'type': 'SUSPICIOUS_PARAMETER_NAME',
                    'severity': 'MEDIUM',
                    'description': f'Suspicious parameter name: {param_name}',
                    'location': 'Query parameters',
                    'recommendation': 'Validate and sanitize parameter names'
                })
            
            # Check for parameter names that might indicate file upload
            file_keywords = ['file', 'upload', 'attachment']
            if any(keyword in param_lower for keyword in file_keywords):
                threats.append({
                    'type': 'POTENTIAL_FILE_UPLOAD',
                    'severity': 'LOW',
                    'description': f'Parameter name suggests file upload: {param_name}',
                    'location': 'Query parameters',
                    'recommendation': 'Validate file uploads with strict constraints'
                })
        
        return threats  # Return all parameter name threats
    
    def _calculate_request_complexity(self, request: HTTPRequest) -> float:
        """
        Calculate complexity score for request (0.0 to 1.0)
        Higher score indicates more complex, potentially malicious request
        
        Args:
            request: Parsed HTTP request
            
        Returns:
            Complexity score between 0.0 and 1.0
        """
        score = 0.0  # Start with zero score
        
        # Factor 1: Number of query parameters (20% weight)
        num_params = len(request.query_params)
        param_score = min(num_params / 20, 1.0) * 0.2  # Normalize to max 20 params
        score += param_score
        
        # Factor 2: URL length (15% weight)
        url_len_score = min(len(request.url) / 500, 1.0) * 0.15  # Normalize to max 500 chars
        score += url_len_score
        
        # Factor 3: Number of headers (10% weight)
        num_headers = len(request.headers)
        header_score = min(num_headers / 30, 1.0) * 0.1  # Normalize to max 30 headers
        score += header_score
        
        # Factor 4: Body size (15% weight)
        if request.body:
            body_size = len(request.body)
            # Normalize to 1MB (1048576 bytes)
            body_score = min(body_size / (1024 * 1024), 1.0) * 0.15
            score += body_score
        
        # Factor 5: Use of encoded characters (20% weight)
        encoded_chars = sum(1 for c in request.url if c in '%&<>')
        encoded_score = min(encoded_chars / 10, 1.0) * 0.2  # Normalize to max 10 encoded chars
        score += encoded_score
        
        # Factor 6: Suspicious parameter names (20% weight)
        suspicious_params = sum(1 for param in request.query_params.keys() 
                              if param.lower() in self.suspicious_params)
        suspicious_score = min(suspicious_params / 5, 1.0) * 0.2  # Normalize to max 5 suspicious params
        score += suspicious_score
        
        return min(score, 1.0)  # Cap at 1.0 (maximum complexity)
    
    def _detect_encoding_anomalies(self, request: HTTPRequest) -> List[Dict[str, Any]]:
        """
        Detect encoding anomalies and obfuscation attempts
        
        Args:
            request: Parsed HTTP request
            
        Returns:
            List of encoding-related threats
        """
        threats = []  # List to store encoding threats
        
        # Convert URL to lowercase for case-insensitive matching
        url_lower = request.url.lower()
        
        # Define encoding patterns to check for
        encoding_patterns = [
            ('%', 'URL_ENCODING'),  # Percent encoding
            ('&amp;', 'HTML_ENTITY_ENCODING'),  # HTML entity encoding
            ('\\u', 'UNICODE_ENCODING'),  # Unicode escape encoding
            ('&#', 'DECIMAL_HTML_ENCODING'),  # Decimal HTML entity
            ('&#x', 'HEX_HTML_ENCODING'),  # Hexadecimal HTML entity
        ]
        
        # Check for excessive encoding (more than 3 occurrences)
        for pattern, encoding_type in encoding_patterns:
            count = url_lower.count(pattern)  # Count occurrences
            if count > 3:  # More than 3 suggests obfuscation
                threats.append({
                    'type': 'EXCESSIVE_ENCODING',
                    'severity': 'MEDIUM',
                    'description': f'Excessive {encoding_type} detected ({count} occurrences)',
                    'location': 'URL',
                    'recommendation': 'Limit encoding depth and validate input'
                })
        
        # Check for mixed encoding schemes (potential obfuscation)
        if '%' in url_lower and ('&amp;' in url_lower or '\\u' in url_lower):
            threats.append({
                'type': 'MIXED_ENCODING',
                'severity': 'MEDIUM',
                'description': 'Mixed encoding schemes detected (potential obfuscation)',
                'location': 'URL',
                'recommendation': 'Normalize and validate encoded input'
            })
        
        # Check for double encoding attempts (common evasion technique)
        double_encoded = False
        decoded_once = urllib.parse.unquote(request.url)  # Decode once
        decoded_twice = urllib.parse.unquote(decoded_once)  # Decode again
        if decoded_twice != decoded_once:  # If different, double encoding detected
            double_encoded = True
        
        if double_encoded:
            threats.append({
                'type': 'DOUBLE_ENCODING',
                'severity': 'HIGH',
                'description': 'Double URL encoding detected (common evasion technique)',
                'location': 'URL',
                'recommendation': 'Decode input once and validate'
            })
        
        return threats  # Return all encoding threats
    
    def _detect_path_traversal(self, path: str) -> List[Dict[str, Any]]:
        """
        Detect path traversal attacks
        
        Args:
            path: URL path component
            
        Returns:
            List of path traversal threats
        """
        threats = []  # List to store path traversal threats
        
        # Decode path to catch encoded traversal attempts
        try:
            decoded_path = urllib.parse.unquote(path)  # Decode URL encoding
        except:
            decoded_path = path  # Use original if decoding fails
        
        # Check for path traversal patterns (../, etc.)
        for pattern in self.PATH_TRAVERSAL_PATTERNS:
            match = pattern.search(decoded_path)  # Search for traversal patterns
            if match:
                threats.append({
                    'type': 'PATH_TRAVERSAL',
                    'severity': 'CRITICAL',
                    'description': 'Path traversal pattern detected',
                    'location': 'URL path',
                    'pattern': pattern.pattern,
                    'matched_content': match.group()[:50],  # First 50 chars
                    'recommendation': 'Validate and sanitize file paths'
                })
        
        # Check for excessive directory depth (potential resource exhaustion)
        depth = decoded_path.count('/')  # Count directory separators
        if depth > 10:  # Arbitrary limit for directory depth
            threats.append({
                'type': 'EXCESSIVE_PATH_DEPTH',
                'severity': 'LOW',
                'description': f'Excessive directory depth ({depth} levels)',
                'location': 'URL path',
                'recommendation': 'Limit maximum path depth'
            })
        
        return threats  # Return all path traversal threats
    
    def _calculate_threat_score(self, threats: List[Dict[str, Any]]) -> float:
        """
        Calculate overall threat score based on detected threats
        
        Args:
            threats: List of detected threats
            
        Returns:
            Threat score between 0.0 and 1.0
        """
        if not threats:  # No threats means zero score
            return 0.0
        
        # Define severity weights for different threat levels
        severity_weights = {
            'CRITICAL': 1.0,  # Most severe
            'HIGH': 0.7,      # High severity
            'MEDIUM': 0.4,    # Medium severity
            'LOW': 0.1,       # Low severity
        }
        
        # Calculate weighted score based on threat severities
        total_weight = 0.0
        for threat in threats:
            severity = threat.get('severity', 'LOW')  # Default to LOW if not specified
            weight = severity_weights.get(severity, 0.1)  # Default weight
            total_weight += weight  # Add to total
        
        # Normalize by number of threats (with diminishing returns)
        # More threats increase score but with decreasing marginal impact
        normalized_score = min(total_weight / (1 + len(threats) * 0.5), 1.0)
        
        return normalized_score  # Return score capped at 1.0
    
    def _get_recommended_action(self, threat_score: float, 
                              threats: List[Dict[str, Any]]) -> str:
        """
        Determine recommended action based on threat score
        
        Args:
            threat_score: Calculated threat score (0.0 to 1.0)
            threats: List of detected threats
            
        Returns:
            Recommended action string
        """
        if threat_score == 0.0:  # No threats
            return "ALLOW - No threats detected"
        
        # Check for critical threats regardless of score
        critical_threats = [t for t in threats if t.get('severity') == 'CRITICAL']
        if critical_threats:  # Always block critical threats
            return "BLOCK - Critical threats detected"
        
        # Action based on threat score ranges
        if threat_score > 0.8:  # Very high threat score
            return "BLOCK - High threat score"
        elif threat_score > 0.6:  # High threat score
            return "CHALLENGE - Require CAPTCHA or 2FA"
        elif threat_score > 0.4:  # Medium threat score
            return "MONITOR - Log and analyze further"
        elif threat_score > 0.2:  # Low threat score
            return "WARN - Flag for review"
        else:  # Very low threat score
            return "ALLOW - Low risk"
    
    def _generate_request_id(self, request: HTTPRequest) -> str:
        """
        Generate unique ID for request based on its characteristics
        
        Args:
            request: Parsed HTTP request
            
        Returns:
            Unique request ID string
        """
        # Create hash input from request characteristics
        hash_input = f"{request.method}:{request.url}:{request.client_ip}"
        if request.body:
            # Include first 100 chars of body (for uniqueness without being too heavy)
            hash_input += f":{request.body[:100]}"
        
        # Generate MD5 hash (for speed, not cryptographic security)
        # Note: In production, consider using SHA-256 for better security
        hash_digest = hashlib.md5(hash_input.encode()).hexdigest()
        return hash_digest[:16]  # Return first 16 chars (64 bits)
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get current parser statistics
        
        Returns:
            Dictionary of statistics
        """
        return self.stats.copy()  # Return copy to prevent external modification