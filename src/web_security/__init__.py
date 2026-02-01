"""
Security Utilities for CyberGuard Web Security AI System.

This module provides comprehensive security validation, sanitization, and
verification functions for web security analysis. All functions follow
OWASP security guidelines and best practices.

Key Features:
- URL validation with security checks
- Input sanitization for XSS, SQLi prevention
- Secure hash generation and verification
- Threat pattern detection
- Email and IP validation
- Secure token generation
"""

import re
import hashlib
import secrets
import ipaddress
import urllib.parse
import os
from typing import Union, Optional, List, Dict, Any, Tuple
from datetime import datetime, timedelta
import hmac
import base64


class SecurityValidator:
    """
    Comprehensive security validator for web applications.
    
    This class provides methods to validate various inputs against
    security best practices and common attack patterns.
    """
    
    # Common attack patterns (OWASP Top-10)
    XSS_PATTERNS = [
        r'<script[^>]*>.*?</script>',          # Script tags
        r'javascript:',                         # JavaScript protocol
        r'onload\s*=', r'onerror\s*=',         # Event handlers
        r'vbscript:',                           # VBScript
        r'expression\s*\(',                     # CSS expressions
        r'data:',                               # Data URIs
        r'<\s*iframe', r'<\s*frame',           # Frame tags
    ]
    
    SQL_INJECTION_PATTERNS = [
        r"(\'|\"|;|\-\-|\#)",                   # SQL meta characters
        r"\b(union|select|insert|update|delete|drop|create|alter)\b",
        r"\b(exec|execute|xp_cmdshell)\b",      # Dangerous commands
        r"\b(0x[0-9a-f]+)\b",                   # Hex encoded
        r"\b(WAITFOR DELAY|SLEEP)\b",           # Time-based attacks
    ]
    
    PATH_TRAVERSAL_PATTERNS = [
        r'\.\./', r'\.\.\\',                    # Directory traversal
        r'/', r'\\',                            # Path separators in params
        r'%(c0|2e)\.%(af|2e)',                  # UTF-8 encoded traversal
        r'\.\.%2f', r'\.\.%5c',                 # URL encoded traversal
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        r'[;&|`]',                              # Command separators
        r'\$(?:\(|{|\[)',                       # Command substitution
        r'\b(rm|del|mkdir|wget|curl|nc|netcat)\b',
        r'\.\./', r'/', r'\\',                  # Path traversal in commands
    ]
    
    def __init__(self, strict_mode: bool = True):
        """
        Initialize security validator.
        
        Args:
            strict_mode: If True, applies stricter validation rules.
                         If False, allows more lenient validation for specific use cases.
        """
        self.strict_mode = strict_mode
        # Compile regex patterns for better performance
        self.compiled_xss_patterns = [re.compile(p, re.IGNORECASE | re.DOTALL) 
                                      for p in self.XSS_PATTERNS]
        self.compiled_sql_patterns = [re.compile(p, re.IGNORECASE) 
                                      for p in self.SQL_INJECTION_PATTERNS]
        
    def validate_url(self, url: str, require_https: bool = True, 
                    allowed_domains: Optional[List[str]] = None) -> Tuple[bool, str]:
        """
        Validate URL with comprehensive security checks.
        
        This function performs multiple security checks on URLs:
        1. URL format validation
        2. Protocol validation (HTTPS requirement)
        3. Domain/IP validation
        4. Path traversal detection
        5. XSS/SQLi pattern detection
        
        Args:
            url: URL string to validate
            require_https: If True, requires HTTPS protocol
            allowed_domains: List of allowed domains (None allows all)
            
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
            
        Example:
            >>> validator = SecurityValidator()
            >>> validator.validate_url("https://example.com")
            (True, "")
            >>> validator.validate_url("javascript:alert('xss')")
            (False, "Invalid protocol: javascript")
        """
        try:
            # Parse URL using urllib
            parsed = urllib.parse.urlparse(url)
            
            # 1. Check protocol exists
            if not parsed.scheme:
                return False, "Missing protocol"
            
            # 2. Enforce HTTPS if required
            if require_https and parsed.scheme.lower() != 'https':
                return False, f"HTTPS required, got {parsed.scheme}"
            
            # 3. Check for dangerous protocols
            dangerous_protocols = ['javascript', 'data', 'vbscript', 'file']
            if parsed.scheme.lower() in dangerous_protocols:
                return False, f"Dangerous protocol: {parsed.scheme}"
            
            # 4. Check network location (domain/IP) exists
            if not parsed.netloc:
                return False, "Missing domain or IP"
            
            # 5. Validate domain or IP
            is_valid_domain, error_msg = self._validate_network_location(parsed.netloc)
            if not is_valid_domain:
                return False, error_msg
            
            # 6. Check for path traversal in path
            if parsed.path and self._contains_path_traversal(parsed.path):
                return False, "Path traversal attempt detected"
            
            # 7. Check query parameters for attacks
            if parsed.query:
                query_params = urllib.parse.parse_qs(parsed.query)
                for param, values in query_params.items():
                    for value in values:
                        # Check each parameter value for XSS
                        if self._contains_xss(value):
                            return False, f"XSS pattern detected in parameter: {param}"
                        # Check each parameter value for SQL injection
                        if self._contains_sql_injection(value):
                            return False, f"SQL injection pattern detected in parameter: {param}"
            
            # 8. Check against allowed domains if specified
            if allowed_domains:
                domain = parsed.netloc.split(':')[0]  # Remove port if present
                if domain not in allowed_domains:
                    return False, f"Domain not in allowed list: {domain}"
            
            return True, ""
            
        except Exception as e:
            return False, f"URL validation error: {str(e)}"
    
    def _validate_network_location(self, netloc: str) -> Tuple[bool, str]:
        """
        Validate network location (domain or IP).
        
        Args:
            netloc: Network location string (e.g., "example.com:8080")
            
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        # Split port if present
        if ':' in netloc:
            host, port = netloc.split(':', 1)
            try:
                port_num = int(port)
                # Validate port range
                if not (1 <= port_num <= 65535):
                    return False, f"Invalid port: {port}"
            except ValueError:
                return False, f"Invalid port: {port}"
        else:
            host = netloc
        
        # Check if it's an IP address
        try:
            ip = ipaddress.ip_address(host)
            # Security checks on IP address
            if ip.is_private and self.strict_mode:
                return False, "Private IP addresses not allowed"
            if ip.is_multicast or ip.is_reserved:
                return False, "Invalid IP address type"
            return True, ""
        except ValueError:
            # Not an IP, assume it's a domain
            pass
        
        # Validate domain name format
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if not re.match(domain_pattern, host):
            return False, f"Invalid domain format: {host}"
        
        # Check for suspicious domain patterns
        suspicious_patterns = [
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP-like domains
            r'localhost', r'127\.0\.0\.1',          # Localhost
            r'\.(exe|dll|bat|cmd|sh)$',             # Executable extensions
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, host, re.IGNORECASE):
                return False, f"Suspicious domain pattern: {host}"
        
        return True, ""
    
    def sanitize_input(self, input_str: str, input_type: str = 'text') -> str:
        """
        Sanitize user input based on input type.
        
        This function applies appropriate sanitization based on the expected
        input type to prevent XSS, SQL injection, and other attacks.
        
        Args:
            input_str: Input string to sanitize
            input_type: Type of input ('text', 'html', 'sql', 'url', 'email')
            
        Returns:
            str: Sanitized input string
            
        Example:
            >>> sanitize_input("<script>alert('xss')</script>", 'text')
            "&lt;script&gt;alert('xss')&lt;/script&gt;"
        """
        if not input_str:
            return ""
        
        # Convert to string if not already
        if not isinstance(input_str, str):
            input_str = str(input_str)
        
        # Remove null bytes which can be used in attacks
        input_str = input_str.replace('\x00', '')
        
        # Trim whitespace
        input_str = input_str.strip()
        
        # Apply type-specific sanitization
        if input_type == 'html':
            # For HTML input, encode special characters
            return self._sanitize_html(input_str)
        elif input_type == 'sql':
            # For SQL input, escape special characters
            return self._sanitize_sql(input_str)
        elif input_type == 'url':
            # For URL input, validate and encode
            return self._sanitize_url(input_str)
        elif input_type == 'email':
            # For email input, validate format
            return self._sanitize_email(input_str)
        else:  # 'text' or default
            # For plain text, encode HTML entities
            return self._sanitize_text(input_str)
    
    def _sanitize_html(self, html: str) -> str:
        """Sanitize HTML input to prevent XSS attacks."""
        # Remove script tags and their content
        html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.IGNORECASE | re.DOTALL)
        # Remove event handlers
        html = re.sub(r'on\w+\s*=\s*["\'][^"\']*["\']', '', html, flags=re.IGNORECASE)
        
        # In strict mode, allow only specific safe tags
        if self.strict_mode:
            allowed_tags = {'b', 'i', 'u', 'strong', 'em', 'p', 'br', 'div', 'span'}
            # Remove any tags not in the allowed list
            pattern = r'<(?!\/?(?:' + '|'.join(allowed_tags) + r')\b)[^>]*>'
            html = re.sub(pattern, '', html)
        
        # Encode special HTML characters to prevent XSS
        html = html.replace('&', '&amp;')
        html = html.replace('<', '&lt;')
        html = html.replace('>', '&gt;')
        html = html.replace('"', '&quot;')
        html = html.replace("'", '&#x27;')
        
        return html
    
    def _sanitize_sql(self, sql_input: str) -> str:
        """Sanitize SQL input to prevent injection attacks."""
        # Escape single quotes (common SQL injection vector)
        sql_input = sql_input.replace("'", "''")
        # Escape double quotes
        sql_input = sql_input.replace('"', '""')
        # Escape backslashes
        sql_input = sql_input.replace('\\', '\\\\')
        
        # Remove SQL comments that could be used in attacks
        sql_input = re.sub(r'--.*$', '', sql_input, flags=re.MULTILINE)
        sql_input = re.sub(r'/\*.*?\*/', '', sql_input, flags=re.DOTALL)
        
        return sql_input
    
    def _sanitize_url(self, url: str) -> str:
        """Sanitize URL input by properly encoding components."""
        try:
            parsed = urllib.parse.urlparse(url)
            # Reconstruct URL with properly encoded components
            safe_url = urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                urllib.parse.quote(parsed.path),
                parsed.params,
                urllib.parse.quote(parsed.query),
                parsed.fragment
            ))
            return safe_url
        except Exception:
            # If URL parsing fails, return URL-encoded version
            return urllib.parse.quote(url)
    
    def _sanitize_email(self, email: str) -> str:
        """Sanitize and validate email address format."""
        email = email.strip().lower()
        
        # Basic email validation regex pattern
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return ""
        
        # Remove potentially dangerous characters
        email = re.sub(r'[<>]', '', email)
        
        return email
    
    def _sanitize_text(self, text: str) -> str:
        """Sanitize plain text input by encoding special characters."""
        # Encode HTML entities to prevent XSS
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        text = text.replace('"', '&quot;')
        text = text.replace("'", '&#x27;')
        
        # Remove control characters (except newline and tab)
        text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', text)
        
        return text
    
    def _contains_xss(self, text: str) -> bool:
        """Check if text contains XSS attack patterns."""
        # Iterate through compiled XSS patterns
        for pattern in self.compiled_xss_patterns:
            if pattern.search(text):
                return True
        return False
    
    def _contains_sql_injection(self, text: str) -> bool:
        """Check if text contains SQL injection patterns."""
        # Iterate through compiled SQL injection patterns
        for pattern in self.compiled_sql_patterns:
            if pattern.search(text):
                return True
        return False
    
    def _contains_path_traversal(self, path: str) -> bool:
        """Check if path contains directory traversal patterns."""
        # Check for various path traversal patterns
        for pattern in self.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                return True
        return False
    
    def check_xss_patterns(self, text: str) -> List[Dict[str, Any]]:
        """
        Check for XSS patterns in text and return detailed findings.
        
        Args:
            text: Text to analyze for XSS patterns
            
        Returns:
            List of dictionaries with pattern matches and locations
        """
        findings = []
        # Check each XSS pattern
        for i, pattern in enumerate(self.compiled_xss_patterns):
            matches = list(pattern.finditer(text))
            if matches:
                for match in matches:
                    findings.append({
                        'pattern': self.XSS_PATTERNS[i],
                        'match': match.group(),
                        'start': match.start(),
                        'end': match.end(),
                        'severity': 'HIGH'
                    })
        return findings
    
    def detect_sql_injection(self, text: str) -> List[Dict[str, Any]]:
        """
        Detect SQL injection patterns in text.
        
        Args:
            text: Text to analyze for SQL injection patterns
            
        Returns:
            List of dictionaries with SQL injection findings
        """
        findings = []
        # Check each SQL injection pattern
        for i, pattern in enumerate(self.compiled_sql_patterns):
            matches = list(pattern.finditer(text))
            if matches:
                for match in matches:
                    findings.append({
                        'pattern': self.SQL_INJECTION_PATTERNS[i],
                        'match': match.group(),
                        'start': match.start(),
                        'end': match.end(),
                        'severity': 'CRITICAL'
                    })
        return findings
    
    def validate_email(self, email: str) -> Tuple[bool, str]:
        """
        Validate email address format and security.
        
        Args:
            email: Email address to validate
            
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        if not email:
            return False, "Email is empty"
        
        email = email.strip().lower()
        
        # RFC 5322 compliant regex (simplified version)
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(email_regex, email):
            return False, "Invalid email format"
        
        # Check for disposable email domains (security risk)
        disposable_domains = {
            'tempmail.com', 'mailinator.com', 'guerrillamail.com',
            '10minutemail.com', 'throwawaymail.com', 'yopmail.com'
        }
        
        domain = email.split('@')[1]
        if domain in disposable_domains:
            return False, "Disposable email domain not allowed"
        
        # Check for suspicious patterns in email domain
        suspicious_patterns = [
            r'\.(exe|dll|bat|js|vbs)$',        # Executable-like domains
            r'localhost', r'127\.0\.0\.1',      # Localhost references
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, domain, re.IGNORECASE):
                return False, f"Suspicious email domain: {domain}"
        
        return True, ""
    
    def validate_ip_address(self, ip: str, allow_private: bool = False) -> Tuple[bool, str]:
        """
        Validate IP address format and type.
        
        Args:
            ip: IP address string to validate
            allow_private: Whether to allow private IP addresses
            
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check various IP address types for security
            if ip_obj.is_multicast:
                return False, "Multicast IP addresses not allowed"
            if ip_obj.is_reserved:
                return False, "Reserved IP addresses not allowed"
            if ip_obj.is_loopback:
                return False, "Loopback IP addresses not allowed"
            if ip_obj.is_link_local:
                return False, "Link-local IP addresses not allowed"
            if ip_obj.is_private and not allow_private:
                return False, "Private IP addresses not allowed"
            
            return True, ""
        except ValueError:
            return False, "Invalid IP address format"


class InputSanitizer:
    """
    Advanced input sanitizer with context-aware cleaning.
    
    This class provides context-aware sanitization based on the
    expected data type and usage context.
    """
    
    def __init__(self):
        # Initialize with a SecurityValidator instance
        self.validator = SecurityValidator()
    
    def sanitize_for_context(self, value: Any, context: str) -> Any:
        """
        Sanitize value based on usage context.
        
        Args:
            value: Value to sanitize
            context: Usage context ('html', 'sql', 'url_param', 'json', 'file_path')
            
        Returns:
            Sanitized value
            
        Raises:
            ValueError: If value cannot be safely sanitized for context
        """
        if value is None:
            return None
        
        # Route to appropriate sanitization method based on context
        if context == 'html':
            return self.sanitize_html(value)
        elif context == 'sql':
            return self.sanitize_sql(value)
        elif context == 'url_param':
            return self.sanitize_url_param(value)
        elif context == 'json':
            return self.sanitize_json(value)
        elif context == 'file_path':
            return self.sanitize_file_path(value)
        else:
            return self.sanitize_text(value)
    
    def sanitize_html(self, value: Union[str, List, Dict]) -> Union[str, List, Dict]:
        """Sanitize HTML content recursively."""
        if isinstance(value, str):
            return self.validator.sanitize_input(value, 'html')
        elif isinstance(value, list):
            # Recursively sanitize list items
            return [self.sanitize_html(item) for item in value]
        elif isinstance(value, dict):
            # Recursively sanitize dictionary values
            return {key: self.sanitize_html(val) for key, val in value.items()}
        else:
            # Convert non-string types to string and sanitize
            return str(value)
    
    def sanitize_sql(self, value: Union[str, List, Dict]) -> Union[str, List, Dict]:
        """Sanitize SQL values recursively."""
        if isinstance(value, str):
            return self.validator._sanitize_sql(value)
        elif isinstance(value, (int, float)):
            # Numbers don't need SQL sanitization
            return value
        elif isinstance(value, list):
            # Recursively sanitize list items
            return [self.sanitize_sql(item) for item in value]
        elif isinstance(value, dict):
            # Recursively sanitize dictionary values
            return {key: self.sanitize_sql(val) for key, val in value.items()}
        else:
            # Convert non-string types to string and sanitize
            return str(value)
    
    def sanitize_url_param(self, value: str) -> str:
        """Sanitize URL parameter values by URL encoding."""
        if not isinstance(value, str):
            value = str(value)
        # URL encode the value
        return urllib.parse.quote(value)
    
    def sanitize_json(self, value: Any) -> Any:
        """Sanitize JSON values recursively."""
        import json
        
        # Handle basic JSON types
        if isinstance(value, (str, int, float, bool, type(None))):
            return value
        elif isinstance(value, list):
            # Recursively sanitize list items
            return [self.sanitize_json(item) for item in value]
        elif isinstance(value, dict):
            # Recursively sanitize dictionary values
            return {key: self.sanitize_json(val) for key, val in value.items()}
        else:
            # Convert to string and sanitize as text
            return self.validator.sanitize_input(str(value), 'text')
    
    def sanitize_file_path(self, path: str) -> str:
        """Sanitize file paths to prevent directory traversal attacks."""
        if not path:
            return ""
        
        # Normalize path (removes redundant separators, etc.)
        path = os.path.normpath(path)
        
        # Remove null bytes (common in path traversal attacks)
        path = path.replace('\x00', '')
        
        # Check for path traversal attempts
        if '..' in path or path.startswith('/') or ':' in path:
            raise ValueError(f"Invalid file path: {path}")
        
        return path
    
    def sanitize_text(self, value: Union[str, List, Dict]) -> Union[str, List, Dict]:
        """Sanitize plain text recursively."""
        if isinstance(value, str):
            return self.validator.sanitize_input(value, 'text')
        elif isinstance(value, list):
            # Recursively sanitize list items
            return [self.sanitize_text(item) for item in value]
        elif isinstance(value, dict):
            # Recursively sanitize dictionary values
            return {key: self.sanitize_text(val) for key, val in value.items()}
        else:
            # Convert to string and sanitize
            return self.validator.sanitize_input(str(value), 'text')


# Standalone utility functions for easy module access

def validate_url(url: str, **kwargs) -> Tuple[bool, str]:
    """
    Validate URL with security checks.
    
    Args:
        url: URL to validate
        **kwargs: Additional arguments for SecurityValidator.validate_url
        
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    validator = SecurityValidator()
    return validator.validate_url(url, **kwargs)


def sanitize_input(input_str: str, input_type: str = 'text') -> str:
    """
    Sanitize user input to prevent attacks.
    
    Args:
        input_str: Input string to sanitize
        input_type: Type of input ('text', 'html', 'sql', 'url', 'email')
        
    Returns:
        Sanitized input string
    """
    validator = SecurityValidator()
    return validator.sanitize_input(input_str, input_type)


def hash_data(data: str, algorithm: str = 'sha256', salt: Optional[str] = None) -> str:
    """
    Generate secure hash of data.
    
    Args:
        data: Data to hash
        algorithm: Hash algorithm ('sha256', 'sha512', 'blake2b')
        salt: Optional salt for the hash
        
    Returns:
        Hex-encoded hash string
    """
    if not data:
        return ""
    
    data_str = str(data)
    # Prepend salt if provided
    if salt:
        data_str = salt + data_str
    
    # Select appropriate hash algorithm
    if algorithm == 'sha256':
        hasher = hashlib.sha256()
    elif algorithm == 'sha512':
        hasher = hashlib.sha512()
    elif algorithm == 'blake2b':
        hasher = hashlib.blake2b()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    # Update hasher with encoded data
    hasher.update(data_str.encode('utf-8'))
    # Return hexadecimal digest
    return hasher.hexdigest()


def verify_hash(data: str, hash_value: str, algorithm: str = 'sha256', 
               salt: Optional[str] = None) -> bool:
    """
    Verify data against a hash using constant-time comparison.
    
    Args:
        data: Data to verify
        hash_value: Expected hash value
        algorithm: Hash algorithm used
        salt: Optional salt used in original hash
        
    Returns:
        True if hash matches, False otherwise
    """
    computed_hash = hash_data(data, algorithm, salt)
    # Use hmac.compare_digest for constant-time comparison
    return hmac.compare_digest(computed_hash, hash_value)


def check_xss_patterns(text: str) -> List[Dict[str, Any]]:
    """
    Check text for XSS attack patterns.
    
    Args:
        text: Text to analyze for XSS patterns
        
    Returns:
        List of XSS pattern matches with details
    """
    validator = SecurityValidator()
    return validator.check_xss_patterns(text)


def detect_sql_injection(text: str) -> List[Dict[str, Any]]:
    """
    Detect SQL injection patterns in text.
    
    Args:
        text: Text to analyze for SQL injection patterns
        
    Returns:
        List of SQL injection pattern matches
    """
    validator = SecurityValidator()
    return validator.detect_sql_injection(text)


def validate_email(email: str) -> Tuple[bool, str]:
    """
    Validate email address format and security.
    
    Args:
        email: Email address to validate
        
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    validator = SecurityValidator()
    return validator.validate_email(email)


def validate_ip_address(ip: str, allow_private: bool = False) -> Tuple[bool, str]:
    """
    Validate IP address.
    
    Args:
        ip: IP address string to validate
        allow_private: Whether to allow private IP addresses
        
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    validator = SecurityValidator()
    return validator.validate_ip_address(ip, allow_private)


def generate_secure_token(length: int = 32) -> str:
    """
    Generate cryptographically secure random token.
    
    Args:
        length: Length of token in bytes
        
    Returns:
        URL-safe base64 encoded token
    """
    if length < 16:
        raise ValueError("Token length must be at least 16 bytes")
    
    # Generate cryptographically secure random bytes
    random_bytes = secrets.token_bytes(length)
    
    # Encode to URL-safe base64
    token = base64.urlsafe_b64encode(random_bytes).decode('utf-8')
    
    # Remove padding and truncate to desired length
    token = token.replace('=', '')[:length]
    
    return token


# Example usage and tests
if __name__ == "__main__":
    # Test the security utilities
    validator = SecurityValidator()
    
    # Test URL validation
    test_urls = [
        "https://example.com",
        "http://example.com",
        "javascript:alert('xss')",
        "https://example.com/<script>alert('xss')</script>",
    ]
    
    print("URL Validation Tests:")
    for url in test_urls:
        is_valid, message = validator.validate_url(url)
        print(f"  {url}: {is_valid} - {message}")
    
    # Test input sanitization
    test_inputs = [
        ("<script>alert('xss')</script>", "html"),
        ("' OR '1'='1", "sql"),
        ("test@example.com", "email"),
    ]
    
    print("\nInput Sanitization Tests:")
    for input_str, input_type in test_inputs:
        sanitized = validator.sanitize_input(input_str, input_type)
        print(f"  {input_str} -> {sanitized}")
    
    # Test hash generation
    data = "sensitive data"
    hash_value = hash_data(data, "sha256")
    print(f"\nHash Test: {data} -> {hash_value[:16]}...")
    
    # Verify hash
    is_valid = verify_hash(data, hash_value)
    print(f"Hash Verification: {is_valid}")