# src/web_security/header_analyzer.py
"""
HTTP Header Security Analyzer for CyberGuard
Analyzes HTTP request and response headers for security issues
Features: Security header validation, misconfiguration detection, attack pattern identification
"""

import re
import json
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime
import hashlib

@dataclass
class HeaderAnalysis:
    """Comprehensive HTTP header analysis results"""
    request_headers: Dict[str, str]          # Original request headers
    response_headers: Dict[str, str]         # Original response headers
    security_headers: Dict[str, Dict[str, Any]]  # Security header analysis
    missing_headers: List[Dict[str, Any]]    # Missing security headers
    misconfigured_headers: List[Dict[str, Any]]  # Misconfigured headers
    suspicious_headers: List[Dict[str, Any]]  # Suspicious or malicious headers
    information_disclosure: List[Dict[str, Any]]  # Information disclosure issues
    protocol_issues: List[Dict[str, Any]]    # HTTP protocol issues
    cookie_analysis: Dict[str, Any]          # Cookie security analysis
    cache_analysis: Dict[str, Any]           # Cache security analysis
    cors_analysis: Dict[str, Any]            # CORS security analysis
    security_score: float                    # Overall security score (0.0 to 1.0)

class HeaderAnalyzer:
    """
    Advanced HTTP header security analyzer
    Detects: Missing security headers, misconfigurations, information disclosure, attack patterns
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize header analyzer with configuration
        
        Args:
            config: Configuration dictionary containing analysis rules
        """
        self.config = config
        
        # Required security headers and their recommended values
        # Define required security headers with their security configurations
        self.required_headers = {
            'Content-Security-Policy': {
                'required': True,
                'secure_values': ["default-src 'self'", "script-src 'self'"],
                'insecure_values': ["'unsafe-inline'", "'unsafe-eval'", "*"],
                'severity': 'HIGH'
            },
            'X-Frame-Options': {
                'required': True,
                'secure_values': ['DENY', 'SAMEORIGIN'],
                'insecure_values': ['ALLOW-FROM'],
                'severity': 'HIGH'
            },
            'X-Content-Type-Options': {
                'required': True,
                'secure_values': ['nosniff'],
                'severity': 'MEDIUM'
            },
            'X-XSS-Protection': {
                'required': False,  # Deprecated but still useful for older browsers
                'secure_values': ['1; mode=block'],
                'severity': 'MEDIUM'
            },
            'Strict-Transport-Security': {
                'required': True,
                'secure_values': ['max-age=31536000', 'includeSubDomains'],
                'insecure_values': ['max-age=0'],
                'severity': 'HIGH'
            },
            'Referrer-Policy': {
                'required': True,
                'secure_values': ['no-referrer', 'same-origin', 'strict-origin'],
                'insecure_values': ['unsafe-url'],
                'severity': 'MEDIUM'
            },
        }
        
        # Headers that shouldn't be exposed (information disclosure)
        # These headers reveal server information that could help attackers
        self.sensitive_headers = [
            'Server',
            'X-Powered-By',
            'X-AspNet-Version',
            'X-AspNetMvc-Version',
            'X-Runtime',
            'X-Version',
            'X-Generator',
        ]
        
        # Suspicious header patterns (potential attacks)
        # Regular expressions to detect potential malicious patterns in headers
        self.suspicious_patterns = [
            (r'X-Forwarded-For.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'POTENTIAL_IP_SPOOFING'),
            (r'User-Agent.*(sqlmap|nikto|nmap|metasploit)', 'SECURITY_SCANNER'),
            (r'Referer.*(javascript:|data:|file:)', 'MALICIOUS_REFERER'),
            (r'Cookie.*[=;]\s*(union|select|insert|update|delete)', 'SQL_INJECTION_IN_COOKIE'),
            (r'Authorization.*Basic\s+[A-Za-z0-9+/]{20,}', 'BASE64_AUTH'),
        ]
        
        # Cookie security attributes and their requirements
        self.cookie_security_attrs = {
            'HttpOnly': {'required': True, 'severity': 'HIGH'},
            'Secure': {'required': True, 'severity': 'HIGH'},
            'SameSite': {'required': True, 'severity': 'MEDIUM'},
            'Max-Age': {'required': True, 'severity': 'MEDIUM'},
            'Path': {'required': True, 'severity': 'LOW'},
            'Domain': {'required': False, 'severity': 'LOW'},
        }
        
        # Cache control directives and their security implications
        self.cache_directives = {
            'no-store': {'security': 'HIGH', 'description': 'Prevents caching'},
            'no-cache': {'security': 'MEDIUM', 'description': 'Validates with server'},
            'private': {'security': 'MEDIUM', 'description': 'Client cache only'},
            'public': {'security': 'LOW', 'description': 'Public cache allowed'},
            'max-age': {'security': 'MEDIUM', 'description': 'Cache duration'},
        }
        
        # CORS headers and security configurations
        self.cors_headers = {
            'Access-Control-Allow-Origin': {
                'insecure_values': ['*'],
                'secure_pattern': r'^https?://[^,\s]+$'
            },
            'Access-Control-Allow-Credentials': {
                'warning': 'true with wildcard origin',
                'secure_with': 'specific origin'
            },
            'Access-Control-Allow-Methods': {
                'insecure_values': ['*'],
                'secure_values': ['GET', 'POST', 'PUT', 'DELETE']
            },
            'Access-Control-Allow-Headers': {
                'insecure_values': ['*'],
                'secure_values': ['Content-Type', 'Authorization']
            },
        }
        
        # Initialize statistics for tracking analysis metrics
        self.stats = {
            'headers_analyzed': 0,
            'security_issues_found': 0,
            'missing_headers': 0,
            'misconfigured_headers': 0,
        }
    
    def analyze_headers(self, request_headers: Dict[str, str], 
                       response_headers: Dict[str, str]) -> HeaderAnalysis:
        """
        Analyze HTTP request and response headers for security issues
        
        Args:
            request_headers: HTTP request headers (case-insensitive dict)
            response_headers: HTTP response headers (case-insensitive dict)
            
        Returns:
            HeaderAnalysis object with analysis results
        """
        # Normalize header keys to lowercase for consistent processing
        # This ensures case-insensitive header matching
        req_headers = {k.lower(): v for k, v in request_headers.items()}
        resp_headers = {k.lower(): v for k, v in response_headers.items()}
        
        # 1. Analyze security headers in response
        security_headers = self._analyze_security_headers(resp_headers)
        
        # 2. Check for missing security headers
        missing_headers = self._check_missing_headers(resp_headers)
        
        # 3. Check for misconfigured headers
        misconfigured_headers = self._check_misconfigured_headers(resp_headers)
        
        # 4. Analyze request headers for suspicious patterns
        suspicious_headers = self._analyze_suspicious_headers(req_headers)
        
        # 5. Check for information disclosure
        information_disclosure = self._check_information_disclosure(resp_headers)
        
        # 6. Check for protocol issues
        protocol_issues = self._check_protocol_issues(req_headers, resp_headers)
        
        # 7. Analyze cookies
        cookie_analysis = self._analyze_cookies(req_headers, resp_headers)
        
        # 8. Analyze cache headers
        cache_analysis = self._analyze_cache_headers(resp_headers)
        
        # 9. Analyze CORS headers
        cors_analysis = self._analyze_cors_headers(resp_headers)
        
        # 10. Calculate security score
        security_score = self._calculate_security_score(
            missing_headers, misconfigured_headers, suspicious_headers,
            information_disclosure, protocol_issues, cookie_analysis
        )
        
        # Update statistics
        self.stats['headers_analyzed'] += 1
        total_issues = (len(missing_headers) + len(misconfigured_headers) + 
                       len(suspicious_headers) + len(information_disclosure) + 
                       len(protocol_issues))
        if total_issues > 0:
            self.stats['security_issues_found'] += total_issues
        self.stats['missing_headers'] += len(missing_headers)
        self.stats['misconfigured_headers'] += len(misconfigured_headers)
        
        # Return comprehensive analysis results
        return HeaderAnalysis(
            request_headers=request_headers,
            response_headers=response_headers,
            security_headers=security_headers,
            missing_headers=missing_headers,
            misconfigured_headers=misconfigured_headers,
            suspicious_headers=suspicious_headers,
            information_disclosure=information_disclosure,
            protocol_issues=protocol_issues,
            cookie_analysis=cookie_analysis,
            cache_analysis=cache_analysis,
            cors_analysis=cors_analysis,
            security_score=security_score
        )
    
    def _analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
        """
        Analyze security headers in HTTP response
        
        Args:
            headers: HTTP response headers
            
        Returns:
            Dictionary of security header analysis
        """
        analysis = {}
        
        # Iterate through each required security header
        for header_name, header_config in self.required_headers.items():
            header_lower = header_name.lower()
            
            if header_lower in headers:
                # Header is present - analyze its value
                header_value = headers[header_lower]
                is_secure = self._is_header_secure(header_name, header_value)
                
                # Store analysis results
                analysis[header_name] = {
                    'present': True,
                    'value': header_value,
                    'secure': is_secure,
                    'severity': header_config['severity'],
                    'recommendation': self._get_header_recommendation(header_name, header_value)
                }
            else:
                # Header is missing
                analysis[header_name] = {
                    'present': False,
                    'value': None,
                    'secure': False,
                    'severity': header_config['severity'],
                    'recommendation': f'Add {header_name} header'
                }
        
        return analysis
    
    def _is_header_secure(self, header_name: str, header_value: str) -> bool:
        """
        Check if security header is securely configured
        
        Args:
            header_name: Security header name
            header_value: Header value
            
        Returns:
            True if header is securely configured
        """
        # If header is not in required headers list, assume it's secure
        if header_name not in self.required_headers:
            return True
        
        # Get header configuration
        config = self.required_headers[header_name]
        header_value_lower = header_value.lower()
        
        # Check for insecure values first
        if 'insecure_values' in config:
            for insecure_value in config['insecure_values']:
                if insecure_value.lower() in header_value_lower:
                    return False  # Header contains insecure value
        
        # Check for secure values
        if 'secure_values' in config:
            for secure_value in config['secure_values']:
                if secure_value.lower() in header_value_lower:
                    return True  # Header contains secure value
        
        # Default: check if value is non-empty
        # Return True if header has any value, False if empty
        return bool(header_value.strip())
    
    def _get_header_recommendation(self, header_name: str, header_value: str) -> str:
        """
        Get recommendation for security header configuration
        
        Args:
            header_name: Security header name
            header_value: Current header value
            
        Returns:
            Recommendation string
        """
        # Predefined recommendations for common security headers
        recommendations = {
            'Content-Security-Policy': 'Use strict CSP without unsafe directives',
            'X-Frame-Options': 'Set to DENY or SAMEORIGIN',
            'X-Content-Type-Options': 'Set to nosniff',
            'X-XSS-Protection': 'Set to 1; mode=block',
            'Strict-Transport-Security': 'Set to max-age=31536000; includeSubDomains',
            'Referrer-Policy': 'Set to no-referrer or same-origin',
        }
        
        # Return specific recommendation if available, otherwise generic one
        if header_name in recommendations:
            return recommendations[header_name]
        
        return 'Configure according to security best practices'
    
    def _check_missing_headers(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Check for missing security headers
        
        Args:
            headers: HTTP response headers
            
        Returns:
            List of missing headers with severity
        """
        missing = []
        
        # Check each required header
        for header_name, config in self.required_headers.items():
            # Only check headers marked as required
            if config['required'] and header_name.lower() not in headers:
                missing.append({
                    'header': header_name,
                    'severity': config['severity'],
                    'description': f'Missing required security header: {header_name}',
                    'recommendation': f'Add {header_name} header to response'
                })
        
        return missing
    
    def _check_misconfigured_headers(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Check for misconfigured headers
        
        Args:
            headers: HTTP response headers
            
        Returns:
            List of misconfigured headers
        """
        misconfigured = []
        
        # Check each required header that is present
        for header_name, config in self.required_headers.items():
            header_lower = header_name.lower()
            
            if header_lower in headers:
                header_value = headers[header_lower]
                
                # Check if header is securely configured
                if not self._is_header_secure(header_name, header_value):
                    misconfigured.append({
                        'header': header_name,
                        'value': header_value,
                        'severity': config['severity'],
                        'description': f'Misconfigured security header: {header_name}',
                        'issue': self._get_header_issue(header_name, header_value),
                        'recommendation': self._get_header_recommendation(header_name, header_value)
                    })
        
        return misconfigured
    
    def _get_header_issue(self, header_name: str, header_value: str) -> str:
        """
        Get specific issue with header configuration
        
        Args:
            header_name: Header name
            header_value: Header value
            
        Returns:
            Issue description
        """
        header_value_lower = header_value.lower()
        
        # Check specific issues for each header type
        if header_name == 'Content-Security-Policy':
            if "'unsafe-inline'" in header_value_lower:
                return 'Contains unsafe-inline directive'
            elif "'unsafe-eval'" in header_value_lower:
                return 'Contains unsafe-eval directive'
            elif '*' in header_value:
                return 'Contains wildcard source'
        
        elif header_name == 'X-Frame-Options':
            if 'allow-from' in header_value_lower:
                return 'Uses ALLOW-FROM (deprecated and insecure)'
        
        elif header_name == 'Strict-Transport-Security':
            if 'max-age=0' in header_value_lower:
                return 'Max-age set to 0 (disables HSTS)'
            elif 'max-age' not in header_value_lower:
                return 'Missing max-age directive'
        
        elif header_name == 'Referrer-Policy':
            if 'unsafe-url' in header_value_lower:
                return 'Uses unsafe-url policy'
        
        # Generic issue description
        return 'Insecure configuration'
    
    def _analyze_suspicious_headers(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Analyze request headers for suspicious patterns
        
        Args:
            headers: HTTP request headers
            
        Returns:
            List of suspicious headers found
        """
        suspicious = []
        
        # Check each header for suspicious patterns
        for header_name, header_value in headers.items():
            header_value_str = str(header_value)
            
            # Check each suspicious pattern
            for pattern, pattern_type in self.suspicious_patterns:
                if re.search(pattern, header_value_str, re.IGNORECASE):
                    suspicious.append({
                        'header': header_name,
                        'value': header_value_str[:100],  # First 100 chars to avoid large output
                        'type': pattern_type,
                        'severity': 'HIGH',
                        'description': f'Suspicious pattern in header {header_name}: {pattern_type}',
                        'recommendation': 'Investigate and potentially block request'
                    })
            
            # Check for overly long headers (potential buffer overflow attacks)
            if len(header_value_str) > 8192:  # 8KB limit (common web server limit)
                suspicious.append({
                    'header': header_name,
                    'value_length': len(header_value_str),
                    'type': 'OVERSIZED_HEADER',
                    'severity': 'MEDIUM',
                    'description': f'Header {header_name} is excessively large ({len(header_value_str)} bytes)',
                    'recommendation': 'Limit header size to 8KB'
                })
        
        return suspicious
    
    def _check_information_disclosure(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Check for information disclosure in headers
        
        Args:
            headers: HTTP response headers
            
        Returns:
            List of information disclosure issues
        """
        disclosures = []
        
        # Check for sensitive headers that should not be exposed
        for header_name in self.sensitive_headers:
            header_lower = header_name.lower()
            
            if header_lower in headers:
                header_value = headers[header_lower]
                
                disclosures.append({
                    'header': header_name,
                    'value': header_value,
                    'severity': 'LOW',
                    'description': f'Information disclosure: {header_name} header exposed',
                    'recommendation': f'Remove or obfuscate {header_name} header'
                })
        
        # Check for detailed error information in version headers
        error_headers = ['x-aspnet-version', 'x-powered-by', 'server']
        for header in error_headers:
            if header in headers:
                value = headers[header]
                # Check if value contains version numbers (e.g., Apache/2.4.41)
                if re.search(r'\d+\.\d+(\.\d+)?', value):
                    disclosures.append({
                        'header': header,
                        'value': value,
                        'severity': 'MEDIUM',
                        'description': f'Version information disclosed in {header} header',
                        'recommendation': 'Remove version information from headers'
                    })
        
        return disclosures
    
    def _check_protocol_issues(self, req_headers: Dict[str, str], 
                             resp_headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Check for HTTP protocol issues
        
        Args:
            req_headers: Request headers
            resp_headers: Response headers
            
        Returns:
            List of protocol issues
        """
        issues = []
        
        # Check for HTTP instead of HTTPS in forwarded requests
        if 'x-forwarded-proto' in req_headers:
            if req_headers['x-forwarded-proto'] == 'http':
                issues.append({
                    'type': 'INSECURE_PROTOCOL',
                    'severity': 'HIGH',
                    'description': 'Request forwarded via HTTP instead of HTTPS',
                    'location': 'X-Forwarded-Proto header',
                    'recommendation': 'Enforce HTTPS for all requests'
                })
        
        # Check for missing HSTS on HTTPS connections
        if 'x-forwarded-proto' in req_headers and req_headers['x-forwarded-proto'] == 'https':
            if 'strict-transport-security' not in resp_headers:
                issues.append({
                    'type': 'MISSING_HSTS',
                    'severity': 'HIGH',
                    'description': 'HTTPS response missing Strict-Transport-Security header',
                    'location': 'Response headers',
                    'recommendation': 'Add Strict-Transport-Security header for HTTPS'
                })
        
        # Check for insecure redirects (HTTP instead of HTTPS)
        if 'location' in resp_headers:
            location = resp_headers['location']
            if location.startswith('http://'):
                issues.append({
                    'type': 'INSECURE_REDIRECT',
                    'severity': 'HIGH',
                    'description': f'Redirect to insecure HTTP URL: {location}',
                    'location': 'Location header',
                    'recommendation': 'Use HTTPS for all redirects'
                })
        
        return issues
    
    def _analyze_cookies(self, req_headers: Dict[str, str], 
                        resp_headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Analyze cookie security
        
        Args:
            req_headers: Request headers
            resp_headers: Response headers
            
        Returns:
            Cookie security analysis
        """
        # Initialize analysis structure
        analysis = {
            'cookies_found': False,
            'secure_cookies': 0,
            'insecure_cookies': 0,
            'issues': [],
            'recommendations': []
        }
        
        # Check Set-Cookie headers in response
        if 'set-cookie' in resp_headers:
            analysis['cookies_found'] = True
            
            # Handle multiple Set-Cookie headers (can be string or list)
            set_cookie_values = resp_headers['set-cookie']
            if isinstance(set_cookie_values, str):
                # Single cookie - convert to list for consistent processing
                set_cookie_values = [set_cookie_values]
            elif not isinstance(set_cookie_values, list):
                # If it's neither string nor list, make it an empty list
                set_cookie_values = []
            
            # Analyze each cookie
            for cookie_str in set_cookie_values:
                cookie_analysis = self._analyze_single_cookie(str(cookie_str))
                
                if cookie_analysis['secure']:
                    analysis['secure_cookies'] += 1
                else:
                    analysis['insecure_cookies'] += 1
                
                if cookie_analysis['issues']:
                    analysis['issues'].extend(cookie_analysis['issues'])
        
        # Add recommendations based on analysis
        if analysis['insecure_cookies'] > 0:
            analysis['recommendations'].append('Add HttpOnly and Secure flags to all cookies')
        
        # Check for session fixation vulnerability
        if 'set-cookie' in resp_headers:
            # Extract cookie string(s) for checking
            cookie_str = resp_headers['set-cookie']
            if isinstance(cookie_str, list):
                cookie_str = ' '.join(cookie_str)
            if 'session' in cookie_str.lower():
                analysis['recommendations'].append('Consider regenerating session IDs on login')
        
        return analysis
    
    def _analyze_single_cookie(self, cookie_str: str) -> Dict[str, Any]:
        """
        Analyze a single Set-Cookie header value
        
        Args:
            cookie_str: Set-Cookie header value
            
        Returns:
            Single cookie analysis
        """
        # Initialize analysis structure
        analysis = {
            'secure': True,  # Start assuming cookie is secure
            'issues': [],
            'attributes': {}
        }
        
        # Parse cookie string into parts
        parts = cookie_str.split(';')
        cookie_name_value = parts[0].strip()
        
        # Extract and analyze each attribute
        for part in parts[1:]:
            part = part.strip()
            if '=' in part:
                # Attribute with value (e.g., Max-Age=3600)
                attr_name, attr_value = part.split('=', 1)
            else:
                # Boolean attribute (e.g., HttpOnly, Secure)
                attr_name, attr_value = part, True
            
            attr_name_lower = attr_name.lower()
            analysis['attributes'][attr_name_lower] = attr_value
            
            # Check security attributes
            if attr_name_lower == 'httponly':
                if not attr_value:
                    analysis['issues'].append({
                        'type': 'MISSING_HTTPONLY',
                        'severity': 'HIGH',
                        'description': 'Cookie missing HttpOnly flag',
                        'recommendation': 'Add HttpOnly flag to prevent JavaScript access'
                    })
                    analysis['secure'] = False
            
            elif attr_name_lower == 'secure':
                if not attr_value:
                    analysis['issues'].append({
                        'type': 'MISSING_SECURE_FLAG',
                        'severity': 'HIGH',
                        'description': 'Cookie missing Secure flag',
                        'recommendation': 'Add Secure flag for HTTPS-only transmission'
                    })
                    analysis['secure'] = False
            
            elif attr_name_lower == 'samesite':
                if attr_value.lower() not in ['strict', 'lax']:
                    analysis['issues'].append({
                        'type': 'WEAK_SAMESITE',
                        'severity': 'MEDIUM',
                        'description': f'Weak SameSite value: {attr_value}',
                        'recommendation': 'Set SameSite=Strict or SameSite=Lax'
                    })
        
        # Check for missing required attributes
        if 'httponly' not in analysis['attributes']:
            analysis['issues'].append({
                'type': 'MISSING_HTTPONLY',
                'severity': 'HIGH',
                'description': 'Cookie missing HttpOnly flag',
                'recommendation': 'Add HttpOnly flag'
            })
            analysis['secure'] = False
        
        if 'secure' not in analysis['attributes']:
            analysis['issues'].append({
                'type': 'MISSING_SECURE_FLAG',
                'severity': 'HIGH',
                'description': 'Cookie missing Secure flag',
                'recommendation': 'Add Secure flag'
            })
            analysis['secure'] = False
        
        if 'samesite' not in analysis['attributes']:
            analysis['issues'].append({
                'type': 'MISSING_SAMESITE',
                'severity': 'MEDIUM',
                'description': 'Cookie missing SameSite attribute',
                'recommendation': 'Add SameSite=Strict or SameSite=Lax'
            })
        
        return analysis
    
    def _analyze_cache_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Analyze cache control headers for security
        
        Args:
            headers: HTTP response headers
            
        Returns:
            Cache security analysis
        """
        # Initialize analysis structure
        analysis = {
            'cache_control_present': False,
            'cache_directives': {},
            'security_issues': [],
            'recommendations': []
        }
        
        # Check for Cache-Control header
        if 'cache-control' in headers:
            analysis['cache_control_present'] = True
            cache_control = headers['cache-control'].lower()
            
            # Parse directives (comma-separated)
            directives = [d.strip() for d in cache_control.split(',')]
            
            # Extract each directive
            for directive in directives:
                if '=' in directive:
                    name, value = directive.split('=', 1)
                else:
                    name, value = directive, True
                
                analysis['cache_directives'][name] = value
            
            # Check security - sensitive content should not be cached
            if 'no-store' not in analysis['cache_directives']:
                analysis['security_issues'].append({
                    'type': 'MISSING_NO_STORE',
                    'severity': 'MEDIUM',
                    'description': 'Cache-Control missing no-store directive for sensitive content',
                    'recommendation': 'Add no-store directive for sensitive responses'
                })
            
            # Check for public caching of sensitive data
            if 'private' not in analysis['cache_directives'] and 'no-store' not in analysis['cache_directives']:
                analysis['security_issues'].append({
                    'type': 'PUBLIC_CACHE',
                    'severity': 'LOW',
                    'description': 'Response may be cached publicly',
                    'recommendation': 'Add private or no-store directive'
                })
        
        else:
            # Missing Cache-Control header
            analysis['security_issues'].append({
                'type': 'MISSING_CACHE_CONTROL',
                'severity': 'LOW',
                'description': 'Missing Cache-Control header',
                'recommendation': 'Add Cache-Control header with appropriate directives'
            })
        
        # Check for other cache-related headers
        if 'pragma' in headers and 'no-cache' in headers['pragma'].lower():
            analysis['cache_directives']['pragma'] = 'no-cache'
        
        if 'expires' in headers:
            analysis['cache_directives']['expires'] = headers['expires']
        
        return analysis
    
    def _analyze_cors_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Analyze CORS headers for security
        
        Args:
            headers: HTTP response headers
            
        Returns:
            CORS security analysis
        """
        # Initialize analysis structure
        analysis = {
            'cors_enabled': False,
            'headers_present': {},
            'security_issues': [],
            'recommendations': []
        }
        
        # Check for presence of CORS headers
        for header_name in self.cors_headers.keys():
            header_lower = header_name.lower()
            if header_lower in headers:
                analysis['cors_enabled'] = True
                analysis['headers_present'][header_name] = headers[header_lower]
        
        # If CORS is enabled, analyze the configuration
        if analysis['cors_enabled']:
            # Analyze Access-Control-Allow-Origin header
            if 'Access-Control-Allow-Origin' in analysis['headers_present']:
                origin = analysis['headers_present']['Access-Control-Allow-Origin']
                
                # Wildcard origin is insecure
                if origin == '*':
                    analysis['security_issues'].append({
                        'type': 'WILDCARD_CORS_ORIGIN',
                        'severity': 'HIGH',
                        'description': 'CORS allows wildcard origin (*)',
                        'recommendation': 'Restrict to specific origins'
                    })
                
                # Check for credentials with wildcard origin (critical security issue)
                if origin == '*' and 'Access-Control-Allow-Credentials' in analysis['headers_present']:
                    if analysis['headers_present']['Access-Control-Allow-Credentials'].lower() == 'true':
                        analysis['security_issues'].append({
                            'type': 'INSECURE_CORS_CREDENTIALS',
                            'severity': 'CRITICAL',
                            'description': 'CORS allows credentials with wildcard origin',
                            'recommendation': 'Disallow credentials or restrict origin'
                        })
            
            # Analyze Access-Control-Allow-Methods header
            if 'Access-Control-Allow-Methods' in analysis['headers_present']:
                methods = analysis['headers_present']['Access-Control-Allow-Methods']
                if methods == '*':
                    analysis['security_issues'].append({
                        'type': 'WILDCARD_CORS_METHODS',
                        'severity': 'MEDIUM',
                        'description': 'CORS allows all HTTP methods',
                        'recommendation': 'Restrict to specific methods'
                    })
            
            # Analyze Access-Control-Allow-Headers header
            if 'Access-Control-Allow-Headers' in analysis['headers_present']:
                headers_list = analysis['headers_present']['Access-Control-Allow-Headers']
                if headers_list == '*':
                    analysis['security_issues'].append({
                        'type': 'WILDCARD_CORS_HEADERS',
                        'severity': 'MEDIUM',
                        'description': 'CORS allows all HTTP headers',
                        'recommendation': 'Restrict to specific headers'
                    })
        
        return analysis
    
    def _calculate_security_score(self, missing_headers: List[Dict[str, Any]],
                                misconfigured_headers: List[Dict[str, Any]],
                                suspicious_headers: List[Dict[str, Any]],
                                information_disclosure: List[Dict[str, Any]],
                                protocol_issues: List[Dict[str, Any]],
                                cookie_analysis: Dict[str, Any]) -> float:
        """
        Calculate overall header security score
        
        Args:
            missing_headers: List of missing headers
            misconfigured_headers: List of misconfigured headers
            suspicious_headers: List of suspicious headers
            information_disclosure: List of information disclosure issues
            protocol_issues: List of protocol issues
            cookie_analysis: Cookie analysis results
            
        Returns:
            Security score between 0.0 (worst) and 1.0 (best)
        """
        # Severity weights for different types of issues
        severity_weights = {
            'CRITICAL': 0.9,
            'HIGH': 0.7,
            'MEDIUM': 0.4,
            'LOW': 0.1,
        }
        
        penalty = 0.0  # Start with no penalty
        
        # Calculate penalty from missing headers
        for issue in missing_headers:
            severity = issue.get('severity', 'LOW')
            penalty += severity_weights.get(severity, 0.1) * 0.3
        
        # Calculate penalty from misconfigured headers
        for issue in misconfigured_headers:
            severity = issue.get('severity', 'LOW')
            penalty += severity_weights.get(severity, 0.1) * 0.4
        
        # Calculate penalty from suspicious headers
        for issue in suspicious_headers:
            severity = issue.get('severity', 'LOW')
            penalty += severity_weights.get(severity, 0.1) * 0.6
        
        # Calculate penalty from information disclosure
        for issue in information_disclosure:
            severity = issue.get('severity', 'LOW')
            penalty += severity_weights.get(severity, 0.1) * 0.2
        
        # Calculate penalty from protocol issues
        for issue in protocol_issues:
            severity = issue.get('severity', 'LOW')
            penalty += severity_weights.get(severity, 0.1) * 0.5
        
        # Calculate penalty from cookie issues
        if cookie_analysis.get('issues'):
            for issue in cookie_analysis['issues']:
                severity = issue.get('severity', 'LOW')
                penalty += severity_weights.get(severity, 0.1) * 0.7
        
        # Count total issues for normalization
        total_issues = (len(missing_headers) + len(misconfigured_headers) + 
                       len(suspicious_headers) + len(information_disclosure) + 
                       len(protocol_issues) + len(cookie_analysis.get('issues', [])))
        
        # Normalize penalty with diminishing returns (more issues don't linearly increase penalty)
        normalized_penalty = min(penalty / (1 + total_issues * 0.1), 1.0)
        
        # Security score is inverse of penalty
        security_score = 1.0 - normalized_penalty
        
        # Ensure score is within [0.0, 1.0] range
        return max(0.0, min(1.0, security_score))
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get analyzer statistics
        
        Returns:
            Dictionary of statistics
        """
        # Return a copy to prevent external modification
        return self.stats.copy()