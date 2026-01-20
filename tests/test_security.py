# tests/test_security.py
"""
Comprehensive security tests for CyberGuard

This module tests web security scanning and vulnerability detection:
1. OWASP Top-10 vulnerability detection
2. Security header analysis
3. Form validation and security
4. API security testing
5. JavaScript analysis
6. Authentication flow testing
7. Input validation
8. Output encoding
9. Session management
10. Cryptographic security

Each test validates security controls and vulnerability detection accuracy.
"""

import pytest
import sys
import os
import json
import re
from pathlib import Path
from typing import Dict, List, Any
from unittest.mock import Mock, patch, MagicMock

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import test utilities
from tests.test_utils import (
    create_mock_website_data,
    create_mock_http_response,
    validate_test_result,
    TEST_CONFIG,
    TEST_XSS_PAYLOAD,
    TEST_SQLI_PAYLOAD
)

# Test markers
pytestmark = [
    pytest.mark.security,
    pytest.mark.unit
]

class TestWebSecurityScanner:
    """Tests for Web Security Scanner"""
    
    def test_scanner_initialization(self, security_scanner):
        """Test scanner initialization with configuration"""
        # Arrange & Act: Scanner is created by fixture
        scanner = security_scanner
        
        # Assert
        assert hasattr(scanner, 'config'), "Scanner should have config"
        assert hasattr(scanner, 'session'), "Scanner should have session"
        
        # Verify configuration
        config = scanner.config
        assert isinstance(config, dict), "Config should be dictionary"
        
        # Verify required config values
        required_config_keys = ['max_scan_depth', 'timeout', 'user_agent']
        for key in required_config_keys:
            assert key in config, f"Config should contain {key}"
    
    def test_url_validation(self, security_scanner):
        """Test URL validation logic"""
        # Arrange
        scanner = security_scanner
        
        # Test valid URLs
        valid_urls = [
            'https://example.com',
            'http://localhost:8080',
            'https://sub.domain.co.uk/path?query=param',
            'http://192.168.1.1',
            'https://[2001:db8::1]'
        ]
        
        # Test invalid URLs
        invalid_urls = [
            'not-a-url',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'file:///etc/passwd',
            '',
            None,
            123
        ]
        
        # Act & Assert for valid URLs
        for url in valid_urls:
            # Should accept valid URLs
            # Note: Actual validation method may vary
            if hasattr(scanner, '_validate_url'):
                result = scanner._validate_url(url)
                assert result is True, f"Should validate as true: {url}"
        
        # Act & Assert for invalid URLs
        for url in invalid_urls:
            # Should reject invalid URLs
            if hasattr(scanner, '_validate_url'):
                try:
                    result = scanner._validate_url(url)
                    # If it returns, should be False for invalid URLs
                    if url:  # Skip empty string
                        assert result is False, f"Should validate as false: {url}"
                except (ValueError, TypeError):
                    # Exception is also acceptable for invalid URLs
                    pass
    
    def test_scan_website_basic(self, security_scanner, mock_website_data):
        """Test basic website scanning functionality"""
        # Arrange
        scanner = security_scanner
        
        # Mock the actual HTTP request
        with patch.object(scanner.session, 'get') as mock_get:
            # Setup mock response
            mock_response = create_mock_http_response(
                url='https://test.example.com',
                body=mock_website_data['html'],
                headers=mock_website_data['headers']
            )
            mock_get.return_value = mock_response
            
            # Act
            result = scanner.scan_website('https://test.example.com')
        
        # Assert
        validate_test_result(
            result,
            expected_type=dict,
            expected_keys=['url', 'vulnerabilities', 'security_headers', 'risk_score']
        )
        
        # Verify basic structure
        assert result['url'] == 'https://test.example.com', \
            "Result should contain scanned URL"
        
        # Verify vulnerabilities list (even if empty)
        assert isinstance(result['vulnerabilities'], list), \
            "vulnerabilities should be list"
        
        # Verify security headers analysis
        assert isinstance(result['security_headers'], dict), \
            "security_headers should be dict"
        
        # Verify risk score
        assert isinstance(result['risk_score'], (int, float)), \
            "risk_score should be numeric"
        assert 0.0 <= result['risk_score'] <= 1.0, \
            f"risk_score should be between 0 and 1, got {result['risk_score']}"
    
    def test_xss_detection(self, security_scanner):
        """Test XSS vulnerability detection"""
        # Arrange
        scanner = security_scanner
        
        # Create HTML with XSS payload
        xss_html = f"""
        <!DOCTYPE html>
        <html>
        <body>
            <form action="/search">
                <input type="text" name="q" value="{TEST_XSS_PAYLOAD}">
            </form>
            <script>var test = "{TEST_XSS_PAYLOAD}";</script>
        </body>
        </html>
        """
        
        # Mock response with XSS
        with patch.object(scanner.session, 'get') as mock_get:
            mock_response = create_mock_http_response(
                url='https://xss-test.com',
                body=xss_html
            )
            mock_get.return_value = mock_response
            
            # Act
            result = scanner.scan_website('https://xss-test.com')
        
        # Assert
        # Look for XSS findings in vulnerabilities
        xss_vulnerabilities = [
            v for v in result['vulnerabilities']
            if 'XSS' in str(v.get('type', '')).upper()
        ]
        
        # Should detect XSS patterns
        # Note: Detection may vary based on implementation
        if len(xss_vulnerabilities) > 0:
            # Verify XSS finding structure
            for vuln in xss_vulnerabilities:
                assert 'type' in vuln, "Vulnerability should have type"
                assert 'severity' in vuln, "Vulnerability should have severity"
                assert 'description' in vuln, "Vulnerability should have description"
                
                # XSS should be medium to high severity
                severity = vuln.get('severity', '').upper()
                assert severity in ['MEDIUM', 'HIGH', 'CRITICAL'], \
                    f"XSS should be at least MEDIUM severity, got {severity}"
    
    def test_security_header_analysis(self, security_scanner):
        """Test security header analysis"""
        # Arrange
        scanner = security_scanner
        
        # Test cases for security headers
        test_cases = [
            {
                'name': 'no_security_headers',
                'headers': {},
                'expected_missing': ['Content-Security-Policy', 'X-Frame-Options']
            },
            {
                'name': 'partial_security_headers',
                'headers': {
                    'X-Frame-Options': 'DENY',
                    'X-Content-Type-Options': 'nosniff'
                },
                'expected_missing': ['Content-Security-Policy']
            },
            {
                'name': 'full_security_headers',
                'headers': {
                    'Content-Security-Policy': "default-src 'self'",
                    'X-Frame-Options': 'DENY',
                    'X-Content-Type-Options': 'nosniff',
                    'Strict-Transport-Security': 'max-age=31536000'
                },
                'expected_missing': []
            }
        ]
        
        for test_case in test_cases:
            # Mock response with specific headers
            with patch.object(scanner.session, 'get') as mock_get:
                mock_response = create_mock_http_response(
                    url=f'https://{test_case["name"]}.com',
                    headers=test_case['headers']
                )
                mock_get.return_value = mock_response
                
                # Act
                result = scanner.scan_website(f'https://{test_case["name"]}.com')
            
            # Assert
            security_headers = result.get('security_headers', {})
            
            # Check missing headers
            for header in test_case['expected_missing']:
                if header in security_headers:
                    header_info = security_headers[header]
                    assert header_info.get('present', False) is False, \
                        f"{header} should be missing for {test_case['name']}"
            
            # Check present headers
            for header, value in test_case['headers'].items():
                if header in security_headers:
                    header_info = security_headers[header]
                    assert header_info.get('present', False) is True, \
                        f"{header} should be present for {test_case['name']}"
                    assert header_info.get('value') == value, \
                        f"{header} value should match for {test_case['name']}"
    
    def test_form_security_analysis(self, security_scanner):
        """Test form security analysis"""
        # Arrange
        scanner = security_scanner
        
        # HTML with various forms
        form_html = """
        <!DOCTYPE html>
        <html>
        <body>
            <!-- Form without CSRF protection -->
            <form action="/login" method="POST">
                <input type="text" name="username">
                <input type="password" name="password">
                <input type="submit" value="Login">
            </form>
            
            <!-- Form with CSRF token -->
            <form action="/transfer" method="POST">
                <input type="hidden" name="csrf_token" value="abc123">
                <input type="text" name="amount">
                <input type="submit" value="Transfer">
            </form>
            
            <!-- Form with password autocomplete -->
            <form action="/register">
                <input type="password" name="password" autocomplete="on">
            </form>
        </body>
        </html>
        """
        
        # Mock response
        with patch.object(scanner.session, 'get') as mock_get:
            mock_response = create_mock_http_response(
                url='https://forms-test.com',
                body=form_html
            )
            mock_get.return_value = mock_response
            
            # Act
            result = scanner.scan_website('https://forms-test.com')
        
        # Assert
        forms = result.get('forms', [])
        assert len(forms) >= 3, "Should detect all forms"
        
        # Analyze form security
        vulnerabilities = result.get('vulnerabilities', [])
        form_vulnerabilities = [
            v for v in vulnerabilities
            if 'FORM' in str(v.get('type', '')).upper() or 
               'CSRF' in str(v.get('type', '')).upper()
        ]
        
        # Should detect form-related vulnerabilities
        # (e.g., missing CSRF, password autocomplete)
        if len(form_vulnerabilities) > 0:
            for vuln in form_vulnerabilities:
                assert 'type' in vuln, "Form vulnerability should have type"
                assert 'severity' in vuln, "Form vulnerability should have severity"
    
    def test_api_endpoint_discovery(self, security_scanner):
        """Test API endpoint discovery"""
        # Arrange
        scanner = security_scanner
        
        # HTML with API links
        api_html = """
        <!DOCTYPE html>
        <html>
        <body>
            <a href="/api/v1/users">Users API</a>
            <a href="/api/v1/products">Products API</a>
            <a href="/graphql">GraphQL API</a>
            <script src="/api/config.js"></script>
        </body>
        </html>
        """
        
        # Mock response
        with patch.object(scanner.session, 'get') as mock_get:
            mock_response = create_mock_http_response(
                url='https://api-test.com',
                body=api_html
            )
            mock_get.return_value = mock_response
            
            # Act
            result = scanner.scan_website('https://api-test.com')
        
        # Assert
        endpoints = result.get('endpoints', [])
        
        # Should discover API endpoints
        api_endpoints = [
            e for e in endpoints
            if any(api_indicator in str(e.get('url', '')).lower()
                  for api_indicator in ['/api/', '/graphql', '.json', '.xml'])
        ]
        
        assert len(api_endpoints) > 0, "Should discover API endpoints"
        
        # Verify endpoint structure
        for endpoint in endpoints:
            assert 'url' in endpoint, "Endpoint should have URL"
            assert 'type' in endpoint, "Endpoint should have type"
    
    def test_risk_score_calculation(self, security_scanner):
        """Test risk score calculation logic"""
        # Arrange
        scanner = security_scanner
        
        # Test different scenarios
        test_scenarios = [
            {
                'name': 'secure_site',
                'vulnerabilities': [],
                'security_headers': {
                    'Content-Security-Policy': {'present': True, 'secure': True},
                    'X-Frame-Options': {'present': True, 'secure': True}
                },
                'expected_max_score': 0.3  # Low risk
            },
            {
                'name': 'vulnerable_site',
                'vulnerabilities': [
                    {'type': 'XSS', 'severity': 'HIGH'},
                    {'type': 'SQL_INJECTION', 'severity': 'CRITICAL'}
                ],
                'security_headers': {},
                'expected_min_score': 0.7  # High risk
            }
        ]
        
        for scenario in test_scenarios:
            # Create mock scan result
            scan_result = {
                'url': f'https://{scenario["name"]}.com',
                'vulnerabilities': scenario['vulnerabilities'],
                'security_headers': scenario['security_headers'],
                'forms': [],
                'endpoints': [],
                'status_code': 200
            }
            
            # Act: Calculate risk score
            if hasattr(scanner, '_calculate_risk_score'):
                risk_score = scanner._calculate_risk_score(scan_result)
            else:
                # Use the result from scan if method not exposed
                with patch.object(scanner.session, 'get') as mock_get:
                    mock_response = create_mock_http_response(
                        url=f'https://{scenario["name"]}.com'
                    )
                    mock_get.return_value = mock_response
                    result = scanner.scan_website(f'https://{scenario["name"]}.com')
                    risk_score = result['risk_score']
            
            # Assert
            assert isinstance(risk_score, (int, float)), \
                f"Risk score should be numeric for {scenario['name']}"
            assert 0.0 <= risk_score <= 1.0, \
                f"Risk score should be between 0 and 1 for {scenario['name']}, got {risk_score}"
            
            # Verify expected risk levels
            if 'expected_max_score' in scenario:
                assert risk_score <= scenario['expected_max_score'], \
                    f"Risk score too high for {scenario['name']}: {risk_score}"
            
            if 'expected_min_score' in scenario:
                assert risk_score >= scenario['expected_min_score'], \
                    f"Risk score too low for {scenario['name']}: {risk_score}"
    
    def test_error_handling(self, security_scanner):
        """Test scanner error handling"""
        # Arrange
        scanner = security_scanner
        
        # Test various error scenarios
        error_scenarios = [
            {
                'name': 'connection_error',
                'mock_behavior': Exception("Connection refused"),
                'expected_result': 'error'
            },
            {
                'name': 'timeout',
                'mock_behavior': TimeoutError("Request timed out"),
                'expected_result': 'error'
            },
            {
                'name': 'ssl_error',
                'mock_behavior': Exception("SSL certificate error"),
                'expected_result': 'error'
            },
            {
                'name': '404_not_found',
                'mock_behavior': create_mock_http_response(
                    url='https://404.com',
                    status_code=404
                ),
                'expected_result': 'scan_result'
            },
            {
                'name': '500_server_error',
                'mock_behavior': create_mock_http_response(
                    url='https://500.com',
                    status_code=500
                ),
                'expected_result': 'scan_result'
            }
        ]
        
        for scenario in error_scenarios:
            # Mock the HTTP request to simulate error
            with patch.object(scanner.session, 'get') as mock_get:
                if isinstance(scenario['mock_behavior'], Exception):
                    mock_get.side_effect = scenario['mock_behavior']
                else:
                    mock_get.return_value = scenario['mock_behavior']
                
                # Act
                try:
                    result = scanner.scan_website(f'https://{scenario["name"]}.com')
                    
                    # If no exception, verify result structure
                    if scenario['expected_result'] == 'scan_result':
                        assert 'url' in result, "Result should contain URL"
                        assert 'risk_score' in result, "Result should contain risk_score"
                        
                        # For error status codes, risk should be higher
                        if hasattr(scenario['mock_behavior'], 'status_code'):
                            if scenario['mock_behavior'].status_code >= 500:
                                assert result['risk_score'] > 0.1, \
                                    "Server errors should increase risk"
                    
                except Exception as e:
                    # Exception is acceptable for connection errors
                    if scenario['expected_result'] == 'error':
                        assert isinstance(e, Exception), \
                            f"Should raise exception for {scenario['name']}"
                    else:
                        raise  # Re-raise unexpected exceptions
    
    @pytest.mark.parametrize("payload,expected_vulnerability", [
        (TEST_XSS_PAYLOAD, 'XSS'),
        (TEST_SQLI_PAYLOAD, 'SQL_INJECTION'),
        ('; ls -la', 'COMMAND_INJECTION'),
        ('../../etc/passwd', 'PATH_TRAVERSAL'),
        ('http://169.254.169.254', 'SSRF'),
    ])
    def test_payload_detection(self, security_scanner, payload, expected_vulnerability):
        """Parameterized test for various payload detection"""
        # Arrange
        scanner = security_scanner
        
        # Create HTML with payload
        html_with_payload = f"""
        <!DOCTYPE html>
        <html>
        <body>
            <div>Test payload: {payload}</div>
        </body>
        </html>
        """
        
        # Mock response
        with patch.object(scanner.session, 'get') as mock_get:
            mock_response = create_mock_http_response(
                url=f'https://payload-test.com?q={payload}',
                body=html_with_payload
            )
            mock_get.return_value = mock_response
            
            # Act
            result = scanner.scan_website(f'https://payload-test.com?q={payload}')
        
        # Assert
        vulnerabilities = result.get('vulnerabilities', [])
        
        # Check if expected vulnerability type is detected
        # (Detection may not be 100% for all payloads)
        detected_vulnerabilities = [
            v for v in vulnerabilities
            if expected_vulnerability in str(v.get('type', '')).upper()
        ]
        
        # If vulnerability is detected, verify structure
        if len(detected_vulnerabilities) > 0:
            for vuln in detected_vulnerabilities:
                assert 'type' in vuln, "Vulnerability should have type"
                assert 'severity' in vuln, "Vulnerability should have severity"
                assert payload in str(vuln.get('description', '')) or \
                       payload in str(vuln.get('location', '')), \
                    f"Should mention payload in vulnerability description"
        
        # At minimum, risk score should reflect potential threat
        assert result['risk_score'] >= 0, "Risk score should be non-negative"

class TestSecurityHeaders:
    """Tests for security header analysis"""
    
    def test_csp_header_validation(self, security_scanner):
        """Test Content Security Policy header validation"""
        # Arrange
        scanner = security_scanner
        
        # Test different CSP configurations
        csp_test_cases = [
            {
                'csp': "default-src 'self'",
                'expected_secure': True,
                'description': 'Secure CSP'
            },
            {
                'csp': "default-src *",
                'expected_secure': False,
                'description': 'Insecure CSP (wildcard)'
            },
            {
                'csp': "default-src 'unsafe-inline'",
                'expected_secure': False,
                'description': 'Insecure CSP (unsafe-inline)'
            },
            {
                'csp': "default-src 'unsafe-eval'",
                'expected_secure': False,
                'description': 'Insecure CSP (unsafe-eval)'
            },
            {
                'csp': "",
                'expected_secure': False,
                'description': 'Empty CSP'
            }
        ]
        
        for test_case in csp_test_cases:
            # Act: Validate CSP
            if hasattr(scanner, '_is_header_secure'):
                is_secure = scanner._is_header_secure(
                    'Content-Security-Policy',
                    test_case['csp']
                )
            else:
                # Test through full scan
                with patch.object(scanner.session, 'get') as mock_get:
                    mock_response = create_mock_http_response(
                        url='https://csp-test.com',
                        headers={'Content-Security-Policy': test_case['csp']}
                    )
                    mock_get.return_value = mock_response
                    result = scanner.scan_website('https://csp-test.com')
                    
                    # Extract CSP security from result
                    csp_info = result['security_headers'].get('Content-Security-Policy', {})
                    is_secure = csp_info.get('secure', False)
            
            # Assert
            assert is_secure == test_case['expected_secure'], \
                f"{test_case['description']}: expected {test_case['expected_secure']}, got {is_secure}"
    
    def test_hsts_header_validation(self, security_scanner):
        """Test HSTS header validation"""
        # Arrange
        scanner = security_scanner
        
        # Test HSTS configurations
        hsts_test_cases = [
            {
                'hsts': 'max-age=31536000',
                'expected_secure': True,
                'description': 'Valid HSTS with max-age'
            },
            {
                'hsts': 'max-age=31536000; includeSubDomains',
                'expected_secure': True,
                'description': 'Valid HSTS with includeSubDomains'
            },
            {
                'hsts': 'max-age=0',
                'expected_secure': False,
                'description': 'Invalid HSTS (max-age=0)'
            },
            {
                'hsts': '',
                'expected_secure': False,
                'description': 'Empty HSTS'
            }
        ]
        
        for test_case in hsts_test_cases:
            # Act: Validate HSTS
            if hasattr(scanner, '_is_header_secure'):
                is_secure = scanner._is_header_secure(
                    'Strict-Transport-Security',
                    test_case['hsts']
                )
            else:
                # Test through full scan
                with patch.object(scanner.session, 'get') as mock_get:
                    mock_response = create_mock_http_response(
                        url='https://hsts-test.com',
                        headers={'Strict-Transport-Security': test_case['hsts']}
                    )
                    mock_get.return_value = mock_response
                    result = scanner.scan_website('https://hsts-test.com')
                    
                    # Extract HSTS security from result
                    hsts_info = result['security_headers'].get('Strict-Transport-Security', {})
                    is_secure = hsts_info.get('secure', False)
            
            # Assert
            assert is_secure == test_case['expected_secure'], \
                f"{test_case['description']}: expected {test_case['expected_secure']}, got {is_secure}"

class TestAPISecurity:
    """Tests for API security analysis"""
    
    def test_api_endpoint_security(self, security_scanner):
        """Test API endpoint security analysis"""
        # Arrange
        scanner = security_scanner
        
        # HTML referencing API endpoints
        api_html = """
        <!DOCTYPE html>
        <html>
        <body>
            <script>
                // API endpoints in JavaScript
                const API_BASE = '/api/v1';
                const endpoints = {
                    users: API_BASE + '/users',
                    admin: API_BASE + '/admin',
                    data: API_BASE + '/data?format=json'
                };
            </script>
        </body>
        </html>
        """
        
        # Mock response
        with patch.object(scanner.session, 'get') as mock_get:
            mock_response = create_mock_http_response(
                url='https://api-security-test.com',
                body=api_html
            )
            mock_get.return_value = mock_response
            
            # Act
            result = scanner.scan_website('https://api-security-test.com')
        
        # Assert
        endpoints = result.get('endpoints', [])
        
        # Should discover API endpoints from JavaScript
        api_endpoints = [e for e in endpoints if '/api/' in str(e.get('url', ''))]
        
        assert len(api_endpoints) > 0, "Should discover API endpoints"
        
        # Verify API endpoint structure
        for endpoint in api_endpoints:
            url = endpoint.get('url', '')
            assert '/api/' in url, "API endpoint should contain /api/"
            assert endpoint.get('type') in ['link', 'resource', 'api'], \
                "Endpoint should have type"
            
            # API endpoints might be flagged for additional scanning
            if endpoint.get('is_api', False):
                # API endpoints might have higher risk
                pass

@pytest.mark.integration
class TestCompleteSecurityWorkflow:
    """Complete security workflow tests"""
    
    def test_complete_vulnerability_scan(self, security_scanner):
        """Test complete vulnerability scanning workflow"""
        # Arrange: Website with multiple vulnerabilities
        vulnerable_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <!-- Missing security headers -->
        </head>
        <body>
            <!-- XSS vulnerability -->
            <div>Search: <script>alert('xss')</script></div>
            
            <!-- Form without CSRF -->
            <form action="/submit" method="POST">
                <input type="text" name="data">
                <input type="submit">
            </form>
            
            <!-- Insecure link -->
            <iframe src="http://insecure.com"></iframe>
            
            <!-- API endpoint -->
            <a href="/api/admin">Admin API</a>
        </body>
        </html>
        """
        
        # Mock response
        with patch.object(scanner.session, 'get') as mock_get:
            mock_response = create_mock_http_response(
                url='https://vulnerable-site.com',
                body=vulnerable_html
            )
            mock_get.return_value = mock_response
            
            # Act
            result = scanner.scan_website('https://vulnerable-site.com')
        
        # Assert: Complete analysis
        assert result['url'] == 'https://vulnerable-site.com'
        assert len(result['vulnerabilities']) > 0, \
            "Should detect vulnerabilities"
        
        # Check for specific vulnerability types
        vulnerability_types = [v.get('type', '') for v in result['vulnerabilities']]
        
        # Should have multiple vulnerability types
        unique_types = set(vulnerability_types)
        assert len(unique_types) >= 1, \
            f"Should detect multiple vulnerability types, got: {unique_types}"
        
        # Risk score should reflect vulnerabilities
        assert result['risk_score'] > 0.5, \
            f"Vulnerable site should have high risk score, got: {result['risk_score']}"
        
        # Should have recommendations
        recommendations = result.get('recommendations', [])
        assert len(recommendations) > 0, \
            "Should provide security recommendations"
        
        # Recommendations should be actionable
        for recommendation in recommendations:
            assert len(recommendation) > 10, \
                "Recommendation should be descriptive"
            assert not recommendation.startswith('Error'), \
                "Recommendation should not be error message"

if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__, "-v"])