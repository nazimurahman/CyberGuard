# tests/__init__.py
"""
CyberGuard Web Security AI System - Test Suite

This module contains all tests for the CyberGuard system:
1. Agent Tests: Test individual security agents
2. Security Tests: Test web security scanning and analysis
3. MHC Tests: Test Manifold-Constrained Hyper-Connections
4. GQA Tests: Test Grouped Query Attention with Flash Attention
5. Adversarial Tests: Test against real attack patterns
6. Load Tests: Test system performance under load

Each test file is designed to be:
- Independent: Can run tests individually
- Comprehensive: Covers edge cases and error conditions
- Deterministic: Produces consistent results
- Fast: Minimizes test execution time
. Safe: No destructive operations

Test Categories:
├── Unit Tests: Test individual functions/methods
├── Integration Tests: Test component interactions
├── System Tests: Test complete workflows
└── Performance Tests: Test under various loads

Test Fixtures:
- mock_threat_data: Simulated attack payloads
- mock_website_data: Simulated website responses
- agent_instances: Pre-initialized agent objects
- mhc_config: MHC configuration for testing

Test Patterns:
- Arrange: Set up test data and objects
- Act: Execute the functionality being tested
- Assert: Verify expected outcomes
- Cleanup: Reset state for next test

Test Coverage Goals:
- Agent Logic: 95%+
- Security Scanning: 90%+
- MHC Coordination: 85%+
- GQA Transformers: 80%+
- End-to-End: 70%+

To run tests:
    python -m pytest tests/ -v              # Run all tests
    python -m pytest tests/test_agents.py   # Run specific test file
    python -m pytest -k "test_threat"       # Run tests by keyword
    python -m pytest --cov=src tests/       # Run with coverage

Test Environment:
- Uses pytest framework
- Supports async tests
- Includes test database
- Has mock HTTP responses
- Provides test fixtures
"""
import sys
import os

# Add the src directory to the Python path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import common test utilities
from .test_utils import (
    create_mock_threat_data,
    create_mock_website_data,
    create_mock_http_response,
    validate_test_result,
    cleanup_test_resources,
    TEST_CONFIG
)

# Test constants
TEST_URL = "https://test.example.com"
TEST_MALICIOUS_URL = "https://evil.example.com"
TEST_API_ENDPOINT = "/api/v1/users"
TEST_XSS_PAYLOAD = "<script>alert('xss')</script>"
TEST_SQLI_PAYLOAD = "' OR '1'='1"
TEST_CSRF_TOKEN = "csrf_test_token_12345"
TEST_USER_AGENT = "CyberGuard-Test-Suite/1.0"

# Test categories
TEST_CATEGORIES = {
    'AGENTS': 'agent functionality tests',
    'SECURITY': 'web security detection tests',
    'MHC': 'manifold-constrained hyper-connections tests',
    'GQA': 'grouped query attention tests',
    'ADVERSARIAL': 'adversarial attack resistance tests',
    'PERFORMANCE': 'system performance tests',
    'INTEGRATION': 'component integration tests'
}

# Test fixtures will be available in conftest.py
__all__ = [
    'create_mock_threat_data',
    'create_mock_website_data',
    'create_mock_http_response',
    'validate_test_result',
    'cleanup_test_resources',
    'TEST_CONFIG',
    'TEST_URL',
    'TEST_MALICIOUS_URL',
    'TEST_API_ENDPOINT',
    'TEST_XSS_PAYLOAD',
    'TEST_SQLI_PAYLOAD',
    'TEST_CSRF_TOKEN',
    'TEST_USER_AGENT',
    'TEST_CATEGORIES'
]