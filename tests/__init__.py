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
- Safe: No destructive operations

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

# Add the src directory to the Python path to allow importing modules from src
# This ensures tests can import application code from the src directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import common test utilities from test_utils module
# These utilities provide helper functions for creating test data and validating results
try:
    from .test_utils import (
        create_mock_threat_data,
        create_mock_website_data,
        create_mock_http_response,
        validate_test_result,
        cleanup_test_resources,
        TEST_CONFIG
    )
except ImportError:
    # Handle case where test_utils module is not available
    # Define placeholder functions to prevent import errors during initial setup
    def create_mock_threat_data():
        """Placeholder function when test_utils is not available."""
        return {}
    
    def create_mock_website_data():
        """Placeholder function when test_utils is not available."""
        return {}
    
    def create_mock_http_response():
        """Placeholder function when test_utils is not available."""
        return None
    
    def validate_test_result(result):
        """Placeholder function when test_utils is not available."""
        return True
    
    def cleanup_test_resources():
        """Placeholder function when test_utils is not available."""
        pass
    
    TEST_CONFIG = {}

# Test constants - predefined values used across multiple test files
# These provide consistent test data and avoid hardcoding values in individual tests

# Standard test URL for testing normal website behavior
TEST_URL = "https://test.example.com"

# Malicious URL for testing security detection capabilities
TEST_MALICIOUS_URL = "https://evil.example.com"

# API endpoint for testing REST API security
TEST_API_ENDPOINT = "/api/v1/users"

# Cross-site scripting (XSS) payload for testing XSS detection
TEST_XSS_PAYLOAD = "<script>alert('xss')</script>"

# SQL injection payload for testing SQL injection detection
TEST_SQLI_PAYLOAD = "' OR '1'='1"

# CSRF token for testing CSRF protection mechanisms
TEST_CSRF_TOKEN = "csrf_test_token_12345"

# User agent string identifying the test suite in HTTP requests
TEST_USER_AGENT = "CyberGuard-Test-Suite/1.0"

# Dictionary defining test categories for organizing and filtering tests
# Each key-value pair maps a category name to its description
TEST_CATEGORIES = {
    'AGENTS': 'agent functionality tests',  # Tests for individual security agents
    'SECURITY': 'web security detection tests',  # Tests for security scanning and detection
    'MHC': 'manifold-constrained hyper-connections tests',  # Tests for MHC coordination
    'GQA': 'grouped query attention tests',  # Tests for GQA transformer implementations
    'ADVERSARIAL': 'adversarial attack resistance tests',  # Tests for handling attack patterns
    'PERFORMANCE': 'system performance tests',  # Tests for load and performance characteristics
    'INTEGRATION': 'component integration tests'  # Tests for cross-component interactions
}

# Define public API for this module - specifies which symbols are exported
# when using 'from tests import *' or when documenting module exports
__all__ = [
    # Test utility functions
    'create_mock_threat_data',
    'create_mock_website_data',
    'create_mock_http_response',
    'validate_test_result',
    'cleanup_test_resources',
    
    # Configuration constants
    'TEST_CONFIG',
    
    # Test data constants
    'TEST_URL',
    'TEST_MALICIOUS_URL',
    'TEST_API_ENDPOINT',
    'TEST_XSS_PAYLOAD',
    'TEST_SQLI_PAYLOAD',
    'TEST_CSRF_TOKEN',
    'TEST_USER_AGENT',
    
    # Test categorization constants
    'TEST_CATEGORIES'
]