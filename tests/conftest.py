# tests/conftest.py
"""
Pytest Configuration and Fixtures for CyberGuard Tests

This file contains pytest fixtures and configuration that are
automatically available to all test files in the tests directory.

Fixtures defined here can be used by simply declaring them as
parameters in test functions.

Example:
    def test_agent_analysis(mock_threat_data, agent_instance):
        result = agent_instance.analyze(mock_threat_data)
        assert result['threat_level'] > 0
"""

import pytest
import sys
import os
from pathlib import Path
from typing import Generator, Dict, Any, List
from unittest.mock import Mock, patch, MagicMock

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import test utilities
from tests.test_utils import (
    create_mock_threat_data,
    create_mock_website_data,
    create_mock_http_response,
    TEST_CONFIG
)

# Pytest configuration
def pytest_configure(config):
    """Configure pytest with custom markers"""
    config.addinivalue_line(
        "markers",
        "integration: mark test as integration test (requires external resources)"
    )
    config.addinivalue_line(
        "markers",
        "slow: mark test as slow (skip in quick test runs)"
    )
    config.addinivalue_line(
        "markers",
        "requires_torch: test requires PyTorch"
    )
    config.addinivalue_line(
        "markers",
        "requires_gpu: test requires GPU"
    )
    config.addinivalue_line(
        "markers",
        "adversarial: adversarial test"
    )

# Session-scoped fixtures (created once per test session)
@pytest.fixture(scope="session")
def test_config() -> Dict[str, Any]:
    """Provide test configuration to all tests"""
    return TEST_CONFIG.copy()

@pytest.fixture(scope="session")
def mock_threat_database() -> Generator[Dict[str, List], None, None]:
    """Create a mock threat database for testing"""
    database = {
        'xss_patterns': [
            '<script>',
            'javascript:',
            'onload=',
            'onerror=',
            'eval(',
            'document.cookie'
        ],
        'sqli_patterns': [
            "' OR '1'='1",
            'UNION SELECT',
            '; DROP TABLE',
            '--',
            '/*',
            'waitfor delay'
        ],
        'csrf_patterns': [
            'missing csrf token',
            'state-changing without verification'
        ],
        'malicious_ips': [
            '1.2.3.4',
            '5.6.7.8',
            '10.0.0.1'
        ],
        'malicious_domains': [
            'evil.com',
            'malware.org',
            'phishing.net'
        ]
    }
    yield database
    # Cleanup if needed
    database.clear()

# Function-scoped fixtures (created fresh for each test)
@pytest.fixture
def mock_threat_data() -> Dict[str, Any]:
    """Provide mock threat data for testing"""
    return create_mock_threat_data('xss')

@pytest.fixture
def mock_website_data() -> Dict[str, Any]:
    """Provide mock website data for testing"""
    return create_mock_website_data(has_vulnerabilities=True)

@pytest.fixture
def mock_secure_website_data() -> Dict[str, Any]:
    """Provide mock secure website data for testing"""
    return create_mock_website_data(
        has_vulnerabilities=False,
        has_security_headers=True
    )

@pytest.fixture
def mock_malicious_website_data() -> Dict[str, Any]:
    """Provide mock malicious website data for testing"""
    return create_mock_website_data(
        has_vulnerabilities=True,
        is_malicious=True
    )

@pytest.fixture
def mock_http_response():
    """Provide a mock HTTP response for testing"""
    return create_mock_http_response(
        url='https://test.example.com',
        status_code=200
    )

@pytest.fixture
def mock_requests_session():
    """Mock requests.Session for testing network calls"""
    with requests_mock.Mocker() as m:
        yield m

# Agent fixtures
@pytest.fixture
def threat_detection_agent():
    """Create a threat detection agent instance for testing"""
    try:
        from src.agents.threat_detection_agent import WebThreatDetectionAgent
        agent = WebThreatDetectionAgent("test_threat_001")
        return agent
    except ImportError:
        # Return mock if actual agent not available
        mock_agent = Mock()
        mock_agent.agent_id = "test_threat_001"
        mock_agent.name = "Test Threat Detection Agent"
        mock_agent.analyze = Mock(return_value={
            'agent_id': 'test_threat_001',
            'findings': [],
            'threat_level': 0.5,
            'confidence': 0.8
        })
        return mock_agent

@pytest.fixture
def traffic_anomaly_agent():
    """Create a traffic anomaly agent instance for testing"""
    try:
        from src.agents.traffic_anomaly_agent import TrafficAnomalyAgent
        agent = TrafficAnomalyAgent("test_traffic_001")
        return agent
    except ImportError:
        mock_agent = Mock()
        mock_agent.agent_id = "test_traffic_001"
        mock_agent.name = "Test Traffic Anomaly Agent"
        return mock_agent

@pytest.fixture
def bot_detection_agent():
    """Create a bot detection agent instance for testing"""
    try:
        from src.agents.bot_detection_agent import BotDetectionAgent
        agent = BotDetectionAgent("test_bot_001")
        return agent
    except ImportError:
        mock_agent = Mock()
        mock_agent.agent_id = "test_bot_001"
        mock_agent.name = "Test Bot Detection Agent"
        return mock_agent

@pytest.fixture
def agent_orchestrator(threat_detection_agent, traffic_anomaly_agent, bot_detection_agent):
    """Create an agent orchestrator with test agents"""
    try:
        from src.agents.agent_orchestrator import AgentOrchestrator
        orchestrator = AgentOrchestrator(state_dim=512)
        orchestrator.register_agent(threat_detection_agent)
        orchestrator.register_agent(traffic_anomaly_agent)
        orchestrator.register_agent(bot_detection_agent)
        return orchestrator
    except ImportError:
        mock_orchestrator = Mock()
        mock_orchestrator.agents = [
            threat_detection_agent,
            traffic_anomaly_agent,
            bot_detection_agent
        ]
        return mock_orchestrator

# MHC fixtures
@pytest.fixture
def mhc_instance(test_config):
    """Create an MHC instance for testing"""
    try:
        from src.core.mhc_architecture import ManifoldConstrainedHyperConnections
        mhc_config = test_config['mhc_config']
        return ManifoldConstrainedHyperConnections(
            n_agents=3,
            state_dim=mhc_config['state_dim'],
            temperature=mhc_config['temperature']
        )
    except ImportError:
        mock_mhc = Mock()
        mock_mhc.n_agents = 3
        mock_mhc.state_dim = 512
        return mock_mhc

# GQA fixtures
@pytest.fixture
def gqa_transformer(test_config):
    """Create a GQA transformer instance for testing"""
    try:
        import torch
        from src.core.gqa_transformer import SecurityGQATransformer
        gqa_config = test_config['gqa_config']
        model = SecurityGQATransformer(
            vocab_size=1000,
            d_model=gqa_config['d_model'],
            n_heads=gqa_config['n_heads'],
            n_groups=gqa_config['n_groups'],
            dropout=gqa_config['dropout']
        )
        model.eval()  # Set to evaluation mode
        return model
    except ImportError:
        pytest.skip("PyTorch or GQA transformer not available")

# Security scanner fixture
@pytest.fixture
def security_scanner(test_config):
    """Create a security scanner instance for testing"""
    try:
        from src.web_security.scanner import WebSecurityScanner
        scanner = WebSecurityScanner(test_config['security_config'])
        return scanner
    except ImportError:
        mock_scanner = Mock()
        mock_scanner.scan_website = Mock(return_value={
            'url': 'https://test.example.com',
            'vulnerabilities': [],
            'risk_score': 0.3
        })
        return mock_scanner

# Patch fixtures for external dependencies
@pytest.fixture
def patch_requests():
    """Patch requests module to prevent actual network calls"""
    with patch('requests.Session') as mock_session:
        mock_instance = Mock()
        mock_instance.get.return_value = create_mock_http_response(
            'https://test.example.com'
        )
        mock_session.return_value = mock_instance
        yield mock_session

@pytest.fixture
def patch_beautifulsoup():
    """Patch BeautifulSoup for HTML parsing tests"""
    with patch('bs4.BeautifulSoup') as mock_bs:
        mock_soup = Mock()
        mock_soup.find_all.return_value = []
        mock_bs.return_value = mock_soup
        yield mock_bs

# Cleanup fixture
@pytest.fixture(autouse=True)
def cleanup_after_test():
    """Auto-cleanup after each test"""
    # Setup
    yield
    # Teardown
    # Any cleanup code here

# Custom pytest hooks
def pytest_collection_modifyitems(config, items):
    """Modify test collection based on markers"""
    skip_slow = pytest.mark.skip(reason="Skipping slow test")
    skip_no_torch = pytest.mark.skip(reason="PyTorch not available")
    
    for item in items:
        # Skip slow tests unless explicitly requested
        if "slow" in item.keywords and not config.getoption("--runslow"):
            item.add_marker(skip_slow)
        
        # Skip torch tests if torch not available
        if "requires_torch" in item.keywords:
            try:
                import torch
            except ImportError:
                item.add_marker(skip_no_torch)

def pytest_addoption(parser):
    """Add custom command line options"""
    parser.addoption(
        "--runslow",
        action="store_true",
        default=False,
        help="run slow tests"
    )
    parser.addoption(
        "--runintegration",
        action="store_true",
        default=False,
        help="run integration tests"
    )
    parser.addoption(
        "--rungpu",
        action="store_true",
        default=False,
        help="run GPU tests"
    )

# Test metadata
def pytest_html_results_table_header(cells):
    """Add custom columns to HTML report"""
    cells.insert(2, '<th class="col-duration">Duration</th>')
    cells.insert(1, '<th class="col-description">Description</th>')

def pytest_html_results_table_row(report, cells):
    """Add custom data to HTML report rows"""
    cells.insert(2, f'<td class="col-duration">{report.duration}</td>')
    cells.insert(1, f'<td class="col-description">{report.description}</td>')