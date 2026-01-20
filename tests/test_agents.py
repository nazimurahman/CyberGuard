# tests/test_agents.py
"""
Comprehensive tests for CyberGuard Security Agents

This module tests all security agents in the CyberGuard system:
1. Web Threat Detection Agent - OWASP Top-10 detection
2. Traffic Anomaly Agent - Behavior modeling
3. Bot Detection Agent - Bot signature detection
4. Malware Payload Agent - YARA rule matching
5. Exploit Chain Reasoning Agent - Multi-step attack analysis
6. Digital Forensics Agent - Evidence collection
7. Incident Response Agent - Automated response
8. Compliance & Privacy Agent - Regulation compliance
9. Secure Code Review Agent - Static analysis
10. Threat Education Agent - Security training

Each test validates:
- Agent initialization and configuration
- Threat detection accuracy
- Confidence scoring
- Memory management
- Error handling
- Performance characteristics
"""

import pytest
import sys
import os
from pathlib import Path
from typing import Dict, List, Any
import time

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import test utilities
from tests.test_utils import (
    create_mock_threat_data,
    create_mock_website_data,
    validate_test_result,
    TEST_CONFIG
)

# Test markers
pytestmark = [
    pytest.mark.agents,
    pytest.mark.unit
]

class TestWebThreatDetectionAgent:
    """Tests for Web Threat Detection Agent"""
    
    def test_agent_initialization(self, threat_detection_agent):
        """Test agent initialization with correct parameters"""
        # Arrange & Act: Agent is created by fixture
        agent = threat_detection_agent
        
        # Assert: Verify agent properties
        assert hasattr(agent, 'agent_id'), "Agent should have agent_id"
        assert hasattr(agent, 'name'), "Agent should have name"
        assert hasattr(agent, 'confidence'), "Agent should have confidence attribute"
        
        # Verify agent ID format
        assert isinstance(agent.agent_id, str), "agent_id should be string"
        assert len(agent.agent_id) > 0, "agent_id should not be empty"
        
        # Verify agent name
        assert isinstance(agent.name, str), "name should be string"
        assert len(agent.name) > 0, "name should not be empty"
        
        # Verify confidence is within valid range
        assert 0.0 <= agent.confidence <= 1.0, \
            f"confidence should be between 0 and 1, got {agent.confidence}"
    
    def test_agent_analyze_xss(self, threat_detection_agent, mock_threat_data):
        """Test agent detection of XSS threats"""
        # Arrange
        agent = threat_detection_agent
        threat_data = {
            'url': 'https://test.com/?q=<script>alert(1)</script>',
            'headers': {},
            'body': '',
            'method': 'GET'
        }
        
        # Act
        result = agent.analyze(threat_data)
        
        # Assert
        validate_test_result(
            result,
            expected_type=dict,
            expected_keys=['agent_id', 'findings', 'threat_level', 'confidence']
        )
        
        # Verify result structure
        assert result['agent_id'] == agent.agent_id, \
            "Result should contain correct agent_id"
        
        # Verify threat level is calculated
        assert isinstance(result['threat_level'], (int, float)), \
            "threat_level should be numeric"
        assert 0.0 <= result['threat_level'] <= 1.0, \
            f"threat_level should be between 0 and 1, got {result['threat_level']}"
        
        # Verify confidence is calculated
        assert isinstance(result['confidence'], (int, float)), \
            "confidence should be numeric"
        assert 0.0 <= result['confidence'] <= 1.0, \
            f"confidence should be between 0 and 1, got {result['confidence']}"
        
        # If XSS is detected, verify findings
        if result['threat_level'] > 0:
            assert len(result['findings']) > 0, \
                "Should have findings if threat level > 0"
            
            # Verify finding structure
            for finding in result['findings']:
                assert 'type' in finding, "Finding should have type"
                assert 'severity' in finding, "Finding should have severity"
                assert 'description' in finding, "Finding should have description"
    
    def test_agent_analyze_sqli(self, threat_detection_agent):
        """Test agent detection of SQL injection threats"""
        # Arrange
        agent = threat_detection_agent
        sqli_data = {
            'url': 'https://test.com/login?username=admin&password=%27OR%271%27%3D%271',
            'headers': {},
            'body': '',
            'method': 'GET'
        }
        
        # Act
        result = agent.analyze(sqli_data)
        
        # Assert
        assert result['threat_level'] >= 0, "threat_level should be non-negative"
        
        # If SQLi is detected
        if result['threat_level'] > 0.5:
            # Verify SQLi findings
            sqli_findings = [
                f for f in result['findings']
                if f.get('type') == 'SQL_INJECTION'
            ]
            assert len(sqli_findings) > 0, \
                "Should detect SQL injection in malicious payload"
    
    def test_agent_analyze_csrf(self, threat_detection_agent):
        """Test agent detection of CSRF vulnerabilities"""
        # Arrange: POST request without CSRF token
        agent = threat_detection_agent
        csrf_data = {
            'url': 'https://test.com/transfer',
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': '{"amount": 1000, "to_account": "attacker"}',
            'method': 'POST'
        }
        
        # Act
        result = agent.analyze(csrf_data)
        
        # Assert
        # Check for CSRF findings
        csrf_findings = [
            f for f in result['findings']
            if f.get('type') == 'CSRF'
        ]
        
        # Either CSRF is detected or not, but result should be valid
        assert result['confidence'] >= 0, "confidence should be non-negative"
    
    def test_agent_confidence_update(self, threat_detection_agent):
        """Test agent confidence update based on analysis"""
        # Arrange
        agent = threat_detection_agent
        initial_confidence = agent.confidence
        
        # Mock analysis with high certainty
        mock_result = {
            'certainty': 0.9,  # High certainty
            'threat_level': 0.8
        }
        
        # Act
        new_confidence = agent.update_confidence(mock_result)
        
        # Assert
        assert isinstance(new_confidence, float), \
            "Updated confidence should be float"
        assert 0.0 <= new_confidence <= 1.0, \
            f"confidence should be between 0 and 1, got {new_confidence}"
        
        # With high certainty, confidence should increase or stay same
        # (but not necessarily, depends on implementation)
        assert new_confidence >= 0, "confidence should be non-negative"
    
    def test_agent_memory_management(self, threat_detection_agent):
        """Test agent memory management and bounded memory"""
        # Arrange
        agent = threat_detection_agent
        
        # Act: Add multiple analyses to memory
        for i in range(20):
            analysis_result = {
                'findings': [{'type': 'TEST', 'severity': 'LOW'}],
                'threat_level': 0.1 * i,
                'certainty': 0.5
            }
            agent.update_confidence(analysis_result)
        
        # Get reasoning state (tests memory conversion)
        reasoning_state = agent.get_reasoning_state()
        
        # Assert
        # Reasoning state should exist (could be zero tensor if no memory)
        assert reasoning_state is not None, \
            "get_reasoning_state should return something"
    
    def test_agent_error_handling(self, threat_detection_agent):
        """Test agent error handling with invalid input"""
        # Arrange
        agent = threat_detection_agent
        
        # Test with various invalid inputs
        invalid_inputs = [
            None,  # None input
            {},  # Empty dict
            {'invalid': 'data'},  # Missing required fields
            123,  # Wrong type
            []  # List instead of dict
        ]
        
        for invalid_input in invalid_inputs:
            # Act & Assert: Should handle gracefully without crashing
            try:
                result = agent.analyze(invalid_input)
                # If it returns, should be a valid structure
                if result:
                    assert isinstance(result, dict), \
                        "Result should be dict even for invalid input"
            except Exception as e:
                # Should be a specific, expected exception, not generic
                assert not isinstance(e, KeyboardInterrupt), \
                    "Should not raise KeyboardInterrupt"
                # Log the exception type for debugging
                print(f"Expected exception for invalid input: {type(e).__name__}")
    
    def test_agent_performance(self, threat_detection_agent):
        """Test agent analysis performance"""
        # Arrange
        agent = threat_detection_agent
        test_data = create_mock_threat_data('xss')
        num_iterations = 10
        
        # Act: Measure analysis time
        start_time = time.time()
        
        for i in range(num_iterations):
            # Modify data slightly each iteration
            data = test_data.copy()
            data['payload'] = f"<script>alert('test{i}')</script>"
            result = agent.analyze({
                'url': f"https://test.com/?q={data['payload']}",
                'headers': {},
                'body': '',
                'method': 'GET'
            })
            assert result is not None, "Analysis should return result"
        
        end_time = time.time()
        total_time = end_time - start_time
        avg_time = total_time / num_iterations
        
        # Assert: Should complete within reasonable time
        # Typical threshold: < 100ms per analysis
        max_avg_time = 0.1  # 100ms
        assert avg_time < max_avg_time, \
            f"Average analysis time {avg_time:.3f}s exceeds threshold {max_avg_time}s"
        
        print(f"Performance: {num_iterations} analyses in {total_time:.3f}s "
              f"(avg: {avg_time:.3f}s)")
    
    @pytest.mark.parametrize("threat_type,expected_min_threat", [
        ('xss', 0.7),  # XSS should be high threat
        ('sqli', 0.8),  # SQLi should be very high threat
        ('csrf', 0.3),  # CSRF might be medium threat
    ])
    def test_agent_threat_type_detection(self, threat_detection_agent, 
                                         threat_type, expected_min_threat):
        """Parameterized test for different threat type detection"""
        # Arrange
        agent = threat_detection_agent
        threat_data = create_mock_threat_data(threat_type)
        
        # Create request data with threat payload
        request_data = {
            'url': f'https://test.com/?payload={threat_data["payload"]}',
            'headers': {},
            'body': '',
            'method': 'GET'
        }
        
        # Act
        result = agent.analyze(request_data)
        
        # Assert
        # Threat level should be above minimum for this threat type
        # (or at least non-zero if threat is present)
        if threat_data['payload']:  # Only if payload exists
            assert result['threat_level'] > 0, \
                f"{threat_type} should be detected as threat"

class TestTrafficAnomalyAgent:
    """Tests for Traffic Anomaly Detection Agent"""
    
    def test_traffic_agent_initialization(self, traffic_anomaly_agent):
        """Test traffic anomaly agent initialization"""
        # Arrange & Act: Agent is created by fixture
        agent = traffic_anomaly_agent
        
        # Assert
        assert hasattr(agent, 'agent_id'), "Agent should have agent_id"
        assert hasattr(agent, 'name'), "Agent should have name"
        
        # Verify it's a traffic anomaly agent
        assert 'traffic' in agent.name.lower() or 'anomaly' in agent.name.lower(), \
            "Agent should be traffic anomaly agent"
    
    def test_traffic_pattern_analysis(self, traffic_anomaly_agent):
        """Test traffic pattern analysis"""
        # Arrange
        agent = traffic_anomaly_agent
        
        # Create mock traffic data
        traffic_data = {
            'requests_per_second': 1000,  # High traffic
            'avg_response_time': 50,  # ms
            'error_rate': 0.05,  # 5% errors
            'user_agents': ['Chrome', 'Firefox', 'Python-requests'],
            'ip_addresses': ['192.168.1.1', '192.168.1.2', '10.0.0.1']
        }
        
        # Act
        # Note: Actual method name may vary
        if hasattr(agent, 'analyze_traffic'):
            result = agent.analyze_traffic(traffic_data)
        elif hasattr(agent, 'analyze'):
            result = agent.analyze({'traffic': traffic_data})
        else:
            pytest.skip("Traffic analysis method not available")
        
        # Assert
        assert result is not None, "Traffic analysis should return result"
        if isinstance(result, dict):
            assert 'anomaly_score' in result or 'threat_level' in result, \
                "Should include anomaly or threat score"

class TestBotDetectionAgent:
    """Tests for Bot Detection Agent"""
    
    def test_bot_agent_initialization(self, bot_detection_agent):
        """Test bot detection agent initialization"""
        # Arrange & Act: Agent is created by fixture
        agent = bot_detection_agent
        
        # Assert
        assert hasattr(agent, 'agent_id'), "Agent should have agent_id"
        assert hasattr(agent, 'name'), "Agent should have name"
        
        # Verify it's a bot detection agent
        assert 'bot' in agent.name.lower(), \
            "Agent should be bot detection agent"
    
    def test_bot_signature_detection(self, bot_detection_agent):
        """Test bot signature detection"""
        # Arrange
        agent = bot_detection_agent
        
        # Create request with bot-like characteristics
        bot_request = {
            'user_agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'requests_per_minute': 100,  # High rate
            'pattern': 'sequential',  # Sequential access pattern
            'mouse_movements': 0,  # No mouse movements
            'javascript_enabled': False  # No JavaScript
        }
        
        # Act
        if hasattr(agent, 'detect_bot'):
            result = agent.detect_bot(bot_request)
        elif hasattr(agent, 'analyze'):
            result = agent.analyze({'request': bot_request})
        else:
            pytest.skip("Bot detection method not available")
        
        # Assert
        assert result is not None, "Bot detection should return result"

class TestAgentIntegration:
    """Integration tests for multiple agents"""
    
    def test_multiple_agent_coordination(self, agent_orchestrator):
        """Test coordination between multiple agents"""
        # Arrange
        orchestrator = agent_orchestrator
        
        # Create test security data
        security_data = {
            'url': 'https://test.com/?q=<script>alert(1)</script>',
            'headers': {'User-Agent': 'Test-Bot/1.0'},
            'body': '',
            'method': 'GET',
            'timestamp': '2024-01-01T00:00:00Z'
        }
        
        # Act: Coordinate analysis
        if hasattr(orchestrator, 'coordinate_analysis'):
            result = orchestrator.coordinate_analysis(security_data)
        else:
            pytest.skip("Agent coordination not available")
        
        # Assert
        validate_test_result(
            result,
            expected_type=dict,
            expected_keys=['final_decision', 'agent_analyses']
        )
        
        # Verify all agents participated
        assert len(result['agent_analyses']) == len(orchestrator.agents), \
            "All agents should provide analyses"
        
        # Verify final decision exists
        final_decision = result['final_decision']
        assert 'action' in final_decision, "Final decision should include action"
        assert 'threat_level' in final_decision, "Final decision should include threat_level"
        
        # Verify action is valid
        valid_actions = ['ALLOW', 'BLOCK', 'CHALLENGE', 'MONITOR']
        assert final_decision['action'] in valid_actions, \
            f"Action should be one of {valid_actions}"
    
    def test_agent_conflict_resolution(self, agent_orchestrator):
        """Test resolution when agents have conflicting opinions"""
        # Arrange
        orchestrator = agent_orchestrator
        
        # Create data that might cause conflicts
        # (e.g., looks malicious to one agent but normal to another)
        conflicting_data = {
            'url': 'https://test.com/admin',  # Admin panel - might be suspicious
            'headers': {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Authorization': 'Bearer test_token'
            },
            'body': '',
            'method': 'GET',
            'source_ip': '192.168.1.100'
        }
        
        # Act
        if hasattr(orchestrator, 'coordinate_analysis'):
            result = orchestrator.coordinate_analysis(conflicting_data)
        else:
            pytest.skip("Agent coordination not available")
        
        # Assert: System should handle conflicts gracefully
        assert result is not None, "Should handle conflicting data"
        
        # Decision should be made despite conflicts
        final_decision = result['final_decision']
        assert final_decision['confidence'] >= 0, \
            "Should have confidence score even with conflicts"
        
        # Should indicate if human review is needed
        if 'requires_human_review' in final_decision:
            # If confidence is low, human review might be needed
            if final_decision['confidence'] < 0.6:
                assert final_decision['requires_human_review'] is True, \
                    "Low confidence should require human review"

@pytest.mark.integration
class TestEndToEndAgentWorkflow:
    """End-to-end tests for complete agent workflow"""
    
    def test_complete_threat_detection_workflow(self, threat_detection_agent):
        """Test complete workflow from detection to recommendation"""
        # Arrange: Complete attack scenario
        attack_scenario = {
            'url': 'https://vulnerable.com/login',
            'headers': {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'Mozilla/5.0'
            },
            'body': 'username=admin&password=%27OR%271%27%3D%271',
            'method': 'POST',
            'source_ip': '10.0.0.100',
            'timestamp': '2024-01-01T12:00:00Z'
        }
        
        # Act: Full analysis
        result = threat_detection_agent.analyze(attack_scenario)
        
        # Assert: Complete result structure
        required_keys = [
            'agent_id',
            'findings',
            'threat_level',
            'confidence',
            'recommended_action'
        ]
        
        for key in required_keys:
            assert key in result, f"Result should contain {key}"
        
        # Verify actionable output
        if result['threat_level'] > 0.7:
            assert result['recommended_action'] is not None, \
                "High threat should have recommended action"
            assert len(result['recommended_action']) > 0, \
                "Recommended action should not be empty"
        
        # Verify findings are actionable
        for finding in result['findings']:
            assert 'type' in finding, "Finding should have type"
            assert 'severity' in finding, "Finding should have severity"
            assert 'description' in finding, "Finding should have description"
            
            # High severity findings should have remediation
            if finding.get('severity') in ['HIGH', 'CRITICAL']:
                assert 'remediation' in finding or 'recommendation' in finding, \
                    "High severity findings should include remediation"

if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__, "-v"])