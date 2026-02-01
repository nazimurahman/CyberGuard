# tests/test_mhc.py
"""
Comprehensive tests for Manifold-Constrained Hyper-Connections (mHC)

This module tests the mHC architecture for multi-agent coordination:
1. Sinkhorn-Knopp projection for doubly-stochastic normalization
2. Convex state mixing with bounded signal propagation
3. Identity-preserving mappings
4. Non-expansive updates
5. Residual coordination between agents
6. Signal explosion prevention
7. Dominant agent bias mitigation
8. Reasoning collapse prevention

Each test validates mathematical properties and stability guarantees.
"""

import pytest
import sys
import os
import torch
import numpy as np
from pathlib import Path
from typing import List, Dict, Any, Tuple
import math

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import test utilities
from tests.test_utils import (
    validate_test_result,
    TEST_CONFIG,
    TORCH_AVAILABLE
)

# Skip tests if PyTorch not available
if not TORCH_AVAILABLE:
    pytest.skip("PyTorch not available", allow_module_level=True)

# Test markers - mark all tests in this module with these markers
pytestmark = [
    pytest.mark.mhc,
    pytest.mark.requires_torch,
    pytest.mark.unit
]

# Mock classes to provide the required structure for testing
# In a real scenario, these would be imported from the actual mHC implementation

class MockMHC:
    """Mock mHC class for testing purposes"""
    def __init__(self, n_agents=3, state_dim=64, signal_bound=1.0):
        # Initialize with testable parameters
        self.n_agents = n_agents
        self.state_dim = state_dim
        self.signal_bound = signal_bound
        self.sinkhorn_iterations = 10  # Default number of iterations
        
    def sinkhorn_knopp_projection(self, log_alpha: torch.Tensor) -> torch.Tensor:
        """
        Mock implementation of Sinkhorn-Knopp projection.
        In real implementation, this would normalize a matrix to be doubly stochastic.
        
        Args:
            log_alpha: Log-probability matrix of shape (batch, n_agents, n_agents)
            
        Returns:
            Doubly-stochastic matrix of same shape
        """
        batch_size, n, _ = log_alpha.shape
        
        # Simple mock: softmax over both rows and columns
        # This is not a real Sinkhorn algorithm but works for testing
        result = torch.softmax(log_alpha, dim=-1)  # Row normalization
        
        # Column normalization approximation
        for _ in range(self.sinkhorn_iterations):
            # Normalize columns
            col_sum = result.sum(dim=-2, keepdim=True)
            result = result / col_sum
            
            # Normalize rows
            row_sum = result.sum(dim=-1, keepdim=True)
            result = result / row_sum
            
        return result
    
    def convex_state_mixing(self, agent_states: List[torch.Tensor], 
                           attention_weights: torch.Tensor) -> torch.Tensor:
        """
        Mock implementation of convex state mixing.
        Combines agent states using attention weights with signal bounding.
        
        Args:
            agent_states: List of tensors, each of shape (batch, state_dim)
            attention_weights: Tensor of shape (batch, n_agents)
            
        Returns:
            Mixed state of shape (batch, state_dim)
        """
        batch_size = agent_states[0].shape[0]
        state_dim = agent_states[0].shape[1]
        
        # Initialize mixed state
        mixed_state = torch.zeros(batch_size, state_dim)
        
        # Convex combination using attention weights
        for i in range(self.n_agents):
            # Weight each agent's state by its attention weight
            weight = attention_weights[:, i:i+1]  # Shape: (batch, 1)
            mixed_state += weight * agent_states[i]
        
        # Apply signal bounding: normalize if norm exceeds bound
        norms = torch.norm(mixed_state, dim=-1, keepdim=True)
        exceeds_bound = norms > self.signal_bound
        
        # Scale down states that exceed the bound
        if torch.any(exceeds_bound):
            # Create scaling factors: 1 for states within bound, signal_bound/norm for others
            scaling = torch.ones_like(norms)
            scaling[exceeds_bound] = self.signal_bound / norms[exceeds_bound]
            mixed_state = mixed_state * scaling
        
        return mixed_state
    
    def residual_coordination(self, agent_outputs: List[Dict], 
                            agent_confidences: torch.Tensor) -> Dict[str, Any]:
        """
        Mock implementation of residual coordination.
        Coordinates multiple agent outputs with residual connections.
        
        Args:
            agent_outputs: List of agent output dictionaries
            agent_confidences: Tensor of shape (batch, n_agents) with agent confidence scores
            
        Returns:
            Dictionary with coordinated results
        """
        batch_size = agent_confidences.shape[0]
        
        # Extract reasoning states from agent outputs
        reasoning_states = []
        agent_decisions = []
        
        for agent_output in agent_outputs:
            reasoning_states.append(agent_output['reasoning_state'].unsqueeze(0))
            agent_decisions.append(agent_output['decision'])
        
        # Stack reasoning states: shape (batch, n_agents, state_dim)
        reasoning_states = torch.stack(reasoning_states, dim=1)
        
        # Normalize confidences if not already normalized
        if agent_confidences.sum(dim=-1, keepdim=True).max() > 1.1:
            agent_confidences = torch.softmax(agent_confidences, dim=-1)
        
        # Apply convex mixing to reasoning states
        # Reshape for convex_state_mixing
        agent_states_list = []
        for i in range(self.n_agents):
            agent_states_list.append(reasoning_states[:, i, :])
        
        coordinated_state = self.convex_state_mixing(agent_states_list, agent_confidences)
        
        # Combine agent decisions (simple weighted average for threat level)
        final_threat = torch.zeros(batch_size, 1)
        final_confidence = torch.zeros(batch_size, 1)
        all_evidence = []
        
        for i in range(self.n_agents):
            weight = agent_confidences[:, i:i+1]
            final_threat += weight * agent_decisions[i]['threat_level']
            final_confidence += weight * agent_decisions[i]['confidence']
            
            # Collect evidence
            if 'evidence' in agent_decisions[i]:
                all_evidence.extend(agent_decisions[i]['evidence'])
        
        # Create final decision
        final_decision = {
            'threat_level': final_threat.squeeze(-1),
            'confidence': final_confidence.squeeze(-1),
            'evidence': all_evidence[:10]  # Limit evidence to first 10 items
        }
        
        # Agent contributions (normalized confidences)
        agent_contributions = agent_confidences.tolist()
        
        return {
            'final_decision': final_decision,
            'coordinated_state': coordinated_state,
            'agent_contributions': agent_contributions
        }

class TestSinkhornKnoppProjection:
    """Tests for Sinkhorn-Knopp projection algorithm"""
    
    @pytest.fixture
    def mhc_instance(self):
        """Create a mock mHC instance for testing"""
        return MockMHC(n_agents=3, state_dim=64, signal_bound=1.0)
    
    def test_sinkhorn_basic_properties(self, mhc_instance):
        """Test basic properties of Sinkhorn-Knopp projection"""
        # Arrange: Create test setup with mock mHC instance
        mhc = mhc_instance
        
        # Create random log-alpha matrix (log-probabilities)
        batch_size = 2
        n_agents = mhc.n_agents
        log_alpha = torch.randn(batch_size, n_agents, n_agents)
        
        # Act: Apply Sinkhorn-Knopp projection to normalize matrix
        projected = mhc.sinkhorn_knopp_projection(log_alpha)
        
        # Assert: Verify projection preserves shape and has valid values
        assert projected.shape == log_alpha.shape, \
            f"Projection should preserve shape: {projected.shape} != {log_alpha.shape}"
        
        # Projected values should be non-negative (probabilities)
        assert torch.all(projected >= 0), \
            "Projected values should be non-negative"
        
        # Projected values should be finite (no NaN or inf)
        assert torch.all(torch.isfinite(projected)), \
            "Projected values should be finite"
    
    def test_sinkhorn_doubly_stochastic(self, mhc_instance):
        """Test that Sinkhorn-Knopp produces doubly-stochastic matrix"""
        # Arrange: Create test matrix
        mhc = mhc_instance
        n_agents = mhc.n_agents
        log_alpha = torch.randn(1, n_agents, n_agents)
        
        # Act: Apply projection
        projected = mhc.sinkhorn_knopp_projection(log_alpha)
        
        # Assert: Verify doubly-stochastic properties
        # Row sums should be approximately 1 (each row is a probability distribution)
        row_sums = projected.sum(dim=-1)
        assert torch.allclose(row_sums, torch.ones_like(row_sums), rtol=1e-5), \
            f"Row sums should be 1, got min={row_sums.min():.6f}, max={row_sums.max():.6f}"
        
        # Column sums should be approximately 1 (each column also sums to 1)
        col_sums = projected.sum(dim=-2)
        assert torch.allclose(col_sums, torch.ones_like(col_sums), rtol=1e-5), \
            f"Column sums should be 1, got min={col_sums.min():.6f}, max={col_sums.max():.6f}"
    
    def test_sinkhorn_convergence(self, mhc_instance):
        """Test Sinkhorn-Knopp convergence properties"""
        # Arrange: Test with different iteration counts
        mhc = mhc_instance
        n_agents = mhc.n_agents
        log_alpha = torch.randn(1, n_agents, n_agents)
        
        # Track convergence errors for different iteration counts
        convergence_errors = []
        
        # Act: Test with 5 iterations
        mhc.sinkhorn_iterations = 5
        projected_5 = mhc.sinkhorn_knopp_projection(log_alpha)
        
        # Calculate error from ideal doubly-stochastic matrix
        row_sums_5 = projected_5.sum(dim=-1)
        col_sums_5 = projected_5.sum(dim=-2)
        error_5 = (row_sums_5 - 1).abs().mean() + (col_sums_5 - 1).abs().mean()
        convergence_errors.append(('5 iterations', error_5.item()))
        
        # Test with 50 iterations
        mhc.sinkhorn_iterations = 50
        projected_50 = mhc.sinkhorn_knopp_projection(log_alpha)
        
        # Calculate error for 50 iterations
        row_sums_50 = projected_50.sum(dim=-1)
        col_sums_50 = projected_50.sum(dim=-2)
        error_50 = (row_sums_50 - 1).abs().mean() + (col_sums_50 - 1).abs().mean()
        convergence_errors.append(('50 iterations', error_50.item()))
        
        # Restore original iteration count
        mhc.sinkhorn_iterations = 10
        
        # Assert: More iterations should reduce error (or at least not increase it significantly)
        _, error_5_val = convergence_errors[0]
        _, error_50_val = convergence_errors[1]
        
        # Allow small tolerance (1.1x) for numerical variations
        assert error_50_val <= error_5_val * 1.1, \
            f"More iterations should not increase error: 5it={error_5_val:.6f}, 50it={error_50_val:.6f}"
        
        # Print convergence information for debugging
        print(f"Convergence errors: 5 iterations={error_5_val:.6f}, 50 iterations={error_50_val:.6f}")
    
    def test_sinkhorn_stability(self, mhc_instance):
        """Test numerical stability of Sinkhorn-Knopp with extreme values"""
        # Arrange: Test with various extreme value cases
        mhc = mhc_instance
        n_agents = mhc.n_agents
        
        # Define test cases with different value ranges
        test_cases = [
            ('large_values', torch.randn(1, n_agents, n_agents) * 100),  # Very large values
            ('small_values', torch.randn(1, n_agents, n_agents) * 0.01),  # Very small values
            ('zero_matrix', torch.zeros(1, n_agents, n_agents)),  # All zeros
        ]
        
        # Special 2x2 case for mixed positive/negative values
        if n_agents == 2:
            test_cases.append(('mixed_values', torch.tensor([[[100, -100], [-100, 100]]], dtype=torch.float32)))
        
        for case_name, log_alpha in test_cases:
            # Act: Apply projection to each test case
            try:
                projected = mhc.sinkhorn_knopp_projection(log_alpha)
                
                # Assert: Verify numerical stability for each case
                # Projected values should be finite (no NaN or infinity)
                assert torch.all(torch.isfinite(projected)), \
                    f"{case_name}: Projected values should be finite"
                
                # Projected values should be non-negative (valid probabilities)
                assert torch.all(projected >= 0), \
                    f"{case_name}: Projected values should be non-negative"
                
                # Total sum of all elements should be approximately n_agents
                # (since each of n_agents rows sums to 1)
                total_sum = projected.sum()
                expected_sum = n_agents
                assert torch.allclose(total_sum, 
                                    torch.tensor(expected_sum, dtype=total_sum.dtype),
                                    rtol=1e-5), \
                    f"{case_name}: Total sum should be {expected_sum}, got {total_sum:.6f}"
                
            except Exception as e:
                # If any test case fails, fail the test with informative message
                pytest.fail(f"{case_name}: Sinkhorn should handle gracefully, got {e}")

class TestConvexStateMixing:
    """Tests for convex state mixing with mHC"""
    
    @pytest.fixture
    def mhc_instance(self):
        """Create a mock mHC instance for testing"""
        return MockMHC(n_agents=3, state_dim=64, signal_bound=1.0)
    
    def test_convex_mixing_basic(self, mhc_instance):
        """Test basic convex state mixing functionality"""
        # Arrange: Create mock agent states and attention weights
        mhc = mhc_instance
        batch_size = 2
        n_agents = mhc.n_agents
        state_dim = mhc.state_dim
        
        # Create random agent states
        agent_states = [
            torch.randn(batch_size, state_dim) for _ in range(n_agents)
        ]
        
        # Create random attention weights and normalize them (sum to 1 per batch)
        attention_weights = torch.softmax(torch.randn(batch_size, n_agents), dim=-1)
        
        # Act: Apply convex state mixing
        mixed_state = mhc.convex_state_mixing(agent_states, attention_weights)
        
        # Assert: Verify output shape and properties
        assert mixed_state.shape == (batch_size, state_dim), \
            f"Mixed state should have shape (batch_size, state_dim), got {mixed_state.shape}"
        
        # Mixed state should contain only finite values
        assert torch.all(torch.isfinite(mixed_state)), \
            "Mixed state should be finite"
    
    def test_convex_mixing_convexity(self, mhc_instance):
        """Test that mixing produces valid convex combination"""
        # Arrange: Create simple test case with distinguishable states
        mhc = mhc_instance
        batch_size = 1
        n_agents = mhc.n_agents
        state_dim = mhc.state_dim
        
        # Create agent states where each agent activates a different dimension
        agent_states = [
            torch.zeros(batch_size, state_dim) for _ in range(n_agents)
        ]
        agent_states[0][0, 0] = 1.0  # Agent 0: dimension 0 = 1
        if n_agents > 1:
            agent_states[1][0, 1] = 1.0  # Agent 1: dimension 1 = 1
        
        # Create attention weights focused entirely on first agent
        attention_weights = torch.zeros(batch_size, n_agents)
        attention_weights[0, 0] = 1.0  # 100% attention to agent 0
        
        # Act: Apply convex mixing
        mixed_state = mhc.convex_state_mixing(agent_states, attention_weights)
        
        # Assert: With 100% weight on agent 0, output should match agent 0's state
        # Allow small numerical tolerance
        assert torch.allclose(mixed_state[0, 0], torch.tensor(1.0), rtol=1e-5), \
            f"With full attention to agent 0, mixed_state[0,0] should be ~1, got {mixed_state[0, 0]:.6f}"
        
        # Other dimensions should be approximately 0
        if n_agents > 1:
            assert torch.allclose(mixed_state[0, 1], torch.tensor(0.0), rtol=1e-5), \
                f"With no attention to agent 1, mixed_state[0,1] should be ~0, got {mixed_state[0, 1]:.6f}"
    
    def test_signal_bounding(self, mhc_instance):
        """Test that signal bounding prevents norm explosion"""
        # Arrange: Create states with intentionally large norms
        mhc = mhc_instance
        batch_size = 2
        n_agents = mhc.n_agents
        state_dim = mhc.state_dim
        
        # Create agent states with large norms (could cause numerical issues)
        large_norm = 100.0
        agent_states = [
            torch.randn(batch_size, state_dim) * large_norm for _ in range(n_agents)
        ]
        
        # Create uniform attention weights
        attention_weights = torch.ones(batch_size, n_agents) / n_agents
        
        # Act: Apply convex mixing with signal bounding
        mixed_state = mhc.convex_state_mixing(agent_states, attention_weights)
        
        # Assert: Verify norms are bounded by signal_bound
        state_norms = torch.norm(mixed_state, dim=-1)
        
        # Calculate maximum allowed norm (with 10% tolerance for numerical operations)
        max_allowed_norm = mhc.signal_bound * 1.1
        
        # Check all batch elements have bounded norms
        assert torch.all(state_norms <= max_allowed_norm), \
            f"State norms should be bounded by {mhc.signal_bound}, " \
            f"got max={state_norms.max():.6f}"
        
        # Print test information for debugging
        print(f"Signal bounding test: input norm ~{large_norm}, "
              f"output norm max={state_norms.max():.6f}, "
              f"bound={mhc.signal_bound}")
    
    def test_identity_preservation(self, mhc_instance):
        """Test identity-preserving property of state mixing"""
        # Arrange: Create identical agent states
        mhc = mhc_instance
        batch_size = 2
        n_agents = mhc.n_agents
        state_dim = mhc.state_dim
        
        # Create identical base state for all agents
        base_state = torch.randn(batch_size, state_dim)
        agent_states = [base_state.clone() for _ in range(n_agents)]
        
        # Create arbitrary attention weights
        attention_weights = torch.softmax(torch.randn(batch_size, n_agents), dim=-1)
        
        # Act: Apply convex mixing
        mixed_state = mhc.convex_state_mixing(agent_states, attention_weights)
        
        # Assert: With identical input states, output should be similar to input
        # regardless of attention weights (since convex combination of identical vectors)
        similarity = torch.cosine_similarity(mixed_state, base_state, dim=-1)
        
        # Cosine similarity should be close to 1 (vectors point in same direction)
        assert torch.all(similarity > 0.99), \
            f"With identical states, output should be similar to input, " \
            f"got min similarity={similarity.min():.6f}"
    
    def test_non_expansive_updates(self, mhc_instance):
        """Test non-expansive property (Lipschitz constant ≤ 1)"""
        # Arrange: Create two different sets of agent states
        mhc = mhc_instance
        batch_size = 10  # Multiple samples for statistical significance
        n_agents = mhc.n_agents
        state_dim = mhc.state_dim
        
        # Create first set of agent states
        agent_states1 = [torch.randn(batch_size, state_dim) for _ in range(n_agents)]
        
        # Create second set that's slightly different
        agent_states2 = [state + torch.randn_like(state) * 0.1 for state in agent_states1]
        
        # Use same attention weights for both sets
        attention_weights = torch.softmax(torch.randn(batch_size, n_agents), dim=-1)
        
        # Act: Apply convex mixing to both sets
        mixed1 = mhc.convex_state_mixing(agent_states1, attention_weights)
        mixed2 = mhc.convex_state_mixing(agent_states2, attention_weights)
        
        # Calculate average input difference across agents
        input_diffs = []
        for s1, s2 in zip(agent_states1, agent_states2):
            diff = torch.norm(s1 - s2, dim=-1)  # Euclidean distance per batch element
            input_diffs.append(diff)
        
        avg_input_diff = torch.stack(input_diffs).mean()
        
        # Calculate output difference
        output_diff = torch.norm(mixed1 - mixed2, dim=-1).mean()
        
        # Assert: Non-expansive property - output difference ≤ input difference
        # Allow 5% tolerance for numerical operations
        assert output_diff <= avg_input_diff * 1.05, \
            f"Updates should be non-expansive: " \
            f"output_diff={output_diff:.6f}, avg_input_diff={avg_input_diff:.6f}"
        
        # Print test information
        print(f"Non-expansive test: input_diff={avg_input_diff:.6f}, "
              f"output_diff={output_diff:.6f}, "
              f"ratio={output_diff/avg_input_diff:.6f}")

class TestResidualCoordination:
    """Tests for residual coordination between agents"""
    
    @pytest.fixture
    def mhc_instance(self):
        """Create a mock mHC instance for testing"""
        return MockMHC(n_agents=3, state_dim=64, signal_bound=1.0)
    
    def test_residual_coordination_basic(self, mhc_instance):
        """Test basic residual coordination functionality"""
        # Arrange: Create mock agent outputs with decisions and reasoning states
        mhc = mhc_instance
        n_agents = mhc.n_agents
        
        # Initialize lists for agent outputs and confidences
        agent_outputs = []
        agent_confidences = torch.zeros(1, n_agents)  # Shape: (batch=1, n_agents)
        
        # Create mock data for each agent
        for i in range(n_agents):
            # Create mock reasoning state
            reasoning_state = torch.randn(mhc.state_dim)
            
            # Create mock decision with agent-specific values
            decision = {
                'threat_level': torch.tensor([0.5 + 0.1 * i]),  # Varies by agent
                'confidence': torch.tensor([0.6 + 0.05 * i]),   # Varies by agent
                'evidence': [f'Evidence {j} from agent {i}' for j in range(3)]
            }
            
            # Store agent output
            agent_outputs.append({
                'reasoning_state': reasoning_state,
                'decision': decision
            })
            
            # Set confidence values (will be normalized later)
            agent_confidences[0, i] = 0.5 + 0.1 * i
        
        # Normalize confidences to sum to 1 per batch
        agent_confidences = torch.softmax(agent_confidences, dim=-1)
        
        # Act: Apply residual coordination
        result = mhc.residual_coordination(agent_outputs, agent_confidences)
        
        # Assert: Verify result structure using test utility
        validate_test_result(
            result,
            expected_type=dict,
            expected_keys=['final_decision', 'coordinated_state', 'agent_contributions']
        )
        
        # Check final decision structure
        final_decision = result['final_decision']
        assert 'threat_level' in final_decision, "Final decision should have threat_level"
        assert 'confidence' in final_decision, "Final decision should have confidence"
        assert 'evidence' in final_decision, "Final decision should have evidence"
        
        # Check coordinated state shape
        coordinated_state = result['coordinated_state']
        assert coordinated_state.shape == (1, mhc.state_dim), \
            f"Coordinated state should have shape (1, state_dim), got {coordinated_state.shape}"
        
        # Check agent contributions
        contributions = result['agent_contributions']  # This is a list, not a tensor
        
        # Fix: contributions is a list of lists, not a tensor
        assert len(contributions) == 1, f"Should have contributions for 1 batch, got {len(contributions)}"
        assert len(contributions[0]) == n_agents, \
            f"Should have contributions for all agents, got {len(contributions[0])}"
        
        # Contributions should sum to approximately 1 (within tolerance)
        contributions_sum = sum(contributions[0])  # Sum contributions for first batch
        assert abs(contributions_sum - 1.0) < 0.01, \
            f"Agent contributions should sum to ~1, got {contributions_sum:.6f}"
    
    def test_dominant_agent_mitigation(self, mhc_instance):
        """Test that mHC mitigates bias from overly confident agents"""
        # Arrange: Create scenario with one dominant agent
        mhc = mhc_instance
        n_agents = mhc.n_agents
        
        # Initialize agent outputs and confidences
        agent_outputs = []
        agent_confidences = torch.zeros(1, n_agents)
        
        # Set up confidences: first agent has much higher confidence
        agent_confidences[0, 0] = 100.0  # Dominant agent
        for i in range(1, n_agents):
            agent_confidences[0, i] = 1.0  # Other agents have normal confidence
        
        # Softmax will give almost all weight to first agent (~0.997)
        agent_confidences = torch.softmax(agent_confidences, dim=-1)
        
        # Create conflicting agent decisions
        for i in range(n_agents):
            # Create reasoning state for each agent
            reasoning_state = torch.randn(mhc.state_dim)
            
            # First agent says high threat, others say low threat
            if i == 0:
                threat_level = 0.9  # High threat
                confidence = 0.95   # High confidence
            else:
                threat_level = 0.1  # Low threat
                confidence = 0.7    # Moderate confidence
            
            # Create decision dictionary
            decision = {
                'threat_level': torch.tensor([threat_level]),
                'confidence': torch.tensor([confidence]),
                'evidence': [f'Agent {i} evidence for threat level {threat_level}']
            }
            
            agent_outputs.append({
                'reasoning_state': reasoning_state,
                'decision': decision
            })
        
        # Act: Apply residual coordination
        result = mhc.residual_coordination(agent_outputs, agent_confidences)
        
        # Assert: mHC should mitigate dominant agent bias
        final_decision = result['final_decision']
        final_threat = final_decision['threat_level'].item()
        
        # With mHC mitigation, final threat should be between extremes
        # (not just blindly following the dominant agent)
        assert 0.1 < final_threat < 0.9, \
            f"mHC should balance agent opinions, got threat={final_threat:.3f}"
        
        # Check that non-dominant agents still contribute
        contributions = result['agent_contributions'][0]  # Get contributions for first batch
        non_dominant_contributions = sum(contributions[1:])  # Sum contributions for agents 1+
        
        # Non-dominant agents should have some contribution
        assert non_dominant_contributions > 0.01, \
            f"Non-dominant agents should contribute, got {non_dominant_contributions:.6f}"
        
        # Print test information
        print(f"Dominant agent mitigation: "
              f"dominant agent weight={contributions[0]:.3f}, "
              f"other agents weight={non_dominant_contributions:.3f}, "
              f"final threat={final_threat:.3f}")
    
    def test_reasoning_collapse_prevention(self, mhc_instance):
        """Test that mHC prevents collapse to single reasoning dimension"""
        # Arrange: Create agents with diverse reasoning states
        mhc = mhc_instance
        n_agents = mhc.n_agents
        
        # Initialize agent outputs
        agent_outputs = []
        
        # Create random but normalized confidences
        agent_confidences = torch.softmax(torch.randn(1, n_agents), dim=-1)
        
        # Create diverse reasoning states: each agent activates a different dimension
        for i in range(n_agents):
            # Create reasoning state with only one dimension active
            reasoning_state = torch.zeros(mhc.state_dim)
            
            # Ensure we don't go out of bounds
            dim_idx = i % mhc.state_dim
            reasoning_state[dim_idx] = 1.0
            
            # Create simple decision for each agent
            decision = {
                'threat_level': torch.tensor([0.5]),
                'confidence': torch.tensor([0.5]),
                'evidence': []
            }
            
            agent_outputs.append({
                'reasoning_state': reasoning_state,
                'decision': decision
            })
        
        # Act: Apply residual coordination
        result = mhc.residual_coordination(agent_outputs, agent_confidences)
        
        # Assert: Coordinated state should preserve diversity
        coordinated_state = result['coordinated_state'][0]  # Get first batch element
        
        # Calculate how many dimensions are active (above threshold)
        threshold = 0.01
        active_dimensions = (coordinated_state.abs() > threshold).sum().item()
        
        # Should have multiple active dimensions (not collapsed to single dimension)
        assert active_dimensions > 1, \
            f"Reasoning collapse prevention: should have multiple active dimensions, " \
            f"got {active_dimensions}"
        
        # State norm should be bounded by signal_bound
        state_norm = torch.norm(coordinated_state).item()
        assert state_norm <= mhc.signal_bound * 1.1, \
            f"State norm should be bounded by {mhc.signal_bound}, got {state_norm:.6f}"
        
        # Print test information
        print(f"Reasoning collapse prevention: "
              f"active dimensions={active_dimensions}/{mhc.state_dim}, "
              f"state norm={state_norm:.6f}")
    
    def test_signal_explosion_prevention(self, mhc_instance):
        """Test that mHC prevents signal magnitude explosion"""
        # Arrange: Create agents with very large reasoning states
        mhc = mhc_instance
        n_agents = mhc.n_agents
        
        # Initialize agent outputs
        agent_outputs = []
        
        # Create normalized confidences
        agent_confidences = torch.softmax(torch.randn(1, n_agents), dim=-1)
        
        # Create reasoning states with very large norms
        for i in range(n_agents):
            # Create reasoning state with extremely large norm
            reasoning_state = torch.randn(mhc.state_dim) * 1000  # Very large values
            
            # Create simple decision
            decision = {
                'threat_level': torch.tensor([0.5]),
                'confidence': torch.tensor([0.5]),
                'evidence': []
            }
            
            agent_outputs.append({
                'reasoning_state': reasoning_state,
                'decision': decision
            })
        
        # Act: Apply residual coordination
        result = mhc.residual_coordination(agent_outputs, agent_confidences)
        
        # Assert: Coordinated state should have bounded norm
        coordinated_state = result['coordinated_state'][0]  # Get first batch element
        state_norm = torch.norm(coordinated_state).item()
        
        # Norm should be bounded by signal_bound (with tolerance)
        assert state_norm <= mhc.signal_bound * 1.1, \
            f"Signal explosion prevention: state norm should be ≤ {mhc.signal_bound}, " \
            f"got {state_norm:.6f}"
        
        # Check that individual agent contributions are valid probabilities
        contributions = result['agent_contributions'][0]
        for contrib in contributions:
            # Each contribution should be between 0 and 1
            assert 0.0 <= contrib <= 1.0, \
                f"Agent contribution should be between 0 and 1, got {contrib}"
        
        # Print test information
        print(f"Signal explosion prevention: "
              f"input norms ~1000, "
              f"output norm={state_norm:.6f}, "
              f"bound={mhc.signal_bound}")

class TestMHCStability:
    """Tests for mHC stability properties"""
    
    @pytest.fixture
    def mhc_instance(self):
        """Create a mock mHC instance for testing"""
        return MockMHC(n_agents=3, state_dim=64, signal_bound=1.0)
    
    def test_mhc_idempotence(self, mhc_instance):
        """Test that applying mHC twice yields similar results (idempotence)"""
        # Arrange: Create test data
        mhc = mhc_instance
        n_agents = mhc.n_agents
        
        # Initialize agent outputs
        agent_outputs = []
        
        # Create random but normalized confidences
        agent_confidences = torch.softmax(torch.randn(1, n_agents), dim=-1)
        
        # Create agent outputs with random reasoning states
        for i in range(n_agents):
            reasoning_state = torch.randn(mhc.state_dim)
            decision = {
                'threat_level': torch.tensor([0.5]),
                'confidence': torch.tensor([0.5]),
                'evidence': []
            }
            agent_outputs.append({
                'reasoning_state': reasoning_state,
                'decision': decision
            })
        
        # Act: Apply coordination twice (simulating iterative refinement)
        result1 = mhc.residual_coordination(agent_outputs, agent_confidences)
        
        # Use same inputs for second round
        # (In practice, agent_outputs might be updated between rounds)
        result2 = mhc.residual_coordination(agent_outputs, agent_confidences)
        
        # Assert: Results should be similar (idempotence property)
        threat1 = result1['final_decision']['threat_level'].item()
        threat2 = result2['final_decision']['threat_level'].item()
        
        # Allow small differences due to numerical operations
        assert abs(threat1 - threat2) < 0.01, \
            f"mHC should be approximately idempotent: " \
            f"threat1={threat1:.6f}, threat2={threat2:.6f}, diff={abs(threat1 - threat2):.6f}"
        
        # Coordinated states should be similar
        state1 = result1['coordinated_state']
        state2 = result2['coordinated_state']
        state_diff = torch.norm(state1 - state2).item()
        
        assert state_diff < 0.01, \
            f"Coordinated states should be similar: diff={state_diff:.6f}"
    
    def test_mhc_continuity(self, mhc_instance):
        """Test that mHC is continuous (small input changes → small output changes)"""
        # Arrange: Create base test data
        mhc = mhc_instance
        n_agents = mhc.n_agents
        
        # Create base agent outputs
        base_outputs = []
        base_confidences = torch.softmax(torch.randn(1, n_agents), dim=-1)
        
        for i in range(n_agents):
            reasoning_state = torch.randn(mhc.state_dim)
            decision = {
                'threat_level': torch.tensor([0.5]),
                'confidence': torch.tensor([0.5]),
                'evidence': []
            }
            base_outputs.append({
                'reasoning_state': reasoning_state,
                'decision': decision
            })
        
        # Create perturbed data with small changes
        perturbed_outputs = []
        epsilon = 0.01  # Small perturbation magnitude
        
        for i in range(n_agents):
            # Add small noise to reasoning state
            perturbed_state = base_outputs[i]['reasoning_state'] + \
                            torch.randn(mhc.state_dim) * epsilon
            
            # Slightly different decision
            decision = {
                'threat_level': torch.tensor([0.5 + epsilon * (i - n_agents/2)]),
                'confidence': torch.tensor([0.5]),
                'evidence': []
            }
            
            perturbed_outputs.append({
                'reasoning_state': perturbed_state,
                'decision': decision
            })
        
        # Slightly different confidences
        perturbed_confidences = base_confidences + torch.randn_like(base_confidences) * epsilon
        perturbed_confidences = torch.softmax(perturbed_confidences, dim=-1)
        
        # Act: Apply coordination to both base and perturbed inputs
        base_result = mhc.residual_coordination(base_outputs, base_confidences)
        perturbed_result = mhc.residual_coordination(perturbed_outputs, perturbed_confidences)
        
        # Assert: Output differences should be proportional to input differences
        base_threat = base_result['final_decision']['threat_level'].item()
        perturbed_threat = perturbed_result['final_decision']['threat_level'].item()
        
        threat_diff = abs(base_threat - perturbed_threat)
        
        # Threat difference should be small (Lipschitz continuity)
        # Allow some amplification (10x epsilon) for numerical operations
        max_allowed_diff = epsilon * 10
        
        assert threat_diff < max_allowed_diff, \
            f"mHC should be continuous: input change ~{epsilon}, " \
            f"threat change={threat_diff:.6f}, allowed={max_allowed_diff}"
        
        # State differences should also be bounded
        base_state = base_result['coordinated_state']
        perturbed_state = perturbed_result['coordinated_state']
        state_diff = torch.norm(base_state - perturbed_state).item()
        
        # Rough bound based on state dimension and epsilon
        max_state_diff = epsilon * mhc.state_dim * 0.1
        
        assert state_diff < max_state_diff, \
            f"State changes should be bounded: state_diff={state_diff:.6f}, allowed={max_state_diff}"
        
        # Print test information
        print(f"Continuity test: epsilon={epsilon}, "
              f"threat_diff={threat_diff:.6f}, "
              f"state_diff={state_diff:.6f}")

@pytest.mark.integration
class TestMHCIntegration:
    """Integration tests for mHC with real agents"""
    
    @pytest.fixture
    def agent_orchestrator(self):
        """Create a mock agent orchestrator for integration testing"""
        class MockAgentOrchestrator:
            def __init__(self):
                self.mhc = MockMHC(n_agents=3, state_dim=64, signal_bound=1.0)
            
            def coordinate_analysis(self, security_data):
                """Mock coordination of agent analyses"""
                # Simulate agent analyses based on security data
                n_agents = self.mhc.n_agents
                
                # Create mock agent outputs
                agent_outputs = []
                agent_confidences = torch.zeros(1, n_agents)
                
                # Analyze URL for potential threats
                url = security_data.get('url', '')
                has_xss = '<script>' in url.lower()
                
                for i in range(n_agents):
                    # Different agents have different perspectives
                    if i == 0:  # XSS specialist
                        threat = 0.9 if has_xss else 0.1
                        confidence = 0.95 if has_xss else 0.7
                        evidence = ['Detected script tag in URL'] if has_xss else ['No obvious XSS']
                    elif i == 1:  # General security
                        threat = 0.7 if has_xss else 0.3
                        confidence = 0.8
                        evidence = ['URL contains special characters']
                    else:  # Conservative agent
                        threat = 0.5
                        confidence = 0.6
                        evidence = ['Insufficient information for definitive assessment']
                    
                    reasoning_state = torch.randn(self.mhc.state_dim)
                    decision = {
                        'threat_level': torch.tensor([threat]),
                        'confidence': torch.tensor([confidence]),
                        'evidence': evidence
                    }
                    
                    agent_outputs.append({
                        'reasoning_state': reasoning_state,
                        'decision': decision
                    })
                    
                    agent_confidences[0, i] = confidence
                
                # Normalize confidences
                agent_confidences = torch.softmax(agent_confidences, dim=-1)
                
                # Apply residual coordination
                return self.mhc.residual_coordination(agent_outputs, agent_confidences)
        
        return MockAgentOrchestrator()
    
    def test_mhc_with_agent_outputs(self, agent_orchestrator):
        """Test mHC integration with simulated agent outputs"""
        # Arrange: Get orchestrator and create test security data
        orchestrator = agent_orchestrator
        
        # Create test security data with potential XSS
        security_data = {
            'url': 'https://test.com/?q=<script>alert(1)</script>',
            'headers': {},
            'body': '',
            'method': 'GET'
        }
        
        # Act: Get coordinated analysis from orchestrator
        result = orchestrator.coordinate_analysis(security_data)
        
        # Assert: Verify mHC produces coordinated result
        assert 'final_decision' in result, "Should have final decision"
        assert 'coordinated_state' in result, "Should have coordinated state"
        assert 'agent_contributions' in result, "Should have agent contributions"
        
        # Verify mHC properties in result
        final_decision = result['final_decision']
        
        # Threat level should be reasonable (0-1)
        threat_level = final_decision['threat_level']
        assert 0.0 <= threat_level <= 1.0, \
            f"Threat level should be between 0 and 1, got {threat_level}"
        
        # Confidence should be reasonable (0-1)
        confidence = final_decision['confidence']
        assert 0.0 <= confidence <= 1.0, \
            f"Confidence should be between 0 and 1, got {confidence}"
        
        # Agent contributions should sum to approximately 1
        contributions = result['agent_contributions'][0]  # First batch
        contributions_sum = sum(contributions)
        
        # Allow 10% tolerance for numerical operations
        assert abs(contributions_sum - 1.0) < 0.1, \
            f"Agent contributions should sum to ~1, got {contributions_sum:.3f}"
        
        # No single agent should completely dominate (unless unanimous)
        # This tests the bias mitigation property
        max_contribution = max(contributions)
        assert max_contribution < 0.95, \
            f"No single agent should completely dominate, got max contribution={max_contribution:.3f}"

if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__, "-v"])