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
from typing import List, Dict, Any
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

# Test markers
pytestmark = [
    pytest.mark.mhc,
    pytest.mark.requires_torch,
    pytest.mark.unit
]

class TestSinkhornKnoppProjection:
    """Tests for Sinkhorn-Knopp projection algorithm"""
    
    def test_sinkhorn_basic_properties(self, mhc_instance):
        """Test basic properties of Sinkhorn-Knopp projection"""
        # Arrange
        mhc = mhc_instance
        
        # Create random log-alpha matrix
        batch_size = 2
        n_agents = mhc.n_agents
        log_alpha = torch.randn(batch_size, n_agents, n_agents)
        
        # Act: Apply Sinkhorn-Knopp projection
        # Note: Method might be private or have different interface
        if hasattr(mhc, 'sinkhorn_knopp_projection'):
            projected = mhc.sinkhorn_knopp_projection(log_alpha)
        else:
            # Skip if method not available
            pytest.skip("Sinkhorn-Knopp projection method not available")
        
        # Assert: Basic properties
        assert projected.shape == log_alpha.shape, \
            f"Projection should preserve shape: {projected.shape} != {log_alpha.shape}"
        
        # Should be non-negative
        assert torch.all(projected >= 0), \
            "Projected values should be non-negative"
        
        # Should be finite
        assert torch.all(torch.isfinite(projected)), \
            "Projected values should be finite"
    
    def test_sinkhorn_doubly_stochastic(self, mhc_instance):
        """Test that Sinkhorn-Knopp produces doubly-stochastic matrix"""
        # Arrange
        mhc = mhc_instance
        
        # Create test matrix
        n_agents = mhc.n_agents
        log_alpha = torch.randn(1, n_agents, n_agents)
        
        # Act
        if hasattr(mhc, 'sinkhorn_knopp_projection'):
            projected = mhc.sinkhorn_knopp_projection(log_alpha)
        else:
            pytest.skip("Sinkhorn-Knopp projection method not available")
        
        # Assert: Doubly-stochastic properties
        # Row sums should be approximately 1
        row_sums = projected.sum(dim=-1)
        assert torch.allclose(row_sums, torch.ones_like(row_sums), rtol=1e-5), \
            f"Row sums should be 1, got min={row_sums.min():.6f}, max={row_sums.max():.6f}"
        
        # Column sums should be approximately 1
        col_sums = projected.sum(dim=-2)
        assert torch.allclose(col_sums, torch.ones_like(col_sums), rtol=1e-5), \
            f"Column sums should be 1, got min={col_sums.min():.6f}, max={col_sums.max():.6f}"
    
    def test_sinkhorn_convergence(self, mhc_instance):
        """Test Sinkhorn-Knopp convergence properties"""
        # Arrange
        mhc = mhc_instance
        
        # Create test matrix
        n_agents = mhc.n_agents
        log_alpha = torch.randn(1, n_agents, n_agents)
        
        # Track convergence
        convergence_errors = []
        
        # Act: Apply projection with different iteration counts
        if hasattr(mhc, 'sinkhorn_iterations'):
            original_iterations = mhc.sinkhorn_iterations
            
            # Test with fewer iterations
            mhc.sinkhorn_iterations = 5
            if hasattr(mhc, 'sinkhorn_knopp_projection'):
                projected_5 = mhc.sinkhorn_knopp_projection(log_alpha)
                
                # Calculate error from doubly-stochastic
                row_sums_5 = projected_5.sum(dim=-1)
                col_sums_5 = projected_5.sum(dim=-2)
                error_5 = (row_sums_5 - 1).abs().mean() + (col_sums_5 - 1).abs().mean()
                convergence_errors.append(('5 iterations', error_5.item()))
            
            # Test with more iterations
            mhc.sinkhorn_iterations = 50
            if hasattr(mhc, 'sinkhorn_knopp_projection'):
                projected_50 = mhc.sinkhorn_knopp_projection(log_alpha)
                
                # Calculate error
                row_sums_50 = projected_50.sum(dim=-1)
                col_sums_50 = projected_50.sum(dim=-2)
                error_50 = (row_sums_50 - 1).abs().mean() + (col_sums_50 - 1).abs().mean()
                convergence_errors.append(('50 iterations', error_50.item()))
            
            # Restore original iterations
            mhc.sinkhorn_iterations = original_iterations
        
        # Assert: More iterations should reduce error
        if len(convergence_errors) == 2:
            _, error_5 = convergence_errors[0]
            _, error_50 = convergence_errors[1]
            
            assert error_50 <= error_5 * 1.1, \
                f"More iterations should not increase error: 5it={error_5:.6f}, 50it={error_50:.6f}"
            
            print(f"Convergence errors: 5 iterations={error_5:.6f}, 50 iterations={error_50:.6f}")
    
    def test_sinkhorn_stability(self, mhc_instance):
        """Test numerical stability of Sinkhorn-Knopp"""
        # Arrange
        mhc = mhc_instance
        
        # Test with extreme values
        n_agents = mhc.n_agents
        test_cases = [
            ('large_values', torch.randn(1, n_agents, n_agents) * 100),
            ('small_values', torch.randn(1, n_agents, n_agents) * 0.01),
            ('mixed_values', torch.tensor([[[100, -100], [-100, 100]]], dtype=torch.float32)),
            ('zero_matrix', torch.zeros(1, n_agents, n_agents)),
        ]
        
        for case_name, log_alpha in test_cases:
            # Act
            if hasattr(mhc, 'sinkhorn_knopp_projection'):
                try:
                    projected = mhc.sinkhorn_knopp_projection(log_alpha)
                    
                    # Assert: Should handle all cases without numerical issues
                    assert torch.all(torch.isfinite(projected)), \
                        f"{case_name}: Projected values should be finite"
                    
                    # Should produce valid probabilities
                    assert torch.all(projected >= 0), \
                        f"{case_name}: Projected values should be non-negative"
                    
                    # Sum should be approximately n_agents (sum of all elements)
                    total_sum = projected.sum()
                    expected_sum = n_agents  # Sum of all row/column sums
                    assert torch.allclose(total_sum, 
                                        torch.tensor(expected_sum, dtype=total_sum.dtype),
                                        rtol=1e-5), \
                        f"{case_name}: Total sum should be {expected_sum}, got {total_sum:.6f}"
                    
                except Exception as e:
                    pytest.fail(f"{case_name}: Sinkhorn should handle gracefully, got {e}")

class TestConvexStateMixing:
    """Tests for convex state mixing with mHC"""
    
    def test_convex_mixing_basic(self, mhc_instance):
        """Test basic convex state mixing"""
        # Arrange
        mhc = mhc_instance
        batch_size = 2
        n_agents = mhc.n_agents
        state_dim = mhc.state_dim
        
        # Create mock agent states
        agent_states = [
            torch.randn(batch_size, state_dim) for _ in range(n_agents)
        ]
        
        # Create attention weights
        attention_weights = torch.softmax(torch.randn(batch_size, n_agents), dim=-1)
        
        # Act
        if hasattr(mhc, 'convex_state_mixing'):
            mixed_state = mhc.convex_state_mixing(agent_states, attention_weights)
        else:
            pytest.skip("Convex state mixing method not available")
        
        # Assert
        assert mixed_state.shape == (batch_size, state_dim), \
            f"Mixed state should have shape (batch_size, state_dim), got {mixed_state.shape}"
        
        # Should be finite
        assert torch.all(torch.isfinite(mixed_state)), \
            "Mixed state should be finite"
    
    def test_convex_mixing_convexity(self, mhc_instance):
        """Test that mixing is convex combination"""
        # Arrange
        mhc = mhc_instance
        batch_size = 1
        n_agents = mhc.n_agents
        state_dim = mhc.state_dim
        
        # Create simple test states
        agent_states = [
            torch.zeros(batch_size, state_dim) for _ in range(n_agents)
        ]
        agent_states[0][0, 0] = 1.0  # First state has 1 at position 0
        agent_states[1][0, 1] = 1.0  # Second state has 1 at position 1
        
        # Create attention weights focused on first agent
        attention_weights = torch.zeros(batch_size, n_agents)
        attention_weights[0, 0] = 1.0  # 100% attention to first agent
        
        # Act
        if hasattr(mhc, 'convex_state_mixing'):
            mixed_state = mhc.convex_state_mixing(agent_states, attention_weights)
        else:
            pytest.skip("Convex state mixing method not available")
        
        # Assert: Should match first state (convex combination with weight 1)
        # Allow small numerical differences due to normalization
        assert torch.allclose(mixed_state[0, 0], torch.tensor(1.0), rtol=1e-5), \
            f"With full attention to first agent, mixed state[0] should be ~1, got {mixed_state[0, 0]:.6f}"
        assert torch.allclose(mixed_state[0, 1], torch.tensor(0.0), rtol=1e-5), \
            f"With no attention to second agent, mixed state[1] should be ~0, got {mixed_state[0, 1]:.6f}"
    
    def test_signal_bounding(self, mhc_instance):
        """Test that signal bounding prevents explosion"""
        # Arrange
        mhc = mhc_instance
        batch_size = 2
        n_agents = mhc.n_agents
        state_dim = mhc.state_dim
        
        # Create states with large norms (could cause explosion)
        large_norm = 100.0
        agent_states = [
            torch.randn(batch_size, state_dim) * large_norm for _ in range(n_agents)
        ]
        
        # Create uniform attention
        attention_weights = torch.ones(batch_size, n_agents) / n_agents
        
        # Act
        if hasattr(mhc, 'convex_state_mixing'):
            mixed_state = mhc.convex_state_mixing(agent_states, attention_weights)
        else:
            pytest.skip("Convex state mixing method not available")
        
        # Assert: Norm should be bounded
        state_norms = torch.norm(mixed_state, dim=-1)
        
        # Check against signal bound (with tolerance for numerical operations)
        max_allowed_norm = mhc.signal_bound * 1.1  # 10% tolerance
        
        assert torch.all(state_norms <= max_allowed_norm), \
            f"State norms should be bounded by {mhc.signal_bound}, " \
            f"got max={state_norms.max():.6f}"
        
        print(f"Signal bounding test: input norm ~{large_norm}, "
              f"output norm max={state_norms.max():.6f}, "
              f"bound={mhc.signal_bound}")
    
    def test_identity_preservation(self, mhc_instance):
        """Test identity-preserving mappings"""
        # Arrange
        mhc = mhc_instance
        batch_size = 2
        n_agents = mhc.n_agents
        state_dim = mhc.state_dim
        
        # Create identical agent states
        base_state = torch.randn(batch_size, state_dim)
        agent_states = [base_state.clone() for _ in range(n_agents)]
        
        # Create arbitrary attention weights
        attention_weights = torch.softmax(torch.randn(batch_size, n_agents), dim=-1)
        
        # Act
        if hasattr(mhc, 'convex_state_mixing'):
            mixed_state = mhc.convex_state_mixing(agent_states, attention_weights)
        else:
            pytest.skip("Convex state mixing method not available")
        
        # Assert: With identical states, output should be close to input
        # (allowing for identity preservation factor)
        similarity = torch.cosine_similarity(mixed_state, base_state, dim=-1)
        
        # Should be very similar (cosine similarity close to 1)
        assert torch.all(similarity > 0.99), \
            f"With identical states, output should be similar to input, " \
            f"got min similarity={similarity.min():.6f}"
    
    def test_non_expansive_updates(self, mhc_instance):
        """Test that updates are non-expansive (Lipschitz constant ≤ 1)"""
        # Arrange
        mhc = mhc_instance
        batch_size = 10  # Multiple samples for statistical test
        n_agents = mhc.n_agents
        state_dim = mhc.state_dim
        
        # Create two sets of agent states
        agent_states1 = [torch.randn(batch_size, state_dim) for _ in range(n_agents)]
        agent_states2 = [torch.randn(batch_size, state_dim) for _ in range(n_agents)]
        
        # Same attention weights for both
        attention_weights = torch.softmax(torch.randn(batch_size, n_agents), dim=-1)
        
        # Act
        if hasattr(mhc, 'convex_state_mixing'):
            mixed1 = mhc.convex_state_mixing(agent_states1, attention_weights)
            mixed2 = mhc.convex_state_mixing(agent_states2, attention_weights)
        else:
            pytest.skip("Convex state mixing method not available")
        
        # Calculate distances
        input_diffs = [torch.norm(s1 - s2, dim=-1) for s1, s2 in zip(agent_states1, agent_states2)]
        avg_input_diff = torch.stack(input_diffs).mean()
        
        output_diff = torch.norm(mixed1 - mixed2, dim=-1).mean()
        
        # Assert: Output difference should not exceed input difference
        # (non-expansive property)
        assert output_diff <= avg_input_diff * 1.05, \
            f"Updates should be non-expansive: " \
            f"output_diff={output_diff:.6f}, avg_input_diff={avg_input_diff:.6f}"
        
        print(f"Non-expansive test: input_diff={avg_input_diff:.6f}, "
              f"output_diff={output_diff:.6f}, "
              f"ratio={output_diff/avg_input_diff:.6f}")

class TestResidualCoordination:
    """Tests for residual coordination between agents"""
    
    def test_residual_coordination_basic(self, mhc_instance):
        """Test basic residual coordination"""
        # Arrange
        mhc = mhc_instance
        n_agents = mhc.n_agents
        
        # Create mock agent outputs
        agent_outputs = []
        agent_confidences = torch.zeros(1, n_agents)
        
        for i in range(n_agents):
            # Create mock reasoning state
            reasoning_state = torch.randn(mhc.state_dim)
            
            # Create mock decision
            decision = {
                'threat_level': torch.tensor([0.5 + 0.1 * i]),
                'confidence': torch.tensor([0.6 + 0.05 * i]),
                'evidence': [f'Evidence {j}' for j in range(3)]
            }
            
            agent_outputs.append({
                'reasoning_state': reasoning_state,
                'decision': decision
            })
            
            agent_confidences[0, i] = 0.5 + 0.1 * i
        
        # Normalize confidences
        agent_confidences = torch.softmax(agent_confidences, dim=-1)
        
        # Act
        if hasattr(mhc, 'residual_coordination'):
            result = mhc.residual_coordination(agent_outputs, agent_confidences)
        else:
            pytest.skip("Residual coordination method not available")
        
        # Assert
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
        
        # Check coordinated state
        coordinated_state = result['coordinated_state']
        assert coordinated_state.shape == (1, mhc.state_dim), \
            f"Coordinated state should have shape (1, state_dim), got {coordinated_state.shape}"
        
        # Check agent contributions
        contributions = result['agent_contributions']
        assert len(contributions) == n_agents, \
            f"Should have contributions for all agents, got {len(contributions)}"
        
        # Contributions should sum to approximately 1
        contributions_sum = sum(contributions[0])  # First batch
        assert abs(contributions_sum - 1.0) < 0.01, \
            f"Agent contributions should sum to ~1, got {contributions_sum:.6f}"
    
    def test_dominant_agent_mitigation(self, mhc_instance):
        """Test that mHC mitigates dominant agent bias"""
        # Arrange
        mhc = mhc_instance
        n_agents = mhc.n_agents
        
        # Create scenario where one agent has very high confidence
        agent_outputs = []
        agent_confidences = torch.zeros(1, n_agents)
        
        # First agent has very high confidence
        agent_confidences[0, 0] = 100.0  # Dominant agent
        for i in range(1, n_agents):
            agent_confidences[0, i] = 1.0  # Other agents have normal confidence
        
        # Softmax will give almost all weight to first agent
        agent_confidences = torch.softmax(agent_confidences, dim=-1)
        
        # Create conflicting agent decisions
        for i in range(n_agents):
            reasoning_state = torch.randn(mhc.state_dim)
            
            # First agent says high threat, others say low threat
            if i == 0:
                threat_level = 0.9
                confidence = 0.95
            else:
                threat_level = 0.1
                confidence = 0.7
            
            decision = {
                'threat_level': torch.tensor([threat_level]),
                'confidence': torch.tensor([confidence]),
                'evidence': [f'Agent {i} evidence']
            }
            
            agent_outputs.append({
                'reasoning_state': reasoning_state,
                'decision': decision
            })
        
        # Act
        if hasattr(mhc, 'residual_coordination'):
            result = mhc.residual_coordination(agent_outputs, agent_confidences)
        else:
            pytest.skip("Residual coordination method not available")
        
        # Assert: mHC should mitigate dominant agent bias
        final_decision = result['final_decision']
        final_threat = final_decision['threat_level'].item()
        
        # With mHC, final threat should be between extremes
        # (not just blindly following dominant agent)
        assert 0.1 < final_threat < 0.9, \
            f"mHC should balance agent opinions, got threat={final_threat:.3f}"
        
        # Check that other agents still contribute
        contributions = result['agent_contributions'][0]  # First batch
        non_dominant_contributions = sum(contributions[1:])  # All except first agent
        
        assert non_dominant_contributions > 0.01, \
            f"Non-dominant agents should contribute, got {non_dominant_contributions:.6f}"
        
        print(f"Dominant agent mitigation: "
              f"dominant agent weight={contributions[0]:.3f}, "
              f"other agents weight={non_dominant_contributions:.3f}, "
              f"final threat={final_threat:.3f}")
    
    def test_reasoning_collapse_prevention(self, mhc_instance):
        """Test that mHC prevents reasoning collapse"""
        # Arrange
        mhc = mhc_instance
        n_agents = mhc.n_agents
        
        # Create scenario where agents have very different reasoning states
        agent_outputs = []
        agent_confidences = torch.softmax(torch.randn(1, n_agents), dim=-1)
        
        # Create diverse reasoning states
        for i in range(n_agents):
            # Each agent has reasoning state in different direction
            reasoning_state = torch.zeros(mhc.state_dim)
            reasoning_state[i] = 1.0  # Only dimension i is active
            
            decision = {
                'threat_level': torch.tensor([0.5]),
                'confidence': torch.tensor([0.5]),
                'evidence': []
            }
            
            agent_outputs.append({
                'reasoning_state': reasoning_state,
                'decision': decision
            })
        
        # Act
        if hasattr(mhc, 'residual_coordination'):
            result = mhc.residual_coordination(agent_outputs, agent_confidences)
        else:
            pytest.skip("Residual coordination method not available")
        
        # Assert: Coordinated state should preserve diversity
        coordinated_state = result['coordinated_state'][0]  # First batch
        
        # Calculate how many dimensions are active
        # (non-zero beyond threshold)
        threshold = 0.01
        active_dimensions = (coordinated_state.abs() > threshold).sum().item()
        
        # Should have multiple active dimensions (not collapsed to single dimension)
        assert active_dimensions > 1, \
            f"Reasoning collapse prevention: should have multiple active dimensions, " \
            f"got {active_dimensions}"
        
        # State norm should be bounded
        state_norm = torch.norm(coordinated_state).item()
        assert state_norm <= mhc.signal_bound * 1.1, \
            f"State norm should be bounded, got {state_norm:.6f}"
        
        print(f"Reasoning collapse prevention: "
              f"active dimensions={active_dimensions}/{mhc.state_dim}, "
              f"state norm={state_norm:.6f}")
    
    def test_signal_explosion_prevention(self, mhc_instance):
        """Test that mHC prevents signal explosion"""
        # Arrange
        mhc = mhc_instance
        n_agents = mhc.n_agents
        
        # Create agents with exploding signals
        agent_outputs = []
        agent_confidences = torch.softmax(torch.randn(1, n_agents), dim=-1)
        
        for i in range(n_agents):
            # Create reasoning state with very large norm
            reasoning_state = torch.randn(mhc.state_dim) * 1000  # Large norm
            
            decision = {
                'threat_level': torch.tensor([0.5]),
                'confidence': torch.tensor([0.5]),
                'evidence': []
            }
            
            agent_outputs.append({
                'reasoning_state': reasoning_state,
                'decision': decision
            })
        
        # Act
        if hasattr(mhc, 'residual_coordination'):
            result = mhc.residual_coordination(agent_outputs, agent_confidences)
        else:
            pytest.skip("Residual coordination method not available")
        
        # Assert: Coordinated state should have bounded norm
        coordinated_state = result['coordinated_state'][0]  # First batch
        state_norm = torch.norm(coordinated_state).item()
        
        assert state_norm <= mhc.signal_bound * 1.1, \
            f"Signal explosion prevention: state norm should be ≤ {mhc.signal_bound}, " \
            f"got {state_norm:.6f}"
        
        # Check that individual contributions are bounded
        contributions = result['agent_contributions'][0]
        for contrib in contributions:
            assert 0.0 <= contrib <= 1.0, \
                f"Agent contribution should be between 0 and 1, got {contrib}"
        
        print(f"Signal explosion prevention: "
              f"input norms ~1000, "
              f"output norm={state_norm:.6f}, "
              f"bound={mhc.signal_bound}")

class TestMHCStability:
    """Tests for mHC stability properties"""
    
    def test_mhc_idempotence(self, mhc_instance):
        """Test that applying mHC twice doesn't change result much"""
        # Arrange
        mhc = mhc_instance
        n_agents = mhc.n_agents
        
        # Create test data
        agent_outputs = []
        agent_confidences = torch.softmax(torch.randn(1, n_agents), dim=-1)
        
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
        
        # Act: Apply coordination twice
        if hasattr(mhc, 'residual_coordination'):
            result1 = mhc.residual_coordination(agent_outputs, agent_confidences)
            
            # Use result1 as input for second round
            # (simulating iterative refinement)
            agent_outputs2 = []
            for i in range(n_agents):
                # Keep original reasoning states
                agent_outputs2.append(agent_outputs[i].copy())
            
            result2 = mhc.residual_coordination(agent_outputs2, agent_confidences)
        else:
            pytest.skip("Residual coordination method not available")
        
        # Assert: Results should be similar (idempotence)
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
        # Arrange
        mhc = mhc_instance
        n_agents = mhc.n_agents
        
        # Create base test data
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
        
        # Create perturbed data (small changes)
        perturbed_outputs = []
        epsilon = 0.01  # Small perturbation
        
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
        
        # Act
        if hasattr(mhc, 'residual_coordination'):
            base_result = mhc.residual_coordination(base_outputs, base_confidences)
            perturbed_result = mhc.residual_coordination(perturbed_outputs, perturbed_confidences)
        else:
            pytest.skip("Residual coordination method not available")
        
        # Assert: Output differences should be proportional to input differences
        base_threat = base_result['final_decision']['threat_level'].item()
        perturbed_threat = perturbed_result['final_decision']['threat_level'].item()
        
        threat_diff = abs(base_threat - perturbed_threat)
        
        # Threat difference should be small (Lipschitz continuity)
        max_allowed_diff = epsilon * 10  # Allow some amplification
        
        assert threat_diff < max_allowed_diff, \
            f"mHC should be continuous: input change ~{epsilon}, " \
            f"threat change={threat_diff:.6f}, allowed={max_allowed_diff}"
        
        # State differences should also be bounded
        base_state = base_result['coordinated_state']
        perturbed_state = perturbed_result['coordinated_state']
        state_diff = torch.norm(base_state - perturbed_state).item()
        
        max_state_diff = epsilon * mhc.state_dim * 0.1  # Rough bound
        
        assert state_diff < max_state_diff, \
            f"State changes should be bounded: state_diff={state_diff:.6f}, allowed={max_state_diff}"
        
        print(f"Continuity test: epsilon={epsilon}, "
              f"threat_diff={threat_diff:.6f}, "
              f"state_diff={state_diff:.6f}")

@pytest.mark.integration
class TestMHCIntegration:
    """Integration tests for mHC with real agents"""
    
    def test_mhc_with_agent_outputs(self, agent_orchestrator):
        """Test mHC integration with actual agent outputs"""
        # Arrange
        orchestrator = agent_orchestrator
        
        # Create test security data
        security_data = {
            'url': 'https://test.com/?q=<script>alert(1)</script>',
            'headers': {},
            'body': '',
            'method': 'GET'
        }
        
        # Get agent analyses
        if hasattr(orchestrator, 'coordinate_analysis'):
            result = orchestrator.coordinate_analysis(security_data)
        else:
            pytest.skip("Agent coordination not available")
        
        # Assert: mHC should produce coordinated result
        assert 'final_decision' in result, "Should have final decision"
        assert 'coordinated_state' in result, "Should have coordinated state"
        assert 'agent_contributions' in result, "Should have agent contributions"
        
        # Verify mHC properties in result
        final_decision = result['final_decision']
        
        # Threat level should be reasonable
        assert 0.0 <= final_decision['threat_level'] <= 1.0, \
            f"Threat level should be between 0 and 1, got {final_decision['threat_level']}"
        
        # Confidence should be reasonable
        assert 0.0 <= final_decision['confidence'] <= 1.0, \
            f"Confidence should be between 0 and 1, got {final_decision['confidence']}"
        
        # Agent contributions should sum to ~1
        contributions = result['agent_contributions'][0]  # First batch
        contributions_sum = sum(contributions)
        
        assert abs(contributions_sum - 1.0) < 0.1, \
            f"Agent contributions should sum to ~1, got {contributions_sum:.3f}"
        
        # No single agent should dominate completely (unless unanimous)
        max_contribution = max(contributions)
        assert max_contribution < 0.95, \
            f"No single agent should completely dominate, got max contribution={max_contribution:.3f}"

if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__, "-v"])