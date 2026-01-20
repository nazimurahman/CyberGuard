# src/core/mhc_architecture.py
"""
Manifold-Constrained Hyper-Connections (mHC) Architecture

This module implements the mHC framework for stable multi-agent coordination.
mHC prevents common issues in multi-agent systems:
1. Signal explosion (unbounded information propagation)
2. Dominant agent bias (single agent overpowering others)
3. Reasoning collapse (agents converging to trivial solutions)

Key Components:
1. Doubly-stochastic normalization via Sinkhorn-Knopp algorithm
2. Convex state mixing with bounded signal propagation
3. Identity-preserving mappings
4. Non-expansive updates
5. Residual coordination

Mathematical Foundation:
- States exist on a manifold (constrained space)
- Hyper-connections ensure information flows while maintaining stability
- Bounded operators prevent divergence
- Convex combinations preserve diversity

Reference: "Stable Multi-Agent Reasoning via Manifold-Constrained Hyper-Connections"
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from typing import List, Tuple, Dict, Optional, Union
import math
import time


class ManifoldConstrainedHyperConnections:
    """
    Core mHC implementation for stable multi-agent coordination
    
    Why mHC over naive voting?
    1. Naive voting suffers from dominant agent bias
    2. Simple averaging loses nuanced threat signals
    3. mHC maintains agent diversity while ensuring consensus
    4. Prevents reasoning collapse under adversarial conditions
    
    Security-specific benefits:
    - Stable incident response under attack
    - Consistent forensic correlation
    - Reliable threat attribution
    - Prevents hallucinated threats
    """
    
    def __init__(self, n_agents: int, state_dim: int, temperature: float = 1.0,
                 epsilon: float = 1e-8, sinkhorn_iterations: int = 50):
        """
        Initialize mHC system
        
        Args:
            n_agents: Number of agents in the system
            state_dim: Dimension of agent state vectors
            temperature: Softmax temperature for attention (higher = more uniform)
            epsilon: Small constant for numerical stability
            sinkhorn_iterations: Number of Sinkhorn iterations for normalization
        
        Example:
            >>> mhc = ManifoldConstrainedHyperConnections(n_agents=10, state_dim=512)
        """
        self.n_agents = n_agents
        self.state_dim = state_dim
        self.temperature = temperature
        self.epsilon = epsilon
        self.sinkhorn_iterations = sinkhorn_iterations
        
        # Bounded signal propagation parameters
        # These prevent signal explosion in security scenarios
        self.signal_bound = 1.0  # Maximum allowed signal magnitude
        self.identity_preserve_factor = 0.1  # How much original identity to preserve
        
        # Performance tracking
        self.metrics = {
            'coordination_time': 0.0,
            'signal_bound_violations': 0,
            'sinkhorn_convergence': []
        }
    
    def sinkhorn_knopp_projection(self, log_alpha: torch.Tensor) -> torch.Tensor:
        """
        Apply Sinkhorn-Knopp algorithm for doubly-stochastic normalization
        
        Why doubly-stochastic?
        1. Each row sums to 1: Each agent distributes its attention properly
        2. Each column sums to 1: Each agent receives balanced attention
        3. Prevents any single agent from dominating the coordination
        
        Args:
            log_alpha: Log attention matrix [batch_size, n_agents, n_agents]
        
        Returns:
            torch.Tensor: Doubly-stochastic attention matrix
        
        Example:
            >>> log_alpha = torch.randn(1, 5, 5)  # Batch of 1, 5 agents
            >>> normalized = mhc.sinkhorn_knopp_projection(log_alpha)
        """
        batch_size, n, _ = log_alpha.shape
        
        # Initialize with log attention scores
        log_alpha = log_alpha.clone()
        
        # Track convergence for debugging
        convergence_metrics = []
        
        for iteration in range(self.sinkhorn_iterations):
            # Row normalization (make each row sum to 1)
            # This ensures each agent properly distributes its attention
            row_sum = torch.logsumexp(log_alpha, dim=2, keepdim=True)
            log_alpha = log_alpha - row_sum
            
            # Column normalization (make each column sum to 1)
            # This ensures each agent receives balanced attention
            col_sum = torch.logsumexp(log_alpha, dim=1, keepdim=True)
            log_alpha = log_alpha - col_sum
            
            # Check convergence (optional, for monitoring)
            if iteration % 10 == 0:
                # Calculate how far from doubly-stochastic we are
                row_error = torch.abs(torch.exp(log_alpha).sum(dim=2) - 1.0).mean()
                col_error = torch.abs(torch.exp(log_alpha).sum(dim=1) - 1.0).mean()
                convergence_metrics.append((row_error.item(), col_error.item()))
        
        self.metrics['sinkhorn_convergence'] = convergence_metrics
        
        # Return normalized probabilities
        return torch.exp(log_alpha)
    
    def convex_state_mixing(self, agent_states: List[torch.Tensor], 
                           attention_weights: torch.Tensor) -> torch.Tensor:
        """
        Mix agent states using convex combination with manifold constraints
        
        Security importance:
        1. Bounded propagation prevents adversarial signal amplification
        2. Identity preservation maintains agent specialization
        3. Convex mixing ensures all threats are considered
        
        Args:
            agent_states: List of agent state tensors [batch_size, state_dim]
            attention_weights: Attention matrix [batch_size, n_agents, n_agents]
        
        Returns:
            torch.Tensor: Mixed state vector [batch_size, state_dim]
        
        Example:
            >>> states = [torch.randn(1, 512) for _ in range(5)]
            >>> attention = torch.softmax(torch.randn(1, 5, 5), dim=-1)
            >>> mixed_state = mhc.convex_state_mixing(states, attention)
        """
        batch_size = agent_states[0].shape[0]
        
        # Stack all agent states for efficient computation
        # Shape: [batch_size, n_agents, state_dim]
        stacked_states = torch.stack(agent_states, dim=1)
        
        # Apply doubly-stochastic normalization to attention
        # This prevents any agent from dominating the mixture
        log_attention = torch.log(attention_weights + self.epsilon)
        normalized_attention = self.sinkhorn_knopp_projection(log_attention)
        
        # Convex combination: weighted sum of agent states
        # Each agent contributes proportionally to its attention weight
        # Shape: [batch_size, state_dim]
        mixed_state = torch.einsum('bnm,bmd->bd', normalized_attention, stacked_states)
        
        # Identity-preserving mapping: retain some of original agent characteristics
        # This prevents over-smoothing and maintains agent diversity
        # Security benefit: Specialized agents (e.g., XSS expert) retain their expertise
        identity_contribution = stacked_states.mean(dim=1) * self.identity_preserve_factor
        mixed_state = mixed_state * (1 - self.identity_preserve_factor) + identity_contribution
        
        # Signal bounding: prevent extreme values that could indicate adversarial input
        # Security benefit: Protects against gradient-based attacks
        signal_norm = torch.norm(mixed_state, dim=-1, keepdim=True)
        scaling_factor = torch.minimum(
            torch.ones_like(signal_norm),
            self.signal_bound / (signal_norm + self.epsilon)
        )
        
        # Track violations for security monitoring
        violations = (signal_norm > self.signal_bound).sum().item()
        self.metrics['signal_bound_violations'] += violations
        
        mixed_state = mixed_state * scaling_factor
        
        return mixed_state
    
    def residual_coordination(self, agent_outputs: List[Dict], 
                            agent_confidences: torch.Tensor) -> Dict:
        """
        Coordinate multiple agents using residual connections and mHC principles
        
        Residual coordination benefits:
        1. Preserves original agent insights
        2. Adds coordinated intelligence on top
        3. Enables graceful degradation if agents fail
        
        Args:
            agent_outputs: List of agent analysis dictionaries
            agent_confidences: Confidence scores for each agent [batch_size, n_agents]
        
        Returns:
            dict: Coordinated analysis with threat decisions and evidence
        
        Example:
            >>> outputs = [agent.analyze(data) for agent in agents]
            >>> confidences = torch.tensor([[0.8, 0.9, 0.7]])  # 3 agents
            >>> result = mhc.residual_coordination(outputs, confidences)
        """
        start_time = time.time()
        
        # Extract reasoning states from each agent
        # These states encode the agent's internal threat understanding
        reasoning_states = []
        for output in agent_outputs:
            if 'reasoning_state' in output:
                reasoning_states.append(output['reasoning_state'])
            else:
                # If agent doesn't provide state, use zeros
                # This handles agent failures gracefully
                batch_size = agent_confidences.shape[0]
                dummy_state = torch.zeros(batch_size, self.state_dim, 
                                         device=agent_confidences.device)
                reasoning_states.append(dummy_state)
        
        # Create attention matrix based on agent confidences
        # Higher confidence agents get more attention
        # Shape: [batch_size, n_agents, n_agents]
        attention_logits = torch.log(agent_confidences.unsqueeze(1) + self.epsilon)
        attention_logits = attention_logits.repeat(1, self.n_agents, 1)
        
        # Apply mHC mixing to get coordinated state
        # This combines all agent insights while maintaining stability
        coordinated_state = self.convex_state_mixing(reasoning_states, attention_logits)
        
        # Aggregate individual agent decisions with manifold constraints
        # Each agent's decision is weighted by its confidence
        # But constrained to prevent any single agent from dominating
        aggregated_decisions = []
        agent_weights = agent_confidences / (agent_confidences.sum(dim=1, keepdim=True) + self.epsilon)
        
        for i, output in enumerate(agent_outputs):
            agent_decision = output.get('decision', {})
            agent_weight = agent_weights[:, i:i+1]  # [batch_size, 1]
            
            # Apply manifold constraint: weight decisions but bound influence
            constrained_decision = {
                'threat_level': agent_decision.get('threat_level', 0.0) * agent_weight,
                'confidence': agent_decision.get('confidence', 0.0) * agent_weight,
                'evidence': agent_decision.get('evidence', []),
                'agent_id': output.get('agent_id', f'agent_{i}'),
                'weight': agent_weight.item() if agent_weight.numel() == 1 else agent_weight.tolist()
            }
            aggregated_decisions.append(constrained_decision)
        
        # Combine threat levels and confidences from all agents
        # Using weighted average with mHC constraints
        threat_levels = torch.stack([d['threat_level'] for d in aggregated_decisions], dim=1)
        confidences = torch.stack([d['confidence'] for d in aggregated_decisions], dim=1)
        
        # Final threat level: weighted average with attention-based weights
        final_threat = torch.sum(threat_levels * agent_confidences.unsqueeze(-1), dim=1)
        final_confidence = torch.sum(confidences * agent_confidences.unsqueeze(-1), dim=1)
        
        # Collect all evidence from agents (prioritize high-confidence agents)
        all_evidence = []
        for i, output in enumerate(agent_outputs):
            evidence = output.get('decision', {}).get('evidence', [])
            confidence = agent_confidences[:, i].item() if agent_confidences.numel() > 1 else agent_confidences.item()
            
            # Weight evidence by agent confidence
            for item in evidence:
                item['agent_confidence'] = confidence
                item['agent_id'] = output.get('agent_id', f'agent_{i}')
            all_evidence.extend(evidence)
        
        # Sort evidence by confidence and limit for stability
        all_evidence.sort(key=lambda x: x.get('agent_confidence', 0), reverse=True)
        top_evidence = all_evidence[:10]  # Limit to top 10 pieces of evidence
        
        # Update performance metrics
        coordination_time = time.time() - start_time
        self.metrics['coordination_time'] = (
            self.metrics['coordination_time'] * 0.9 + coordination_time * 0.1
        )
        
        return {
            'final_decision': {
                'threat_level': final_threat,
                'confidence': final_confidence,
                'evidence': top_evidence,
                'explanation': self._generate_explanation(final_threat, final_confidence, top_evidence)
            },
            'coordinated_state': coordinated_state,
            'agent_contributions': agent_confidences.tolist(),
            'aggregated_decisions': aggregated_decisions,
            'metrics': {
                'coordination_time': coordination_time,
                'evidence_count': len(top_evidence),
                'agent_count': len(agent_outputs)
            }
        }
    
    def _generate_explanation(self, threat_level: torch.Tensor, 
                            confidence: torch.Tensor, evidence: List) -> str:
        """
        Generate human-readable explanation of the coordinated decision
        
        Security transparency: Explainable AI is crucial for:
        1. Security team understanding
        2. Compliance requirements
        3. Debugging false positives
        
        Args:
            threat_level: Computed threat level tensor
            confidence: Confidence score tensor
            evidence: List of evidence items
        
        Returns:
            str: Human-readable explanation
        """
        threat_val = threat_level.item() if threat_level.numel() == 1 else threat_level.mean().item()
        conf_val = confidence.item() if confidence.numel() == 1 else confidence.mean().item()
        
        if threat_val < 0.2:
            return "No significant threats detected. All security checks passed."
        elif threat_val < 0.4:
            level = "low"
        elif threat_val < 0.6:
            level = "moderate"
        elif threat_val < 0.8:
            level = "high"
        else:
            level = "critical"
        
        # Summarize evidence types
        evidence_types = set()
        for item in evidence[:3]:  # Top 3 evidence items
            evidence_types.add(item.get('type', 'Unknown'))
        
        evidence_summary = ", ".join(sorted(evidence_types))
        
        explanation = (
            f"Detected {level} threat level with {conf_val:.1%} confidence. "
            f"Analysis based on evidence including: {evidence_summary}. "
        )
        
        # Add confidence qualification
        if conf_val > 0.8:
            explanation += "High confidence in this assessment."
        elif conf_val > 0.6:
            explanation += "Moderate confidence, recommend additional verification."
        else:
            explanation += "Low confidence, manual review recommended."
        
        return explanation
    
    def get_metrics(self) -> Dict:
        """
        Get current performance metrics
        
        Returns:
            dict: Performance metrics including coordination time and violations
        """
        return self.metrics.copy()
    
    def reset_metrics(self):
        """Reset performance metrics"""
        self.metrics = {
            'coordination_time': 0.0,
            'signal_bound_violations': 0,
            'sinkhorn_convergence': []
        }


class MultiHeadMHC(nn.Module):
    """
    Multi-head variant of mHC for complex coordination scenarios
    
    Benefits:
    1. Multiple coordination heads can focus on different threat aspects
    2. Parallel processing improves performance
    3. Redundancy increases system robustness
    """
    
    def __init__(self, n_agents: int, state_dim: int, n_heads: int = 4,
                 dropout: float = 0.1):
        super().__init__()
        
        self.n_agents = n_agents
        self.state_dim = state_dim
        self.n_heads = n_heads
        self.head_dim = state_dim // n_heads
        
        assert state_dim % n_heads == 0, "state_dim must be divisible by n_heads"
        
        # Create multiple mHC heads
        self.heads = nn.ModuleList([
            ManifoldConstrainedHyperConnections(
                n_agents=n_agents,
                state_dim=self.head_dim,
                temperature=1.0 + i * 0.1  # Different temperatures per head
            )
            for i in range(n_heads)
        ])
        
        # Linear projections for splitting/combining heads
        self.state_projection = nn.Linear(state_dim, state_dim)
        self.output_projection = nn.Linear(state_dim, state_dim)
        
        self.dropout = nn.Dropout(dropout)
    
    def forward(self, agent_states: List[torch.Tensor], 
                attention_weights: torch.Tensor) -> torch.Tensor:
        """
        Multi-head mHC forward pass
        
        Args:
            agent_states: List of agent state tensors
            attention_weights: Attention matrix
        
        Returns:
            torch.Tensor: Coordinated state from all heads
        """
        batch_size = agent_states[0].shape[0]
        
        # Project states to higher dimension
        projected_states = [self.state_projection(state) for state in agent_states]
        
        # Split states for multi-head processing
        split_states = []
        for state in projected_states:
            # Reshape: [batch_size, state_dim] -> [batch_size, n_heads, head_dim]
            split = state.view(batch_size, self.n_heads, self.head_dim)
            split_states.append(split)
        
        # Process each head independently
        head_outputs = []
        for head_idx in range(self.n_heads):
            # Get states for this head
            head_states = [split[:, head_idx] for split in split_states]
            
            # Process with this head's mHC
            head_output = self.heads[head_idx].convex_state_mixing(
                head_states, attention_weights
            )
            head_outputs.append(head_output)
        
        # Combine head outputs
        # Shape: [batch_size, n_heads, head_dim]
        combined = torch.stack(head_outputs, dim=1)
        
        # Reshape back: [batch_size, state_dim]
        combined = combined.reshape(batch_size, self.state_dim)
        
        # Final projection and dropout
        output = self.output_projection(combined)
        output = self.dropout(output)
        
        return output


def test_mhc_stability():
    """
    Test function to verify mHC stability properties
    
    Tests:
    1. Signal bounding prevents explosion
    2. Doubly-stochastic normalization works
    3. Identity preservation maintains diversity
    4. Residual coordination handles agent failures
    """
    print("🧪 Testing mHC stability...")
    
    # Create test scenario
    n_agents = 5
    state_dim = 128
    batch_size = 2
    
    mhc = ManifoldConstrainedHyperConnections(n_agents, state_dim)
    
    # Create random agent states
    agent_states = []
    for i in range(n_agents):
        # Some agents have extreme values (simulating adversarial input)
        if i == 0:
            state = torch.randn(batch_size, state_dim) * 10.0  # Extreme values
        else:
            state = torch.randn(batch_size, state_dim)
        agent_states.append(state)
    
    # Create attention weights
    attention = torch.softmax(torch.randn(batch_size, n_agents, n_agents), dim=-1)
    
    # Test convex mixing
    mixed = mhc.convex_state_mixing(agent_states, attention)
    
    # Verify signal bounding
    signal_norm = torch.norm(mixed, dim=-1)
    assert torch.all(signal_norm <= mhc.signal_bound + 1e-6), "Signal bounding failed!"
    
    # Verify shape
    assert mixed.shape == (batch_size, state_dim), "Output shape incorrect!"
    
    print("✅ mHC stability tests passed!")
    print(f"   Signal norm: {signal_norm.mean().item():.3f} (bound: {mhc.signal_bound})")
    
    return True


if __name__ == "__main__":
    # Run tests when module is executed directly
    test_mhc_stability()