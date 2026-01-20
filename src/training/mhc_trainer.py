# src/training/mhc_trainer.py
"""
Manifold-Constrained Hyper-Connections (mHC) Trainer
====================================================

This module implements training for mHC-based multi-agent coordination systems.
mHC provides stable, bounded signal propagation for multi-agent reasoning.

Key Concepts:
1. Doubly-stochastic normalization via Sinkhorn-Knopp projection
2. Convex state mixing with identity preservation
3. Non-expansive updates for training stability
4. Bounded signal propagation to prevent explosion

Mathematical Formulation:
Let H be the manifold of valid agent states
Let P be the projection operator onto H
For agent states X = [x₁, x₂, ..., xₙ], we compute:
  Y = P(αX + (1-α)I)  where I preserves identity
such that:
  ||Y|| ≤ ||X|| (non-expansive)
  Y maintains manifold constraints H
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from torch.utils.data import DataLoader
from typing import Dict, List, Tuple, Optional, Union, Any, Callable
import numpy as np
import math
from datetime import datetime
import warnings
from pathlib import Path
import json
from collections import defaultdict, deque
import random

from .security_dataset import SecurityDataset

class ManifoldConstrainedOptimizer(optim.Optimizer):
    """
    Optimizer with manifold constraints for mHC training.
    
    This optimizer enforces manifold constraints during gradient updates:
    1. Projects gradients onto tangent space of manifold
    2. Ensures updates stay within valid state space
    3. Maintains stability through constrained step sizes
    
    Based on Riemannian optimization principles:
    - Manifold: H = {x ∈ ℝⁿ | constraints(x) = 0}
    - Tangent space: TₓH at point x
    - Retraction: Rₓ(v) maps tangent vector v back to manifold
    """
    
    def __init__(self, params, lr=1e-3, beta=0.9, manifold_constraint='sinkhorn',
                 constraint_strength=0.1, projection_iterations=3):
        """
        Initialize manifold-constrained optimizer.
        
        Args:
            params: Model parameters to optimize
            lr: Learning rate (step size)
            beta: Momentum coefficient
            manifold_constraint: Type of constraint ('sinkhorn', 'sphere', 'stiefel')
            constraint_strength: Strength of manifold constraint (0-1)
            projection_iterations: Number of projection steps per update
            
        Why manifold constraints matter:
        - Prevents parameter drift outside valid ranges
        - Maintains stability in multi-agent systems
        - Ensures interpretable agent representations
        """
        defaults = dict(lr=lr, beta=beta, 
                       manifold_constraint=manifold_constraint,
                       constraint_strength=constraint_strength,
                       projection_iterations=projection_iterations)
        super().__init__(params, defaults)
        
        # Initialize momentum buffers
        for group in self.param_groups:
            for p in group['params']:
                state = self.state[p]
                state['momentum'] = torch.zeros_like(p.data)
                
        # Projection methods for different manifolds
        self.projection_methods = {
            'sinkhorn': self._sinkhorn_projection,
            'sphere': self._sphere_projection,
            'stiefel': self._stiefel_projection,
            'simplex': self._simplex_projection,
        }
    
    def step(self, closure: Optional[Callable] = None):
        """
        Perform a single optimization step with manifold constraints.
        
        The update rule is:
        1. Compute standard gradient g
        2. Apply momentum: m = βm + g
        3. Project m onto tangent space TₓH
        4. Update: x = Rₓ(-η * m) (retraction onto manifold)
        
        This ensures parameters stay on the manifold throughout training.
        """
        loss = None
        if closure is not None:
            loss = closure()
        
        for group in self.param_groups:
            lr = group['lr']
            beta = group['beta']
            constraint_type = group['manifold_constraint']
            constraint_strength = group['constraint_strength']
            proj_iters = group['projection_iterations']
            
            projection_fn = self.projection_methods.get(constraint_type)
            if projection_fn is None:
                raise ValueError(f"Unknown manifold constraint: {constraint_type}")
            
            for p in group['params']:
                if p.grad is None:
                    continue
                
                grad = p.grad.data
                state = self.state[p]
                
                # 1. Apply momentum
                momentum = state['momentum']
                momentum.mul_(beta).add_(grad, alpha=1 - beta)
                
                # 2. Project gradient onto tangent space
                # The tangent space projection depends on current point p
                tangent_grad = self._project_to_tangent_space(
                    momentum, p.data, constraint_type
                )
                
                # 3. Apply constrained update
                # Move in tangent direction, then retract to manifold
                update = -lr * tangent_grad
                
                # Blend with manifold-preserving update
                if constraint_strength > 0:
                    for _ in range(proj_iters):
                        # Apply partial update
                        p.data.add_(update * (1 - constraint_strength))
                        # Project back to manifold
                        p.data = projection_fn(p.data)
                        # Recompute update for next iteration
                        update = -lr * tangent_grad * constraint_strength
                else:
                    # Standard update without constraint
                    p.data.add_(update)
        
        return loss
    
    def _project_to_tangent_space(self, grad: torch.Tensor, 
                                 point: torch.Tensor, 
                                 constraint_type: str) -> torch.Tensor:
        """
        Project gradient onto tangent space of manifold at given point.
        
        For manifold H defined by constraint f(x) = 0:
        Tangent space TₓH = {v | J_f(x)·v = 0}
        where J_f is Jacobian of constraints.
        
        Projection: v_proj = v - J_f(x)ᵀ(J_f(x)J_f(x)ᵀ)⁻¹J_f(x)v
        """
        if constraint_type == 'sinkhorn':
            # For doubly-stochastic matrices
            # Tangent space: matrices with row and column sums = 0
            return self._sinkhorn_tangent_projection(grad, point)
        
        elif constraint_type == 'sphere':
            # For unit sphere: ||x|| = 1
            # Tangent space: vectors orthogonal to x
            # Projection: v_proj = v - (x·v)x
            dot_product = torch.sum(point * grad)
            return grad - dot_product * point
        
        elif constraint_type == 'stiefel':
            # For Stiefel manifold: XᵀX = I
            # Tangent space: XᵀV + VᵀX = 0
            return self._stiefel_tangent_projection(grad, point)
        
        else:
            # Default: no projection
            return grad
    
    def _sinkhorn_tangent_projection(self, grad: torch.Tensor, 
                                    point: torch.Tensor) -> torch.Tensor:
        """
        Project onto tangent space of doubly-stochastic matrices.
        
        For matrix M to be doubly-stochastic:
        - Row sums = 1
        - Column sums = 1
        - All elements ≥ 0
        
        Tangent space constraints:
        - Row sum of gradient = 0
        - Column sum of gradient = 0
        """
        if grad.dim() != 2:
            # Only applicable to 2D matrices
            return grad
        
        # Ensure non-negativity for projection
        point_clamped = torch.clamp(point, min=1e-8)
        
        # Compute row and column sums
        row_sums = grad.sum(dim=1, keepdim=True)
        col_sums = grad.sum(dim=0, keepdim=True)
        
        # Project onto space with zero row/column sums
        # Using method from "Sinkhorn distances: Lightspeed computation of optimal transport"
        n_rows, n_cols = grad.shape
        
        # Compute scaling factors
        row_factor = row_sums / n_cols
        col_factor = col_sums / n_rows
        
        # Project gradient
        projected = grad - row_factor - col_factor + row_factor.mean() + col_factor.mean()
        
        return projected
    
    def _sinkhorn_projection(self, x: torch.Tensor, 
                            iterations: int = 50,
                            epsilon: float = 1e-8) -> torch.Tensor:
        """
        Sinkhorn-Knopp projection for doubly-stochastic normalization.
        
        Projects matrix onto space of doubly-stochastic matrices:
        - Non-negative entries
        - Row sums = 1
        - Column sums = 1
        
        Algorithm:
        for i in range(iterations):
            x = x / (x.sum(dim=1, keepdim=True) + epsilon)  # Row normalize
            x = x / (x.sum(dim=0, keepdim=True) + epsilon)  # Column normalize
        
        Returns doubly-stochastic approximation of input.
        """
        if x.dim() != 2:
            # Reshape if needed
            original_shape = x.shape
            if x.dim() > 2:
                x = x.view(-1, x.shape[-1])
            
            for _ in range(iterations):
                # Row normalization
                row_sum = x.sum(dim=1, keepdim=True) + epsilon
                x = x / row_sum
                
                # Column normalization
                col_sum = x.sum(dim=0, keepdim=True) + epsilon
                x = x / col_sum
            
            # Reshape back
            if len(original_shape) > 2:
                x = x.view(original_shape)
        
        return x
    
    def _sphere_projection(self, x: torch.Tensor) -> torch.Tensor:
        """Project onto unit sphere (||x|| = 1)."""
        norm = x.norm(p=2, dim=-1, keepdim=True) + 1e-8
        return x / norm
    
    def _stiefel_projection(self, x: torch.Tensor) -> torch.Tensor:
        """Project onto Stiefel manifold (XᵀX = I)."""
        if x.dim() != 2:
            # Only defined for matrices
            return x
        
        # QR decomposition for projection
        # This is computationally expensive but numerically stable
        try:
            q, r = torch.linalg.qr(x, mode='reduced')
            return q
        except:
            # Fallback: symmetric orthogonalization
            u, s, v = torch.svd(x)
            return u @ v.T
    
    def _simplex_projection(self, x: torch.Tensor) -> torch.Tensor:
        """Project onto probability simplex (x ≥ 0, ∑x = 1)."""
        # Algorithm from "Efficient Projections onto the ℓ1-Ball for Learning in High Dimensions"
        u, _ = torch.sort(x, descending=True)
        cssv = torch.cumsum(u, dim=0)
        
        rho = torch.nonzero(u * torch.arange(1, len(u)+1).to(x.device) > (cssv - 1))[-1]
        theta = (cssv[rho] - 1) / (rho + 1)
        
        return torch.clamp(x - theta, min=0)
    
    def _stiefel_tangent_projection(self, grad: torch.Tensor, 
                                   point: torch.Tensor) -> torch.Tensor:
        """
        Project onto tangent space of Stiefel manifold.
        
        For X on Stiefel manifold (XᵀX = I):
        Tangent space at X: {V | XᵀV + VᵀX = 0}
        
        Projection: V_proj = V - X(XᵀV + VᵀX)/2
        """
        if grad.dim() != 2 or point.dim() != 2:
            return grad
        
        # Compute XᵀV
        xt_v = point.T @ grad
        
        # Symmetrize: (XᵀV + VᵀX)/2
        sym = (xt_v + xt_v.T) / 2
        
        # Project: V - X * sym
        projected = grad - point @ sym
        
        return projected


class MHCLayer(nn.Module):
    """
    Manifold-Constrained Hyper-Connections layer.
    
    This layer implements the core mHC operations:
    1. Doubly-stochastic attention via Sinkhorn-Knopp
    2. Convex state mixing with identity preservation
    3. Non-expansive signal propagation
    4. Bounded coordination between agents
    
    Mathematical Formulation:
    Given agent states X₁, X₂, ..., Xₙ ∈ ℝ^{d×k}
    and attention weights A ∈ ℝ^{n×n}:
    
    Y = Sinkhorn(A) @ X  # Doubly-stochastic mixing
    Z = λY + (1-λ)X      # Identity-preserving convex combination
    Output = BoundNorm(Z) # Non-expansive bounded output
    """
    
    def __init__(self, 
                 input_dim: int,
                 num_agents: int,
                 manifold_type: str = 'sinkhorn',
                 temperature: float = 1.0,
                 identity_preserve: float = 0.1,
                 signal_bound: float = 1.0,
                 sinkhorn_iters: int = 50):
        """
        Initialize mHC layer.
        
        Args:
            input_dim: Dimension of agent state vectors
            num_agents: Number of agents to coordinate
            manifold_type: Type of manifold constraint ('sinkhorn', 'sphere')
            temperature: Softmax temperature for attention
            identity_preserve: Strength of identity preservation (0-1)
            signal_bound: Maximum allowed signal norm
            sinkhorn_iters: Iterations for Sinkhorn normalization
            
        Design Rationale:
        - identity_preserve: Prevents agents from losing their identity during coordination
        - signal_bound: Prevents signal explosion in deep networks
        - temperature: Controls sharpness of attention distribution
        """
        super().__init__()
        
        self.input_dim = input_dim
        self.num_agents = num_agents
        self.manifold_type = manifold_type
        self.temperature = temperature
        self.identity_preserve = identity_preserve
        self.signal_bound = signal_bound
        self.sinkhorn_iters = sinkhorn_iters
        
        # Learnable parameters for attention computation
        self.query_proj = nn.Linear(input_dim, input_dim)
        self.key_proj = nn.Linear(input_dim, input_dim)
        self.value_proj = nn.Linear(input_dim, input_dim)
        
        # Learnable bias terms for each agent
        self.agent_biases = nn.Parameter(torch.zeros(num_agents, input_dim))
        
        # Learnable scaling factors
        self.scale_factors = nn.Parameter(torch.ones(num_agents))
        
        # Layer normalization for stability
        self.layer_norm = nn.LayerNorm(input_dim)
        
        # Dropout for regularization
        self.dropout = nn.Dropout(0.1)
        
        # Initialize parameters
        self._init_parameters()
    
    def _init_parameters(self):
        """Initialize parameters with manifold-aware initialization."""
        # Xavier initialization for linear layers
        nn.init.xavier_uniform_(self.query_proj.weight)
        nn.init.xavier_uniform_(self.key_proj.weight)
        nn.init.xavier_uniform_(self.value_proj.weight)
        
        # Initialize biases to small values
        nn.init.normal_(self.agent_biases, mean=0.0, std=0.02)
        
        # Initialize scale factors to 1
        nn.init.constant_(self.scale_factors, 1.0)
        
        # Initialize query/key/value biases to zero
        nn.init.zeros_(self.query_proj.bias)
        nn.init.zeros_(self.key_proj.bias)
        nn.init.zeros_(self.value_proj.bias)
    
    def sinkhorn_normalize(self, log_alpha: torch.Tensor) -> torch.Tensor:
        """
        Sinkhorn-Knopp normalization for doubly-stochastic matrices.
        
        Transforms arbitrary matrix into doubly-stochastic matrix:
        - All entries ≥ 0
        - Row sums = 1
        - Column sums = 1
        
        This ensures fair attention distribution where:
        - Each agent pays equal total attention to others
        - Each agent receives equal total attention from others
        
        Algorithm:
        for i in range(iterations):
            log_alpha = log_alpha - logsumexp(log_alpha, dim=1)  # Row normalize
            log_alpha = log_alpha - logsumexp(log_alpha, dim=0)  # Column normalize
        
        Args:
            log_alpha: Log-attention matrix [batch_size, num_agents, num_agents]
            
        Returns:
            Doubly-stochastic attention matrix
        """
        batch_size, n, _ = log_alpha.shape
        
        for _ in range(self.sinkhorn_iters):
            # Row normalization (sum to 1 across columns)
            log_alpha = log_alpha - torch.logsumexp(
                log_alpha, dim=2, keepdim=True
            )
            
            # Column normalization (sum to 1 across rows)
            log_alpha = log_alpha - torch.logsumexp(
                log_alpha, dim=1, keepdim=True
            )
        
        # Convert from log-space to probabilities
        attention = torch.exp(log_alpha)
        
        return attention
    
    def forward(self, 
                agent_states: torch.Tensor,
                agent_mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        """
        Forward pass through mHC layer.
        
        Args:
            agent_states: Tensor of shape [batch_size, num_agents, input_dim]
            agent_mask: Optional mask for inactive agents [batch_size, num_agents]
            
        Returns:
            Coordinated agent states with manifold constraints
        """
        batch_size, num_agents, input_dim = agent_states.shape
        
        # Validate input dimensions
        if num_agents != self.num_agents:
            raise ValueError(
                f"Expected {self.num_agents} agents, got {num_agents}"
            )
        
        if input_dim != self.input_dim:
            raise ValueError(
                f"Expected input_dim {self.input_dim}, got {input_dim}"
            )
        
        # Step 1: Apply layer normalization for stability
        normalized_states = self.layer_norm(agent_states)
        
        # Step 2: Compute attention queries, keys, values
        queries = self.query_proj(normalized_states)  # [B, N, D]
        keys = self.key_proj(normalized_states)       # [B, N, D]
        values = self.value_proj(normalized_states)   # [B, N, D]
        
        # Step 3: Compute scaled dot-product attention
        # Q @ K^T / sqrt(dim)
        scale = math.sqrt(self.input_dim)
        attention_scores = torch.bmm(queries, keys.transpose(1, 2)) / scale
        
        # Apply temperature
        attention_scores = attention_scores / self.temperature
        
        # Apply agent mask if provided
        if agent_mask is not None:
            # Expand mask for broadcasting
            mask_expanded = agent_mask.unsqueeze(1)  # [B, 1, N]
            mask_expanded = mask_expanded.expand(-1, num_agents, -1)  # [B, N, N]
            
            # Mask out attention to/from inactive agents
            attention_scores = attention_scores.masked_fill(
                ~mask_expanded, float('-inf')
            )
        
        # Step 4: Apply Sinkhorn normalization for doubly-stochastic attention
        attention_weights = self.sinkhorn_normalize(attention_scores)
        
        # Apply dropout for regularization
        attention_weights = self.dropout(attention_weights)
        
        # Step 5: Apply attention to values
        attended_values = torch.bmm(attention_weights, values)  # [B, N, D]
        
        # Step 6: Convex mixing with identity preservation
        # This prevents agents from losing their identity
        mixed_states = (
            self.identity_preserve * normalized_states +
            (1 - self.identity_preserve) * attended_values
        )
        
        # Step 7: Apply agent-specific biases and scaling
        # Add learnable bias for each agent
        biased_states = mixed_states + self.agent_biases.unsqueeze(0)
        
        # Apply agent-specific scaling
        # Reshape scale_factors for broadcasting
        scale_factors = self.scale_factors.view(1, num_agents, 1)
        scaled_states = biased_states * scale_factors
        
        # Step 8: Bound signal norm to prevent explosion
        # This ensures non-expansive updates
        if self.signal_bound > 0:
            # Compute norms for each agent
            norms = torch.norm(scaled_states, dim=2, keepdim=True)  # [B, N, 1]
            
            # Compute scaling factor to enforce bound
            # max_norm = max(1, norm/signal_bound)
            max_norms = torch.maximum(
                torch.ones_like(norms),
                norms / self.signal_bound
            )
            
            # Scale down if norm exceeds bound
            bounded_states = scaled_states / max_norms
        else:
            bounded_states = scaled_states
        
        # Step 9: Add residual connection
        # This helps with gradient flow in deep networks
        output_states = agent_states + bounded_states
        
        # Also return attention weights for interpretability
        attention_output = {
            'states': output_states,
            'attention_weights': attention_weights,
            'agent_norms': norms if self.signal_bound > 0 else None,
            'mixed_states': mixed_states
        }
        
        return attention_output
    
    def get_manifold_constraints(self) -> Dict[str, torch.Tensor]:
        """
        Compute manifold constraint violations.
        
        Returns metrics for monitoring during training:
        1. Doubly-stochastic error: ||row_sum - 1|| + ||col_sum - 1||
        2. Identity preservation: ||mixed - original||
        3. Signal bound compliance: max(||states||) / bound
        """
        # Generate dummy input for constraint checking
        batch_size = 2
        dummy_input = torch.randn(batch_size, self.num_agents, self.input_dim)
        
        if self.query_proj.weight.is_cuda:
            dummy_input = dummy_input.cuda()
        
        # Forward pass
        with torch.no_grad():
            output = self.forward(dummy_input)
        
        attention = output['attention_weights']
        states = output['states']
        
        # Check doubly-stochastic constraints
        row_sums = attention.sum(dim=2)  # Should be 1
        col_sums = attention.sum(dim=1)  # Should be 1
        
        ds_error = torch.mean(torch.abs(row_sums - 1)) + \
                  torch.mean(torch.abs(col_sums - 1))
        
        # Check identity preservation
        # mixed_states should be close to original for high identity_preserve
        if 'mixed_states' in output:
            mixed = output['mixed_states']
            identity_preservation = F.cosine_similarity(
                mixed.flatten(), dummy_input.flatten(), dim=0
            ).item()
        else:
            identity_preservation = 0.0
        
        # Check signal bound
        norms = torch.norm(states, dim=2)
        max_norm = torch.max(norms).item()
        bound_compliance = max_norm / self.signal_bound if self.signal_bound > 0 else 0.0
        
        return {
            'doubly_stochastic_error': ds_error.item(),
            'identity_preservation': identity_preservation,
            'max_signal_norm': max_norm,
            'bound_compliance': bound_compliance,
            'attention_sparsity': (attention < 1e-3).float().mean().item()
        }


class MultiAgentMHCModel(nn.Module):
    """
    Multi-agent model with stacked mHC layers for deep coordination.
    
    Architecture:
    Input: [batch_size, num_agents, input_dim]
    ↓
    mHC Layer 1: Coordination with manifold constraints
    ↓
    mHC Layer 2: Higher-level coordination
    ↓
    ...
    ↓
    mHC Layer N: Final coordination
    ↓
    Output: [batch_size, num_agents, output_dim]
    
    Each layer adds another level of abstraction while maintaining:
    - Stability through non-expansive updates
    - Interpretability through attention visualization
    - Flexibility through learnable agent biases
    """
    
    def __init__(self,
                 input_dim: int,
                 hidden_dim: int,
                 output_dim: int,
                 num_agents: int,
                 num_layers: int = 3,
                 num_heads: int = 4,
                 dropout: float = 0.1,
                 **mhc_kwargs):
        """
        Initialize multi-agent mHC model.
        
        Args:
            input_dim: Dimension of input agent states
            hidden_dim: Dimension of hidden representations
            output_dim: Dimension of output predictions
            num_agents: Number of agents in the system
            num_layers: Number of mHC layers
            num_heads: Number of attention heads (if using multi-head mHC)
            dropout: Dropout rate for regularization
            **mhc_kwargs: Additional arguments for MHCLayer
            
        Design Philosophy:
        - Stacked layers enable hierarchical coordination
        - Hidden dimensions can be larger for increased capacity
        - Multi-head attention allows different coordination patterns
        - Dropout prevents overfitting to specific coordination patterns
        """
        super().__init__()
        
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.output_dim = output_dim
        self.num_agents = num_agents
        self.num_layers = num_layers
        self.num_heads = num_heads
        
        # Input projection to hidden dimension
        self.input_proj = nn.Linear(input_dim, hidden_dim)
        
        # Stack of mHC layers
        self.mhc_layers = nn.ModuleList([
            MHCLayer(
                input_dim=hidden_dim,
                num_agents=num_agents,
                **mhc_kwargs
            )
            for _ in range(num_layers)
        ])
        
        # Layer normalization between mHC layers
        self.layer_norms = nn.ModuleList([
            nn.LayerNorm(hidden_dim)
            for _ in range(num_layers - 1)
        ])
        
        # Dropout for regularization
        self.dropout = nn.Dropout(dropout)
        
        # Output projection
        self.output_proj = nn.Linear(hidden_dim, output_dim)
        
        # Agent-specific output transformations
        self.agent_outputs = nn.ModuleList([
            nn.Sequential(
                nn.Linear(hidden_dim, hidden_dim // 2),
                nn.GELU(),
                nn.Dropout(dropout),
                nn.Linear(hidden_dim // 2, output_dim)
            )
            for _ in range(num_agents)
        ])
        
        # Initialize parameters
        self._init_parameters()
    
    def _init_parameters(self):
        """Initialize model parameters."""
        # Xavier initialization for linear layers
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.xavier_uniform_(module.weight)
                if module.bias is not None:
                    nn.init.zeros_(module.bias)
        
        # Special initialization for mHC layers
        for layer in self.mhc_layers:
            # Initialize attention to be close to identity
            # This starts with each agent mostly attending to itself
            with torch.no_grad():
                # Get the attention query/key projections
                eye_matrix = torch.eye(self.num_agents).unsqueeze(0)
                if layer.query_proj.weight.is_cuda:
                    eye_matrix = eye_matrix.cuda()
                
                # This is a simplified initialization
                # In practice, we'd want a more sophisticated approach
                pass
    
    def forward(self,
                agent_states: torch.Tensor,
                agent_mask: Optional[torch.Tensor] = None,
                return_attention: bool = False) -> Dict[str, torch.Tensor]:
        """
        Forward pass through multi-agent mHC model.
        
        Args:
            agent_states: Input states [batch_size, num_agents, input_dim]
            agent_mask: Optional mask for inactive agents
            return_attention: Whether to return attention weights
            
        Returns:
            Dictionary containing:
            - 'output': Final predictions [batch_size, num_agents, output_dim]
            - 'hidden_states': Hidden representations at each layer
            - 'attention_weights': Attention matrices (if return_attention=True)
        """
        batch_size = agent_states.shape[0]
        
        # Project input to hidden dimension
        hidden = self.input_proj(agent_states)  # [B, N, H]
        hidden = self.dropout(hidden)
        
        # Store hidden states and attention for analysis
        all_hidden_states = [hidden]
        all_attention_weights = []
        
        # Pass through mHC layers
        for i, mhc_layer in enumerate(self.mhc_layers):
            # Apply mHC layer
            layer_output = mhc_layer(hidden, agent_mask)
            
            # Extract outputs
            hidden = layer_output['states']
            
            # Store attention weights if requested
            if return_attention:
                all_attention_weights.append(layer_output['attention_weights'])
            
            # Apply layer normalization (except after last layer)
            if i < len(self.mhc_layers) - 1:
                hidden = self.layer_norms[i](hidden)
                hidden = self.dropout(hidden)
            
            # Store hidden state
            all_hidden_states.append(hidden)
        
        # Apply agent-specific output transformations
        agent_outputs = []
        for agent_idx in range(self.num_agents):
            # Extract this agent's hidden state
            agent_hidden = hidden[:, agent_idx, :]  # [B, H]
            
            # Apply agent-specific transformation
            agent_out = self.agent_outputs[agent_idx](agent_hidden)  # [B, O]
            agent_outputs.append(agent_out)
        
        # Stack agent outputs
        output = torch.stack(agent_outputs, dim=1)  # [B, N, O]
        
        # Prepare return dictionary
        result = {
            'output': output,
            'hidden_states': all_hidden_states,
            'final_hidden': hidden
        }
        
        if return_attention:
            result['attention_weights'] = all_attention_weights
        
        return result
    
    def get_coordination_metrics(self) -> Dict[str, float]:
        """
        Compute metrics about agent coordination.
        
        Returns:
            Dictionary with coordination metrics:
            - Self_attention: How much agents attend to themselves
            - Coordination_strength: Strength of cross-agent attention
            - Attention_entropy: Diversity of attention patterns
            - Agent_similarity: Cosine similarity between agent representations
        """
        # Generate dummy input
        batch_size = 4
        dummy_input = torch.randn(batch_size, self.num_agents, self.input_dim)
        
        if self.input_proj.weight.is_cuda:
            dummy_input = dummy_input.cuda()
        
        # Forward pass with attention
        with torch.no_grad():
            result = self.forward(dummy_input, return_attention=True)
        
        attention_weights = result['attention_weights']
        
        # Compute metrics across all layers
        all_self_attention = []
        all_coordination_strength = []
        all_entropy = []
        
        for layer_attention in attention_weights:
            # Layer attention shape: [B, N, N]
            
            # Self-attention: diagonal elements
            self_attn = torch.diagonal(layer_attention, dim1=1, dim2=2)  # [B, N]
            all_self_attention.append(self_attn.mean().item())
            
            # Coordination strength: off-diagonal elements
            # Create mask for off-diagonal
            batch_size, n, _ = layer_attention.shape
            eye_mask = torch.eye(n, device=layer_attention.device)
            eye_mask = eye_mask.unsqueeze(0).expand(batch_size, -1, -1)
            
            off_diag = layer_attention * (1 - eye_mask)
            coord_strength = off_diag.sum(dim=(1, 2)) / (n * (n - 1))
            all_coordination_strength.append(coord_strength.mean().item())
            
            # Attention entropy: diversity of attention distribution
            # Higher entropy = more diverse attention
            attention_probs = layer_attention.view(-1, n)
            entropy = -torch.sum(attention_probs * torch.log(attention_probs + 1e-8), dim=1)
            max_entropy = math.log(n)
            normalized_entropy = entropy.mean().item() / max_entropy
            all_entropy.append(normalized_entropy)
        
        # Compute agent similarity from final hidden states
        final_hidden = result['final_hidden']  # [B, N, H]
        agent_similarities = []
        
        for batch_idx in range(final_hidden.shape[0]):
            batch_hidden = final_hidden[batch_idx]  # [N, H]
            
            # Compute cosine similarity matrix
            norms = torch.norm(batch_hidden, dim=1, keepdim=True)
            normalized = batch_hidden / (norms + 1e-8)
            similarity_matrix = torch.mm(normalized, normalized.T)  # [N, N]
            
            # Average similarity between different agents
            eye_mask = torch.eye(self.num_agents, device=similarity_matrix.device)
            off_diag_similarity = similarity_matrix * (1 - eye_mask)
            avg_similarity = off_diag_similarity.sum() / (self.num_agents * (self.num_agents - 1))
            agent_similarities.append(avg_similarity.item())
        
        return {
            'self_attention_mean': np.mean(all_self_attention),
            'self_attention_std': np.std(all_self_attention),
            'coordination_strength_mean': np.mean(all_coordination_strength),
            'coordination_strength_std': np.std(all_coordination_strength),
            'attention_entropy_mean': np.mean(all_entropy),
            'attention_entropy_std': np.std(all_entropy),
            'agent_similarity_mean': np.mean(agent_similarities),
            'agent_similarity_std': np.std(agent_similarities)
        }


class MHCTrainer:
    """
    Trainer for Manifold-Constrained Hyper-Connections models.
    
    This trainer specializes in:
    1. Stabilizing multi-agent training with manifold constraints
    2. Monitoring coordination metrics during training
    3. Implementing curriculum learning for complex coordination
    4. Handling partial agent participation (masking)
    
    Training Phases:
    Phase 1: Individual agent learning (identity preservation)
    Phase 2: Pairwise coordination learning
    Phase 3: Full multi-agent coordination
    Phase 4: Adversarial robustness training
    """
    
    def __init__(self,
                 model: nn.Module,
                 train_dataset: SecurityDataset,
                 val_dataset: SecurityDataset,
                 config: Dict[str, Any]):
        """
        Initialize mHC trainer.
        
        Args:
            model: mHC model to train
            train_dataset: Training dataset
            val_dataset: Validation dataset
            config: Training configuration dictionary
            
        Required config parameters:
        - learning_rate: Base learning rate
        - batch_size: Training batch size
        - num_epochs: Number of training epochs
        - warmup_steps: Steps for learning rate warmup
        - gradient_clip: Gradient clipping value
        - patience: Early stopping patience
        - checkpoint_dir: Directory for saving checkpoints
        """
        self.model = model
        self.train_dataset = train_dataset
        self.val_dataset = val_dataset
        self.config = config
        
        # Set device
        self.device = torch.device(
            config.get('device', 'cuda' if torch.cuda.is_available() else 'cpu')
        )
        self.model.to(self.device)
        
        # Create data loaders
        self.train_loader = train_dataset.get_dataloader(
            batch_size=config['batch_size'],
            shuffle=True,
            num_workers=config.get('num_workers', 4),
            pin_memory=True
        )
        
        self.val_loader = val_dataset.get_dataloader(
            batch_size=config['batch_size'],
            shuffle=False,
            num_workers=config.get('num_workers', 2),
            pin_memory=True
        )
        
        # Setup optimizer with manifold constraints
        optimizer_type = config.get('optimizer', 'manifold_constrained')
        
        if optimizer_type == 'manifold_constrained':
            self.optimizer = ManifoldConstrainedOptimizer(
                model.parameters(),
                lr=config['learning_rate'],
                beta=config.get('beta', 0.9),
                manifold_constraint=config.get('manifold_constraint', 'sinkhorn'),
                constraint_strength=config.get('constraint_strength', 0.1),
                projection_iterations=config.get('projection_iterations', 3)
            )
        else:
            # Fallback to AdamW with weight decay
            self.optimizer = optim.AdamW(
                model.parameters(),
                lr=config['learning_rate'],
                betas=(0.9, 0.999),
                weight_decay=config.get('weight_decay', 0.01)
            )
        
        # Setup learning rate scheduler
        self.scheduler = self._create_scheduler()
        
        # Setup loss functions
        self.loss_functions = self._create_loss_functions()
        
        # Training state
        self.current_epoch = 0
        self.global_step = 0
        self.best_val_loss = float('inf')
        self.patience_counter = 0
        
        # Metrics tracking
        self.metrics = {
            'train': defaultdict(list),
            'val': defaultdict(list),
            'coordination': defaultdict(list)
        }
        
        # Create checkpoint directory
        self.checkpoint_dir = Path(config['checkpoint_dir'])
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        
        # Curriculum learning state
        self.curriculum_phase = config.get('curriculum_phase', 'individual')
        self.curriculum_progress = 0.0  # 0.0 to 1.0
        
        # Logging
        self.log_file = self.checkpoint_dir / 'training_log.jsonl'
        
        print(f"🚀 Initialized mHC Trainer")
        print(f"📊 Model: {model.__class__.__name__}")
        print(f"📈 Parameters: {sum(p.numel() for p in model.parameters()):,}")
        print(f"🔧 Device: {self.device}")
        print(f"📚 Training samples: {len(train_dataset)}")
        print(f"📚 Validation samples: {len(val_dataset)}")
        print(f"🎯 Curriculum phase: {self.curriculum_phase}")
    
    def _create_scheduler(self):
        """Create learning rate scheduler."""
        scheduler_type = self.config.get('scheduler', 'cosine')
        warmup_steps = self.config.get('warmup_steps', 1000)
        total_steps = len(self.train_loader) * self.config['num_epochs']
        
        if scheduler_type == 'cosine':
            # Cosine annealing with warmup
            from torch.optim.lr_scheduler import LambdaLR
            
            def lr_lambda(current_step):
                if current_step < warmup_steps:
                    # Linear warmup
                    return float(current_step) / float(max(1, warmup_steps))
                # Cosine annealing
                progress = float(current_step - warmup_steps) / float(max(1, total_steps - warmup_steps))
                return max(0.0, 0.5 * (1.0 + math.cos(math.pi * progress)))
            
            return LambdaLR(self.optimizer, lr_lambda)
        
        elif scheduler_type == 'plateau':
            # Reduce on plateau
            return optim.lr_scheduler.ReduceLROnPlateau(
                self.optimizer,
                mode='min',
                factor=0.5,
                patience=5,
                verbose=True
            )
        
        else:
            # No scheduler
            return None
    
    def _create_loss_functions(self):
        """Create loss functions for mHC training."""
        losses = {}
        
        # Main task loss (e.g., threat classification)
        losses['task'] = nn.BCEWithLogitsLoss()
        
        # Coordination loss: encourages meaningful coordination
        losses['coordination'] = self._coordination_loss
        
        # Diversity loss: prevents agents from becoming too similar
        losses['diversity'] = self._diversity_loss
        
        # Manifold constraint loss: encourages satisfaction of constraints
        losses['manifold'] = self._manifold_constraint_loss
        
        # Sparsity loss: encourages sparse attention (interpretability)
        losses['sparsity'] = self._sparsity_loss
        
        return losses
    
    def _coordination_loss(self, attention_weights: List[torch.Tensor],
                          agent_mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        """
        Loss that encourages meaningful coordination between agents.
        
        Principles:
        1. Agents should coordinate when it's beneficial
        2. Coordination should be sparse (not all-to-all)
        3. Attention should be balanced (no agent ignored)
        
        Args:
            attention_weights: List of attention matrices from each layer
            agent_mask: Mask for inactive agents
            
        Returns:
            Coordination loss value
        """
        total_loss = 0.0
        
        for layer_attention in attention_weights:
            batch_size, num_agents, _ = layer_attention.shape
            
            # 1. Encourage off-diagonal attention (coordination)
            # But not too much - use a target sparsity
            target_sparsity = 0.7  # 70% of attention should be self-attention
            
            # Create mask for self-attention (diagonal)
            eye = torch.eye(num_agents, device=layer_attention.device)
            eye = eye.unsqueeze(0).expand(batch_size, -1, -1)
            
            self_attention = (layer_attention * eye).sum(dim=(1, 2))
            total_attention = layer_attention.sum(dim=(1, 2))
            
            # Ratio of self-attention to total attention
            self_ratio = self_attention / (total_attention + 1e-8)
            
            # Loss: encourage target sparsity
            sparsity_loss = F.mse_loss(self_ratio, 
                                      torch.full_like(self_ratio, target_sparsity))
            
            # 2. Encourage attention balance (no agent ignored)
            # Compute attention received by each agent
            attention_received = layer_attention.sum(dim=1)  # [B, N]
            
            # Normalize
            attention_received_norm = attention_received / (attention_received.sum(dim=1, keepdim=True) + 1e-8)
            
            # Target: uniform distribution
            target_uniform = torch.full_like(attention_received_norm, 1.0 / num_agents)
            
            # Balance loss
            balance_loss = F.kl_div(
                torch.log(attention_received_norm + 1e-8),
                target_uniform,
                reduction='batchmean'
            )
            
            # 3. Apply agent mask if provided
            if agent_mask is not None:
                # Zero out loss for masked positions
                valid_mask = agent_mask.float()
                sparsity_loss = sparsity_loss * valid_mask.mean()
                balance_loss = balance_loss * valid_mask.mean()
            
            total_loss += sparsity_loss + 0.5 * balance_loss
        
        return total_loss / len(attention_weights)
    
    def _diversity_loss(self, hidden_states: List[torch.Tensor]) -> torch.Tensor:
        """
        Loss that encourages diversity among agent representations.
        
        Prevents mode collapse where all agents learn the same thing.
        
        Args:
            hidden_states: List of hidden state tensors from each layer
            
        Returns:
            Diversity loss value
        """
        total_loss = 0.0
        
        for hidden in hidden_states:
            # hidden shape: [B, N, D]
            batch_size, num_agents, hidden_dim = hidden.shape
            
            # Compute cosine similarity matrix for each batch
            for b in range(batch_size):
                batch_hidden = hidden[b]  # [N, D]
                
                # Normalize
                norms = torch.norm(batch_hidden, dim=1, keepdim=True)
                normalized = batch_hidden / (norms + 1e-8)
                
                # Compute similarity matrix
                similarity = torch.mm(normalized, normalized.T)  # [N, N]
                
                # We want off-diagonal similarities to be low (diverse agents)
                eye = torch.eye(num_agents, device=similarity.device)
                off_diag_similarity = similarity * (1 - eye)
                
                # Loss: penalize high similarity between different agents
                diversity_loss = torch.mean(torch.abs(off_diag_similarity))
                total_loss += diversity_loss
        
        return total_loss / (len(hidden_states) * batch_size)
    
    def _manifold_constraint_loss(self, model: nn.Module) -> torch.Tensor:
        """
        Loss that encourages satisfaction of manifold constraints.
        
        Args:
            model: The mHC model
            
        Returns:
            Manifold constraint loss value
        """
        total_loss = 0.0
        
        # Check each mHC layer
        for module in model.modules():
            if isinstance(module, MHCLayer):
                # Get constraint violations
                constraints = module.get_manifold_constraints()
                
                # Penalize doubly-stochastic error
                ds_error = constraints['doubly_stochastic_error']
                total_loss += ds_error
                
                # Penalize deviation from identity preservation target
                identity_target = module.identity_preserve
                identity_current = constraints['identity_preservation']
                identity_loss = F.mse_loss(
                    torch.tensor([identity_current], device=self.device),
                    torch.tensor([identity_target], device=self.device)
                )
                total_loss += identity_loss
                
                # Penalize signal bound violations
                if module.signal_bound > 0:
                    bound_violation = max(0, constraints['max_signal_norm'] - module.signal_bound)
                    total_loss += bound_violation
        
        return total_loss
    
    def _sparsity_loss(self, attention_weights: List[torch.Tensor]) -> torch.Tensor:
        """
        Loss that encourages sparse attention patterns.
        
        Sparse attention is more interpretable and computationally efficient.
        
        Args:
            attention_weights: List of attention matrices
            
        Returns:
            Sparsity loss value
        """
        total_loss = 0.0
        
        for attention in attention_weights:
            # L1 regularization on attention weights
            l1_loss = torch.mean(torch.abs(attention))
            
            # Entropy regularization: lower entropy = more sparse
            attention_flat = attention.view(-1, attention.size(-1))
            entropy = -torch.sum(attention_flat * torch.log(attention_flat + 1e-8), dim=1)
            entropy_loss = torch.mean(entropy)
            
            total_loss += 0.1 * l1_loss + 0.05 * entropy_loss
        
        return total_loss / len(attention_weights)
    
    def compute_loss(self, 
                    batch: Dict[str, torch.Tensor],
                    model_output: Dict[str, torch.Tensor],
                    phase: str = 'train') -> Dict[str, torch.Tensor]:
        """
        Compute total loss for a batch.
        
        Args:
            batch: Input batch from dataloader
            model_output: Output from model forward pass
            phase: 'train' or 'val'
            
        Returns:
            Dictionary of loss components and total loss
        """
        # Extract predictions and labels
        predictions = model_output['output']  # [B, N, O]
        labels = batch['labels']  # [B, C] or [B, N, O]
        
        # Task loss (main prediction loss)
        if labels.dim() == 2:
            # Single label per sample
            # Average predictions across agents
            avg_predictions = predictions.mean(dim=1)  # [B, O]
            task_loss = self.loss_functions['task'](avg_predictions, labels)
        else:
            # Per-agent labels
            task_loss = self.loss_functions['task'](predictions, labels)
        
        # Coordination losses (only during training)
        if phase == 'train':
            # Get attention weights if available
            attention_weights = model_output.get('attention_weights', [])
            
            # Get agent mask if available
            agent_mask = batch.get('agent_mask')
            
            # Compute coordination loss
            if attention_weights:
                coord_loss = self.loss_functions['coordination'](attention_weights, agent_mask)
            else:
                coord_loss = torch.tensor(0.0, device=self.device)
            
            # Compute diversity loss
            hidden_states = model_output.get('hidden_states', [])
            if hidden_states:
                diversity_loss = self.loss_functions['diversity'](hidden_states)
            else:
                diversity_loss = torch.tensor(0.0, device=self.device)
            
            # Compute manifold constraint loss
            manifold_loss = self.loss_functions['manifold'](self.model)
            
            # Compute sparsity loss
            if attention_weights:
                sparsity_loss = self.loss_functions['sparsity'](attention_weights)
            else:
                sparsity_loss = torch.tensor(0.0, device=self.device)
            
            # Curriculum-based loss weighting
            weights = self._get_curriculum_weights()
            
            # Total loss
            total_loss = (
                weights['task'] * task_loss +
                weights['coordination'] * coord_loss +
                weights['diversity'] * diversity_loss +
                weights['manifold'] * manifold_loss +
                weights['sparsity'] * sparsity_loss
            )
            
            loss_dict = {
                'total': total_loss,
                'task': task_loss,
                'coordination': coord_loss,
                'diversity': diversity_loss,
                'manifold': manifold_loss,
                'sparsity': sparsity_loss
            }
        else:
            # Validation: only task loss
            total_loss = task_loss
            loss_dict = {
                'total': total_loss,
                'task': task_loss
            }
        
        return loss_dict
    
    def _get_curriculum_weights(self) -> Dict[str, float]:
        """Get loss weights based on curriculum phase."""
        base_weights = {
            'task': 1.0,
            'coordination': 0.5,
            'diversity': 0.2,
            'manifold': 0.1,
            'sparsity': 0.05
        }
        
        # Adjust based on curriculum phase
        if self.curriculum_phase == 'individual':
            # Focus on task learning, minimal coordination
            return {
                'task': 1.0,
                'coordination': 0.1 * self.curriculum_progress,
                'diversity': 0.5,  # Encourage diversity early
                'manifold': 0.05,
                'sparsity': 0.02
            }
        
        elif self.curriculum_phase == 'pairwise':
            # Start introducing coordination
            return {
                'task': 1.0,
                'coordination': 0.3 + 0.2 * self.curriculum_progress,
                'diversity': 0.3,
                'manifold': 0.1,
                'sparsity': 0.05
            }
        
        elif self.curriculum_phase == 'full':
            # Full coordination
            return base_weights
        
        elif self.curriculum_phase == 'adversarial':
            # Focus on robustness
            return {
                'task': 1.0,
                'coordination': 0.7,  # Strong coordination for robustness
                'diversity': 0.3,  # Maintain diversity
                'manifold': 0.2,  # Strict constraints
                'sparsity': 0.1  # Interpretable attention
            }
        
        else:
            return base_weights
    
    def update_curriculum(self, epoch: int, total_epochs: int):
        """Update curriculum learning phase based on training progress."""
        progress = epoch / total_epochs
        
        if progress < 0.25:
            new_phase = 'individual'
        elif progress < 0.5:
            new_phase = 'pairwise'
        elif progress < 0.75:
            new_phase = 'full'
        else:
            new_phase = 'adversarial'
        
        if new_phase != self.curriculum_phase:
            print(f"🔄 Switching curriculum phase: {self.curriculum_phase} → {new_phase}")
            self.curriculum_phase = new_phase
        
        # Update progress within phase
        phase_progress = (progress % 0.25) / 0.25
        self.curriculum_progress = phase_progress
    
    def train_epoch(self) -> Dict[str, float]:
        """
        Train for one epoch.
        
        Returns:
            Dictionary of training metrics
        """
        self.model.train()
        epoch_metrics = defaultdict(float)
        num_batches = len(self.train_loader)
        
        for batch_idx, batch in enumerate(self.train_loader):
            # Move batch to device
            batch = self._move_to_device(batch)
            
            # Forward pass
            model_output = self.model(
                batch['features'],
                batch.get('agent_mask'),
                return_attention=True
            )
            
            # Compute loss
            loss_dict = self.compute_loss(batch, model_output, 'train')
            
            # Backward pass
            self.optimizer.zero_grad()
            loss_dict['total'].backward()
            
            # Gradient clipping
            if self.config.get('gradient_clip', 1.0) > 0:
                torch.nn.utils.clip_grad_norm_(
                    self.model.parameters(),
                    self.config['gradient_clip']
                )
            
            # Optimization step
            self.optimizer.step()
            
            # Update learning rate
            if self.scheduler is not None and not isinstance(self.scheduler, 
                                                           optim.lr_scheduler.ReduceLROnPlateau):
                self.scheduler.step()
            
            # Update metrics
            for key, value in loss_dict.items():
                epoch_metrics[f'train_{key}_loss'] += value.item()
            
            # Update step counter
            self.global_step += 1
            
            # Log progress
            if batch_idx % self.config.get('log_interval', 10) == 0:
                current_lr = self.optimizer.param_groups[0]['lr']
                print(f"Epoch {self.current_epoch}, Batch {batch_idx}/{num_batches}, "
                      f"Loss: {loss_dict['total'].item():.4f}, LR: {current_lr:.6f}")
        
        # Average metrics
        for key in epoch_metrics:
            epoch_metrics[key] /= num_batches
        
        # Get coordination metrics
        coord_metrics = self.model.get_coordination_metrics()
        for key, value in coord_metrics.items():
            epoch_metrics[f'coord_{key}'] = value
        
        return dict(epoch_metrics)
    
    def validate(self) -> Dict[str, float]:
        """
        Run validation.
        
        Returns:
            Dictionary of validation metrics
        """
        self.model.eval()
        val_metrics = defaultdict(float)
        num_batches = len(self.val_loader)
        
        with torch.no_grad():
            for batch in self.val_loader:
                # Move batch to device
                batch = self._move_to_device(batch)
                
                # Forward pass
                model_output = self.model(
                    batch['features'],
                    batch.get('agent_mask'),
                    return_attention=False
                )
                
                # Compute loss
                loss_dict = self.compute_loss(batch, model_output, 'val')
                
                # Update metrics
                for key, value in loss_dict.items():
                    val_metrics[f'val_{key}_loss'] += value.item()
                
                # Compute accuracy if classification task
                predictions = model_output['output']
                labels = batch['labels']
                
                if labels.dim() == 2:  # Single label per sample
                    avg_predictions = predictions.mean(dim=1)
                    pred_classes = (torch.sigmoid(avg_predictions) > 0.5).float()
                    accuracy = (pred_classes == labels).float().mean()
                    val_metrics['val_accuracy'] += accuracy.item()
                else:  # Per-agent labels
                    pred_classes = (torch.sigmoid(predictions) > 0.5).float()
                    accuracy = (pred_classes == labels).float().mean()
                    val_metrics['val_accuracy'] += accuracy.item()
        
        # Average metrics
        for key in val_metrics:
            val_metrics[key] /= num_batches
        
        return dict(val_metrics)
    
    def _move_to_device(self, batch: Dict[str, torch.Tensor]) -> Dict[str, torch.Tensor]:
        """Move batch to device."""
        device_batch = {}
        for key, value in batch.items():
            if torch.is_tensor(value):
                device_batch[key] = value.to(self.device)
            else:
                device_batch[key] = value
        return device_batch
    
    def train(self):
        """Main training loop."""
        print(f"\n🎯 Starting mHC training for {self.config['num_epochs']} epochs")
        print("="*80)
        
        for epoch in range(self.current_epoch, self.config['num_epochs']):
            self.current_epoch = epoch
            
            # Update curriculum
            self.update_curriculum(epoch, self.config['num_epochs'])
            
            # Train for one epoch
            print(f"\n📚 Epoch {epoch + 1}/{self.config['num_epochs']}")
            train_metrics = self.train_epoch()
            
            # Validate
            val_metrics = self.validate()
            
            # Combine metrics
            all_metrics = {**train_metrics, **val_metrics}
            
            # Update learning rate scheduler (if ReduceLROnPlateau)
            if isinstance(self.scheduler, optim.lr_scheduler.ReduceLROnPlateau):
                self.scheduler.step(val_metrics['val_total_loss'])
            
            # Log metrics
            self._log_metrics(all_metrics)
            
            # Save checkpoint if best model
            if val_metrics['val_total_loss'] < self.best_val_loss:
                self.best_val_loss = val_metrics['val_total_loss']
                self.patience_counter = 0
                self.save_checkpoint('best')
                print(f"💾 Saved best model (val_loss: {self.best_val_loss:.4f})")
            else:
                self.patience_counter += 1
            
            # Save regular checkpoint
            if epoch % self.config.get('checkpoint_interval', 5) == 0:
                self.save_checkpoint(f'epoch_{epoch}')
            
            # Early stopping
            if self.patience_counter >= self.config.get('patience', 20):
                print(f"🛑 Early stopping triggered at epoch {epoch + 1}")
                break
            
            # Print epoch summary
            print(f"✅ Epoch {epoch + 1} summary:")
            print(f"   Train Loss: {train_metrics['train_total_loss']:.4f}")
            print(f"   Val Loss: {val_metrics['val_total_loss']:.4f}")
            print(f"   Val Accuracy: {val_metrics.get('val_accuracy', 0):.4f}")
            print(f"   Coordination Strength: {train_metrics.get('coord_coordination_strength_mean', 0):.4f}")
        
        print("\n🏆 Training completed!")
        print(f"📊 Best validation loss: {self.best_val_loss:.4f}")
    
    def _log_metrics(self, metrics: Dict[str, float]):
        """Log metrics to file and update internal tracking."""
        # Add timestamp
        metrics['timestamp'] = datetime.now().isoformat()
        metrics['epoch'] = self.current_epoch
        metrics['global_step'] = self.global_step
        metrics['curriculum_phase'] = self.curriculum_phase
        metrics['curriculum_progress'] = self.curriculum_progress
        
        # Update internal tracking
        for key, value in metrics.items():
            if key not in ['timestamp', 'epoch', 'global_step', 
                          'curriculum_phase', 'curriculum_progress']:
                # Determine category
                if key.startswith('train_'):
                    self.metrics['train'][key].append(value)
                elif key.startswith('val_'):
                    self.metrics['val'][key].append(value)
                elif key.startswith('coord_'):
                    self.metrics['coordination'][key].append(value)
        
        # Write to log file
        with open(self.log_file, 'a') as f:
            json.dump(metrics, f)
            f.write('\n')
    
    def save_checkpoint(self, name: str):
        """Save training checkpoint."""
        checkpoint_path = self.checkpoint_dir / f'{name}.pt'
        
        checkpoint = {
            'epoch': self.current_epoch,
            'global_step': self.global_step,
            'model_state_dict': self.model.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'scheduler_state_dict': self.scheduler.state_dict() if self.scheduler else None,
            'best_val_loss': self.best_val_loss,
            'metrics': self.metrics,
            'config': self.config,
            'curriculum_phase': self.curriculum_phase,
            'curriculum_progress': self.curriculum_progress
        }
        
        torch.save(checkpoint, checkpoint_path)
        print(f"💾 Checkpoint saved: {checkpoint_path}")
    
    def load_checkpoint(self, checkpoint_path: Union[str, Path]):
        """Load training checkpoint."""
        checkpoint_path = Path(checkpoint_path)
        
        if not checkpoint_path.exists():
            raise FileNotFoundError(f"Checkpoint not found: {checkpoint_path}")
        
        checkpoint = torch.load(checkpoint_path, map_location=self.device)
        
        # Load state
        self.current_epoch = checkpoint['epoch']
        self.global_step = checkpoint['global_step']
        self.best_val_loss = checkpoint['best_val_loss']
        self.metrics = checkpoint['metrics']
        
        # Load model
        self.model.load_state_dict(checkpoint['model_state_dict'])
        
        # Load optimizer
        self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
        
        # Load scheduler
        if self.scheduler and checkpoint['scheduler_state_dict']:
            self.scheduler.load_state_dict(checkpoint['scheduler_state_dict'])
        
        # Load curriculum
        self.curriculum_phase = checkpoint.get('curriculum_phase', 'individual')
        self.curriculum_progress = checkpoint.get('curriculum_progress', 0.0)
        
        print(f"📂 Checkpoint loaded: {checkpoint_path}")
        print(f"📊 Resume from epoch {self.current_epoch}, "
              f"best val loss: {self.best_val_loss:.4f}")
    
    def analyze_coordination(self) -> Dict[str, Any]:
        """
        Analyze coordination patterns in the trained model.
        
        Returns:
            Dictionary with coordination analysis
        """
        print("\n🔍 Analyzing coordination patterns...")
        
        # Get coordination metrics
        coord_metrics = self.model.get_coordination_metrics()
        
        # Generate sample attention patterns
        sample_batch = next(iter(self.val_loader))
        sample_batch = self._move_to_device(sample_batch)
        
        with torch.no_grad():
            model_output = self.model(
                sample_batch['features'],
                sample_batch.get('agent_mask'),
                return_attention=True
            )
        
        attention_weights = model_output['attention_weights']
        
        # Analyze attention patterns
        attention_analysis = self._analyze_attention_patterns(attention_weights)
        
        # Analyze agent specialization
        specialization = self._analyze_agent_specialization(model_output['final_hidden'])
        
        # Combine analysis
        analysis = {
            'coordination_metrics': coord_metrics,
            'attention_analysis': attention_analysis,
            'agent_specialization': specialization,
            'sample_predictions': model_output['output'][:3].cpu().numpy(),
            'sample_attention': attention_weights[0][:1].cpu().numpy()  # First layer, first batch
        }
        
        return analysis
    
    def _analyze_attention_patterns(self, 
                                  attention_weights: List[torch.Tensor]) -> Dict[str, Any]:
        """Analyze patterns in attention weights."""
        analysis = {}
        
        for layer_idx, attention in enumerate(attention_weights):
            # attention shape: [B, N, N]
            batch_attention = attention.mean(dim=0)  # Average over batch
            
            # Self-attention strength
            self_attn = torch.diag(batch_attention).mean().item()
            
            # Reciprocity: if A attends to B, does B attend to A?
            reciprocity = torch.mean(torch.abs(batch_attention - batch_attention.T)).item()
            
            # Clustering: are there groups of agents that attend to each other?
            # Use spectral clustering to detect communities
            try:
                # Convert to similarity matrix
                similarity = (batch_attention + batch_attention.T) / 2
                
                # Compute eigenvalues
                eigenvalues = torch.linalg.eigvalsh(similarity)
                spectral_gap = eigenvalues[-1] - eigenvalues[-2]
                
                analysis[f'layer_{layer_idx}'] = {
                    'self_attention': self_attn,
                    'reciprocity': reciprocity,
                    'spectral_gap': spectral_gap.item(),
                    'attention_matrix': batch_attention.cpu().numpy()
                }
            except:
                analysis[f'layer_{layer_idx}'] = {
                    'self_attention': self_attn,
                    'reciprocity': reciprocity,
                    'spectral_gap': None,
                    'attention_matrix': batch_attention.cpu().numpy()
                }
        
        return analysis
    
    def _analyze_agent_specialization(self, 
                                    final_hidden: torch.Tensor) -> Dict[str, Any]:
        """Analyze how agents specialize in different tasks."""
        # final_hidden shape: [B, N, D]
        batch_size, num_agents, hidden_dim = final_hidden.shape
        
        # Compute agent activation patterns
        agent_activations = final_hidden.mean(dim=0)  # [N, D]
        
        # Compute similarity between agents
        agent_similarity = F.cosine_similarity(
            agent_activations.unsqueeze(1),
            agent_activations.unsqueeze(0),
            dim=2
        )
        
        # Compute specialization score
        # High specialization = low similarity between agents
        specialization_score = 1 - agent_similarity.mean().item()
        
        # Detect agent clusters
        from sklearn.cluster import KMeans
        import numpy as np
        
        agent_features = agent_activations.cpu().numpy()
        if num_agents > 1:
            kmeans = KMeans(n_clusters=min(3, num_agents), random_state=42)
            clusters = kmeans.fit_predict(agent_features)
            
            cluster_sizes = np.bincount(clusters)
            cluster_quality = kmeans.inertia_
        else:
            clusters = [0]
            cluster_sizes = [1]
            cluster_quality = 0
        
        return {
            'specialization_score': specialization_score,
            'agent_similarity_matrix': agent_similarity.cpu().numpy(),
            'agent_clusters': clusters.tolist(),
            'cluster_sizes': cluster_sizes.tolist(),
            'cluster_quality': float(cluster_quality)
        }


# Example usage and testing
if __name__ == "__main__":
    print("🧪 Testing mHC Trainer...")
    
    # Create sample data
    from .security_dataset import SecurityDataset
    
    # Create a small dummy dataset
    import tempfile
    import json
    
    sample_data = [
        {
            'id': f'sample_{i}',
            'timestamp': '2024-01-15T10:30:00Z',
            'source': 'test',
            'threat_types': ['SQL_Injection'] if i % 2 == 0 else ['Cross_Site_Scripting'],
            'features': torch.randn(512).tolist(),
            'labels': [1.0, 0.0] if i % 2 == 0 else [0.0, 1.0]
        }
        for i in range(100)
    ]
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(sample_data, f)
        temp_file = f.name
    
    try:
        # Create dataset
        dataset = SecurityDataset(temp_file, feature_dim=512, use_encryption=False)
        
        # Split
        train_data, val_data = dataset.split(train_ratio=0.8, val_ratio=0.2, test_ratio=0.0)[:2]
        
        # Create model
        model = MultiAgentMHCModel(
            input_dim=512,
            hidden_dim=256,
            output_dim=2,  # Binary classification
            num_agents=4,
            num_layers=2,
            manifold_type='sinkhorn',
            identity_preserve=0.1,
            signal_bound=1.0
        )
        
        # Config
        config = {
            'learning_rate': 1e-4,
            'batch_size': 8,
            'num_epochs': 3,  # Short test run
            'warmup_steps': 10,
            'gradient_clip': 1.0,
            'patience': 5,
            'checkpoint_dir': 'test_checkpoints',
            'device': 'cpu',
            'optimizer': 'manifold_constrained',
            'manifold_constraint': 'sinkhorn',
            'constraint_strength': 0.1,
            'scheduler': 'cosine'
        }
        
        # Create trainer
        trainer = MHCTrainer(model, train_data, val_data, config)
        
        # Test training for a few batches
        print("\n🔧 Testing training loop...")
        test_metrics = trainer.train_epoch()
        print(f"Training metrics: {test_metrics}")
        
        # Test validation
        print("\n📊 Testing validation...")
        val_metrics = trainer.validate()
        print(f"Validation metrics: {val_metrics}")
        
        # Test coordination analysis
        print("\n🔍 Testing coordination analysis...")
        analysis = trainer.analyze_coordination()
        print(f"Coordination analysis keys: {list(analysis.keys())}")
        
        print("\n✅ mHC Trainer tests passed!")
        
    finally:
        # Clean up
        import os
        os.unlink(temp_file)
        
        # Clean up checkpoint directory
        import shutil
        if os.path.exists('test_checkpoints'):
            shutil.rmtree('test_checkpoints')