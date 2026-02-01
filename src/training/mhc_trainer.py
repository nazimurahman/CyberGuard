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
from torch.utils.data import DataLoader, Dataset
from typing import Dict, List, Tuple, Optional, Union, Any, Callable
import numpy as np
import math
from datetime import datetime
import warnings
from pathlib import Path
import json
from collections import defaultdict, deque
import random

# Removed circular import and created a minimal Dataset class for the example
class SecurityDataset(Dataset):
    """
    Minimal dataset class to replace the original import.
    In practice, this would be the actual SecurityDataset implementation.
    """
    def __init__(self, data_file: str, feature_dim: int = 512, use_encryption: bool = False):
        # Initialize with sample data for testing
        self.features = []
        self.labels = []
        self.num_agents = 4  # Default number of agents
        self.feature_dim = feature_dim
        
        # Generate dummy data for testing
        for i in range(100):
            # Create features for multiple agents
            agent_features = torch.randn(self.num_agents, feature_dim)
            self.features.append(agent_features)
            
            # Create labels (binary classification)
            label = torch.tensor([1.0, 0.0] if i % 2 == 0 else [0.0, 1.0])
            self.labels.append(label)
    
    def __len__(self) -> int:
        return len(self.features)
    
    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        return {
            'features': self.features[idx],
            'labels': self.labels[idx],
            'agent_mask': torch.ones(self.num_agents, dtype=torch.bool)  # Default all agents active
        }
    
    def get_dataloader(self, 
                      batch_size: int = 32, 
                      shuffle: bool = True, 
                      num_workers: int = 0,
                      pin_memory: bool = False) -> DataLoader:
        """
        Create a DataLoader for this dataset.
        """
        return DataLoader(
            self,
            batch_size=batch_size,
            shuffle=shuffle,
            num_workers=num_workers,
            pin_memory=pin_memory,
            collate_fn=self._collate_fn
        )
    
    def _collate_fn(self, batch: List[Dict[str, torch.Tensor]]) -> Dict[str, torch.Tensor]:
        """
        Custom collate function to handle the dataset structure.
        """
        collated = {}
        for key in batch[0].keys():
            if key == 'agent_mask':
                # Stack boolean masks
                collated[key] = torch.stack([item[key] for item in batch])
            else:
                # Stack tensors
                collated[key] = torch.stack([item[key] for item in batch])
        return collated
    
    def split(self, train_ratio: float = 0.8, val_ratio: float = 0.1, test_ratio: float = 0.1):
        """
        Split the dataset into train, validation, and test sets.
        Returns tuple of (train_dataset, val_dataset, test_dataset).
        """
        # Simple random split for testing
        indices = list(range(len(self)))
        random.shuffle(indices)
        
        train_size = int(len(self) * train_ratio)
        val_size = int(len(self) * val_ratio)
        
        train_indices = indices[:train_size]
        val_indices = indices[train_size:train_size + val_size]
        test_indices = indices[train_size + val_size:]
        
        # Create subset datasets
        train_dataset = self._create_subset(train_indices)
        val_dataset = self._create_subset(val_indices)
        test_dataset = self._create_subset(test_indices)
        
        return train_dataset, val_dataset, test_dataset
    
    def _create_subset(self, indices: List[int]) -> 'SecurityDataset':
        """
        Create a subset of the dataset.
        """
        subset = SecurityDataset.__new__(SecurityDataset)
        subset.features = [self.features[i] for i in indices]
        subset.labels = [self.labels[i] for i in indices]
        subset.num_agents = self.num_agents
        subset.feature_dim = self.feature_dim
        return subset


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
        """
        loss = None
        if closure is not None:
            with torch.enable_grad():
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
                
                # Apply momentum
                momentum = state['momentum']
                momentum.mul_(beta).add_(grad, alpha=1 - beta)
                
                # Project gradient onto tangent space
                tangent_grad = self._project_to_tangent_space(
                    momentum, p.data, constraint_type
                )
                
                # Apply constrained update
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
        """
        if constraint_type == 'sinkhorn':
            # For doubly-stochastic matrices
            return self._sinkhorn_tangent_projection(grad, point)
        
        elif constraint_type == 'sphere':
            # For unit sphere: ||x|| = 1
            # Tangent space: vectors orthogonal to x
            if point.dim() == 1:
                dot_product = torch.dot(point, grad)
                return grad - dot_product * point
            else:
                # Handle multi-dimensional case
                dot_product = torch.sum(point * grad, dim=-1, keepdim=True)
                return grad - dot_product * point
        
        elif constraint_type == 'stiefel':
            # For Stiefel manifold: XᵀX = I
            return self._stiefel_tangent_projection(grad, point)
        
        else:
            # Default: no projection
            return grad
    
    def _sinkhorn_tangent_projection(self, grad: torch.Tensor, 
                                    point: torch.Tensor) -> torch.Tensor:
        """
        Project onto tangent space of doubly-stochastic matrices.
        """
        if grad.dim() != 2:
            # Only applicable to 2D matrices
            return grad
        
        # Compute row and column sums
        row_sums = grad.sum(dim=1, keepdim=True)
        col_sums = grad.sum(dim=0, keepdim=True)
        
        # Project onto space with zero row/column sums
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
        """
        if x.dim() != 2:
            # Reshape if needed
            original_shape = x.shape
            if x.dim() > 2:
                x = x.reshape(-1, x.shape[-1])
            
            x_proj = x.clone()
            for _ in range(iterations):
                # Row normalization
                row_sum = x_proj.sum(dim=1, keepdim=True) + epsilon
                x_proj = x_proj / row_sum
                
                # Column normalization
                col_sum = x_proj.sum(dim=0, keepdim=True) + epsilon
                x_proj = x_proj / col_sum
            
            # Reshape back
            if len(original_shape) > 2:
                x_proj = x_proj.reshape(original_shape)
            return x_proj
        else:
            # Original 2D case
            x_proj = x.clone()
            for _ in range(iterations):
                row_sum = x_proj.sum(dim=1, keepdim=True) + epsilon
                x_proj = x_proj / row_sum
                
                col_sum = x_proj.sum(dim=0, keepdim=True) + epsilon
                x_proj = x_proj / col_sum
            return x_proj
    
    def _sphere_projection(self, x: torch.Tensor) -> torch.Tensor:
        """Project onto unit sphere (||x|| = 1)."""
        # Handle different dimensionalities
        if x.dim() == 1:
            norm = x.norm(p=2) + 1e-8
            return x / norm
        else:
            norm = x.norm(p=2, dim=-1, keepdim=True) + 1e-8
            return x / norm
    
    def _stiefel_projection(self, x: torch.Tensor) -> torch.Tensor:
        """Project onto Stiefel manifold (XᵀX = I)."""
        if x.dim() != 2:
            # Only defined for matrices
            return x
        
        # QR decomposition for projection
        try:
            q, r = torch.linalg.qr(x, mode='reduced')
            return q
        except:
            # Fallback: symmetric orthogonalization
            u, s, v = torch.svd(x)
            return u @ v.T
    
    def _simplex_projection(self, x: torch.Tensor) -> torch.Tensor:
        """Project onto probability simplex (x ≥ 0, ∑x = 1)."""
        # Ensure we're working with 1D vectors
        if x.dim() > 1:
            # Flatten and project each row
            original_shape = x.shape
            x_flat = x.view(-1, original_shape[-1])
            results = []
            for i in range(x_flat.shape[0]):
                results.append(self._simplex_projection_1d(x_flat[i]))
            result = torch.stack(results, dim=0)
            return result.view(original_shape)
        else:
            return self._simplex_projection_1d(x)
    
    def _simplex_projection_1d(self, x: torch.Tensor) -> torch.Tensor:
        """Project 1D tensor onto probability simplex."""
        # Algorithm from "Efficient Projections onto the ℓ1-Ball for Learning in High Dimensions"
        u, indices = torch.sort(x, descending=True)
        cssv = torch.cumsum(u, dim=0)
        
        # Find rho
        rho_candidates = (u * torch.arange(1, len(u) + 1).to(x.device) > (cssv - 1))
        rho = torch.nonzero(rho_candidates, as_tuple=True)[0]
        if len(rho) == 0:
            rho = torch.tensor(len(u) - 1, device=x.device)
        else:
            rho = rho[-1]
        
        theta = (cssv[rho] - 1) / (rho.item() + 1)
        
        return torch.clamp(x - theta, min=0)
    
    def _stiefel_tangent_projection(self, grad: torch.Tensor, 
                                   point: torch.Tensor) -> torch.Tensor:
        """
        Project onto tangent space of Stiefel manifold.
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
        """
        batch_size, n, _ = log_alpha.shape
        
        # Work in log space for numerical stability
        log_alpha_normalized = log_alpha.clone()
        
        for _ in range(self.sinkhorn_iters):
            # Row normalization (sum to 1 across columns)
            log_alpha_normalized = log_alpha_normalized - torch.logsumexp(
                log_alpha_normalized, dim=2, keepdim=True
            )
            
            # Column normalization (sum to 1 across rows)
            log_alpha_normalized = log_alpha_normalized - torch.logsumexp(
                log_alpha_normalized, dim=1, keepdim=True
            )
        
        # Convert from log-space to probabilities
        attention = torch.exp(log_alpha_normalized)
        
        return attention
    
    def forward(self, 
                agent_states: torch.Tensor,
                agent_mask: Optional[torch.Tensor] = None) -> Dict[str, torch.Tensor]:
        """
        Forward pass through mHC layer.
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
        
        # Apply layer normalization for stability
        normalized_states = self.layer_norm(agent_states)
        
        # Compute attention queries, keys, values
        queries = self.query_proj(normalized_states)
        keys = self.key_proj(normalized_states)
        values = self.value_proj(normalized_states)
        
        # Compute scaled dot-product attention
        scale = math.sqrt(self.input_dim)
        attention_scores = torch.bmm(queries, keys.transpose(1, 2)) / scale
        
        # Apply temperature
        attention_scores = attention_scores / self.temperature
        
        # Apply agent mask if provided
        if agent_mask is not None:
            # Expand mask for broadcasting
            mask_expanded = agent_mask.unsqueeze(1)
            mask_expanded = mask_expanded.expand(-1, num_agents, -1)
            
            # Mask out attention to/from inactive agents
            attention_scores = attention_scores.masked_fill(
                ~mask_expanded, float('-inf')
            )
        
        # Apply Sinkhorn normalization for doubly-stochastic attention
        attention_weights = self.sinkhorn_normalize(attention_scores)
        
        # Apply dropout for regularization
        attention_weights = self.dropout(attention_weights)
        
        # Apply attention to values
        attended_values = torch.bmm(attention_weights, values)
        
        # Convex mixing with identity preservation
        mixed_states = (
            self.identity_preserve * normalized_states +
            (1 - self.identity_preserve) * attended_values
        )
        
        # Apply agent-specific biases and scaling
        biased_states = mixed_states + self.agent_biases.unsqueeze(0)
        
        # Apply agent-specific scaling
        scale_factors = self.scale_factors.view(1, num_agents, 1)
        scaled_states = biased_states * scale_factors
        
        # Initialize norms variable for output
        norms = None
        
        # Bound signal norm to prevent explosion
        if self.signal_bound > 0:
            # Compute norms for each agent
            norms = torch.norm(scaled_states, dim=2, keepdim=True)
            
            # Compute scaling factor to enforce bound
            max_norms = torch.maximum(
                torch.ones_like(norms),
                norms / self.signal_bound
            )
            
            # Scale down if norm exceeds bound
            bounded_states = scaled_states / max_norms
        else:
            bounded_states = scaled_states
        
        # Add residual connection
        output_states = agent_states + bounded_states
        
        # Return attention weights and other outputs
        attention_output = {
            'states': output_states,
            'attention_weights': attention_weights,
            'agent_norms': norms,
            'mixed_states': mixed_states
        }
        
        return attention_output
    
    def get_manifold_constraints(self) -> Dict[str, float]:
        """
        Compute manifold constraint violations.
        """
        # Generate dummy input for constraint checking
        batch_size = 2
        dummy_input = torch.randn(batch_size, self.num_agents, self.input_dim)
        
        # Move to same device as parameters
        device = next(self.parameters()).device
        dummy_input = dummy_input.to(device)
        
        # Forward pass
        with torch.no_grad():
            output = self.forward(dummy_input)
        
        attention = output['attention_weights']
        
        # Check doubly-stochastic constraints
        row_sums = attention.sum(dim=2)
        col_sums = attention.sum(dim=1)
        
        ds_error = torch.mean(torch.abs(row_sums - 1)).item() + \
                  torch.mean(torch.abs(col_sums - 1)).item()
        
        # Check identity preservation
        mixed = output['mixed_states']
        # Flatten tensors for cosine similarity calculation
        mixed_flat = mixed.reshape(-1)
        input_flat = dummy_input.reshape(-1)
        identity_preservation = F.cosine_similarity(
            mixed_flat.unsqueeze(0), input_flat.unsqueeze(0), dim=1
        ).item()
        
        # Check signal bound
        states = output['states']
        norms = torch.norm(states, dim=2)
        max_norm = torch.max(norms).item()
        bound_compliance = max_norm / self.signal_bound if self.signal_bound > 0 else 0.0
        
        return {
            'doubly_stochastic_error': float(ds_error),
            'identity_preservation': float(identity_preservation),
            'max_signal_norm': float(max_norm),
            'bound_compliance': float(bound_compliance),
            'attention_sparsity': float((attention < 1e-3).float().mean().item())
        }


class MultiAgentMHCModel(nn.Module):
    """
    Multi-agent model with stacked mHC layers for deep coordination.
    """
    
    def __init__(self,
                 input_dim: int,
                 hidden_dim: int,
                 output_dim: int,
                 num_agents: int,
                 num_layers: int = 3,
                 dropout: float = 0.1,
                 **mhc_kwargs):
        """
        Initialize multi-agent mHC model.
        """
        super().__init__()
        
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.output_dim = output_dim
        self.num_agents = num_agents
        self.num_layers = num_layers
        
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
    
    def forward(self,
                agent_states: torch.Tensor,
                agent_mask: Optional[torch.Tensor] = None,
                return_attention: bool = False) -> Dict[str, torch.Tensor]:
        """
        Forward pass through multi-agent mHC model.
        """
        batch_size = agent_states.shape[0]
        
        # Project input to hidden dimension
        hidden = self.input_proj(agent_states)
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
            agent_hidden = hidden[:, agent_idx, :]
            
            # Apply agent-specific transformation
            agent_out = self.agent_outputs[agent_idx](agent_hidden)
            agent_outputs.append(agent_out)
        
        # Stack agent outputs
        output = torch.stack(agent_outputs, dim=1)
        
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
        """
        # Generate dummy input
        batch_size = 4
        dummy_input = torch.randn(batch_size, self.num_agents, self.input_dim)
        
        # Move to same device as parameters
        device = next(self.parameters()).device
        dummy_input = dummy_input.to(device)
        
        # Forward pass with attention
        with torch.no_grad():
            result = self.forward(dummy_input, return_attention=True)
        
        attention_weights = result.get('attention_weights', [])
        
        # Compute metrics across all layers
        all_self_attention = []
        all_coordination_strength = []
        all_entropy = []
        
        for layer_attention in attention_weights:
            # Self-attention: diagonal elements
            self_attn = torch.diagonal(layer_attention, dim1=1, dim2=2)
            all_self_attention.append(self_attn.mean().item())
            
            # Coordination strength: off-diagonal elements
            batch_size, n, _ = layer_attention.shape
            eye_mask = torch.eye(n, device=layer_attention.device)
            eye_mask = eye_mask.unsqueeze(0).expand(batch_size, -1, -1)
            
            off_diag = layer_attention * (1 - eye_mask)
            coord_strength = off_diag.sum(dim=(1, 2)) / (n * (n - 1))
            all_coordination_strength.append(coord_strength.mean().item())
            
            # Attention entropy: diversity of attention distribution
            attention_probs = layer_attention.view(-1, n)
            entropy = -torch.sum(attention_probs * torch.log(attention_probs + 1e-8), dim=1)
            max_entropy = math.log(n)
            normalized_entropy = entropy.mean().item() / max_entropy
            all_entropy.append(normalized_entropy)
        
        # Compute agent similarity from final hidden states
        final_hidden = result['final_hidden']
        agent_similarities = []
        
        for batch_idx in range(final_hidden.shape[0]):
            batch_hidden = final_hidden[batch_idx]
            
            # Compute cosine similarity matrix
            norms = torch.norm(batch_hidden, dim=1, keepdim=True)
            normalized = batch_hidden / (norms + 1e-8)
            similarity_matrix = torch.mm(normalized, normalized.T)
            
            # Average similarity between different agents
            eye_mask = torch.eye(self.num_agents, device=similarity_matrix.device)
            off_diag_similarity = similarity_matrix * (1 - eye_mask)
            avg_similarity = off_diag_similarity.sum() / (self.num_agents * (self.num_agents - 1))
            agent_similarities.append(avg_similarity.item())
        
        # Handle empty lists
        self_attention_mean = np.mean(all_self_attention) if all_self_attention else 0.0
        self_attention_std = np.std(all_self_attention) if all_self_attention else 0.0
        coord_strength_mean = np.mean(all_coordination_strength) if all_coordination_strength else 0.0
        coord_strength_std = np.std(all_coordination_strength) if all_coordination_strength else 0.0
        entropy_mean = np.mean(all_entropy) if all_entropy else 0.0
        entropy_std = np.std(all_entropy) if all_entropy else 0.0
        agent_similarity_mean = np.mean(agent_similarities) if agent_similarities else 0.0
        agent_similarity_std = np.std(agent_similarities) if agent_similarities else 0.0
        
        return {
            'self_attention_mean': float(self_attention_mean),
            'self_attention_std': float(self_attention_std),
            'coordination_strength_mean': float(coord_strength_mean),
            'coordination_strength_std': float(coord_strength_std),
            'attention_entropy_mean': float(entropy_mean),
            'attention_entropy_std': float(entropy_std),
            'agent_similarity_mean': float(agent_similarity_mean),
            'agent_similarity_std': float(agent_similarity_std)
        }


class MHCTrainer:
    """
    Trainer for Manifold-Constrained Hyper-Connections models.
    """
    
    def __init__(self,
                 model: nn.Module,
                 train_dataset: SecurityDataset,
                 val_dataset: SecurityDataset,
                 config: Dict[str, Any]):
        """
        Initialize mHC trainer.
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
            num_workers=config.get('num_workers', 0),
            pin_memory=config.get('pin_memory', True)
        )
        
        self.val_loader = val_dataset.get_dataloader(
            batch_size=config['batch_size'],
            shuffle=False,
            num_workers=config.get('num_workers', 0),
            pin_memory=config.get('pin_memory', True)
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
        self.curriculum_progress = 0.0
        
        # Logging
        self.log_file = self.checkpoint_dir / 'training_log.jsonl'
        
        print(f"Initialized mHC Trainer")
        print(f"Model: {model.__class__.__name__}")
        print(f"Parameters: {sum(p.numel() for p in model.parameters()):,}")
        print(f"Device: {self.device}")
        print(f"Training samples: {len(train_dataset)}")
        print(f"Validation samples: {len(val_dataset)}")
        print(f"Curriculum phase: {self.curriculum_phase}")
    
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
        """
        if not attention_weights:
            return torch.tensor(0.0, device=self.device)
        
        total_loss = 0.0
        
        for layer_attention in attention_weights:
            batch_size, num_agents, _ = layer_attention.shape
            
            # Create mask for self-attention (diagonal)
            eye = torch.eye(num_agents, device=layer_attention.device)
            eye = eye.unsqueeze(0).expand(batch_size, -1, -1)
            
            self_attention = (layer_attention * eye).sum(dim=(1, 2))
            total_attention = layer_attention.sum(dim=(1, 2))
            
            # Ratio of self-attention to total attention
            self_ratio = self_attention / (total_attention + 1e-8)
            
            # Loss: encourage target sparsity
            target_sparsity = 0.7
            sparsity_loss = F.mse_loss(
                self_ratio, 
                torch.full_like(self_ratio, target_sparsity)
            )
            
            # Attention balance loss
            attention_received = layer_attention.sum(dim=1)
            attention_received_norm = attention_received / (attention_received.sum(dim=1, keepdim=True) + 1e-8)
            
            target_uniform = torch.full_like(attention_received_norm, 1.0 / num_agents)
            
            balance_loss = F.kl_div(
                torch.log(attention_received_norm + 1e-8),
                target_uniform,
                reduction='batchmean'
            )
            
            # Apply agent mask if provided
            if agent_mask is not None:
                valid_mask = agent_mask.float()
                sparsity_loss = sparsity_loss * valid_mask.mean()
                balance_loss = balance_loss * valid_mask.mean()
            
            total_loss += sparsity_loss + 0.5 * balance_loss
        
        return total_loss / len(attention_weights)
    
    def _diversity_loss(self, hidden_states: List[torch.Tensor]) -> torch.Tensor:
        """
        Loss that encourages diversity among agent representations.
        """
        if not hidden_states:
            return torch.tensor(0.0, device=self.device)
        
        total_loss = 0.0
        
        for hidden in hidden_states:
            # hidden shape: [B, N, D]
            batch_size, num_agents, hidden_dim = hidden.shape
            
            if num_agents < 2:
                # Cannot compute diversity with single agent
                continue
                
            # Compute cosine similarity matrix for each batch
            for b in range(batch_size):
                batch_hidden = hidden[b]
                
                # Normalize
                norms = torch.norm(batch_hidden, dim=1, keepdim=True)
                normalized = batch_hidden / (norms + 1e-8)
                
                # Compute similarity matrix
                similarity = torch.mm(normalized, normalized.T)
                
                # We want off-diagonal similarities to be low (diverse agents)
                eye = torch.eye(num_agents, device=similarity.device)
                off_diag_similarity = similarity * (1 - eye)
                
                # Loss: penalize high similarity between different agents
                diversity_loss = torch.mean(torch.abs(off_diag_similarity))
                total_loss += diversity_loss
        
        # Avoid division by zero
        num_batches = sum(h.shape[0] for h in hidden_states)
        if num_batches > 0:
            return total_loss / num_batches
        else:
            return torch.tensor(0.0, device=self.device)
    
    def _manifold_constraint_loss(self, model: nn.Module) -> torch.Tensor:
        """
        Loss that encourages satisfaction of manifold constraints.
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
                    torch.tensor([identity_current], device=self.device, dtype=torch.float32),
                    torch.tensor([identity_target], device=self.device, dtype=torch.float32)
                )
                total_loss += identity_loss
                
                # Penalize signal bound violations
                if module.signal_bound > 0:
                    bound_violation = max(0.0, constraints['max_signal_norm'] - module.signal_bound)
                    total_loss += bound_violation
        
        return torch.tensor(total_loss, device=self.device)
    
    def _sparsity_loss(self, attention_weights: List[torch.Tensor]) -> torch.Tensor:
        """
        Loss that encourages sparse attention patterns.
        """
        if not attention_weights:
            return torch.tensor(0.0, device=self.device)
        
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
        """
        # Extract predictions and labels
        predictions = model_output['output']
        labels = batch['labels']
        
        # Task loss (main prediction loss)
        if labels.dim() == 2:
            # Single label per sample
            avg_predictions = predictions.mean(dim=1)
            task_loss = self.loss_functions['task'](avg_predictions, labels)
        else:
            # Per-agent labels
            task_loss = self.loss_functions['task'](predictions, labels)
        
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
        if self.curriculum_phase == 'individual':
            # Focus on task learning, minimal coordination
            return {
                'task': 1.0,
                'coordination': 0.1 * self.curriculum_progress,
                'diversity': 0.5,
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
            return {
                'task': 1.0,
                'coordination': 0.5,
                'diversity': 0.2,
                'manifold': 0.1,
                'sparsity': 0.05
            }
        
        elif self.curriculum_phase == 'adversarial':
            # Focus on robustness
            return {
                'task': 1.0,
                'coordination': 0.7,
                'diversity': 0.3,
                'manifold': 0.2,
                'sparsity': 0.1
            }
        
        else:
            return {
                'task': 1.0,
                'coordination': 0.5,
                'diversity': 0.2,
                'manifold': 0.1,
                'sparsity': 0.05
            }
    
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
            print(f"Switching curriculum phase: {self.curriculum_phase} to {new_phase}")
            self.curriculum_phase = new_phase
        
        # Update progress within phase
        phase_progress = (progress % 0.25) / 0.25
        self.curriculum_progress = phase_progress
    
    def train_epoch(self) -> Dict[str, float]:
        """
        Train for one epoch.
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
            epoch_metrics[key] /= max(num_batches, 1)
        
        # Get coordination metrics
        try:
            coord_metrics = self.model.get_coordination_metrics()
            for key, value in coord_metrics.items():
                epoch_metrics[f'coord_{key}'] = value
        except:
            # Skip if model doesn't have this method
            pass
        
        return dict(epoch_metrics)
    
    def validate(self) -> Dict[str, float]:
        """
        Run validation.
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
            val_metrics[key] /= max(num_batches, 1)
        
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
        print(f"\nStarting mHC training for {self.config['num_epochs']} epochs")
        print("="*80)
        
        for epoch in range(self.current_epoch, self.config['num_epochs']):
            self.current_epoch = epoch
            
            # Update curriculum
            self.update_curriculum(epoch, self.config['num_epochs'])
            
            # Train for one epoch
            print(f"\nEpoch {epoch + 1}/{self.config['num_epochs']}")
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
                print(f"Saved best model (val_loss: {self.best_val_loss:.4f})")
            else:
                self.patience_counter += 1
            
            # Save regular checkpoint
            if epoch % self.config.get('checkpoint_interval', 5) == 0:
                self.save_checkpoint(f'epoch_{epoch}')
            
            # Early stopping
            if self.patience_counter >= self.config.get('patience', 20):
                print(f"Early stopping triggered at epoch {epoch + 1}")
                break
            
            # Print epoch summary
            print(f"Epoch {epoch + 1} summary:")
            print(f"   Train Loss: {train_metrics['train_total_loss']:.4f}")
            print(f"   Val Loss: {val_metrics['val_total_loss']:.4f}")
            print(f"   Val Accuracy: {val_metrics.get('val_accuracy', 0):.4f}")
        
        print("\nTraining completed!")
        print(f"Best validation loss: {self.best_val_loss:.4f}")
    
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
        print(f"Checkpoint saved: {checkpoint_path}")
    
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
        
        print(f"Checkpoint loaded: {checkpoint_path}")
        print(f"Resume from epoch {self.current_epoch}, "
              f"best val loss: {self.best_val_loss:.4f}")


# Example usage and testing
if __name__ == "__main__":
    print("Testing mHC Trainer...")
    
    # Create a small dummy dataset
    import tempfile
    
    # Create temporary dataset files
    train_dataset = SecurityDataset("", feature_dim=512, use_encryption=False)
    val_dataset = SecurityDataset("", feature_dim=512, use_encryption=False)
    
    # Split datasets
    train_data, val_data, _ = train_dataset.split(train_ratio=0.8, val_ratio=0.2, test_ratio=0.0)
    
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
    print("\nTesting training loop...")
    test_metrics = trainer.train_epoch()
    print(f"Training metrics: {test_metrics}")
    
    # Test validation
    print("\nTesting validation...")
    val_metrics = trainer.validate()
    print(f"Validation metrics: {val_metrics}")
    
    print("\nmHC Trainer tests completed!")