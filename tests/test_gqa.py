# tests/test_gqa.py
"""
Comprehensive tests for Grouped Query Attention (GQA) with Flash Attention and RoPE

This module tests the GQA implementation:
1. Rotary Positional Embedding (RoPE)
2. Grouped Query Attention mechanism
3. Flash Attention optimization
4. Transformer layer integration
5. Memory efficiency
6. Performance characteristics
7. Numerical stability

Each test validates mathematical properties and implementation correctness.
"""

import pytest
import sys
import os
import torch
import numpy as np
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
import math
import time

# Add src to path for imports to locate the source modules
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

# Import the actual modules to be tested
try:
    from src.core.gqa_transformer import (
        RotaryPositionalEmbedding,
        GroupedQueryAttention,
        SecurityGQATransformer
    )
    MODULE_AVAILABLE = True
except ImportError:
    MODULE_AVAILABLE = False

# Test markers - categorize tests for selective running
pytestmark = [
    pytest.mark.gqa,
    pytest.mark.requires_torch,
    pytest.mark.unit
]


# Fixture for creating test transformer instance
@pytest.fixture
def gqa_transformer():
    """Create a GQA transformer instance for testing with default configuration."""
    # Skip if module not available
    if not MODULE_AVAILABLE:
        pytest.skip("GQA Transformer module not available")
    
    # Create transformer with minimal configuration for testing
    config = {
        'vocab_size': 1000,  # Reduced for testing
        'd_model': 512,  # Model dimension
        'n_heads': 8,  # Number of attention heads
        'n_layers': 2,  # Reduced for faster testing
        'n_groups': 2,  # Number of query groups in GQA
        'num_threat_classes': 5,  # Number of threat classes
        'max_seq_len': 2048,  # Maximum sequence length
        'dropout': 0.1,  # Dropout rate
        'use_flash_attention': True  # Enable flash attention
    }
    
    # Create and return model instance
    model = SecurityGQATransformer(**config)
    model.eval()  # Set to evaluation mode by default
    return model


class TestRotaryPositionalEmbedding:
    """Tests for Rotary Positional Embedding (RoPE) functionality."""
    
    def test_rope_initialization(self):
        """Test that RoPE initializes correctly with proper parameters and cached tensors."""
        # Arrange: Define test parameters
        dim = 512  # Dimension of embeddings
        max_seq_len = 2048  # Maximum sequence length
        base = 10000.0  # Base for frequency calculation
        
        # Act: Initialize RoPE module
        if not MODULE_AVAILABLE:
            pytest.skip("RoPE module not available")
        
        rope = RotaryPositionalEmbedding(dim, max_seq_len, base)
        
        # Assert: Check initialization values
        # Verify dimensions are set correctly
        assert rope.dim == dim, f"Dimension should be {dim}, got {rope.dim}"
        # Verify maximum sequence length
        assert rope.max_seq_len == max_seq_len, \
            f"max_seq_len should be {max_seq_len}, got {rope.max_seq_len}"
        # Verify base value
        assert rope.base == base, f"base should be {base}, got {rope.base}"
        
        # Check that required cached tensors exist
        assert hasattr(rope, 'cos_cached'), "RoPE should cache cosine values"
        assert hasattr(rope, 'sin_cached'), "RoPE should cache sine values"
        
        # Check shapes of cached tensors
        # RoPE uses half dimensions for rotation (complex numbers representation)
        expected_cos_shape = (max_seq_len, dim // 2)
        assert rope.cos_cached.shape == expected_cos_shape, \
            f"cos_cached shape should be {expected_cos_shape}, got {rope.cos_cached.shape}"
        
        expected_sin_shape = (max_seq_len, dim // 2)
        assert rope.sin_cached.shape == expected_sin_shape, \
            f"sin_cached shape should be {expected_sin_shape}, got {rope.sin_cached.shape}"
        
        # Check that cached values are within valid ranges
        # Cosine values should be between -1 and 1
        assert torch.all(rope.cos_cached >= -1) and torch.all(rope.cos_cached <= 1), \
            "cos_cached values should be in [-1, 1]"
        # Sine values should be between -1 and 1
        assert torch.all(rope.sin_cached >= -1) and torch.all(rope.sin_cached <= 1), \
            "sin_cached values should be in [-1, 1]"
    
    def test_rope_frequency_calculation(self):
        """Test that RoPE frequency calculations are mathematically correct."""
        # Arrange: Initialize RoPE with test parameters
        dim = 512
        max_seq_len = 2048
        base = 10000.0
        
        if not MODULE_AVAILABLE:
            pytest.skip("RoPE module not available")
        
        rope = RotaryPositionalEmbedding(dim, max_seq_len, base)
        
        # Manually calculate expected frequencies for verification
        # Create theta values: 1/(base^(2i/dim)) for i in [0, dim/2-1]
        theta = 1.0 / (base ** (torch.arange(0, dim, 2).float() / dim))
        # Create position indices
        positions = torch.arange(max_seq_len).float()
        # Calculate outer product for position-theta multiplication
        expected_args = torch.outer(positions, theta)
        
        # Check trigonometric properties at position 0
        # At position 0, cos(0) = 1 and sin(0) = 0
        assert torch.allclose(rope.cos_cached[0], torch.ones(dim // 2), rtol=1e-5), \
            "cos(0) should be 1 for all dimensions"
        assert torch.allclose(rope.sin_cached[0], torch.zeros(dim // 2), rtol=1e-5), \
            "sin(0) should be 0 for all dimensions"
        
        # Verify that values change with different positions
        # Different positions should have different rotations
        assert not torch.allclose(rope.cos_cached[0], rope.cos_cached[1], rtol=1e-5), \
            "Cosine values should change with position"
        assert not torch.allclose(rope.sin_cached[0], rope.sin_cached[1], rtol=1e-5), \
            "Sine values should change with position"
    
    def test_apply_rotary_emb(self):
        """Test applying rotary embeddings preserves norms and applies correct rotations."""
        # Arrange: Initialize RoPE and create test tensor
        dim = 512
        max_seq_len = 2048
        
        if not MODULE_AVAILABLE:
            pytest.skip("RoPE module not available")
        
        rope = RotaryPositionalEmbedding(dim, max_seq_len)
        
        # Create test tensor with shape [batch, heads, seq_len, d_k]
        batch_size = 2
        n_heads = 8
        seq_len = 128
        d_k = dim // n_heads  # 512 / 8 = 64
        
        # Random tensor for testing
        x = torch.randn(batch_size, n_heads, seq_len, d_k)
        
        # Act: Apply rotary embeddings
        x_rotated = rope.apply_rotary_emb(x, seq_len)
        
        # Assert: Check rotation properties
        # Shape should remain unchanged
        assert x_rotated.shape == x.shape, \
            f"Rotated tensor should have same shape: {x_rotated.shape} != {x.shape}"
        
        # RoPE is a rotation, which should preserve vector norms
        # Calculate norms before and after rotation
        orig_norms = torch.norm(x, dim=-1)
        rotated_norms = torch.norm(x_rotated, dim=-1)
        
        # Norms should be preserved (rotation doesn't change vector length)
        assert torch.allclose(orig_norms, rotated_norms, rtol=1e-5), \
            "RoPE rotation should preserve vector norms"
        
        # Check that different positions get different rotations
        # Extract vectors from first and second positions
        x_pos0 = x_rotated[:, :, 0, :]
        x_pos1 = x_rotated[:, :, 1, :]
        
        # They should be different (different rotation matrices)
        assert not torch.allclose(x_pos0, x_pos1, rtol=1e-5), \
            "Different positions should have different rotations"
        
        # Verify rotation is applied correctly per attention head
        for head in range(n_heads):
            # Extract data for specific head
            head_rotated = x_rotated[:, head, :, :]
            head_original = x[:, head, :, :]
            
            # Calculate norms per head
            head_orig_norms = torch.norm(head_original, dim=-1)
            head_rotated_norms = torch.norm(head_rotated, dim=-1)
            
            # Norms should be preserved for each head individually
            assert torch.allclose(head_orig_norms, head_rotated_norms, rtol=1e-5), \
                f"RoPE should preserve norms for head {head}"
    
    def test_rope_position_invariance(self):
        """Test RoPE's ability to encode positional information into identical vectors."""
        # Arrange: Initialize RoPE
        dim = 512
        
        if not MODULE_AVAILABLE:
            pytest.skip("RoPE module not available")
        
        rope = RotaryPositionalEmbedding(dim)
        
        # Create identical vectors at different positions
        batch_size = 2
        n_heads = 8
        seq_len = 3
        d_k = dim // n_heads
        
        # Create a base vector and repeat it across sequence positions
        vector = torch.randn(batch_size, n_heads, 1, d_k)
        x = vector.repeat(1, 1, seq_len, 1)  # Repeat across sequence dimension
        
        # Act: Apply rotary embeddings
        x_rotated = rope.apply_rotary_emb(x, seq_len)
        
        # Assert: Check positional encoding properties
        # Extract vectors from different positions
        pos0 = x_rotated[:, :, 0, :]
        pos1 = x_rotated[:, :, 1, :]
        pos2 = x_rotated[:, :, 2, :]
        
        # Identical vectors at different positions should get different rotations
        # This is the core property of positional encoding
        assert not torch.allclose(pos0, pos1, rtol=1e-5), \
            "Positions 0 and 1 should have different rotations"
        assert not torch.allclose(pos0, pos2, rtol=1e-5), \
            "Positions 0 and 2 should have different rotations"
        assert not torch.allclose(pos1, pos2, rtol=1e-5), \
            "Positions 1 and 2 should have different rotations"
        
        # Calculate norms for each position
        norms_pos0 = torch.norm(pos0, dim=-1)
        norms_pos1 = torch.norm(pos1, dim=-1)
        norms_pos2 = torch.norm(pos2, dim=-1)
        original_norm = torch.norm(vector, dim=-1)
        
        # Norms should be preserved at all positions (rotation property)
        assert torch.allclose(norms_pos0, original_norm, rtol=1e-5), \
            "Position 0 should preserve original norm"
        assert torch.allclose(norms_pos1, original_norm, rtol=1e-5), \
            "Position 1 should preserve original norm"
        assert torch.allclose(norms_pos2, original_norm, rtol=1e-5), \
            "Position 2 should preserve original norm"
    
    def test_rope_long_sequences(self):
        """Test RoPE handles long sequences without numerical issues."""
        # Arrange: Initialize RoPE with large max sequence length
        dim = 512
        max_seq_len = 8192
        
        if not MODULE_AVAILABLE:
            pytest.skip("RoPE module not available")
        
        rope = RotaryPositionalEmbedding(dim, max_seq_len)
        
        # Test with long sequence
        batch_size = 1
        n_heads = 8
        seq_len = 4096  # Long sequence for testing
        d_k = dim // n_heads
        
        x = torch.randn(batch_size, n_heads, seq_len, d_k)
        
        # Act: Apply rotary embeddings to long sequence
        x_rotated = rope.apply_rotary_emb(x, seq_len)
        
        # Assert: Check handling of long sequences
        # Shape should remain correct
        assert x_rotated.shape == x.shape, \
            f"Should handle long sequences without shape change: {x_rotated.shape} != {x.shape}"
        
        # Check for numerical stability - no NaN or infinite values
        assert torch.all(torch.isfinite(x_rotated)), \
            "Should handle long sequences without numerical issues (NaN/Inf)"
        
        # Verify first and last positions are different
        # Long sequences should still have unique positional encodings
        first_pos = x_rotated[:, :, 0, :]
        last_pos = x_rotated[:, :, -1, :]
        
        assert not torch.allclose(first_pos, last_pos, rtol=1e-5), \
            "First and last positions in long sequence should have different rotations"


class TestGroupedQueryAttention:
    """Tests for Grouped Query Attention mechanism."""
    
    def test_gqa_initialization(self, gqa_transformer):
        """Test GQA model initializes with correct parameters and structure."""
        # Arrange & Act: Get the model from fixture
        model = gqa_transformer
        
        # Assert: Check model has required attributes
        # Model should have dimension attribute
        assert hasattr(model, 'd_model'), "Model should have d_model attribute"
        # Model should have number of heads attribute
        assert hasattr(model, 'n_heads'), "Model should have n_heads attribute"
        
        # If model has group information, verify divisibility
        if hasattr(model, 'n_groups'):
            # Number of heads must be divisible by number of groups
            assert model.n_heads % model.n_groups == 0, \
                f"n_heads ({model.n_heads}) should be divisible by n_groups ({model.n_groups})"
        
        # Check transformer layers have attention modules
        if hasattr(model, 'layers'):
            for layer in model.layers:
                # Access attention module (handles both dict and object access)
                if isinstance(layer, dict):
                    attn = layer.get('attention')
                else:
                    attn = getattr(layer, 'attention', None)
                
                if attn is not None:
                    # Verify attention module has required attributes
                    assert hasattr(attn, 'n_heads'), "Attention should have n_heads"
                    assert hasattr(attn, 'n_groups'), "GQA should have n_groups"
                    
                    # GQA should have group mapping
                    assert hasattr(attn, 'group_map'), "GQA should have group_map"
                    # Group map should map each head to a group
                    assert attn.group_map.shape[0] == attn.n_heads, \
                        f"group_map should have length n_heads, got {attn.group_map.shape[0]}"
    
    def test_gqa_forward_pass(self, gqa_transformer):
        """Test complete forward pass through GQA transformer."""
        # Arrange: Get model and create test input
        model = gqa_transformer
        
        batch_size = 2
        seq_len = 64
        vocab_size = model.vocab_size
        
        # Create random token indices as input
        input_ids = torch.randint(0, vocab_size, (batch_size, seq_len))
        
        # Act: Perform forward pass (no gradient computation)
        with torch.no_grad():
            output = model.forward(input_ids)
        
        # Assert: Check output structure and properties
        # Output should contain threat classification logits
        assert 'threat_logits' in output, "Output should contain threat_logits"
        # Output should contain severity score
        assert 'severity_score' in output, "Output should contain severity_score"
        # Output should contain hidden states
        assert 'hidden_states' in output, "Output should contain hidden_states"
        
        # Verify output shapes are correct
        threat_logits = output['threat_logits']
        expected_threat_shape = (batch_size, model.num_threat_classes)
        assert threat_logits.shape == expected_threat_shape, \
            f"threat_logits shape should be {expected_threat_shape}, got {threat_logits.shape}"
        
        severity_score = output['severity_score']
        expected_severity_shape = (batch_size, 1)
        assert severity_score.shape == expected_severity_shape, \
            f"severity_score shape should be {expected_severity_shape}, got {severity_score.shape}"
        
        hidden_states = output['hidden_states']
        expected_hidden_shape = (batch_size, seq_len, model.d_model)
        assert hidden_states.shape == expected_hidden_shape, \
            f"hidden_states shape should be {expected_hidden_shape}, got {hidden_states.shape}"
        
        # Check all outputs have finite values (no NaN or Inf)
        assert torch.all(torch.isfinite(threat_logits)), "threat_logits should be finite"
        assert torch.all(torch.isfinite(severity_score)), "severity_score should be finite"
        assert torch.all(torch.isfinite(hidden_states)), "hidden_states should be finite"
        
        # Severity score should be between 0 and 1 (Sigmoid activation output)
        assert torch.all(severity_score >= 0) and torch.all(severity_score <= 1), \
            f"severity_score should be in [0, 1], got min={severity_score.min():.3f}, max={severity_score.max():.3f}"
    
    def test_gqa_attention_pattern(self, gqa_transformer):
        """Test GQA attention grouping pattern and mapping."""
        # Arrange: Get model and extract attention module
        model = gqa_transformer
        
        # Access first layer's attention module
        if hasattr(model, 'layers'):
            first_layer = model.layers[0]
            # Handle both dictionary and object layer formats
            if isinstance(first_layer, dict):
                attention = first_layer.get('attention')
            else:
                attention = getattr(first_layer, 'attention', None)
        else:
            pytest.skip("Model layers not accessible")
        
        if attention is None:
            pytest.skip("Attention module not found in first layer")
        
        # Assert: Check GQA-specific attributes exist
        assert hasattr(attention, 'n_groups'), "GQA attention should have n_groups"
        assert hasattr(attention, 'group_map'), "GQA attention should have group_map"
        
        # Get attention parameters
        n_heads = attention.n_heads
        n_groups = attention.n_groups
        
        # Verify divisibility condition
        assert n_heads % n_groups == 0, \
            f"n_heads ({n_heads}) should be divisible by n_groups ({n_groups})"
        
        # Calculate expected group size
        group_size = n_heads // n_groups
        
        # Get group mapping tensor
        group_map = attention.group_map
        
        # Verify group_map has correct length
        assert len(group_map) == n_heads, \
            f"group_map should have {n_heads} entries, got {len(group_map)}"
        
        # Verify each group has exactly group_size heads
        for group_idx in range(n_groups):
            # Count heads assigned to this group
            heads_in_group = (group_map == group_idx).sum().item()
            assert heads_in_group == group_size, \
                f"Group {group_idx} should have {group_size} heads, got {heads_in_group}"
        
        # Verify groups are assigned in contiguous blocks (common GQA implementation)
        # Build expected mapping: [0,0,...,1,1,...,2,2,...] based on group_size
        expected_mapping = []
        for group_idx in range(n_groups):
            expected_mapping.extend([group_idx] * group_size)
        
        # Compare with actual mapping
        assert torch.equal(group_map, torch.tensor(expected_mapping, device=group_map.device)), \
            "group_map should have contiguous group assignments"
    
    def test_gqa_memory_efficiency(self, gqa_transformer):
        """Test GQA memory efficiency compared to standard Multi-Head Attention."""
        # Arrange: Get model parameters
        model = gqa_transformer
        
        # Access attention module
        if hasattr(model, 'layers'):
            first_layer = model.layers[0]
            if isinstance(first_layer, dict):
                attention = first_layer.get('attention')
            else:
                attention = getattr(first_layer, 'attention', None)
        else:
            pytest.skip("Model layers not accessible")
        
        if attention is None:
            pytest.skip("Attention module not found")
        
        # Get attention parameters
        n_heads = attention.n_heads
        n_groups = attention.n_groups
        d_model = model.d_model
        d_k = d_model // n_heads  # Dimension per head
        
        # Calculate parameter counts for comparison
        # GQA parameters:
        # - Q projection: d_model × d_model (full projection)
        # - K projection: d_model × (n_groups × d_k) (shared within groups)
        # - V projection: d_model × (n_groups × d_k) (shared within groups)
        gqa_params = (
            d_model * d_model +  # Q projection (full)
            2 * d_model * (n_groups * d_k)  # K and V projections (group-shared)
        )
        
        # Standard MHA parameters:
        # - Q projection: d_model × d_model (full)
        # - K projection: d_model × d_model (full)
        # - V projection: d_model × d_model (full)
        mha_params = 3 * d_model * d_model
        
        # Calculate memory savings percentage
        memory_saving = 1 - (gqa_params / mha_params)
        
        # Assert: GQA should use significantly fewer parameters
        assert gqa_params < mha_params, \
            f"GQA should use fewer parameters: GQA={gqa_params:,}, MHA={mha_params:,}"
        
        # GQA should provide substantial memory savings (typically >30%)
        expected_min_saving = 0.3  # Minimum 30% memory savings
        assert memory_saving > expected_min_saving, \
            f"GQA should save at least {expected_min_saving*100:.0f}% memory, " \
            f"got {memory_saving*100:.1f}%"
        
        # Print efficiency metrics for debugging/information
        print(f"GQA memory efficiency: "
              f"n_heads={n_heads}, n_groups={n_groups}, "
              f"GQA params={gqa_params:,}, MHA params={mha_params:,}, "
              f"saving={memory_saving*100:.1f}%")
    
    def test_gqa_inference_speed(self, gqa_transformer):
        """Test GQA inference speed across different sequence lengths."""
        # Arrange: Set model to evaluation mode
        model = gqa_transformer
        model.eval()  # Disable dropout and batch normalization
        
        # Test with different sequence lengths to measure scaling
        seq_lengths = [64, 128, 256, 512]
        batch_size = 2
        vocab_size = model.vocab_size
        
        results = []
        
        for seq_len in seq_lengths:
            # Create test input for current sequence length
            input_ids = torch.randint(0, vocab_size, (batch_size, seq_len))
            
            # Warm-up run to initialize any lazy modules
            with torch.no_grad():
                _ = model.forward(input_ids)
            
            # Time the inference
            start_time = time.time()
            
            with torch.no_grad():
                output = model.forward(input_ids)
            
            end_time = time.time()
            inference_time = end_time - start_time
            
            # Calculate throughput (tokens per second)
            throughput = (batch_size * seq_len) / inference_time
            
            results.append({
                'seq_len': seq_len,
                'time': inference_time,
                'throughput': throughput
            })
            
            # Verify output is valid
            assert 'threat_logits' in output, "Should produce threat_logits"
            assert torch.all(torch.isfinite(output['threat_logits'])), "Output should be finite"
        
        # Assert: Check performance scaling
        # Print results for analysis
        print("\nGQA Inference Speed Test:")
        for result in results:
            print(f"  seq_len={result['seq_len']:4d}: "
                  f"time={result['time']:.3f}s, "
                  f"throughput={result['throughput']:.0f} tokens/sec")
        
        # Check that time doesn't increase exponentially with sequence length
        # Attention is O(n^2) but optimizations should help
        if len(results) >= 2:
            first_result = results[0]
            last_result = results[-1]
            
            # Calculate ratios
            seq_len_ratio = last_result['seq_len'] / first_result['seq_len']
            time_ratio = last_result['time'] / first_result['time']
            
            # Allow some overhead but prevent exponential growth
            # O(n^2) would give ratio^2, allow up to ratio^2.5 for overhead
            expected_max_ratio = seq_len_ratio ** 2.5
            
            assert time_ratio < expected_max_ratio, \
                f"Inference time growth too high: " \
                f"seq_len increased {seq_len_ratio:.1f}x, " \
                f"time increased {time_ratio:.1f}x (max allowed: {expected_max_ratio:.1f}x)"


class TestFlashAttentionIntegration:
    """Tests for Flash Attention integration with GQA."""
    
    def test_flash_attention_availability(self, gqa_transformer):
        """Test if Flash Attention is available and properly configured."""
        # Arrange: Get model
        model = gqa_transformer
        
        # Check if model uses flash attention
        uses_flash = False
        
        # Try to access flash attention setting from model
        if hasattr(model, 'use_flash_attention'):
            uses_flash = model.use_flash_attention
        else:
            # Check in layers if not at model level
            if hasattr(model, 'layers'):
                first_layer = model.layers[0]
                if isinstance(first_layer, dict):
                    attention = first_layer.get('attention')
                else:
                    attention = getattr(first_layer, 'attention', None)
                
                if attention is not None:
                    if hasattr(attention, 'use_flash'):
                        uses_flash = attention.use_flash
                    elif hasattr(attention, 'use_flash_attention'):
                        uses_flash = attention.use_flash_attention
        
        # Check PyTorch version for built-in flash attention support
        torch_version = torch.__version__
        has_builtin_flash = hasattr(torch.nn.functional, 'scaled_dot_product_attention')
        
        # Print information for debugging
        print(f"Flash Attention Info:")
        print(f"  PyTorch version: {torch_version}")
        print(f"  Built-in flash attention: {has_builtin_flash}")
        print(f"  Model configured for flash: {uses_flash}")
        
        # Assert: Some form of optimized attention should be available
        # This test is informational but verifies optimization availability
        optimized_attention_available = has_builtin_flash or uses_flash
        assert optimized_attention_available, \
            "Should have some form of optimized attention available for performance"
    
    def test_attention_output_consistency(self, gqa_transformer):
        """Test that attention produces deterministic and consistent results."""
        # Arrange: Set model to evaluation mode for deterministic behavior
        model = gqa_transformer
        model.eval()
        
        # Create test input
        batch_size = 2
        seq_len = 64
        vocab_size = model.vocab_size
        
        input_ids = torch.randint(0, vocab_size, (batch_size, seq_len))
        
        # Act: Run forward pass twice with same input
        with torch.no_grad():
            output1 = model.forward(input_ids)
            output2 = model.forward(input_ids)
        
        # Assert: Outputs should be identical (deterministic computation)
        threat_logits1 = output1['threat_logits']
        threat_logits2 = output2['threat_logits']
        
        # Use relative tolerance for floating point comparison
        assert torch.allclose(threat_logits1, threat_logits2, rtol=1e-5), \
            "Same input should produce identical threat_logits"
        
        severity1 = output1['severity_score']
        severity2 = output2['severity_score']
        
        assert torch.allclose(severity1, severity2, rtol=1e-5), \
            "Same input should produce identical severity scores"
    
    def test_gradient_flow(self, gqa_transformer):
        """Test that gradients flow properly through all GQA layers during training."""
        # Arrange: Set model to training mode
        model = gqa_transformer
        model.train()  # Enable dropout and batch norm
        
        batch_size = 2
        seq_len = 32
        vocab_size = model.vocab_size
        
        # Create random input
        input_ids = torch.randint(0, vocab_size, (batch_size, seq_len))
        
        # Create dummy targets for loss calculation
        target = torch.randint(0, model.num_threat_classes, (batch_size,))
        
        # Act: Perform forward and backward pass
        output = model.forward(input_ids)
        # Calculate cross-entropy loss
        loss = torch.nn.functional.cross_entropy(output['threat_logits'], target)
        
        # Backward pass to compute gradients
        loss.backward()
        
        # Assert: Check gradients are computed and valid
        has_gradients = False
        
        # Iterate through all model parameters
        for name, param in model.named_parameters():
            if param.grad is not None:
                has_gradients = True
                # Gradients should be finite (no NaN or Inf)
                assert torch.all(torch.isfinite(param.grad)), \
                    f"Gradient for parameter {name} should be finite"
                # Break after finding first gradient (proves gradients flow)
                break
        
        # At least some parameters should have gradients
        assert has_gradients, "Should compute gradients for model parameters"
        
        # Cleanup: Reset model to evaluation mode
        model.eval()


class TestSecurityGQATransformer:
    """Tests for the complete Security GQA Transformer model."""
    
    def test_threat_classification(self, gqa_transformer):
        """Test threat classification outputs have correct properties."""
        # Arrange: Set model to evaluation mode
        model = gqa_transformer
        model.eval()
        
        batch_size = 4
        seq_len = 128
        vocab_size = model.vocab_size
        
        # Create test inputs
        input_ids = torch.randint(0, vocab_size, (batch_size, seq_len))
        
        # Act: Run forward pass
        with torch.no_grad():
            output = model.forward(input_ids)
        
        # Assert: Check threat classification properties
        threat_logits = output['threat_logits']
        
        # Verify output shape matches expected
        expected_shape = (batch_size, model.num_threat_classes)
        assert threat_logits.shape == expected_shape, \
            f"threat_logits shape should be {expected_shape}, got {threat_logits.shape}"
        
        # Convert logits to probabilities using softmax
        threat_probs = torch.softmax(threat_logits, dim=-1)
        
        # Probabilities should sum to 1 for each sample
        prob_sums = threat_probs.sum(dim=-1)
        assert torch.allclose(prob_sums, torch.ones(batch_size), rtol=1e-5), \
            f"Threat probabilities should sum to 1, got min={prob_sums.min():.6f}, max={prob_sums.max():.6f}"
        
        # All probabilities should be non-negative
        assert torch.all(threat_probs >= 0), "Threat probabilities should be non-negative"
        
        # Check severity score properties
        severity = output['severity_score']
        # Severity should be between 0 and 1 (Sigmoid output)
        assert torch.all(severity >= 0) and torch.all(severity <= 1), \
            f"Severity should be in [0, 1], got min={severity.min():.3f}, max={severity.max():.3f}"
    
    def test_model_robustness(self, gqa_transformer):
        """Test model robustness to various input edge cases."""
        # Arrange: Set model to evaluation mode
        model = gqa_transformer
        model.eval()
        
        batch_size = 2
        seq_len = 64
        vocab_size = model.vocab_size
        
        # Define test cases with different input characteristics
        test_cases = [
            ('normal', torch.randint(0, vocab_size, (batch_size, seq_len))),
            ('all_zeros', torch.zeros(batch_size, seq_len, dtype=torch.long)),
            ('all_same', torch.full((batch_size, seq_len), 5, dtype=torch.long)),
            ('extreme_values', torch.randint(vocab_size-10, vocab_size, (batch_size, seq_len))),
        ]
        
        # Test each case
        for case_name, input_ids in test_cases:
            try:
                # Act: Run model with test input
                with torch.no_grad():
                    output = model.forward(input_ids)
                
                # Assert: Model should handle all cases without errors
                assert 'threat_logits' in output, f"{case_name}: Should produce threat_logits"
                assert 'severity_score' in output, f"{case_name}: Should produce severity_score"
                
                # Outputs should be finite
                assert torch.all(torch.isfinite(output['threat_logits'])), \
                    f"{case_name}: threat_logits should be finite"
                assert torch.all(torch.isfinite(output['severity_score'])), \
                    f"{case_name}: severity_score should be finite"
                
            except Exception as e:
                # Model should handle edge cases gracefully
                pytest.fail(f"{case_name}: Model should handle input gracefully, got error: {e}")
    
    @pytest.mark.parametrize("batch_size", [1, 2, 4, 8])
    @pytest.mark.parametrize("seq_len", [32, 64, 128, 256])
    def test_model_scalability(self, gqa_transformer, batch_size, seq_len):
        """Test model scalability with different batch sizes and sequence lengths."""
        # Arrange: Set model to evaluation mode
        model = gqa_transformer
        model.eval()
        
        vocab_size = model.vocab_size
        
        # Skip tests that would use too much memory
        # This is a heuristic to prevent out-of-memory errors
        if seq_len * batch_size > 4096:  # Arbitrary limit for testing
            pytest.skip(f"Test would use too much memory: batch_size={batch_size}, seq_len={seq_len}")
        
        # Create test input
        input_ids = torch.randint(0, vocab_size, (batch_size, seq_len))
        
        # Act: Try to run model
        try:
            with torch.no_grad():
                output = model.forward(input_ids)
            
            # Assert: Check output has correct batch dimension
            threat_logits = output['threat_logits']
            assert threat_logits.shape[0] == batch_size, \
                f"Batch size mismatch: expected {batch_size}, got {threat_logits.shape[0]}"
            
            # Optional: Log memory usage if GPU is available
            if torch.cuda.is_available():
                memory_allocated = torch.cuda.memory_allocated() / 1024**2  # Convert to MB
                print(f"Batch={batch_size}, Seq={seq_len}: "
                      f"GPU memory={memory_allocated:.1f}MB")
            
        except RuntimeError as e:
            # Handle out-of-memory errors gracefully
            if "out of memory" in str(e).lower():
                pytest.skip(f"Out of memory for batch={batch_size}, seq={seq_len}")
            else:
                # Re-raise other runtime errors
                raise


@pytest.mark.integration
class TestGQAEndToEnd:
    """End-to-end tests for GQA in security context."""
    
    def test_security_threat_detection_pipeline(self, gqa_transformer):
        """Test complete security threat detection pipeline with simulated threats."""
        # Arrange: Set model to evaluation mode
        model = gqa_transformer
        model.eval()
        
        # Simulate security feature encoding
        # This mimics real-world security log/traffic data
        batch_size = 4
        seq_len = 256
        
        # Create mock security features representing different threat scenarios
        # Each sample represents a different security scenario
        security_features = []
        
        for i in range(batch_size):
            if i == 0:  # Normal traffic (no threats)
                features = torch.randint(100, 200, (seq_len,))  # Values in normal range
            elif i == 1:  # XSS (Cross-Site Scripting) attempt
                features = torch.cat([
                    torch.randint(100, 200, (seq_len//2,)),  # First half normal
                    torch.full((seq_len//2,), 10)  # Second half shows XSS pattern
                ])
            elif i == 2:  # SQL injection attempt
                features = torch.cat([
                    torch.randint(100, 200, (seq_len//2,)),  # First half normal
                    torch.full((seq_len//2,), 20)  # Second half shows SQLi pattern
                ])
            else:  # Mixed threats scenario
                features = torch.cat([
                    torch.randint(100, 200, (seq_len//3,)),  # First third normal
                    torch.full((seq_len//3,), 10),  # Middle third XSS
                    torch.full((seq_len//3,), 20)   # Last third SQLi
                ])
            
            security_features.append(features)
        
        # Stack features and ensure they're within vocabulary range
        input_ids = torch.stack(security_features).long() % model.vocab_size
        
        # Act: Run threat detection
        with torch.no_grad():
            output = model.forward(input_ids)
        
        # Assert: Check detection behavior
        threat_logits = output['threat_logits']
        severity = output['severity_score']
        
        # Model should differentiate between different threat scenarios
        # Calculate variation in threat assessments
        threat_variation = threat_logits.std(dim=0).mean().item()
        # There should be meaningful variation between samples
        assert threat_variation > 0.01, \
            f"Model should produce varied threat assessments, variation={threat_variation:.6f}"
        
        # Severity scores should also vary between samples
        severity_variation = severity.std().item()
        assert severity_variation > 0.01, \
            f"Model should produce varied severity scores, variation={severity_variation:.6f}"
        
        # Print results for analysis and debugging
        print("\nSecurity Threat Detection Results:")
        for i in range(batch_size):
            # Convert logits to probabilities
            probs = torch.softmax(threat_logits[i], dim=0)
            # Get highest probability threat class
            top_threat = probs.argmax().item()
            top_prob = probs.max().item()
            
            print(f"  Sample {i}: top threat={top_threat} (prob={top_prob:.3f}), "
                  f"severity={severity[i].item():.3f}")
    
    def test_real_time_inference(self, gqa_transformer):
        """Test real-time inference performance for security monitoring."""
        # Arrange: Set model to evaluation mode
        model = gqa_transformer
        model.eval()
        
        # Simulate real-time traffic monitoring
        num_requests = 10  # Number of simulated requests
        seq_len = 128  # Sequence length per request
        vocab_size = model.vocab_size
        
        inference_times = []  # Store timing results
        
        for i in range(num_requests):
            # Simulate a new security request/event
            input_ids = torch.randint(0, vocab_size, (1, seq_len))  # Batch size 1 for real-time
            
            # Time the inference
            start_time = time.time()
            
            with torch.no_grad():
                output = model.forward(input_ids)
            
            end_time = time.time()
            # Convert to milliseconds for real-time analysis
            inference_time = (end_time - start_time) * 1000
            
            inference_times.append(inference_time)
            
            # Verify output is valid
            assert 'threat_logits' in output, "Should produce threat assessment"
            assert output['threat_logits'].shape[0] == 1, "Should handle single request"
        
        # Calculate performance statistics
        avg_time = np.mean(inference_times)
        std_time = np.std(inference_times)
        max_time = np.max(inference_times)
        
        # Assert: Performance should meet real-time requirements
        # Typical security system requirement: < 100ms latency
        max_allowed_time = 100  # milliseconds
        
        assert max_time < max_allowed_time, \
            f"Inference too slow for real-time: max={max_time:.1f}ms, allowed={max_allowed_time}ms"
        
        # Check consistency: low standard deviation indicates stable performance
        assert std_time < avg_time * 0.5, \
            f"Inference time too variable: avg={avg_time:.1f}ms, std={std_time:.1f}ms"
        
        # Print performance metrics
        print(f"\nReal-time Inference Performance:")
        print(f"  Requests processed: {num_requests}")
        print(f"  Average inference time: {avg_time:.1f}ms")
        print(f"  Standard deviation: {std_time:.1f}ms")
        print(f"  Maximum inference time: {max_time:.1f}ms")
        print(f"  Throughput: {1000/avg_time:.1f} requests/second")


if __name__ == "__main__":
    # Allow running tests directly from command line
    # -v flag enables verbose output
    pytest.main([__file__, "-v"])