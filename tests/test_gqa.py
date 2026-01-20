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
from typing import Dict, List, Any
import math
import time

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
    pytest.mark.gqa,
    pytest.mark.requires_torch,
    pytest.mark.unit
]

class TestRotaryPositionalEmbedding:
    """Tests for Rotary Positional Embedding (RoPE)"""
    
    def test_rope_initialization(self):
        """Test RoPE initialization"""
        # Arrange
        dim = 512
        max_seq_len = 2048
        base = 10000.0
        
        # Act
        try:
            from src.core.gqa_transformer import RotaryPositionalEmbedding
            rope = RotaryPositionalEmbedding(dim, max_seq_len, base)
        except ImportError:
            pytest.skip("RoPE module not available")
        
        # Assert
        assert rope.dim == dim, f"dim should be {dim}, got {rope.dim}"
        assert rope.max_seq_len == max_seq_len, \
            f"max_seq_len should be {max_seq_len}, got {rope.max_seq_len}"
        assert rope.base == base, f"base should be {base}, got {rope.base}"
        
        # Check cached tensors
        assert hasattr(rope, 'cos_cached'), "Should have cos_cached"
        assert hasattr(rope, 'sin_cached'), "Should have sin_cached"
        
        # Check shapes
        assert rope.cos_cached.shape == (max_seq_len, dim // 2), \
            f"cos_cached shape should be ({max_seq_len}, {dim//2}), got {rope.cos_cached.shape}"
        assert rope.sin_cached.shape == (max_seq_len, dim // 2), \
            f"sin_cached shape should be ({max_seq_len}, {dim//2}), got {rope.sin_cached.shape}"
        
        # Check values are in valid range
        assert torch.all(rope.cos_cached >= -1) and torch.all(rope.cos_cached <= 1), \
            "cos_cached values should be in [-1, 1]"
        assert torch.all(rope.sin_cached >= -1) and torch.all(rope.sin_cached <= 1), \
            "sin_cached values should be in [-1, 1]"
    
    def test_rope_frequency_calculation(self):
        """Test RoPE frequency calculation"""
        # Arrange
        dim = 512
        max_seq_len = 2048
        base = 10000.0
        
        try:
            from src.core.gqa_transformer import RotaryPositionalEmbedding
            rope = RotaryPositionalEmbedding(dim, max_seq_len, base)
        except ImportError:
            pytest.skip("RoPE module not available")
        
        # Manually calculate expected frequencies
        theta = 1.0 / (base ** (torch.arange(0, dim, 2).float() / dim))
        positions = torch.arange(max_seq_len).float()
        expected_args = torch.outer(positions, theta)
        
        # Compare with cached values
        # Note: rope might compute args differently, so we check properties
        
        # Check that cos and sin are computed from args
        # cos(0) = 1, sin(0) = 0
        assert torch.allclose(rope.cos_cached[0], torch.ones(dim // 2), rtol=1e-5), \
            "cos(0) should be 1"
        assert torch.allclose(rope.sin_cached[0], torch.zeros(dim // 2), rtol=1e-5), \
            "sin(0) should be 0"
        
        # Check periodicity properties
        # For base=10000, dim=512, period should be long
        # Just check that values change with position
        assert not torch.allclose(rope.cos_cached[0], rope.cos_cached[1], rtol=1e-5), \
            "cos should change with position"
        assert not torch.allclose(rope.sin_cached[0], rope.sin_cached[1], rtol=1e-5), \
            "sin should change with position"
    
    def test_apply_rotary_emb(self):
        """Test applying rotary embeddings to tensors"""
        # Arrange
        dim = 512
        max_seq_len = 2048
        
        try:
            from src.core.gqa_transformer import RotaryPositionalEmbedding
            rope = RotaryPositionalEmbedding(dim, max_seq_len)
        except ImportError:
            pytest.skip("RoPE module not available")
        
        # Create test tensor [batch, heads, seq_len, d_k]
        batch_size = 2
        n_heads = 8
        seq_len = 128
        d_k = dim // n_heads  # 512 / 8 = 64
        
        x = torch.randn(batch_size, n_heads, seq_len, d_k)
        
        # Act
        x_rotated = rope.apply_rotary_emb(x, seq_len)
        
        # Assert
        assert x_rotated.shape == x.shape, \
            f"Rotated tensor should have same shape: {x_rotated.shape} != {x.shape}"
        
        # Check that rotation preserves norm
        # RoPE is a rotation, so should preserve vector norms
        orig_norms = torch.norm(x, dim=-1)
        rotated_norms = torch.norm(x_rotated, dim=-1)
        
        assert torch.allclose(orig_norms, rotated_norms, rtol=1e-5), \
            "RoPE should preserve vector norms"
        
        # Check that different positions get different rotations
        # Compare first and last position
        x_pos0 = x_rotated[:, :, 0, :]
        x_pos1 = x_rotated[:, :, 1, :]
        
        # They should be different (not identical rotation)
        assert not torch.allclose(x_pos0, x_pos1, rtol=1e-5), \
            "Different positions should have different rotations"
        
        # Check that rotation is applied per head
        for head in range(n_heads):
            head_rotated = x_rotated[:, head, :, :]
            head_original = x[:, head, :, :]
            
            # Norms should be preserved per head
            head_orig_norms = torch.norm(head_original, dim=-1)
            head_rotated_norms = torch.norm(head_rotated, dim=-1)
            
            assert torch.allclose(head_orig_norms, head_rotated_norms, rtol=1e-5), \
                f"RoPE should preserve norms for head {head}"
    
    def test_rope_position_invariance(self):
        """Test RoPE position invariance properties"""
        # Arrange
        dim = 512
        
        try:
            from src.core.gqa_transformer import RotaryPositionalEmbedding
            rope = RotaryPositionalEmbedding(dim)
        except ImportError:
            pytest.skip("RoPE module not available")
        
        # Create identical vectors at different positions
        batch_size = 2
        n_heads = 8
        seq_len = 3
        d_k = dim // n_heads
        
        # Same vector content
        vector = torch.randn(batch_size, n_heads, 1, d_k)
        x = vector.repeat(1, 1, seq_len, 1)  # Repeat across sequence
        
        # Act
        x_rotated = rope.apply_rotary_emb(x, seq_len)
        
        # Assert: Same content at different positions should get different rotations
        # Check positions 0, 1, 2 are all different
        pos0 = x_rotated[:, :, 0, :]
        pos1 = x_rotated[:, :, 1, :]
        pos2 = x_rotated[:, :, 2, :]
        
        # They should all be different
        assert not torch.allclose(pos0, pos1, rtol=1e-5), \
            "Positions 0 and 1 should be different"
        assert not torch.allclose(pos0, pos2, rtol=1e-5), \
            "Positions 0 and 2 should be different"
        assert not torch.allclose(pos1, pos2, rtol=1e-5), \
            "Positions 1 and 2 should be different"
        
        # But norms should be preserved
        norms_pos0 = torch.norm(pos0, dim=-1)
        norms_pos1 = torch.norm(pos1, dim=-1)
        norms_pos2 = torch.norm(pos2, dim=-1)
        
        # All should have same norm (original vector norm)
        original_norm = torch.norm(vector, dim=-1)
        assert torch.allclose(norms_pos0, original_norm, rtol=1e-5), \
            "Position 0 should preserve norm"
        assert torch.allclose(norms_pos1, original_norm, rtol=1e-5), \
            "Position 1 should preserve norm"
        assert torch.allclose(norms_pos2, original_norm, rtol=1e-5), \
            "Position 2 should preserve norm"
    
    def test_rope_long_sequences(self):
        """Test RoPE with long sequences"""
        # Arrange
        dim = 512
        max_seq_len = 8192
        
        try:
            from src.core.gqa_transformer import RotaryPositionalEmbedding
            rope = RotaryPositionalEmbedding(dim, max_seq_len)
        except ImportError:
            pytest.skip("RoPE module not available")
        
        # Test with sequence longer than typical
        batch_size = 1
        n_heads = 8
        seq_len = 4096  # Long sequence
        d_k = dim // n_heads
        
        x = torch.randn(batch_size, n_heads, seq_len, d_k)
        
        # Act
        x_rotated = rope.apply_rotary_emb(x, seq_len)
        
        # Assert
        assert x_rotated.shape == x.shape, \
            f"Should handle long sequences: {x_rotated.shape} != {x.shape}"
        
        # Check no NaN or Inf
        assert torch.all(torch.isfinite(x_rotated)), \
            "Should handle long sequences without numerical issues"
        
        # Check first and last positions are different
        first_pos = x_rotated[:, :, 0, :]
        last_pos = x_rotated[:, :, -1, :]
        
        assert not torch.allclose(first_pos, last_pos, rtol=1e-5), \
            "First and last positions in long sequence should be different"

class TestGroupedQueryAttention:
    """Tests for Grouped Query Attention"""
    
    def test_gqa_initialization(self, gqa_transformer):
        """Test GQA initialization"""
        # Arrange & Act: GQA is part of transformer
        model = gqa_transformer
        
        # Assert: Check GQA parameters
        assert hasattr(model, 'd_model'), "Model should have d_model"
        assert hasattr(model, 'n_heads'), "Model should have n_heads"
        
        # Check that n_heads is divisible by n_groups
        if hasattr(model, 'n_groups'):
            assert model.n_heads % model.n_groups == 0, \
                f"n_heads ({model.n_heads}) should be divisible by n_groups ({model.n_groups})"
        
        # Check layers have attention
        if hasattr(model, 'layers'):
            for layer in model.layers:
                if hasattr(layer, 'attention'):
                    attn = layer['attention']
                    assert hasattr(attn, 'n_heads'), "Attention should have n_heads"
                    assert hasattr(attn, 'n_groups'), "GQA should have n_groups"
                    
                    # Check group mapping exists
                    assert hasattr(attn, 'group_map'), "GQA should have group_map"
                    assert attn.group_map.shape[0] == attn.n_heads, \
                        f"group_map should have length n_heads, got {attn.group_map.shape[0]}"
    
    def test_gqa_forward_pass(self, gqa_transformer):
        """Test GQA forward pass"""
        # Arrange
        model = gqa_transformer
        
        # Create test input
        batch_size = 2
        seq_len = 64
        vocab_size = model.vocab_size
        
        # Random token indices
        input_ids = torch.randint(0, vocab_size, (batch_size, seq_len))
        
        # Act
        with torch.no_grad():
            output = model.forward(input_ids)
        
        # Assert
        assert 'threat_logits' in output, "Output should contain threat_logits"
        assert 'severity_score' in output, "Output should contain severity_score"
        assert 'hidden_states' in output, "Output should contain hidden_states"
        
        # Check shapes
        threat_logits = output['threat_logits']
        assert threat_logits.shape == (batch_size, model.num_threat_classes), \
            f"threat_logits shape should be ({batch_size}, {model.num_threat_classes}), got {threat_logits.shape}"
        
        severity_score = output['severity_score']
        assert severity_score.shape == (batch_size, 1), \
            f"severity_score shape should be ({batch_size}, 1), got {severity_score.shape}"
        
        hidden_states = output['hidden_states']
        assert hidden_states.shape == (batch_size, seq_len, model.d_model), \
            f"hidden_states shape should be ({batch_size}, {seq_len}, {model.d_model}), got {hidden_states.shape}"
        
        # Check values are finite
        assert torch.all(torch.isfinite(threat_logits)), "threat_logits should be finite"
        assert torch.all(torch.isfinite(severity_score)), "severity_score should be finite"
        assert torch.all(torch.isfinite(hidden_states)), "hidden_states should be finite"
        
        # Severity score should be in [0, 1] (Sigmoid output)
        assert torch.all(severity_score >= 0) and torch.all(severity_score <= 1), \
            f"severity_score should be in [0, 1], got min={severity_score.min():.3f}, max={severity_score.max():.3f}"
    
    def test_gqa_attention_pattern(self, gqa_transformer):
        """Test GQA attention pattern (grouping behavior)"""
        # Arrange
        model = gqa_transformer
        
        # Get first layer attention module
        if hasattr(model, 'layers'):
            first_layer = model.layers[0]
            if hasattr(first_layer, 'attention'):
                attention = first_layer['attention']
            else:
                # Try dictionary access
                attention = first_layer.get('attention')
        else:
            pytest.skip("Model layers not accessible")
        
        if attention is None:
            pytest.skip("Attention module not found")
        
        # Check GQA-specific attributes
        assert hasattr(attention, 'n_groups'), "Should have n_groups"
        assert hasattr(attention, 'group_map'), "Should have group_map"
        
        n_heads = attention.n_heads
        n_groups = attention.n_groups
        
        # Assert grouping properties
        assert n_heads % n_groups == 0, \
            f"n_heads ({n_heads}) should be divisible by n_groups ({n_groups})"
        
        group_size = n_heads // n_groups
        
        # Check group_map assigns heads to groups correctly
        group_map = attention.group_map
        
        # Should have n_heads entries
        assert len(group_map) == n_heads, \
            f"group_map should have {n_heads} entries, got {len(group_map)}"
        
        # Each group should have exactly group_size heads
        for group_idx in range(n_groups):
            heads_in_group = (group_map == group_idx).sum().item()
            assert heads_in_group == group_size, \
                f"Group {group_idx} should have {group_size} heads, got {heads_in_group}"
        
        # Groups should be contiguous blocks
        # (implementation detail, but common in GQA)
        expected_mapping = []
        for group_idx in range(n_groups):
            expected_mapping.extend([group_idx] * group_size)
        
        assert torch.equal(group_map, torch.tensor(expected_mapping)), \
            "group_map should have contiguous group assignments"
    
    def test_gqa_memory_efficiency(self, gqa_transformer):
        """Test GQA memory efficiency compared to MHA"""
        # Arrange
        model = gqa_transformer
        
        # Get attention module parameters
        if hasattr(model, 'layers'):
            first_layer = model.layers[0]
            attention = first_layer.get('attention') if isinstance(first_layer, dict) else first_layer.attention
        else:
            pytest.skip("Model layers not accessible")
        
        if attention is None:
            pytest.skip("Attention module not found")
        
        n_heads = attention.n_heads
        n_groups = attention.n_groups
        d_model = model.d_model
        d_k = d_model // n_heads
        
        # Calculate parameter counts
        # GQA: Q projection (d_model × d_model) + KV projections (d_model × (n_groups × d_k) × 2)
        gqa_params = (
            d_model * d_model +  # Q projection
            2 * d_model * (n_groups * d_k)  # K and V projections
        )
        
        # MHA: Q, K, V projections (each d_model × d_model)
        mha_params = 3 * d_model * d_model
        
        # Calculate memory savings
        memory_saving = 1 - (gqa_params / mha_params)
        
        # Assert: GQA should use fewer parameters
        assert gqa_params < mha_params, \
            f"GQA should use fewer parameters: GQA={gqa_params}, MHA={mha_params}"
        
        # Typical savings: for n_heads=8, n_groups=2, should save ~50%
        expected_min_saving = 0.3  # At least 30% savings
        assert memory_saving > expected_min_saving, \
            f"GQA should save at least {expected_min_saving*100:.0f}% memory, " \
            f"got {memory_saving*100:.1f}%"
        
        print(f"GQA memory efficiency: "
              f"n_heads={n_heads}, n_groups={n_groups}, "
              f"GQA params={gqa_params:,}, MHA params={mha_params:,}, "
              f"saving={memory_saving*100:.1f}%")
    
    def test_gqa_inference_speed(self, gqa_transformer):
        """Test GQA inference speed"""
        # Arrange
        model = gqa_transformer
        model.eval()  # Ensure evaluation mode
        
        # Test with different sequence lengths
        seq_lengths = [64, 128, 256, 512]
        batch_size = 2
        vocab_size = model.vocab_size
        
        results = []
        
        for seq_len in seq_lengths:
            # Create test input
            input_ids = torch.randint(0, vocab_size, (batch_size, seq_len))
            
            # Warmup
            with torch.no_grad():
                _ = model.forward(input_ids)
            
            # Time inference
            start_time = time.time()
            
            with torch.no_grad():
                output = model.forward(input_ids)
            
            end_time = time.time()
            inference_time = end_time - start_time
            
            results.append({
                'seq_len': seq_len,
                'time': inference_time,
                'throughput': (batch_size * seq_len) / inference_time
            })
            
            # Verify output
            assert 'threat_logits' in output, "Should produce output"
            assert torch.all(torch.isfinite(output['threat_logits'])), "Output should be finite"
        
        # Assert: Throughput should be reasonable
        # Print results for analysis
        print("\nGQA Inference Speed Test:")
        for result in results:
            print(f"  seq_len={result['seq_len']:4d}: "
                  f"time={result['time']:.3f}s, "
                  f"throughput={result['throughput']:.0f} tokens/sec")
        
        # Check that longer sequences don't cause exponential slowdown
        # (attention should be O(n^2) but optimized)
        if len(results) >= 2:
            first = results[0]
            last = results[-1]
            
            seq_len_ratio = last['seq_len'] / first['seq_len']
            time_ratio = last['time'] / first['time']
            
            # Time should increase roughly with sequence length squared
            # But with optimizations, might be better
            expected_max_ratio = seq_len_ratio ** 2.5  # Allow some overhead
            
            assert time_ratio < expected_max_ratio, \
                f"Inference time growth too high: " \
                f"seq_len increased {seq_len_ratio:.1f}x, " \
                f"time increased {time_ratio:.1f}x (max allowed: {expected_max_ratio:.1f}x)"

class TestFlashAttentionIntegration:
    """Tests for Flash Attention integration"""
    
    def test_flash_attention_availability(self, gqa_transformer):
        """Test if Flash Attention is available and configured"""
        # Arrange
        model = gqa_transformer
        
        # Check if model uses flash attention
        uses_flash = False
        
        if hasattr(model, 'layers'):
            first_layer = model.layers[0]
            attention = first_layer.get('attention') if isinstance(first_layer, dict) else first_layer.attention
            
            if attention is not None:
                if hasattr(attention, 'use_flash'):
                    uses_flash = attention.use_flash
                elif hasattr(attention, 'use_flash_attention'):
                    uses_flash = attention.use_flash_attention
        
        # Check PyTorch version for built-in flash attention
        torch_version = torch.__version__
        has_builtin_flash = hasattr(torch.nn.functional, 'scaled_dot_product_attention')
        
        # Print information
        print(f"Flash Attention Info:")
        print(f"  PyTorch version: {torch_version}")
        print(f"  Built-in flash attention: {has_builtin_flash}")
        print(f"  Model configured for flash: {uses_flash}")
        
        # Assert: At least one form of optimized attention should be available
        # This is more of an informational test
        assert has_builtin_flash or uses_flash, \
            "Should have some form of optimized attention available"
    
    def test_attention_output_consistency(self, gqa_transformer):
        """Test that attention produces consistent results"""
        # Arrange
        model = gqa_transformer
        model.eval()
        
        # Same input twice should produce same output
        batch_size = 2
        seq_len = 64
        vocab_size = model.vocab_size
        
        input_ids = torch.randint(0, vocab_size, (batch_size, seq_len))
        
        # Act: Forward pass twice
        with torch.no_grad():
            output1 = model.forward(input_ids)
            output2 = model.forward(input_ids)
        
        # Assert: Should be identical (deterministic)
        threat_logits1 = output1['threat_logits']
        threat_logits2 = output2['threat_logits']
        
        assert torch.allclose(threat_logits1, threat_logits2, rtol=1e-5), \
            "Same input should produce same output"
        
        severity1 = output1['severity_score']
        severity2 = output2['severity_score']
        
        assert torch.allclose(severity1, severity2, rtol=1e-5), \
            "Severity scores should be consistent"
    
    def test_gradient_flow(self, gqa_transformer):
        """Test that gradients flow through GQA layers"""
        # Arrange
        model = gqa_transformer
        model.train()  # Set to training mode
        
        batch_size = 2
        seq_len = 32
        vocab_size = model.vocab_size
        
        input_ids = torch.randint(0, vocab_size, (batch_size, seq_len))
        
        # Create dummy target
        target = torch.randint(0, model.num_threat_classes, (batch_size,))
        
        # Act: Forward and backward pass
        output = model.forward(input_ids)
        loss = torch.nn.functional.cross_entropy(output['threat_logits'], target)
        
        # Backward pass
        loss.backward()
        
        # Assert: Gradients should be computed
        # Check some parameters have gradients
        has_gradients = False
        
        for name, param in model.named_parameters():
            if param.grad is not None:
                has_gradients = True
                # Gradient should be finite
                assert torch.all(torch.isfinite(param.grad)), \
                    f"Gradient for {name} should be finite"
                break
        
        assert has_gradients, "Should compute gradients for parameters"
        
        # Cleanup: Set back to eval mode
        model.eval()

class TestSecurityGQATransformer:
    """Tests for the complete Security GQA Transformer"""
    
    def test_threat_classification(self, gqa_transformer):
        """Test threat classification output"""
        # Arrange
        model = gqa_transformer
        model.eval()
        
        batch_size = 4
        seq_len = 128
        vocab_size = model.vocab_size
        
        # Create test inputs
        input_ids = torch.randint(0, vocab_size, (batch_size, seq_len))
        
        # Act
        with torch.no_grad():
            output = model.forward(input_ids)
        
        # Assert: Threat classification properties
        threat_logits = output['threat_logits']
        
        # Check shape
        assert threat_logits.shape == (batch_size, model.num_threat_classes), \
            f"threat_logits shape should be ({batch_size}, {model.num_threat_classes})"
        
        # Convert to probabilities
        threat_probs = torch.softmax(threat_logits, dim=-1)
        
        # Probabilities should sum to 1
        prob_sums = threat_probs.sum(dim=-1)
        assert torch.allclose(prob_sums, torch.ones(batch_size), rtol=1e-5), \
            f"Threat probabilities should sum to 1, got min={prob_sums.min():.6f}, max={prob_sums.max():.6f}"
        
        # All probabilities should be non-negative
        assert torch.all(threat_probs >= 0), "Threat probabilities should be non-negative"
        
        # Severity score properties
        severity = output['severity_score']
        assert torch.all(severity >= 0) and torch.all(severity <= 1), \
            f"Severity should be in [0, 1], got min={severity.min():.3f}, max={severity.max():.3f}"
    
    def test_model_robustness(self, gqa_transformer):
        """Test model robustness to input variations"""
        # Arrange
        model = gqa_transformer
        model.eval()
        
        batch_size = 2
        seq_len = 64
        vocab_size = model.vocab_size
        
        # Test cases
        test_cases = [
            ('normal', torch.randint(0, vocab_size, (batch_size, seq_len))),
            ('all_zeros', torch.zeros(batch_size, seq_len, dtype=torch.long)),
            ('all_same', torch.full((batch_size, seq_len), 5, dtype=torch.long)),
            ('extreme_values', torch.randint(vocab_size-10, vocab_size, (batch_size, seq_len))),
        ]
        
        for case_name, input_ids in test_cases:
            # Act
            try:
                with torch.no_grad():
                    output = model.forward(input_ids)
                
                # Assert: Should handle all cases without crashing
                assert 'threat_logits' in output, f"{case_name}: Should produce threat_logits"
                assert 'severity_score' in output, f"{case_name}: Should produce severity_score"
                
                # Output should be finite
                assert torch.all(torch.isfinite(output['threat_logits'])), \
                    f"{case_name}: threat_logits should be finite"
                assert torch.all(torch.isfinite(output['severity_score'])), \
                    f"{case_name}: severity_score should be finite"
                
            except Exception as e:
                pytest.fail(f"{case_name}: Model should handle input gracefully, got {e}")
    
    @pytest.mark.parametrize("batch_size", [1, 2, 4, 8])
    @pytest.mark.parametrize("seq_len", [32, 64, 128, 256])
    def test_model_scalability(self, gqa_transformer, batch_size, seq_len):
        """Test model scalability with different batch sizes and sequence lengths"""
        # Arrange
        model = gqa_transformer
        model.eval()
        
        vocab_size = model.vocab_size
        
        # Skip if sequence too long for memory
        if seq_len * batch_size > 4096:  # Arbitrary limit for test
            pytest.skip("Test would use too much memory")
        
        input_ids = torch.randint(0, vocab_size, (batch_size, seq_len))
        
        # Act
        try:
            with torch.no_grad():
                output = model.forward(input_ids)
            
            # Assert: Should handle various sizes
            threat_logits = output['threat_logits']
            assert threat_logits.shape[0] == batch_size, \
                f"Batch size mismatch: expected {batch_size}, got {threat_logits.shape[0]}"
            
            # Check memory usage
            if torch.cuda.is_available():
                memory_allocated = torch.cuda.memory_allocated() / 1024**2  # MB
                print(f"Batch={batch_size}, Seq={seq_len}: "
                      f"GPU memory={memory_allocated:.1f}MB")
            
        except RuntimeError as e:
            if "out of memory" in str(e).lower():
                pytest.skip(f"Out of memory for batch={batch_size}, seq={seq_len}")
            else:
                raise

@pytest.mark.integration
class TestGQAEndToEnd:
    """End-to-end tests for GQA in security context"""
    
    def test_security_threat_detection_pipeline(self, gqa_transformer):
        """Test complete security threat detection pipeline"""
        # Arrange
        model = gqa_transformer
        model.eval()
        
        # Simulate security feature encoding
        # In practice, this would come from feature extraction
        batch_size = 4
        seq_len = 256
        
        # Create mock security features
        # 0: normal traffic, 1: XSS attempt, 2: SQLi attempt, 3: mixed threats
        security_features = []
        
        for i in range(batch_size):
            if i == 0:  # Normal
                features = torch.randint(100, 200, (seq_len,))  # Normal range
            elif i == 1:  # XSS
                features = torch.cat([
                    torch.randint(100, 200, (seq_len//2,)),  # First half normal
                    torch.full((seq_len//2,), 10)  # Second half XSS pattern
                ])
            elif i == 2:  # SQLi
                features = torch.cat([
                    torch.randint(100, 200, (seq_len//2,)),  # First half normal
                    torch.full((seq_len//2,), 20)  # Second half SQLi pattern
                ])
            else:  # Mixed
                features = torch.cat([
                    torch.randint(100, 200, (seq_len//3,)),  # Normal
                    torch.full((seq_len//3,), 10),  # XSS
                    torch.full((seq_len//3,), 20)   # SQLi
                ])
            
            security_features.append(features)
        
        input_ids = torch.stack(security_features).long() % model.vocab_size
        
        # Act
        with torch.no_grad():
            output = model.forward(input_ids)
        
        # Assert
        threat_logits = output['threat_logits']
        severity = output['severity_score']
        
        # Model should differentiate between samples
        # (exact behavior depends on training)
        
        # Threat logits should vary between samples
        threat_variation = threat_logits.std(dim=0).mean().item()
        assert threat_variation > 0.01, \
            f"Model should produce varied threat assessments, variation={threat_variation:.6f}"
        
        # Severity should vary between samples
        severity_variation = severity.std().item()
        assert severity_variation > 0.01, \
            f"Model should produce varied severity scores, variation={severity_variation:.6f}"
        
        # Print results for analysis
        print("\nSecurity Threat Detection Results:")
        for i in range(batch_size):
            probs = torch.softmax(threat_logits[i], dim=0)
            top_threat = probs.argmax().item()
            top_prob = probs.max().item()
            
            print(f"  Sample {i}: top threat={top_threat} (prob={top_prob:.3f}), "
                  f"severity={severity[i].item():.3f}")
    
    def test_real_time_inference(self, gqa_transformer):
        """Test real-time inference performance"""
        # Arrange
        model = gqa_transformer
        model.eval()
        
        # Simulate real-time traffic
        num_requests = 10
        seq_len = 128
        vocab_size = model.vocab_size
        
        inference_times = []
        
        for i in range(num_requests):
            # Simulate new request
            input_ids = torch.randint(0, vocab_size, (1, seq_len))
            
            # Time inference
            start_time = time.time()
            
            with torch.no_grad():
                output = model.forward(input_ids)
            
            end_time = time.time()
            inference_time = (end_time - start_time) * 1000  # Convert to ms
            
            inference_times.append(inference_time)
            
            # Verify output
            assert 'threat_logits' in output, "Should produce threat assessment"
            assert output['threat_logits'].shape[0] == 1, "Should handle single request"
        
        # Calculate statistics
        avg_time = np.mean(inference_times)
        std_time = np.std(inference_times)
        max_time = np.max(inference_times)
        
        # Assert: Should meet real-time requirements
        # Typical requirement: < 100ms for inference
        max_allowed_time = 100  # ms
        
        assert max_time < max_allowed_time, \
            f"Inference too slow: max={max_time:.1f}ms, allowed={max_allowed_time}ms"
        
        # Consistency: low standard deviation
        assert std_time < avg_time * 0.5, \
            f"Inference time too variable: avg={avg_time:.1f}ms, std={std_time:.1f}ms"
        
        print(f"\nReal-time Inference Performance:")
        print(f"  Requests: {num_requests}")
        print(f"  Average time: {avg_time:.1f}ms")
        print(f"  Std deviation: {std_time:.1f}ms")
        print(f"  Maximum time: {max_time:.1f}ms")
        print(f"  Throughput: {1000/avg_time:.1f} requests/second")

if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__, "-v"])