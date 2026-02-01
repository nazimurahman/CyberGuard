# src/core/gqa_transformer.py
"""
Grouped Query Attention (GQA) Transformer with Flash Attention and Rotary Positional Embeddings

This module implements an optimized transformer architecture specifically designed for:
1. Memory efficiency through grouped query attention
2. High performance with Flash Attention
3. Long sequence handling with Rotary Positional Embeddings (RoPE)
4. Security threat analysis specialization

Key Innovations:
- GQA: Reduces KV cache memory by 75% compared to Multi-Head Attention
- Flash Attention: Optimized attention computation using IO-aware algorithms
- RoPE: Relative positional encoding that handles long sequences better than absolute encoding

Security Benefits:
- Efficient processing of long HTTP headers and request bodies
- Real-time analysis without memory bottlenecks
- Stable attention across variable-length security logs
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import math
from typing import Optional, Tuple, Dict, List, Union
import warnings
import time  # Added import for time module


class RotaryPositionalEmbedding(nn.Module):
    """
    Rotary Positional Embedding (RoPE)
    
    Advantages over traditional positional encoding:
    1. Relative position awareness (better for variable-length sequences)
    2. Distance decay naturally encoded in rotations
    3. No sequence length limit (unlike learned positional embeddings)
    4. Works well with Flash Attention
    
    Mathematical foundation:
    For position m and embedding dimension i:
    RoPE(x, m) = [x1 cos(mθ) - x2 sin(mθ), x1 sin(mθ) + x2 cos(mθ)]
    where θ = 10000^(-2i/d_model)
    
    Security application: Handles variable-length attack payloads and logs
    """
    
    def __init__(self, dim: int, max_seq_len: int = 8192, base: float = 10000.0,
                 device: Optional[torch.device] = None, dtype: Optional[torch.dtype] = None):
        """
        Initialize RoPE
        
        Args:
            dim: Embedding dimension (must be even)
            max_seq_len: Maximum sequence length to precompute
            base: Base for frequency calculation (controls rotation speed)
            device: Target device for computations
            dtype: Data type for computations
        
        Example:
            >>> rope = RotaryPositionalEmbedding(dim=512, max_seq_len=2048)
        """
        super().__init__()
        
        if dim % 2 != 0:
            raise ValueError(f"dim must be even, got {dim}")
        
        self.dim = dim
        self.max_seq_len = max_seq_len
        self.base = base
        
        # Precompute theta values for each dimension pair
        # θ_i = base^(-2i/dim) for i in [0, 2, 4, ..., dim-2]
        theta = 1.0 / (self.base ** (torch.arange(0, self.dim, 2, dtype=torch.float32) / self.dim))
        
        # Create position indices [0, 1, 2, ..., max_seq_len-1]
        positions = torch.arange(self.max_seq_len, dtype=torch.float32)
        
        # Outer product: position × theta
        # args[m, i] = m * θ_i
        args = torch.outer(positions, theta)
        
        # Precompute cosine and sine values
        # We'll cache these for efficiency
        cos_cached = torch.cos(args)
        sin_cached = torch.sin(args)
        
        # Register as buffers (not trainable parameters)
        self.register_buffer('cos_cached', cos_cached, persistent=False)
        self.register_buffer('sin_cached', sin_cached, persistent=False)
        
        # For backward compatibility with different devices/dtypes
        if device is not None:
            self.cos_cached = self.cos_cached.to(device)
            self.sin_cached = self.sin_cached.to(device)
        
        if dtype is not None:
            self.cos_cached = self.cos_cached.to(dtype)
            self.sin_cached = self.sin_cached.to(dtype)
    
    def forward(self, x: torch.Tensor, seq_len: Optional[int] = None) -> torch.Tensor:
        """
        Apply rotary positional embeddings to input tensor
        
        Args:
            x: Input tensor of shape [batch_size, num_heads, seq_len, head_dim]
            seq_len: Optional sequence length (if None, uses x.shape[2])
        
        Returns:
            torch.Tensor: Position-aware tensor with same shape as input
        
        Example:
            >>> x = torch.randn(2, 8, 128, 64)  # [batch, heads, seq_len, head_dim]
            >>> x_rotated = rope(x)
        """
        batch_size, num_heads, seq_len_x, head_dim = x.shape
        
        if seq_len is None:
            seq_len = seq_len_x
        
        # Validate dimensions
        if head_dim != self.dim:
            raise ValueError(f"head_dim ({head_dim}) must match RoPE dim ({self.dim})")
        
        if seq_len > self.max_seq_len:
            warnings.warn(
                f"Sequence length {seq_len} exceeds precomputed max {self.max_seq_len}. "
                f"Consider increasing max_seq_len during initialization.",
                UserWarning
            )
        
        # Get precomputed sin/cos for this sequence length
        # Shape: [seq_len, head_dim//2]
        cos = self.cos_cached[:seq_len, :head_dim//2]
        sin = self.sin_cached[:seq_len, :head_dim//2]
        
        # Reshape input for rotary transformation
        # [batch, heads, seq_len, head_dim] -> [batch, heads, seq_len, head_dim//2, 2]
        x_reshaped = x.view(batch_size, num_heads, seq_len, head_dim // 2, 2)
        
        # Split into real and imaginary parts (or x and y coordinates)
        x1 = x_reshaped[..., 0]  # Real part / x-coordinate
        x2 = x_reshaped[..., 1]  # Imaginary part / y-coordinate
        
        # Expand sin/cos for broadcasting
        # Add dimensions for batch and heads
        cos = cos.unsqueeze(0).unsqueeze(0)  # [1, 1, seq_len, head_dim//2]
        sin = sin.unsqueeze(0).unsqueeze(0)  # [1, 1, seq_len, head_dim//2]
        
        # Apply 2D rotation: (x1, x2) → (x1 cos - x2 sin, x1 sin + x2 cos)
        # This is equivalent to complex multiplication: (x1 + i x2) × (cos + i sin)
        x1_out = x1 * cos - x2 * sin
        x2_out = x1 * sin + x2 * cos
        
        # Stack back together
        out = torch.stack([x1_out, x2_out], dim=-1)
        
        # Reshape to original format
        return out.view(batch_size, num_heads, seq_len, head_dim)
    
    def apply_rotary_emb_qkv(self, q: torch.Tensor, k: torch.Tensor,
                            seq_len: Optional[int] = None) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Apply rotary embeddings to both queries and keys
        
        Security note: Only apply to Q and K, not V
        Position matters for matching queries to keys, but values carry content
        
        Args:
            q: Query tensor [batch, heads, seq_len, head_dim]
            k: Key tensor [batch, heads, seq_len, head_dim]
            seq_len: Optional sequence length
        
        Returns:
            Tuple[torch.Tensor, torch.Tensor]: Rotated queries and keys
        """
        return self.forward(q, seq_len), self.forward(k, seq_len)


class FlashGQA(nn.Module):
    """
    Flash Grouped Query Attention (GQA)
    
    Memory efficiency: Instead of N heads each with separate K/V, we have G groups
    where multiple query heads share the same key/value heads.
    
    Configuration examples:
    - 8 heads, 2 groups: Each group serves 4 query heads
    - 32 heads, 8 groups: Each group serves 4 query heads (Llama 2 style)
    
    Security benefit: Enables analyzing longer attack payloads within memory constraints
    """
    
    def __init__(self, d_model: int, n_heads: int, n_groups: Optional[int] = None,
                 dropout: float = 0.1, use_flash: bool = True, causal: bool = False):
        """
        Initialize Flash GQA
        
        Args:
            d_model: Model dimension (embedding size)
            n_heads: Number of query heads
            n_groups: Number of key/value groups (if None, uses n_heads // 4)
            dropout: Attention dropout probability
            use_flash: Use Flash Attention if available
            causal: Use causal masking (for autoregressive generation)
        
        Example:
            >>> attn = FlashGQA(d_model=512, n_heads=8, n_groups=2)
        """
        super().__init__()
        
        # Validate dimensions
        if d_model % n_heads != 0:
            raise ValueError(f"d_model ({d_model}) must be divisible by n_heads ({n_heads})")
        
        self.d_model = d_model
        self.n_heads = n_heads
        self.d_k = d_model // n_heads  # Dimension per head
        self.dropout = dropout
        self.use_flash = use_flash
        self.causal = causal
        
        # Set default groups if not specified
        if n_groups is None:
            n_groups = max(1, n_heads // 4)  # Common practice: 4 query heads per KV group
        
        self.n_groups = n_groups
        
        # Validate group configuration
        if n_heads % n_groups != 0:
            raise ValueError(f"n_heads ({n_heads}) must be divisible by n_groups ({n_groups})")
        
        self.group_size = n_heads // n_groups  # How many query heads per KV group
        
        # Initialize Rotary Positional Embedding
        # RoPE dimension matches head dimension (d_k)
        self.rope = RotaryPositionalEmbedding(dim=self.d_k)
        
        # Linear projections
        # Query projection: separate for each head
        self.W_q = nn.Linear(d_model, d_model)
        
        # Key/Value projections: shared within groups
        # Each group has its own K/V projection
        self.W_k = nn.Linear(d_model, n_groups * self.d_k)
        self.W_v = nn.Linear(d_model, n_groups * self.d_k)
        
        # Output projection
        self.W_o = nn.Linear(d_model, d_model)
        
        # Group mapping: which query head belongs to which KV group
        # Precompute for efficiency
        self.register_buffer('group_map', self._create_group_map(), persistent=False)
        
        # Flash Attention availability check
        self.flash_available = False
        if self.use_flash:
            self._check_flash_availability()
    
    def _create_group_map(self) -> torch.Tensor:
        """
        Create mapping from query head index to KV group index
        
        Example with 8 heads, 2 groups:
        group_map = [0, 0, 0, 0, 1, 1, 1, 1]
        First 4 query heads use KV group 0, next 4 use KV group 1
        """
        mapping = []
        for group_idx in range(self.n_groups):
            mapping.extend([group_idx] * self.group_size)
        return torch.tensor(mapping, dtype=torch.long)
    
    def _check_flash_availability(self):
        """Check if Flash Attention is available"""
        try:
            # Check for PyTorch 2.0+ Flash Attention
            if hasattr(F, 'scaled_dot_product_attention'):
                self.flash_available = True
            else:
                self.flash_available = False
                warnings.warn(
                    "Flash Attention not available. Falling back to standard attention. "
                    "Consider upgrading to PyTorch 2.0+ for better performance.",
                    UserWarning
                )
        except Exception as e:
            self.flash_available = False
            warnings.warn(f"Flash Attention check failed: {e}")
    
    def forward(self, q: torch.Tensor, k: torch.Tensor, v: torch.Tensor,
                mask: Optional[torch.Tensor] = None,
                kv_cache: Optional[Tuple[torch.Tensor, torch.Tensor]] = None) -> Union[torch.Tensor, Tuple[torch.Tensor, Tuple[torch.Tensor, torch.Tensor]]]:
        """
        Forward pass with optional Flash Attention
        
        Args:
            q: Query tensor [batch_size, seq_len_q, d_model]
            k: Key tensor [batch_size, seq_len_kv, d_model]
            v: Value tensor [batch_size, seq_len_kv, d_model]
            mask: Optional attention mask [batch_size, seq_len_q, seq_len_kv]
            kv_cache: Optional cached keys and values for incremental decoding
        
        Returns:
            torch.Tensor: Attention output [batch_size, seq_len_q, d_model]
            OR Tuple if kv_cache provided: (output, (K, V))
        
        Example:
            >>> q = torch.randn(2, 128, 512)  # [batch, seq_len, d_model]
            >>> k = v = q  # Self-attention
            >>> output = attn(q, k, v)
        """
        batch_size, seq_len_q, _ = q.shape
        seq_len_kv = k.shape[1]
        
        # 1. Linear projections
        # Query: separate projection for each head
        # Shape: [batch, seq_len_q, d_model] -> [batch, seq_len_q, n_heads, d_k]
        Q = self.W_q(q).view(batch_size, seq_len_q, self.n_heads, self.d_k)
        Q = Q.transpose(1, 2)  # [batch, n_heads, seq_len_q, d_k]
        
        # Key/Value: grouped projections
        # Shape: [batch, seq_len_kv, d_model] -> [batch, seq_len_kv, n_groups, d_k]
        K = self.W_k(k).view(batch_size, seq_len_kv, self.n_groups, self.d_k)
        V = self.W_v(v).view(batch_size, seq_len_kv, self.n_groups, self.d_k)
        K = K.transpose(1, 2)  # [batch, n_groups, seq_len_kv, d_k]
        V = V.transpose(1, 2)  # [batch, n_groups, seq_len_kv, d_k]
        
        # Handle KV cache for incremental decoding (useful for real-time analysis)
        if kv_cache is not None:
            K_cache, V_cache = kv_cache
            K = torch.cat([K_cache, K], dim=2)
            V = torch.cat([V_cache, V], dim=2)
            seq_len_kv = K.shape[2]
        
        # 2. Apply Rotary Positional Embedding to Q and K
        # Only apply to Q and K (not V) - position matters for matching
        Q_rotated = self.rope.forward(Q, seq_len_q)
        K_rotated = self.rope.forward(K, seq_len_kv)
        
        # 3. Expand KV heads to match Q heads using group mapping
        # Each KV group is repeated for its corresponding query heads
        # Shape: [batch, n_heads, seq_len_kv, d_k]
        K_expanded = K_rotated[:, self.group_map]
        V_expanded = V[:, self.group_map]  # Use V directly, not V_rotated
        
        # 4. Compute attention
        if self.flash_available and mask is None:
            output = self._flash_attention_pt2(Q_rotated, K_expanded, V_expanded)
        else:
            output = self._standard_attention(Q_rotated, K_expanded, V_expanded, mask)
        
        # 5. Combine heads and project output
        # Shape: [batch, n_heads, seq_len_q, d_k] -> [batch, seq_len_q, d_model]
        output = output.transpose(1, 2).contiguous()
        output = output.view(batch_size, seq_len_q, self.d_model)
        output = self.W_o(output)
        
        # Return output and updated KV cache if provided
        if kv_cache is not None:
            return output, (K, V)
        
        return output
    
    def _flash_attention_pt2(self, Q: torch.Tensor, K: torch.Tensor, V: torch.Tensor) -> torch.Tensor:
        """
        Use PyTorch 2.0+ Flash Attention implementation
        
        Benefits:
        - Memory efficient (no intermediate attention matrix)
        - Faster on supported hardware (GPUs with tensor cores)
        - Numerically stable
        """
        # Enable Flash Attention kernel
        with torch.backends.cuda.sdp_kernel(enable_flash=True, enable_math=False, enable_mem_efficient=False):
            output = F.scaled_dot_product_attention(
                Q, K, V,
                dropout_p=self.dropout if self.training else 0.0,
                is_causal=self.causal,
                scale=1.0 / math.sqrt(self.d_k)
            )
        return output
    
    def _standard_attention(self, Q: torch.Tensor, K: torch.Tensor, V: torch.Tensor,
                           mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        """
        Standard attention implementation (fallback when Flash not available)
        
        Security note: This is less memory efficient but more interpretable
        Useful for debugging and analysis
        """
        # Compute attention scores
        # Q: [batch, n_heads, seq_len_q, d_k]
        # K: [batch, n_heads, seq_len_kv, d_k]
        # scores: [batch, n_heads, seq_len_q, seq_len_kv]
        scores = torch.matmul(Q, K.transpose(-2, -1)) / math.sqrt(self.d_k)
        
        # Apply mask if provided
        if mask is not None:
            # Expand mask for multi-head attention
            if mask.dim() == 2:
                mask = mask.unsqueeze(0).unsqueeze(0)  # [1, 1, seq_len_q, seq_len_kv]
            elif mask.dim() == 3:
                mask = mask.unsqueeze(1)  # [batch, 1, seq_len_q, seq_len_kv]
            
            # Apply mask (usually -inf for masked positions)
            scores = scores.masked_fill(mask == 0, -1e9)
        
        # Apply causal mask if needed (for autoregressive tasks)
        if self.causal:
            causal_mask = torch.triu(
                torch.ones(Q.size(2), K.size(2), device=Q.device, dtype=torch.bool),
                diagonal=1
            )
            scores = scores.masked_fill(causal_mask.unsqueeze(0).unsqueeze(0), -1e9)
        
        # Softmax to get attention weights
        attn_weights = F.softmax(scores, dim=-1)
        
        # Apply dropout during training
        if self.training and self.dropout > 0:
            attn_weights = F.dropout(attn_weights, p=self.dropout)
        
        # Apply attention to values
        # [batch, n_heads, seq_len_q, seq_len_kv] × [batch, n_heads, seq_len_kv, d_k]
        # = [batch, n_heads, seq_len_q, d_k]
        output = torch.matmul(attn_weights, V)
        
        return output
    
    def get_kv_cache_size(self, seq_len: int, dtype: torch.dtype = torch.float16) -> int:
        """
        Calculate KV cache memory usage in bytes
        
        Security application: Helps plan memory for real-time monitoring systems
        
        Args:
            seq_len: Sequence length
            dtype: Data type for KV cache
        
        Returns:
            int: Memory usage in bytes
        """
        # KV cache per layer: 2 * n_groups * seq_len * d_k
        kv_cache_elements = 2 * self.n_groups * seq_len * self.d_k
        
        # Bytes per element based on dtype
        if dtype == torch.float32:
            bytes_per_element = 4
        elif dtype == torch.float16 or dtype == torch.bfloat16:
            bytes_per_element = 2
        elif dtype == torch.int8:
            bytes_per_element = 1
        else:
            bytes_per_element = 2  # Default assumption
        
        return kv_cache_elements * bytes_per_element
    
    def memory_savings_vs_mha(self) -> float:
        """
        Calculate memory savings compared to Multi-Head Attention
        
        Returns:
            float: Percentage reduction in KV cache memory
        """
        mha_memory = 2 * self.n_heads  # MHA: separate KV for each head
        gqa_memory = 2 * self.n_groups  # GQA: shared KV within groups
        return 1.0 - (gqa_memory / mha_memory)


class SecurityGQATransformer(nn.Module):
    """
    Complete GQA Transformer specialized for security threat analysis
    
    Architecture:
    - Input: Security feature embeddings
    - Multiple GQA layers with residual connections
    - Threat classification and severity regression heads
    - Designed for real-time web security analysis
    
    Security features handled:
    - HTTP request/response patterns
    - Attack payload signatures
    - Behavioral anomalies
    - Compliance violations
    """
    
    def __init__(self, vocab_size: int, d_model: int = 512, n_layers: int = 6,
                 n_heads: int = 8, n_groups: Optional[int] = None, 
                 max_seq_len: int = 2048, dropout: float = 0.1,
                 num_threat_classes: int = 10, use_flash: bool = True):
        """
        Initialize Security GQA Transformer
        
        Args:
            vocab_size: Size of security feature vocabulary
            d_model: Model dimension (embedding size)
            n_layers: Number of transformer layers
            n_heads: Number of attention heads
            n_groups: Number of KV groups (if None, uses n_heads // 4)
            max_seq_len: Maximum sequence length
            dropout: Dropout probability
            num_threat_classes: Number of threat types to classify
            use_flash: Use Flash Attention if available
        
        Example:
            >>> model = SecurityGQATransformer(
            ...     vocab_size=10000,
            ...     d_model=512,
            ...     n_layers=6,
            ...     n_heads=8,
            ...     num_threat_classes=10
            ... )
        """
        super().__init__()
        
        self.vocab_size = vocab_size
        self.d_model = d_model
        self.n_layers = n_layers
        self.max_seq_len = max_seq_len
        self.num_threat_classes = num_threat_classes
        
        # 1. Security feature embeddings
        # Each security feature (e.g., "XSS", "SQLi", "CSRF") gets an embedding
        self.threat_embedding = nn.Embedding(vocab_size, d_model)
        
        # 2. Positional embeddings (learned, for compatibility)
        # RoPE handles relative positions, but we also include learned embeddings
        # for absolute position awareness
        self.position_embedding = nn.Embedding(max_seq_len, d_model)
        
        # 3. GQA Transformer layers
        self.layers = nn.ModuleList([
            self._create_gqa_layer(d_model, n_heads, n_groups, dropout, use_flash)
            for _ in range(n_layers)
        ])
        
        # 4. Layer normalization
        self.norm = nn.LayerNorm(d_model)
        
        # 5. Classification head for threat types
        # Output: probabilities for each threat class
        self.threat_classifier = nn.Sequential(
            nn.Linear(d_model, d_model * 2),
            nn.GELU(),  # Gaussian Error Linear Unit (smooth ReLU)
            nn.Dropout(dropout),
            nn.Linear(d_model * 2, num_threat_classes)
        )
        
        # 6. Severity regression head
        # Output: severity score between 0 and 1
        self.severity_regressor = nn.Sequential(
            nn.Linear(d_model, d_model),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(d_model, 1),
            nn.Sigmoid()  # Bound output to [0, 1]
        )
        
        # 7. Confidence estimation head
        # Measures model confidence in its predictions
        self.confidence_estimator = nn.Sequential(
            nn.Linear(d_model, d_model // 2),
            nn.GELU(),
            nn.Linear(d_model // 2, 1),
            nn.Sigmoid()
        )
        
        # Initialize weights
        self.apply(self._init_weights)
    
    def _create_gqa_layer(self, d_model: int, n_heads: int, n_groups: Optional[int],
                         dropout: float, use_flash: bool) -> nn.ModuleDict:
        """
        Create a single GQA transformer layer
        
        Each layer consists of:
        1. Multi-head GQA attention with residual connection
        2. Feed-forward network with residual connection
        3. Layer normalization before each sub-layer (pre-norm architecture)
        """
        return nn.ModuleDict({
            'attention': FlashGQA(
                d_model=d_model,
                n_heads=n_heads,
                n_groups=n_groups,
                dropout=dropout,
                use_flash=use_flash,
                causal=False  # Not causal for security analysis (bidirectional)
            ),
            'norm1': nn.LayerNorm(d_model),
            'ffn': nn.Sequential(
                nn.Linear(d_model, d_model * 4),  # Expand
                nn.GELU(),
                nn.Dropout(dropout),
                nn.Linear(d_model * 4, d_model),  # Project back
                nn.Dropout(dropout)
            ),
            'norm2': nn.LayerNorm(d_model),
            'dropout': nn.Dropout(dropout)
        })
    
    def _init_weights(self, module):
        """Initialize weights using Xavier/Glorot initialization"""
        if isinstance(module, nn.Linear):
            nn.init.xavier_uniform_(module.weight)
            if module.bias is not None:
                nn.init.zeros_(module.bias)
        elif isinstance(module, nn.Embedding):
            nn.init.normal_(module.weight, mean=0.0, std=0.02)
        elif isinstance(module, nn.LayerNorm):
            nn.init.ones_(module.weight)
            nn.init.zeros_(module.bias)
    
    def forward(self, threat_features: torch.Tensor, 
                positions: Optional[torch.Tensor] = None,
                attention_mask: Optional[torch.Tensor] = None) -> Dict[str, torch.Tensor]:
        """
        Forward pass for security threat analysis
        
        Args:
            threat_features: Security feature indices [batch_size, seq_len]
            positions: Position indices [batch_size, seq_len] (if None, auto-generated)
            attention_mask: Attention mask [batch_size, seq_len, seq_len]
        
        Returns:
            Dict containing:
                - threat_logits: Raw scores for each threat class
                - threat_probs: Probabilities for each threat class
                - severity_score: Severity estimate [0, 1]
                - confidence: Model confidence in predictions [0, 1]
                - hidden_states: All layer hidden states (for analysis)
        
        Example:
            >>> features = torch.randint(0, 10000, (2, 128))  # 2 samples, seq_len 128
            >>> outputs = model(features)
            >>> print(outputs['severity_score'].shape)  # [2, 1]
        """
        batch_size, seq_len = threat_features.shape
        
        # 1. Generate position indices if not provided
        if positions is None:
            positions = torch.arange(seq_len, device=threat_features.device)
            positions = positions.unsqueeze(0).expand(batch_size, seq_len)
        
        # Truncate if sequence exceeds maximum length
        if seq_len > self.max_seq_len:
            threat_features = threat_features[:, :self.max_seq_len]
            positions = positions[:, :self.max_seq_len]
            seq_len = self.max_seq_len
            if attention_mask is not None:
                attention_mask = attention_mask[:, :self.max_seq_len, :self.max_seq_len]
        
        # 2. Create embeddings
        # Threat feature embeddings: convert indices to dense vectors
        threat_embeds = self.threat_embedding(threat_features)
        
        # Position embeddings: add positional information
        position_embeds = self.position_embedding(positions)
        
        # Combine embeddings
        x = threat_embeds + position_embeds
        
        # 3. Store hidden states for analysis
        hidden_states = []
        
        # 4. Process through GQA layers
        for layer_idx, layer in enumerate(self.layers):
            # Store pre-attention state (for analysis)
            hidden_states.append(x.detach().clone())
            
            # Layer normalization before attention (pre-norm)
            x_norm = layer['norm1'](x)
            
            # Self-attention with residual connection
            # Q, K, V all come from the normalized input
            attn_output = layer['attention'](x_norm, x_norm, x_norm, attention_mask)
            x = x + layer['dropout'](attn_output)
            
            # Layer normalization before FFN
            x_norm = layer['norm2'](x)
            
            # Feed-forward network with residual connection
            ffn_output = layer['ffn'](x_norm)
            x = x + layer['dropout'](ffn_output)
        
        # 5. Final layer normalization
        x = self.norm(x)
        hidden_states.append(x.detach().clone())
        
        # 6. Pooling: extract sequence-level representation
        # Use mean pooling across sequence dimension
        # Alternative: could use CLS token or max pooling
        pooled = x.mean(dim=1)  # [batch_size, d_model]
        
        # 7. Threat classification
        threat_logits = self.threat_classifier(pooled)  # [batch_size, num_threat_classes]
        threat_probs = F.softmax(threat_logits, dim=-1)
        
        # 8. Severity estimation
        severity_score = self.severity_regressor(pooled)  # [batch_size, 1]
        
        # 9. Confidence estimation
        confidence = self.confidence_estimator(pooled)  # [batch_size, 1]
        
        return {
            'threat_logits': threat_logits,
            'threat_probs': threat_probs,
            'severity_score': severity_score,
            'confidence': confidence,
            'hidden_states': hidden_states,
            'pooled_representation': pooled
        }
    
    def analyze_threat_pattern(self, threat_features: torch.Tensor, 
                              threshold: float = 0.5) -> Dict[str, torch.Tensor]:
        """
        High-level threat analysis with thresholding
        
        Args:
            threat_features: Security feature indices
            threshold: Confidence threshold for threat detection
        
        Returns:
            Dict with threat analysis results
        """
        # Get model predictions
        outputs = self.forward(threat_features)
        
        # Detect threats above threshold
        threat_detected = (outputs['severity_score'] > threshold).float()
        
        # Get top threat classes
        top_threats = torch.topk(outputs['threat_probs'], k=3, dim=-1)
        
        return {
            **outputs,
            'threat_detected': threat_detected,
            'top_threat_classes': top_threats.indices,
            'top_threat_probs': top_threats.values,
            'analysis_timestamp': torch.tensor(time.time())
        }
    
    def get_attention_patterns(self, threat_features: torch.Tensor, 
                              layer_idx: int = -1) -> torch.Tensor:
        """
        Extract attention patterns for interpretability
        
        Security benefit: Understand which features the model focuses on
        
        Args:
            threat_features: Input features
            layer_idx: Which layer to extract patterns from (-1 for last)
        
        Returns:
            Attention patterns [batch_size, n_heads, seq_len, seq_len]
        """
        if layer_idx < 0:
            layer_idx = self.n_layers + layer_idx
        
        # Note: This is a simplified placeholder
        # In a real implementation, you would need to modify the FlashGQA forward pass
        # to return attention weights when not using flash attention
        
        # Placeholder implementation for demonstration
        batch_size, seq_len = threat_features.shape
        n_heads = self.layers[layer_idx]['attention'].n_heads
        
        # Generate random attention patterns (placeholder)
        attention_patterns = torch.randn(batch_size, n_heads, seq_len, seq_len)
        
        # Normalize to make it a proper attention distribution
        attention_patterns = F.softmax(attention_patterns, dim=-1)
        
        return attention_patterns
    
    def estimate_memory_usage(self, batch_size: int, seq_len: int,
                             dtype: torch.dtype = torch.float16) -> Dict[str, int]:
        """
        Estimate memory usage for different components
        
        Useful for deployment planning
        
        Args:
            batch_size: Batch size
            seq_len: Sequence length
            dtype: Data type
        
        Returns:
            Dict with memory estimates in bytes
        """
        # Model parameters
        param_memory = sum(p.numel() for p in self.parameters()) * 2  # Assuming fp16
        
        # Activation memory (approximate)
        activation_memory = batch_size * seq_len * self.d_model * 2
        
        # KV cache memory
        kv_cache_memory = 0
        for layer in self.layers:
            attn = layer['attention']
            kv_cache_memory += attn.get_kv_cache_size(seq_len, dtype)
        
        # Total inference memory
        total_memory = param_memory + activation_memory + kv_cache_memory
        
        return {
            'parameters_memory_bytes': param_memory,
            'activations_memory_bytes': activation_memory,
            'kv_cache_memory_bytes': kv_cache_memory,
            'total_memory_bytes': total_memory,
            'total_memory_mb': total_memory / (1024 * 1024)
        }


def test_gqa_performance():
    """
    Test GQA performance and memory efficiency
    """
    print("Testing GQA Transformer...")
    
    # Create model
    model = SecurityGQATransformer(
        vocab_size=10000,
        d_model=512,
        n_layers=4,
        n_heads=8,
        n_groups=2,
        num_threat_classes=10
    )
    
    # Test input
    batch_size = 2
    seq_len = 128
    inputs = torch.randint(0, 10000, (batch_size, seq_len))
    
    # Forward pass
    start_time = time.time()
    outputs = model(inputs)
    inference_time = time.time() - start_time
    
    # Verify outputs
    assert outputs['threat_logits'].shape == (batch_size, 10), "Threat logits shape incorrect!"
    assert outputs['severity_score'].shape == (batch_size, 1), "Severity score shape incorrect!"
    assert outputs['confidence'].shape == (batch_size, 1), "Confidence shape incorrect!"
    
    # Check memory estimates
    memory = model.estimate_memory_usage(batch_size, seq_len)
    
    print("GQA Transformer tests passed!")
    print(f"   Inference time: {inference_time:.3f}s")
    print(f"   Total memory: {memory['total_memory_mb']:.1f} MB")
    print(f"   KV cache savings: {model.layers[0]['attention'].memory_savings_vs_mha():.1%}")
    
    return True


if __name__ == "__main__":
    test_gqa_performance()