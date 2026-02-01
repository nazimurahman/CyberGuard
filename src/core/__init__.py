"""
CyberGuard Core Module
======================

This module contains the core components of the CyberGuard Web Security AI System:
- mHC (Manifold-Constrained Hyper-Connections) for stable multi-agent reasoning
- GQA (Grouped Query Attention) with Flash Attention and RoPE for efficient transformers
- Security encoder for web security feature extraction
- Model factory for creating and managing security models

Author: CyberGuard Security Team
Version: 1.0.0
"""

import sys
from pathlib import Path

# Add the parent directory to the path for relative imports
sys.path.append(str(Path(__file__).parent.parent))

# Version information
__version__ = "1.0.0"
__author__ = "CyberGuard Security Team"
__license__ = "Apache 2.0"

# Core exports - Import statements for all components
from .mhc_architecture import (
    ManifoldConstrainedHyperConnections,
    SinkhornProjection,
    ConvexStateMixing,
    ResidualCoordination,
    BoundedSignalPropagation
)

from .gqa_transformer import (
    RotaryPositionalEmbedding,
    FlashGQA,
    SecurityGQATransformer,
    GroupedQueryAttention,
    OptimizedGQA,
    GQATransformerBlock,
    SecurityAttentionHead
)

from .security_encoder import (
    SecurityFeatureEncoder,
    WebTrafficEncoder,
    VulnerabilityEncoder,
    ThreatPatternEncoder,
    SecurityContextEncoder
)

from .model_factory import (
    SecurityModelFactory,
    ModelRegistry,
    create_security_model,
    load_pretrained_model,
    save_model_checkpoint,
    ModelConfig,
    TrainingConfig
)

# Utility functions

def get_core_version() -> str:
    """
    Return the current version of the core module.
    
    Returns:
        str: Version string of the module
    """
    return __version__

def list_available_models() -> list:
    """
    List all available security models registered in the ModelRegistry.
    
    Returns:
        list: List of model names that are available
    """
    # Import ModelRegistry inside function to avoid circular imports
    from .model_factory import ModelRegistry
    return list(ModelRegistry.get_registered_models().keys())

def initialize_core(device: str = None) -> dict:
    """
    Initialize the core module with default configurations.
    
    Args:
        device: The device to use for computation ('cuda' or 'cpu').
                If None, automatically detects CUDA availability.
    
    Returns:
        dict: Initialization status and configuration information
    """
    # Import torch inside function to handle import errors gracefully
    try:
        import torch
        
        # Set default device if not provided
        if device is None:
            device = "cuda" if torch.cuda.is_available() else "cpu"
        
        # Initialize status dictionary with system information
        status = {
            "version": __version__,
            "device": device,
            "torch_version": torch.__version__,
            "cuda_available": torch.cuda.is_available(),
            "cuda_device_count": torch.cuda.device_count() if torch.cuda.is_available() else 0,
            "initialized_models": [],
            "available_memory": None,
            "initialized": True
        }
        
        # Collect GPU memory information if CUDA is available
        if torch.cuda.is_available():
            try:
                status["available_memory"] = {
                    "total": torch.cuda.get_device_properties(0).total_memory,
                    "allocated": torch.cuda.memory_allocated(0),
                    "reserved": torch.cuda.memory_reserved(0)
                }
            except Exception as e:
                status["available_memory"] = {"error": str(e)}
        
        # Set the default torch device
        torch.set_default_device(device)
        
        return status
        
    except ImportError as e:
        # Handle case where PyTorch is not installed
        return {
            "error": f"PyTorch not installed: {str(e)}",
            "initialized": False,
            "version": __version__,
            "device": "cpu"
        }
    except Exception as e:
        # Handle any other initialization errors
        return {
            "error": f"Initialization failed: {str(e)}",
            "initialized": False,
            "version": __version__
        }

# Initialize module when imported
try:
    # Import torch to check availability
    import torch
    
    # Check if CUDA is available for default device selection
    if torch.cuda.is_available():
        DEFAULT_DEVICE = "cuda"
    else:
        DEFAULT_DEVICE = "cpu"
    
    # Core is successfully initialized
    CORE_INITIALIZED = True
    
    # Perform core initialization and store status
    _initialization_status = initialize_core(DEFAULT_DEVICE)
    
except ImportError:
    # PyTorch is not installed
    CORE_INITIALIZED = False
    DEFAULT_DEVICE = "cpu"
    _initialization_status = {
        "error": "PyTorch not installed",
        "initialized": False,
        "version": __version__
    }
except Exception as e:
    # Other initialization errors
    CORE_INITIALIZED = False
    DEFAULT_DEVICE = "cpu"
    _initialization_status = {
        "error": f"Initialization error: {str(e)}",
        "initialized": False,
        "version": __version__
    }

# Define what gets imported with "from core import *"
# This controls the public API of the module
__all__ = [
    # mHC Architecture components
    "ManifoldConstrainedHyperConnections",
    "SinkhornProjection", 
    "ConvexStateMixing",
    "ResidualCoordination",
    "BoundedSignalPropagation",
    
    # GQA Transformer components
    "RotaryPositionalEmbedding",
    "FlashGQA",
    "SecurityGQATransformer", 
    "GroupedQueryAttention",
    "OptimizedGQA",
    "GQATransformerBlock",
    "SecurityAttentionHead",
    
    # Security Encoder components
    "SecurityFeatureEncoder",
    "WebTrafficEncoder", 
    "VulnerabilityEncoder",
    "ThreatPatternEncoder",
    "SecurityContextEncoder",
    
    # Model Factory components
    "SecurityModelFactory",
    "ModelRegistry",
    "create_security_model",
    "load_pretrained_model", 
    "save_model_checkpoint",
    "ModelConfig",
    "TrainingConfig",
    
    # Utility functions
    "get_core_version",
    "list_available_models",
    "initialize_core",
    
    # Module constants
    "__version__",
    "__author__", 
    "__license__",
    "CORE_INITIALIZED",
    "DEFAULT_DEVICE"
]
from src.core import (
    SecurityGQATransformer,
    ManifoldConstrainedHyperConnections,
    SecurityFeatureEncoder,
    create_security_model
)

# Initialize core components
model = create_security_model("web_threat_detector")
mhc = ManifoldConstrainedHyperConnections(n_agents=10, state_dim=512)
encoder = SecurityFeatureEncoder()

# Check initialization status
from src.core import get_core_version, CORE_INITIALIZED
print(f"CyberGuard Core v{get_core_version()}, Initialized: {CORE_INITIALIZED}")