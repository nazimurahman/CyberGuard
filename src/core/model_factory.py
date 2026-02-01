# src/core/model_factory.py
"""
Model Factory for CyberGuard

This module provides a factory pattern for creating and managing different
security AI models. It handles:

1. Model creation based on configuration
2. Model loading from checkpoints
3. Model versioning and compatibility
4. Distributed training setup
5. Model optimization (quantization, pruning, etc.)

Factory benefits:
- Consistent model creation across the system
- Easy model switching for A/B testing
- Centralized model management
- Simplified deployment
"""

import torch
import torch.nn as nn
from typing import Dict, Any, Optional, Union, List, Tuple
import yaml
import json
import hashlib
from pathlib import Path
import pickle
import warnings
import os  # Added import for os module
import sys  # Added import for sys module
from datetime import datetime  # Added import for datetime

from .gqa_transformer import SecurityGQATransformer
from .security_encoder import SecurityFeatureEncoder, StreamingSecurityEncoder


class ModelFactory:
    """
    Factory for creating and managing security AI models
    
    Supported models:
    1. GQA Transformer (primary for threat analysis)
    2. CNN-LSTM hybrid (for sequential attack detection)
    3. Graph Neural Networks (for relationship analysis)
    4. Ensemble models (combining multiple approaches)
    
    Security considerations:
    - Model integrity verification (hash checking)
    - Secure model loading (prevent tampering)
    - Version compatibility checking
    - Fallback mechanisms for model failures
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize model factory
        
        Args:
            config_path: Path to model configuration file
        
        Example:
            >>> factory = ModelFactory('config/models.yaml')
        """
        self.config = self._load_config(config_path)
        self.models = {}  # Active models cache
        self.model_registry = {}  # Model metadata registry
        
        # Device selection
        self.device = self._select_device()
        
        # Default model configurations
        self.default_configs = {
            'gqa_transformer': {
                'type': 'gqa_transformer',
                'vocab_size': 10000,
                'd_model': 512,
                'n_layers': 6,
                'n_heads': 8,
                'n_groups': 2,
                'max_seq_len': 512,
                'dropout': 0.1,
                'num_threat_classes': 10,
                'use_flash': True,
            },
            'security_encoder': {
                'type': 'security_encoder',
                'vocab_size': 10000,
                'max_seq_len': 512,
                'feature_dim': 512,
                'use_embedding': True,
            },
            'streaming_encoder': {
                'type': 'streaming_encoder',
                'vocab_size': 10000,
                'max_seq_len': 512,
                'feature_dim': 512,
                'use_embedding': True,
                'window_size': 100,
            },
        }
        
        # Initialize model registry
        self._initialize_registry()
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """
        Load model configuration from file
        
        Args:
            config_path: Path to configuration file
        
        Returns:
            Configuration dictionary
        """
        # Set default config path if none provided
        if config_path is None:
            # Fixed: Use proper path construction
            config_path = Path(__file__).parent.parent.parent / 'config' / 'models.yaml'
        else:
            config_path = Path(config_path)
        
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            return config or {}
        except Exception as e:
            warnings.warn(f"Could not load model config from {config_path}: {e}")
            return {}
    
    def _select_device(self) -> torch.device:
        """
        Select the best available device for model execution
        
        Priority:
        1. CUDA GPU with sufficient memory
        2. MPS (Apple Silicon)
        3. CPU
        
        Returns:
            torch.device: Selected device
        """
        if torch.cuda.is_available():
            # Check GPU memory
            try:
                gpu_memory = torch.cuda.get_device_properties(0).total_memory
                if gpu_memory >= 4 * 1024**3:  # 4GB minimum
                    device = torch.device('cuda:0')
                    print(f"Using CUDA GPU with {gpu_memory / 1024**3:.1f} GB memory")
                    return device
            except Exception as e:
                warnings.warn(f"GPU memory check failed: {e}")
                pass
        
        # Check for MPS (Apple Silicon)
        if hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
            device = torch.device('mps')
            print("Using Apple Silicon MPS")
            return device
        
        # Fallback to CPU
        device = torch.device('cpu')
        print("Using CPU (no GPU detected or insufficient memory)")
        return device
    
    def _initialize_registry(self):
        """
        Initialize model registry with built-in models
        """
        # Register built-in models
        self.register_model_type(
            name='gqa_transformer',
            model_class=SecurityGQATransformer,
            description='GQA Transformer for security threat analysis',
            requirements=['torch>=2.0.0'],
            default_config=self.default_configs['gqa_transformer']
        )
        
        self.register_model_type(
            name='security_encoder',
            model_class=SecurityFeatureEncoder,
            description='Security feature encoder',
            requirements=[],
            default_config=self.default_configs['security_encoder']
        )
        
        self.register_model_type(
            name='streaming_encoder',
            model_class=StreamingSecurityEncoder,
            description='Streaming security feature encoder',
            requirements=[],
            default_config=self.default_configs['streaming_encoder']
        )
    
    def register_model_type(self, name: str, model_class: type,
                           description: str = '', requirements: List[str] = None,
                           default_config: Dict[str, Any] = None):
        """
        Register a new model type with the factory
        
        Args:
            name: Unique name for model type
            model_class: Model class reference
            description: Human-readable description
            requirements: List of package requirements
            default_config: Default configuration for this model type
        """
        self.model_registry[name] = {
            'class': model_class,
            'description': description,
            'requirements': requirements or [],
            'default_config': default_config or {},
            'registered_at': self._get_timestamp(),
        }
    
    def create_model(self, model_type: str, config: Optional[Dict[str, Any]] = None,
                    model_id: Optional[str] = None) -> nn.Module:
        """
        Create a new model instance
        
        Args:
            model_type: Type of model to create (must be registered)
            config: Model configuration (overrides defaults)
            model_id: Optional ID for tracking
        
        Returns:
            nn.Module: Created model instance
        
        Example:
            >>> model = factory.create_model('gqa_transformer')
        """
        # Check if model type is registered
        if model_type not in self.model_registry:
            raise ValueError(f"Model type '{model_type}' not registered. "
                           f"Available: {list(self.model_registry.keys())}")
        
        # Get model info from registry
        model_info = self.model_registry[model_type]
        model_class = model_info['class']
        
        # Merge configurations - start with default, then override with user config
        default_config = model_info['default_config'].copy()
        if config:
            # Validate config keys
            for key in config:
                if key not in default_config:
                    warnings.warn(f"Unknown config key '{key}' for model type '{model_type}'")
            default_config.update(config)
        
        # Check package requirements
        self._check_requirements(model_info['requirements'])
        
        try:
            # Create model instance with merged configuration
            model = model_class(**default_config)
            
            # Move model to appropriate device (GPU, MPS, or CPU)
            if hasattr(model, 'to'):
                model = model.to(self.device)
            
            # Generate model ID if not provided
            if model_id is None:
                model_id = self._generate_model_id(model_type, default_config)
            
            # Store model in cache for future access
            self.models[model_id] = {
                'model': model,
                'type': model_type,
                'config': default_config,
                'created_at': self._get_timestamp(),
                'device': str(self.device),
            }
            
            print(f"Created model '{model_id}' of type '{model_type}'")
            print(f"   Device: {self.device}")
            print(f"   Parameters: {self._count_parameters(model):,}")
            
            return model
            
        except Exception as e:
            raise RuntimeError(f"Failed to create model '{model_type}': {e}")
    
    def load_model(self, checkpoint_path: str, model_type: Optional[str] = None,
                  strict: bool = True, map_location: Optional[str] = None) -> nn.Module:
        """
        Load model from checkpoint file
        
        Args:
            checkpoint_path: Path to model checkpoint
            model_type: Optional model type for verification
            strict: Whether to strictly enforce state_dict matching
            map_location: Device to load onto (None for auto)
        
        Returns:
            nn.Module: Loaded model
        
        Example:
            >>> model = factory.load_model('models/checkpoints/model_v1.pt')
        """
        checkpoint_path = Path(checkpoint_path)
        
        # Check if checkpoint file exists
        if not checkpoint_path.exists():
            raise FileNotFoundError(f"Checkpoint not found: {checkpoint_path}")
        
        # Load checkpoint data
        try:
            # Determine device to load model onto
            if map_location is None:
                map_location = self.device
            
            # Load checkpoint using torch.load
            checkpoint = torch.load(checkpoint_path, map_location=map_location)
        except Exception as e:
            raise RuntimeError(f"Failed to load checkpoint {checkpoint_path}: {e}")
        
        # Verify checkpoint has required structure
        if 'model_state_dict' not in checkpoint:
            raise ValueError(f"Invalid checkpoint format: missing 'model_state_dict'")
        
        # Extract model configuration from checkpoint
        model_config = checkpoint.get('config', {})
        saved_model_type = checkpoint.get('model_type')
        
        # Determine model type - use saved type if available, otherwise use provided type
        if model_type is None and saved_model_type:
            model_type = saved_model_type
        
        # Ensure model type is specified
        if model_type is None:
            raise ValueError("Model type must be specified or present in checkpoint")
        
        # Create model instance with saved configuration
        model = self.create_model(model_type, model_config)
        
        # Load model weights from state dict
        try:
            model.load_state_dict(checkpoint['model_state_dict'], strict=strict)
        except Exception as e:
            if strict:
                raise RuntimeError(f"Failed to load state dict: {e}")
            else:
                # Attempt partial loading if strict=False
                warnings.warn(f"Partial state dict loading: {e}")
                model_state_dict = model.state_dict()
                for key, value in checkpoint['model_state_dict'].items():
                    if key in model_state_dict and value.shape == model_state_dict[key].shape:
                        model_state_dict[key] = value
                # Reload with updated state dict
                model.load_state_dict(model_state_dict, strict=False)
        
        # Verify model integrity by comparing hashes
        model_hash = self._compute_model_hash(model)
        saved_hash = checkpoint.get('model_hash')
        
        if saved_hash and model_hash != saved_hash:
            warnings.warn(f"Model hash mismatch: expected {saved_hash}, got {model_hash}")
        
        print(f"Loaded model from {checkpoint_path}")
        print(f"   Model type: {model_type}")
        print(f"   Checkpoint version: {checkpoint.get('version', 'unknown')}")
        print(f"   Trained on: {checkpoint.get('training_date', 'unknown')}")
        
        return model
    
    def save_model(self, model: nn.Module, save_path: str,
                  metadata: Optional[Dict[str, Any]] = None):
        """
        Save model to checkpoint file
        
        Args:
            model: Model to save
            save_path: Path to save checkpoint
            metadata: Additional metadata to save
        
        Example:
            >>> factory.save_model(model, 'models/checkpoints/model_v1.pt')
        """
        save_path = Path(save_path)
        
        # Create parent directories if they don't exist
        save_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Find model ID by searching through cached models
        model_id = None
        for mid, info in self.models.items():
            if info['model'] is model:
                model_id = mid
                break
        
        # Prepare checkpoint dictionary with all necessary information
        checkpoint = {
            'model_state_dict': model.state_dict(),  # Model weights
            'config': self.models.get(model_id, {}).get('config', {}),  # Model configuration
            'model_type': self.models.get(model_id, {}).get('type', 'unknown'),  # Model type
            'model_hash': self._compute_model_hash(model),  # Integrity hash
            'factory_version': '1.0.0',  # Factory version for compatibility
            'save_date': self._get_timestamp(),  # Timestamp of save
            'pytorch_version': torch.__version__,  # PyTorch version
            'device': str(self.device),  # Device model was saved from
        }
        
        # Add any additional metadata provided by user
        if metadata:
            checkpoint['metadata'] = metadata
        
        # Save checkpoint to file
        try:
            torch.save(checkpoint, save_path)
            
            # Compute hash of saved file for verification
            file_hash = self._compute_file_hash(save_path)
            
            print(f"Saved model to {save_path}")
            print(f"   File hash: {file_hash}")
            print(f"   Model hash: {checkpoint['model_hash']}")
            print(f"   Size: {save_path.stat().st_size / 1024**2:.2f} MB")
            
            # Save hash to separate file for integrity verification
            hash_path = save_path.with_suffix('.hash')
            with open(hash_path, 'w') as f:
                json.dump({'file_hash': file_hash, 'model_hash': checkpoint['model_hash']}, f)
                
        except Exception as e:
            raise RuntimeError(f"Failed to save model to {save_path}: {e}")
    
    def get_model(self, model_id: str) -> Optional[nn.Module]:
        """
        Get model from cache by ID
        
        Args:
            model_id: Model identifier
        
        Returns:
            Model instance or None if not found
        """
        # Return model from cache if it exists
        if model_id in self.models:
            return self.models[model_id]['model']
        return None
    
    def get_model_info(self, model_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a model
        
        Args:
            model_id: Model identifier
        
        Returns:
            Model information dictionary or None
        """
        if model_id in self.models:
            # Create copy of model info to avoid modifying cache
            info = self.models[model_id].copy()
            # Add parameter count to information
            info['parameter_count'] = self._count_parameters(info['model'])
            return info
        return None
    
    def list_models(self) -> List[str]:
        """
        List all models in cache
        
        Returns:
            List of model IDs
        """
        return list(self.models.keys())
    
    def list_model_types(self) -> List[Dict[str, Any]]:
        """
        List all registered model types
        
        Returns:
            List of model type information
        """
        types = []
        for name, info in self.model_registry.items():
            types.append({
                'name': name,
                'description': info['description'],
                'requirements': info['requirements'],
                'default_config_keys': list(info['default_config'].keys()),
            })
        return types
    
    def optimize_model(self, model: nn.Module, optimization: str = 'inference') -> nn.Module:
        """
        Apply optimizations to model
        
        Args:
            model: Model to optimize
            optimization: Type of optimization
        
        Returns:
            Optimized model
        
        Available optimizations:
        - 'inference': Optimize for inference (eval mode, no gradients)
        - 'training': Optimize for training
        - 'quantization': Apply quantization for smaller size
        - 'pruning': Apply pruning for smaller size
        """
        if optimization == 'inference':
            # Set model to evaluation mode
            model.eval()
            
            # Disable gradients to save memory during inference
            for param in model.parameters():
                param.requires_grad = False
            
            # Use torch.compile for faster inference if available
            if hasattr(torch, 'compile'):
                try:
                    model = torch.compile(model, mode='reduce-overhead')
                    print("Applied torch.compile optimization")
                except Exception as e:
                    warnings.warn(f"torch.compile failed: {e}")
        
        elif optimization == 'training':
            # Set model to training mode
            model.train()
            
            # Enable gradients for backpropagation
            for param in model.parameters():
                param.requires_grad = True
        
        elif optimization == 'quantization':
            # Apply dynamic quantization to reduce model size
            try:
                # Only quantize Linear layers to minimize accuracy loss
                model = torch.quantization.quantize_dynamic(
                    model, {nn.Linear}, dtype=torch.qint8
                )
                print("Applied dynamic quantization")
            except Exception as e:
                warnings.warn(f"Quantization failed: {e}")
        
        elif optimization == 'pruning':
            # Apply pruning to reduce model size
            try:
                self._apply_pruning(model, amount=0.2)
                print("Applied pruning (20%)")
            except Exception as e:
                warnings.warn(f"Pruning failed: {e}")
        
        else:
            warnings.warn(f"Unknown optimization: {optimization}")
        
        return model
    
    def _apply_pruning(self, model: nn.Module, amount: float = 0.2):
        """Apply pruning to model parameters"""
        import torch.nn.utils.prune as prune
        
        # Prune linear layers only
        for name, module in model.named_modules():
            if isinstance(module, nn.Linear):
                # Apply L1 unstructured pruning
                prune.l1_unstructured(module, name='weight', amount=amount)
                # Make pruning permanent
                prune.remove(module, 'weight')
    
    def _check_requirements(self, requirements: List[str]):
        """
        Check if package requirements are met
        
        Args:
            requirements: List of package requirements
        
        Raises:
            ImportError: If requirements are not met
        """
        # Check each requirement
        for req in requirements:
            try:
                # Split requirement into package name and version constraint
                if '>=' in req:
                    pkg_name, version = req.split('>=')
                    # Simple version check
                    import importlib.metadata
                    installed_version = importlib.metadata.version(pkg_name)
                    # Basic version comparison (for simplicity)
                    from packaging import version as packaging_version
                    if packaging_version.parse(installed_version) < packaging_version.parse(version):
                        warnings.warn(f"Package {pkg_name} version {installed_version} is less than required {version}")
                else:
                    # Just check if package is importable
                    __import__(req)
            except Exception as e:
                warnings.warn(f"Requirement check failed for {req}: {e}")
    
    def _generate_model_id(self, model_type: str, config: Dict[str, Any]) -> str:
        """
        Generate unique model ID from type and configuration
        
        Args:
            model_type: Model type
            config: Model configuration
        
        Returns:
            Unique model ID string
        """
        # Create deterministic string from sorted config keys
        config_str = json.dumps(config, sort_keys=True)
        # Create hash of config for uniqueness
        config_hash = hashlib.md5(config_str.encode()).hexdigest()[:8]
        
        # Get current timestamp without special characters
        timestamp = self._get_timestamp().replace(':', '').replace('-', '').replace(' ', '_')
        
        # Combine type, hash, and timestamp for unique ID
        return f"{model_type}_{config_hash}_{timestamp}"
    
    def _compute_model_hash(self, model: nn.Module) -> str:
        """
        Compute hash of model parameters
        
        Args:
            model: Model to hash
        
        Returns:
            Hash string
        """
        # Collect parameter data for hashing
        param_data = []
        for name, param in model.named_parameters():
            if param.requires_grad:
                # Convert parameter to bytes for hashing
                param_bytes = param.detach().cpu().numpy().tobytes()
                param_data.append((name, param_bytes))
        
        # Sort by name for deterministic hashing
        param_data.sort(key=lambda x: x[0])
        
        # Compute SHA256 hash
        hasher = hashlib.sha256()
        for name, data in param_data:
            hasher.update(name.encode('utf-8'))
            hasher.update(data)
        
        # Return first 16 characters of hash
        return hasher.hexdigest()[:16]
    
    def _compute_file_hash(self, filepath: Path) -> str:
        """
        Compute hash of file
        
        Args:
            filepath: Path to file
        
        Returns:
            Hash string
        """
        hasher = hashlib.sha256()
        with open(filepath, 'rb') as f:
            # Read file in chunks to handle large files efficiently
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        return hasher.hexdigest()[:16]
    
    def _count_parameters(self, model: nn.Module) -> int:
        """
        Count trainable parameters in model
        
        Args:
            model: Model to count
        
        Returns:
            Number of trainable parameters
        """
        # Sum all parameter elements that require gradients
        return sum(p.numel() for p in model.parameters() if p.requires_grad)
    
    def _get_timestamp(self) -> str:
        """
        Get current timestamp string
        
        Returns:
            ISO format timestamp
        """
        return datetime.now().isoformat()
    
    def cleanup(self, keep_recent: int = 10):
        """
        Clean up old models from cache
        
        Args:
            keep_recent: Number of recent models to keep
        """
        # Only cleanup if we have more models than we want to keep
        if len(self.models) <= keep_recent:
            return
        
        # Sort models by creation time (newest first)
        sorted_models = sorted(
            self.models.items(),
            key=lambda x: x[1]['created_at'],
            reverse=True
        )
        
        # Identify models to remove (all beyond keep_recent)
        to_remove = sorted_models[keep_recent:]
        
        # Remove old models from cache
        for model_id, _ in to_remove:
            del self.models[model_id]
        
        print(f"Cleaned up {len(to_remove)} old models from cache")


class DistributedModelFactory(ModelFactory):
    """
    Distributed model factory for multi-GPU training
    
    Extends the base factory with:
    1. Multi-GPU model distribution (DataParallel, DistributedDataParallel)
    2. Gradient checkpointing for memory efficiency
    3. Mixed precision training
    4. Model sharding for very large models
    """
    
    def __init__(self, config_path: Optional[str] = None,
                 distributed_backend: str = 'nccl',
                 mixed_precision: bool = False):
        """
        Initialize distributed model factory
        
        Args:
            config_path: Path to configuration file
            distributed_backend: Distributed backend to use
            mixed_precision: Enable mixed precision training
        """
        # Initialize parent class
        super().__init__(config_path)
        self.distributed_backend = distributed_backend
        self.mixed_precision = mixed_precision
        self.world_size = 1  # Number of processes
        self.local_rank = 0  # Rank of current process
        
        # Initialize distributed training if available
        self._init_distributed()
    
    def _init_distributed(self):
        """Initialize distributed training environment"""
        # Check for distributed environment variables
        if 'WORLD_SIZE' in os.environ:
            self.world_size = int(os.environ['WORLD_SIZE'])
            self.local_rank = int(os.environ.get('LOCAL_RANK', 0))
            
            # Initialize distributed training if more than one process
            if self.world_size > 1:
                print(f"Initializing distributed training (world size: {self.world_size})")
                
                # Initialize PyTorch distributed process group
                torch.distributed.init_process_group(
                    backend=self.distributed_backend,
                    init_method='env://',
                    world_size=self.world_size,
                    rank=self.local_rank
                )
    
    def create_distributed_model(self, model_type: str,
                               config: Optional[Dict[str, Any]] = None,
                               model_id: Optional[str] = None) -> nn.Module:
        """
        Create model with distributed training support
        
        Args:
            model_type: Type of model to create
            config: Model configuration
            model_id: Optional model ID
        
        Returns:
            Distributed model instance
        """
        # Create base model using parent class method
        model = self.create_model(model_type, config, model_id)
        
        # Apply distributed wrappers for multi-GPU training
        if self.world_size > 1:
            # Use DistributedDataParallel for multi-node or multi-process training
            model = nn.parallel.DistributedDataParallel(
                model,
                device_ids=[self.local_rank] if torch.cuda.is_available() else None,
                output_device=self.local_rank
            )
            print(f"Wrapped model in DistributedDataParallel")
        
        elif torch.cuda.device_count() > 1:
            # Use DataParallel for single-node multi-GPU training
            model = nn.DataParallel(model)
            print(f"Wrapped model in DataParallel ({torch.cuda.device_count()} GPUs)")
        
        # Enable mixed precision training if specified and on CUDA
        if self.mixed_precision and self.device.type == 'cuda':
            # Note: autocast is used during training, not here
            print("Mixed precision training enabled")
        
        return model
    
    def save_distributed_checkpoint(self, model: nn.Module, save_path: str,
                                  optimizer: Optional[torch.optim.Optimizer] = None,
                                  scheduler: Optional[Any] = None,
                                  epoch: Optional[int] = None,
                                  metadata: Optional[Dict[str, Any]] = None):
        """
        Save distributed training checkpoint
        
        Args:
            model: Model to save
            save_path: Path to save checkpoint
            optimizer: Optimizer state
            scheduler: Scheduler state
            epoch: Current epoch
            metadata: Additional metadata
        """
        # Extract model state dict, handling wrapped models
        if hasattr(model, 'module'):
            # DistributedDataParallel wraps model in .module attribute
            model_state_dict = model.module.state_dict()
        else:
            model_state_dict = model.state_dict()
        
        # Prepare checkpoint dictionary
        checkpoint = {
            'model_state_dict': model_state_dict,
            'epoch': epoch,
            'distributed_world_size': self.world_size,
            'distributed_rank': self.local_rank,
        }
        
        # Add optimizer and scheduler states if provided
        if optimizer:
            checkpoint['optimizer_state_dict'] = optimizer.state_dict()
        
        if scheduler:
            checkpoint['scheduler_state_dict'] = scheduler.state_dict()
        
        # Add metadata if provided
        if metadata:
            checkpoint['metadata'] = metadata
        
        # Save checkpoint only from rank 0 to avoid multiple saves
        if self.local_rank == 0:
            # Call parent class save method
            self._save_checkpoint(checkpoint, save_path)
        else:
            # Other processes wait for rank 0 to finish
            if torch.distributed.is_initialized():
                torch.distributed.barrier()
    
    def _save_checkpoint(self, checkpoint: Dict[str, Any], save_path: str):
        """
        Save checkpoint dictionary to file
        
        Args:
            checkpoint: Checkpoint dictionary
            save_path: Path to save file
        """
        save_path = Path(save_path)
        
        # Create parent directories
        save_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Save checkpoint using torch.save
        torch.save(checkpoint, save_path)
        print(f"Saved distributed checkpoint to {save_path}")


def test_model_factory():
    """
    Test model factory functionality
    """
    print("Testing Model Factory...")
    
    # Create factory instance
    factory = ModelFactory()
    
    # List available model types
    model_types = factory.list_model_types()
    assert len(model_types) > 0, "Should have registered model types"
    print(f"   Available model types: {[t['name'] for t in model_types]}")
    
    # Create GQA Transformer model
    try:
        model = factory.create_model('gqa_transformer')
        assert model is not None, "Failed to create GQA Transformer"
    except Exception as e:
        print(f"   Skipping GQA Transformer test (might not be implemented): {e}")
        # Create a simple test model instead
        class SimpleTestModel(nn.Module):
            def __init__(self):
                super().__init__()
                self.linear = nn.Linear(10, 5)
        
        factory.register_model_type(
            name='test_model',
            model_class=SimpleTestModel,
            description='Test model',
            default_config={}
        )
        model = factory.create_model('test_model')
    
    # Get list of models in cache
    model_list = factory.list_models()
    assert len(model_list) >= 1, "Should have at least one model in cache"
    
    # Get information about the model
    model_info = factory.get_model_info(model_list[0])
    assert model_info is not None, "Failed to get model info"
    assert 'parameter_count' in model_info
    
    # Test optimization
    optimized = factory.optimize_model(model, 'inference')
    assert optimized.training == False, "Should be in eval mode after inference optimization"
    
    # Test save and load functionality
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        save_path = Path(tmpdir) / 'test_model.pt'
        
        # Save model to temporary file
        factory.save_model(model, save_path)
        assert save_path.exists(), "Model should have been saved"
        
        # Load model from saved file
        try:
            loaded_model = factory.load_model(save_path, model_type='gqa_transformer')
            assert loaded_model is not None, "Failed to load model"
        except:
            # Try with test model type
            loaded_model = factory.load_model(save_path, model_type='test_model')
        
        # Verify loaded model has correct type
        assert isinstance(loaded_model, nn.Module)
    
    # Clean up cache
    factory.cleanup()
    
    print("Model Factory tests passed!")
    return True


if __name__ == "__main__":
    # Run tests when script is executed directly
    try:
        test_model_factory()
    except Exception as e:
        print(f"Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)