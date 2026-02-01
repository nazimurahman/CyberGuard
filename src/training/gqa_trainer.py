# src/training/gqa_trainer.py
"""
Grouped Query Attention (GQA) Training Module
Purpose: Train GQA-based transformer models for security threat analysis

This module implements:
1. Multi-GPU distributed training for GQA models
2. Mixed precision training with gradient scaling
3. Gradient checkpointing for memory efficiency
4. Learning rate schedulers (cosine, linear, step)
5. Model checkpointing and early stopping
6. Training metrics visualization
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from torch.cuda.amp import GradScaler, autocast
from torch.utils.data import DataLoader, DistributedSampler
from torch.utils.tensorboard import SummaryWriter
import torch.distributed as dist
from typing import Dict, List, Tuple, Optional, Any
import numpy as np
import time
import logging
import os
from pathlib import Path
import json
from dataclasses import dataclass
from enum import Enum
import math
from safetensors.torch import save_file  # Added missing import
import onnx  # Added for ONNX export verification
import onnxruntime as ort  # Added for ONNX runtime validation


class LossType(Enum):
    """Types of loss functions for security model training"""
    CROSS_ENTROPY = "cross_entropy"
    FOCAL_LOSS = "focal_loss"  # For class imbalance in threat detection
    LABEL_SMOOTHING = "label_smoothing"  # For regularization
    CONTRASTIVE_LOSS = "contrastive_loss"  # For representation learning


@dataclass
class GQATrainingConfig:
    """
    Configuration for GQA training
    Each parameter is explained in detail for clarity
    """
    # Model architecture parameters
    d_model: int = 512  # Model dimension (embedding size)
    n_heads: int = 8    # Total number of attention heads
    n_groups: int = 2   # Number of KV head groups (GQA parameter)
    n_layers: int = 6   # Number of transformer layers
    vocab_size: int = 50257  # Vocabulary size for tokenizer
    
    # Training hyperparameters
    batch_size: int = 32  # Samples per training batch
    learning_rate: float = 1e-4  # Initial learning rate
    weight_decay: float = 0.01  # L2 regularization strength
    warmup_steps: int = 1000  # Steps for linear learning rate warmup
    total_steps: int = 100000  # Total training steps
    gradient_clip: float = 1.0  # Maximum gradient norm for clipping
    
    # Optimization parameters
    optimizer: str = "adamw"  # Optimizer type: adamw, adam, sgd
    scheduler: str = "cosine"  # LR scheduler: cosine, linear, step, plateau
    beta1: float = 0.9  # Adam beta1 parameter
    beta2: float = 0.95  # Adam beta2 parameter
    eps: float = 1e-8  # Adam epsilon parameter
    
    # Loss configuration
    loss_type: LossType = LossType.FOCAL_LOSS  # Loss function for threat classification
    focal_loss_gamma: float = 2.0  # Gamma parameter for focal loss
    label_smoothing: float = 0.1  # Label smoothing epsilon
    
    # Training stability
    gradient_checkpointing: bool = True  # Trade compute for memory
    mixed_precision: bool = True  # Use FP16 for faster training
    gradient_accumulation_steps: int = 4  # Accumulate gradients over multiple steps
    
    # Checkpointing
    save_checkpoint_steps: int = 1000  # Save checkpoint every N steps
    checkpoint_dir: str = "./checkpoints/gqa"  # Directory for checkpoints
    max_checkpoints: int = 10  # Maximum number of checkpoints to keep
    
    # Early stopping
    early_stopping_patience: int = 20  # Steps to wait before early stopping
    early_stopping_min_delta: float = 1e-4  # Minimum improvement to reset patience
    
    # Distributed training
    distributed: bool = False  # Enable distributed training
    world_size: int = 1  # Number of GPUs for distributed training
    local_rank: int = 0  # Local rank for distributed training


class GQATrainer:
    """
    Trainer for GQA-based transformer models with advanced features:
    - Distributed training across multiple GPUs
    - Mixed precision training for speed and memory efficiency
    - Gradient checkpointing for large models
    - Multiple loss functions for security tasks
    - Comprehensive logging and visualization
    """
    
    def __init__(self, model: nn.Module, config: GQATrainingConfig):
        """
        Initialize GQA trainer with model and configuration
        
        Args:
            model: GQA transformer model to train
            config: Training configuration parameters
        """
        self.model = model
        self.config = config
        
        # Initialize logger early for error reporting
        self.logger = self._setup_logger()
        
        # Setup device (GPU/CPU)
        self.device = self._setup_device()
        
        # Move model to device
        self.model.to(self.device)
        
        # Setup distributed training if enabled
        if config.distributed:
            self._setup_distributed()
        
        # Setup optimizer
        self.optimizer = self._setup_optimizer()
        
        # Setup learning rate scheduler
        self.scheduler = self._setup_scheduler()
        
        # Setup mixed precision training (only on CUDA)
        self.scaler = GradScaler() if config.mixed_precision and torch.cuda.is_available() else None
        
        # Setup gradient checkpointing
        if config.gradient_checkpointing:
            self._enable_gradient_checkpointing()
        
        # Setup TensorBoard writer
        self.writer = SummaryWriter(log_dir=f"runs/gqa_{time.strftime('%Y%m%d_%H%M%S')}")
        
        # Training state
        self.global_step = 0
        self.epoch = 0
        self.best_loss = float('inf')
        self.patience_counter = 0
        
        # Metrics tracking
        self.metrics = {
            'train_loss': [],
            'val_loss': [],
            'train_accuracy': [],
            'val_accuracy': [],
            'learning_rate': [],
            'grad_norm': []
        }
        
        self.logger.info(f"GQA Trainer initialized with config: {config}")
    
    def _setup_logger(self) -> logging.Logger:
        """
        Setup logging configuration
        
        Returns:
            Configured logger instance
        """
        # Create logs directory if it doesn't exist
        log_dir = Path("logs/training")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup logger
        logger = logging.getLogger("GQATrainer")
        logger.setLevel(logging.INFO)
        
        # Clear existing handlers to avoid duplicate logs
        if logger.hasHandlers():
            logger.handlers.clear()
        
        # File handler for persistent logs
        file_handler = logging.FileHandler(
            log_dir / f"gqa_training_{time.strftime('%Y%m%d_%H%M%S')}.log"
        )
        file_handler.setLevel(logging.INFO)
        
        # Console handler for real-time output
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatter for log messages
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers to logger
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
        
    def _setup_device(self) -> torch.device:
        """
        Setup training device (GPU if available, else CPU)
        
        Returns:
            torch.device: Device to use for training
        """
        if torch.cuda.is_available():
            device = torch.device(f"cuda:{self.config.local_rank}")
            torch.cuda.set_device(device)
            self.logger.info(f"Using GPU: {torch.cuda.get_device_name(device)}")
            return device
        else:
            self.logger.info("Using CPU for training")
            return torch.device("cpu")
    
    def _setup_distributed(self):
        """
        Setup distributed training across multiple GPUs
        Required for training large models on multiple GPUs
        """
        # Check if CUDA is available for distributed training
        if not torch.cuda.is_available():
            self.logger.warning("CUDA not available for distributed training")
            return
            
        # Initialize distributed process group
        dist.init_process_group(
            backend='nccl',  # NVIDIA Collective Communications Library
            init_method='env://',  # Use environment variables
            world_size=self.config.world_size,
            rank=self.config.local_rank
        )
        
        # Wrap model with DistributedDataParallel for parallel training
        self.model = nn.parallel.DistributedDataParallel(
            self.model,
            device_ids=[self.config.local_rank],
            output_device=self.config.local_rank,
            find_unused_parameters=True  # For models with conditional computation
        )
        
        self.logger.info(f"Distributed training enabled on rank {self.config.local_rank}")
    
    def _setup_optimizer(self) -> torch.optim.Optimizer:
        """
        Setup optimizer with weight decay for different parameter types
        
        Returns:
            Optimizer configured for training
        """
        # Separate parameters for weight decay
        # LayerNorm and bias parameters typically don't need weight decay
        decay_params = []
        no_decay_params = []
        
        for name, param in self.model.named_parameters():
            if not param.requires_grad:
                continue  # Skip frozen parameters
            
            # Check parameter name for weight decay exclusion
            # Fixed: Added layer_norm (without .weight) and .bias check
            if any(nd in name for nd in ["bias", "LayerNorm", "layer_norm"]):
                no_decay_params.append(param)
            else:
                decay_params.append(param)
        
        # Create parameter groups with different weight decay
        optimizer_groups = [
            {
                'params': decay_params,
                'weight_decay': self.config.weight_decay,
            },
            {
                'params': no_decay_params,
                'weight_decay': 0.0,
            }
        ]
        
        # Select optimizer based on config
        if self.config.optimizer == "adamw":
            optimizer = optim.AdamW(
                optimizer_groups,
                lr=self.config.learning_rate,
                betas=(self.config.beta1, self.config.beta2),
                eps=self.config.eps,
                # Removed duplicate weight_decay parameter
            )
        elif self.config.optimizer == "adam":
            optimizer = optim.Adam(
                optimizer_groups,
                lr=self.config.learning_rate,
                betas=(self.config.beta1, self.config.beta2),
                eps=self.config.eps
            )
        elif self.config.optimizer == "sgd":
            optimizer = optim.SGD(
                optimizer_groups,
                lr=self.config.learning_rate,
                momentum=0.9,
                weight_decay=self.config.weight_decay
            )
        else:
            raise ValueError(f"Unknown optimizer: {self.config.optimizer}")
        
        return optimizer
    
    def _setup_scheduler(self) -> Optional[torch.optim.lr_scheduler._LRScheduler]:
        """
        Setup learning rate scheduler with warmup
        
        Returns:
            Learning rate scheduler or None
        """
        if self.config.scheduler == "cosine":
            # Cosine annealing with warmup
            scheduler = self._create_cosine_scheduler()
        elif self.config.scheduler == "linear":
            # Linear decay with warmup
            scheduler = self._create_linear_scheduler()
        elif self.config.scheduler == "step":
            # Step decay
            scheduler = optim.lr_scheduler.StepLR(
                self.optimizer,
                step_size=10000,
                gamma=0.1
            )
        elif self.config.scheduler == "plateau":
            # Reduce on plateau
            scheduler = optim.lr_scheduler.ReduceLROnPlateau(
                self.optimizer,
                mode='min',
                factor=0.5,
                patience=5,
                min_lr=1e-6
            )
        else:
            scheduler = None
        
        return scheduler
    
    def _create_cosine_scheduler(self) -> optim.lr_scheduler.LambdaLR:
        """
        Create cosine annealing scheduler with warmup
        
        Returns:
            LambdaLR scheduler with cosine decay
        """
        def lr_lambda(current_step: int):
            # Linear warmup for first warmup_steps
            if current_step < self.config.warmup_steps:
                return float(current_step) / float(max(1, self.config.warmup_steps))
            
            # Cosine decay after warmup
            progress = float(current_step - self.config.warmup_steps) / float(
                max(1, self.config.total_steps - self.config.warmup_steps)
            )
            return max(0.0, 0.5 * (1.0 + math.cos(math.pi * progress)))
        
        return optim.lr_scheduler.LambdaLR(self.optimizer, lr_lambda)
    
    def _create_linear_scheduler(self) -> optim.lr_scheduler.LambdaLR:
        """
        Create linear decay scheduler with warmup
        
        Returns:
            LambdaLR scheduler with linear decay
        """
        def lr_lambda(current_step: int):
            # Linear warmup for first warmup_steps
            if current_step < self.config.warmup_steps:
                return float(current_step) / float(max(1, self.config.warmup_steps))
            
            # Linear decay after warmup
            progress = float(current_step - self.config.warmup_steps) / float(
                max(1, self.config.total_steps - self.config.warmup_steps)
            )
            return max(0.0, 1.0 - progress)
        
        return optim.lr_scheduler.LambdaLR(self.optimizer, lr_lambda)
    
    def _enable_gradient_checkpointing(self):
        """
        Enable gradient checkpointing to save memory
        This trades compute for memory by recomputing activations during backward pass
        """
        # Check if model supports gradient checkpointing
        if hasattr(self.model, 'gradient_checkpointing_enable'):
            self.model.gradient_checkpointing_enable()
            self.logger.info("Gradient checkpointing enabled")
        elif hasattr(self.model, 'module') and hasattr(self.model.module, 'gradient_checkpointing_enable'):
            # Handle DistributedDataParallel wrapped models
            self.model.module.gradient_checkpointing_enable()
            self.logger.info("Gradient checkpointing enabled on wrapped model")
        else:
            self.logger.warning("Model does not support gradient checkpointing")
    
    def compute_loss(self, logits: torch.Tensor, labels: torch.Tensor) -> torch.Tensor:
        """
        Compute loss based on configured loss type
        
        Args:
            logits: Model predictions [batch_size, num_classes]
            labels: Ground truth labels [batch_size]
            
        Returns:
            Loss tensor
        """
        if self.config.loss_type == LossType.CROSS_ENTROPY:
            return F.cross_entropy(logits, labels)
        
        elif self.config.loss_type == LossType.FOCAL_LOSS:
            return self._focal_loss(logits, labels)
        
        elif self.config.loss_type == LossType.LABEL_SMOOTHING:
            return self._label_smoothing_loss(logits, labels)
        
        elif self.config.loss_type == LossType.CONTRASTIVE_LOSS:
            return self._contrastive_loss(logits, labels)
        
        else:
            raise ValueError(f"Unknown loss type: {self.config.loss_type}")
    
    def _focal_loss(self, logits: torch.Tensor, labels: torch.Tensor) -> torch.Tensor:
        """
        Focal loss for handling class imbalance in threat detection
        Down-weights easy examples and focuses on hard misclassified examples
        
        Args:
            logits: Model predictions [batch_size, num_classes]
            labels: Ground truth labels [batch_size]
            
        Returns:
            Focal loss tensor
        """
        # Get number of classes from logits shape
        num_classes = logits.size(-1)
        
        # Compute softmax probabilities
        probs = F.softmax(logits, dim=-1)
        
        # Create one-hot encoded labels
        labels_one_hot = F.one_hot(labels, num_classes).float()
        
        # Compute focal loss
        pt = (probs * labels_one_hot).sum(dim=1) + (1 - probs) * (1 - labels_one_hot).sum(dim=1)
        modulating_factor = (1 - pt) ** self.config.focal_loss_gamma
        
        # Cross entropy loss
        ce_loss = F.cross_entropy(logits, labels, reduction='none')
        
        # Apply focal weighting
        focal_loss = modulating_factor * ce_loss
        
        return focal_loss.mean()
    
    def _label_smoothing_loss(self, logits: torch.Tensor, labels: torch.Tensor) -> torch.Tensor:
        """
        Label smoothing loss for regularization
        Prevents overconfidence and improves generalization
        
        Args:
            logits: Model predictions [batch_size, num_classes]
            labels: Ground truth labels [batch_size]
            
        Returns:
            Label smoothing loss tensor
        """
        num_classes = logits.size(-1)
        
        # Create smoothed labels
        smooth_labels = torch.full_like(logits, 
                                       self.config.label_smoothing / (num_classes - 1))
        smooth_labels.scatter_(1, labels.unsqueeze(1), 
                             1.0 - self.config.label_smoothing)  # Fixed: changed to 1.0
        
        # Compute negative log likelihood with smoothed labels
        log_probs = F.log_softmax(logits, dim=-1)
        loss = -(smooth_labels * log_probs).sum(dim=-1).mean()
        
        return loss
    
    def _contrastive_loss(self, embeddings: torch.Tensor, labels: torch.Tensor) -> torch.Tensor:
        """
        Contrastive loss for learning good representations
        Pulls similar examples together, pushes dissimilar examples apart
        
        Args:
            embeddings: Model embeddings [batch_size, embedding_dim]
            labels: Ground truth labels [batch_size]
            
        Returns:
            Contrastive loss tensor
        """
        batch_size = embeddings.size(0)
        
        # Normalize embeddings to unit vectors
        embeddings = F.normalize(embeddings, p=2, dim=1)
        
        # Compute similarity matrix using cosine similarity
        similarity_matrix = torch.matmul(embeddings, embeddings.T)
        
        # Create mask for positive pairs (same class)
        label_matrix = labels.unsqueeze(0) == labels.unsqueeze(1)
        
        # Remove diagonal (self-similarity)
        mask = torch.eye(batch_size, device=embeddings.device).bool()
        label_matrix = label_matrix & (~mask)
        
        # Compute positive and negative similarities
        positive_similarities = similarity_matrix[label_matrix]
        negative_similarities = similarity_matrix[~label_matrix]
        
        # Reshape to ensure proper dimensions
        if positive_similarities.numel() > 0:
            positive_similarities = positive_similarities.view(batch_size, -1)
        else:
            positive_similarities = torch.zeros(batch_size, 0, device=embeddings.device)
            
        if negative_similarities.numel() > 0:
            negative_similarities = negative_similarities.view(batch_size, -1)
        else:
            negative_similarities = torch.zeros(batch_size, 0, device=embeddings.device)
        
        # Compute contrastive loss (InfoNCE style)
        # Positive pairs should have high similarity
        positive_loss = -torch.log(positive_similarities + 1e-8).mean()
        # Negative pairs should have low similarity
        negative_loss = torch.log(1 + torch.exp(negative_similarities)).mean()
        
        return positive_loss + negative_loss
    
    def train_step(self, batch: Dict[str, torch.Tensor]) -> Dict[str, float]:
        """
        Perform a single training step
        
        Args:
            batch: Dictionary containing 'input_ids' and 'labels'
            
        Returns:
            Dictionary with training metrics
        """
        # Set model to training mode
        self.model.train()
        
        # Move batch to device
        input_ids = batch['input_ids'].to(self.device)
        labels = batch['labels'].to(self.device)
        
        # Initialize gradient accumulation
        loss = 0.0
        accuracy = 0.0
        
        # Split batch for gradient accumulation
        batch_size = input_ids.size(0)
        chunk_size = max(1, batch_size // self.config.gradient_accumulation_steps)
        
        for i in range(self.config.gradient_accumulation_steps):
            # Get chunk of batch
            start_idx = i * chunk_size
            end_idx = min(start_idx + chunk_size, batch_size)
            
            # Skip if chunk is empty
            if start_idx >= end_idx:
                continue
                
            chunk_input = input_ids[start_idx:end_idx]
            chunk_labels = labels[start_idx:end_idx]
            
            # Forward pass with mixed precision if enabled
            with autocast(enabled=self.config.mixed_precision and torch.cuda.is_available()):
                outputs = self.model(chunk_input)
                
                # Check if model returns threat_logits
                if 'threat_logits' not in outputs:
                    raise KeyError("Model must return 'threat_logits' in outputs")
                    
                chunk_loss = self.compute_loss(outputs['threat_logits'], chunk_labels)
                
                # Scale loss for gradient accumulation
                chunk_loss = chunk_loss / self.config.gradient_accumulation_steps
            
            # Backward pass with gradient scaling for mixed precision
            if self.config.mixed_precision and self.scaler is not None:
                self.scaler.scale(chunk_loss).backward()
            else:
                chunk_loss.backward()
            
            # Accumulate metrics
            loss += chunk_loss.item() * self.config.gradient_accumulation_steps
            
            # Compute accuracy
            with torch.no_grad():
                predictions = torch.argmax(outputs['threat_logits'], dim=-1)
                chunk_accuracy = (predictions == chunk_labels).float().mean().item()
                accuracy += chunk_accuracy / self.config.gradient_accumulation_steps
        
        # Gradient clipping to prevent exploding gradients
        grad_norm = None
        if self.config.gradient_clip > 0:
            if self.config.mixed_precision and self.scaler is not None:
                self.scaler.unscale_(self.optimizer)
            
            # Clip gradients
            grad_norm = torch.nn.utils.clip_grad_norm_(
                self.model.parameters(),
                self.config.gradient_clip
            )
        
        # Optimizer step with gradient scaling for mixed precision
        if self.config.mixed_precision and self.scaler is not None:
            self.scaler.step(self.optimizer)
            self.scaler.update()
        else:
            self.optimizer.step()
        
        # Zero gradients
        self.optimizer.zero_grad()
        
        # Learning rate scheduler step (skip for ReduceLROnPlateau)
        if self.scheduler is not None and not isinstance(
            self.scheduler, optim.lr_scheduler.ReduceLROnPlateau
        ):
            self.scheduler.step()
        
        # Update global step
        self.global_step += 1
        
        # Get current learning rate
        current_lr = self.optimizer.param_groups[0]['lr']
        
        # Return metrics
        metrics = {
            'loss': loss,
            'accuracy': accuracy,
            'learning_rate': current_lr,
        }
        
        if grad_norm is not None:
            metrics['grad_norm'] = grad_norm.item()
        
        return metrics
    
    def validate(self, val_loader: DataLoader) -> Dict[str, float]:
        """
        Perform validation on the validation set
        
        Args:
            val_loader: DataLoader for validation data
            
        Returns:
            Dictionary with validation metrics
        """
        # Set model to evaluation mode
        self.model.eval()
        
        total_loss = 0.0
        total_accuracy = 0.0
        total_samples = 0
        
        # Disable gradient computation for validation
        with torch.no_grad():
            for batch in val_loader:
                # Move batch to device
                input_ids = batch['input_ids'].to(self.device)
                labels = batch['labels'].to(self.device)
                
                # Forward pass with mixed precision if enabled
                with autocast(enabled=self.config.mixed_precision and torch.cuda.is_available()):
                    outputs = self.model(input_ids)
                    
                    # Check if model returns threat_logits
                    if 'threat_logits' not in outputs:
                        raise KeyError("Model must return 'threat_logits' in outputs")
                        
                    loss = self.compute_loss(outputs['threat_logits'], labels)
                
                # Compute accuracy
                predictions = torch.argmax(outputs['threat_logits'], dim=-1)
                accuracy = (predictions == labels).float().mean().item()
                
                # Accumulate metrics
                batch_size = input_ids.size(0)
                total_loss += loss.item() * batch_size
                total_accuracy += accuracy * batch_size
                total_samples += batch_size
        
        # Compute average metrics
        avg_loss = total_loss / max(1, total_samples)
        avg_accuracy = total_accuracy / max(1, total_samples)
        
        return {
            'val_loss': avg_loss,
            'val_accuracy': avg_accuracy
        }
    
    def train(self, 
              train_loader: DataLoader, 
              val_loader: DataLoader, 
              num_epochs: Optional[int] = None) -> Dict[str, List[float]]:
        """
        Main training loop
        
        Args:
            train_loader: DataLoader for training data
            val_loader: DataLoader for validation data
            num_epochs: Number of epochs to train (overrides config if provided)
            
        Returns:
            Dictionary with training history
        """
        # Use config total_steps if epochs not specified
        if num_epochs is None:
            # Calculate epochs based on total steps
            steps_per_epoch = max(1, len(train_loader) // self.config.gradient_accumulation_steps)
            num_epochs = max(1, self.config.total_steps // steps_per_epoch)
        
        self.logger.info(f"Starting training for {num_epochs} epochs")
        self.logger.info(f"Total steps: {self.config.total_steps}")
        self.logger.info(f"Batch size: {self.config.batch_size}")
        self.logger.info(f"Learning rate: {self.config.learning_rate}")
        
        # Training loop
        for epoch in range(num_epochs):
            self.epoch = epoch + 1
            epoch_start_time = time.time()
            
            # Training phase
            epoch_loss = 0.0
            epoch_accuracy = 0.0
            num_batches = 0
            
            # Set sampler epoch for distributed training
            if self.config.distributed and hasattr(train_loader, 'sampler'):
                train_loader.sampler.set_epoch(epoch)
            
            for batch_idx, batch in enumerate(train_loader):
                # Training step
                metrics = self.train_step(batch)
                
                # Accumulate epoch metrics
                epoch_loss += metrics['loss']
                epoch_accuracy += metrics['accuracy']
                num_batches += 1
                
                # Log training progress
                if self.global_step % 100 == 0:
                    self._log_training_progress(metrics, batch_idx, len(train_loader))
                
                # Save checkpoint
                if self.global_step % self.config.save_checkpoint_steps == 0:
                    self.save_checkpoint(f"step_{self.global_step}")
                
                # Early stopping check based on steps
                if self.global_step >= self.config.total_steps:
                    self.logger.info(f"Reached total steps: {self.config.total_steps}")
                    break
            
            # Compute epoch averages
            avg_epoch_loss = epoch_loss / max(1, num_batches)
            avg_epoch_accuracy = epoch_accuracy / max(1, num_batches)
            
            # Validation phase
            val_metrics = self.validate(val_loader)
            
            # Update metrics history
            self.metrics['train_loss'].append(avg_epoch_loss)
            self.metrics['train_accuracy'].append(avg_epoch_accuracy)
            self.metrics['val_loss'].append(val_metrics['val_loss'])
            self.metrics['val_accuracy'].append(val_metrics['val_accuracy'])
            if num_batches > 0:  # Only add if we have training data
                self.metrics['learning_rate'].append(metrics.get('learning_rate', self.config.learning_rate))
            
            # Log epoch summary
            epoch_time = time.time() - epoch_start_time
            self._log_epoch_summary(epoch + 1, avg_epoch_loss, avg_epoch_accuracy, 
                                  val_metrics, epoch_time)
            
            # TensorBoard logging
            self._log_to_tensorboard(metrics, val_metrics)
            
            # Check early stopping based on validation loss
            if self._check_early_stopping(val_metrics['val_loss']):
                self.logger.info(f"Early stopping triggered at epoch {epoch + 1}")
                break
            
            # Learning rate scheduler step (for ReduceLROnPlateau)
            if isinstance(self.scheduler, optim.lr_scheduler.ReduceLROnPlateau):
                self.scheduler.step(val_metrics['val_loss'])
            
            # Check if we've reached total steps
            if self.global_step >= self.config.total_steps:
                self.logger.info(f"Reached total steps: {self.config.total_steps}")
                break
        
        self.logger.info("Training completed!")
        
        # Save final model
        self.save_checkpoint("final")
        
        # Close TensorBoard writer
        self.writer.close()
        
        return self.metrics
    
    def _log_training_progress(self, metrics: Dict[str, float], 
                             batch_idx: int, total_batches: int):
        """
        Log training progress during epoch
        
        Args:
            metrics: Training metrics from current batch
            batch_idx: Current batch index
            total_batches: Total number of batches in epoch
        """
        progress = (batch_idx + 1) / max(1, total_batches) * 100
        log_msg = (f"Step {self.global_step:6d} | "
                   f"Progress: {progress:5.1f}% | "
                   f"Loss: {metrics['loss']:.4f} | "
                   f"Acc: {metrics['accuracy']:.4f} | "
                   f"LR: {metrics['learning_rate']:.6f}")
        
        if 'grad_norm' in metrics:
            log_msg += f" | Grad Norm: {metrics['grad_norm']:.4f}"
        
        self.logger.info(log_msg)
    
    def _log_epoch_summary(self, epoch: int, train_loss: float, 
                          train_accuracy: float, val_metrics: Dict[str, float],
                          epoch_time: float):
        """
        Log summary at the end of each epoch
        
        Args:
            epoch: Current epoch number
            train_loss: Average training loss for epoch
            train_accuracy: Average training accuracy for epoch
            val_metrics: Validation metrics
            epoch_time: Time taken for epoch
        """
        self.logger.info("\n" + "="*80)
        self.logger.info(f"Epoch {epoch:3d} Summary:")
        self.logger.info(f"  Time: {epoch_time:.2f}s")
        self.logger.info(f"  Training Loss: {train_loss:.4f}")
        self.logger.info(f"  Training Accuracy: {train_accuracy:.4f}")
        self.logger.info(f"  Validation Loss: {val_metrics['val_loss']:.4f}")
        self.logger.info(f"  Validation Accuracy: {val_metrics['val_accuracy']:.4f}")
        self.logger.info("="*80 + "\n")
    
    def _log_to_tensorboard(self, train_metrics: Dict[str, float], 
                          val_metrics: Dict[str, float]):
        """
        Log metrics to TensorBoard for visualization
        
        Args:
            train_metrics: Training metrics
            val_metrics: Validation metrics
        """
        try:
            # Log scalar metrics
            self.writer.add_scalar('Loss/Train', train_metrics['loss'], self.global_step)
            self.writer.add_scalar('Loss/Validation', val_metrics['val_loss'], self.global_step)
            self.writer.add_scalar('Accuracy/Train', train_metrics['accuracy'], self.global_step)
            self.writer.add_scalar('Accuracy/Validation', val_metrics['val_accuracy'], self.global_step)
            self.writer.add_scalar('Learning_Rate', train_metrics['learning_rate'], self.global_step)
            
            if 'grad_norm' in train_metrics:
                self.writer.add_scalar('Gradient_Norm', train_metrics['grad_norm'], self.global_step)
        except Exception as e:
            self.logger.warning(f"Failed to log to TensorBoard: {e}")
    
    def _check_early_stopping(self, val_loss: float) -> bool:
        """
        Check if early stopping criteria is met
        
        Args:
            val_loss: Current validation loss
            
        Returns:
            True if training should stop, False otherwise
        """
        # Check for improvement
        improvement = self.best_loss - val_loss
        
        if improvement > self.config.early_stopping_min_delta:
            # Improvement detected, update best loss and reset patience
            self.best_loss = val_loss
            self.patience_counter = 0
            self.logger.info(f"New best validation loss: {val_loss:.4f}")
            return False
        else:
            # No improvement, increment patience counter
            self.patience_counter += 1
            self.logger.info(f"No improvement for {self.patience_counter} epochs")
            
            # Check if patience exceeded
            if self.patience_counter >= self.config.early_stopping_patience:
                return True
        
        return False
    
    def save_checkpoint(self, name: str):
        """
        Save training checkpoint
        
        Args:
            name: Checkpoint name
        """
        # Create checkpoint directory if it doesn't exist
        checkpoint_dir = Path(self.config.checkpoint_dir)
        checkpoint_dir.mkdir(parents=True, exist_ok=True)
        
        # Get model state dict (handle DistributedDataParallel)
        if isinstance(self.model, nn.parallel.DistributedDataParallel):
            model_state_dict = self.model.module.state_dict()
        else:
            model_state_dict = self.model.state_dict()
        
        # Prepare checkpoint dictionary
        checkpoint = {
            'epoch': self.epoch,
            'global_step': self.global_step,
            'model_state_dict': model_state_dict,
            'optimizer_state_dict': self.optimizer.state_dict(),
            'scheduler_state_dict': self.scheduler.state_dict() if self.scheduler else None,
            'scaler_state_dict': self.scaler.state_dict() if self.scaler else None,
            'best_loss': self.best_loss,
            'metrics': self.metrics,
            'config': self.config.__dict__,
        }
        
        # Save checkpoint
        checkpoint_path = checkpoint_dir / f"{name}.pt"
        torch.save(checkpoint, checkpoint_path)
        
        # Clean up old checkpoints
        self._cleanup_old_checkpoints(checkpoint_dir)
        
        self.logger.info(f"Checkpoint saved: {checkpoint_path}")
    
    def _cleanup_old_checkpoints(self, checkpoint_dir: Path):
        """
        Clean up old checkpoints, keeping only the most recent ones
        
        Args:
            checkpoint_dir: Directory containing checkpoints
        """
        # List all checkpoint files
        checkpoint_files = list(checkpoint_dir.glob("*.pt"))
        
        if len(checkpoint_files) > self.config.max_checkpoints:
            # Sort by modification time (oldest first)
            checkpoint_files.sort(key=lambda x: x.stat().st_mtime)
            
            # Remove oldest checkpoints
            files_to_remove = checkpoint_files[:-self.config.max_checkpoints]
            for file_path in files_to_remove:
                try:
                    file_path.unlink()
                    self.logger.info(f"Removed old checkpoint: {file_path}")
                except Exception as e:
                    self.logger.warning(f"Failed to remove checkpoint {file_path}: {e}")
    
    def load_checkpoint(self, checkpoint_path: str):
        """
        Load training checkpoint
        
        Args:
            checkpoint_path: Path to checkpoint file
        """
        checkpoint = torch.load(checkpoint_path, map_location=self.device)
        
        # Load model state
        if isinstance(self.model, nn.parallel.DistributedDataParallel):
            self.model.module.load_state_dict(checkpoint['model_state_dict'])
        else:
            self.model.load_state_dict(checkpoint['model_state_dict'])
        
        # Load optimizer state
        self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
        
        # Load scheduler state
        if checkpoint['scheduler_state_dict'] and self.scheduler:
            self.scheduler.load_state_dict(checkpoint['scheduler_state_dict'])
        
        # Load scaler state for mixed precision
        if checkpoint['scaler_state_dict'] and self.scaler:
            self.scaler.load_state_dict(checkpoint['scaler_state_dict'])
        
        # Load training state
        self.epoch = checkpoint['epoch']
        self.global_step = checkpoint['global_step']
        self.best_loss = checkpoint['best_loss']
        self.metrics = checkpoint['metrics']
        
        self.logger.info(f"Checkpoint loaded from {checkpoint_path}")
        self.logger.info(f"Resuming from epoch {self.epoch}, step {self.global_step}")
    
    def evaluate(self, test_loader: DataLoader) -> Dict[str, Any]:
        """
        Evaluate model on test set
        
        Args:
            test_loader: DataLoader for test data
            
        Returns:
            Dictionary with evaluation metrics
        """
        self.model.eval()
        
        all_predictions = []
        all_labels = []
        total_loss = 0.0
        total_samples = 0
        
        # Disable gradient computation
        with torch.no_grad():
            for batch in test_loader:
                # Move batch to device
                input_ids = batch['input_ids'].to(self.device)
                labels = batch['labels'].to(self.device)
                
                # Forward pass with mixed precision if enabled
                with autocast(enabled=self.config.mixed_precision and torch.cuda.is_available()):
                    outputs = self.model(input_ids)
                    
                    # Check if model returns threat_logits
                    if 'threat_logits' not in outputs:
                        raise KeyError("Model must return 'threat_logits' in outputs")
                        
                    loss = self.compute_loss(outputs['threat_logits'], labels)
                
                # Get predictions
                predictions = torch.argmax(outputs['threat_logits'], dim=-1)
                
                # Accumulate
                all_predictions.extend(predictions.cpu().numpy())
                all_labels.extend(labels.cpu().numpy())
                
                batch_size = input_ids.size(0)
                total_loss += loss.item() * batch_size
                total_samples += batch_size
        
        # Compute basic metrics
        avg_loss = total_loss / max(1, total_samples)
        accuracy = np.mean(np.array(all_predictions) == np.array(all_labels))
        
        # Compute additional metrics for threat detection
        try:
            from sklearn.metrics import precision_recall_fscore_support, confusion_matrix
            
            precision, recall, f1, _ = precision_recall_fscore_support(
                all_labels, all_predictions, average='weighted'
            )
            
            # Create confusion matrix
            conf_matrix = confusion_matrix(all_labels, all_predictions)
            
            # Compute threat detection specific metrics
            threat_metrics = self._compute_threat_detection_metrics(all_labels, all_predictions)
            
            return {
                'test_loss': avg_loss,
                'test_accuracy': accuracy,
                'test_precision': precision,
                'test_recall': recall,
                'test_f1': f1,
                'confusion_matrix': conf_matrix.tolist(),  # Convert to list for JSON serialization
                **threat_metrics
            }
        except ImportError:
            self.logger.warning("scikit-learn not installed, returning basic metrics only")
            return {
                'test_loss': avg_loss,
                'test_accuracy': accuracy,
            }
    
    def _compute_threat_detection_metrics(self, labels: List[int], 
                                        predictions: List[int]) -> Dict[str, float]:
        """
        Compute threat detection specific metrics
        
        Args:
            labels: Ground truth labels
            predictions: Model predictions
            
        Returns:
            Dictionary with threat detection metrics
        """
        # Convert to numpy arrays
        labels = np.array(labels)
        predictions = np.array(predictions)
        
        # Threat detection metrics
        metrics = {}
        
        # Get unique classes
        unique_classes = np.unique(labels)
        
        # True Positive Rate (Sensitivity) for each threat class
        for threat_class in unique_classes:
            true_positives = np.sum((labels == threat_class) & (predictions == threat_class))
            actual_positives = np.sum(labels == threat_class)
            
            if actual_positives > 0:
                tpr = true_positives / actual_positives
                metrics[f'tpr_class_{threat_class}'] = float(tpr)
        
        # False Positive Rate for each threat class
        for threat_class in unique_classes:
            false_positives = np.sum((labels != threat_class) & (predictions == threat_class))
            actual_negatives = np.sum(labels != threat_class)
            
            if actual_negatives > 0:
                fpr = false_positives / actual_negatives
                metrics[f'fpr_class_{threat_class}'] = float(fpr)
        
        # Threat severity weighted accuracy
        # Higher weight for critical threats (assuming class 0-2 are critical)
        severity_weights = {
            0: 3.0,  # Critical threats
            1: 2.0,  # High severity
            2: 1.5,  # Medium severity
        }
        
        weighted_correct = 0.0
        weighted_total = 0.0
        
        for label, pred in zip(labels, predictions):
            weight = severity_weights.get(int(label), 1.0)
            weighted_total += weight
            if label == pred:
                weighted_correct += weight
        
        if weighted_total > 0:
            metrics['weighted_accuracy'] = float(weighted_correct / weighted_total)
        
        return metrics
    
    def export_model(self, export_path: str, format: str = "onnx"):
        """
        Export trained model for deployment
        
        Args:
            export_path: Path to save exported model
            format: Export format ("onnx", "torchscript", "safetensors")
        """
        self.model.eval()
        
        if format == "onnx":
            self._export_to_onnx(export_path)
        elif format == "torchscript":
            self._export_to_torchscript(export_path)
        elif format == "safetensors":
            self._export_to_safetensors(export_path)
        else:
            raise ValueError(f"Unknown export format: {format}")
        
        self.logger.info(f"Model exported to {export_path} in {format} format")
    
    def _export_to_onnx(self, export_path: str):
        """
        Export model to ONNX format for production deployment
        
        Args:
            export_path: Path to save ONNX model
        """
        # Get model (unwrap from DistributedDataParallel if needed)
        if isinstance(self.model, nn.parallel.DistributedDataParallel):
            model_to_export = self.model.module
        else:
            model_to_export = self.model
        
        # Create dummy input for tracing
        dummy_input = torch.randint(0, self.config.vocab_size, 
                                   (1, 256), device=self.device)
        
        # Export model
        torch.onnx.export(
            model_to_export,
            dummy_input,
            export_path,
            export_params=True,
            opset_version=14,
            do_constant_folding=True,
            input_names=['input_ids'],
            output_names=['threat_logits'],  # Fixed: removed severity_score which wasn't defined
            dynamic_axes={
                'input_ids': {0: 'batch_size', 1: 'sequence_length'},
                'threat_logits': {0: 'batch_size'},
            },
        )
        
        # Verify exported model
        onnx_model = onnx.load(export_path)
        onnx.checker.check_model(onnx_model)
        
        # Test with ONNX Runtime
        ort_session = ort.InferenceSession(export_path)
        ort_inputs = {ort_session.get_inputs()[0].name: 
                     dummy_input.cpu().numpy()}
        ort_outputs = ort_session.run(None, ort_inputs)
        
        self.logger.info(f"ONNX model verified and ready for deployment")
    
    def _export_to_torchscript(self, export_path: str):
        """
        Export model to TorchScript for production deployment
        
        Args:
            export_path: Path to save TorchScript model
        """
        # Get model (unwrap from DistributedDataParallel if needed)
        if isinstance(self.model, nn.parallel.DistributedDataParallel):
            model_to_export = self.model.module
        else:
            model_to_export = self.model
            
        # Set model to evaluation mode
        model_to_export.eval()
        
        # Trace model
        dummy_input = torch.randint(0, self.config.vocab_size, 
                                   (1, 256), device=self.device)
        
        traced_model = torch.jit.trace(model_to_export, dummy_input)
        traced_model.save(export_path)
    
    def _export_to_safetensors(self, export_path: str):
        """
        Export model to SafeTensors format
        
        Args:
            export_path: Path to save SafeTensors model
        """
        # Get model state dict (unwrap from DistributedDataParallel if needed)
        if isinstance(self.model, nn.parallel.DistributedDataParallel):
            state_dict = self.model.module.state_dict()
        else:
            state_dict = self.model.state_dict()
        
        # Save to SafeTensors format
        save_file(state_dict, export_path)


def create_training_data_loader(dataset, config: GQATrainingConfig, 
                              is_training: bool = True) -> DataLoader:
    """
    Create DataLoader for training or validation
    
    Args:
        dataset: Dataset object
        config: Training configuration
        is_training: Whether this is for training (shuffle) or validation
        
    Returns:
        Configured DataLoader
    """
    if config.distributed and torch.cuda.is_available():
        # Distributed sampler for multi-GPU training
        sampler = DistributedSampler(
            dataset,
            num_replicas=config.world_size,
            rank=config.local_rank,
            shuffle=is_training
        )
    else:
        sampler = None
    
    # Create DataLoader
    loader = DataLoader(
        dataset,
        batch_size=config.batch_size,
        shuffle=(is_training and sampler is None),
        sampler=sampler,
        num_workers=min(4, os.cpu_count() or 1),  # Adjust based on available CPUs
        pin_memory=torch.cuda.is_available(),  # Faster data transfer to GPU
        drop_last=is_training,  # Drop last incomplete batch for training
        persistent_workers=True  # Keep workers alive between epochs
    )
    
    return loader