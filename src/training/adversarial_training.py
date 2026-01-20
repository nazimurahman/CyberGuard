# src/training/adversarial_training.py
"""
Adversarial Training Module for Cybersecurity AI
Purpose: Make AI models robust against adversarial attacks and evasion techniques

This module implements:
1. Adversarial example generation for security threats
2. Adversarial training with various attack methods
3. Defense against evasion attacks in security systems
4. Robustness evaluation against adversarial perturbations
5. Certified defenses for provable security
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from torch.autograd import grad
import numpy as np
from typing import Dict, List, Tuple, Optional, Any, Callable
import time
import logging
from pathlib import Path
from dataclasses import dataclass
from enum import Enum
import random
import math


class AttackMethod(Enum):
    """Adversarial attack methods for security testing"""
    FGSM = "fgsm"  # Fast Gradient Sign Method
    PGD = "pgd"    # Projected Gradient Descent
    CW = "cw"      # Carlini & Wagner attack
    DEEPFOOL = "deepfool"  # DeepFool attack
    JSMA = "jsma"  # Jacobian-based Saliency Map Attack
    BIM = "bim"    # Basic Iterative Method
    MIM = "mim"    # Momentum Iterative Method
    AUTOATTACK = "autoattack"  # Ensemble of attacks


class DefenseMethod(Enum):
    """Defense methods against adversarial attacks"""
    ADVERSARIAL_TRAINING = "adversarial_training"
    DISTILLATION = "distillation"
    RANDOMIZATION = "randomization"
    ENSEMBLE = "ensemble"
    CERTIFIED_ROBUSTNESS = "certified_robustness"
    DETECTION = "detection"


@dataclass
class AdversarialTrainingConfig:
    """
    Configuration for adversarial training
    
    Parameters for generating attacks and training robust models
    """
    # Attack configuration
    attack_method: AttackMethod = AttackMethod.PGD
    epsilon: float = 0.03  # Maximum perturbation (L∞ norm)
    step_size: float = 0.01  # Step size for iterative attacks
    num_steps: int = 40  # Number of attack iterations
    
    # Attack-specific parameters
    cw_confidence: float = 0.0  # Confidence for CW attack
    cw_learning_rate: float = 0.01  # Learning rate for CW attack
    cw_iterations: int = 1000  # Iterations for CW attack
    
    # Defense configuration
    defense_method: DefenseMethod = DefenseMethod.ADVERSARIAL_TRAINING
    adversarial_weight: float = 0.5  # Weight for adversarial loss
    
    # Training parameters
    batch_size: int = 32
    learning_rate: float = 1e-4
    num_epochs: int = 100
    warmup_epochs: int = 10  # Train normally before adversarial training
    
    # Robustness evaluation
    eval_attacks: List[AttackMethod] = None  # Attacks to evaluate against
    eval_epsilons: List[float] = None  # Perturbation sizes to evaluate
    
    # Certified robustness
    certified_smoothing: bool = False
    smoothing_noise: float = 0.25  # Noise level for randomized smoothing
    smoothing_samples: int = 1000  # Samples for certification
    
    # Checkpointing
    save_frequency: int = 10  # Save every N epochs
    checkpoint_dir: str = "./checkpoints/adversarial"
    
    def __post_init__(self):
        """Set default values for eval parameters"""
        if self.eval_attacks is None:
            self.eval_attacks = [AttackMethod.FGSM, AttackMethod.PGD]
        
        if self.eval_epsilons is None:
            self.eval_epsilons = [0.01, 0.03, 0.05, 0.1]


class AdversarialAttacker:
    """
    Generates adversarial examples for security models
    
    Implements various attack methods to test model robustness
    """
    
    def __init__(self, model: nn.Module, config: AdversarialTrainingConfig):
        """
        Initialize adversarial attacker
        
        Args:
            model: Model to attack
            config: Attack configuration
        """
        self.model = model
        self.config = config
        
        # Set model to evaluation mode for attacks
        self.model.eval()
    
    def fgsm_attack(self, images: torch.Tensor, labels: torch.Tensor) -> torch.Tensor:
        """
        Fast Gradient Sign Method (FGSM) attack
        
        Args:
            images: Clean images [batch_size, ...]
            labels: True labels
            
        Returns:
            Adversarial images
        """
        # Enable gradient computation
        images.requires_grad = True
        
        # Forward pass
        outputs = self.model(images)
        loss = F.cross_entropy(outputs, labels)
        
        # Compute gradients
        self.model.zero_grad()
        loss.backward()
        
        # Get gradient sign
        gradient_sign = images.grad.data.sign()
        
        # Create adversarial examples
        adversarial_images = images + self.config.epsilon * gradient_sign
        
        # Clip to valid range
        adversarial_images = torch.clamp(adversarial_images, 0, 1)
        
        return adversarial_images.detach()
    
    def pgd_attack(self, images: torch.Tensor, labels: torch.Tensor) -> torch.Tensor:
        """
        Projected Gradient Descent (PGD) attack
        
        Args:
            images: Clean images [batch_size, ...]
            labels: True labels
            
        Returns:
            Adversarial images
        """
        # Initialize adversarial examples with random noise
        adversarial_images = images.clone().detach()
        adversarial_images = adversarial_images + torch.empty_like(adversarial_images).uniform_(
            -self.config.epsilon, self.config.epsilon
        )
        adversarial_images = torch.clamp(adversarial_images, 0, 1)
        
        # PGD iterations
        for i in range(self.config.num_steps):
            adversarial_images.requires_grad = True
            
            # Forward pass
            outputs = self.model(adversarial_images)
            loss = F.cross_entropy(outputs, labels)
            
            # Compute gradients
            self.model.zero_grad()
            loss.backward()
            
            # Get gradient
            gradient = adversarial_images.grad.data
            
            # Update adversarial images
            adversarial_images = adversarial_images.detach() + self.config.step_size * gradient.sign()
            
            # Project back to epsilon ball
            delta = torch.clamp(adversarial_images - images, 
                              -self.config.epsilon, self.config.epsilon)
            adversarial_images = images + delta
            
            # Clip to valid range
            adversarial_images = torch.clamp(adversarial_images, 0, 1)
        
        return adversarial_images.detach()
    
    def cw_attack(self, images: torch.Tensor, labels: torch.Tensor) -> torch.Tensor:
        """
        Carlini & Wagner (CW) L2 attack
        
        Args:
            images: Clean images [batch_size, ...]
            labels: True labels
            
        Returns:
            Adversarial images
        """
        batch_size = images.shape[0]
        
        # Variables to optimize
        w = torch.zeros_like(images, requires_grad=True)
        
        # Optimizer for CW attack
        optimizer = optim.Adam([w], lr=self.config.cw_learning_rate)
        
        # Target labels (least likely class)
        with torch.no_grad():
            outputs = self.model(images)
            target_labels = torch.argmin(outputs, dim=1)
        
        # CW optimization loop
        for iteration in range(self.config.cw_iterations):
            # Compute adversarial images from w
            adversarial_images = 0.5 * (torch.tanh(w) + 1)
            
            # Forward pass
            outputs = self.model(adversarial_images)
            
            # CW loss components
            # 1. Distance loss (L2 norm)
            l2_distance = torch.norm(adversarial_images - images, p=2, dim=(1, 2, 3))
            
            # 2. Classification loss
            correct_logits = outputs[range(batch_size), labels]
            target_logits = outputs[range(batch_size), target_labels]
            
            # CW loss function
            loss = l2_distance.sum() + torch.clamp(correct_logits - target_logits + self.config.cw_confidence, min=0).sum()
            
            # Optimization step
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
        
        # Final adversarial images
        adversarial_images = 0.5 * (torch.tanh(w) + 1).detach()
        
        return adversarial_images
    
    def deepfool_attack(self, images: torch.Tensor, labels: torch.Tensor) -> torch.Tensor:
        """
        DeepFool attack for minimal perturbation
        
        Args:
            images: Clean images [batch_size, ...]
            labels: True labels
            
        Returns:
            Adversarial images
        """
        batch_size = images.shape[0]
        image_shape = images.shape[1:]
        
        adversarial_images = images.clone().detach()
        adversarial_images.requires_grad = True
        
        # Forward pass
        outputs = self.model(adversarial_images)
        
        # Get number of classes
        num_classes = outputs.shape[1]
        
        # Compute gradient for each class
        grads = []
        for c in range(num_classes):
            # Zero gradients
            if adversarial_images.grad is not None:
                adversarial_images.grad.zero_()
            
            # Compute gradient for class c
            loss = outputs[:, c].sum()
            loss.backward(retain_graph=True)
            
            grads.append(adversarial_images.grad.clone())
        
        # Compute DeepFool perturbation for each sample
        for i in range(batch_size):
            image = images[i]
            label = labels[i]
            
            # Initialize perturbation
            perturbation = torch.zeros_like(image)
            
            # DeepFool iterations
            for iteration in range(50):
                adversarial_image = image + perturbation
                adversarial_image.requires_grad = True
                
                # Forward pass
                output = self.model(adversarial_image.unsqueeze(0))
                
                # Get top-2 classes
                sorted_indices = torch.argsort(output[0], descending=True)
                
                if sorted_indices[0] != label:
                    # Already misclassified
                    break
                
                # Compute perturbation
                w = grads[sorted_indices[1]][i] - grads[label][i]
                f = output[0, sorted_indices[1]] - output[0, label]
                
                perturbation_i = (torch.abs(f) / torch.norm(w.flatten())) * w
                perturbation += perturbation_i
                
                # Check if misclassified
                if torch.norm(perturbation) > 10 * self.config.epsilon:
                    break
            
            # Apply perturbation with epsilon constraint
            perturbation = torch.clamp(perturbation, -self.config.epsilon, self.config.epsilon)
            adversarial_images[i] = image + perturbation
        
        return adversarial_images.detach()
    
    def generate_attack(self, images: torch.Tensor, labels: torch.Tensor) -> torch.Tensor:
        """
        Generate adversarial examples using configured attack method
        
        Args:
            images: Clean images
            labels: True labels
            
        Returns:
            Adversarial images
        """
        if self.config.attack_method == AttackMethod.FGSM:
            return self.fgsm_attack(images, labels)
        elif self.config.attack_method == AttackMethod.PGD:
            return self.pgd_attack(images, labels)
        elif self.config.attack_method == AttackMethod.CW:
            return self.cw_attack(images, labels)
        elif self.config.attack_method == AttackMethod.DEEPFOOL:
            return self.deepfool_attack(images, labels)
        elif self.config.attack_method == AttackMethod.BIM:
            return self.bim_attack(images, labels)
        elif self.config.attack_method == AttackMethod.MIM:
            return self.mim_attack(images, labels)
        else:
            raise ValueError(f"Unknown attack method: {self.config.attack_method}")
    
    def bim_attack(self, images: torch.Tensor, labels: torch.Tensor) -> torch.Tensor:
        """
        Basic Iterative Method (BIM) attack
        
        Args:
            images: Clean images
            labels: True labels
            
        Returns:
            Adversarial images
        """
        # BIM is similar to PGD but with smaller step size and more iterations
        original_step_size = self.config.step_size
        original_num_steps = self.config.num_steps
        
        # Use smaller step size for BIM
        self.config.step_size = self.config.epsilon / 10
        self.config.num_steps = min(100, original_num_steps * 2)
        
        adversarial_images = self.pgd_attack(images, labels)
        
        # Restore original configuration
        self.config.step_size = original_step_size
        self.config.num_steps = original_num_steps
        
        return adversarial_images
    
    def mim_attack(self, images: torch.Tensor, labels: torch.Tensor) -> torch.Tensor:
        """
        Momentum Iterative Method (MIM) attack
        
        Args:
            images: Clean images
            labels: True labels
            
        Returns:
            Adversarial images
        """
        adversarial_images = images.clone().detach()
        momentum = torch.zeros_like(images)
        
        # MIM hyperparameters
        decay_factor = 1.0
        num_iterations = self.config.num_steps
        
        for i in range(num_iterations):
            adversarial_images.requires_grad = True
            
            # Forward pass
            outputs = self.model(adversarial_images)
            loss = F.cross_entropy(outputs, labels)
            
            # Compute gradients
            self.model.zero_grad()
            loss.backward()
            
            # Accumulate momentum
            gradient = adversarial_images.grad.data
            momentum = decay_factor * momentum + gradient / torch.norm(gradient.view(gradient.shape[0], -1), p=1, dim=1).view(-1, 1, 1, 1)
            
            # Update adversarial images
            adversarial_images = adversarial_images.detach() + self.config.step_size * momentum.sign()
            
            # Project back to epsilon ball
            delta = torch.clamp(adversarial_images - images, 
                              -self.config.epsilon, self.config.epsilon)
            adversarial_images = images + delta
            
            # Clip to valid range
            adversarial_images = torch.clamp(adversarial_images, 0, 1)
        
        return adversarial_images.detach()


class RandomizedSmoothing:
    """
    Randomized smoothing for certified robustness
    
    Provides provable robustness guarantees against adversarial attacks
    """
    
    def __init__(self, base_model: nn.Module, sigma: float = 0.25):
        """
        Initialize randomized smoothing
        
        Args:
            base_model: Base classification model
            sigma: Noise standard deviation
        """
        self.base_model = base_model
        self.sigma = sigma
    
    def predict(self, images: torch.Tensor, num_samples: int = 1000, 
                alpha: float = 0.001) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Make prediction with randomized smoothing
        
        Args:
            images: Input images
            num_samples: Number of noise samples
            alpha: Confidence level for certification
            
        Returns:
            Tuple of (predictions, robustness radii)
        """
        batch_size = images.shape[0]
        
        # Sample noise
        noise = torch.randn(num_samples, *images.shape, device=images.device) * self.sigma
        
        # Repeat images for each noise sample
        images_repeated = images.repeat(num_samples, 1, 1, 1)
        
        # Add noise
        noisy_images = images_repeated + noise
        
        # Get predictions
        with torch.no_grad():
            outputs = self.base_model(noisy_images)
            predictions = torch.argmax(outputs, dim=1)
        
        # Reshape predictions
        predictions = predictions.view(num_samples, batch_size)
        
        # Count votes for each class
        votes = torch.zeros(batch_size, outputs.shape[1], device=images.device)
        for b in range(batch_size):
            for s in range(num_samples):
                votes[b, predictions[s, b]] += 1
        
        # Get top-2 classes
        top_values, top_indices = torch.topk(votes, 2, dim=1)
        
        # Predictions (most voted class)
        pred_labels = top_indices[:, 0]
        
        # Compute robustness radius using binomial confidence interval
        p_a = top_values[:, 0] / num_samples
        p_b = top_values[:, 1] / num_samples
        
        # Lower bound for p_a
        p_a_lower = self._binomial_lower_bound(p_a, num_samples, alpha)
        
        # Upper bound for p_b
        p_b_upper = self._binomial_upper_bound(p_b, num_samples, alpha)
        
        # Certified radius
        radii = (self.sigma / 2) * (p_a_lower - p_b_upper)
        radii = torch.clamp(radii, min=0)
        
        return pred_labels, radii
    
    def _binomial_lower_bound(self, p: torch.Tensor, n: int, alpha: float) -> torch.Tensor:
        """Compute lower confidence bound for binomial proportion"""
        # Clopper-Pearson exact interval
        import scipy.stats as stats
        
        lower_bounds = []
        for p_val in p.cpu().numpy():
            k = int(p_val * n)
            if k == 0:
                lower = 0.0
            else:
                lower = stats.beta.ppf(alpha / 2, k, n - k + 1)
            lower_bounds.append(lower)
        
        return torch.tensor(lower_bounds, device=p.device)
    
    def _binomial_upper_bound(self, p: torch.Tensor, n: int, alpha: float) -> torch.Tensor:
        """Compute upper confidence bound for binomial proportion"""
        import scipy.stats as stats
        
        upper_bounds = []
        for p_val in p.cpu().numpy():
            k = int(p_val * n)
            if k == n:
                upper = 1.0
            else:
                upper = stats.beta.ppf(1 - alpha / 2, k + 1, n - k)
            upper_bounds.append(upper)
        
        return torch.tensor(upper_bounds, device=p.device)


class AdversarialTrainer:
    """
    Trainer for adversarial robustness in security models
    
    Implements various defense methods against adversarial attacks
    """
    
    def __init__(self, model: nn.Module, config: AdversarialTrainingConfig):
        """
        Initialize adversarial trainer
        
        Args:
            model: Model to train
            config: Training configuration
        """
        self.model = model
        self.config = config
        
        # Setup device
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)
        
        # Setup optimizer
        self.optimizer = optim.Adam(
            self.model.parameters(),
            lr=config.learning_rate,
            weight_decay=1e-4
        )
        
        # Setup adversarial attacker
        self.attacker = AdversarialAttacker(self.model, config)
        
        # Setup randomized smoothing if enabled
        if config.certified_smoothing:
            self.smoothing = RandomizedSmoothing(
                self.model,
                sigma=config.smoothing_noise
            )
        else:
            self.smoothing = None
        
        # Training state
        self.epoch = 0
        self.best_robust_accuracy = 0.0
        
        # Metrics tracking
        self.metrics = {
            'train_loss': [],
            'train_accuracy': [],
            'train_robust_accuracy': [],
            'val_loss': [],
            'val_accuracy': [],
            'val_robust_accuracy': [],
            'certified_radii': []
        }
        
        # Setup logging
        self.logger = self._setup_logger()
        
        self.logger.info(f"Adversarial Trainer initialized")
        self.logger.info(f"Attack method: {config.attack_method}")
        self.logger.info(f"Defense method: {config.defense_method}")
        self.logger.info(f"Epsilon: {config.epsilon}")
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger("AdversarialTrainer")
        logger.setLevel(logging.INFO)
        
        # Create logs directory
        log_dir = Path("logs/adversarial")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # File handler
        file_handler = logging.FileHandler(
            log_dir / f"adversarial_training_{time.strftime('%Y%m%d_%H%M%S')}.log"
        )
        file_handler.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def adversarial_training_step(self, images: torch.Tensor, 
                                labels: torch.Tensor) -> Dict[str, float]:
        """
        Adversarial training step
        
        Args:
            images: Clean images
            labels: True labels
            
        Returns:
            Training metrics
        """
        self.model.train()
        
        # Move data to device
        images = images.to(self.device)
        labels = labels.to(self.device)
        
        # Generate adversarial examples
        adversarial_images = self.attacker.generate_attack(images, labels)
        
        # Forward pass on clean and adversarial images
        clean_outputs = self.model(images)
        adversarial_outputs = self.model(adversarial_images)
        
        # Compute losses
        clean_loss = F.cross_entropy(clean_outputs, labels)
        adversarial_loss = F.cross_entropy(adversarial_outputs, labels)
        
        # Combined loss
        loss = (1 - self.config.adversarial_weight) * clean_loss + \
               self.config.adversarial_weight * adversarial_loss
        
        # Optimization step
        self.optimizer.zero_grad()
        loss.backward()
        self.optimizer.step()
        
        # Compute accuracies
        clean_accuracy = (clean_outputs.argmax(dim=1) == labels).float().mean().item()
        robust_accuracy = (adversarial_outputs.argmax(dim=1) == labels).float().mean().item()
        
        return {
            'loss': loss.item(),
            'clean_accuracy': clean_accuracy,
            'robust_accuracy': robust_accuracy
        }
    
    def distillation_training_step(self, images: torch.Tensor, 
                                 labels: torch.Tensor, 
                                 teacher_model: nn.Module, 
                                 temperature: float = 4.0) -> Dict[str, float]:
        """
        Defensive distillation training step
        
        Args:
            images: Clean images
            labels: True labels
            teacher_model: Teacher model for distillation
            temperature: Distillation temperature
            
        Returns:
            Training metrics
        """
        self.model.train()
        teacher_model.eval()
        
        images = images.to(self.device)
        labels = labels.to(self.device)
        
        # Get teacher predictions
        with torch.no_grad():
            teacher_logits = teacher_model(images)
            teacher_probs = F.softmax(teacher_logits / temperature, dim=-1)
        
        # Generate adversarial examples
        adversarial_images = self.attacker.generate_attack(images, labels)
        
        # Student forward pass
        student_logits = self.model(adversarial_images)
        student_probs = F.softmax(student_logits / temperature, dim=-1)
        
        # Distillation loss (KL divergence)
        distillation_loss = F.kl_div(
            student_probs.log(),
            teacher_probs,
            reduction='batchmean'
        )
        
        # Standard cross-entropy loss
        ce_loss = F.cross_entropy(student_logits, labels)
        
        # Combined loss
        loss = 0.5 * distillation_loss + 0.5 * ce_loss
        
        # Optimization step
        self.optimizer.zero_grad()
        loss.backward()
        self.optimizer.step()
        
        # Compute accuracy
        accuracy = (student_logits.argmax(dim=1) == labels).float().mean().item()
        
        return {
            'loss': loss.item(),
            'accuracy': accuracy,
            'distillation_loss': distillation_loss.item(),
            'ce_loss': ce_loss.item()
        }
    
    def train_epoch(self, train_loader, defense_method: DefenseMethod = None):
        """
        Train for one epoch
        
        Args:
            train_loader: Training data loader
            defense_method: Defense method to use (overrides config)
        """
        if defense_method is None:
            defense_method = self.config.defense_method
        
        epoch_loss = 0
        epoch_clean_accuracy = 0
        epoch_robust_accuracy = 0
        num_batches = 0
        
        for batch_idx, (images, labels) in enumerate(train_loader):
            # Skip warmup epochs for adversarial training
            if self.epoch < self.config.warmup_epochs:
                # Standard training
                images = images.to(self.device)
                labels = labels.to(self.device)
                
                outputs = self.model(images)
                loss = F.cross_entropy(outputs, labels)
                
                self.optimizer.zero_grad()
                loss.backward()
                self.optimizer.step()
                
                accuracy = (outputs.argmax(dim=1) == labels).float().mean().item()
                
                metrics = {
                    'loss': loss.item(),
                    'clean_accuracy': accuracy,
                    'robust_accuracy': accuracy
                }
            else:
                # Adversarial training based on defense method
                if defense_method == DefenseMethod.ADVERSARIAL_TRAINING:
                    metrics = self.adversarial_training_step(images, labels)
                elif defense_method == DefenseMethod.DISTILLATION:
                    # Need teacher model for distillation
                    # For simplicity, using self as teacher
                    metrics = self.distillation_training_step(
                        images, labels, self.model
                    )
                else:
                    # Default to adversarial training
                    metrics = self.adversarial_training_step(images, labels)
            
            # Accumulate metrics
            epoch_loss += metrics['loss']
            epoch_clean_accuracy += metrics.get('clean_accuracy', 0)
            epoch_robust_accuracy += metrics.get('robust_accuracy', 0)
            num_batches += 1
            
            # Log batch progress
            if batch_idx % 100 == 0:
                self.logger.info(f"Batch {batch_idx} | "
                               f"Loss: {metrics['loss']:.4f} | "
                               f"Clean Acc: {metrics.get('clean_accuracy', 0):.2%} | "
                               f"Robust Acc: {metrics.get('robust_accuracy', 0):.2%}")
        
        # Compute epoch averages
        avg_loss = epoch_loss / num_batches
        avg_clean_accuracy = epoch_clean_accuracy / num_batches
        avg_robust_accuracy = epoch_robust_accuracy / num_batches
        
        # Update metrics
        self.metrics['train_loss'].append(avg_loss)
        self.metrics['train_accuracy'].append(avg_clean_accuracy)
        self.metrics['train_robust_accuracy'].append(avg_robust_accuracy)
        
        return avg_loss, avg_clean_accuracy, avg_robust_accuracy
    
    def evaluate(self, val_loader, attacker: AdversarialAttacker = None):
        """
        Evaluate model on validation set
        
        Args:
            val_loader: Validation data loader
            attacker: Adversarial attacker for evaluation
            
        Returns:
            Evaluation metrics
        """
        self.model.eval()
        
        if attacker is None:
            attacker = self.attacker
        
        total_loss = 0
        total_clean_accuracy = 0
        total_robust_accuracy = 0
        num_samples = 0
        
        with torch.no_grad():
            for images, labels in val_loader:
                images = images.to(self.device)
                labels = labels.to(self.device)
                
                # Clean accuracy
                clean_outputs = self.model(images)
                clean_loss = F.cross_entropy(clean_outputs, labels)
                clean_accuracy = (clean_outputs.argmax(dim=1) == labels).float().mean().item()
                
                # Robust accuracy (under attack)
                adversarial_images = attacker.generate_attack(images, labels)
                adversarial_outputs = self.model(adversarial_images)
                robust_accuracy = (adversarial_outputs.argmax(dim=1) == labels).float().mean().item()
                
                # Accumulate
                batch_size = images.shape[0]
                total_loss += clean_loss.item() * batch_size
                total_clean_accuracy += clean_accuracy * batch_size
                total_robust_accuracy += robust_accuracy * batch_size
                num_samples += batch_size
        
        # Compute averages
        avg_loss = total_loss / num_samples
        avg_clean_accuracy = total_clean_accuracy / num_samples
        avg_robust_accuracy = total_robust_accuracy / num_samples
        
        # Update metrics
        self.metrics['val_loss'].append(avg_loss)
        self.metrics['val_accuracy'].append(avg_clean_accuracy)
        self.metrics['val_robust_accuracy'].append(avg_robust_accuracy)
        
        return {
            'loss': avg_loss,
            'clean_accuracy': avg_clean_accuracy,
            'robust_accuracy': avg_robust_accuracy
        }
    
    def evaluate_robustness(self, test_loader, attacks: List[AttackMethod] = None,
                          epsilons: List[float] = None):
        """
        Evaluate model robustness against multiple attacks
        
        Args:
            test_loader: Test data loader
            attacks: List of attack methods to evaluate
            epsilons: List of epsilon values to evaluate
            
        Returns:
            Robustness evaluation results
        """
        if attacks is None:
            attacks = self.config.eval_attacks
        
        if epsilons is None:
            epsilons = self.config.eval_epsilons
        
        results = {}
        
        for attack_method in attacks:
            results[attack_method.value] = {}
            
            for epsilon in epsilons:
                # Create attacker with current epsilon
                attack_config = AdversarialTrainingConfig(
                    attack_method=attack_method,
                    epsilon=epsilon,
                    step_size=epsilon / 4,
                    num_steps=40
                )
                
                attacker = AdversarialAttacker(self.model, attack_config)
                
                # Evaluate under this attack
                eval_metrics = self.evaluate(test_loader, attacker)
                
                results[attack_method.value][epsilon] = {
                    'clean_accuracy': eval_metrics['clean_accuracy'],
                    'robust_accuracy': eval_metrics['robust_accuracy'],
                    'accuracy_drop': eval_metrics['clean_accuracy'] - eval_metrics['robust_accuracy']
                }
                
                self.logger.info(f"Attack: {attack_method.value} | "
                               f"Epsilon: {epsilon} | "
                               f"Clean Acc: {eval_metrics['clean_accuracy']:.2%} | "
                               f"Robust Acc: {eval_metrics['robust_accuracy']:.2%}")
        
        return results
    
    def compute_certified_robustness(self, test_loader, num_samples: int = None):
        """
        Compute certified robustness using randomized smoothing
        
        Args:
            test_loader: Test data loader
            num_samples: Number of noise samples
            
        Returns:
            Certified robustness metrics
        """
        if self.smoothing is None:
            self.logger.warning("Randomized smoothing not enabled")
            return None
        
        if num_samples is None:
            num_samples = self.config.smoothing_samples
        
        self.model.eval()
        
        certified_correct = 0
        total_certified = 0
        radii = []
        
        with torch.no_grad():
            for images, labels in test_loader:
                images = images.to(self.device)
                labels = labels.to(self.device)
                
                for i in range(images.shape[0]):
                    image = images[i:i+1]
                    label = labels[i:i+1]
                    
                    # Get smoothed prediction and certified radius
                    pred, radius = self.smoothing.predict(
                        image, num_samples, alpha=0.001
                    )
                    
                    # Check if prediction is correct
                    if pred.item() == label.item():
                        certified_correct += 1
                        radii.append(radius.item())
                    
                    total_certified += 1
        
        # Compute metrics
        certified_accuracy = certified_correct / total_certified if total_certified > 0 else 0
        avg_radius = np.mean(radii) if radii else 0
        
        # Update metrics
        self.metrics['certified_radii'].extend(radii)
        
        return {
            'certified_accuracy': certified_accuracy,
            'avg_certified_radius': avg_radius,
            'total_certified': total_certified
        }
    
    def train(self, train_loader, val_loader, num_epochs: int = None):
        """
        Main training loop
        
        Args:
            train_loader: Training data loader
            val_loader: Validation data loader
            num_epochs: Number of epochs to train
            
        Returns:
            Training metrics
        """
        if num_epochs is None:
            num_epochs = self.config.num_epochs
        
        self.logger.info(f"Starting adversarial training for {num_epochs} epochs")
        
        for epoch in range(num_epochs):
            self.epoch = epoch + 1
            epoch_start_time = time.time()
            
            # Training phase
            train_loss, train_clean_acc, train_robust_acc = self.train_epoch(train_loader)
            
            # Validation phase
            val_metrics = self.evaluate(val_loader)
            
            # Log epoch summary
            epoch_time = time.time() - epoch_start_time
            
            self.logger.info("\n" + "="*80)
            self.logger.info(f"Epoch {self.epoch:3d} Summary:")
            self.logger.info(f"  Time: {epoch_time:.2f}s")
            self.logger.info(f"  Train Loss: {train_loss:.4f}")
            self.logger.info(f"  Train Clean Acc: {train_clean_acc:.2%}")
            self.logger.info(f"  Train Robust Acc: {train_robust_acc:.2%}")
            self.logger.info(f"  Val Clean Acc: {val_metrics['clean_accuracy']:.2%}")
            self.logger.info(f"  Val Robust Acc: {val_metrics['robust_accuracy']:.2%}")
            self.logger.info("="*80 + "\n")
            
            # Save checkpoint
            if self.epoch % self.config.save_frequency == 0:
                self.save_checkpoint(f"epoch_{self.epoch}")
            
            # Save best model
            if val_metrics['robust_accuracy'] > self.best_robust_accuracy:
                self.best_robust_accuracy = val_metrics['robust_accuracy']
                self.save_checkpoint("best_robust")
                self.logger.info(f"New best robust accuracy: {self.best_robust_accuracy:.2%}")
            
            # Compute certified robustness periodically
            if self.smoothing and self.epoch % 20 == 0:
                certified_metrics = self.compute_certified_robustness(val_loader)
                if certified_metrics:
                    self.logger.info(f"Certified Accuracy: {certified_metrics['certified_accuracy']:.2%}")
                    self.logger.info(f"Avg Certified Radius: {certified_metrics['avg_certified_radius']:.4f}")
        
        self.logger.info("Adversarial training completed!")
        
        # Final evaluation
        self.logger.info("Performing final robustness evaluation...")
        robustness_results = self.evaluate_robustness(val_loader)
        
        # Save final model
        self.save_checkpoint("final")
        
        return self.metrics
    
    def save_checkpoint(self, name: str):
        """
        Save training checkpoint
        
        Args:
            name: Checkpoint name
        """
        checkpoint_dir = Path(self.config.checkpoint_dir)
        checkpoint_dir.mkdir(parents=True, exist_ok=True)
        
        checkpoint = {
            'epoch': self.epoch,
            'model_state_dict': self.model.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'best_robust_accuracy': self.best_robust_accuracy,
            'metrics': self.metrics,
            'config': self.config.__dict__,
        }
        
        checkpoint_path = checkpoint_dir / f"{name}.pt"
        torch.save(checkpoint, checkpoint_path)
        
        self.logger.info(f"Checkpoint saved: {checkpoint_path}")
    
    def load_checkpoint(self, checkpoint_path: str):
        """
        Load training checkpoint
        
        Args:
            checkpoint_path: Path to checkpoint file
        """
        checkpoint = torch.load(checkpoint_path, map_location=self.device)
        
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
        
        self.epoch = checkpoint['epoch']
        self.best_robust_accuracy = checkpoint['best_robust_accuracy']
        self.metrics = checkpoint['metrics']
        
        self.logger.info(f"Checkpoint loaded from {checkpoint_path}")
        self.logger.info(f"Resuming from epoch {self.epoch}")
    
    def export_robust_model(self, export_path: str, format: str = "onnx"):
        """
        Export robust model for deployment
        
        Args:
            export_path: Path to save exported model
            format: Export format
        """
        self.model.eval()
        
        if format == "onnx":
            # For ONNX export, we need to handle randomized smoothing differently
            if self.smoothing:
                # Export the base model
                dummy_input = torch.randn(1, 3, 32, 32, device=self.device)
                
                torch.onnx.export(
                    self.model,
                    dummy_input,
                    export_path,
                    export_params=True,
                    opset_version=14,
                    do_constant_folding=True,
                    input_names=['input'],
                    output_names=['output'],
                    dynamic_axes={
                        'input': {0: 'batch_size'},
                        'output': {0: 'batch_size'}
                    }
                )
                
                # Note: Randomized smoothing must be applied separately in deployment
                self.logger.info("Exported base model. Apply randomized smoothing in deployment.")
            else:
                # Standard ONNX export
                dummy_input = torch.randn(1, 3, 32, 32, device=self.device)
                
                torch.onnx.export(
                    self.model,
                    dummy_input,
                    export_path,
                    export_params=True,
                    opset_version=14,
                    do_constant_folding=True,
                    input_names=['input'],
                    output_names=['output'],
                    dynamic_axes={
                        'input': {0: 'batch_size'},
                        'output': {0: 'batch_size'}
                    }
                )
        
        elif format == "torchscript":
            # Export to TorchScript
            dummy_input = torch.randn(1, 3, 32, 32, device=self.device)
            traced_model = torch.jit.trace(self.model, dummy_input)
            traced_model.save(export_path)
        
        else:
            raise ValueError(f"Unknown export format: {format}")
        
        self.logger.info(f"Robust model exported to {export_path}")


def create_adversarial_dataset(clean_dataset, attacker: AdversarialAttacker, 
                             num_samples: int = 1000):
    """
    Create dataset of adversarial examples
    
    Args:
        clean_dataset: Clean dataset
        attacker: Adversarial attacker
        num_samples: Number of adversarial examples to generate
        
    Returns:
        Adversarial dataset
    """
    adversarial_images = []
    adversarial_labels = []
    clean_labels = []
    
    # Generate adversarial examples
    for i in range(min(num_samples, len(clean_dataset))):
        image, label = clean_dataset[i]
        
        # Convert to batch format
        image_batch = image.unsqueeze(0)
        label_batch = torch.tensor([label])
        
        # Generate adversarial example
        adversarial_image = attacker.generate_attack(image_batch, label_batch)
        
        adversarial_images.append(adversarial_image.squeeze(0))
        adversarial_labels.append(label)  # True labels
        clean_labels.append(label)  # For comparison
    
    # Create dataset
    from torch.utils.data import TensorDataset
    
    adversarial_images = torch.stack(adversarial_images)
    adversarial_labels = torch.tensor(adversarial_labels)
    clean_labels = torch.tensor(clean_labels)
    
    return TensorDataset(adversarial_images, adversarial_labels, clean_labels)


def analyze_adversarial_examples(model: nn.Module, adversarial_dataset, 
                               num_examples: int = 10):
    """
    Analyze adversarial examples
    
    Args:
        model: Model to analyze
        adversarial_dataset: Dataset of adversarial examples
        num_examples: Number of examples to analyze
        
    Returns:
        Analysis results
    """
    model.eval()
    
    results = []
    
    for i in range(min(num_examples, len(adversarial_dataset))):
        adversarial_image, true_label, _ = adversarial_dataset[i]
        
        # Add batch dimension
        adversarial_image = adversarial_image.unsqueeze(0)
        
        # Get model predictions
        with torch.no_grad():
            output = model(adversarial_image)
            prediction = output.argmax(dim=1).item()
            confidence = torch.softmax(output, dim=1).max().item()
        
        # Check if adversarial example succeeded
        is_adversarial = prediction != true_label
        
        results.append({
            'index': i,
            'true_label': true_label,
            'predicted_label': prediction,
            'confidence': confidence,
            'is_adversarial': is_adversarial,
            'adversarial_success': is_adversarial
        })
    
    # Compute statistics
    total_examples = len(results)
    adversarial_success = sum(r['adversarial_success'] for r in results)
    success_rate = adversarial_success / total_examples if total_examples > 0 else 0
    
    analysis = {
        'total_examples': total_examples,
        'adversarial_success': adversarial_success,
        'success_rate': success_rate,
        'examples': results[:10]  # First 10 examples
    }
    
    return analysis