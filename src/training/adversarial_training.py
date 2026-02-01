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
from typing import Dict, List, Tuple, Optional, Any, Callable, Union
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
    eval_attacks: Optional[List[AttackMethod]] = None  # Attacks to evaluate against
    eval_epsilons: Optional[List[float]] = None  # Perturbation sizes to evaluate
    
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
        # Ensure images require gradients for attack generation
        images = images.clone().detach().requires_grad_(True)
        
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
        
        # Clip to valid range [0, 1] for image data
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
        # Initialize adversarial examples with random noise within epsilon bound
        adversarial_images = images.clone().detach()
        noise = torch.empty_like(adversarial_images).uniform_(
            -self.config.epsilon, self.config.epsilon
        )
        adversarial_images = adversarial_images + noise
        adversarial_images = torch.clamp(adversarial_images, 0, 1)
        
        # PGD iterations for iterative optimization
        for i in range(self.config.num_steps):
            adversarial_images.requires_grad_(True)
            
            # Forward pass
            outputs = self.model(adversarial_images)
            loss = F.cross_entropy(outputs, labels)
            
            # Compute gradients
            self.model.zero_grad()
            loss.backward()
            
            # Get gradient of loss with respect to input
            gradient = adversarial_images.grad.data
            
            # Update adversarial images in direction of gradient sign
            adversarial_images = adversarial_images.detach() + self.config.step_size * gradient.sign()
            
            # Project back to epsilon ball around original images
            delta = torch.clamp(adversarial_images - images, 
                              -self.config.epsilon, self.config.epsilon)
            adversarial_images = images + delta
            
            # Clip to valid pixel range [0, 1]
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
        
        # Initialize optimization variable w in tanh space for box constraints
        w = torch.zeros_like(images, requires_grad=True)
        
        # Optimizer for CW attack
        optimizer = optim.Adam([w], lr=self.config.cw_learning_rate)
        
        # Target labels (least likely class to increase attack difficulty)
        with torch.no_grad():
            outputs = self.model(images)
            target_labels = torch.argmin(outputs, dim=1)
        
        # CW optimization loop
        for iteration in range(self.config.cw_iterations):
            # Map w from (-inf, inf) to [0, 1] using tanh
            adversarial_images = 0.5 * (torch.tanh(w) + 1)
            
            # Forward pass through model
            outputs = self.model(adversarial_images)
            
            # CW loss components
            # 1. Distance loss (L2 norm between original and adversarial)
            l2_distance = torch.norm(adversarial_images - images, p=2, dim=(1, 2, 3))
            
            # 2. Classification loss to encourage misclassification
            correct_logits = outputs[range(batch_size), labels]
            target_logits = outputs[range(batch_size), target_labels]
            
            # CW loss function: balance distance and misclassification
            loss = l2_distance.sum() + torch.clamp(correct_logits - target_logits + self.config.cw_confidence, min=0).sum()
            
            # Optimization step
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
        
        # Final adversarial images after optimization
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
        adversarial_images.requires_grad_(True)
        
        # Forward pass to get initial outputs
        outputs = self.model(adversarial_images)
        
        # Get number of classes from output dimension
        num_classes = outputs.shape[1]
        
        # Compute gradient for each class (needed for DeepFool)
        grads = []
        for c in range(num_classes):
            # Zero gradients before computing for each class
            if adversarial_images.grad is not None:
                adversarial_images.grad.zero_()
            
            # Compute gradient for class c
            loss = outputs[:, c].sum()
            loss.backward(retain_graph=True)
            
            grads.append(adversarial_images.grad.clone())
        
        # Reset adversarial_images for per-sample processing
        adversarial_images = images.clone().detach()
        
        # Compute DeepFool perturbation for each sample individually
        for i in range(batch_size):
            image = images[i].unsqueeze(0)  # Keep batch dimension
            label = labels[i].unsqueeze(0)
            
            # Initialize perturbation
            perturbation = torch.zeros_like(image)
            
            # DeepFool iterations for minimal perturbation
            for iteration in range(50):  # Max 50 iterations per sample
                adversarial_image = image + perturbation
                adversarial_image.requires_grad_(True)
                
                # Forward pass
                output = self.model(adversarial_image)
                
                # Get top-2 classes (current prediction and runner-up)
                sorted_indices = torch.argsort(output[0], descending=True)
                
                # Check if already misclassified
                if sorted_indices[0] != label.item():
                    break  # Attack successful
                
                # Compute perturbation direction using linear approximation
                w = grads[sorted_indices[1]][i] - grads[label.item()][i]
                f = output[0, sorted_indices[1]] - output[0, label.item()]
                
                # Compute minimal perturbation
                perturbation_i = (torch.abs(f) / (torch.norm(w.flatten()) + 1e-8)) * w
                perturbation = perturbation + perturbation_i.unsqueeze(0)
                
                # Early stopping if perturbation becomes too large
                if torch.norm(perturbation) > 10 * self.config.epsilon:
                    break
            
            # Apply perturbation with epsilon constraint for consistency
            perturbation = torch.clamp(perturbation, -self.config.epsilon, self.config.epsilon)
            adversarial_images[i] = image + perturbation
        
        return adversarial_images.detach()
    
    def jsma_attack(self, images: torch.Tensor, labels: torch.Tensor) -> torch.Tensor:
        """
        Jacobian-based Saliency Map Attack (JSMA)
        
        Args:
            images: Clean images
            labels: True labels
            
        Returns:
            Adversarial images
        """
        # Note: JSMA attack implementation would be complex and omitted for brevity
        # It typically involves computing saliency maps and iterative pixel modification
        raise NotImplementedError("JSMA attack not fully implemented in this version")
    
    def autoattack_attack(self, images: torch.Tensor, labels: torch.Tensor) -> torch.Tensor:
        """
        AutoAttack - ensemble of attacks
        
        Args:
            images: Clean images
            labels: True labels
            
        Returns:
            Adversarial images
        """
        # Note: AutoAttack combines multiple attacks
        # For simplicity, using PGD as baseline
        return self.pgd_attack(images, labels)
    
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
        
        # Use smaller step size for BIM (typical: epsilon/10)
        self.config.step_size = self.config.epsilon / 10
        self.config.num_steps = min(100, original_num_steps * 2)
        
        # Generate adversarial examples using PGD with BIM parameters
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
        decay_factor = 1.0  # Momentum decay factor
        num_iterations = self.config.num_steps
        
        # Iterative attack with momentum
        for i in range(num_iterations):
            adversarial_images.requires_grad_(True)
            
            # Forward pass
            outputs = self.model(adversarial_images)
            loss = F.cross_entropy(outputs, labels)
            
            # Compute gradients
            self.model.zero_grad()
            loss.backward()
            
            # Accumulate momentum (normalized gradient)
            gradient = adversarial_images.grad.data
            momentum = decay_factor * momentum + gradient / (torch.norm(gradient.view(gradient.shape[0], -1), p=1, dim=1).view(-1, 1, 1, 1) + 1e-8)
            
            # Update adversarial images in direction of momentum
            adversarial_images = adversarial_images.detach() + self.config.step_size * momentum.sign()
            
            # Project back to epsilon ball
            delta = torch.clamp(adversarial_images - images, 
                              -self.config.epsilon, self.config.epsilon)
            adversarial_images = images + delta
            
            # Clip to valid range [0, 1]
            adversarial_images = torch.clamp(adversarial_images, 0, 1)
        
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
        # Route to appropriate attack method based on configuration
        if self.config.attack_method == AttackMethod.FGSM:
            return self.fgsm_attack(images, labels)
        elif self.config.attack_method == AttackMethod.PGD:
            return self.pgd_attack(images, labels)
        elif self.config.attack_method == AttackMethod.CW:
            return self.cw_attack(images, labels)
        elif self.config.attack_method == AttackMethod.DEEPFOOL:
            return self.deepfool_attack(images, labels)
        elif self.config.attack_method == AttackMethod.JSMA:
            return self.jsma_attack(images, labels)
        elif self.config.attack_method == AttackMethod.BIM:
            return self.bim_attack(images, labels)
        elif self.config.attack_method == AttackMethod.MIM:
            return self.mim_attack(images, labels)
        elif self.config.attack_method == AttackMethod.AUTOATTACK:
            return self.autoattack_attack(images, labels)
        else:
            raise ValueError(f"Unknown attack method: {self.config.attack_method}")


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
            sigma: Noise standard deviation for Gaussian smoothing
        """
        self.base_model = base_model
        self.sigma = sigma
    
    def predict(self, images: torch.Tensor, num_samples: int = 1000, 
                alpha: float = 0.001) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Make prediction with randomized smoothing
        
        Args:
            images: Input images
            num_samples: Number of noise samples for Monte Carlo estimation
            alpha: Confidence level for certification
            
        Returns:
            Tuple of (predictions, robustness radii)
        """
        batch_size = images.shape[0]
        
        # Sample Gaussian noise for randomization
        noise = torch.randn(num_samples, *images.shape, device=images.device) * self.sigma
        
        # Repeat images for each noise sample
        images_repeated = images.repeat(num_samples, 1, 1, 1)
        
        # Add noise to create noisy versions
        noisy_images = images_repeated + noise
        
        # Get predictions for all noisy samples
        with torch.no_grad():
            outputs = self.base_model(noisy_images)
            predictions = torch.argmax(outputs, dim=1)
        
        # Reshape predictions to [num_samples, batch_size]
        predictions = predictions.view(num_samples, batch_size)
        
        # Count votes for each class across all samples
        votes = torch.zeros(batch_size, outputs.shape[1], device=images.device)
        for b in range(batch_size):
            for s in range(num_samples):
                votes[b, predictions[s, b]] += 1
        
        # Get top-2 classes (most and second most frequent)
        top_values, top_indices = torch.topk(votes, 2, dim=1)
        
        # Final predictions (most voted class)
        pred_labels = top_indices[:, 0]
        
        # Compute robustness radius using binomial confidence interval
        p_a = top_values[:, 0] / num_samples  # Proportion for top class
        p_b = top_values[:, 1] / num_samples  # Proportion for second class
        
        # Lower confidence bound for p_a
        p_a_lower = self._binomial_lower_bound(p_a, num_samples, alpha)
        
        # Upper confidence bound for p_b
        p_b_upper = self._binomial_upper_bound(p_b, num_samples, alpha)
        
        # Certified radius formula for randomized smoothing
        radii = (self.sigma / 2) * (p_a_lower - p_b_upper)
        radii = torch.clamp(radii, min=0)  # Ensure non-negative radii
        
        return pred_labels, radii
    
    def _binomial_lower_bound(self, p: torch.Tensor, n: int, alpha: float) -> torch.Tensor:
        """Compute lower confidence bound for binomial proportion using Clopper-Pearson interval"""
        try:
            import scipy.stats as stats
        except ImportError:
            raise ImportError("scipy is required for certified robustness computations")
        
        lower_bounds = []
        for p_val in p.cpu().numpy():
            k = int(p_val * n)  # Number of successes
            if k == 0:
                lower = 0.0  # No successes, lower bound is 0
            else:
                # Clopper-Pearson exact lower bound
                lower = stats.beta.ppf(alpha / 2, k, n - k + 1)
            lower_bounds.append(lower)
        
        return torch.tensor(lower_bounds, device=p.device)
    
    def _binomial_upper_bound(self, p: torch.Tensor, n: int, alpha: float) -> torch.Tensor:
        """Compute upper confidence bound for binomial proportion using Clopper-Pearson interval"""
        try:
            import scipy.stats as stats
        except ImportError:
            raise ImportError("scipy is required for certified robustness computations")
        
        upper_bounds = []
        for p_val in p.cpu().numpy():
            k = int(p_val * n)  # Number of successes
            if k == n:
                upper = 1.0  # All successes, upper bound is 1
            else:
                # Clopper-Pearson exact upper bound
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
        
        # Setup device (GPU if available, otherwise CPU)
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)
        
        # Setup optimizer for model training
        self.optimizer = optim.Adam(
            self.model.parameters(),
            lr=config.learning_rate,
            weight_decay=1e-4  # L2 regularization
        )
        
        # Setup adversarial attacker for generating attacks during training
        self.attacker = AdversarialAttacker(self.model, config)
        
        # Setup randomized smoothing if certified robustness is enabled
        if config.certified_smoothing:
            self.smoothing = RandomizedSmoothing(
                self.model,
                sigma=config.smoothing_noise
            )
        else:
            self.smoothing = None
        
        # Training state tracking
        self.epoch = 0
        self.best_robust_accuracy = 0.0
        
        # Metrics tracking for training history
        self.metrics = {
            'train_loss': [],
            'train_accuracy': [],
            'train_robust_accuracy': [],
            'val_loss': [],
            'val_accuracy': [],
            'val_robust_accuracy': [],
            'certified_radii': []
        }
        
        # Setup logging for training progress
        self.logger = self._setup_logger()
        
        # Log initialization information
        self.logger.info("Adversarial Trainer initialized")
        self.logger.info(f"Attack method: {config.attack_method}")
        self.logger.info(f"Defense method: {config.defense_method}")
        self.logger.info(f"Epsilon: {config.epsilon}")
        self.logger.info(f"Device: {self.device}")
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logging configuration for training progress tracking"""
        logger = logging.getLogger("AdversarialTrainer")
        logger.setLevel(logging.INFO)
        
        # Prevent duplicate handlers if logger already exists
        if logger.handlers:
            return logger
        
        # Create logs directory if it doesn't exist
        log_dir = Path("logs/adversarial")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # File handler for logging to file
        file_handler = logging.FileHandler(
            log_dir / f"adversarial_training_{time.strftime('%Y%m%d_%H%M%S')}.log"
        )
        file_handler.setLevel(logging.INFO)
        
        # Console handler for logging to terminal
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
    
    def adversarial_training_step(self, images: torch.Tensor, 
                                labels: torch.Tensor) -> Dict[str, float]:
        """
        Adversarial training step - train on both clean and adversarial examples
        
        Args:
            images: Clean images
            labels: True labels
            
        Returns:
            Training metrics dictionary
        """
        self.model.train()
        
        # Move data to appropriate device (GPU/CPU)
        images = images.to(self.device)
        labels = labels.to(self.device)
        
        # Generate adversarial examples using configured attack method
        adversarial_images = self.attacker.generate_attack(images, labels)
        
        # Forward pass on both clean and adversarial images
        clean_outputs = self.model(images)
        adversarial_outputs = self.model(adversarial_images)
        
        # Compute losses for clean and adversarial examples
        clean_loss = F.cross_entropy(clean_outputs, labels)
        adversarial_loss = F.cross_entropy(adversarial_outputs, labels)
        
        # Combined loss weighted by adversarial_weight parameter
        loss = (1 - self.config.adversarial_weight) * clean_loss + \
               self.config.adversarial_weight * adversarial_loss
        
        # Optimization step: zero gradients, backward pass, update weights
        self.optimizer.zero_grad()
        loss.backward()
        self.optimizer.step()
        
        # Compute accuracies for monitoring
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
        Defensive distillation training step - train student model using teacher's soft labels
        
        Args:
            images: Clean images
            labels: True labels
            teacher_model: Teacher model for distillation
            temperature: Distillation temperature for softening probabilities
            
        Returns:
            Training metrics dictionary
        """
        self.model.train()
        teacher_model.eval()
        
        # Move data to device
        images = images.to(self.device)
        labels = labels.to(self.device)
        
        # Get teacher predictions (without training teacher)
        with torch.no_grad():
            teacher_logits = teacher_model(images)
            # Soften probabilities using temperature scaling
            teacher_probs = F.softmax(teacher_logits / temperature, dim=-1)
        
        # Generate adversarial examples for training
        adversarial_images = self.attacker.generate_attack(images, labels)
        
        # Student forward pass on adversarial examples
        student_logits = self.model(adversarial_images)
        student_probs = F.softmax(student_logits / temperature, dim=-1)
        
        # Distillation loss: KL divergence between teacher and student distributions
        distillation_loss = F.kl_div(
            student_probs.log(),  # Student log probabilities
            teacher_probs,        # Teacher probabilities (target)
            reduction='batchmean' # Average over batch
        )
        
        # Standard cross-entropy loss for true labels
        ce_loss = F.cross_entropy(student_logits, labels)
        
        # Combined loss balancing distillation and classification
        loss = 0.5 * distillation_loss + 0.5 * ce_loss
        
        # Optimization step
        self.optimizer.zero_grad()
        loss.backward()
        self.optimizer.step()
        
        # Compute accuracy on adversarial examples
        accuracy = (student_logits.argmax(dim=1) == labels).float().mean().item()
        
        return {
            'loss': loss.item(),
            'accuracy': accuracy,
            'distillation_loss': distillation_loss.item(),
            'ce_loss': ce_loss.item()
        }
    
    def train_epoch(self, train_loader, defense_method: DefenseMethod = None) -> Tuple[float, float, float]:
        """
        Train for one complete epoch
        
        Args:
            train_loader: Training data loader
            defense_method: Defense method to use (overrides config if provided)
            
        Returns:
            Tuple of (average loss, clean accuracy, robust accuracy)
        """
        if defense_method is None:
            defense_method = self.config.defense_method
        
        # Initialize metrics accumulation
        epoch_loss = 0.0
        epoch_clean_accuracy = 0.0
        epoch_robust_accuracy = 0.0
        num_batches = 0
        
        # Iterate through training batches
        for batch_idx, (images, labels) in enumerate(train_loader):
            # Warmup phase: standard training without adversarial examples
            if self.epoch < self.config.warmup_epochs:
                # Move data to device
                images = images.to(self.device)
                labels = labels.to(self.device)
                
                # Standard forward pass
                outputs = self.model(images)
                loss = F.cross_entropy(outputs, labels)
                
                # Optimization step
                self.optimizer.zero_grad()
                loss.backward()
                self.optimizer.step()
                
                # Compute accuracy
                accuracy = (outputs.argmax(dim=1) == labels).float().mean().item()
                
                # Create metrics dictionary (same format for consistency)
                metrics = {
                    'loss': loss.item(),
                    'clean_accuracy': accuracy,
                    'robust_accuracy': accuracy  # Same as clean during warmup
                }
            else:
                # Adversarial training phase based on selected defense method
                if defense_method == DefenseMethod.ADVERSARIAL_TRAINING:
                    metrics = self.adversarial_training_step(images, labels)
                elif defense_method == DefenseMethod.DISTILLATION:
                    # For distillation, use current model as teacher (self-distillation)
                    metrics = self.distillation_training_step(
                        images, labels, self.model
                    )
                else:
                    # Default to adversarial training for other defense methods
                    metrics = self.adversarial_training_step(images, labels)
            
            # Accumulate metrics across batches
            epoch_loss += metrics['loss']
            epoch_clean_accuracy += metrics.get('clean_accuracy', 0)
            epoch_robust_accuracy += metrics.get('robust_accuracy', 0)
            num_batches += 1
            
            # Log batch progress periodically
            if batch_idx % 100 == 0:
                self.logger.info(f"Batch {batch_idx} | "
                               f"Loss: {metrics['loss']:.4f} | "
                               f"Clean Acc: {metrics.get('clean_accuracy', 0):.2%} | "
                               f"Robust Acc: {metrics.get('robust_accuracy', 0):.2%}")
        
        # Compute epoch averages by dividing by number of batches
        avg_loss = epoch_loss / num_batches if num_batches > 0 else 0.0
        avg_clean_accuracy = epoch_clean_accuracy / num_batches if num_batches > 0 else 0.0
        avg_robust_accuracy = epoch_robust_accuracy / num_batches if num_batches > 0 else 0.0
        
        # Update metrics history
        self.metrics['train_loss'].append(avg_loss)
        self.metrics['train_accuracy'].append(avg_clean_accuracy)
        self.metrics['train_robust_accuracy'].append(avg_robust_accuracy)
        
        return avg_loss, avg_clean_accuracy, avg_robust_accuracy
    
    def evaluate(self, val_loader, attacker: Optional[AdversarialAttacker] = None) -> Dict[str, float]:
        """
        Evaluate model on validation set with and without attacks
        
        Args:
            val_loader: Validation data loader
            attacker: Adversarial attacker for evaluation (uses default if None)
            
        Returns:
            Evaluation metrics dictionary
        """
        self.model.eval()  # Set model to evaluation mode
        
        # Use default attacker if none provided
        if attacker is None:
            attacker = self.attacker
        
        # Initialize metrics accumulation
        total_loss = 0.0
        total_clean_accuracy = 0.0
        total_robust_accuracy = 0.0
        num_samples = 0
        
        # Disable gradient computation for evaluation
        with torch.no_grad():
            for images, labels in val_loader:
                # Move data to device
                images = images.to(self.device)
                labels = labels.to(self.device)
                
                # Clean accuracy evaluation (no attack)
                clean_outputs = self.model(images)
                clean_loss = F.cross_entropy(clean_outputs, labels)
                clean_accuracy = (clean_outputs.argmax(dim=1) == labels).float().mean().item()
                
                # Robust accuracy evaluation (under attack)
                adversarial_images = attacker.generate_attack(images, labels)
                adversarial_outputs = self.model(adversarial_images)
                robust_accuracy = (adversarial_outputs.argmax(dim=1) == labels).float().mean().item()
                
                # Accumulate metrics weighted by batch size
                batch_size = images.shape[0]
                total_loss += clean_loss.item() * batch_size
                total_clean_accuracy += clean_accuracy * batch_size
                total_robust_accuracy += robust_accuracy * batch_size
                num_samples += batch_size
        
        # Compute average metrics
        avg_loss = total_loss / num_samples if num_samples > 0 else 0.0
        avg_clean_accuracy = total_clean_accuracy / num_samples if num_samples > 0 else 0.0
        avg_robust_accuracy = total_robust_accuracy / num_samples if num_samples > 0 else 0.0
        
        # Update validation metrics history
        self.metrics['val_loss'].append(avg_loss)
        self.metrics['val_accuracy'].append(avg_clean_accuracy)
        self.metrics['val_robust_accuracy'].append(avg_robust_accuracy)
        
        return {
            'loss': avg_loss,
            'clean_accuracy': avg_clean_accuracy,
            'robust_accuracy': avg_robust_accuracy
        }
    
    def evaluate_robustness(self, test_loader, attacks: Optional[List[AttackMethod]] = None,
                          epsilons: Optional[List[float]] = None) -> Dict[str, Any]:
        """
        Evaluate model robustness against multiple attacks with different perturbation sizes
        
        Args:
            test_loader: Test data loader
            attacks: List of attack methods to evaluate (uses config defaults if None)
            epsilons: List of epsilon values to evaluate (uses config defaults if None)
            
        Returns:
            Nested dictionary with robustness evaluation results
        """
        # Use default attacks and epsilons if not provided
        if attacks is None:
            attacks = self.config.eval_attacks
        
        if epsilons is None:
            epsilons = self.config.eval_epsilons
        
        # Initialize results dictionary
        results = {}
        
        # Evaluate against each attack method
        for attack_method in attacks:
            results[attack_method.value] = {}
            
            # Evaluate with each epsilon value
            for epsilon in epsilons:
                # Create attacker configuration for current epsilon
                attack_config = AdversarialTrainingConfig(
                    attack_method=attack_method,
                    epsilon=epsilon,
                    step_size=epsilon / 4,  # Standard step size: epsilon/4
                    num_steps=40  # Fixed number of attack iterations
                )
                
                # Create attacker with current configuration
                attacker = AdversarialAttacker(self.model, attack_config)
                
                # Evaluate model under this specific attack
                eval_metrics = self.evaluate(test_loader, attacker)
                
                # Store results for this attack and epsilon
                results[attack_method.value][epsilon] = {
                    'clean_accuracy': eval_metrics['clean_accuracy'],
                    'robust_accuracy': eval_metrics['robust_accuracy'],
                    'accuracy_drop': eval_metrics['clean_accuracy'] - eval_metrics['robust_accuracy']
                }
                
                # Log evaluation results
                self.logger.info(f"Attack: {attack_method.value} | "
                               f"Epsilon: {epsilon} | "
                               f"Clean Acc: {eval_metrics['clean_accuracy']:.2%} | "
                               f"Robust Acc: {eval_metrics['robust_accuracy']:.2%}")
        
        return results
    
    def compute_certified_robustness(self, test_loader, num_samples: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Compute certified robustness using randomized smoothing
        
        Args:
            test_loader: Test data loader
            num_samples: Number of noise samples for certification
            
        Returns:
            Certified robustness metrics or None if smoothing not enabled
        """
        # Check if randomized smoothing is enabled
        if self.smoothing is None:
            self.logger.warning("Randomized smoothing not enabled, skipping certified robustness computation")
            return None
        
        # Use default number of samples if not specified
        if num_samples is None:
            num_samples = self.config.smoothing_samples
        
        self.model.eval()
        
        # Initialize certification metrics
        certified_correct = 0
        total_certified = 0
        radii = []
        
        # Disable gradients for certification
        with torch.no_grad():
            for images, labels in test_loader:
                images = images.to(self.device)
                labels = labels.to(self.device)
                
                # Process each sample individually for certification
                for i in range(images.shape[0]):
                    image = images[i:i+1]  # Keep batch dimension
                    label = labels[i:i+1]
                    
                    # Get smoothed prediction and certified radius
                    pred, radius = self.smoothing.predict(
                        image, num_samples, alpha=0.001  # 99.9% confidence
                    )
                    
                    # Check if prediction is correct
                    if pred.item() == label.item():
                        certified_correct += 1
                        radii.append(radius.item())
                    
                    total_certified += 1
        
        # Compute certification metrics
        certified_accuracy = certified_correct / total_certified if total_certified > 0 else 0.0
        avg_radius = np.mean(radii) if radii else 0.0
        
        # Update metrics history
        self.metrics['certified_radii'].extend(radii)
        
        return {
            'certified_accuracy': certified_accuracy,
            'avg_certified_radius': avg_radius,
            'total_certified': total_certified
        }
    
    def train(self, train_loader, val_loader, num_epochs: Optional[int] = None) -> Dict[str, List[float]]:
        """
        Main training loop for adversarial training
        
        Args:
            train_loader: Training data loader
            val_loader: Validation data loader
            num_epochs: Number of epochs to train (uses config if None)
            
        Returns:
            Training metrics history
        """
        # Use configured number of epochs if not specified
        if num_epochs is None:
            num_epochs = self.config.num_epochs
        
        self.logger.info(f"Starting adversarial training for {num_epochs} epochs")
        
        # Main training loop
        for epoch in range(num_epochs):
            self.epoch = epoch + 1
            epoch_start_time = time.time()
            
            # Training phase for one epoch
            train_loss, train_clean_acc, train_robust_acc = self.train_epoch(train_loader)
            
            # Validation phase after training
            val_metrics = self.evaluate(val_loader)
            
            # Compute epoch duration
            epoch_time = time.time() - epoch_start_time
            
            # Log comprehensive epoch summary
            self.logger.info("\n" + "="*80)
            self.logger.info(f"Epoch {self.epoch:3d} Summary:")
            self.logger.info(f"  Time: {epoch_time:.2f}s")
            self.logger.info(f"  Train Loss: {train_loss:.4f}")
            self.logger.info(f"  Train Clean Acc: {train_clean_acc:.2%}")
            self.logger.info(f"  Train Robust Acc: {train_robust_acc:.2%}")
            self.logger.info(f"  Val Clean Acc: {val_metrics['clean_accuracy']:.2%}")
            self.logger.info(f"  Val Robust Acc: {val_metrics['robust_accuracy']:.2%}")
            self.logger.info("="*80 + "\n")
            
            # Save checkpoint periodically
            if self.epoch % self.config.save_frequency == 0:
                self.save_checkpoint(f"epoch_{self.epoch}")
            
            # Save best model based on robust accuracy
            if val_metrics['robust_accuracy'] > self.best_robust_accuracy:
                self.best_robust_accuracy = val_metrics['robust_accuracy']
                self.save_checkpoint("best_robust")
                self.logger.info(f"New best robust accuracy: {self.best_robust_accuracy:.2%}")
            
            # Compute certified robustness periodically (if enabled)
            if self.smoothing and self.epoch % 20 == 0:
                certified_metrics = self.compute_certified_robustness(val_loader)
                if certified_metrics:
                    self.logger.info(f"Certified Accuracy: {certified_metrics['certified_accuracy']:.2%}")
                    self.logger.info(f"Avg Certified Radius: {certified_metrics['avg_certified_radius']:.4f}")
        
        self.logger.info("Adversarial training completed!")
        
        # Final robustness evaluation with all configured attacks
        self.logger.info("Performing final robustness evaluation...")
        robustness_results = self.evaluate_robustness(val_loader)
        
        # Save final model checkpoint
        self.save_checkpoint("final")
        
        return self.metrics
    
    def save_checkpoint(self, name: str):
        """
        Save training checkpoint including model, optimizer, and metrics
        
        Args:
            name: Checkpoint name for file naming
        """
        # Create checkpoint directory if it doesn't exist
        checkpoint_dir = Path(self.config.checkpoint_dir)
        checkpoint_dir.mkdir(parents=True, exist_ok=True)
        
        # Prepare checkpoint dictionary
        checkpoint = {
            'epoch': self.epoch,
            'model_state_dict': self.model.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'best_robust_accuracy': self.best_robust_accuracy,
            'metrics': self.metrics,
            'config': self.config.__dict__,
        }
        
        # Save checkpoint to file
        checkpoint_path = checkpoint_dir / f"{name}.pt"
        torch.save(checkpoint, checkpoint_path)
        
        self.logger.info(f"Checkpoint saved: {checkpoint_path}")
    
    def load_checkpoint(self, checkpoint_path: str):
        """
        Load training checkpoint to resume training
        
        Args:
            checkpoint_path: Path to checkpoint file
        """
        # Load checkpoint from file
        checkpoint = torch.load(checkpoint_path, map_location=self.device)
        
        # Restore model and optimizer states
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
        
        # Restore training state
        self.epoch = checkpoint['epoch']
        self.best_robust_accuracy = checkpoint['best_robust_accuracy']
        self.metrics = checkpoint['metrics']
        
        # Log checkpoint loading
        self.logger.info(f"Checkpoint loaded from {checkpoint_path}")
        self.logger.info(f"Resuming from epoch {self.epoch}")
    
    def export_robust_model(self, export_path: str, format: str = "onnx"):
        """
        Export robust model for deployment
        
        Args:
            export_path: Path to save exported model
            format: Export format ("onnx" or "torchscript")
            
        Raises:
            ValueError: If unknown export format is specified
        """
        self.model.eval()
        
        if format == "onnx":
            # ONNX export for interoperability
            if self.smoothing:
                # Export the base model (randomized smoothing applied separately)
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
                
                # Note for deployment: Randomized smoothing must be applied separately
                self.logger.info("Exported base model. Apply randomized smoothing in deployment.")
            else:
                # Standard ONNX export for non-smoothed models
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
            # TorchScript export for PyTorch deployment
            dummy_input = torch.randn(1, 3, 32, 32, device=self.device)
            traced_model = torch.jit.trace(self.model, dummy_input)
            traced_model.save(export_path)
        
        else:
            raise ValueError(f"Unknown export format: {format}")
        
        self.logger.info(f"Robust model exported to {export_path}")


def create_adversarial_dataset(clean_dataset, attacker: AdversarialAttacker, 
                             num_samples: int = 1000):
    """
    Create dataset of adversarial examples from clean dataset
    
    Args:
        clean_dataset: Clean dataset (images, labels)
        attacker: Adversarial attacker for generating examples
        num_samples: Number of adversarial examples to generate
        
    Returns:
        TensorDataset containing adversarial images, true labels, and clean labels
    """
    adversarial_images = []
    adversarial_labels = []
    clean_labels = []
    
    # Limit samples to dataset size or requested number
    actual_samples = min(num_samples, len(clean_dataset))
    
    # Generate adversarial examples
    for i in range(actual_samples):
        image, label = clean_dataset[i]
        
        # Convert to batch format (add batch dimension)
        image_batch = image.unsqueeze(0)
        label_batch = torch.tensor([label])
        
        # Generate adversarial example using attacker
        adversarial_image = attacker.generate_attack(image_batch, label_batch)
        
        # Store results (remove batch dimension)
        adversarial_images.append(adversarial_image.squeeze(0))
        adversarial_labels.append(label)  # True labels for evaluation
        clean_labels.append(label)  # Clean labels for comparison
    
    # Create TensorDataset from collected data
    from torch.utils.data import TensorDataset
    
    adversarial_images = torch.stack(adversarial_images)
    adversarial_labels = torch.tensor(adversarial_labels)
    clean_labels = torch.tensor(clean_labels)
    
    # Return dataset with adversarial images, true labels, and clean labels
    return TensorDataset(adversarial_images, adversarial_labels, clean_labels)


def analyze_adversarial_examples(model: nn.Module, adversarial_dataset, 
                               num_examples: int = 10) -> Dict[str, Any]:
    """
    Analyze adversarial examples to understand attack effectiveness
    
    Args:
        model: Model to analyze
        adversarial_dataset: Dataset of adversarial examples
        num_examples: Number of examples to analyze in detail
        
    Returns:
        Analysis results including statistics and example details
    """
    model.eval()
    
    results = []
    
    # Analyze specified number of examples
    actual_examples = min(num_examples, len(adversarial_dataset))
    
    for i in range(actual_examples):
        adversarial_image, true_label, _ = adversarial_dataset[i]
        
        # Add batch dimension for model input
        adversarial_image = adversarial_image.unsqueeze(0)
        
        # Get model predictions
        with torch.no_grad():
            output = model(adversarial_image)
            prediction = output.argmax(dim=1).item()
            confidence = torch.softmax(output, dim=1).max().item()
        
        # Check if adversarial example succeeded (caused misclassification)
        is_adversarial = prediction != true_label
        
        # Store analysis for this example
        results.append({
            'index': i,
            'true_label': true_label,
            'predicted_label': prediction,
            'confidence': confidence,
            'is_adversarial': is_adversarial,
            'adversarial_success': is_adversarial
        })
    
    # Compute overall statistics
    total_examples = len(results)
    adversarial_success = sum(r['adversarial_success'] for r in results)
    success_rate = adversarial_success / total_examples if total_examples > 0 else 0.0
    
    # Compile analysis summary
    analysis = {
        'total_examples': total_examples,
        'adversarial_success': adversarial_success,
        'success_rate': success_rate,
        'examples': results[:10]  # Include first 10 examples for detailed inspection
    }
    
    return analysis