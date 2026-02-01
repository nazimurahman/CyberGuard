"""
CyberGuard Training Package
==========================

Advanced training modules for cybersecurity AI agents, incorporating:
1. Manifold-Constrained Hyper-Connections (mHC) training
2. Grouped Query Attention (GQA) transformer training
3. Multi-agent reinforcement learning
4. Adversarial training for robustness
5. Security-specific dataset handling

Key Features:
- mHC-based stable multi-agent coordination
- GQA with Flash Attention + RoPE optimization
- Federated learning for privacy-preserving training
- Adversarial robustness against evasion attacks
- Real-time threat intelligence integration
"""

# Import all necessary module classes and functions
# Security dataset handling classes
from .security_dataset import SecurityDataset, ThreatIntelligenceDataset, WebTrafficDataset

# Manifold-Constrained Hyper-Connections training components
from .mhc_trainer import MHCTrainer, ManifoldConstrainedOptimizer

# Grouped Query Attention training components  
from .gqa_trainer import GQATrainer, FlashAttentionOptimizer

# Multi-agent reinforcement learning components
from .agent_trainer import MultiAgentTrainer, AgentCurriculum

# Adversarial training components for robustness
from .adversarial_training import AdversarialTrainer, AttackSimulator

# Define the public API - all classes and functions that should be accessible 
# when users import the package using "from cyberguard_training import *"
__all__ = [
    # Dataset classes for security-specific data handling
    'SecurityDataset',           # Base security dataset class
    'ThreatIntelligenceDataset', # Dataset for threat intelligence feeds
    'WebTrafficDataset',         # Dataset for web traffic analysis
    
    # mHC (Manifold-Constrained Hyper-Connections) Training components
    'MHCTrainer',                 # Main trainer for mHC architecture
    'ManifoldConstrainedOptimizer', # Optimizer with manifold constraints
    
    # GQA (Grouped Query Attention) Training components
    'GQATrainer',                # Trainer for GQA transformer models
    'FlashAttentionOptimizer',   # Optimizer with Flash Attention implementation
    
    # Multi-Agent Reinforcement Learning components
    'MultiAgentTrainer',         # Coordinator for multiple AI agents
    'AgentCurriculum',           # Curriculum learning scheduler for agents
    
    # Adversarial Training components
    'AdversarialTrainer',        # Trainer for adversarial robustness
    'AttackSimulator',           # Simulator for generating attack scenarios
]

# Package version following semantic versioning (MAJOR.MINOR.PATCH)
__version__ = '1.0.0'

# Author/development team information
__author__ = 'CyberGuard Security Team'