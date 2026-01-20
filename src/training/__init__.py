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

from .security_dataset import SecurityDataset, ThreatIntelligenceDataset, WebTrafficDataset
from .mhc_trainer import MHCTrainer, ManifoldConstrainedOptimizer
from .gqa_trainer import GQATrainer, FlashAttentionOptimizer
from .agent_trainer import MultiAgentTrainer, AgentCurriculum
from .adversarial_training import AdversarialTrainer, AttackSimulator

__all__ = [
    # Dataset classes
    'SecurityDataset',
    'ThreatIntelligenceDataset', 
    'WebTrafficDataset',
    
    # mHC Training
    'MHCTrainer',
    'ManifoldConstrainedOptimizer',
    
    # GQA Training
    'GQATrainer', 
    'FlashAttentionOptimizer',
    
    # Agent Training
    'MultiAgentTrainer',
    'AgentCurriculum',
    
    # Adversarial Training
    'AdversarialTrainer',
    'AttackSimulator',
]

__version__ = '1.0.0'
__author__ = 'CyberGuard Security Team'