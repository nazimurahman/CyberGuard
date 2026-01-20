"""
CyberGuard Agents Package
=======================

This package contains all specialized security agents for the CyberGuard system.
Each agent is designed to detect specific types of threats and vulnerabilities,
and they coordinate through the mHC (Manifold-Constrained Hyper-Connections) framework.

Agent Architecture:
------------------
1. Base Agent: Abstract base class with common functionality
2. Specialized Agents: 10 agents each focusing on different security domains
3. Orchestrator: Coordinates agents using mHC principles

Key Principles:
--------------
- Each agent has a specific domain expertise
- Agents communicate through residual connections
- mHC prevents reasoning collapse and signal explosion
- Confidence-based weighting for decisions
- Memory-bounded processing for stability
"""

# Import all agent classes for easy access
from .base_agent import SecurityAgent
from .threat_detection_agent import WebThreatDetectionAgent
from .traffic_anomaly_agent import TrafficAnomalyAgent
from .bot_detection_agent import BotDetectionAgent
from .malware_agent import MalwarePayloadAgent
from .exploit_chain_agent import ExploitChainReasoningAgent
from .forensics_agent import DigitalForensicsAgent
from .incident_response_agent import IncidentResponseAgent
from .compliance_agent import CompliancePrivacyAgent
from .code_review_agent import SecureCodeReviewAgent
from .threat_education_agent import ThreatEducationAgent
from .agent_orchestrator import AgentOrchestrator

# Define what gets imported with "from agents import *"
__all__ = [
    'SecurityAgent',
    'WebThreatDetectionAgent',
    'TrafficAnomalyAgent',
    'BotDetectionAgent',
    'MalwarePayloadAgent',
    'ExploitChainReasoningAgent',
    'DigitalForensicsAgent',
    'IncidentResponseAgent',
    'CompliancePrivacyAgent',
    'SecureCodeReviewAgent',
    'ThreatEducationAgent',
    'AgentOrchestrator'
]

# Package metadata
__version__ = '1.0.0'
__author__ = 'CyberGuard Security Team'
__description__ = 'Multi-agent cybersecurity threat detection and analysis system'