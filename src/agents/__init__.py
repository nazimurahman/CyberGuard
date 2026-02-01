"""
CyberGuard Agents Package
This package contains all specialized security agents for the CyberGuard system.
Each agent is designed to detect specific types of threats and vulnerabilities,
and they coordinate through the mHC (Manifold-Constrained Hyper-Connections) framework.

Agent Architecture:
1. Base Agent: Abstract base class with common functionality
2. Specialized Agents: 10 agents each focusing on different security domains
3. Orchestrator: Coordinates agents using mHC principles

Key Principles:
- Each agent has a specific domain expertise
- Agents communicate through residual connections
- mHC prevents reasoning collapse and signal explosion
- Confidence-based weighting for decisions
- Memory-bounded processing for stability
"""

# Import all agent classes for easy access
# Note: These imports assume the corresponding Python files exist in the same directory
from .base_agent import SecurityAgent  # Import base abstract agent class
from .threat_detection_agent import WebThreatDetectionAgent  # Import web threat detection agent
from .traffic_anomaly_agent import TrafficAnomalyAgent  # Import network traffic anomaly detection agent
from .bot_detection_agent import BotDetectionAgent  # Import bot and automated threat detection agent
from .malware_agent import MalwarePayloadAgent  # Import malware analysis agent
from .exploit_chain_agent import ExploitChainReasoningAgent  # Import exploit chain analysis agent
from .forensics_agent import DigitalForensicsAgent  # Import digital forensics investigation agent
from .incident_response_agent import IncidentResponseAgent  # Import incident response coordination agent
from .compliance_agent import CompliancePrivacyAgent  # Import compliance and privacy checking agent
from .code_review_agent import SecureCodeReviewAgent  # Import secure code review agent
from .threat_education_agent import ThreatEducationAgent  # Import threat intelligence and education agent
from .agent_orchestrator import AgentOrchestrator  # Import main orchestrator that coordinates all agents

# Define what gets imported with "from agents import *"
# This controls the public API of the package
__all__ = [
    'SecurityAgent',  # Base agent class
    'WebThreatDetectionAgent',  # Web threat detection specialization
    'TrafficAnomalyAgent',  # Network traffic analysis specialization
    'BotDetectionAgent',  # Bot detection specialization
    'MalwarePayloadAgent',  # Malware analysis specialization
    'ExploitChainReasoningAgent',  # Exploit chain analysis specialization
    'DigitalForensicsAgent',  # Digital forensics specialization
    'IncidentResponseAgent',  # Incident response specialization
    'CompliancePrivacyAgent',  # Compliance checking specialization
    'SecureCodeReviewAgent',  # Code security review specialization
    'ThreatEducationAgent',  # Threat education specialization
    'AgentOrchestrator'  # Main coordinator
]

# Package metadata
__version__ = '1.0.0'  # Current version of the package
__author__ = 'CyberGuard Security Team'  # Package author/development team
__description__ = 'Multi-agent cybersecurity threat detection and analysis system'  # Package description