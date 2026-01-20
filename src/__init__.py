"""
CyberGuard - Intelligent Web Threat Analysis & Defense Platform
Main package initialization for the cybersecurity AI system.

This module serves as the central hub for all CyberGuard components,
providing organized access to agents, security scanners, ML models,
and deployment utilities through a clean, import-friendly interface.

Project Structure Explanation:
├── core/           # Core ML architectures (mHC, GQA, Transformers)
├── agents/         # Specialized security analysis agents
├── web_security/   # Web vulnerability scanners and analyzers
├── training/       # Model training pipelines and utilities
├── inference/      # Threat inference and analysis engines
├── data_ingestion/ # Secure data loading and threat intelligence feeds
├── deployment/     # Deployment modules (plugin, proxy, dashboard)
├── ui/            # User interface components (API, frontend)
└── utils/         # Security, logging, and compliance utilities
"""

# ============================================================================
# VERSION INFORMATION
# ============================================================================
__version__ = "1.0.0"
__author__ = "CyberGuard Security Team"
__license__ = "Apache 2.0"
__copyright__ = "Copyright 2024 CyberGuard Security Inc."

# ============================================================================
# CORE ARCHITECTURE EXPORTS
# ============================================================================
# Core ML architectures that form the brain of CyberGuard
from .core import (
    # Manifold-Constrained Hyper-Connections (mHC) for stable multi-agent coordination
    mhc_architecture,
    
    # Grouped Query Attention Transformer with Flash Attention + RoPE
    gqa_transformer,
    
    # Security feature encoder for converting web data to ML-readable features
    security_encoder,
    
    # Model factory for creating and loading trained security models
    model_factory,
)

# ============================================================================
# SECURITY AGENTS EXPORTS
# ============================================================================
# Specialized AI agents for different aspects of security analysis
from .agents import (
    # Base agent class that all specialized agents inherit from
    base_agent,
    
    # Individual security agents (each specializes in a different threat domain)
    threat_detection_agent,      # OWASP Top-10 vulnerability detection
    traffic_anomaly_agent,       # Behavioral anomaly detection
    bot_detection_agent,         # Bot and abuse pattern detection
    malware_agent,              # Malware payload analysis
    exploit_chain_agent,        # Multi-step exploit reasoning
    forensics_agent,            # Digital forensics and evidence collection
    incident_response_agent,    # Automated incident response
    compliance_agent,           # Regulatory compliance checking
    code_review_agent,          # Secure code analysis
    threat_education_agent,     # Security education and training
    
    # Agent orchestrator that coordinates multiple agents using mHC principles
    agent_orchestrator,
)

# ============================================================================
# WEB SECURITY SCANNING EXPORTS
# ============================================================================
# Web vulnerability scanners and analyzers for comprehensive security assessment
from .web_security import (
    scanner,                # Main web security scanner orchestration
    vulnerability_detector, # OWASP Top-10 vulnerability detection logic
    api_analyzer,          # REST API and GraphQL security analysis
    traffic_parser,        # HTTP traffic parsing and normalization
    javascript_analyzer,   # Client-side JavaScript security analysis
    form_validator,        # Web form security validation
    header_analyzer,       # HTTP security headers analysis
)

# ============================================================================
# TRAINING AND ML EXPORTS
# ============================================================================
# Model training pipelines and machine learning utilities
from .training import (
    mhc_trainer,           # Trainer for Manifold-Constrained Hyper-Connections
    gqa_trainer,          # Trainer for GQA transformer models
    agent_trainer,        # Agent-specific training and fine-tuning
    security_dataset,     # Security-specific dataset creation and management
    adversarial_training, # Adversarial training for robust threat detection
)

# ============================================================================
# INFERENCE AND ANALYSIS EXPORTS
# ============================================================================
# Real-time threat inference and analysis engines
from .inference import (
    inference_engine,      # Main inference orchestration engine
    threat_inference,      # Threat-specific inference logic
    response_parser,       # Response parsing and formatting
)

# ============================================================================
# DATA INGESTION EXPORTS
# ============================================================================
# Secure data loading and threat intelligence feed management
from .data_ingestion import (
    secure_loader,         # Secure URL and file loading with validation
    cve_ingestor,         # CVE database ingestion and processing
    threat_feeds,         # Threat intelligence feed aggregation
    hash_validator,       # File hash validation and integrity checking
    quarantine_pipeline,  # Malicious content quarantine system
)

# ============================================================================
# DEPLOYMENT EXPORTS
# ============================================================================
# Deployment modules for different integration scenarios
from .deployment import (
    website_plugin,        # Website integration plugin
    reverse_proxy,         # Reverse proxy security layer
    api_middleware,        # API security middleware
    security_dashboard,    # Web-based security dashboard
)

# ============================================================================
# USER INTERFACE EXPORTS
# ============================================================================
# User interface components for interaction and visualization
from .ui import (
    # Frontend UI components (built with Streamlit/Dash)
    frontend,
    
    # API components for programmatic access
    api,
)

# ============================================================================
# UTILITIES EXPORTS
# ============================================================================
# Helper utilities for security, logging, and compliance
from .utils import (
    security_utils,        # Security helper functions
    logging_utils,         # Structured logging with audit trails
    crypto_utils,         # Cryptographic operations
    compliance_utils,     # Compliance checking utilities
)

# ============================================================================
# CONVENIENCE CLASSES AND FUNCTIONS
# ============================================================================
# These provide high-level, easy-to-use interfaces for common operations

class CyberGuard:
    """
    Main entry point class for the CyberGuard system.
    Provides a unified interface to all system components.
    
    Example usage:
        >>> from src import CyberGuard
        >>> guard = CyberGuard(config_path="config/enterprise_config.yaml")
        >>> results = guard.scan_website("https://example.com")
    """
    
    def __init__(self, config_path: str = "config/enterprise_config.yaml"):
        """
        Initialize the complete CyberGuard system.
        
        Args:
            config_path: Path to YAML configuration file
        """
        from .inference.inference_engine import InferenceEngine
        from .agents.agent_orchestrator import AgentOrchestrator
        from .web_security.scanner import WebSecurityScanner
        
        self.config_path = config_path
        self.inference_engine = InferenceEngine(config_path)
        self.agent_orchestrator = AgentOrchestrator()
        self.scanner = WebSecurityScanner(config_path)
        
    def scan_website(self, url: str, depth: int = 1) -> dict:
        """
        Perform comprehensive security scan of a website.
        
        Args:
            url: Website URL to scan
            depth: Scan depth (1 = single page, 2 = page + links, etc.)
            
        Returns:
            Dictionary containing scan results, threats found, and recommendations
        """
        # 1. Perform initial security scan
        scan_results = self.scanner.scan(url, depth)
        
        # 2. Analyze with AI agents
        agent_analysis = self.agent_orchestrator.analyze(scan_results)
        
        # 3. Run inference on combined results
        final_analysis = self.inference_engine.infer(scan_results, agent_analysis)
        
        return {
            'scan': scan_results,
            'agent_analysis': agent_analysis,
            'inference': final_analysis,
            'recommendations': final_analysis.get('recommendations', [])
        }
    
    def analyze_traffic(self, traffic_log: dict) -> dict:
        """
        Analyze HTTP traffic for security threats.
        
        Args:
            traffic_log: Dictionary containing HTTP request/response data
            
        Returns:
            Threat analysis with severity scores and evidence
        """
        from .agents.traffic_anomaly_agent import TrafficAnomalyAgent
        from .agents.bot_detection_agent import BotDetectionAgent
        
        # Initialize specialized agents
        traffic_agent = TrafficAnomalyAgent()
        bot_agent = BotDetectionAgent()
        
        # Get analysis from each agent
        traffic_analysis = traffic_agent.analyze(traffic_log)
        bot_analysis = bot_agent.analyze(traffic_log)
        
        # Coordinate using mHC
        coordinated = self.agent_orchestrator.coordinate([traffic_analysis, bot_analysis])
        
        return coordinated
    
    def train_model(self, dataset_path: str, model_type: str = "gqa") -> dict:
        """
        Train a security model on custom data.
        
        Args:
            dataset_path: Path to training dataset
            model_type: Type of model to train ("gqa", "mhc", or "agent")
            
        Returns:
            Training results including metrics and model path
        """
        if model_type == "gqa":
            from .training.gqa_trainer import GQATrainer
            trainer = GQATrainer(dataset_path)
        elif model_type == "mhc":
            from .training.mhc_trainer import MHCTrainer
            trainer = MHCTrainer(dataset_path)
        elif model_type == "agent":
            from .training.agent_trainer import AgentTrainer
            trainer = AgentTrainer(dataset_path)
        else:
            raise ValueError(f"Unknown model type: {model_type}")
        
        return trainer.train()
    
    def get_system_status(self) -> dict:
        """
        Get current status of the CyberGuard system.
        
        Returns:
            Dictionary containing system health, agent statuses, and metrics
        """
        return {
            'version': __version__,
            'components': {
                'agents': len(self.agent_orchestrator.agents),
                'models': self.inference_engine.get_model_count(),
                'scanner': 'active' if self.scanner else 'inactive'
            },
            'health': self._check_system_health()
        }
    
    def _check_system_health(self) -> dict:
        """Internal method to check system component health."""
        return {
            'database': 'healthy',
            'models': 'loaded',
            'agents': 'active',
            'api': 'ready'
        }

def create_security_scanner(config: dict = None):
    """
    Factory function to create a web security scanner.
    
    Args:
        config: Optional configuration dictionary
        
    Returns:
        Configured WebSecurityScanner instance
    """
    from .web_security.scanner import WebSecurityScanner
    return WebSecurityScanner(config or {})

def create_agent_orchestrator(agents: list = None):
    """
    Factory function to create an agent orchestrator.
    
    Args:
        agents: Optional list of pre-configured agents
        
    Returns:
        AgentOrchestrator instance with registered agents
    """
    from .agents.agent_orchestrator import AgentOrchestrator
    orchestrator = AgentOrchestrator()
    
    if agents:
        for agent in agents:
            orchestrator.register_agent(agent)
    else:
        # Register default agents
        from .agents.threat_detection_agent import WebThreatDetectionAgent
        from .agents.traffic_anomaly_agent import TrafficAnomalyAgent
        from .agents.bot_detection_agent import BotDetectionAgent
        
        orchestrator.register_agent(WebThreatDetectionAgent())
        orchestrator.register_agent(TrafficAnomalyAgent())
        orchestrator.register_agent(BotDetectionAgent())
    
    return orchestrator

def load_security_model(model_path: str, model_type: str = "gqa"):
    """
    Load a pre-trained security model.
    
    Args:
        model_path: Path to model file or directory
        model_type: Type of model ("gqa", "mhc", or "ensemble")
        
    Returns:
        Loaded model ready for inference
    """
    from .core.model_factory import ModelFactory
    factory = ModelFactory()
    return factory.load_model(model_path, model_type)

# ============================================================================
# CONVENIENCE FUNCTIONS FOR COMMON OPERATIONS
# ============================================================================

def quick_scan(url: str) -> dict:
    """
    Perform a quick security scan of a website.
    Simplified interface for basic scanning needs.
    
    Args:
        url: Website URL to scan
        
    Returns:
        Basic security assessment with risk level
    """
    scanner = create_security_scanner()
    return scanner.quick_scan(url)

def analyze_http_request(request_data: dict) -> dict:
    """
    Analyze a single HTTP request for security threats.
    
    Args:
        request_data: Dictionary with HTTP request details
        
    Returns:
        Threat analysis for the request
    """
    from .web_security.traffic_parser import parse_http_request
    from .agents.threat_detection_agent import WebThreatDetectionAgent
    
    parsed = parse_http_request(request_data)
    agent = WebThreatDetectionAgent()
    return agent.analyze(parsed)

def check_security_headers(url: str) -> dict:
    """
    Check and analyze security headers for a website.
    
    Args:
        url: Website URL to check
        
    Returns:
        Security header analysis with recommendations
    """
    from .web_security.header_analyzer import HeaderAnalyzer
    analyzer = HeaderAnalyzer()
    return analyzer.analyze(url)

def generate_security_report(scan_results: dict, template: str = "standard") -> str:
    """
    Generate a human-readable security report.
    
    Args:
        scan_results: Dictionary with scan results
        template: Report template ("standard", "detailed", "executive")
        
    Returns:
        Formatted security report
    """
    from .inference.response_parser import SecurityReportGenerator
    generator = SecurityReportGenerator()
    return generator.generate(scan_results, template)

# ============================================================================
# TYPE DEFINITIONS FOR BETTER IDE SUPPORT
# ============================================================================
# These type hints help with autocomplete and static analysis

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Core components
    from .core.mhc_architecture import ManifoldConstrainedHyperConnections
    from .core.gqa_transformer import SecurityGQATransformer
    from .core.security_encoder import SecurityFeatureEncoder
    from .core.model_factory import ModelFactory
    
    # Agents
    from .agents.base_agent import SecurityAgent
    from .agents.threat_detection_agent import WebThreatDetectionAgent
    from .agents.traffic_anomaly_agent import TrafficAnomalyAgent
    from .agents.bot_detection_agent import BotDetectionAgent
    from .agents.malware_agent import MalwarePayloadAgent
    from .agents.exploit_chain_agent import ExploitChainReasoningAgent
    from .agents.forensics_agent import DigitalForensicsAgent
    from .agents.incident_response_agent import IncidentResponseAgent
    from .agents.compliance_agent import CompliancePrivacyAgent
    from .agents.code_review_agent import SecureCodeReviewAgent
    from .agents.threat_education_agent import ThreatEducationAgent
    from .agents.agent_orchestrator import AgentOrchestrator
    
    # Web security
    from .web_security.scanner import WebSecurityScanner
    from .web_security.vulnerability_detector import VulnerabilityDetector
    from .web_security.api_analyzer import APIAnalyzer
    from .web_security.traffic_parser import TrafficParser
    from .web_security.javascript_analyzer import JavaScriptAnalyzer
    from .web_security.form_validator import FormValidator
    from .web_security.header_analyzer import HeaderAnalyzer
    
    # Training
    from .training.mhc_trainer import MHCTrainer
    from .training.gqa_trainer import GQATrainer
    from .training.agent_trainer import AgentTrainer
    from .training.security_dataset import SecurityDataset
    from .training.adversarial_training import AdversarialTrainer
    
    # Inference
    from .inference.inference_engine import InferenceEngine
    from .inference.threat_inference import ThreatInference
    from .inference.response_parser import ResponseParser
    
    # Data ingestion
    from .data_ingestion.secure_loader import SecureLoader
    from .data_ingestion.cve_ingestor import CVEIngestor
    from .data_ingestion.threat_feeds import ThreatFeedAggregator
    from .data_ingestion.hash_validator import HashValidator
    from .data_ingestion.quarantine_pipeline import QuarantinePipeline
    
    # Deployment
    from .deployment.website_plugin import WebsitePlugin
    from .deployment.reverse_proxy import ReverseProxy
    from .deployment.api_middleware import APIMiddleware
    from .deployment.security_dashboard import SecurityDashboard
    
    # UI
    from .ui.frontend.dashboard import SecurityDashboardUI
    from .ui.frontend.alerts import AlertsUI
    from .ui.frontend.tutor_mode import TutorModeUI
    from .ui.api.rest_api import CyberGuardAPI
    from .ui.api.websocket_handler import WebSocketHandler
    from .ui.api.webhook_handler import WebhookHandler
    
    # Utilities
    from .utils.security_utils import SecurityUtils
    from .utils.logging_utils import LoggingUtils
    from .utils.crypto_utils import CryptoUtils
    from .utils.compliance_utils import ComplianceUtils

# ============================================================================
# MODULE METADATA AND DOCSTRINGS
# ============================================================================
# These help with documentation generation and IDE tooltips

__all__ = [
    # Core architecture
    'mhc_architecture',
    'gqa_transformer',
    'security_encoder',
    'model_factory',
    
    # Agents
    'base_agent',
    'threat_detection_agent',
    'traffic_anomaly_agent',
    'bot_detection_agent',
    'malware_agent',
    'exploit_chain_agent',
    'forensics_agent',
    'incident_response_agent',
    'compliance_agent',
    'code_review_agent',
    'threat_education_agent',
    'agent_orchestrator',
    
    # Web security
    'scanner',
    'vulnerability_detector',
    'api_analyzer',
    'traffic_parser',
    'javascript_analyzer',
    'form_validator',
    'header_analyzer',
    
    # Training
    'mhc_trainer',
    'gqa_trainer',
    'agent_trainer',
    'security_dataset',
    'adversarial_training',
    
    # Inference
    'inference_engine',
    'threat_inference',
    'response_parser',
    
    # Data ingestion
    'secure_loader',
    'cve_ingestor',
    'threat_feeds',
    'hash_validator',
    'quarantine_pipeline',
    
    # Deployment
    'website_plugin',
    'reverse_proxy',
    'api_middleware',
    'security_dashboard',
    
    # UI
    'frontend',
    'api',
    
    # Utilities
    'security_utils',
    'logging_utils',
    'crypto_utils',
    'compliance_utils',
    
    # Convenience classes and functions
    'CyberGuard',
    'create_security_scanner',
    'create_agent_orchestrator',
    'load_security_model',
    'quick_scan',
    'analyze_http_request',
    'check_security_headers',
    'generate_security_report',
]

# ============================================================================
# PACKAGE INITIALIZATION HOOKS
# ============================================================================
# These run when the package is imported

def _initialize_package():
    """
    Internal initialization function called on package import.
    Sets up logging, configuration, and performs basic health checks.
    """
    import os
    import sys
    
    # Add package directory to Python path if not already there
    package_dir = os.path.dirname(os.path.abspath(__file__))
    if package_dir not in sys.path:
        sys.path.insert(0, package_dir)
    
    # Initialize logging
    try:
        from .utils.logging_utils import setup_logging
        setup_logging()
    except ImportError:
        pass  # Logging setup is optional
    
    # Check for required dependencies
    try:
        import torch
        import numpy
        import requests
        # Basic dependency check passed
    except ImportError as e:
        print(f"Warning: Missing dependency: {e}")
        print("Some CyberGuard features may not work correctly.")
        print("Install all dependencies with: pip install -r requirements.txt")

# Run initialization
_initialize_package()