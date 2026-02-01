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
# Note: Using try-except blocks to handle missing modules gracefully
try:
    # Import core ML architectures that form the brain of CyberGuard
    from .core import (
        mhc_architecture,    # Manifold-Constrained Hyper-Connections for stable multi-agent coordination
        gqa_transformer,     # Grouped Query Attention Transformer with Flash Attention + RoPE
        security_encoder,    # Security feature encoder for converting web data to ML-readable features
        model_factory,       # Model factory for creating and loading trained security models
    )
except ImportError as e:
    # Log warning if core modules are not available
    print(f"Warning: Could not import core modules: {e}")
    # Initialize as None to prevent runtime errors
    mhc_architecture = None
    gqa_transformer = None
    security_encoder = None
    model_factory = None

# ============================================================================
# SECURITY AGENTS EXPORTS
# ============================================================================
try:
    # Import specialized AI agents for different aspects of security analysis
    from .agents import (
        base_agent,                 # Base agent class that all specialized agents inherit from
        threat_detection_agent,     # OWASP Top-10 vulnerability detection
        traffic_anomaly_agent,      # Behavioral anomaly detection
        bot_detection_agent,        # Bot and abuse pattern detection
        malware_agent,              # Malware payload analysis
        exploit_chain_agent,        # Multi-step exploit reasoning
        forensics_agent,            # Digital forensics and evidence collection
        incident_response_agent,    # Automated incident response
        compliance_agent,           # Regulatory compliance checking
        code_review_agent,          # Secure code analysis
        threat_education_agent,     # Security education and training
        agent_orchestrator,         # Agent orchestrator that coordinates multiple agents using mHC principles
    )
except ImportError as e:
    print(f"Warning: Could not import agent modules: {e}")
    # Set all agent modules to None to maintain consistent interface
    base_agent = None
    threat_detection_agent = None
    traffic_anomaly_agent = None
    bot_detection_agent = None
    malware_agent = None
    exploit_chain_agent = None
    forensics_agent = None
    incident_response_agent = None
    compliance_agent = None
    code_review_agent = None
    threat_education_agent = None
    agent_orchestrator = None

# ============================================================================
# WEB SECURITY SCANNING EXPORTS
# ============================================================================
try:
    # Import web vulnerability scanners and analyzers for comprehensive security assessment
    from .web_security import (
        scanner,                # Main web security scanner orchestration
        vulnerability_detector, # OWASP Top-10 vulnerability detection logic
        api_analyzer,          # REST API and GraphQL security analysis
        traffic_parser,        # HTTP traffic parsing and normalization
        javascript_analyzer,   # Client-side JavaScript security analysis
        form_validator,        # Web form security validation
        header_analyzer,       # HTTP security headers analysis
    )
except ImportError as e:
    print(f"Warning: Could not import web security modules: {e}")
    scanner = None
    vulnerability_detector = None
    api_analyzer = None
    traffic_parser = None
    javascript_analyzer = None
    form_validator = None
    header_analyzer = None

# ============================================================================
# TRAINING AND ML EXPORTS
# ============================================================================
try:
    # Import model training pipelines and machine learning utilities
    from .training import (
        mhc_trainer,           # Trainer for Manifold-Constrained Hyper-Connections
        gqa_trainer,          # Trainer for GQA transformer models
        agent_trainer,        # Agent-specific training and fine-tuning
        security_dataset,     # Security-specific dataset creation and management
        adversarial_training, # Adversarial training for robust threat detection
    )
except ImportError as e:
    print(f"Warning: Could not import training modules: {e}")
    mhc_trainer = None
    gqa_trainer = None
    agent_trainer = None
    security_dataset = None
    adversarial_training = None

# ============================================================================
# INFERENCE AND ANALYSIS EXPORTS
# ============================================================================
try:
    # Import real-time threat inference and analysis engines
    from .inference import (
        inference_engine,      # Main inference orchestration engine
        threat_inference,      # Threat-specific inference logic
        response_parser,       # Response parsing and formatting
    )
except ImportError as e:
    print(f"Warning: Could not import inference modules: {e}")
    inference_engine = None
    threat_inference = None
    response_parser = None

# ============================================================================
# DATA INGESTION EXPORTS
# ============================================================================
try:
    # Import secure data loading and threat intelligence feed management
    from .data_ingestion import (
        secure_loader,         # Secure URL and file loading with validation
        cve_ingestor,         # CVE database ingestion and processing
        threat_feeds,         # Threat intelligence feed aggregation
        hash_validator,       # File hash validation and integrity checking
        quarantine_pipeline,  # Malicious content quarantine system
    )
except ImportError as e:
    print(f"Warning: Could not import data ingestion modules: {e}")
    secure_loader = None
    cve_ingestor = None
    threat_feeds = None
    hash_validator = None
    quarantine_pipeline = None

# ============================================================================
# DEPLOYMENT EXPORTS
# ============================================================================
try:
    # Import deployment modules for different integration scenarios
    from .deployment import (
        website_plugin,        # Website integration plugin
        reverse_proxy,         # Reverse proxy security layer
        api_middleware,        # API security middleware
        security_dashboard,    # Web-based security dashboard
    )
except ImportError as e:
    print(f"Warning: Could not import deployment modules: {e}")
    website_plugin = None
    reverse_proxy = None
    api_middleware = None
    security_dashboard = None

# ============================================================================
# USER INTERFACE EXPORTS
# ============================================================================
try:
    # Import user interface components for interaction and visualization
    from .ui import (
        frontend,  # Frontend UI components (built with Streamlit/Dash)
        api,       # API components for programmatic access
    )
except ImportError as e:
    print(f"Warning: Could not import UI modules: {e}")
    frontend = None
    api = None

# ============================================================================
# UTILITIES EXPORTS
# ============================================================================
try:
    # Import helper utilities for security, logging, and compliance
    from .utils import (
        security_utils,    # Security helper functions
        logging_utils,     # Structured logging with audit trails
        crypto_utils,      # Cryptographic operations
        compliance_utils,  # Compliance checking utilities
    )
except ImportError as e:
    print(f"Warning: Could not import utility modules: {e}")
    security_utils = None
    logging_utils = None
    crypto_utils = None
    compliance_utils = None

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
        self.config_path = config_path
        # Use lazy imports to avoid circular dependencies and missing module errors
        self.inference_engine = None
        self.agent_orchestrator = None
        self.scanner = None
        
    def _initialize_components(self):
        """Initialize components on-demand to handle missing dependencies gracefully."""
        if self.inference_engine is None:
            try:
                from .inference.inference_engine import InferenceEngine
                self.inference_engine = InferenceEngine(self.config_path)
            except ImportError:
                self.inference_engine = None
        
        if self.agent_orchestrator is None:
            try:
                from .agents.agent_orchestrator import AgentOrchestrator
                self.agent_orchestrator = AgentOrchestrator()
            except ImportError:
                self.agent_orchestrator = None
        
        if self.scanner is None:
            try:
                from .web_security.scanner import WebSecurityScanner
                self.scanner = WebSecurityScanner(self.config_path)
            except ImportError:
                self.scanner = None
    
    def scan_website(self, url: str, depth: int = 1) -> dict:
        """
        Perform comprehensive security scan of a website.
        
        Args:
            url: Website URL to scan
            depth: Scan depth (1 = single page, 2 = page + links, etc.)
            
        Returns:
            Dictionary containing scan results, threats found, and recommendations
        """
        # Initialize components if not already done
        self._initialize_components()
        
        # Check if scanner is available
        if self.scanner is None:
            return {
                'error': 'Web security scanner not available',
                'scan': {},
                'agent_analysis': {},
                'inference': {},
                'recommendations': []
            }
        
        # 1. Perform initial security scan
        scan_results = self.scanner.scan(url, depth)
        
        # 2. Analyze with AI agents if available
        agent_analysis = {}
        if self.agent_orchestrator is not None:
            agent_analysis = self.agent_orchestrator.analyze(scan_results)
        
        # 3. Run inference on combined results if available
        final_analysis = {}
        if self.inference_engine is not None:
            final_analysis = self.inference_engine.infer(scan_results, agent_analysis)
        
        return {
            'scan': scan_results,
            'agent_analysis': agent_analysis,
            'inference': final_analysis,
            'recommendations': final_analysis.get('recommendations', []) if final_analysis else []
        }
    
    def analyze_traffic(self, traffic_log: dict) -> dict:
        """
        Analyze HTTP traffic for security threats.
        
        Args:
            traffic_log: Dictionary containing HTTP request/response data
            
        Returns:
            Threat analysis with severity scores and evidence
        """
        self._initialize_components()
        
        # Initialize specialized agents with error handling
        traffic_agent = None
        bot_agent = None
        
        try:
            from .agents.traffic_anomaly_agent import TrafficAnomalyAgent
            traffic_agent = TrafficAnomalyAgent()
        except ImportError:
            pass
        
        try:
            from .agents.bot_detection_agent import BotDetectionAgent
            bot_agent = BotDetectionAgent()
        except ImportError:
            pass
        
        # Get analysis from each agent if available
        traffic_analysis = {}
        bot_analysis = {}
        
        if traffic_agent is not None:
            traffic_analysis = traffic_agent.analyze(traffic_log)
        
        if bot_agent is not None:
            bot_analysis = bot_agent.analyze(traffic_log)
        
        # Coordinate using mHC if orchestrator is available
        coordinated = {}
        if self.agent_orchestrator is not None:
            coordinated = self.agent_orchestrator.coordinate([traffic_analysis, bot_analysis])
        else:
            # Simple merge if no orchestrator
            coordinated = {
                'traffic_analysis': traffic_analysis,
                'bot_analysis': bot_analysis
            }
        
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
        trainer = None
        
        try:
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
        except ImportError as e:
            return {
                'error': f'Could not import trainer for model type {model_type}: {e}',
                'success': False,
                'metrics': {},
                'model_path': None
            }
        
        if trainer is None:
            return {
                'error': f'Trainer for model type {model_type} not available',
                'success': False,
                'metrics': {},
                'model_path': None
            }
        
        return trainer.train()
    
    def get_system_status(self) -> dict:
        """
        Get current status of the CyberGuard system.
        
        Returns:
            Dictionary containing system health, agent statuses, and metrics
        """
        self._initialize_components()
        
        agent_count = 0
        model_count = 0
        scanner_status = 'inactive'
        
        if self.agent_orchestrator is not None:
            # Safely get agent count, handling missing attributes
            try:
                agent_count = len(self.agent_orchestrator.agents)
            except AttributeError:
                agent_count = 0
        
        if self.inference_engine is not None:
            # Safely get model count, handling missing methods
            try:
                model_count = self.inference_engine.get_model_count()
            except AttributeError:
                model_count = 0
        
        if self.scanner is not None:
            scanner_status = 'active'
        
        return {
            'version': __version__,
            'components': {
                'agents': agent_count,
                'models': model_count,
                'scanner': scanner_status
            },
            'health': self._check_system_health()
        }
    
    def _check_system_health(self) -> dict:
        """Internal method to check system component health."""
        # Basic health check that doesn't rely on external components
        health_status = {
            'database': 'unknown',
            'models': 'unknown',
            'agents': 'unknown',
            'api': 'unknown'
        }
        
        # Check if modules are importable
        try:
            import torch
            health_status['models'] = 'torch_available'
        except ImportError:
            health_status['models'] = 'torch_missing'
        
        try:
            import requests
            health_status['api'] = 'requests_available'
        except ImportError:
            health_status['api'] = 'requests_missing'
        
        return health_status

def create_security_scanner(config: dict = None):
    """
    Factory function to create a web security scanner.
    
    Args:
        config: Optional configuration dictionary
        
    Returns:
        Configured WebSecurityScanner instance or None if unavailable
    """
    try:
        from .web_security.scanner import WebSecurityScanner
        return WebSecurityScanner(config or {})
    except ImportError:
        print("Warning: WebSecurityScanner not available")
        return None

def create_agent_orchestrator(agents: list = None):
    """
    Factory function to create an agent orchestrator.
    
    Args:
        agents: Optional list of pre-configured agents
        
    Returns:
        AgentOrchestrator instance with registered agents or None if unavailable
    """
    try:
        from .agents.agent_orchestrator import AgentOrchestrator
        orchestrator = AgentOrchestrator()
        
        if agents:
            for agent in agents:
                orchestrator.register_agent(agent)
        else:
            # Try to register default agents with error handling
            try:
                from .agents.threat_detection_agent import WebThreatDetectionAgent
                orchestrator.register_agent(WebThreatDetectionAgent())
            except ImportError:
                pass
            
            try:
                from .agents.traffic_anomaly_agent import TrafficAnomalyAgent
                orchestrator.register_agent(TrafficAnomalyAgent())
            except ImportError:
                pass
            
            try:
                from .agents.bot_detection_agent import BotDetectionAgent
                orchestrator.register_agent(BotDetectionAgent())
            except ImportError:
                pass
        
        return orchestrator
    except ImportError:
        print("Warning: AgentOrchestrator not available")
        return None

def load_security_model(model_path: str, model_type: str = "gqa"):
    """
    Load a pre-trained security model.
    
    Args:
        model_path: Path to model file or directory
        model_type: Type of model ("gqa", "mhc", or "ensemble")
        
    Returns:
        Loaded model ready for inference or None if unavailable
    """
    try:
        from .core.model_factory import ModelFactory
        factory = ModelFactory()
        return factory.load_model(model_path, model_type)
    except ImportError:
        print(f"Warning: Could not load model factory for type {model_type}")
        return None

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
        Basic security assessment with risk level or error message
    """
    scanner = create_security_scanner()
    if scanner is None:
        return {'error': 'Security scanner not available', 'risk_level': 'unknown'}
    return scanner.quick_scan(url)

def analyze_http_request(request_data: dict) -> dict:
    """
    Analyze a single HTTP request for security threats.
    
    Args:
        request_data: Dictionary with HTTP request details
        
    Returns:
        Threat analysis for the request or error message
    """
    try:
        from .web_security.traffic_parser import parse_http_request
        parsed = parse_http_request(request_data)
    except ImportError:
        return {'error': 'Traffic parser not available', 'threats': []}
    
    try:
        from .agents.threat_detection_agent import WebThreatDetectionAgent
        agent = WebThreatDetectionAgent()
        return agent.analyze(parsed)
    except ImportError:
        return {'error': 'Threat detection agent not available', 'parsed_data': parsed}

def check_security_headers(url: str) -> dict:
    """
    Check and analyze security headers for a website.
    
    Args:
        url: Website URL to check
        
    Returns:
        Security header analysis with recommendations or error message
    """
    try:
        from .web_security.header_analyzer import HeaderAnalyzer
        analyzer = HeaderAnalyzer()
        return analyzer.analyze(url)
    except ImportError:
        return {'error': 'Header analyzer not available', 'url': url}

def generate_security_report(scan_results: dict, template: str = "standard") -> str:
    """
    Generate a human-readable security report.
    
    Args:
        scan_results: Dictionary with scan results
        template: Report template ("standard", "detailed", "executive")
        
    Returns:
        Formatted security report or error message
    """
    try:
        from .inference.response_parser import SecurityReportGenerator
        generator = SecurityReportGenerator()
        return generator.generate(scan_results, template)
    except ImportError:
        return f"Security Report Generation Error: Module not available\nScan Results: {scan_results}"

# ============================================================================
# TYPE DEFINITIONS FOR BETTER IDE SUPPORT
# ============================================================================
# These type hints help with autocomplete and static analysis

from typing import TYPE_CHECKING, Optional, Dict, Any, List

if TYPE_CHECKING:
    # Type checking only imports - won't execute at runtime
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
    
    # Initialize logging with error handling
    try:
        from .utils.logging_utils import setup_logging
        setup_logging()
    except ImportError:
        pass  # Logging setup is optional, continue without it
    except Exception as e:
        # Catch any other exception to prevent import failure
        print(f"Warning: Logging setup failed: {e}")
    
    # Check for required dependencies with comprehensive error handling
    dependencies = ['torch', 'numpy', 'requests']
    missing_deps = []
    
    for dep in dependencies:
        try:
            __import__(dep)
        except ImportError:
            missing_deps.append(dep)
    
    if missing_deps:
        print(f"Warning: Missing dependencies: {', '.join(missing_deps)}")
        print("Some CyberGuard features may not work correctly.")
        print("Install all dependencies with: pip install -r requirements.txt")

# Run initialization when module is imported
_initialize_package()