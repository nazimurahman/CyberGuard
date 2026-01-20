#!/usr/bin/env python3
"""
============================================================================
CyberGuard - Intelligent Web Threat Analysis & Defense Platform
============================================================================
MAIN ENTRY POINT: Orchestrates the complete cybersecurity AI system

This file serves as the primary interface for:
1. System initialization and configuration
2. Multi-agent security analysis coordination
3. Web security scanning and threat detection
4. REST API and Dashboard serving
5. Command-line interface for operations

Architecture Components:
- Manifold-Constrained Hyper-Connections (mHC) for stable multi-agent reasoning
- Grouped Query Attention (GQA) with Flash Attention optimization
- 10 specialized security agents for comprehensive threat analysis
- Real-time web security scanner with OWASP Top-10 detection
- Interactive dashboard and REST API for operational control

Author: CyberGuard AI Team
Version: 1.0.0
License: MIT
============================================================================
"""

# ============================================================================
# IMPORTS AND DEPENDENCIES
# ============================================================================

# Standard library imports - Python built-in modules
import os                     # Operating system interfaces (file paths, environment variables)
import sys                    # System-specific parameters and functions
import argparse               # Command-line argument parsing
import json                   # JSON serialization and deserialization
import yaml                   # YAML configuration file parsing
import time                   # Time access and conversions
import logging                # Flexible event logging system
import threading              # Thread-based parallelism
import signal                 # Signal handling for graceful shutdown
from datetime import datetime # Date and time manipulation
from typing import Dict, Any, List, Optional, Tuple, Union  # Type hints for better code documentation
from pathlib import Path      # Object-oriented filesystem paths

# Third-party imports - External libraries
import torch                  # PyTorch deep learning framework
import numpy as np            # Numerical computing with arrays
import pandas as pd           # Data manipulation and analysis
import requests               # HTTP library for API requests

# Local application imports - Our own modules
# Add the src directory to Python path for module imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

# Core architecture components
from src.core.mhc_architecture import ManifoldConstrainedHyperConnections
from src.core.gqa_transformer import SecurityGQATransformer, FlashGQA
from src.core.security_encoder import SecurityFeatureEncoder

# Agent system components
from src.agents.agent_orchestrator import AgentOrchestrator
from src.agents.base_agent import SecurityAgent
from src.agents.threat_detection_agent import WebThreatDetectionAgent
from src.agents.traffic_anomaly_agent import TrafficAnomalyAgent
from src.agents.bot_detection_agent import BotDetectionAgent
from src.agents.malware_agent import MalwarePayloadAgent
from src.agents.exploit_chain_agent import ExploitChainReasoningAgent
from src.agents.forensics_agent import DigitalForensicsAgent
from src.agents.incident_response_agent import IncidentResponseAgent
from src.agents.compliance_agent import CompliancePrivacyAgent
from src.agents.code_review_agent import SecureCodeReviewAgent
from src.agents.threat_education_agent import ThreatEducationAgent

# Web security components
from src.web_security.scanner import WebSecurityScanner
from src.web_security.vulnerability_detector import VulnerabilityDetector
from src.web_security.api_analyzer import APIAnalyzer
from src.web_security.traffic_parser import TrafficParser

# Deployment components
from src.deployment.website_plugin import WebsitePlugin
from src.deployment.reverse_proxy import ReverseProxy
from src.deployment.security_dashboard import SecurityDashboard

# UI components
from src.ui.api.rest_api import CyberGuardAPI
from src.ui.frontend.dashboard import start_dashboard

# Utility modules
from src.utils.security_utils import (
    validate_url, sanitize_input, hash_sensitive_data, 
    generate_secure_token, encrypt_data, decrypt_data
)
from src.utils.logging_utils import setup_logging, get_logger
from src.utils.crypto_utils import CryptoManager
from src.utils.compliance_utils import ComplianceChecker

# Training components
from src.training.mhc_trainer import MHCTrainer
from src.training.gqa_trainer import GQATrainer
from src.training.security_dataset import SecurityDataset

# Data ingestion components
from src.data_ingestion.secure_loader import SecureDataLoader
from src.data_ingestion.cve_ingestor import CVEIngestor
from src.data_ingestion.threat_feeds import ThreatFeedManager

# ============================================================================
# CONSTANTS AND GLOBAL CONFIGURATION
# ============================================================================

# System version information
VERSION = "1.0.0"
RELEASE_DATE = "2024-01-15"
SYSTEM_NAME = "CyberGuard Web Security AI System"

# Default configuration paths
DEFAULT_CONFIG_PATH = "config/enterprise_config.yaml"
DEFAULT_LOGGING_CONFIG = "config/logging_config.yaml"
DEFAULT_SECURITY_RULES = "config/security_rules.yaml"

# System ports for services
DEFAULT_API_PORT = 8000
DEFAULT_DASHBOARD_PORT = 8080
DEFAULT_WEBSOCKET_PORT = 9000

# Security constants
MAX_SCAN_DEPTH = 3           # Maximum recursion depth for website crawling
REQUEST_TIMEOUT = 30         # Timeout for HTTP requests in seconds
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB maximum file size for analysis
RATE_LIMIT_REQUESTS = 100    # Maximum requests per minute
RATE_LIMIT_PERIOD = 60       # Rate limit period in seconds

# Performance constants
AGENT_COORDINATION_TIMEOUT = 10  # Maximum time for agent coordination in seconds
MODEL_INFERENCE_TIMEOUT = 5      # Maximum time for model inference in seconds
CACHE_TTL = 300                  # Cache time-to-live in seconds

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

# Initialize logging before anything else to capture all events
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/cyberguard.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

# Create main logger instance
logger = logging.getLogger(__name__)

# ============================================================================
# CYBERGUARD SYSTEM CLASS
# ============================================================================

class CyberGuardSystem:
    """
    ==========================================================================
    MAIN CYBERGUARD SYSTEM CLASS
    
    This class orchestrates the complete cybersecurity AI system including:
    1. Multi-agent security analysis with mHC coordination
    2. Web security scanning and vulnerability detection
    3. Machine learning model management
    4. API and dashboard serving
    5. Threat intelligence integration
    
    Design Principles:
    - Zero-trust architecture
    - Explainable AI decisions
    - Scalable agent-based architecture
    - Real-time threat detection
    - Compliance-aware operations
    ==========================================================================
    """
    
    def __init__(self, config_path: str = DEFAULT_CONFIG_PATH):
        """
        Initialize the CyberGuard system with configuration.
        
        Args:
            config_path (str): Path to the YAML configuration file.
            
        Process:
            1. Load and validate configuration
            2. Initialize core components (mHC, GQA)
            3. Register security agents
            4. Initialize web security scanner
            5. Setup deployment components
            6. Load threat intelligence
        """
        
        # Display startup banner
        self._display_startup_banner()
        
        # Track initialization start time
        self.start_time = time.time()
        
        # Step 1: Load and validate configuration
        logger.info("Step 1/7: Loading enterprise configuration...")
        self.config = self._load_configuration(config_path)
        
        # Step 2: Setup logging system
        logger.info("Step 2/7: Configuring logging system...")
        self._setup_logging()
        
        # Step 3: Initialize core architecture components
        logger.info("Step 3/7: Initializing core architecture (mHC + GQA)...")
        self._initialize_core_architecture()
        
        # Step 4: Register security agents
        logger.info("Step 4/7: Registering security agents...")
        self._initialize_agents()
        
        # Step 5: Initialize web security components
        logger.info("Step 5/7: Initializing web security scanner...")
        self._initialize_security_components()
        
        # Step 6: Initialize deployment components
        logger.info("Step 6/7: Initializing deployment components...")
        self._initialize_deployment()
        
        # Step 7: Load threat intelligence
        logger.info("Step 7/7: Loading threat intelligence...")
        self._load_threat_intelligence()
        
        # Calculate and display initialization time
        init_time = time.time() - self.start_time
        logger.info(f"✅ CyberGuard initialization completed in {init_time:.2f} seconds")
        
        # Display system status
        self._display_system_status()
        
    def _display_startup_banner(self):
        """
        Display the CyberGuard startup banner with ASCII art.
        """
        banner = """
        ╔══════════════════════════════════════════════════════════════════════════════╗
        ║                                                                              ║
        ║    ██████╗██╗   ██╗██████╗ ███████╗██████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗║
        ║   ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗║
        ║   ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║  ███╗██║   ██║███████║██████╔╝║
        ║   ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║   ██║██║   ██║██╔══██║██╔══██╗║
        ║   ╚██████╗   ██║   ██║  ██║███████╗██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║║
        ║    ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝║
        ║                                                                              ║
        ║                 Intelligent Web Threat Analysis & Defense Platform           ║
        ║                             Version: {version:37}           ║
        ║                                                                              ║
        ╚══════════════════════════════════════════════════════════════════════════════╝
        """.format(version=VERSION)
        
        print(banner)
        print(f"\n🚀 Initializing {SYSTEM_NAME}...")
        print("=" * 80)
    
    def _load_configuration(self, config_path: str) -> Dict[str, Any]:
        """
        Load and validate system configuration from YAML file.
        
        Args:
            config_path (str): Path to configuration file
            
        Returns:
            Dict[str, Any]: Validated configuration dictionary
            
        Raises:
            FileNotFoundError: If configuration file doesn't exist
            yaml.YAMLError: If configuration file has invalid YAML syntax
            ValueError: If configuration validation fails
        """
        try:
            # Check if config file exists
            if not os.path.exists(config_path):
                logger.warning(f"Configuration file not found: {config_path}")
                logger.info("Using default configuration")
                return self._get_default_config()
            
            # Load YAML configuration
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Validate required sections
            required_sections = ['system', 'security', 'agents', 'api']
            for section in required_sections:
                if section not in config:
                    raise ValueError(f"Missing required configuration section: {section}")
            
            # Set defaults for optional sections
            config.setdefault('logging', {'level': 'INFO', 'file': 'logs/cyberguard.log'})
            config.setdefault('performance', {'cache_ttl': 300, 'max_workers': 4})
            config.setdefault('training', {'enabled': False, 'auto_update': False})
            
            # Validate security settings
            if 'max_scan_depth' not in config['security']:
                config['security']['max_scan_depth'] = MAX_SCAN_DEPTH
            
            # Validate API settings
            if 'port' not in config['api']:
                config['api']['port'] = DEFAULT_API_PORT
            
            logger.info(f"✅ Configuration loaded from {config_path}")
            return config
            
        except yaml.YAMLError as e:
            logger.error(f"Invalid YAML in configuration file: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            raise
    
    def _get_default_config(self) -> Dict[str, Any]:
        """
        Get default configuration when no config file is provided.
        
        Returns:
            Dict[str, Any]: Default configuration dictionary
        """
        return {
            'system': {
                'name': SYSTEM_NAME,
                'version': VERSION,
                'environment': 'development',
                'debug': True
            },
            'security': {
                'max_scan_depth': MAX_SCAN_DEPTH,
                'request_timeout': REQUEST_TIMEOUT,
                'rate_limit': RATE_LIMIT_REQUESTS,
                'enable_threat_feeds': True
            },
            'agents': {
                'enable_all': True,
                'confidence_threshold': 0.6,
                'coordination_timeout': AGENT_COORDINATION_TIMEOUT
            },
            'api': {
                'port': DEFAULT_API_PORT,
                'host': '0.0.0.0',
                'cors_enabled': True,
                'rate_limit': '100/minute'
            },
            'dashboard': {
                'port': DEFAULT_DASHBOARD_PORT,
                'host': '0.0.0.0',
                'auth_required': False
            },
            'logging': {
                'level': 'INFO',
                'file': 'logs/cyberguard.log',
                'max_size': '100MB',
                'backup_count': 10
            },
            'performance': {
                'cache_ttl': CACHE_TTL,
                'max_workers': 4,
                'model_inference_timeout': MODEL_INFERENCE_TIMEOUT
            }
        }
    
    def _setup_logging(self):
        """
        Configure the logging system based on configuration.
        
        This sets up:
        - Log levels (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        - Log file rotation
        - Log formatting
        - Multiple handlers (file, console)
        """
        log_config = self.config.get('logging', {})
        log_level = getattr(logging, log_config.get('level', 'INFO'))
        log_file = log_config.get('file', 'logs/cyberguard.log')
        
        # Ensure log directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Configure root logger
        logging.getLogger().setLevel(log_level)
        
        # Clear existing handlers
        logging.getLogger().handlers.clear()
        
        # Create formatters
        detailed_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
        )
        simple_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # File handler with rotation
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=100 * 1024 * 1024,  # 100MB
            backupCount=10
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(detailed_formatter)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(simple_formatter)
        
        # Add handlers
        logging.getLogger().addHandler(file_handler)
        logging.getLogger().addHandler(console_handler)
        
        logger.info(f"✅ Logging configured. Level: {log_level}, File: {log_file}")
    
    def _initialize_core_architecture(self):
        """
        Initialize core architectural components:
        1. Manifold-Constrained Hyper-Connections (mHC)
        2. Grouped Query Attention (GQA) Transformer
        3. Security feature encoder
        
        mHC ensures stable multi-agent coordination by:
        - Preventing signal explosion
        - Avoiding dominant agent bias
        - Maintaining reasoning integrity
        - Enabling convex state mixing
        """
        try:
            # Initialize mHC for agent coordination
            state_dim = self.config.get('mhc', {}).get('state_dim', 512)
            self.mhc = ManifoldConstrainedHyperConnections(
                n_agents=10,  # Will be updated with actual agent count
                state_dim=state_dim,
                temperature=1.0,
                sinkhorn_iterations=50
            )
            
            # Initialize GQA Transformer for security analysis
            gqa_config = self.config.get('gqa', {})
            self.gqa_model = SecurityGQATransformer(
                vocab_size=10000,  # Security token vocabulary
                d_model=gqa_config.get('d_model', 512),
                n_heads=gqa_config.get('n_heads', 8),
                n_groups=gqa_config.get('n_groups', 2),
                dropout=gqa_config.get('dropout', 0.1),
                num_threat_classes=10  # OWASP Top-10 + other
            )
            
            # Initialize security feature encoder
            self.security_encoder = SecurityFeatureEncoder(
                feature_dim=state_dim,
                use_positional_encoding=True
            )
            
            # Move models to GPU if available
            if torch.cuda.is_available():
                self.gqa_model = self.gqa_model.cuda()
                logger.info("✅ Models moved to GPU for accelerated computation")
            else:
                logger.info("✅ Models running on CPU")
            
            logger.info("✅ Core architecture initialized (mHC + GQA)")
            
        except Exception as e:
            logger.error(f"Failed to initialize core architecture: {e}")
            raise
    
    def _initialize_agents(self):
        """
        Initialize and register all security agents.
        
        Each agent specializes in a specific aspect of security analysis:
        1. Web Threat Detection - OWASP Top-10 vulnerabilities
        2. Traffic Anomaly - Behavioral analysis
        3. Bot Detection - Automated threat identification
        4. Malware Analysis - Payload inspection
        5. Exploit Chain - Multi-step attack analysis
        6. Digital Forensics - Evidence collection
        7. Incident Response - Automated remediation
        8. Compliance - Regulatory requirements
        9. Code Review - Security best practices
        10. Threat Education - Developer training
        
        Agents coordinate through mHC to ensure stable, consensus-based decisions.
        """
        try:
            # Initialize agent orchestrator
            self.orchestrator = AgentOrchestrator(
                state_dim=self.config.get('mhc', {}).get('state_dim', 512)
            )
            
            # Register each specialized agent
            agents_config = self.config.get('agents', {})
            
            # 1. Web Threat Detection Agent
            if agents_config.get('enable_threat_detection', True):
                self.orchestrator.register_agent(
                    WebThreatDetectionAgent(
                        agent_id="threat_detection_001",
                        config=agents_config.get('threat_detection', {})
                    )
                )
                logger.debug("Registered Web Threat Detection Agent")
            
            # 2. Traffic Anomaly Agent
            if agents_config.get('enable_traffic_analysis', True):
                self.orchestrator.register_agent(
                    TrafficAnomalyAgent(
                        agent_id="traffic_anomaly_001",
                        config=agents_config.get('traffic_anomaly', {})
                    )
                )
                logger.debug("Registered Traffic Anomaly Agent")
            
            # 3. Bot Detection Agent
            if agents_config.get('enable_bot_detection', True):
                self.orchestrator.register_agent(
                    BotDetectionAgent(
                        agent_id="bot_detection_001",
                        config=agents_config.get('bot_detection', {})
                    )
                )
                logger.debug("Registered Bot Detection Agent")
            
            # 4. Malware Payload Agent
            if agents_config.get('enable_malware_analysis', True):
                self.orchestrator.register_agent(
                    MalwarePayloadAgent(
                        agent_id="malware_agent_001",
                        config=agents_config.get('malware', {})
                    )
                )
                logger.debug("Registered Malware Payload Agent")
            
            # 5. Exploit Chain Reasoning Agent
            if agents_config.get('enable_exploit_analysis', True):
                self.orchestrator.register_agent(
                    ExploitChainReasoningAgent(
                        agent_id="exploit_chain_001",
                        config=agents_config.get('exploit_chain', {})
                    )
                )
                logger.debug("Registered Exploit Chain Reasoning Agent")
            
            # 6. Digital Forensics Agent
            if agents_config.get('enable_forensics', True):
                self.orchestrator.register_agent(
                    DigitalForensicsAgent(
                        agent_id="forensics_agent_001",
                        config=agents_config.get('forensics', {})
                    )
                )
                logger.debug("Registered Digital Forensics Agent")
            
            # 7. Incident Response Agent
            if agents_config.get('enable_incident_response', True):
                self.orchestrator.register_agent(
                    IncidentResponseAgent(
                        agent_id="incident_response_001",
                        config=agents_config.get('incident_response', {})
                    )
                )
                logger.debug("Registered Incident Response Agent")
            
            # 8. Compliance & Privacy Agent
            if agents_config.get('enable_compliance', True):
                self.orchestrator.register_agent(
                    CompliancePrivacyAgent(
                        agent_id="compliance_agent_001",
                        config=agents_config.get('compliance', {})
                    )
                )
                logger.debug("Registered Compliance & Privacy Agent")
            
            # 9. Secure Code Review Agent
            if agents_config.get('enable_code_review', True):
                self.orchestrator.register_agent(
                    SecureCodeReviewAgent(
                        agent_id="code_review_001",
                        config=agents_config.get('code_review', {})
                    )
                )
                logger.debug("Registered Secure Code Review Agent")
            
            # 10. Threat Education Agent
            if agents_config.get('enable_education', True):
                self.orchestrator.register_agent(
                    ThreatEducationAgent(
                        agent_id="threat_education_001",
                        config=agents_config.get('education', {})
                    )
                )
                logger.debug("Registered Threat Education Agent")
            
            total_agents = len(self.orchestrator.agents)
            logger.info(f"✅ {total_agents} security agents registered and ready")
            
        except Exception as e:
            logger.error(f"Failed to initialize agents: {e}")
            raise
    
    def _initialize_security_components(self):
        """
        Initialize web security scanning and analysis components.
        
        Components include:
        1. Web Security Scanner - Comprehensive website analysis
        2. Vulnerability Detector - OWASP Top-10 detection
        3. API Analyzer - REST/GraphQL security assessment
        4. Traffic Parser - HTTP traffic analysis
        
        These components work together to provide multi-layered security analysis.
        """
        try:
            security_config = self.config.get('security', {})
            
            # Initialize Web Security Scanner
            self.scanner = WebSecurityScanner(
                config=security_config,
                max_depth=security_config.get('max_scan_depth', MAX_SCAN_DEPTH),
                timeout=security_config.get('request_timeout', REQUEST_TIMEOUT),
                user_agent=security_config.get('user_agent', 'CyberGuard-Security-Scanner/1.0')
            )
            
            # Initialize Vulnerability Detector
            self.vulnerability_detector = VulnerabilityDetector(
                rules_file='config/security_rules.yaml',
                enable_heuristics=True,
                confidence_threshold=0.7
            )
            
            # Initialize API Analyzer
            self.api_analyzer = APIAnalyzer(
                config=security_config.get('api_analysis', {})
            )
            
            # Initialize Traffic Parser
            self.traffic_parser = TrafficParser(
                config=security_config.get('traffic_analysis', {})
            )
            
            logger.info("✅ Web security components initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize security components: {e}")
            raise
    
    def _initialize_deployment(self):
        """
        Initialize deployment components for different deployment scenarios:
        
        1. Website Plugin - For direct website integration
        2. Reverse Proxy - For existing application protection
        3. API Middleware - For microservices security
        4. Security Dashboard - For monitoring and management
        
        These components enable flexible deployment in various environments.
        """
        try:
            deployment_config = self.config.get('deployment', {})
            
            # Initialize Website Plugin (if enabled)
            if deployment_config.get('enable_plugin', False):
                self.website_plugin = WebsitePlugin(
                    config=deployment_config.get('plugin', {})
                )
                logger.debug("Website plugin initialized")
            
            # Initialize Reverse Proxy (if enabled)
            if deployment_config.get('enable_reverse_proxy', False):
                self.reverse_proxy = ReverseProxy(
                    config=deployment_config.get('reverse_proxy', {})
                )
                logger.debug("Reverse proxy initialized")
            
            # Initialize Security Dashboard
            dashboard_config = self.config.get('dashboard', {})
            self.dashboard = SecurityDashboard(
                orchestrator=self.orchestrator,
                scanner=self.scanner,
                config=dashboard_config
            )
            
            # Initialize REST API
            api_config = self.config.get('api', {})
            self.api = CyberGuardAPI(
                orchestrator=self.orchestrator,
                scanner=self.scanner,
                dashboard=self.dashboard,
                config=api_config
            )
            
            logger.info("✅ Deployment components initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize deployment components: {e}")
            raise
    
    def _load_threat_intelligence(self):
        """
        Load threat intelligence from various sources:
        
        1. CVE databases - Common Vulnerabilities and Exposures
        2. Threat feeds - Real-time threat intelligence
        3. Attack patterns - Known attack methodologies
        4. Malware signatures - Known malicious code patterns
        
        This enables proactive threat detection based on known indicators.
        """
        try:
            security_config = self.config.get('security', {})
            
            if security_config.get('enable_threat_feeds', True):
                logger.info("📡 Loading threat intelligence feeds...")
                
                # Initialize CVE ingestor
                self.cve_ingestor = CVEIngestor(
                    cache_dir='data/cve_database',
                    update_frequency=24  # Update every 24 hours
                )
                
                # Load CVE database
                cve_count = self.cve_ingestor.load_database()
                logger.info(f"📊 Loaded {cve_count} CVE entries")
                
                # Initialize threat feed manager
                self.threat_feed_manager = ThreatFeedManager(
                    feed_urls=security_config.get('threat_feeds', []),
                    cache_dir='data/threat_feeds'
                )
                
                # Load threat feeds
                feed_results = self.threat_feed_manager.load_feeds()
                logger.info(f"📡 Loaded {len(feed_results)} threat feeds")
                
                # Initialize secure data loader
                self.data_loader = SecureDataLoader(
                    config=security_config.get('data_loading', {})
                )
                
                logger.info("✅ Threat intelligence loaded")
            else:
                logger.info("⚠️ Threat intelligence feeds disabled by configuration")
                
        except Exception as e:
            logger.warning(f"Could not load threat intelligence: {e}")
            # Continue without threat intelligence - system will still function
    
    def _display_system_status(self):
        """
        Display comprehensive system status after initialization.
        
        Shows:
        - Agent status and count
        - Component readiness
        - Configuration summary
        - Available services
        """
        print("\n" + "="*80)
        print("📊 CYBERGUARD SYSTEM STATUS")
        print("="*80)
        
        # Agent Information
        agent_status = self.orchestrator.get_system_status()
        print(f"\n🤖 AGENTS: {len(self.orchestrator.agents)} registered")
        for agent in agent_status['agent_statuses']:
            status_icon = "✅" if agent['confidence'] > 0.5 else "⚠️"
            print(f"   {status_icon} {agent['name']}: Confidence={agent['confidence']:.2f}")
        
        # Component Status
        print(f"\n🔧 COMPONENTS:")
        print(f"   ✅ mHC Architecture: {self.mhc.__class__.__name__}")
        print(f"   ✅ GQA Transformer: {self.gqa_model.__class__.__name__}")
        print(f"   ✅ Web Security Scanner: {self.scanner.__class__.__name__}")
        print(f"   ✅ Vulnerability Detector: {self.vulnerability_detector.__class__.__name__}")
        print(f"   ✅ Security Dashboard: {self.dashboard.__class__.__name__}")
        print(f"   ✅ REST API: {self.api.__class__.__name__}")
        
        # Configuration Summary
        config = self.config
        print(f"\n⚙️ CONFIGURATION:")
        print(f"   Environment: {config['system'].get('environment', 'development')}")
        print(f"   Debug Mode: {'Enabled' if config['system'].get('debug', False) else 'Disabled'}")
        print(f"   Max Scan Depth: {config['security'].get('max_scan_depth', MAX_SCAN_DEPTH)}")
        print(f"   Request Timeout: {config['security'].get('request_timeout', REQUEST_TIMEOUT)}s")
        
        # Available Services
        print(f"\n🌐 AVAILABLE SERVICES:")
        api_port = config['api'].get('port', DEFAULT_API_PORT)
        dashboard_port = config['dashboard'].get('port', DEFAULT_DASHBOARD_PORT)
        print(f"   🔗 REST API: http://localhost:{api_port}/docs")
        print(f"   📊 Dashboard: http://localhost:{dashboard_port}")
        print(f"   📡 WebSocket: ws://localhost:{DEFAULT_WEBSOCKET_PORT}")
        
        # Performance Metrics
        print(f"\n📈 PERFORMANCE METRICS:")
        print(f"   Agent Coordination Timeout: {config['agents'].get('coordination_timeout', AGENT_COORDINATION_TIMEOUT)}s")
        print(f"   Model Inference Timeout: {config['performance'].get('model_inference_timeout', MODEL_INFERENCE_TIMEOUT)}s")
        print(f"   Cache TTL: {config['performance'].get('cache_ttl', CACHE_TTL)}s")
        
        # Security Features
        print(f"\n🔐 SECURITY FEATURES:")
        print(f"   Threat Intelligence: {'Enabled' if config['security'].get('enable_threat_feeds', True) else 'Disabled'}")
        print(f"   Rate Limiting: {config['api'].get('rate_limit', '100/minute')}")
        print(f"   CORS: {'Enabled' if config['api'].get('cors_enabled', True) else 'Disabled'}")
        
        # Quick Start Commands
        print(f"\n🚀 QUICK START:")
        print(f"   Scan a website: python main.py --mode scan --url https://example.com")
        print(f"   Start API server: python main.py --mode api")
        print(f"   Start Dashboard: python main.py --mode dashboard")
        print(f"   Interactive mode: python main.py --mode interactive")
        
        print("\n" + "="*80)
        print("✅ CyberGuard is ready to protect your web applications!")
        print("="*80 + "\n")
    
    # =========================================================================
    # PUBLIC INTERFACE METHODS
    # =========================================================================
    
    def scan_website(self, url: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform comprehensive security scan of a website.
        
        This method orchestrates:
        1. Website crawling and discovery
        2. Vulnerability scanning
        3. Multi-agent security analysis
        4. Risk assessment and reporting
        
        Args:
            url (str): The website URL to scan
            options (Dict[str, Any], optional): Scanning options
            
        Returns:
            Dict[str, Any]: Comprehensive security report
            
        Example:
            >>> report = cyberguard.scan_website("https://example.com")
            >>> print(f"Risk Level: {report['metadata']['risk_level']}")
        """
        try:
            logger.info(f"🔍 Starting security scan: {url}")
            
            # Validate URL
            if not validate_url(url):
                raise ValueError(f"Invalid URL: {url}")
            
            # Merge options with defaults
            scan_options = {
                'max_depth': self.config['security'].get('max_scan_depth', MAX_SCAN_DEPTH),
                'timeout': self.config['security'].get('request_timeout', REQUEST_TIMEOUT),
                'check_headers': True,
                'check_forms': True,
                'check_scripts': True,
                'check_endpoints': True,
                'follow_redirects': True
            }
            
            if options:
                scan_options.update(options)
            
            # Step 1: Perform initial security scan
            logger.debug("Step 1: Performing initial security scan...")
            scan_start = time.time()
            scan_results = self.scanner.scan_website(url, options=scan_options)
            scan_duration = time.time() - scan_start
            logger.info(f"✅ Initial scan completed in {scan_duration:.2f} seconds")
            
            # Step 2: Analyze with vulnerability detector
            logger.debug("Step 2: Running vulnerability detection...")
            vuln_start = time.time()
            vulnerability_results = self.vulnerability_detector.analyze(scan_results)
            vuln_duration = time.time() - vuln_start
            logger.info(f"✅ Vulnerability analysis completed in {vuln_duration:.2f} seconds")
            
            # Step 3: Coordinate multi-agent analysis
            logger.debug("Step 3: Coordinating multi-agent analysis...")
            agent_start = time.time()
            
            # Prepare data for agents
            security_data = {
                'url': url,
                'scan_results': scan_results,
                'vulnerability_results': vulnerability_results,
                'timestamp': datetime.now().isoformat(),
                'scan_options': scan_options
            }
            
            # Run agent coordination
            analysis_results = self.orchestrator.coordinate_analysis(security_data)
            agent_duration = time.time() - agent_start
            logger.info(f"✅ Multi-agent analysis completed in {agent_duration:.2f} seconds")
            
            # Step 4: Generate comprehensive report
            logger.debug("Step 4: Generating security report...")
            report_start = time.time()
            report = self._generate_security_report(
                url=url,
                scan_results=scan_results,
                vulnerability_results=vulnerability_results,
                analysis_results=analysis_results,
                scan_duration=scan_duration + vuln_duration + agent_duration
            )
            report_duration = time.time() - report_start
            
            total_duration = time.time() - scan_start
            logger.info(f"✅ Security scan completed in {total_duration:.2f} seconds")
            
            # Update dashboard
            self.dashboard.add_scan_result(url, report)
            
            return report
            
        except Exception as e:
            logger.error(f"Website scan failed: {e}")
            raise
    
    def _generate_security_report(self, url: str, scan_results: Dict[str, Any],
                                vulnerability_results: Dict[str, Any],
                                analysis_results: Dict[str, Any],
                                scan_duration: float) -> Dict[str, Any]:
        """
        Generate comprehensive security report from scan results.
        
        Args:
            url (str): Scanned website URL
            scan_results (Dict): Raw scan results
            vulnerability_results (Dict): Vulnerability analysis
            analysis_results (Dict): Multi-agent analysis
            scan_duration (float): Total scan duration in seconds
            
        Returns:
            Dict[str, Any]: Structured security report
        """
        # Extract final decision from agent coordination
        final_decision = analysis_results.get('final_decision', {})
        threat_level = final_decision.get('threat_level', 0.0)
        confidence = final_decision.get('confidence', 0.0)
        
        # Determine risk level
        if threat_level >= 0.8:
            risk_level = "CRITICAL"
            risk_color = "red"
        elif threat_level >= 0.6:
            risk_level = "HIGH"
            risk_color = "orange"
        elif threat_level >= 0.4:
            risk_level = "MEDIUM"
            risk_color = "yellow"
        elif threat_level >= 0.2:
            risk_level = "LOW"
            risk_color = "blue"
        else:
            risk_level = "INFORMATIONAL"
            risk_color = "green"
        
        # Compile all vulnerabilities
        all_vulnerabilities = []
        
        # Add scan vulnerabilities
        for vuln in scan_results.get('vulnerabilities', []):
            all_vulnerabilities.append({
                'source': 'scanner',
                'type': vuln.get('type', 'Unknown'),
                'severity': vuln.get('severity', 'UNKNOWN'),
                'description': vuln.get('description', ''),
                'location': vuln.get('location', ''),
                'recommendation': vuln.get('recommendation', '')
            })
        
        # Add vulnerability detector findings
        for vuln in vulnerability_results.get('findings', []):
            all_vulnerabilities.append({
                'source': 'detector',
                'type': vuln.get('vulnerability_type', 'Unknown'),
                'severity': vuln.get('severity', 'UNKNOWN'),
                'description': vuln.get('description', ''),
                'location': vuln.get('location', ''),
                'recommendation': vuln.get('fix_recommendation', '')
            })
        
        # Add agent findings
        for agent_analysis in analysis_results.get('agent_analyses', []):
            for finding in agent_analysis.get('findings', []):
                all_vulnerabilities.append({
                    'source': f"agent:{agent_analysis.get('agent_name', 'Unknown')}",
                    'type': finding.get('type', 'Unknown'),
                    'severity': finding.get('severity', 'UNKNOWN'),
                    'description': finding.get('description', ''),
                    'location': finding.get('location', ''),
                    'recommendation': finding.get('recommended_action', '')
                })
        
        # Count vulnerabilities by severity
        severity_counts = {
            'CRITICAL': len([v for v in all_vulnerabilities if v['severity'] == 'CRITICAL']),
            'HIGH': len([v for v in all_vulnerabilities if v['severity'] == 'HIGH']),
            'MEDIUM': len([v for v in all_vulnerabilities if v['severity'] == 'MEDIUM']),
            'LOW': len([v for v in all_vulnerabilities if v['severity'] == 'LOW']),
            'INFORMATIONAL': len([v for v in all_vulnerabilities if v['severity'] == 'INFORMATIONAL'])
        }
        
        # Generate recommendations
        recommendations = []
        
        # Add agent recommendations
        if final_decision.get('mitigations'):
            recommendations.extend(final_decision['mitigations'])
        
        # Add scanner recommendations
        if scan_results.get('recommendations'):
            recommendations.extend(scan_results['recommendations'])
        
        # Deduplicate recommendations
        recommendations = list(set(recommendations))
        
        # Compile report
        report = {
            'metadata': {
                'report_id': f"CG-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                'url': url,
                'scan_date': datetime.now().isoformat(),
                'scan_duration_seconds': scan_duration,
                'cyberguard_version': VERSION,
                'report_format_version': '1.0'
            },
            'summary': {
                'risk_level': risk_level,
                'risk_color': risk_color,
                'threat_score': threat_level,
                'confidence_score': confidence,
                'total_vulnerabilities': len(all_vulnerabilities),
                'severity_breakdown': severity_counts,
                'requires_immediate_action': threat_level >= 0.7,
                'requires_human_review': final_decision.get('requires_human_review', False)
            },
            'scan_details': {
                'status_code': scan_results.get('status_code'),
                'technologies_detected': scan_results.get('technologies', []),
                'security_headers': scan_results.get('security_headers', {}),
                'forms_analyzed': len(scan_results.get('forms', [])),
                'endpoints_discovered': len(scan_results.get('endpoints', []))
            },
            'vulnerabilities': {
                'count': len(all_vulnerabilities),
                'list': all_vulnerabilities[:50],  # Limit to top 50
                'by_source': {
                    'scanner': len([v for v in all_vulnerabilities if v['source'] == 'scanner']),
                    'detector': len([v for v in all_vulnerabilities if v['source'] == 'detector']),
                    'agents': len([v for v in all_vulnerabilities if v['source'].startswith('agent:')])
                }
            },
            'agent_analysis': {
                'agents_participated': len(analysis_results.get('agent_analyses', [])),
                'coordinated_decision': final_decision,
                'agent_contributions': analysis_results.get('agent_contributions', []),
                'coordination_time': analysis_results.get('coordination_time', 0.0)
            },
            'recommendations': {
                'immediate_actions': [r for r in recommendations if any(
                    keyword in r.lower() for keyword in ['block', 'critical', 'immediate', 'urgent']
                )],
                'short_term': [r for r in recommendations if any(
                    keyword in r.lower() for keyword in ['implement', 'configure', 'enable', 'add']
                )],
                'long_term': [r for r in recommendations if any(
                    keyword in r.lower() for keyword in ['consider', 'evaluate', 'plan', 'review']
                )]
            },
            'compliance': {
                'owasp_top_10_violations': self._check_owasp_compliance(all_vulnerabilities),
                'pci_dss_violations': self._check_pci_dss_compliance(all_vulnerabilities),
                'gdpr_violations': self._check_gdpr_compliance(scan_results)
            },
            'executive_summary': self._generate_executive_summary(
                risk_level, threat_level, severity_counts, recommendations
            )
        }
        
        return report
    
    def _check_owasp_compliance(self, vulnerabilities: List[Dict]) -> List[str]:
        """
        Check OWASP Top-10 compliance violations.
        
        Args:
            vulnerabilities (List[Dict]): List of vulnerability findings
            
        Returns:
            List[str]: List of OWASP Top-10 violations found
        """
        owasp_categories = {
            'A01: Broken Access Control': ['access control', 'authorization', 'permission'],
            'A02: Cryptographic Failures': ['crypto', 'encryption', 'ssl', 'tls'],
            'A03: Injection': ['sql injection', 'xss', 'command injection', 'xxe'],
            'A04: Insecure Design': ['design flaw', 'architecture', 'security by design'],
            'A05: Security Misconfiguration': ['misconfiguration', 'default', 'debug'],
            'A06: Vulnerable Components': ['component', 'library', 'dependency'],
            'A07: Authentication Failures': ['authentication', 'login', 'password', 'session'],
            'A08: Software Integrity': ['integrity', 'tampering', 'code signing'],
            'A09: Security Logging': ['logging', 'audit', 'monitoring'],
            'A10: Server-Side Request Forgery': ['ssrf', 'request forgery']
        }
        
        violations = []
        for category, keywords in owasp_categories.items():
            for vuln in vulnerabilities:
                description = vuln.get('description', '').lower()
                if any(keyword in description for keyword in keywords):
                    violations.append(category)
                    break
        
        return violations
    
    def _check_pci_dss_compliance(self, vulnerabilities: List[Dict]) -> List[str]:
        """
        Check PCI DSS compliance violations.
        
        Args:
            vulnerabilities (List[Dict]): List of vulnerability findings
            
        Returns:
            List[str]: List of PCI DSS violations found
        """
        pci_requirements = {
            'Req 1: Firewall Configuration': ['firewall', 'network security'],
            'Req 2: System Passwords': ['password', 'default credential'],
            'Req 3: Protect Cardholder Data': ['cardholder', 'pci', 'encryption'],
            'Req 4: Encrypt Transmission': ['ssl', 'tls', 'encryption in transit'],
            'Req 5: Anti-virus': ['malware', 'virus', 'antivirus'],
            'Req 6: Secure Systems': ['patch', 'update', 'vulnerability'],
            'Req 7: Access Control': ['access control', 'least privilege'],
            'Req 8: Authentication': ['authentication', 'multi-factor', 'mfa'],
            'Req 9: Physical Security': ['physical', 'access log'],
            'Req 10: Monitoring': ['logging', 'monitoring', 'audit trail'],
            'Req 11: Security Testing': ['testing', 'scan', 'penetration test'],
            'Req 12: Security Policy': ['policy', 'procedure', 'documentation']
        }
        
        violations = []
        for requirement, keywords in pci_requirements.items():
            for vuln in vulnerabilities:
                description = vuln.get('description', '').lower()
                if any(keyword in description for keyword in keywords):
                    violations.append(requirement)
                    break
        
        return violations
    
    def _check_gdpr_compliance(self, scan_results: Dict[str, Any]) -> List[str]:
        """
        Check GDPR compliance violations.
        
        Args:
            scan_results (Dict): Scan results
            
        Returns:
            List[str]: List of GDPR violations found
        """
        violations = []
        
        # Check for privacy-related headers
        headers = scan_results.get('security_headers', {})
        
        if not headers.get('Privacy-Policy', {}).get('present', False):
            violations.append("Missing Privacy Policy header")
        
        # Check forms for data collection
        forms = scan_results.get('forms', [])
        for form in forms:
            inputs = form.get('inputs', [])
            for input_field in inputs:
                if input_field.get('type') == 'email' and not form.get('privacy_notice', False):
                    violations.append("Form collects email without privacy notice")
                    break
        
        return violations
    
    def _generate_executive_summary(self, risk_level: str, threat_score: float,
                                  severity_counts: Dict[str, int], 
                                  recommendations: List[str]) -> str:
        """
        Generate executive summary for non-technical stakeholders.
        
        Args:
            risk_level (str): Overall risk level
            threat_score (float): Threat score (0.0 to 1.0)
            severity_counts (Dict): Vulnerability counts by severity
            recommendations (List): Security recommendations
            
        Returns:
            str: Executive summary text
        """
        critical_count = severity_counts.get('CRITICAL', 0)
        high_count = severity_counts.get('HIGH', 0)
        total_vulns = sum(severity_counts.values())
        
        summary = f"""
        EXECUTIVE SECURITY SUMMARY
        
        Overall Risk Assessment: {risk_level}
        
        The security assessment has identified {total_vulns} security issues, 
        including {critical_count} critical and {high_count} high-severity vulnerabilities.
        
        Key Findings:
        • Threat Score: {threat_score:.1%} (on a scale of 0% to 100%)
        • Immediate Action Required: {'Yes' if critical_count > 0 else 'No'}
        • Compliance Issues: Found {len(self._check_owasp_compliance([]))} OWASP Top-10 violations
        
        Top Recommendations:
        1. {recommendations[0] if recommendations else 'No specific recommendations'}
        2. {recommendations[1] if len(recommendations) > 1 else 'Conduct regular security reviews'}
        3. {recommendations[2] if len(recommendations) > 2 else 'Implement security monitoring'}
        
        Next Steps:
        • Address critical vulnerabilities within 24 hours
        • Review and implement recommendations within 7 days
        • Schedule follow-up assessment in 30 days
        
        For detailed technical information, please refer to the full report.
        """
        
        return summary
    
    def start_api_server(self, port: Optional[int] = None, host: str = "0.0.0.0"):
        """
        Start the REST API server for programmatic access.
        
        Args:
            port (int, optional): Port to bind the API server
            host (str): Host address to bind (default: 0.0.0.0 for all interfaces)
            
        The API provides endpoints for:
        - Website scanning
        - Threat analysis
        - System monitoring
        - Report generation
        """
        try:
            # Use configured port if not specified
            if port is None:
                port = self.config['api'].get('port', DEFAULT_API_PORT)
            
            logger.info(f"🌐 Starting REST API server on {host}:{port}")
            
            # Start API in a separate thread
            api_thread = threading.Thread(
                target=self.api.start,
                args=(host, port),
                daemon=True
            )
            api_thread.start()
            
            logger.info(f"✅ REST API server started")
            logger.info(f"📚 API Documentation: http://{host}:{port}/docs")
            
            return api_thread
            
        except Exception as e:
            logger.error(f"Failed to start API server: {e}")
            raise
    
    def start_dashboard(self, port: Optional[int] = None, host: str = "0.0.0.0"):
        """
        Start the security dashboard for visual monitoring.
        
        Args:
            port (int, optional): Port to bind the dashboard
            host (str): Host address to bind
            
        The dashboard provides:
        - Real-time security metrics
        - Scan results visualization
        - Threat intelligence feeds
        - Agent performance monitoring
        """
        try:
            # Use configured port if not specified
            if port is None:
                port = self.config['dashboard'].get('port', DEFAULT_DASHBOARD_PORT)
            
            logger.info(f"📊 Starting security dashboard on {host}:{port}")
            
            # Start dashboard in a separate thread
            dashboard_thread = threading.Thread(
                target=self.dashboard.start,
                args=(host, port),
                daemon=True
            )
            dashboard_thread.start()
            
            logger.info(f"✅ Security dashboard started")
            logger.info(f"🔗 Dashboard URL: http://{host}:{port}")
            
            return dashboard_thread
            
        except Exception as e:
            logger.error(f"Failed to start dashboard: {e}")
            raise
    
    def start_websocket_server(self, port: int = DEFAULT_WEBSOCKET_PORT):
        """
        Start WebSocket server for real-time updates.
        
        Args:
            port (int): WebSocket server port
            
        WebSocket provides:
        - Real-time scan progress
        - Live threat alerts
        - Agent coordination updates
        - System health monitoring
        """
        try:
            logger.info(f"📡 Starting WebSocket server on port {port}")
            
            # Import here to avoid circular imports
            from src.ui.api.websocket_handler import WebSocketHandler
            
            self.websocket_handler = WebSocketHandler(
                orchestrator=self.orchestrator,
                port=port
            )
            
            websocket_thread = threading.Thread(
                target=self.websocket_handler.start,
                daemon=True
            )
            websocket_thread.start()
            
            logger.info(f"✅ WebSocket server started on port {port}")
            
            return websocket_thread
            
        except Exception as e:
            logger.error(f"Failed to start WebSocket server: {e}")
            raise
    
    def shutdown(self):
        """
        Gracefully shutdown the CyberGuard system.
        
        This method:
        1. Stops all running services
        2. Saves system state
        3. Closes database connections
        4. Ensures clean exit
        """
        logger.info("🛑 Shutting down CyberGuard system...")
        
        try:
            # Stop API server if running
            if hasattr(self, 'api') and hasattr(self.api, 'stop'):
                self.api.stop()
                logger.info("✅ API server stopped")
            
            # Stop dashboard if running
            if hasattr(self, 'dashboard') and hasattr(self.dashboard, 'stop'):
                self.dashboard.stop()
                logger.info("✅ Dashboard stopped")
            
            # Stop WebSocket server if running
            if hasattr(self, 'websocket_handler') and hasattr(self.websocket_handler, 'stop'):
                self.websocket_handler.stop()
                logger.info("✅ WebSocket server stopped")
            
            # Save system state
            self._save_system_state()
            
            # Close database connections
            self._close_database_connections()
            
            # Log shutdown completion
            uptime = time.time() - self.start_time
            logger.info(f"✅ CyberGuard shutdown complete. Uptime: {uptime:.2f} seconds")
            
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
    
    def _save_system_state(self):
        """
        Save current system state for recovery.
        
        Saves:
        - Agent configurations
        - Scan history
        - Threat intelligence cache
        - System metrics
        """
        try:
            state_dir = Path("data/system_state")
            state_dir.mkdir(parents=True, exist_ok=True)
            
            state = {
                'timestamp': datetime.now().isoformat(),
                'agents': [
                    {
                        'id': agent.agent_id,
                        'name': agent.name,
                        'confidence': agent.confidence,
                        'memory_usage': len(agent.memory)
                    }
                    for agent in self.orchestrator.agents
                ],
                'metrics': self.orchestrator.get_system_status()['metrics'],
                'total_scans': len(self.dashboard.scan_history) if hasattr(self.dashboard, 'scan_history') else 0
            }
            
            state_file = state_dir / f"state_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(state_file, 'w') as f:
                json.dump(state, f, indent=2)
            
            logger.info(f"✅ System state saved to {state_file}")
            
        except Exception as e:
            logger.warning(f"Could not save system state: {e}")
    
    def _close_database_connections(self):
        """
        Close all database connections.
        """
        # This would close connections to SQL databases, Redis, etc.
        # Implementation depends on the database layer used
        pass
    
    def get_system_health(self) -> Dict[str, Any]:
        """
        Get comprehensive system health status.
        
        Returns:
            Dict[str, Any]: Health status including:
                - Component status
                - Resource usage
                - Performance metrics
                - Error rates
        """
        import psutil
        import socket
        
        health = {
            'timestamp': datetime.now().isoformat(),
            'system': {
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent,
                'uptime_seconds': time.time() - self.start_time
            },
            'components': {
                'orchestrator': 'healthy' if self.orchestrator else 'unhealthy',
                'scanner': 'healthy' if self.scanner else 'unhealthy',
                'api': 'healthy' if hasattr(self, 'api') else 'unhealthy',
                'dashboard': 'healthy' if hasattr(self, 'dashboard') else 'unhealthy',
                'agents': f"{len(self.orchestrator.agents)} healthy" if self.orchestrator else 'no agents'
            },
            'performance': self.orchestrator.get_system_status()['metrics'] if self.orchestrator else {},
            'network': {
                'hostname': socket.gethostname(),
                'ip_address': socket.gethostbyname(socket.gethostname())
            }
        }
        
        return health

# ============================================================================
# COMMAND-LINE INTERFACE
# ============================================================================

def main():
    """
    Main entry point for the CyberGuard command-line interface.
    
    This function:
    1. Parses command-line arguments
    2. Initializes the CyberGuard system
    3. Executes the requested operation mode
    4. Handles errors and clean shutdown
    
    Command-line modes:
    - scan: Scan a specific website
    - api: Start REST API server
    - dashboard: Start security dashboard
    - interactive: Start interactive console
    - train: Train machine learning models
    - health: Check system health
    """
    
    # Create argument parser
    parser = argparse.ArgumentParser(
        description=f"{SYSTEM_NAME} v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --mode scan --url https://example.com
  %(prog)s --mode api --port 8000
  %(prog)s --mode dashboard --port 8080
  %(prog)s --mode interactive
        """
    )
    
    # Define command-line arguments
    parser.add_argument(
        '--mode', '-m',
        type=str,
        choices=['scan', 'api', 'dashboard', 'interactive', 'train', 'health'],
        default='interactive',
        help='Operation mode (default: interactive)'
    )
    
    parser.add_argument(
        '--url', '-u',
        type=str,
        help='Website URL to scan (required for scan mode)'
    )
    
    parser.add_argument(
        '--config', '-c',
        type=str,
        default=DEFAULT_CONFIG_PATH,
        help=f'Configuration file path (default: {DEFAULT_CONFIG_PATH})'
    )
    
    parser.add_argument(
        '--port', '-p',
        type=int,
        help='Port for API or dashboard mode'
    )
    
    parser.add_argument(
        '--host',
        type=str,
        default='0.0.0.0',
        help='Host address to bind (default: 0.0.0.0)'
    )
    
    parser.add_argument(
        '--output', '-o',
        type=str,
        help='Output file for scan results'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {VERSION} ({RELEASE_DATE})'
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # Setup logging level based on verbose flag
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")
    
    # Initialize CyberGuard system
    try:
        logger.info(f"Initializing CyberGuard in {args.mode} mode...")
        cyberguard = CyberGuardSystem(config_path=args.config)
        
    except Exception as e:
        logger.error(f"Failed to initialize CyberGuard: {e}")
        sys.exit(1)
    
    # Handle different operation modes
    try:
        if args.mode == 'scan':
            # Scan mode: Scan a specific website
            if not args.url:
                logger.error("URL is required for scan mode. Use --url <URL>")
                sys.exit(1)
            
            logger.info(f"Starting scan of {args.url}")
            report = cyberguard.scan_website(args.url)
            
            # Output results
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(report, f, indent=2)
                logger.info(f"Report saved to {args.output}")
            else:
                print("\n" + "="*80)
                print("SCAN REPORT SUMMARY")
                print("="*80)
                print(f"URL: {report['metadata']['url']}")
                print(f"Risk Level: {report['summary']['risk_level']}")
                print(f"Threat Score: {report['summary']['threat_score']:.2f}")
                print(f"Total Vulnerabilities: {report['summary']['total_vulnerabilities']}")
                
                if report['summary']['requires_immediate_action']:
                    print("\n⚠️  IMMEDIATE ACTION REQUIRED!")
                    print("Critical vulnerabilities detected that require immediate attention.")
                
                # Display top recommendations
                if report['recommendations']['immediate_actions']:
                    print("\n🚨 IMMEDIATE ACTIONS:")
                    for action in report['recommendations']['immediate_actions'][:3]:
                        print(f"  • {action}")
        
        elif args.mode == 'api':
            # API mode: Start REST API server
            port = args.port or cyberguard.config['api'].get('port', DEFAULT_API_PORT)
            
            # Start API server
            api_thread = cyberguard.start_api_server(port=port, host=args.host)
            
            # Start WebSocket server for real-time updates
            websocket_thread = cyberguard.start_websocket_server()
            
            # Keep main thread alive
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Shutting down API server...")
                cyberguard.shutdown()
        
        elif args.mode == 'dashboard':
            # Dashboard mode: Start security dashboard
            port = args.port or cyberguard.config['dashboard'].get('port', DEFAULT_DASHBOARD_PORT)
            
            # Start dashboard
            dashboard_thread = cyberguard.start_dashboard(port=port, host=args.host)
            
            # Keep main thread alive
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Shutting down dashboard...")
                cyberguard.shutdown()
        
        elif args.mode == 'train':
            # Train mode: Train machine learning models
            logger.info("Starting model training...")
            
            # Initialize trainer
            trainer = GQATrainer(
                model=cyberguard.gqa_model,
                config=cyberguard.config.get('training', {})
            )
            
            # Train model
            trainer.train()
            
            logger.info("Model training completed")
        
        elif args.mode == 'health':
            # Health mode: Check system health
            health = cyberguard.get_system_health()
            
            print("\n" + "="*80)
            print("SYSTEM HEALTH CHECK")
            print("="*80)
            
            print(f"\n📊 System Resources:")
            print(f"  CPU Usage: {health['system']['cpu_percent']:.1f}%")
            print(f"  Memory Usage: {health['system']['memory_percent']:.1f}%")
            print(f"  Disk Usage: {health['system']['disk_percent']:.1f}%")
            print(f"  Uptime: {health['system']['uptime_seconds']:.0f} seconds")
            
            print(f"\n🔧 Component Status:")
            for component, status in health['components'].items():
                status_icon = "✅" if 'healthy' in status else "❌"
                print(f"  {status_icon} {component}: {status}")
            
            print(f"\n📈 Performance Metrics:")
            if health['performance']:
                for metric, value in health['performance'].items():
                    print(f"  • {metric}: {value}")
            else:
                print("  No performance metrics available")
            
            print(f"\n🌐 Network:")
            print(f"  Hostname: {health['network']['hostname']}")
            print(f"  IP Address: {health['network']['ip_address']}")
            
            print("\n" + "="*80)
        
        elif args.mode == 'interactive':
            # Interactive mode: Start interactive console
            print("\n" + "="*80)
            print("💻 CYBERGUARD INTERACTIVE CONSOLE")
            print("="*80)
            print("Type 'help' for available commands")
            print("Type 'exit' or 'quit' to exit")
            print("="*80)
            
            while True:
                try:
                    # Get user command
                    command = input("\ncyberguard> ").strip()
                    
                    if not command:
                        continue
                    
                    # Parse command
                    parts = command.split()
                    cmd = parts[0].lower()
                    
                    if cmd in ['exit', 'quit', 'q']:
                        print("\n👋 Goodbye!")
                        break
                    
                    elif cmd == 'help':
                        print("\n📚 Available Commands:")
                        print("  scan <url>           - Scan a website for security vulnerabilities")
                        print("  health               - Check system health")
                        print("  agents               - List all security agents")
                        print("  status               - Show system status")
                        print("  api start            - Start REST API server")
                        print("  dashboard start      - Start security dashboard")
                        print("  clear                - Clear screen")
                        print("  help                 - Show this help message")
                        print("  exit/quit/q          - Exit CyberGuard")
                    
                    elif cmd == 'scan' and len(parts) > 1:
                        url = parts[1]
                        print(f"\n🔍 Scanning {url}...")
                        report = cyberguard.scan_website(url)
                        
                        print(f"\n📋 Scan Results:")
                        print(f"  Risk Level: {report['summary']['risk_level']}")
                        print(f"  Threat Score: {report['summary']['threat_score']:.2f}")
                        print(f"  Vulnerabilities: {report['summary']['total_vulnerabilities']}")
                        
                        # Save report
                        report_file = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                        with open(report_file, 'w') as f:
                            json.dump(report, f, indent=2)
                        print(f"  Report saved to: {report_file}")
                    
                    elif cmd == 'health':
                        health = cyberguard.get_system_health()
                        print(f"\n💚 System Health:")
                        print(f"  CPU: {health['system']['cpu_percent']:.1f}%")
                        print(f"  Memory: {health['system']['memory_percent']:.1f}%")
                        print(f"  Uptime: {health['system']['uptime_seconds']:.0f}s")
                    
                    elif cmd == 'agents':
                        status = cyberguard.orchestrator.get_system_status()
                        print(f"\n🤖 Security Agents ({len(cyberguard.orchestrator.agents)}):")
                        for agent in status['agent_statuses']:
                            confidence = agent['confidence']
                            icon = "✅" if confidence > 0.7 else "⚠️" if confidence > 0.4 else "❌"
                            print(f"  {icon} {agent['name']} (Confidence: {confidence:.2f})")
                    
                    elif cmd == 'status':
                        status = cyberguard.orchestrator.get_system_status()
                        print(f"\n📊 System Status:")
                        print(f"  Total Analyses: {status['metrics']['total_analyses']}")
                        print(f"  Threats Detected: {status['metrics']['threats_detected']}")
                        print(f"  Coordination Time: {status['metrics']['avg_coordination_time']:.3f}s")
                    
                    elif cmd == 'api' and len(parts) > 1 and parts[1] == 'start':
                        print("\n🌐 Starting API server...")
                        api_thread = cyberguard.start_api_server()
                        print(f"✅ API server started")
                        print(f"📚 Documentation: http://localhost:{cyberguard.config['api'].get('port', DEFAULT_API_PORT)}/docs")
                        print("Press Ctrl+C to stop")
                        
                        try:
                            while True:
                                time.sleep(1)
                        except KeyboardInterrupt:
                            print("\n🛑 Stopping API server...")
                    
                    elif cmd == 'dashboard' and len(parts) > 1 and parts[1] == 'start':
                        print("\n📊 Starting dashboard...")
                        dashboard_thread = cyberguard.start_dashboard()
                        print(f"✅ Dashboard started")
                        print(f"🔗 URL: http://localhost:{cyberguard.config['dashboard'].get('port', DEFAULT_DASHBOARD_PORT)}")
                        print("Press Ctrl+C to stop")
                        
                        try:
                            while True:
                                time.sleep(1)
                        except KeyboardInterrupt:
                            print("\n🛑 Stopping dashboard...")
                    
                    elif cmd == 'clear':
                        os.system('cls' if os.name == 'nt' else 'clear')
                    
                    else:
                        print(f"❓ Unknown command: {command}")
                        print("Type 'help' for available commands")
                
                except KeyboardInterrupt:
                    print("\n\n👋 Goodbye!")
                    break
                except Exception as e:
                    print(f"⚠️  Error: {e}")
        
        else:
            logger.error(f"Unknown mode: {args.mode}")
            sys.exit(1)
    
    except KeyboardInterrupt:
        logger.info("Shutdown requested by user")
        cyberguard.shutdown()
    except Exception as e:
        logger.error(f"Operation failed: {e}")
        cyberguard.shutdown()
        sys.exit(1)

# ============================================================================
# SIGNAL HANDLERS FOR GRACEFUL SHUTDOWN
# ============================================================================

def signal_handler(signum, frame):
    """
    Handle system signals for graceful shutdown.
    
    Args:
        signum (int): Signal number
        frame: Current stack frame
    """
    signal_name = {
        signal.SIGINT: "SIGINT",
        signal.SIGTERM: "SIGTERM",
        signal.SIGQUIT: "SIGQUIT"
    }.get(signum, f"Signal {signum}")
    
    logger.info(f"Received {signal_name}, initiating graceful shutdown...")
    sys.exit(0)

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    """
    Main entry point when script is executed directly.
    
    This block:
    1. Sets up signal handlers
    2. Runs the main function
    3. Handles uncaught exceptions
    4. Ensures clean exit
    """
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 CyberGuard shutdown by user")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Unhandled exception: {e}", exc_info=True)
        sys.exit(1)