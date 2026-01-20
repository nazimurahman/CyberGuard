"""
CyberGuard Deployment Module
============================

This module contains all deployment components for the CyberGuard Web Security AI System.
It provides multiple deployment options for integrating CyberGuard into existing web infrastructure.

Deployment Modes:
1. Website Plugin: Lightweight JavaScript plugin for websites
2. Reverse Proxy: Full-featured security proxy layer
3. API Middleware: Security middleware for API gateways
4. Security Dashboard: Centralized monitoring and management interface

Key Features:
- Zero-downtime deployment
- Horizontal scalability
- Automatic configuration
- Health monitoring
- Security hardening
"""

# Core deployment components
from .website_plugin import WebsitePlugin
from .reverse_proxy import ReverseProxySecurityLayer
from .api_middleware import APISecurityMiddleware
from .security_dashboard import SecurityDashboard

# Deployment orchestrator
from .deployment_orchestrator import DeploymentOrchestrator

# Configuration utilities
from .config_manager import DeploymentConfigManager

# Health and monitoring
from .health_monitor import DeploymentHealthMonitor

# Version information
__version__ = "1.0.0"
__author__ = "CyberGuard Security Team"
__license__ = "Apache 2.0"

# Public API
__all__ = [
    'WebsitePlugin',
    'ReverseProxySecurityLayer', 
    'APISecurityMiddleware',
    'SecurityDashboard',
    'DeploymentOrchestrator',
    'DeploymentConfigManager',
    'DeploymentHealthMonitor',
]

# Initialize logging for deployment module
import logging

# Create module-specific logger
logger = logging.getLogger(__name__)

def setup_deployment_logging(level=logging.INFO):
    """
    Configure logging for the deployment module.
    
    Args:
        level: Logging level (default: INFO)
    
    Example:
        >>> from src.deployment import setup_deployment_logging
        >>> setup_deployment_logging(logging.DEBUG)
    """
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - [DEPLOYMENT] - %(message)s'
    )
    
    # Create handler (console for now, can be extended to file)
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    
    # Configure module logger
    logger.setLevel(level)
    logger.addHandler(handler)
    
    logger.info(f"Deployment module logging configured at level: {logging.getLevelName(level)}")

# Auto-configure logging if not already configured
if not logger.handlers:
    setup_deployment_logging()

# Export version and configuration check
def get_deployment_info():
    """
    Get deployment module information and configuration status.
    
    Returns:
        Dictionary containing module information and configuration status.
    
    Example:
        >>> info = get_deployment_info()
        >>> print(info['version'])
        1.0.0
    """
    return {
        'version': __version__,
        'components': __all__,
        'logging_configured': bool(logger.handlers),
        'log_level': logging.getLevelName(logger.level)
    }

# Initialize module with default configuration
try:
    # Import configuration
    from ..config import get_deployment_config
    
    # Get deployment configuration
    deployment_config = get_deployment_config()
    
    # Update logging level from config if available
    if deployment_config and 'log_level' in deployment_config:
        log_level_name = deployment_config['log_level']
        log_level = getattr(logging, log_level_name.upper(), logging.INFO)
        setup_deployment_logging(log_level)
    
    logger.info(f"CyberGuard Deployment Module v{__version__} initialized successfully")
    
except ImportError:
    logger.warning("Could not load deployment configuration, using defaults")
    logger.info(f"CyberGuard Deployment Module v{__version__} initialized with default configuration")

# Clean up namespace
del logging