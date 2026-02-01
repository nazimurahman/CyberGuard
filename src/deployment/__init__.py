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

# Core deployment components - Import from submodules (these need to exist)
# Note: These imports assume the classes exist in their respective modules
from .website_plugin import WebsitePlugin  # Import WebsitePlugin class from website_plugin.py
from .reverse_proxy import ReverseProxySecurityLayer  # Import ReverseProxySecurityLayer from reverse_proxy.py
from .api_middleware import APISecurityMiddleware  # Import APISecurityMiddleware from api_middleware.py
from .security_dashboard import SecurityDashboard  # Import SecurityDashboard from security_dashboard.py

# Deployment orchestrator - Import orchestrator class
from .deployment_orchestrator import DeploymentOrchestrator  # Import DeploymentOrchestrator from deployment_orchestrator.py

# Configuration utilities - Import configuration manager
from .config_manager import DeploymentConfigManager  # Import DeploymentConfigManager from config_manager.py

# Health and monitoring - Import health monitor
from .health_monitor import DeploymentHealthMonitor  # Import DeploymentHealthMonitor from health_monitor.py

# Version information - Module metadata
__version__ = "1.0.0"  # Current module version
__author__ = "CyberGuard Security Team"  # Author/team name
__license__ = "Apache 2.0"  # Software license

# Public API - List of symbols to export when using "from module import *"
__all__ = [
    'WebsitePlugin',  # Export WebsitePlugin
    'ReverseProxySecurityLayer',  # Export ReverseProxySecurityLayer
    'APISecurityMiddleware',  # Export APISecurityMiddleware
    'SecurityDashboard',  # Export SecurityDashboard
    'DeploymentOrchestrator',  # Export DeploymentOrchestrator
    'DeploymentConfigManager',  # Export DeploymentConfigManager
    'DeploymentHealthMonitor',  # Export DeploymentHealthMonitor
]

# Initialize logging for deployment module
import logging  # Import Python's standard logging module

# Create module-specific logger
# __name__ gives the fully qualified module name (e.g., "src.deployment")
logger = logging.getLogger(__name__)  # Create a logger specific to this module

def setup_deployment_logging(level=logging.INFO):
    """
    Configure logging for the deployment module.
    
    Args:
        level: Logging level (default: INFO)
    
    Example:
        >>> from src.deployment import setup_deployment_logging
        >>> setup_deployment_logging(logging.DEBUG)
    """
    # Create formatter to define log message format
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - [DEPLOYMENT] - %(message)s'
    )  # Create formatter with timestamp, logger name, level, and deployment tag
    
    # Create handler (console for now, can be extended to file)
    handler = logging.StreamHandler()  # Create a stream handler that outputs to console
    handler.setFormatter(formatter)  # Apply the formatter to the handler
    
    # Remove existing handlers to avoid duplicate logs if reconfiguring
    for hdlr in logger.handlers[:]:
        logger.removeHandler(hdlr)
    
    # Configure module logger
    logger.setLevel(level)  # Set the logging level for this logger
    logger.addHandler(handler)  # Add the handler to the logger
    
    logger.info(f"Deployment module logging configured at level: {logging.getLevelName(level)}")  # Log the configuration

# Auto-configure logging if not already configured
if not logger.handlers:  # Check if logger has no handlers
    setup_deployment_logging()  # Set up default logging configuration

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
        'version': __version__,  # Module version
        'components': __all__,  # List of exported components
        'logging_configured': bool(logger.handlers),  # Whether logging is configured
        'log_level': logging.getLevelName(logger.level)  # Current log level as string
    }

# Initialize module with default configuration
try:
    # Import configuration from parent package
    from ..config import get_deployment_config  # Import config function from parent's config module
    
    # Get deployment configuration
    deployment_config = get_deployment_config()  # Call function to get configuration
    
    # Update logging level from config if available
    if deployment_config and 'log_level' in deployment_config:
        log_level_name = deployment_config['log_level']  # Get log level from config
        log_level = getattr(logging, log_level_name.upper(), logging.INFO)  # Convert string to logging level constant
        setup_deployment_logging(log_level)  # Reconfigure logging with config level
    
    logger.info(f"CyberGuard Deployment Module v{__version__} initialized successfully")  # Log successful initialization
    
except ImportError:
    # Handle case where config module is not available
    logger.warning("Could not load deployment configuration, using defaults")  # Log warning
    logger.info(f"CyberGuard Deployment Module v{__version__} initialized with default configuration")  # Log default initialization

# Clean up namespace - Remove imported names we don't want to export
del logging  # Remove the logging module from namespace to keep it clean

# Note: The del statement only removes it from this module's namespace,
# not from where it was imported elsewhere. It's optional but helps
# with clean namespace management.