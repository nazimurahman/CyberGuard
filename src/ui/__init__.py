# src/ui/__init__.py
"""
CyberGuard Web Security AI System - Flask UI Package

This module provides the web interface for the CyberGuard security platform,
including dashboard, real-time monitoring, alert management, and security tutor mode.

Architecture:
- Flask-based web application
- WebSocket for real-time updates
- REST API for programmatic access
- Jinja2 templating with Bootstrap 5
- Responsive design for mobile/desktop

Security Features:
- CSRF protection
- Rate limiting
- Session management
- Authentication & Authorization
- Audit logging
"""

import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))

# Package version
__version__ = "1.0.0"
__author__ = "CyberGuard Security Team"
__description__ = "Web Security AI Platform UI"

# Export main components
from .api.rest_api import CyberGuardAPI, api_blueprint
from .api.websocket_handler import WebSocketHandler, websocket_blueprint
from .api.webhook_handler import WebhookHandler, webhook_blueprint
from .frontend.dashboard import DashboardApp, dashboard_blueprint
from .frontend.alerts import AlertsManager, alerts_blueprint
from .frontend.tutor_mode import TutorMode, tutor_blueprint

# Create a factory function to initialize the complete UI
def create_ui_app(agent_orchestrator=None, security_scanner=None, config=None):
    """
    Factory function to create and configure the complete CyberGuard UI application.
    
    Args:
        agent_orchestrator: Instance of AgentOrchestrator for multi-agent coordination
        security_scanner: Instance of WebSecurityScanner for vulnerability scanning
        config: Configuration dictionary for UI settings
    
    Returns:
        Flask application instance with all UI components registered
    """
    from flask import Flask
    
    # Create Flask app
    app = Flask(__name__, 
                template_folder='templates',
                static_folder='static')
    
    # Default configuration
    default_config = {
        'SECRET_KEY': os.environ.get('SECRET_KEY', 'cyberguard-secure-key-2024'),
        'SESSION_TYPE': 'filesystem',
        'SESSION_PERMANENT': False,
        'SESSION_USE_SIGNER': True,
        'SESSION_COOKIE_SECURE': True,
        'SESSION_COOKIE_HTTPONLY': True,
        'SESSION_COOKIE_SAMESITE': 'Lax',
        'PERMANENT_SESSION_LIFETIME': 3600,  # 1 hour
        'MAX_CONTENT_LENGTH': 16 * 1024 * 1024,  # 16MB max upload
        'RATELIMIT_ENABLED': True,
        'RATELIMIT_DEFAULT': '100 per minute',
        'DEBUG': False,
        'TESTING': False,
        'WTF_CSRF_ENABLED': True,
        'WTF_CSRF_SECRET_KEY': os.environ.get('CSRF_SECRET_KEY', 'csrf-secure-key-2024')
    }
    
    # Update with provided config
    if config:
        default_config.update(config)
    
    # Apply configuration
    app.config.update(default_config)
    
    # Initialize components with dependencies
    if agent_orchestrator and security_scanner:
        # Initialize API with dependencies
        api = CyberGuardAPI(agent_orchestrator, security_scanner)
        
        # Register blueprints
        app.register_blueprint(api_blueprint)
        app.register_blueprint(websocket_blueprint)
        app.register_blueprint(webhook_blueprint)
        app.register_blueprint(dashboard_blueprint)
        app.register_blueprint(alerts_blueprint)
        app.register_blueprint(tutor_blueprint)
        
        # Store components in app context for access in routes
        app.agent_orchestrator = agent_orchestrator
        app.security_scanner = security_scanner
        app.api = api
    
    # Register error handlers
    register_error_handlers(app)
    
    # Add context processor for template variables
    @app.context_processor
    def inject_globals():
        """Inject global variables into all templates"""
        return {
            'app_version': __version__,
            'app_name': 'CyberGuard',
            'current_year': 2024
        }
    
    return app

def register_error_handlers(app):
    """Register custom error handlers for the Flask application"""
    
    @app.errorhandler(404)
    def page_not_found(e):
        """Handle 404 Not Found errors"""
        return render_template('errors/404.html'), 404
    
    @app.errorhandler(403)
    def forbidden(e):
        """Handle 403 Forbidden errors"""
        return render_template('errors/403.html'), 403
    
    @app.errorhandler(500)
    def internal_server_error(e):
        """Handle 500 Internal Server errors"""
        return render_template('errors/500.html'), 500
    
    @app.errorhandler(429)
    def rate_limit_exceeded(e):
        """Handle 429 Rate Limit exceeded"""
        return render_template('errors/429.html'), 429

# Export the factory function
__all__ = [
    'create_ui_app',
    'CyberGuardAPI',
    'WebSocketHandler',
    'WebhookHandler',
    'DashboardApp',
    'AlertsManager',
    'TutorMode'
]

print(f"CyberGuard UI Package v{__version__} initialized")