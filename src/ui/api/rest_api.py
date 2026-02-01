# src/ui/api/rest_api.py
"""
REST API for CyberGuard Web Security AI System

Provides programmatic access to security scanning, threat analysis,
and system management through HTTP endpoints.

Features:
- Rate limiting per IP/API key
- API key authentication
- Request validation
- Comprehensive error handling
- JSON response formatting
- OpenAPI/Swagger documentation
"""

from flask import Blueprint, request, jsonify, current_app, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import json
import time
import hashlib
import hmac
from typing import Dict, Any, Optional, List, Tuple, Callable
from datetime import datetime, timedelta
import re
from urllib.parse import urlparse

# Create blueprint for API routes - groups related routes together
api_blueprint = Blueprint('api', __name__, url_prefix='/api/v1')

# Initialize rate limiter with default limits (will be fully configured in app factory)
limiter = Limiter(
    key_func=get_remote_address,  # Uses client IP address for rate limiting
    default_limits=["100 per minute"]  # Default limit for all endpoints
)

def init_limiter(app):
    """Initialize rate limiter with the Flask application instance"""
    limiter.init_app(app)

# API key management - in production, use a database or secure storage
API_KEYS = {
    # Format: 'api_key': {'name': 'Client Name', 'permissions': ['scan', 'read', 'write']}
    'cyberguard-dev-2024': {
        'name': 'Development',
        'permissions': ['scan', 'read', 'write', 'admin'],
        'rate_limit': '100/minute'
    },
    'cyberguard-readonly-2024': {
        'name': 'Read Only',
        'permissions': ['read'],
        'rate_limit': '50/minute'
    }
}

def require_api_key(f: Callable) -> Callable:
    """
    Decorator to require valid API key for endpoint access
    
    This implements HMAC-based API key validation with timestamp checking
    to prevent replay attacks.
    
    Args:
        f: The function to decorate
        
    Returns:
        Decorated function that validates API key before execution
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get API key and signature from request headers
        api_key = request.headers.get('X-API-Key')
        api_signature = request.headers.get('X-API-Signature')
        api_timestamp = request.headers.get('X-API-Timestamp')
        
        # Check if API key is provided
        if not api_key:
            return jsonify({
                'error': 'API key required',
                'code': 'API_KEY_MISSING'
            }), 401
        
        # Validate API key exists in our system
        if api_key not in API_KEYS:
            return jsonify({
                'error': 'Invalid API key',
                'code': 'API_KEY_INVALID'
            }), 401
        
        # Check timestamp to prevent replay attacks (within 5 minutes)
        if api_timestamp:
            try:
                # Convert timestamp to datetime object
                request_time = datetime.fromtimestamp(int(api_timestamp))
                current_time = datetime.now()
                time_diff = current_time - request_time
                
                # Reject if timestamp is too old or too far in future
                if abs(time_diff) > timedelta(minutes=5):
                    return jsonify({
                        'error': 'Request timestamp expired',
                        'code': 'TIMESTAMP_EXPIRED'
                    }), 401
            except (ValueError, TypeError):
                # Handle invalid timestamp format
                return jsonify({
                    'error': 'Invalid timestamp',
                    'code': 'TIMESTAMP_INVALID'
                }), 401
        
        # Verify HMAC signature for write operations (POST, PUT, DELETE, PATCH)
        if api_signature and request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            # Get request payload for signature calculation
            payload = request.get_data(as_text=True) or ''
            
            # Create secret for HMAC - combine API key with timestamp
            secret = f"{api_key}-{api_timestamp}" if api_timestamp else api_key
            
            # Calculate expected signature
            expected_signature = hmac.new(
                secret.encode('utf-8'),
                payload.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()
            
            # Compare signatures securely (prevents timing attacks)
            if not hmac.compare_digest(api_signature, expected_signature):
                return jsonify({
                    'error': 'Invalid signature',
                    'code': 'SIGNATURE_INVALID'
                }), 401
        
        # Store API key information in Flask's global context for route access
        g.api_key_info = API_KEYS[api_key]
        g.api_key = api_key
        
        # Execute the original function if all checks pass
        return f(*args, **kwargs)
    
    return decorated_function

def require_permission(permission: str) -> Callable:
    """
    Decorator factory to require specific permission for endpoint access
    
    Args:
        permission: Required permission (e.g., 'scan', 'read', 'write', 'admin')
        
    Returns:
        Decorator function that checks permissions
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        @require_api_key  # Chain decorators - require API key first, then check permission
        def decorated_function(*args, **kwargs):
            # Check if API key has the required permission
            if permission not in g.api_key_info.get('permissions', []):
                return jsonify({
                    'error': f'Permission denied: {permission} required',
                    'code': 'PERMISSION_DENIED'
                }), 403
            
            # Execute the original function if permission check passes
            return f(*args, **kwargs)
        return decorated_function
    return decorator

class CyberGuardAPI:
    """Main API class for CyberGuard security operations"""
    
    def __init__(self, agent_orchestrator, security_scanner):
        """
        Initialize API with core system components
        
        Args:
            agent_orchestrator: AgentOrchestrator instance for multi-agent analysis
            security_scanner: WebSecurityScanner instance for vulnerability scanning
        """
        self.agent_orchestrator = agent_orchestrator
        self.security_scanner = security_scanner
        self.scan_history = []  # Simple in-memory storage - in production, use database
        self.max_history = 1000  # Maximum number of scans to keep in history
    
    def _validate_url(self, url: str) -> bool:
        """
        Validate URL format and safety to prevent SSRF attacks
        
        Args:
            url: URL string to validate
            
        Returns:
            True if URL is valid and safe, False otherwise
        """
        # Basic URL pattern validation using regex
        url_pattern = re.compile(
            r'^(https?://)'  # http:// or https://
            r'(([A-Za-z0-9-]+\.)+[A-Za-z]{2,})'  # domain with subdomains
            r'(:\d+)?'  # optional port
            r'(/.*)?$'  # optional path
        )
        
        # Check if URL matches the pattern
        if not url_pattern.match(url):
            return False
        
        # Parse URL for additional validation
        parsed = urlparse(url)
        
        # Check for localhost/internal IP addresses (could be SSRF attempt)
        if parsed.hostname in ['localhost', '127.0.0.1', '0.0.0.0']:
            return False
        
        # Check for private IP ranges (RFC 1918)
        if parsed.hostname:
            if parsed.hostname.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.', 
                                         '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
                                         '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
                                         '172.29.', '172.30.', '172.31.')):
                return False
        
        return True
    
    def scan_website(self, url: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform security scan of a website
        
        Args:
            url: Website URL to scan
            options: Additional scan options (depth, timeout, etc.)
            
        Returns:
            Scan results including vulnerabilities and recommendations
            
        Raises:
            ValueError: If URL is invalid or unsafe
        """
        # Validate URL before proceeding
        if not self._validate_url(url):
            raise ValueError(f"Invalid or unsafe URL: {url}")
        
        # Set default options if none provided
        options = options or {}
        scan_depth = options.get('depth', 3)
        timeout = options.get('timeout', 30)
        
        # Record start time for performance measurement
        scan_start = time.time()
        
        # Step 1: Perform initial security scan
        scan_results = self.security_scanner.scan_website(url)
        
        # Step 2: Analyze results with multi-agent system
        analysis_input = {
            'url': url,
            'scan_results': scan_results,
            'timestamp': datetime.now().isoformat(),
            'options': options
        }
        
        # Coordinate analysis across different security agents
        analysis_results = self.agent_orchestrator.coordinate_analysis(analysis_input)
        
        # Step 3: Generate comprehensive API-friendly report
        report = self._generate_api_report(scan_results, analysis_results)
        
        # Step 4: Store result in history
        self._store_scan_result(url, report)
        
        # Calculate scan duration
        scan_duration = time.time() - scan_start
        
        return {
            'status': 'success',
            'data': {
                'scan_id': report['scan_id'],
                'url': url,
                'scan_duration': scan_duration,
                'report': report,
                'timestamp': datetime.now().isoformat()
            }
        }
    
    def _generate_api_report(self, scan_results: Dict[str, Any], 
                            analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate API-friendly security report from scan and analysis results
        
        Args:
            scan_results: Raw scan results from security scanner
            analysis_results: Processed results from agent analysis
            
        Returns:
            Formatted report dictionary ready for API response
        """
        # Generate unique scan ID using hash of timestamp and URL
        scan_id = hashlib.sha256(
            f"{datetime.now().isoformat()}{scan_results.get('url', '')}".encode()
        ).hexdigest()[:16]  # Use first 16 chars as scan ID
        
        # Extract threat level from analysis
        threat_level = analysis_results['final_decision']['threat_level']
        
        # Determine risk level based on threat score
        if threat_level > 0.8:
            risk_level = "CRITICAL"
        elif threat_level > 0.6:
            risk_level = "HIGH"
        elif threat_level > 0.4:
            risk_level = "MEDIUM"
        elif threat_level > 0.2:
            risk_level = "LOW"
        else:
            risk_level = "INFORMATIONAL"
        
        # Compile vulnerabilities from all agent findings
        vulnerabilities = []
        for agent_analysis in analysis_results.get('agent_analyses', []):
            for finding in agent_analysis.get('findings', []):
                vulnerabilities.append({
                    'type': finding.get('type', 'Unknown'),
                    'severity': finding.get('severity', 'UNKNOWN'),
                    'description': finding.get('description', ''),
                    'location': finding.get('location', ''),
                    'agent': agent_analysis.get('agent_name', 'Unknown'),
                    'confidence': finding.get('confidence', 0.5)
                })
        
        # Sort vulnerabilities by severity (most severe first)
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFORMATIONAL': 4}
        vulnerabilities.sort(key=lambda x: severity_order.get(x['severity'], 5))
        
        # Count missing security headers
        security_headers = scan_results.get('security_headers', {})
        missing_headers_count = 0
        for header_info in security_headers.values():
            if not header_info.get('present'):
                missing_headers_count += 1
        
        return {
            'scan_id': scan_id,
            'metadata': {
                'scan_date': datetime.now().isoformat(),
                'risk_level': risk_level,
                'threat_score': float(threat_level),
                'confidence_score': analysis_results['final_decision']['confidence'],
                'requires_human_review': analysis_results['final_decision'].get('requires_human_review', False)
            },
            'summary': {
                'total_vulnerabilities': len(vulnerabilities),
                'by_severity': {
                    'CRITICAL': len([v for v in vulnerabilities if v['severity'] == 'CRITICAL']),
                    'HIGH': len([v for v in vulnerabilities if v['severity'] == 'HIGH']),
                    'MEDIUM': len([v for v in vulnerabilities if v['severity'] == 'MEDIUM']),
                    'LOW': len([v for v in vulnerabilities if v['severity'] == 'LOW']),
                    'INFORMATIONAL': len([v for v in vulnerabilities if v['severity'] == 'INFORMATIONAL'])
                },
                'security_headers': {
                    'total': len(security_headers),
                    'missing': missing_headers_count
                }
            },
            'vulnerabilities': vulnerabilities[:50],  # Limit to 50 for API response
            'security_headers': security_headers,
            'recommendations': analysis_results['final_decision'].get('mitigations', []),
            'agent_contributions': analysis_results.get('agent_contributions', []),
            'action': analysis_results['final_decision'].get('action', 'ALLOW')
        }
    
    def _store_scan_result(self, url: str, report: Dict[str, Any]) -> None:
        """
        Store scan result in history (in-memory implementation)
        
        Args:
            url: Scanned URL
            report: Generated scan report
        """
        self.scan_history.append({
            'url': url,
            'report': report,
            'timestamp': datetime.now().isoformat()
        })
        
        # Keep only recent history (FIFO)
        if len(self.scan_history) > self.max_history:
            self.scan_history = self.scan_history[-self.max_history:]
    
    def get_scan_history(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Get scan history with pagination
        
        Args:
            limit: Maximum number of results to return
            offset: Starting position in history
            
        Returns:
            List of scan history entries
        """
        start = offset
        end = offset + limit
        return self.scan_history[start:end]
    
    def get_system_status(self) -> Dict[str, Any]:
        """
        Get system status and metrics
        
        Returns:
            Dictionary containing system status information
        """
        # Get agent system status if available
        if self.agent_orchestrator:
            status = self.agent_orchestrator.get_system_status()
        else:
            status = {}
        
        return {
            'status': 'operational',
            'timestamp': datetime.now().isoformat(),
            'metrics': status.get('metrics', {}),
            'agents': status.get('agent_statuses', []),
            'total_scans': len(self.scan_history),
            'api_version': '1.0.0'
        }

# API Routes - defined as Flask route handlers

@api_blueprint.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint for monitoring and load balancers
    
    Returns:
        JSON response indicating service health status
    """
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'service': 'cyberguard-api'
    }), 200

@api_blueprint.route('/scan', methods=['POST'])
@limiter.limit("10 per minute")  # More restrictive rate limit for resource-intensive scans
@require_permission('scan')  # Requires 'scan' permission
def scan_endpoint():
    """
    Endpoint to scan a website for security vulnerabilities
    
    Expected JSON request body:
    {
        "url": "https://example.com",
        "options": {
            "depth": 3,
            "timeout": 30,
            "check_headers": true
        }
    }
    
    Returns:
        JSON response with scan results or error message
    """
    try:
        # Parse JSON request data
        data = request.get_json()
        
        # Validate required field
        if not data or 'url' not in data:
            return jsonify({
                'error': 'Missing required field: url',
                'code': 'VALIDATION_ERROR'
            }), 400
        
        # Extract parameters
        url = data['url']
        options = data.get('options', {})
        
        # Get API instance from Flask app context
        api_instance = current_app.api
        
        # Validate URL
        if not api_instance._validate_url(url):
            return jsonify({
                'error': 'Invalid or unsafe URL',
                'code': 'URL_INVALID'
            }), 400
        
        # Perform the scan
        result = api_instance.scan_website(url, options)
        
        return jsonify(result), 200
        
    except ValueError as e:
        # Handle validation errors
        return jsonify({
            'error': str(e),
            'code': 'VALIDATION_ERROR'
        }), 400
    except Exception as e:
        # Log unexpected errors and return generic error message
        current_app.logger.error(f"Scan error: {str(e)}")
        return jsonify({
            'error': 'Internal server error during scan',
            'code': 'SCAN_ERROR'
        }), 500

@api_blueprint.route('/scan/<scan_id>', methods=['GET'])
@require_permission('read')  # Requires 'read' permission
def get_scan_result(scan_id: str):
    """
    Get specific scan result by scan ID
    
    Args:
        scan_id: Unique identifier of the scan
        
    Returns:
        JSON response with scan details or 404 if not found
    """
    api_instance = current_app.api
    
    # Search for scan in history (most recent first)
    for scan in reversed(api_instance.scan_history):
        if scan['report'].get('scan_id') == scan_id:
            return jsonify({
                'status': 'success',
                'data': scan
            }), 200
    
    # Scan not found
    return jsonify({
        'error': 'Scan not found',
        'code': 'SCAN_NOT_FOUND'
    }), 404

@api_blueprint.route('/scans', methods=['GET'])
@require_permission('read')  # Requires 'read' permission
def list_scans():
    """
    List recent scans with pagination
    
    Query parameters:
        limit: Maximum number of results (default: 50, max: 100)
        offset: Starting position (default: 0)
        
    Returns:
        JSON response with paginated scan list
    """
    api_instance = current_app.api
    
    # Get and validate pagination parameters
    try:
        limit = min(int(request.args.get('limit', 50)), 100)  # Cap at 100 for performance
        offset = int(request.args.get('offset', 0))
    except ValueError:
        return jsonify({
            'error': 'Invalid pagination parameters',
            'code': 'VALIDATION_ERROR'
        }), 400
    
    # Get paginated scan history
    scans = api_instance.get_scan_history(limit, offset)
    
    return jsonify({
        'status': 'success',
        'data': {
            'scans': scans,
            'pagination': {
                'limit': limit,
                'offset': offset,
                'total': len(api_instance.scan_history),
                'has_more': offset + limit < len(api_instance.scan_history)
            }
        }
    }), 200

@api_blueprint.route('/status', methods=['GET'])
@require_api_key  # Requires API key but no specific permission
def system_status():
    """
    Get system status and metrics
    
    Returns:
        JSON response with system status information
    """
    api_instance = current_app.api
    status = api_instance.get_system_status()
    
    return jsonify({
        'status': 'success',
        'data': status
    }), 200

@api_blueprint.route('/agents', methods=['GET'])
@require_permission('read')  # Requires 'read' permission
def list_agents():
    """
    List all active security agents and their status
    
    Returns:
        JSON response with agent information
    """
    api_instance = current_app.api
    
    # Check if agent system is available
    if not api_instance.agent_orchestrator:
        return jsonify({
            'error': 'Agent system not available',
            'code': 'AGENTS_UNAVAILABLE'
        }), 503
    
    # Get agent system status
    status = api_instance.agent_orchestrator.get_system_status()
    
    return jsonify({
        'status': 'success',
        'data': {
            'agents': status.get('agent_statuses', []),
            'total': status.get('active_agents', 0)
        }
    }), 200

@api_blueprint.route('/analyze', methods=['POST'])
@require_permission('write')  # Requires 'write' permission
def analyze_raw_data():
    """
    Analyze raw security data without full website scan
    
    Useful for analyzing specific requests, headers, or payloads
    
    Expected JSON request body:
    {
        "url": "https://example.com",
        "method": "GET",
        "headers": {...},
        "body": "...",
        "query_params": {...}
    }
    
    Returns:
        JSON response with analysis results
    """
    try:
        # Parse request data
        data = request.get_json()
        
        # Validate request has data
        if not data:
            return jsonify({
                'error': 'No data provided',
                'code': 'VALIDATION_ERROR'
            }), 400
        
        # Check required fields
        required_fields = ['url', 'method']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'error': f'Missing required field: {field}',
                    'code': 'VALIDATION_ERROR'
                }), 400
        
        api_instance = current_app.api
        
        # Prepare analysis input
        analysis_input = {
            'url': data['url'],
            'method': data['method'],
            'headers': data.get('headers', {}),
            'body': data.get('body', ''),
            'query_params': data.get('query_params', {}),
            'timestamp': datetime.now().isoformat()
        }
        
        # Perform analysis using agent system
        analysis_results = api_instance.agent_orchestrator.coordinate_analysis(analysis_input)
        
        return jsonify({
            'status': 'success',
            'data': {
                'analysis': analysis_results,
                'timestamp': datetime.now().isoformat()
            }
        }), 200
        
    except Exception as e:
        # Log and handle analysis errors
        current_app.logger.error(f"Analysis error: {str(e)}")
        return jsonify({
            'error': 'Analysis failed',
            'code': 'ANALYSIS_ERROR'
        }), 500

@api_blueprint.route('/docs', methods=['GET'])
def api_docs():
    """
    API documentation endpoint (OpenAPI/Swagger format)
    
    Returns:
        OpenAPI specification in JSON format
    """
    docs = {
        'openapi': '3.0.0',
        'info': {
            'title': 'CyberGuard Security API',
            'version': '1.0.0',
            'description': 'REST API for web security scanning and analysis'
        },
        'paths': {
            '/api/v1/health': {
                'get': {
                    'summary': 'Health check',
                    'responses': {
                        '200': {
                            'description': 'Service is healthy'
                        }
                    }
                }
            },
            '/api/v1/scan': {
                'post': {
                    'summary': 'Scan website for vulnerabilities',
                    'security': [{'apiKey': []}],
                    'responses': {
                        '200': {
                            'description': 'Scan completed successfully'
                        },
                        '400': {
                            'description': 'Invalid request'
                        },
                        '401': {
                            'description': 'Authentication required'
                        },
                        '429': {
                            'description': 'Rate limit exceeded'
                        }
                    }
                }
            }
        },
        'components': {
            'securitySchemes': {
                'apiKey': {
                    'type': 'apiKey',
                    'in': 'header',
                    'name': 'X-API-Key'
                }
            }
        }
    }
    
    return jsonify(docs), 200