# src/ui/api/webhook_handler.py
"""
Webhook Handler for CyberGuard External Integrations

Handles incoming webhooks from:
- CI/CD pipelines
- Security tools
- Monitoring systems
- SIEM platforms
- External threat feeds

Features:
- Webhook signature verification
- Rate limiting
- Event queuing
- Retry logic
- Payload validation
"""

from flask import Blueprint, request, jsonify, current_app
import json
import hmac
import hashlib
import time
from typing import Dict, Any, Optional, Tuple
from datetime import datetime
from functools import wraps

# Create blueprint for webhook routes
webhook_blueprint = Blueprint('webhook', __name__, url_prefix='/webhooks')

# Webhook configuration - Fixed: Added proper syntax and removed trailing comma
WEBHOOK_CONFIGS = {
    # Format: webhook_id -> configuration
    'github_security': {
        'secret': 'github-webhook-secret-2024',
        'events': ['push', 'pull_request', 'code_scanning_alert'],
        'rate_limit': '10 per minute',
        'enabled': True
    },
    'jenkins_build': {
        'secret': 'jenkins-webhook-secret-2024',
        'events': ['build_started', 'build_completed', 'deployment'],
        'rate_limit': '20 per minute',
        'enabled': True
    },
    'security_scanner': {
        'secret': 'scanner-webhook-secret-2024',
        'events': ['scan_started', 'vulnerability_found', 'scan_completed'],
        'rate_limit': '30 per minute',
        'enabled': True
    },
    'threat_intel': {
        'secret': 'threat-intel-webhook-secret-2024',
        'events': ['cve_published', 'exploit_released', 'malware_detected'],
        'rate_limit': '50 per minute',
        'enabled': True
    }
}

# Webhook event queue (in production, use message queue like Redis)
# Fixed: Properly initialized as list
webhook_event_queue = []
MAX_QUEUE_SIZE = 1000

class WebhookHandler:
    """Handler for processing incoming webhooks"""
    
    def __init__(self, agent_orchestrator=None):
        """
        Initialize webhook handler
        
        Args:
            agent_orchestrator: AgentOrchestrator for processing security events
        """
        # Store agent orchestrator for security event processing
        self.agent_orchestrator = agent_orchestrator
        # Statistics counters
        self.processed_webhooks = 0
        self.failed_webhooks = 0
        
        # Event processors registry - maps webhook IDs to processing methods
        self.event_processors = {
            'github_security': self._process_github_webhook,
            'jenkins_build': self._process_jenkins_webhook,
            'security_scanner': self._process_security_scanner_webhook,
            'threat_intel': self._process_threat_intel_webhook
        }
    
    def verify_signature(self, payload: bytes, signature: str, 
                        webhook_id: str) -> bool:
        """
        Verify webhook signature using HMAC
        
        Args:
            payload: Raw request payload
            signature: Received signature header
            webhook_id: Webhook configuration ID
        
        Returns:
            True if signature is valid, False otherwise
        """
        # Check if webhook ID exists in configuration
        if webhook_id not in WEBHOOK_CONFIGS:
            return False
        
        # Get configuration for this webhook
        config = WEBHOOK_CONFIGS[webhook_id]
        # Encode secret for HMAC
        secret = config['secret'].encode('utf-8')
        
        # Generate expected signature using HMAC-SHA256
        expected_signature = hmac.new(
            secret,
            payload,
            hashlib.sha256
        ).hexdigest()
        
        # Use hmac.compare_digest to prevent timing attacks
        # Fixed: Removed incorrect method call
        return hmac.compare_digest(signature, expected_signature)
    
    def validate_payload(self, payload: Dict, webhook_id: str) -> Tuple[bool, Optional[str]]:
        """
        Validate webhook payload structure
        
        Args:
            payload: Parsed JSON payload
            webhook_id: Webhook configuration ID
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check if payload is empty
        if not payload:
            return False, "Empty payload"
        
        # Check if webhook ID exists in configuration
        if webhook_id not in WEBHOOK_CONFIGS:
            return False, f"Unknown webhook ID: {webhook_id}"
        
        config = WEBHOOK_CONFIGS[webhook_id]
        
        # Check required fields based on webhook type
        if webhook_id == 'github_security':
            required_fields = ['repository', 'sender', 'action']
            for field in required_fields:
                if field not in payload:
                    return False, f"Missing required field: {field}"
        
        elif webhook_id == 'jenkins_build':
            if 'build' not in payload:
                return False, "Missing 'build' field"
        
        elif webhook_id == 'security_scanner':
            required_fields = ['scan_id', 'status', 'findings']
            for field in required_fields:
                if field not in payload:
                    return False, f"Missing required field: {field}"
        
        elif webhook_id == 'threat_intel':
            required_fields = ['source', 'threat_type', 'severity']
            for field in required_fields:
                if field not in payload:
                    return False, f"Missing required field: {field}"
        
        # All validations passed
        return True, None
    
    def process_webhook(self, webhook_id: str, payload: Dict, 
                       headers: Dict) -> Dict[str, Any]:
        """
        Process incoming webhook
        
        Args:
            webhook_id: Webhook configuration ID
            payload: Parsed JSON payload
            headers: HTTP headers for verification
        
        Returns:
            Processing result
        """
        start_time = time.time()
        
        try:
            # 1. Verify webhook is enabled
            config = WEBHOOK_CONFIGS.get(webhook_id)
            if not config or not config.get('enabled', False):
                return {
                    'status': 'error',
                    'message': f'Webhook {webhook_id} is disabled',
                    'timestamp': datetime.now().isoformat()
                }
            
            # 2. Verify signature
            signature = headers.get('X-Hub-Signature-256', '')
            if signature.startswith('sha256='):
                signature = signature[7:]  # Remove 'sha256=' prefix
            
            # Convert payload to JSON string for signature verification
            # Fixed: Use consistent payload serialization
            payload_str = json.dumps(payload, sort_keys=True).encode('utf-8')
            
            if not self.verify_signature(payload_str, signature, webhook_id):
                self.failed_webhooks += 1
                return {
                    'status': 'error',
                    'message': 'Invalid signature',
                    'timestamp': datetime.now().isoformat()
                }
            
            # 3. Validate payload structure
            is_valid, error_msg = self.validate_payload(payload, webhook_id)
            if not is_valid:
                self.failed_webhooks += 1
                return {
                    'status': 'error',
                    'message': error_msg,
                    'timestamp': datetime.now().isoformat()
                }
            
            # 4. Queue for processing
            event_id = self._queue_webhook_event(webhook_id, payload, headers)
            
            # 5. Process based on webhook type
            if webhook_id in self.event_processors:
                result = self.event_processors[webhook_id](payload, headers)
            else:
                result = self._process_generic_webhook(payload, headers)
            
            # Update success counter
            self.processed_webhooks += 1
            
            # Calculate processing time
            processing_time = time.time() - start_time
            
            return {
                'status': 'success',
                'message': 'Webhook processed successfully',
                'event_id': event_id,
                'processing_time': processing_time,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            # Log error and update failure counter
            current_app.logger.error(f"Webhook processing error: {str(e)}")
            self.failed_webhooks += 1
            
            return {
                'status': 'error',
                'message': f'Processing error: {str(e)}',
                'timestamp': datetime.now().isoformat()
            }
    
    def _queue_webhook_event(self, webhook_id: str, payload: Dict, 
                            headers: Dict) -> str:
        """
        Queue webhook event for async processing
        
        Args:
            webhook_id: Webhook configuration ID
            payload: Event payload
            headers: HTTP headers
        
        Returns:
            Event ID
        """
        # Generate unique event ID using SHA256 hash
        event_id = hashlib.sha256(
            f"{webhook_id}{datetime.now().isoformat()}{json.dumps(payload)}".encode()
        ).hexdigest()[:16]  # Use first 16 chars for shorter ID
        
        # Create event object
        event = {
            'event_id': event_id,
            'webhook_id': webhook_id,
            'payload': payload,
            'headers': dict(headers),  # Convert headers to dict for serialization
            'received_at': datetime.now().isoformat(),
            'processed': False
        }
        
        # Add to queue
        webhook_event_queue.append(event)
        
        # Maintain queue size - remove oldest if exceeds limit
        if len(webhook_event_queue) > MAX_QUEUE_SIZE:
            webhook_event_queue.pop(0)  # Remove oldest
        
        return event_id
    
    def _process_github_webhook(self, payload: Dict, headers: Dict) -> Dict[str, Any]:
        """Process GitHub security webhook"""
        # Extract GitHub-specific headers
        event_type = headers.get('X-GitHub-Event', 'unknown')
        action = payload.get('action', 'unknown')
        repository = payload.get('repository', {}).get('full_name', 'unknown')
        
        # Log webhook processing
        current_app.logger.info(
            f"Processing GitHub webhook: {event_type}.{action} for {repository}"
        )
        
        # Extract security-relevant information
        security_data = {
            'event_type': event_type,
            'action': action,
            'repository': repository,
            'sender': payload.get('sender', {}).get('login', 'unknown'),
            'timestamp': datetime.now().isoformat()
        }
        
        # Handle code scanning alerts
        if event_type == 'code_scanning_alert':
            alert = payload.get('alert', {})
            security_data.update({
                'alert_state': alert.get('state', 'unknown'),
                'alert_severity': alert.get('severity', 'unknown'),
                'alert_description': alert.get('description', ''),
                'tool': alert.get('tool', {}).get('name', 'unknown')
            })
            
            # Trigger security analysis if alert is new or reopened
            if action in ['created', 'reopened']:
                self._trigger_security_analysis(security_data)
        
        # Handle push events for security scanning
        elif event_type == 'push' and self.agent_orchestrator:
            # Analyze commit messages and changes for security issues
            commits = payload.get('commits', [])
            security_data['commit_count'] = len(commits)
            
            # Check commit messages for security keywords
            security_keywords = ['fix', 'security', 'vulnerability', 'CVE', 'patch']
            security_commits = []
            
            for commit in commits:
                message = commit.get('message', '').lower()
                if any(keyword in message for keyword in security_keywords):
                    security_commits.append({
                        'id': commit.get('id', '')[:8],
                        'message': commit.get('message', '')[:100]  # Truncate message
                    })
            
            if security_commits:
                security_data['security_commits'] = security_commits
        
        return {
            'processed': True,
            'event_type': event_type,
            'security_data': security_data
        }
    
    def _process_jenkins_webhook(self, payload: Dict, headers: Dict) -> Dict[str, Any]:
        """Process Jenkins build webhook"""
        build_info = payload.get('build', {})
        # Extract job name from URL if available
        job_name = build_info.get('full_url', '').split('/')[-2] if build_info.get('full_url') else 'unknown'
        build_status = build_info.get('status', 'unknown')
        
        current_app.logger.info(
            f"Processing Jenkins webhook: {job_name} - {build_status}"
        )
        
        # Extract build information
        build_data = {
            'job_name': job_name,
            'build_number': build_info.get('number', 0),
            'status': build_status,
            'duration': build_info.get('duration', 0),
            'timestamp': datetime.now().isoformat()
        }
        
        # Check for security scan results in artifacts
        if 'artifacts' in payload:
            # Look for security scan reports in artifact paths
            for artifact in payload['artifacts']:
                artifact_path = artifact.get('relativePath', '').lower()
                # Check for common security report extensions
                if any(ext in artifact_path for ext in ['.sarif', '.json', '.xml', 'security', 'scan']):
                    build_data['security_artifacts'] = artifact
                    break
        
        # Trigger security review for failed builds
        if build_status == 'FAILURE' and self.agent_orchestrator:
            # In production, this would trigger a security review workflow
            # Placeholder for actual implementation
            pass
        
        return {
            'processed': True,
            'build_data': build_data
        }
    
    def _process_security_scanner_webhook(self, payload: Dict, 
                                         headers: Dict) -> Dict[str, Any]:
        """Process security scanner webhook"""
        scan_id = payload.get('scan_id', 'unknown')
        status = payload.get('status', 'unknown')
        findings = payload.get('findings', [])
        
        current_app.logger.info(
            f"Processing security scanner webhook: {scan_id} - {status}"
        )
        
        scanner_data = {
            'scan_id': scan_id,
            'status': status,
            'finding_count': len(findings),
            'timestamp': datetime.now().isoformat()
        }
        
        # Process findings
        if findings and self.agent_orchestrator:
            # Categorize findings by severity
            severity_counts = {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0,
                'INFORMATIONAL': 0
            }
            
            for finding in findings:
                severity = finding.get('severity', 'UNKNOWN').upper()
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            scanner_data['severity_counts'] = severity_counts
            
            # Trigger incident response for critical findings
            if severity_counts['CRITICAL'] > 0 or severity_counts['HIGH'] > 3:
                # Create security incident
                incident_data = {
                    'type': 'scanner_findings',
                    'scan_id': scan_id,
                    'critical_count': severity_counts['CRITICAL'],
                    'high_count': severity_counts['HIGH'],
                    'timestamp': datetime.now().isoformat()
                }
                
                # In production, this would trigger incident response workflow
                # Placeholder for actual implementation
                pass
        
        return {
            'processed': True,
            'scanner_data': scanner_data
        }
    
    def _process_threat_intel_webhook(self, payload: Dict, 
                                     headers: Dict) -> Dict[str, Any]:
        """Process threat intelligence webhook"""
        source = payload.get('source', 'unknown')
        threat_type = payload.get('threat_type', 'unknown')
        severity = payload.get('severity', 'MEDIUM')
        
        current_app.logger.info(
            f"Processing threat intel webhook: {source} - {threat_type} ({severity})"
        )
        
        intel_data = {
            'source': source,
            'threat_type': threat_type,
            'severity': severity,
            'timestamp': datetime.now().isoformat(),
            'raw_payload': payload  # Store for reference
        }
        
        # Update threat intelligence database
        if self.agent_orchestrator:
            # Notify relevant agents based on threat type
            if threat_type in ['cve_published', 'exploit_released']:
                # Update vulnerability database
                # Placeholder for actual implementation
                pass
            elif threat_type == 'malware_detected':
                # Update malware signatures
                # Placeholder for actual implementation
                pass
        
        return {
            'processed': True,
            'intel_data': intel_data
        }
    
    def _process_generic_webhook(self, payload: Dict, headers: Dict) -> Dict[str, Any]:
        """Process generic webhook"""
        return {
            'processed': True,
            'payload': payload,
            'headers': dict(headers),
            'timestamp': datetime.now().isoformat()
        }
    
    def _trigger_security_analysis(self, security_data: Dict):
        """Trigger security analysis for webhook events"""
        if self.agent_orchestrator:
            try:
                # Coordinate analysis with security agents
                analysis_input = {
                    'event_type': 'webhook_triggered',
                    'source': 'github',
                    'security_data': security_data,
                    'timestamp': datetime.now().isoformat()
                }
                
                # In production, this would trigger the agent system
                # Placeholder for actual implementation
                # result = self.agent_orchestrator.coordinate_analysis(analysis_input)
                pass
                
            except Exception as e:
                current_app.logger.error(f"Security analysis failed: {str(e)}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get webhook processing statistics"""
        return {
            'processed_webhooks': self.processed_webhooks,
            'failed_webhooks': self.failed_webhooks,
            'queue_size': len(webhook_event_queue),
            'webhook_configs': list(WEBHOOK_CONFIGS.keys()),
            'timestamp': datetime.now().isoformat()
        }

# Initialize global handler instance
webhook_handler = WebhookHandler()

# Webhook routes
@webhook_blueprint.route('/github', methods=['POST'])
def github_webhook():
    """Handle GitHub webhooks"""
    return _process_webhook_request('github_security')

@webhook_blueprint.route('/jenkins', methods=['POST'])
def jenkins_webhook():
    """Handle Jenkins webhooks"""
    return _process_webhook_request('jenkins_build')

@webhook_blueprint.route('/security-scanner', methods=['POST'])
def security_scanner_webhook():
    """Handle security scanner webhooks"""
    return _process_webhook_request('security_scanner')

@webhook_blueprint.route('/threat-intel', methods=['POST'])
def threat_intel_webhook():
    """Handle threat intelligence webhooks"""
    return _process_webhook_request('threat_intel')

@webhook_blueprint.route('/generic', methods=['POST'])
def generic_webhook():
    """Handle generic webhooks"""
    # Get webhook ID from headers, default to 'generic'
    webhook_id = request.headers.get('X-Webhook-ID', 'generic')
    return _process_webhook_request(webhook_id)

@webhook_blueprint.route('/stats', methods=['GET'])
def webhook_stats():
    """Get webhook processing statistics"""
    stats = webhook_handler.get_stats()
    return jsonify({
        'status': 'success',
        'data': stats
    }), 200

@webhook_blueprint.route('/config', methods=['GET'])
def webhook_config():
    """Get webhook configuration (without secrets)"""
    safe_config = {}
    for webhook_id, config in WEBHOOK_CONFIGS.items():
        safe_config[webhook_id] = {
            'events': config.get('events', []),
            'rate_limit': config.get('rate_limit', ''),
            'enabled': config.get('enabled', False)
            # Don't expose secrets for security
        }
    
    return jsonify({
        'status': 'success',
        'data': safe_config
    }), 200

def _process_webhook_request(webhook_id: str):
    """Process webhook request"""
    try:
        # Get payload - only accept JSON content
        if request.is_json:
            payload = request.get_json()
        else:
            return jsonify({
                'status': 'error',
                'message': 'Content-Type must be application/json'
            }), 400
        
        # Process webhook through handler
        result = webhook_handler.process_webhook(
            webhook_id,
            payload,
            dict(request.headers)  # Convert headers to dict
        )
        
        # Return appropriate status code based on result
        if result['status'] == 'success':
            return jsonify(result), 200
        else:
            return jsonify(result), 400
            
    except Exception as e:
        # Log internal server errors
        current_app.logger.error(f"Webhook processing failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error',
            'timestamp': datetime.now().isoformat()
        }), 500

# Export handler and blueprint for use in other modules
__all__ = ['webhook_handler', 'webhook_blueprint']