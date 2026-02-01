# src/ui/frontend/alerts.py
"""
Alerts Management System for CyberGuard

Handles security alerts including:
- Real-time alert display
- Alert categorization and prioritization
- Acknowledgment workflow
- Alert history and archiving
- Notification system integration

Features:
- Severity-based filtering
- Search and filtering
- Bulk operations
- Export functionality
- Notification rules
"""

from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import login_required, current_user  # Added current_user import
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from enum import Enum

# Create blueprint for alerts routes
alerts_blueprint = Blueprint('alerts', __name__, url_prefix='/alerts')

class AlertSeverity(Enum):
    """Alert severity levels"""
    INFORMATIONAL = 'informational'
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'

class AlertStatus(Enum):
    """Alert status"""
    NEW = 'new'
    ACKNOWLEDGED = 'acknowledged'
    INVESTIGATING = 'investigating'
    RESOLVED = 'resolved'
    FALSE_POSITIVE = 'false_positive'

class AlertType(Enum):
    """Alert types"""
    SCAN_RESULT = 'scan_result'
    THREAT_DETECTED = 'threat_detected'
    SYSTEM_ALERT = 'system_alert'
    AGENT_ALERT = 'agent_alert'
    COMPLIANCE_ALERT = 'compliance_alert'
    PERFORMANCE_ALERT = 'performance_alert'

class AlertsManager:
    """Manager for security alerts"""
    
    def __init__(self):
        """Initialize alerts manager"""
        self.alerts = []  # In production, use database
        self.next_alert_id = 1
        
        # Alert rules configuration
        self.rules = {
            'auto_acknowledge_low': True,
            'notification_enabled': True,
            'email_notifications': False,
            'slack_notifications': False,
            'retention_days': 90
        }
        
        # Load sample alerts for demonstration
        self._load_sample_alerts()
    
    def _load_sample_alerts(self):
        """Load sample alerts for demonstration"""
        sample_alerts = [
            {
                'id': self._generate_alert_id(),
                'type': AlertType.SCAN_RESULT.value,
                'severity': AlertSeverity.HIGH.value,
                'title': 'SQL Injection vulnerability detected',
                'description': 'Potential SQL injection attack attempt detected in login form',
                'source': 'Web Threat Detection Agent',
                'timestamp': (datetime.now() - timedelta(hours=2)).isoformat(),
                'status': AlertStatus.NEW.value,
                'metadata': {
                    'url': 'https://example.com/login',
                    'payload': "' OR '1'='1",
                    'confidence': 0.85
                }
            },
            {
                'id': self._generate_alert_id(),
                'type': AlertType.SCAN_RESULT.value,
                'severity': AlertSeverity.MEDIUM.value,
                'title': 'Missing security headers',
                'description': 'Website missing Content-Security-Policy header',
                'source': 'Security Scanner',
                'timestamp': (datetime.now() - timedelta(hours=5)).isoformat(),
                'status': AlertStatus.ACKNOWLEDGED.value,
                'metadata': {
                    'url': 'https://example.com',
                    'missing_headers': ['Content-Security-Policy', 'X-Frame-Options']
                }
            },
            {
                'id': self._generate_alert_id(),
                'type': AlertType.SYSTEM_ALERT.value,
                'severity': AlertSeverity.CRITICAL.value,
                'title': 'High system load detected',
                'description': 'System CPU usage above 90% for 5 minutes',
                'source': 'System Monitor',
                'timestamp': (datetime.now() - timedelta(minutes=30)).isoformat(),
                'status': AlertStatus.INVESTIGATING.value,
                'metadata': {
                    'metric': 'cpu_usage',
                    'value': 92.5,
                    'threshold': 90.0
                }
            }
        ]
        
        self.alerts.extend(sample_alerts)
    
    def _generate_alert_id(self) -> str:
        """Generate unique alert ID"""
        alert_id = f"ALERT-{self.next_alert_id:06d}"  # Format with leading zeros
        self.next_alert_id += 1
        return alert_id
    
    def create_alert(self, alert_data: Dict[str, Any]) -> str:
        """
        Create a new security alert
        
        Args:
            alert_data: Alert information
        
        Returns:
            Alert ID
        """
        # Validate required fields
        required_fields = ['type', 'severity', 'title', 'description', 'source']
        for field in required_fields:
            if field not in alert_data:
                raise ValueError(f"Missing required field: {field}")
        
        # Generate alert ID
        alert_id = self._generate_alert_id()
        
        # Create alert object
        alert = {
            'id': alert_id,
            'type': alert_data['type'],
            'severity': alert_data['severity'],
            'title': alert_data['title'],
            'description': alert_data['description'],
            'source': alert_data['source'],
            'timestamp': datetime.now().isoformat(),
            'status': AlertStatus.NEW.value,
            'metadata': alert_data.get('metadata', {}),
            'assigned_to': alert_data.get('assigned_to'),
            'notes': []
        }
        
        # Auto-acknowledge low severity alerts if configured
        if (self.rules['auto_acknowledge_low'] and 
            alert['severity'] == AlertSeverity.LOW.value):
            alert['status'] = AlertStatus.ACKNOWLEDGED.value
        
        # Add to alerts list
        self.alerts.append(alert)
        
        # Trigger notifications
        self._trigger_notifications(alert)
        
        return alert_id
    
    def _trigger_notifications(self, alert: Dict):
        """Trigger notifications for new alert"""
        if not self.rules['notification_enabled']:
            return
        
        # Only notify for medium or higher severity
        if alert['severity'] in [AlertSeverity.LOW.value, AlertSeverity.INFORMATIONAL.value]:
            return
        
        # Log notification (in production, send actual notifications)
        current_app.logger.info(
            f"Alert notification: {alert['title']} (Severity: {alert['severity']})"
        )
    
    def get_alerts(self, filters: Optional[Dict] = None, 
                  limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Get alerts with optional filtering
        
        Args:
            filters: Filter criteria
            limit: Maximum number of alerts to return
            offset: Offset for pagination
        
        Returns:
            List of filtered alerts
        """
        filtered_alerts = self.alerts.copy()  # Create copy to avoid modifying original
        
        # Apply filters if provided
        if filters:
            # Filter by severity
            if 'severity' in filters:
                filtered_alerts = [
                    a for a in filtered_alerts 
                    if a['severity'] == filters['severity']
                ]
            
            # Filter by status
            if 'status' in filters:
                filtered_alerts = [
                    a for a in filtered_alerts 
                    if a['status'] == filters['status']
                ]
            
            # Filter by type
            if 'type' in filters:
                filtered_alerts = [
                    a for a in filtered_alerts 
                    if a['type'] == filters['type']
                ]
            
            # Filter by date range
            if 'start_date' in filters and 'end_date' in filters:
                try:
                    start_date = datetime.fromisoformat(filters['start_date'])
                    end_date = datetime.fromisoformat(filters['end_date'])
                    
                    filtered_alerts = [
                        a for a in filtered_alerts 
                        if start_date <= datetime.fromisoformat(a['timestamp']) <= end_date
                    ]
                except ValueError:
                    pass  # Invalid date format, skip date filtering
            
            # Search in title and description
            if 'search' in filters and filters['search']:
                search_term = filters['search'].lower()
                filtered_alerts = [
                    a for a in filtered_alerts 
                    if (search_term in a['title'].lower() or 
                        search_term in a['description'].lower())
                ]
        
        # Sort by timestamp (newest first)
        filtered_alerts.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Apply pagination
        start_idx = offset
        end_idx = offset + limit
        return filtered_alerts[start_idx:end_idx]
    
    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Get specific alert by ID"""
        for alert in self.alerts:
            if alert['id'] == alert_id:
                return alert
        return None
    
    def update_alert_status(self, alert_id: str, status: str, 
                           notes: Optional[str] = None) -> bool:
        """
        Update alert status
        
        Args:
            alert_id: Alert ID to update
            status: New status
            notes: Optional notes about the status change
        
        Returns:
            True if updated successfully, False otherwise
        """
        # Validate status
        valid_statuses = [s.value for s in AlertStatus]
        if status not in valid_statuses:
            raise ValueError(f"Invalid status. Must be one of: {valid_statuses}")
        
        # Find and update alert
        for alert in self.alerts:
            if alert['id'] == alert_id:
                alert['status'] = status
                alert['updated_at'] = datetime.now().isoformat()
                
                # Add notes if provided
                if notes:
                    if 'notes' not in alert:
                        alert['notes'] = []
                    # Use current user if available, otherwise use 'system'
                    author = getattr(current_user, 'username', 'system') if hasattr(current_user, 'username') else 'system'
                    alert['notes'].append({
                        'timestamp': datetime.now().isoformat(),
                        'text': notes,
                        'author': author
                    })
                
                return True
        
        return False
    
    def add_note_to_alert(self, alert_id: str, note: str, author: str = 'system') -> bool:
        """Add note to alert"""
        for alert in self.alerts:
            if alert['id'] == alert_id:
                if 'notes' not in alert:
                    alert['notes'] = []
                
                alert['notes'].append({
                    'timestamp': datetime.now().isoformat(),
                    'text': note,
                    'author': author
                })
                
                return True
        
        return False
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get alert statistics"""
        total_alerts = len(self.alerts)
        
        # Count by severity
        severity_counts = {s.value: 0 for s in AlertSeverity}
        for alert in self.alerts:
            severity_counts[alert['severity']] = severity_counts.get(alert['severity'], 0) + 1
        
        # Count by status
        status_counts = {s.value: 0 for s in AlertStatus}
        for alert in self.alerts:
            status_counts[alert['status']] = status_counts.get(alert['status'], 0) + 1
        
        # Count by type
        type_counts = {}
        for alert in self.alerts:
            alert_type = alert['type']
            type_counts[alert_type] = type_counts.get(alert_type, 0) + 1
        
        # Recent alerts (last 24 hours)
        recent_threshold = datetime.now() - timedelta(hours=24)
        recent_alerts = [
            alert for alert in self.alerts 
            if datetime.fromisoformat(alert['timestamp']) > recent_threshold
        ]
        
        return {
            'total_alerts': total_alerts,
            'severity_counts': severity_counts,
            'status_counts': status_counts,
            'type_counts': type_counts,
            'recent_alerts_24h': len(recent_alerts),
            'unacknowledged_alerts': status_counts.get(AlertStatus.NEW.value, 0),
            'timestamp': datetime.now().isoformat()
        }
    
    def delete_alert(self, alert_id: str) -> bool:
        """Delete alert by ID"""
        for i, alert in enumerate(self.alerts):
            if alert['id'] == alert_id:
                self.alerts.pop(i)
                return True
        
        return False
    
    def cleanup_old_alerts(self, days: int = 90):
        """Clean up alerts older than specified days"""
        cutoff_date = datetime.now() - timedelta(days=days)
        
        self.alerts = [
            alert for alert in self.alerts 
            if datetime.fromisoformat(alert['timestamp']) > cutoff_date
        ]

# Initialize alerts manager (single instance for the application)
alerts_manager = AlertsManager()

# ============================================
# ROUTE DEFINITIONS
# ============================================

@alerts_blueprint.route('/')
@login_required
def alerts_overview():
    """Alerts overview page - shows dashboard with statistics and recent alerts"""
    stats = alerts_manager.get_alert_statistics()
    
    # Get recent alerts for dashboard display
    recent_alerts = alerts_manager.get_alerts(limit=10)
    
    return render_template(
        'alerts/overview.html',
        title='Security Alerts',
        stats=stats,
        recent_alerts=recent_alerts,
        severity_levels=[s.value for s in AlertSeverity],
        alert_statuses=[s.value for s in AlertStatus]
    )

@alerts_blueprint.route('/list')
@login_required
def alerts_list():
    """List all alerts with filtering and pagination support"""
    # Get filter parameters from query string
    filters = {}
    
    if 'severity' in request.args and request.args['severity']:
        filters['severity'] = request.args['severity']
    
    if 'status' in request.args and request.args['status']:
        filters['status'] = request.args['status']
    
    if 'type' in request.args and request.args['type']:
        filters['type'] = request.args['type']
    
    if 'search' in request.args and request.args['search']:
        filters['search'] = request.args['search']
    
    if 'start_date' in request.args and request.args['start_date'] and \
       'end_date' in request.args and request.args['end_date']:
        filters['start_date'] = request.args['start_date']
        filters['end_date'] = request.args['end_date']
    
    # Get pagination parameters
    try:
        page = int(request.args.get('page', 1))
    except ValueError:
        page = 1  # Default to page 1 if invalid value
    
    per_page = 20
    
    # Get all filtered alerts
    all_alerts = alerts_manager.get_alerts(filters=filters)
    
    # Calculate pagination info
    total_alerts = len(all_alerts)
    total_pages = max(1, (total_alerts + per_page - 1) // per_page)  # Ensure at least 1 page
    
    # Get alerts for current page
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    page_alerts = all_alerts[start_idx:end_idx]
    
    return render_template(
        'alerts/list.html',
        title='Alert List',
        alerts=page_alerts,
        filters=filters,
        pagination={
            'page': page,
            'per_page': per_page,
            'total_pages': total_pages,
            'total_alerts': total_alerts
        }
    )

@alerts_blueprint.route('/<alert_id>')
@login_required
def alert_detail(alert_id):
    """Display detailed information for a specific alert"""
    alert = alerts_manager.get_alert(alert_id)
    
    if not alert:
        return render_template('errors/404.html'), 404
    
    return render_template(
        'alerts/detail.html',
        title=f"Alert: {alert_id}",
        alert=alert
    )

# ============================================
# API ENDPOINTS
# ============================================

@alerts_blueprint.route('/api/alerts', methods=['GET'])
@login_required
def api_get_alerts():
    """API endpoint to get alerts with filtering and pagination"""
    try:
        # Get pagination parameters with error handling
        try:
            limit = int(request.args.get('limit', 50))
            offset = int(request.args.get('offset', 0))
        except ValueError:
            limit = 50
            offset = 0
        
        # Get filters from query parameters
        filters = {}
        
        filter_fields = ['severity', 'status', 'type', 'search', 
                        'start_date', 'end_date']
        for field in filter_fields:
            if field in request.args and request.args[field]:
                filters[field] = request.args[field]
        
        # Get alerts from manager
        alerts = alerts_manager.get_alerts(filters=filters, limit=limit, offset=offset)
        
        # Get statistics for summary
        stats = alerts_manager.get_alert_statistics()
        
        return jsonify({
            'status': 'success',
            'data': {
                'alerts': alerts,
                'statistics': stats,
                'pagination': {
                    'limit': limit,
                    'offset': offset,
                    'total': len(alerts_manager.alerts),
                    'returned': len(alerts)
                }
            }
        })
        
    except Exception as e:
        current_app.logger.error(f"Error getting alerts: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error'
        }), 500

@alerts_blueprint.route('/api/alerts/<alert_id>', methods=['GET'])
@login_required
def api_get_alert(alert_id):
    """API endpoint to get a specific alert by ID"""
    alert = alerts_manager.get_alert(alert_id)
    
    if not alert:
        return jsonify({
            'status': 'error',
            'message': 'Alert not found'
        }), 404
    
    return jsonify({
        'status': 'success',
        'data': alert
    })

@alerts_blueprint.route('/api/alerts/<alert_id>/status', methods=['PUT'])
@login_required
def api_update_alert_status(alert_id):
    """API endpoint to update alert status"""
    try:
        # Parse JSON request body
        if not request.is_json:
            return jsonify({
                'status': 'error',
                'message': 'Content-Type must be application/json'
            }), 400
        
        data = request.get_json()
        
        if not data or 'status' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Status is required'
            }), 400
        
        status = data['status']
        notes = data.get('notes')
        
        # Update alert status
        success = alerts_manager.update_alert_status(alert_id, status, notes)
        
        if not success:
            return jsonify({
                'status': 'error',
                'message': 'Alert not found'
            }), 404
        
        return jsonify({
            'status': 'success',
            'message': 'Alert status updated'
        })
        
    except ValueError as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400
    except Exception as e:
        current_app.logger.error(f"Error updating alert: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error'
        }), 500

@alerts_blueprint.route('/api/alerts/<alert_id>/notes', methods=['POST'])
@login_required
def api_add_alert_note(alert_id):
    """API endpoint to add note to alert"""
    try:
        # Parse JSON request body
        if not request.is_json:
            return jsonify({
                'status': 'error',
                'message': 'Content-Type must be application/json'
            }), 400
        
        data = request.get_json()
        
        if not data or 'note' not in data or not data['note']:
            return jsonify({
                'status': 'error',
                'message': 'Note is required and cannot be empty'
            }), 400
        
        note = data['note']
        author = data.get('author', 'system')
        
        # Add note to alert
        success = alerts_manager.add_note_to_alert(alert_id, note, author)
        
        if not success:
            return jsonify({
                'status': 'error',
                'message': 'Alert not found'
            }), 404
        
        return jsonify({
            'status': 'success',
            'message': 'Note added to alert'
        })
        
    except Exception as e:
        current_app.logger.error(f"Error adding note: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error'
        }), 500

@alerts_blueprint.route('/api/alerts/statistics', methods=['GET'])
@login_required
def api_get_alert_statistics():
    """API endpoint to get alert statistics for dashboards"""
    stats = alerts_manager.get_alert_statistics()
    
    return jsonify({
        'status': 'success',
        'data': stats
    })

@alerts_blueprint.route('/api/alerts/bulk/update', methods=['POST'])
@login_required
def api_bulk_update_alerts():
    """API endpoint for bulk alert updates (multiple alerts at once)"""
    try:
        # Parse JSON request body
        if not request.is_json:
            return jsonify({
                'status': 'error',
                'message': 'Content-Type must be application/json'
            }), 400
        
        data = request.get_json()
        
        if not data or 'alert_ids' not in data or 'status' not in data:
            return jsonify({
                'status': 'error',
                'message': 'alert_ids and status are required'
            }), 400
        
        alert_ids = data['alert_ids']
        status = data['status']
        notes = data.get('notes')
        
        # Validate alert_ids is a list
        if not isinstance(alert_ids, list):
            return jsonify({
                'status': 'error',
                'message': 'alert_ids must be a list'
            }), 400
        
        # Update each alert
        results = []
        for alert_id in alert_ids:
            success = alerts_manager.update_alert_status(alert_id, status, notes)
            results.append({
                'alert_id': alert_id,
                'success': success
            })
        
        # Count successful updates
        success_count = sum(1 for r in results if r['success'])
        
        return jsonify({
            'status': 'success',
            'message': f'Updated {success_count} of {len(alert_ids)} alerts',
            'data': results
        })
        
    except ValueError as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400
    except Exception as e:
        current_app.logger.error(f"Error in bulk update: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error'
        }), 500

# Export blueprint and manager for use in other modules
__all__ = ['AlertsManager', 'AlertSeverity', 'AlertStatus', 'AlertType', 'alerts_blueprint']