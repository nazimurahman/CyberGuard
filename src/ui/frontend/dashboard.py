# src/ui/frontend/dashboard.py
"""
CyberGuard Security Dashboard - Flask Frontend

Main dashboard interface providing:
- Real-time security monitoring
- Scan management and results
- Threat visualization
- System metrics
- Agent status monitoring

Features:
- Responsive Bootstrap 5 design
- Real-time updates via WebSocket
- Interactive charts with Plotly
- Role-based access control
- Export functionality
"""

from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for, current_app
from flask_login import login_required, current_user
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import plotly
import plotly.graph_objs as go
from plotly.subplots import make_subplots
from collections import defaultdict

# Create blueprint for dashboard routes
dashboard_blueprint = Blueprint('dashboard', __name__, url_prefix='/dashboard')


class DashboardApp:
    """Main dashboard application class responsible for managing dashboard data and visualizations"""
    
    def __init__(self, agent_orchestrator, security_scanner):
        """
        Initialize dashboard with system components
        
        Args:
            agent_orchestrator: AgentOrchestrator instance for agent management
            security_scanner: WebSecurityScanner instance for scan functionality
        """
        self.agent_orchestrator = agent_orchestrator
        self.security_scanner = security_scanner
        self.scan_history = []  # Store scan history in memory (in production, use database)
        
        # Dashboard configuration settings
        self.config = {
            'refresh_interval': 30,  # Auto-refresh interval in seconds
            'max_scans_display': 50,  # Maximum scans to display
            'charts_enabled': True,   # Enable/disable chart rendering
            'real_time_updates': True  # Enable real-time updates
        }
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """
        Get all data needed for dashboard display
        
        Returns:
            Dictionary containing all dashboard data including system status,
            recent scans, threat stats, agent status, charts, and alerts
        """
        data = {
            'system_status': self.get_system_status(),
            'recent_scans': self.get_recent_scans(),
            'threat_stats': self.get_threat_statistics(),
            'agent_status': self.get_agent_status(),
            'charts': self.get_chart_data() if self.config['charts_enabled'] else {},
            'alerts': self.get_recent_alerts(),
            'timestamp': datetime.now().isoformat()  # Current timestamp for cache busting
        }
        
        return data
    
    def get_system_status(self) -> Dict[str, Any]:
        """
        Get overall system health and status
        
        Returns:
            Dictionary with system health metrics, agent counts, and threat statistics
        """
        if self.agent_orchestrator:
            status = self.agent_orchestrator.get_system_status()
        else:
            status = {}
        
        # Extract metrics from system status
        metrics = status.get('metrics', {})
        total_analyses = metrics.get('total_analyses', 0)
        threats_detected = metrics.get('threats_detected', 0)
        
        # Calculate threat rate percentage
        if total_analyses > 0:
            threat_rate = (threats_detected / total_analyses) * 100
        else:
            threat_rate = 0
        
        # Determine system health based on threat rate
        if threat_rate > 20:
            system_health = 'critical'
            health_color = 'danger'
        elif threat_rate > 10:
            system_health = 'warning'
            health_color = 'warning'
        else:
            system_health = 'healthy'
            health_color = 'success'
        
        return {
            'health': system_health,
            'health_color': health_color,
            'total_analyses': total_analyses,
            'threats_detected': threats_detected,
            'threat_rate': f"{threat_rate:.1f}%",
            'active_agents': status.get('active_agents', 0),
            'uptime': '24h',  # Would be calculated from system startup time
            'timestamp': datetime.now().isoformat()
        }
    
    def get_recent_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get most recent scan results
        
        Args:
            limit: Maximum number of scans to return
            
        Returns:
            List of recent scan dictionaries, sorted by timestamp (newest first)
        """
        if not self.scan_history:
            return []
        
        # Sort scans by timestamp in descending order (newest first)
        sorted_scans = sorted(
            self.scan_history,
            key=lambda x: x.get('timestamp', ''),
            reverse=True
        )
        
        # Return limited number of scans
        return sorted_scans[:limit]
    
    def get_threat_statistics(self) -> Dict[str, Any]:
        """
        Aggregate threat statistics from all scans
        
        Returns:
            Dictionary with total scans, vulnerabilities found,
            counts by severity, and top threat types
        """
        if not self.scan_history:
            return {
                'total_scans': 0,
                'vulnerabilities_found': 0,
                'by_severity': {
                    'CRITICAL': 0,
                    'HIGH': 0,
                    'MEDIUM': 0,
                    'LOW': 0,
                    'INFORMATIONAL': 0
                },
                'top_threat_types': []
            }
        
        # Initialize counters
        total_vulnerabilities = 0
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFORMATIONAL': 0
        }
        
        threat_type_counts = {}
        
        # Aggregate statistics from all scans
        for scan in self.scan_history:
            report = scan.get('report', {})
            summary = report.get('summary', {})
            
            # Count total vulnerabilities
            vuln_count = summary.get('total_vulnerabilities', 0)
            total_vulnerabilities += vuln_count
            
            # Count vulnerabilities by severity
            by_severity = summary.get('by_severity', {})
            for severity, count in by_severity.items():
                if severity in severity_counts:
                    severity_counts[severity] += count
            
            # Count occurrences of each threat type
            vulnerabilities = report.get('vulnerabilities', [])
            for vuln in vulnerabilities:
                threat_type = vuln.get('type', 'Unknown')
                threat_type_counts[threat_type] = threat_type_counts.get(threat_type, 0) + 1
        
        # Get top 5 most common threat types
        top_threats = sorted(
            threat_type_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        return {
            'total_scans': len(self.scan_history),
            'vulnerabilities_found': total_vulnerabilities,
            'by_severity': severity_counts,
            'top_threat_types': top_threats
        }
    
    def get_agent_status(self) -> List[Dict[str, Any]]:
        """
        Get status information for all security agents
        
        Returns:
            List of agent status dictionaries
        """
        if not self.agent_orchestrator:
            return []
        
        status = self.agent_orchestrator.get_system_status()
        return status.get('agent_statuses', [])
    
    def get_chart_data(self) -> Dict[str, Any]:
        """
        Generate chart data for dashboard visualization
        
        Returns:
            Dictionary with Plotly chart JSON strings for different visualizations
        """
        charts = {}
        
        # 1. Threat severity distribution chart (bar chart)
        threat_stats = self.get_threat_statistics()
        severity_counts = threat_stats.get('by_severity', {})
        
        # Filter out zero values for cleaner visualization
        severity_data = {k: v for k, v in severity_counts.items() if v > 0}
        
        if severity_data:
            # Create bar chart for severity distribution
            severity_chart = go.Figure(data=[
                go.Bar(
                    x=list(severity_data.keys()),
                    y=list(severity_data.values()),
                    marker_color=['#dc3545', '#fd7e14', '#ffc107', '#20c997', '#0dcaf0'],  # Bootstrap color scheme
                    text=list(severity_data.values()),  # Display values on bars
                    textposition='auto'
                )
            ])
            
            # Configure chart layout
            severity_chart.update_layout(
                title='Threats by Severity',
                xaxis_title='Severity',
                yaxis_title='Count',
                height=300,
                margin=dict(l=20, r=20, t=40, b=20)
            )
            
            # Convert chart to JSON for frontend rendering
            charts['severity_chart'] = plotly.io.to_json(severity_chart)
        
        # 2. Scan timeline chart (last 7 days)
        if self.scan_history:
            # Group scans by date
            date_counts = defaultdict(int)
            
            for scan in self.scan_history:
                timestamp = scan.get('timestamp', '')
                if timestamp:
                    try:
                        # Extract date from ISO timestamp
                        scan_date = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        date_str = scan_date.strftime('%Y-%m-%d')
                        date_counts[date_str] += 1
                    except (ValueError, AttributeError):
                        # Skip invalid timestamps
                        continue
            
            # Create timeline for last 7 days
            dates = []
            counts = []
            
            for i in range(6, -1, -1):  # Last 7 days, oldest first
                date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
                dates.append(date)
                counts.append(date_counts.get(date, 0))
            
            # Create line chart for scan timeline
            timeline_chart = go.Figure(data=[
                go.Scatter(
                    x=dates,
                    y=counts,
                    mode='lines+markers',
                    line=dict(color='#0d6efd', width=3),
                    marker=dict(size=8)
                )
            ])
            
            timeline_chart.update_layout(
                title='Scans per Day (Last 7 Days)',
                xaxis_title='Date',
                yaxis_title='Scan Count',
                height=300,
                margin=dict(l=20, r=20, t=40, b=20)
            )
            
            charts['timeline_chart'] = plotly.io.to_json(timeline_chart)
        
        # 3. Agent confidence levels chart
        agent_status = self.get_agent_status()
        if agent_status:
            # Extract agent names and confidence levels
            agent_names = []
            agent_confidences = []
            
            for i, agent in enumerate(agent_status):
                agent_names.append(agent.get('name', f"Agent {i+1}"))
                # Convert confidence to percentage (0-100)
                confidence = agent.get('confidence', 0)
                agent_confidences.append(confidence * 100)
            
            # Create bar chart for agent confidence
            agent_chart = go.Figure(data=[
                go.Bar(
                    x=agent_names,
                    y=agent_confidences,
                    marker_color='#20c997',
                    text=[f"{c:.1f}%" for c in agent_confidences],
                    textposition='auto'
                )
            ])
            
            agent_chart.update_layout(
                title='Agent Confidence Levels',
                xaxis_title='Agent',
                yaxis_title='Confidence (%)',
                height=300,
                margin=dict(l=20, r=20, t=40, b=20),
                yaxis=dict(range=[0, 100])  # Fixed scale for percentage
            )
            
            charts['agent_chart'] = plotly.io.to_json(agent_chart)
        
        return charts
    
    def get_recent_alerts(self, limit: int = 5) -> List[Dict[str, Any]]:
        """
        Get recent security alerts from scan history
        
        Args:
            limit: Maximum number of alerts to return
            
        Returns:
            List of alert dictionaries sorted by timestamp (newest first)
        """
        alerts = []
        
        # Check last 10 scans for alert generation
        for scan in self.scan_history[-10:]:
            report = scan.get('report', {})
            metadata = report.get('metadata', {})
            
            risk_level = metadata.get('risk_level', 'LOW')
            threat_score = metadata.get('threat_score', 0)
            
            # Only create alerts for medium or higher risk levels
            if risk_level in ['MEDIUM', 'HIGH', 'CRITICAL']:
                alert = {
                    'id': report.get('scan_id', 'unknown'),
                    'type': 'scan_result',
                    'severity': risk_level.lower(),
                    'title': f'{risk_level} risk detected',
                    'message': f'Scan of {scan.get("url", "unknown")} found {report.get("summary", {}).get("total_vulnerabilities", 0)} vulnerabilities',
                    'timestamp': metadata.get('scan_date', ''),
                    'url': scan.get('url', ''),
                    'acknowledged': False
                }
                alerts.append(alert)
        
        # Sort alerts by timestamp (most recent first)
        alerts.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        return alerts[:limit]
    
    def add_scan_result(self, url: str, scan_results: Dict, analysis_results: Dict):
        """
        Add scan result to dashboard history
        
        Args:
            url: The URL that was scanned
            scan_results: Raw scan results from security scanner
            analysis_results: Analyzed results from agent orchestration
        """
        scan_data = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'scan_results': scan_results,
            'analysis_results': analysis_results,
            'report': self._generate_scan_report(scan_results, analysis_results)
        }
        
        # Add to history
        self.scan_history.append(scan_data)
        
        # Maintain history within configured limits
        if len(self.scan_history) > self.config['max_scans_display'] * 2:
            self.scan_history = self.scan_history[-self.config['max_scans_display']:]
    
    def _generate_scan_report(self, scan_results: Dict, analysis_results: Dict) -> Dict[str, Any]:
        """
        Generate dashboard-friendly scan report from raw results
        
        Args:
            scan_results: Raw scan results from security scanner
            analysis_results: Analyzed results from agent orchestration
            
        Returns:
            Formatted report dictionary for dashboard display
        """
        import hashlib
        
        # Generate unique scan ID using hash of timestamp and URL
        scan_id = hashlib.sha256(
            f"{datetime.now().isoformat()}{scan_results.get('url', '')}".encode()
        ).hexdigest()[:16]
        
        # Extract threat level from analysis
        final_decision = analysis_results.get('final_decision', {})
        threat_level = final_decision.get('threat_level', 0)
        
        # Determine risk level based on threat level
        if threat_level > 0.8:
            risk_level = "CRITICAL"
            risk_color = "danger"
        elif threat_level > 0.6:
            risk_level = "HIGH"
            risk_color = "warning"
        elif threat_level > 0.4:
            risk_level = "MEDIUM"
            risk_color = "info"
        elif threat_level > 0.2:
            risk_level = "LOW"
            risk_color = "primary"
        else:
            risk_level = "INFORMATIONAL"
            risk_color = "success"
        
        # Compile vulnerabilities from agent analyses
        vulnerabilities = []
        for agent_analysis in analysis_results.get('agent_analyses', []):
            for finding in agent_analysis.get('findings', []):
                vulnerabilities.append({
                    'type': finding.get('type', 'Unknown'),
                    'severity': finding.get('severity', 'UNKNOWN'),
                    'description': finding.get('description', ''),
                    'location': finding.get('location', ''),
                    'agent': agent_analysis.get('agent_name', 'Unknown')
                })
        
        # Count vulnerabilities by severity
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFORMATIONAL': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln['severity']
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Get security header analysis
        security_headers = scan_results.get('security_headers', {})
        missing_headers = [h for h in security_headers.values() if not h.get('present', True)]
        
        return {
            'scan_id': scan_id,
            'metadata': {
                'scan_date': datetime.now().isoformat(),
                'risk_level': risk_level,
                'risk_color': risk_color,
                'threat_score': float(threat_level),
                'confidence_score': final_decision.get('confidence', 0),
                'requires_human_review': final_decision.get('requires_human_review', False)
            },
            'summary': {
                'total_vulnerabilities': len(vulnerabilities),
                'by_severity': severity_counts,
                'security_headers': {
                    'total': len(security_headers),
                    'missing': len(missing_headers)
                }
            },
            'vulnerabilities': vulnerabilities[:20],  # Limit for dashboard display
            'recommendations': final_decision.get('mitigations', [])[:5],
            'agent_contributions': analysis_results.get('agent_contributions', [])
        }


# ============================================================================
# DASHBOARD ROUTES
# ============================================================================

@dashboard_blueprint.route('/')
@login_required
def dashboard_home():
    """Main dashboard landing page - displays overview with charts and stats"""
    dashboard = current_app.dashboard_app  # Get dashboard instance from Flask app
    
    # Get all dashboard data for rendering
    data = dashboard.get_dashboard_data()
    
    return render_template(
        'dashboard/index.html',
        title='CyberGuard Dashboard',
        data=data,
        config=dashboard.config
    )


@dashboard_blueprint.route('/scans')
@login_required
def scans_list():
    """Display paginated list of all historical scans"""
    dashboard = current_app.dashboard_app
    
    # Get pagination parameters from query string
    page = int(request.args.get('page', 1))
    per_page = 20
    
    scans = dashboard.scan_history
    
    # Calculate pagination details
    total_scans = len(scans)
    total_pages = (total_scans + per_page - 1) // per_page if total_scans > 0 else 1
    
    # Ensure page is within valid range
    page = max(1, min(page, total_pages))
    
    # Get scans for current page
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    page_scans = scans[start_idx:end_idx]
    
    return render_template(
        'dashboard/scans.html',
        title='Scan History',
        scans=page_scans,
        pagination={
            'page': page,
            'per_page': per_page,
            'total_pages': total_pages,
            'total_scans': total_scans
        }
    )


@dashboard_blueprint.route('/scan/<scan_id>')
@login_required
def scan_detail(scan_id):
    """Display detailed information for a specific scan"""
    dashboard = current_app.dashboard_app
    
    # Find scan by ID in history
    scan = None
    for s in dashboard.scan_history:
        if s.get('report', {}).get('scan_id') == scan_id:
            scan = s
            break
    
    # Return 404 if scan not found
    if not scan:
        return render_template('errors/404.html'), 404
    
    return render_template(
        'dashboard/scan_detail.html',
        title=f"Scan: {scan_id[:8]}...",  # Truncate ID for display
        scan=scan
    )


@dashboard_blueprint.route('/agents')
@login_required
def agents_status():
    """Display status and metrics for all security agents"""
    dashboard = current_app.dashboard_app
    
    agents = dashboard.get_agent_status()
    system_status = dashboard.get_system_status()
    
    return render_template(
        'dashboard/agents.html',
        title='Agent Status',
        agents=agents,
        system_status=system_status
    )


@dashboard_blueprint.route('/alerts')
@login_required
def alerts_list():
    """Display and manage security alerts"""
    dashboard = current_app.dashboard_app
    
    alerts = dashboard.get_recent_alerts(limit=50)
    
    return render_template(
        'dashboard/alerts.html',
        title='Security Alerts',
        alerts=alerts
    )


@dashboard_blueprint.route('/new-scan')
@login_required
def new_scan():
    """Display form for initiating a new security scan"""
    return render_template(
        'dashboard/new_scan.html',
        title='New Security Scan'
    )


# ============================================================================
# API ENDPOINTS
# ============================================================================

@dashboard_blueprint.route('/api/dashboard-data')
@login_required
def api_dashboard_data():
    """API endpoint for AJAX dashboard data updates"""
    dashboard = current_app.dashboard_app
    
    data = dashboard.get_dashboard_data()
    
    return jsonify({
        'status': 'success',
        'data': data
    })


@dashboard_blueprint.route('/api/scan', methods=['POST'])
@login_required
def api_start_scan():
    """API endpoint to initiate a new security scan"""
    try:
        # Parse JSON request data
        data = request.get_json()
        
        # Validate required parameters
        if not data or 'url' not in data:
            return jsonify({
                'status': 'error',
                'message': 'URL is required'
            }), 400
        
        url = data['url']
        options = data.get('options', {})
        
        # Validate URL format
        if not url.startswith(('http://', 'https://')):
            return jsonify({
                'status': 'error',
                'message': 'Invalid URL format. Must start with http:// or https://'
            }), 400
        
        # Get system components from Flask app context
        agent_orchestrator = current_app.agent_orchestrator
        security_scanner = current_app.security_scanner
        
        # Check system availability
        if not agent_orchestrator or not security_scanner:
            return jsonify({
                'status': 'error',
                'message': 'System components not available. Please try again later.'
            }), 503
        
        # Perform website security scan
        scan_results = security_scanner.scan_website(url)
        
        # Prepare input for agent analysis
        analysis_input = {
            'url': url,
            'scan_results': scan_results,
            'timestamp': datetime.now().isoformat()
        }
        
        # Coordinate analysis across all security agents
        analysis_results = agent_orchestrator.coordinate_analysis(analysis_input)
        
        # Add results to dashboard history
        dashboard = current_app.dashboard_app
        dashboard.add_scan_result(url, scan_results, analysis_results)
        
        # Get scan ID for response
        scan_id = dashboard.scan_history[-1]['report']['scan_id']
        
        return jsonify({
            'status': 'success',
            'message': 'Scan started successfully',
            'scan_id': scan_id,
            'redirect': url_for('dashboard.scan_detail', scan_id=scan_id)
        }), 202  # Accepted status code for async operations
        
    except Exception as e:
        # Log error and return error response
        current_app.logger.error(f"Scan error: {str(e)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': f'Scan failed: {str(e)}'
        }), 500


@dashboard_blueprint.route('/api/alert/<alert_id>/acknowledge', methods=['POST'])
@login_required
def api_acknowledge_alert(alert_id):
    """
    API endpoint to acknowledge a security alert
    
    Note: In production, this would update alert status in a database
    """
    # Implementation would update alert status in persistent storage
    # For now, return success response
    
    return jsonify({
        'status': 'success',
        'message': f'Alert {alert_id} acknowledged'
    })


# Export blueprint and class for use in other modules
__all__ = ['DashboardApp', 'dashboard_blueprint']