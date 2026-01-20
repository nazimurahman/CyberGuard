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

from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for
from flask_login import login_required, current_user
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import plotly
import plotly.graph_objs as go
from plotly.subplots import make_subplots

# Create blueprint for dashboard routes
dashboard_blueprint = Blueprint('dashboard', __name__, url_prefix='/dashboard')

class DashboardApp:
    """Main dashboard application"""
    
    def __init__(self, agent_orchestrator, security_scanner):
        """
        Initialize dashboard with system components
        
        Args:
            agent_orchestrator: AgentOrchestrator for agent status
            security_scanner: WebSecurityScanner for scan functionality
        """
        self.agent_orchestrator = agent_orchestrator
        self.security_scanner = security_scanner
        self.scan_history = []
        
        # Dashboard configuration
        self.config = {
            'refresh_interval': 30,  # seconds
            'max_scans_display': 50,
            'charts_enabled': True,
            'real_time_updates': True
        }
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get all data needed for dashboard display"""
        data = {
            'system_status': self.get_system_status(),
            'recent_scans': self.get_recent_scans(),
            'threat_stats': self.get_threat_statistics(),
            'agent_status': self.get_agent_status(),
            'charts': self.get_chart_data() if self.config['charts_enabled'] else {},
            'alerts': self.get_recent_alerts(),
            'timestamp': datetime.now().isoformat()
        }
        
        return data
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get overall system status"""
        if self.agent_orchestrator:
            status = self.agent_orchestrator.get_system_status()
        else:
            status = {}
        
        # Calculate system health
        total_analyses = status.get('metrics', {}).get('total_analyses', 0)
        threats_detected = status.get('metrics', {}).get('threats_detected', 0)
        
        if total_analyses > 0:
            threat_rate = (threats_detected / total_analyses) * 100
        else:
            threat_rate = 0
        
        # Determine health status
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
            'uptime': '24h',  # Would be calculated from startup time
            'timestamp': datetime.now().isoformat()
        }
    
    def get_recent_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent scan results"""
        if not self.scan_history:
            return []
        
        # Sort by timestamp (most recent first)
        sorted_scans = sorted(
            self.scan_history,
            key=lambda x: x.get('timestamp', ''),
            reverse=True
        )
        
        return sorted_scans[:limit]
    
    def get_threat_statistics(self) -> Dict[str, Any]:
        """Get threat statistics"""
        if not self.scan_history:
            return {
                'total_scans': 0,
                'vulnerabilities_found': 0,
                'by_severity': {},
                'top_threat_types': []
            }
        
        # Aggregate statistics from scan history
        total_vulnerabilities = 0
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFORMATIONAL': 0
        }
        
        threat_type_counts = {}
        
        for scan in self.scan_history:
            report = scan.get('report', {})
            summary = report.get('summary', {})
            
            # Count vulnerabilities
            vuln_count = summary.get('total_vulnerabilities', 0)
            total_vulnerabilities += vuln_count
            
            # Count by severity
            by_severity = summary.get('by_severity', {})
            for severity, count in by_severity.items():
                if severity in severity_counts:
                    severity_counts[severity] += count
            
            # Count threat types
            vulnerabilities = report.get('vulnerabilities', [])
            for vuln in vulnerabilities:
                threat_type = vuln.get('type', 'Unknown')
                threat_type_counts[threat_type] = threat_type_counts.get(threat_type, 0) + 1
        
        # Get top threat types
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
        """Get status of all security agents"""
        if not self.agent_orchestrator:
            return []
        
        status = self.agent_orchestrator.get_system_status()
        return status.get('agent_statuses', [])
    
    def get_chart_data(self) -> Dict[str, Any]:
        """Generate chart data for dashboard"""
        charts = {}
        
        # 1. Threat severity distribution chart
        threat_stats = self.get_threat_statistics()
        severity_counts = threat_stats.get('by_severity', {})
        
        # Remove zero values for cleaner chart
        severity_data = {k: v for k, v in severity_counts.items() if v > 0}
        
        if severity_data:
            severity_chart = go.Figure(data=[
                go.Bar(
                    x=list(severity_data.keys()),
                    y=list(severity_data.values()),
                    marker_color=['#dc3545', '#fd7e14', '#ffc107', '#20c997', '#0dcaf0'],  # Bootstrap colors
                    text=list(severity_data.values()),
                    textposition='auto'
                )
            ])
            
            severity_chart.update_layout(
                title='Threats by Severity',
                xaxis_title='Severity',
                yaxis_title='Count',
                height=300,
                margin=dict(l=20, r=20, t=40, b=20)
            )
            
            charts['severity_chart'] = plotly.io.to_json(severity_chart)
        
        # 2. Scan timeline (last 7 days)
        if self.scan_history:
            # Group scans by date
            from collections import defaultdict
            from datetime import datetime, timedelta
            
            date_counts = defaultdict(int)
            
            for scan in self.scan_history:
                timestamp = scan.get('timestamp', '')
                if timestamp:
                    try:
                        scan_date = datetime.fromisoformat(timestamp.split('T')[0])
                        date_str = scan_date.strftime('%Y-%m-%d')
                        date_counts[date_str] += 1
                    except:
                        pass
            
            # Create timeline for last 7 days
            dates = []
            counts = []
            
            for i in range(7):
                date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
                dates.insert(0, date)  # Oldest first
                counts.insert(0, date_counts.get(date, 0))
            
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
        
        # 3. Agent confidence levels
        agent_status = self.get_agent_status()
        if agent_status:
            agent_names = [agent.get('name', f"Agent {i}") for i, agent in enumerate(agent_status)]
            agent_confidences = [agent.get('confidence', 0) * 100 for agent in agent_status]
            
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
                yaxis=dict(range=[0, 100])
            )
            
            charts['agent_chart'] = plotly.io.to_json(agent_chart)
        
        return charts
    
    def get_recent_alerts(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Get recent security alerts"""
        # In production, this would query from a database
        # For now, generate sample alerts from scan history
        
        alerts = []
        
        for scan in self.scan_history[-10:]:  # Check last 10 scans
            report = scan.get('report', {})
            metadata = report.get('metadata', {})
            
            risk_level = metadata.get('risk_level', 'LOW')
            threat_score = metadata.get('threat_score', 0)
            
            # Only create alerts for medium or higher risk
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
        
        # Sort by timestamp (most recent first)
        alerts.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        return alerts[:limit]
    
    def add_scan_result(self, url: str, scan_results: Dict, analysis_results: Dict):
        """Add scan result to dashboard history"""
        scan_data = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'scan_results': scan_results,
            'analysis_results': analysis_results,
            'report': self._generate_scan_report(scan_results, analysis_results)
        }
        
        self.scan_history.append(scan_data)
        
        # Keep history within limit
        if len(self.scan_history) > self.config['max_scans_display'] * 2:  # Keep buffer
            self.scan_history = self.scan_history[-self.config['max_scans_display']:]
    
    def _generate_scan_report(self, scan_results: Dict, analysis_results: Dict) -> Dict[str, Any]:
        """Generate dashboard-friendly scan report"""
        from datetime import datetime
        
        # Generate scan ID
        import hashlib
        scan_id = hashlib.sha256(
            f"{datetime.now().isoformat()}{scan_results.get('url', '')}".encode()
        ).hexdigest()[:16]
        
        threat_level = analysis_results['final_decision']['threat_level']
        
        # Determine risk level
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
        
        # Compile vulnerabilities
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
        
        return {
            'scan_id': scan_id,
            'metadata': {
                'scan_date': datetime.now().isoformat(),
                'risk_level': risk_level,
                'risk_color': risk_color,
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
                    'total': len(scan_results.get('security_headers', {})),
                    'missing': len([h for h in scan_results.get('security_headers', {}).values() 
                                  if not h.get('present')])
                }
            },
            'vulnerabilities': vulnerabilities[:20],  # Limit for dashboard display
            'recommendations': analysis_results['final_decision'].get('mitigations', [])[:5],
            'agent_contributions': analysis_results.get('agent_contributions', [])
        }

# Dashboard routes
@dashboard_blueprint.route('/')
@login_required
def dashboard_home():
    """Main dashboard page"""
    dashboard = current_app.dashboard_app
    
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
    """List all scans"""
    dashboard = current_app.dashboard_app
    
    # Get pagination parameters
    page = int(request.args.get('page', 1))
    per_page = 20
    
    scans = dashboard.scan_history
    
    # Calculate pagination
    total_scans = len(scans)
    total_pages = (total_scans + per_page - 1) // per_page
    
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
    """Scan detail page"""
    dashboard = current_app.dashboard_app
    
    # Find scan by ID
    scan = None
    for s in dashboard.scan_history:
        if s.get('report', {}).get('scan_id') == scan_id:
            scan = s
            break
    
    if not scan:
        return render_template('errors/404.html'), 404
    
    return render_template(
        'dashboard/scan_detail.html',
        title=f"Scan: {scan_id[:8]}...",
        scan=scan
    )

@dashboard_blueprint.route('/agents')
@login_required
def agents_status():
    """Agent status page"""
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
    """Alerts management page"""
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
    """New scan form"""
    return render_template(
        'dashboard/new_scan.html',
        title='New Security Scan'
    )

@dashboard_blueprint.route('/api/dashboard-data')
@login_required
def api_dashboard_data():
    """API endpoint for dashboard data (AJAX)"""
    dashboard = current_app.dashboard_app
    
    data = dashboard.get_dashboard_data()
    
    return jsonify({
        'status': 'success',
        'data': data
    })

@dashboard_blueprint.route('/api/scan', methods=['POST'])
@login_required
def api_start_scan():
    """API endpoint to start a new scan"""
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'status': 'error',
                'message': 'URL is required'
            }), 400
        
        url = data['url']
        options = data.get('options', {})
        
        # Validate URL
        if not url.startswith(('http://', 'https://')):
            return jsonify({
                'status': 'error',
                'message': 'Invalid URL format'
            }), 400
        
        # Get system components from app context
        agent_orchestrator = current_app.agent_orchestrator
        security_scanner = current_app.security_scanner
        
        if not agent_orchestrator or not security_scanner:
            return jsonify({
                'status': 'error',
                'message': 'System components not available'
            }), 503
        
        # Perform scan
        scan_results = security_scanner.scan_website(url)
        
        # Analyze with agents
        analysis_input = {
            'url': url,
            'scan_results': scan_results,
            'timestamp': datetime.now().isoformat()
        }
        
        analysis_results = agent_orchestrator.coordinate_analysis(analysis_input)
        
        # Add to dashboard
        dashboard = current_app.dashboard_app
        dashboard.add_scan_result(url, scan_results, analysis_results)
        
        # Return scan ID
        scan_id = dashboard.scan_history[-1]['report']['scan_id']
        
        return jsonify({
            'status': 'success',
            'message': 'Scan started successfully',
            'scan_id': scan_id,
            'redirect': url_for('dashboard.scan_detail', scan_id=scan_id)
        }), 202
        
    except Exception as e:
        current_app.logger.error(f"Scan error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Scan failed: {str(e)}'
        }), 500

@dashboard_blueprint.route('/api/alert/<alert_id>/acknowledge', methods=['POST'])
@login_required
def api_acknowledge_alert(alert_id):
    """API endpoint to acknowledge an alert"""
    # In production, this would update alert status in database
    
    return jsonify({
        'status': 'success',
        'message': f'Alert {alert_id} acknowledged'
    })

# Export blueprint and class
__all__ = ['DashboardApp', 'dashboard_blueprint']