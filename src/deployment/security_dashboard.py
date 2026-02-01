"""
Security Dashboard for CyberGuard - Real-time security monitoring and management
Purpose: Provide comprehensive visualization, alerting, and management interface
Features: Real-time threat visualization, incident management, reporting, team collaboration
"""

import asyncio
import json
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple, Deque
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import logging
from collections import defaultdict, deque
import hashlib

# Third-party imports for dashboard functionality
STREAMLIT_AVAILABLE = False
PROMETHEUS_AVAILABLE = False

try:
    # Import streamlit and related visualization libraries
    import streamlit as st
    import plotly.graph_objects as go
    import plotly.express as px
    import pandas as pd
    import numpy as np
    from streamlit_autorefresh import st_autorefresh
    STREAMLIT_AVAILABLE = True
except ImportError:
    # Handle missing streamlit - dashboard UI will be disabled
    print("Warning: Streamlit not available - dashboard UI disabled")

try:
    # Import Prometheus for metrics collection
    from prometheus_client import CollectorRegistry, generate_latest
    PROMETHEUS_AVAILABLE = True
except ImportError:
    # Handle missing prometheus
    print("Warning: Prometheus not available - metrics collection disabled")

# Configure logging for the application
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)  # Create logger instance

# ============================================================================
# DATA MODELS - Define data structures for the security dashboard
# ============================================================================

class ThreatSeverity(Enum):
    """Enumeration of threat severity levels for classification"""
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatStatus(Enum):
    """Enumeration of threat incident status"""
    DETECTED = "DETECTED"
    INVESTIGATING = "INVESTIGATING"
    MITIGATED = "MITIGATED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class AlertPriority(Enum):
    """Enumeration of alert priority levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ThreatIncident:
    """
    Threat incident data model
    Represents a detected security threat with full context
    """
    # Unique identifier for the incident
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    # When the incident was detected
    timestamp: datetime = field(default_factory=datetime.now)
    # Type of threat (SQL Injection, XSS, etc.)
    threat_type: str = ""
    # Severity level of the threat
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    # Current status of the incident
    status: ThreatStatus = ThreatStatus.DETECTED
    # Source IP address of the threat
    source_ip: str = ""
    # Target URL that was attacked
    target_url: str = ""
    # Detailed description of the threat
    description: str = ""
    # Evidence data related to the threat
    evidence: Dict[str, Any] = field(default_factory=dict)
    # Confidence score (0.0 to 1.0)
    confidence: float = 0.0
    # List of affected systems
    affected_systems: List[str] = field(default_factory=list)
    # Steps taken to mitigate the threat
    mitigation_steps: List[str] = field(default_factory=list)
    # Person assigned to investigate
    assigned_to: str = ""
    # Timeline of notes/comments
    notes: List[Dict[str, str]] = field(default_factory=list)
    # Tags for categorization
    tags: Set[str] = field(default_factory=set)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert threat incident to dictionary for serialization"""
        data = asdict(self)  # Convert dataclass to dictionary
        # Convert datetime to ISO format string
        data['timestamp'] = self.timestamp.isoformat()
        # Convert enums to their string values
        data['severity'] = self.severity.value
        data['status'] = self.status.value
        # Convert set to list for JSON serialization
        data['tags'] = list(self.tags)
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ThreatIncident':
        """Create ThreatIncident object from dictionary data"""
        # Parse ISO format string back to datetime
        data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        # Convert string values back to enum instances
        data['severity'] = ThreatSeverity(data['severity'])
        data['status'] = ThreatStatus(data['status'])
        # Convert list back to set
        data['tags'] = set(data.get('tags', []))
        # Create and return new ThreatIncident instance
        return cls(**data)


@dataclass
class SecurityAlert:
    """
    Security alert for real-time notification
    """
    # Unique identifier for the alert
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    # When the alert was created
    timestamp: datetime = field(default_factory=datetime.now)
    # Title of the alert
    title: str = ""
    # Detailed message
    message: str = ""
    # Priority level of the alert
    priority: AlertPriority = AlertPriority.MEDIUM
    # Reference to related incident (optional)
    incident_id: Optional[str] = None
    # Whether the alert has been acknowledged
    acknowledged: bool = False
    # Who acknowledged the alert
    acknowledged_by: str = ""
    # When the alert was acknowledged
    acknowledged_at: Optional[datetime] = None
    # When the alert expires
    expires_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert security alert to dictionary"""
        data = asdict(self)  # Convert dataclass to dictionary
        # Convert datetime fields to ISO format strings
        data['timestamp'] = self.timestamp.isoformat()
        data['priority'] = self.priority.value
        if self.acknowledged_at:
            data['acknowledged_at'] = self.acknowledged_at.isoformat()
        if self.expires_at:
            data['expires_at'] = self.expires_at.isoformat()
        return data


@dataclass
class DashboardMetrics:
    """
    Dashboard metrics for real-time monitoring
    """
    # When these metrics were collected
    timestamp: datetime = field(default_factory=datetime.now)
    
    # Request-related metrics
    total_requests: int = 0
    blocked_requests: int = 0
    allowed_requests: int = 0
    request_rate_per_second: float = 0.0
    
    # Threat-related metrics
    total_threats: int = 0
    threats_by_severity: Dict[str, int] = field(default_factory=dict)
    threats_by_type: Dict[str, int] = field(default_factory=dict)
    top_source_ips: List[Tuple[str, int]] = field(default_factory=list)
    top_target_urls: List[Tuple[str, int]] = field(default_factory=list)
    
    # System performance metrics
    system_uptime: float = 0.0  # in seconds
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    active_connections: int = 0
    
    # Security agent metrics
    active_agents: int = 0
    agent_health_status: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary"""
        data = asdict(self)  # Convert dataclass to dictionary
        data['timestamp'] = self.timestamp.isoformat()
        # Calculate block rate as percentage
        data['block_rate'] = self.blocked_requests / max(self.total_requests, 1)
        return data


# ============================================================================
# DATA STORAGE - Persistent storage for security data
# ============================================================================

class SecurityDataStore:
    """
    Data store for security incidents, alerts, and metrics
    Provides persistence and query capabilities
    """
    
    def __init__(self, storage_path: str = "data/security_dashboard"):
        """
        Initialize data store with specified storage path
        
        Args:
            storage_path: Path to store data files
        """
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # In-memory stores with size limits
        self.incidents: Dict[str, ThreatIncident] = {}
        self.alerts: Dict[str, SecurityAlert] = {}
        self.metrics_history: Deque[DashboardMetrics] = deque(maxlen=10000)
        
        # Load existing data from storage
        self._load_data()
        
        # Background cleanup task (not implemented in this version)
        self._cleanup_task = None
    
    def _load_data(self):
        """Load data from JSON storage files"""
        try:
            # Load incidents from JSON file
            incidents_file = self.storage_path / "incidents.json"
            if incidents_file.exists():
                with open(incidents_file, 'r', encoding='utf-8') as f:
                    incidents_data = json.load(f)
                    for incident_data in incidents_data:
                        # Convert dict to ThreatIncident object
                        incident = ThreatIncident.from_dict(incident_data)
                        self.incidents[incident.id] = incident
            
            # Load alerts from JSON file
            alerts_file = self.storage_path / "alerts.json"
            if alerts_file.exists():
                with open(alerts_file, 'r', encoding='utf-8') as f:
                    alerts_data = json.load(f)
                    for alert_data in alerts_data:
                        # Convert dict to SecurityAlert object
                        alert = SecurityAlert()
                        for key, value in alert_data.items():
                            if hasattr(alert, key):
                                if key == 'timestamp':
                                    value = datetime.fromisoformat(value)
                                elif key == 'priority':
                                    value = AlertPriority(value)
                                elif key == 'acknowledged_at' and value:
                                    value = datetime.fromisoformat(value)
                                elif key == 'expires_at' and value:
                                    value = datetime.fromisoformat(value)
                                setattr(alert, key, value)
                        self.alerts[alert.id] = alert
            
            logger.info(f"Loaded {len(self.incidents)} incidents and {len(self.alerts)} alerts")
        except Exception as e:
            logger.error(f"Error loading data: {e}")
    
    def _save_data(self):
        """Save data to JSON storage files"""
        try:
            # Save incidents to JSON
            incidents_file = self.storage_path / "incidents.json"
            incidents_data = [incident.to_dict() for incident in self.incidents.values()]
            with open(incidents_file, 'w', encoding='utf-8') as f:
                json.dump(incidents_data, f, indent=2, default=str)
            
            # Save alerts to JSON
            alerts_file = self.storage_path / "alerts.json"
            alerts_data = [alert.to_dict() for alert in self.alerts.values()]
            with open(alerts_file, 'w', encoding='utf-8') as f:
                json.dump(alerts_data, f, indent=2, default=str)
            
        except Exception as e:
            logger.error(f"Error saving data: {e}")
    
    def add_incident(self, incident: ThreatIncident) -> str:
        """
        Add a new threat incident to the data store
        
        Args:
            incident: ThreatIncident object to add
            
        Returns:
            Incident ID
        """
        # Store incident in memory
        self.incidents[incident.id] = incident
        
        # Persist to disk
        self._save_data()
        
        # Create alert for high severity incidents
        if incident.severity in [ThreatSeverity.HIGH, ThreatSeverity.CRITICAL]:
            self.create_alert(
                title=f"{incident.severity.value} Threat Detected",
                message=f"{incident.threat_type} from {incident.source_ip}",
                priority=AlertPriority.CRITICAL if incident.severity == ThreatSeverity.CRITICAL else AlertPriority.HIGH,
                incident_id=incident.id
            )
        
        return incident.id
    
    def update_incident(self, incident_id: str, updates: Dict[str, Any]) -> bool:
        """
        Update an existing incident
        
        Args:
            incident_id: ID of incident to update
            updates: Dictionary of field updates
            
        Returns:
            True if successful, False if incident not found
        """
        if incident_id not in self.incidents:
            return False
        
        incident = self.incidents[incident_id]
        
        # Apply updates to incident fields
        for key, value in updates.items():
            if hasattr(incident, key):
                # Handle enum conversions
                if key == 'severity' and isinstance(value, str):
                    value = ThreatSeverity(value)
                elif key == 'status' and isinstance(value, str):
                    value = ThreatStatus(value)
                elif key == 'tags' and isinstance(value, list):
                    value = set(value)
                
                # Update the field
                setattr(incident, key, value)
        
        # Persist changes
        self._save_data()
        
        return True
    
    def add_note_to_incident(self, incident_id: str, user: str, note: str) -> bool:
        """
        Add a note to an incident
        
        Args:
            incident_id: Incident ID
            user: User adding the note
            note: Note content
            
        Returns:
            True if successful
        """
        if incident_id not in self.incidents:
            return False
        
        incident = self.incidents[incident_id]
        # Add note with timestamp
        incident.notes.append({
            'timestamp': datetime.now().isoformat(),
            'user': user,
            'note': note
        })
        
        # Persist changes
        self._save_data()
        
        return True
    
    def create_alert(self, 
                    title: str, 
                    message: str, 
                    priority: AlertPriority = AlertPriority.MEDIUM,
                    incident_id: Optional[str] = None,
                    ttl_hours: int = 24) -> str:
        """
        Create a new security alert
        
        Args:
            title: Alert title
            message: Alert message
            priority: Alert priority level
            incident_id: Associated incident ID (optional)
            ttl_hours: Time to live in hours
            
        Returns:
            Alert ID
        """
        # Create alert with expiration time
        alert = SecurityAlert(
            title=title,
            message=message,
            priority=priority,
            incident_id=incident_id,
            expires_at=datetime.now() + timedelta(hours=ttl_hours)
        )
        
        # Store alert
        self.alerts[alert.id] = alert
        
        # Persist to disk
        self._save_data()
        
        return alert.id
    
    def acknowledge_alert(self, alert_id: str, user: str) -> bool:
        """
        Acknowledge an alert
        
        Args:
            alert_id: Alert ID to acknowledge
            user: User acknowledging the alert
            
        Returns:
            True if successful
        """
        if alert_id not in self.alerts:
            return False
        
        alert = self.alerts[alert_id]
        alert.acknowledged = True
        alert.acknowledged_by = user
        alert.acknowledged_at = datetime.now()
        
        # Persist changes
        self._save_data()
        
        return True
    
    def add_metrics(self, metrics: DashboardMetrics):
        """
        Add metrics to history
        
        Args:
            metrics: DashboardMetrics object to add
        """
        self.metrics_history.append(metrics)
    
    def get_incidents(self, 
                     filters: Optional[Dict[str, Any]] = None,
                     limit: int = 100,
                     offset: int = 0) -> List[ThreatIncident]:
        """
        Get incidents with optional filtering
        
        Args:
            filters: Dictionary of filter criteria
            limit: Maximum number of incidents to return
            offset: Offset for pagination
            
        Returns:
            List of filtered incidents
        """
        incidents = list(self.incidents.values())
        
        # Apply filters if specified
        if filters:
            filtered_incidents = []
            for incident in incidents:
                matches = True
                
                # Check each filter criterion
                for key, value in filters.items():
                    if key == 'severity':
                        if incident.severity.value != value:
                            matches = False
                            break
                    elif key == 'status':
                        if incident.status.value != value:
                            matches = False
                            break
                    elif key == 'source_ip':
                        if value not in incident.source_ip:
                            matches = False
                            break
                    elif key == 'threat_type':
                        if value not in incident.threat_type:
                            matches = False
                            break
                    elif key == 'date_from':
                        # Convert string to datetime if needed
                        date_from = datetime.fromisoformat(value) if isinstance(value, str) else value
                        if incident.timestamp < date_from:
                            matches = False
                            break
                    elif key == 'date_to':
                        # Convert string to datetime if needed
                        date_to = datetime.fromisoformat(value) if isinstance(value, str) else value
                        if incident.timestamp > date_to:
                            matches = False
                            break
                    elif hasattr(incident, key):
                        # Compare attribute value
                        if getattr(incident, key) != value:
                            matches = False
                            break
                
                # Add incident if all filters match
                if matches:
                    filtered_incidents.append(incident)
            
            incidents = filtered_incidents
        
        # Sort by timestamp (newest first)
        incidents.sort(key=lambda x: x.timestamp, reverse=True)
        
        # Apply pagination
        return incidents[offset:offset + limit]
    
    def get_active_alerts(self, 
                         priority: Optional[AlertPriority] = None,
                         unacknowledged_only: bool = True) -> List[SecurityAlert]:
        """
        Get active alerts
        
        Args:
            priority: Filter by priority (optional)
            unacknowledged_only: Only return unacknowledged alerts
            
        Returns:
            List of alerts
        """
        now = datetime.now()
        alerts = []
        
        for alert in self.alerts.values():
            # Skip expired alerts
            if alert.expires_at and alert.expires_at < now:
                continue
            
            # Apply filters
            if unacknowledged_only and alert.acknowledged:
                continue
            
            if priority and alert.priority != priority:
                continue
            
            alerts.append(alert)
        
        # Sort by priority (critical first) and timestamp (newest first)
        priority_order = {AlertPriority.CRITICAL: 0, AlertPriority.HIGH: 1, 
                         AlertPriority.MEDIUM: 2, AlertPriority.LOW: 3}
        alerts.sort(key=lambda x: (priority_order[x.priority], x.timestamp), reverse=True)
        
        return alerts
    
    def get_metrics_timeseries(self, 
                              metric_name: str,
                              time_window_hours: int = 24) -> List[Tuple[datetime, Any]]:
        """
        Get time series data for a specific metric
        
        Args:
            metric_name: Name of metric to retrieve
            time_window_hours: Time window in hours
            
        Returns:
            List of (timestamp, value) pairs
        """
        # Calculate cutoff time
        cutoff = datetime.now() - timedelta(hours=time_window_hours)
        timeseries = []
        
        # Collect metrics within time window
        for metrics in self.metrics_history:
            if metrics.timestamp >= cutoff:
                if hasattr(metrics, metric_name):
                    value = getattr(metrics, metric_name)
                    timeseries.append((metrics.timestamp, value))
        
        return timeseries
    
    def get_statistics(self, time_window_hours: int = 24) -> Dict[str, Any]:
        """
        Get statistics for the specified time window
        
        Args:
            time_window_hours: Time window in hours
            
        Returns:
            Dictionary of statistics
        """
        # Calculate cutoff time
        cutoff = datetime.now() - timedelta(hours=time_window_hours)
        
        # Filter incidents within time window
        recent_incidents = [
            incident for incident in self.incidents.values()
            if incident.timestamp >= cutoff
        ]
        
        # Calculate basic statistics
        total_incidents = len(recent_incidents)
        
        # Count incidents by severity
        severity_counts = defaultdict(int)
        for incident in recent_incidents:
            severity_counts[incident.severity.value] += 1
        
        # Count incidents by type
        type_counts = defaultdict(int)
        for incident in recent_incidents:
            type_counts[incident.threat_type] += 1
        
        # Calculate resolution rate
        resolved_incidents = [
            incident for incident in recent_incidents
            if incident.status in [ThreatStatus.RESOLVED, ThreatStatus.MITIGATED, ThreatStatus.FALSE_POSITIVE]
        ]
        resolution_rate = len(resolved_incidents) / max(total_incidents, 1)
        
        # Calculate average time to resolution
        resolution_times = []
        for incident in resolved_incidents:
            if incident.notes:
                # Find when status changed to resolved
                for note in incident.notes:
                    note_text = note.get('note', '').lower()
                    if 'resolved' in note_text or 'mitigated' in note_text:
                        try:
                            resolution_time = datetime.fromisoformat(note['timestamp'])
                            time_to_resolve = (resolution_time - incident.timestamp).total_seconds() / 3600  # hours
                            resolution_times.append(time_to_resolve)
                        except (ValueError, KeyError):
                            pass
        
        avg_time_to_resolution = sum(resolution_times) / max(len(resolution_times), 1) if resolution_times else 0
        
        # Compile statistics
        return {
            'time_window_hours': time_window_hours,
            'total_incidents': total_incidents,
            'severity_distribution': dict(severity_counts),
            'type_distribution': dict(type_counts),
            'resolution_rate': resolution_rate,
            'avg_time_to_resolution_hours': avg_time_to_resolution,
            'top_source_ips': self._get_top_items(recent_incidents, 'source_ip', 5),
            'top_target_urls': self._get_top_items(recent_incidents, 'target_url', 5),
        }
    
    def _get_top_items(self, incidents: List[ThreatIncident], 
                      attribute: str, top_n: int) -> List[Tuple[str, int]]:
        """Get top N items by count for a given attribute"""
        counter = defaultdict(int)
        for incident in incidents:
            value = getattr(incident, attribute, '')
            if value:
                counter[value] += 1
        
        # Sort by count descending and return top N
        return sorted(counter.items(), key=lambda x: x[1], reverse=True)[:top_n]
    
    def run_cleanup(self):
        """Clean up expired data"""
        now = datetime.now()
        
        # Identify expired alerts
        expired_alert_ids = [
            alert_id for alert_id, alert in self.alerts.items()
            if alert.expires_at and alert.expires_at < now
        ]
        
        # Remove expired alerts
        for alert_id in expired_alert_ids:
            del self.alerts[alert_id]
        
        # Log and save if any alerts were removed
        if expired_alert_ids:
            logger.info(f"Cleaned up {len(expired_alert_ids)} expired alerts")
            self._save_data()


# ============================================================================
# DASHBOARD VISUALIZATION COMPONENTS
# ============================================================================

class DashboardVisualizations:
    """
    Visualization components for the security dashboard
    Creates charts, graphs, and visual representations of security data
    """
    
    @staticmethod
    def create_threat_timeline(incidents: List[ThreatIncident], 
                              time_window_hours: int = 24) -> go.Figure:
        """
        Create a timeline visualization of threats
        
        Args:
            incidents: List of threat incidents
            time_window_hours: Time window to display
            
        Returns:
            Plotly figure object
        """
        # Prepare data for visualization
        data = []
        for incident in incidents:
            data.append({
                'timestamp': incident.timestamp,
                'threat_type': incident.threat_type,
                'severity': incident.severity.value,
                'source_ip': incident.source_ip,
                'description': incident.description[:50] + '...' if len(incident.description) > 50 else incident.description
            })
        
        # Handle case with no data
        if not data:
            fig = go.Figure()  # Create empty figure
            fig.update_layout(
                title="No Threats Detected",
                xaxis_title="Time",
                yaxis_title="Threat Severity",
                height=400
            )
            return fig
        
        # Create DataFrame from data
        df = pd.DataFrame(data)
        
        # Color mapping for threat severity levels
        severity_colors = {
            'CRITICAL': '#ff0000',  # Red
            'HIGH': '#ff6600',      # Orange
            'MEDIUM': '#ffcc00',    # Yellow
            'LOW': '#00cc00',       # Green
            'INFORMATIONAL': '#0066cc'  # Blue
        }
        
        # Create scatter plot with Plotly Express
        fig = px.scatter(
            df,
            x='timestamp',
            y='severity',
            color='severity',
            color_discrete_map=severity_colors,
            hover_data=['threat_type', 'source_ip', 'description'],
            title=f'Threat Timeline (Last {time_window_hours} hours)',
            labels={'timestamp': 'Time', 'severity': 'Severity'}
        )
        
        # Customize layout
        fig.update_layout(
            height=500,
            xaxis_title="Time",
            yaxis_title="Threat Severity",
            hovermode='closest',
            showlegend=True
        )
        
        # Customize marker appearance
        fig.update_traces(
            marker=dict(size=12, line=dict(width=2, color='DarkSlateGrey')),
            selector=dict(mode='markers')
        )
        
        return fig
    
    @staticmethod
    def create_severity_distribution_chart(severity_counts: Dict[str, int]) -> go.Figure:
        """
        Create a pie chart for threat severity distribution
        
        Args:
            severity_counts: Dictionary of severity counts
            
        Returns:
            Plotly figure object
        """
        # Handle case with no data
        if not severity_counts:
            fig = go.Figure()  # Create empty figure
            fig.update_layout(
                title="No Threat Data",
                height=400
            )
            return fig
        
        # Prepare data for pie chart
        labels = list(severity_counts.keys())
        values = list(severity_counts.values())
        
        # Color mapping for consistency
        color_map = {
            'CRITICAL': '#ff0000',
            'HIGH': '#ff6600',
            'MEDIUM': '#ffcc00',
            'LOW': '#00cc00',
            'INFORMATIONAL': '#0066cc'
        }
        
        # Get colors for each label
        colors = [color_map.get(label, '#999999') for label in labels]
        
        # Create pie chart
        fig = go.Figure(data=[go.Pie(
            labels=labels,
            values=values,
            hole=.3,  # Donut chart style
            marker=dict(colors=colors),
            textinfo='label+percent',
            hoverinfo='label+value+percent'
        )])
        
        # Customize layout
        fig.update_layout(
            title="Threat Severity Distribution",
            height=500,
            showlegend=True
        )
        
        return fig
    
    @staticmethod
    def create_metrics_timeseries(metrics_data: List[Tuple[datetime, Any]], 
                                 title: str, 
                                 yaxis_title: str) -> go.Figure:
        """
        Create a time series chart for metrics
        
        Args:
            metrics_data: List of (timestamp, value) pairs
            title: Chart title
            yaxis_title: Y-axis title
            
        Returns:
            Plotly figure object
        """
        # Handle case with no data
        if not metrics_data:
            fig = go.Figure()  # Create empty figure
            fig.update_layout(
                title=f"No Data for {title}",
                height=300
            )
            return fig
        
        # Extract timestamps and values
        timestamps = [ts for ts, _ in metrics_data]
        values = [val for _, val in metrics_data]
        
        # Create line chart
        fig = go.Figure()
        
        # Add primary data trace
        fig.add_trace(go.Scatter(
            x=timestamps,
            y=values,
            mode='lines+markers',
            name=yaxis_title,
            line=dict(color='#0066cc', width=2),
            marker=dict(size=6, color='#0066cc')
        ))
        
        # Add moving average if enough data points
        if len(values) >= 7:
            moving_avg = pd.Series(values).rolling(window=7, min_periods=1).mean().tolist()
            fig.add_trace(go.Scatter(
                x=timestamps,
                y=moving_avg,
                mode='lines',
                name='7-Point Moving Average',
                line=dict(color='#ff6600', width=2, dash='dash')
            ))
        
        # Customize layout
        fig.update_layout(
            title=title,
            xaxis_title="Time",
            yaxis_title=yaxis_title,
            height=400,
            hovermode='x unified',
            showlegend=True
        )
        
        return fig
    
    @staticmethod
    def create_heatmap(incidents: List[ThreatIncident]) -> go.Figure:
        """
        Create a heatmap of threat activity by hour and day
        
        Args:
            incidents: List of threat incidents
            
        Returns:
            Plotly figure object
        """
        # Handle case with no data
        if not incidents:
            fig = go.Figure()  # Create empty figure
            fig.update_layout(
                title="No Threat Activity",
                height=400
            )
            return fig
        
        # Prepare labels for heatmap axes
        days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        hours = list(range(24))
        
        # Initialize heatmap data matrix
        heatmap_data = np.zeros((len(days), len(hours)))
        
        # Count incidents by day and hour with severity weighting
        for incident in incidents:
            day_idx = incident.timestamp.weekday()  # Monday=0, Sunday=6
            hour_idx = incident.timestamp.hour
            
            # Weight by severity for visual impact
            severity_weights = {
                'CRITICAL': 4,
                'HIGH': 3,
                'MEDIUM': 2,
                'LOW': 1,
                'INFORMATIONAL': 0.5
            }
            
            weight = severity_weights.get(incident.severity.value, 1)
            heatmap_data[day_idx, hour_idx] += weight
        
        # Create heatmap visualization
        fig = go.Figure(data=go.Heatmap(
            z=heatmap_data,
            x=hours,
            y=days,
            colorscale='RdYlGn_r',  # Red-Yellow-Green reversed
            hoverongaps=False,
            colorbar=dict(title="Threat Activity")
        ))
        
        # Customize layout
        fig.update_layout(
            title="Threat Activity Heatmap (Last 7 Days)",
            xaxis_title="Hour of Day",
            yaxis_title="Day of Week",
            height=500
        )
        
        return fig


# ============================================================================
# MAIN DASHBOARD CLASS
# ============================================================================

class SecurityDashboard:
    """
    Main security dashboard class
    Integrates data storage, visualizations, and web interface
    """
    
    def __init__(self, 
                 data_store: SecurityDataStore,
                 refresh_interval: int = 30):
        """
        Initialize security dashboard
        
        Args:
            data_store: SecurityDataStore instance
            refresh_interval: Auto-refresh interval in seconds
        """
        self.data_store = data_store
        self.refresh_interval = refresh_interval
        
        # Visualization component
        self.visualizations = DashboardVisualizations()
        
        # Dashboard state
        self.last_refresh = datetime.now()
        self.is_running = False
        
        # User management (simplified - for demonstration only)
        # In production, use proper authentication system
        self.users = {
            'admin': {
                'password_hash': hashlib.sha256('admin123'.encode()).hexdigest(),
                'role': 'admin',
                'name': 'Administrator'
            },
            'analyst': {
                'password_hash': hashlib.sha256('analyst123'.encode()).hexdigest(),
                'role': 'analyst',
                'name': 'Security Analyst'
            }
        }
        
        # Current user session
        self.current_user: Optional[Dict[str, str]] = None
        
        logger.info("Security Dashboard initialized")
    
    def start(self, port: int = 8080, host: str = "0.0.0.0"):
        """
        Start the dashboard web server
        
        Args:
            port: Port to listen on
            host: Host to bind to
        """
        # Check if Streamlit is available
        if not STREAMLIT_AVAILABLE:
            logger.error("Streamlit not available. Cannot start dashboard.")
            return
        
        self.is_running = True
        
        # Set Streamlit page configuration
        st.set_page_config(
            page_title="CyberGuard Security Dashboard",
            page_icon="shield",  # Using text instead of emoji
            layout="wide",
            initial_sidebar_state="expanded"
        )
        
        # Run the Streamlit app
        self._run_streamlit_app()
    
    def _run_streamlit_app(self):
        """Main Streamlit application logic"""
        
        # Custom CSS for dashboard styling
        st.markdown("""
        <style>
        .main-header {
            font-size: 2.5rem;
            color: #0066cc;
            text-align: center;
            margin-bottom: 1rem;
        }
        .sub-header {
            font-size: 1.5rem;
            color: #333333;
            margin-top: 1rem;
            margin-bottom: 0.5rem;
        }
        .metric-card {
            background-color: #f0f2f6;
            padding: 1rem;
            border-radius: 0.5rem;
            margin-bottom: 1rem;
        }
        .alert-critical {
            background-color: #ffcccc;
            padding: 1rem;
            border-radius: 0.5rem;
            border-left: 5px solid #ff0000;
            margin-bottom: 1rem;
        }
        .alert-high {
            background-color: #ffe6cc;
            padding: 1rem;
            border-radius: 0.5rem;
            border-left: 5px solid #ff6600;
            margin-bottom: 1rem;
        }
        .threat-card {
            background-color: #ffffff;
            padding: 1rem;
            border-radius: 0.5rem;
            border: 1px solid #e0e0e0;
            margin-bottom: 1rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        </style>
        """, unsafe_allow_html=True)
        
        # Sidebar for navigation and filters
        with st.sidebar:
            st.markdown("<h2 style='text-align: center;'>CyberGuard</h2>", unsafe_allow_html=True)
            st.markdown("---")  # Horizontal line
            
            # Authentication section
            if not self.current_user:
                self._render_login_form()
            else:
                self._render_sidebar_content()
        
        # Main content area (only shown when logged in)
        if self.current_user:
            self._render_main_content()
        else:
            # Show login prompt in main area
            st.markdown("<h1 class='main-header'>CyberGuard Security Dashboard</h1>", unsafe_allow_html=True)
            st.info("Please login from the sidebar to access the dashboard.")
    
    def _render_login_form(self):
        """Render login form in sidebar"""
        st.subheader("Login")
        
        # Login form fields
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        
        # Login button
        if st.button("Login", type="primary"):
            if self._authenticate_user(username, password):
                st.success(f"Welcome, {self.current_user['name']}!")
                st.rerun()  # Refresh the page
            else:
                st.error("Invalid username or password")
        
        st.markdown("---")
        # Demo credentials (for testing only)
        st.markdown("**Demo Credentials:**")
        st.markdown("- **Admin:** admin / admin123")
        st.markdown("- **Analyst:** analyst / analyst123")
    
    def _authenticate_user(self, username: str, password: str) -> bool:
        """
        Authenticate user with username and password
        
        Args:
            username: Username to authenticate
            password: Password to verify
            
        Returns:
            True if authentication successful
        """
        # Check if user exists
        if username in self.users:
            user_data = self.users[username]
            # Hash provided password for comparison
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            # Compare hashed passwords
            if user_data['password_hash'] == password_hash:
                # Set current user session
                self.current_user = {
                    'username': username,
                    'role': user_data['role'],
                    'name': user_data['name']
                }
                return True
        
        return False
    
    def _render_sidebar_content(self):
        """Render sidebar content after login"""
        # Display welcome message
        st.markdown(f"**Welcome, {self.current_user['name']}**")
        
        # Logout button
        if st.button("Logout"):
            self.current_user = None
            st.rerun()  # Refresh the page
        
        st.markdown("---")
        
        # Time filter for data
        st.subheader("Time Filter")
        time_filter = st.selectbox(
            "View data from:",
            ["Last 1 hour", "Last 6 hours", "Last 24 hours", "Last 7 days", "Last 30 days", "All time"]
        )
        
        # Map selection to hours
        time_map = {
            "Last 1 hour": 1,
            "Last 6 hours": 6,
            "Last 24 hours": 24,
            "Last 7 days": 168,
            "Last 30 days": 720,
            "All time": 8760  # Approximately 1 year
        }
        self.time_window_hours = time_map.get(time_filter, 24)
        
        st.markdown("---")
        
        # Severity filter for threats
        st.subheader("Severity Filter")
        severity_filter = st.multiselect(
            "Filter by severity:",
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"],
            default=["CRITICAL", "HIGH", "MEDIUM"]
        )
        self.severity_filter = severity_filter
        
        st.markdown("---")
        
        # Quick action buttons
        st.subheader("Quick Actions")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("Refresh"):
                st.rerun()
        
        with col2:
            if st.button("Export"):
                self._export_data()
        
        # New incident button
        if st.button("New Incident"):
            self._create_new_incident_modal()
        
        # Auto-refresh toggle
        auto_refresh = st.checkbox("Auto-refresh", value=True)
        if auto_refresh and STREAMLIT_AVAILABLE:
            # Use auto-refresh component if available
            try:
                st_autorefresh(interval=self.refresh_interval * 1000, key="dashboard_refresh")
            except:
                pass  # Silently fail if auto-refresh not available
    
    def _render_main_content(self):
        """Render main dashboard content"""
        
        # Header
        st.markdown("<h1 class='main-header'>CyberGuard Security Dashboard</h1>", unsafe_allow_html=True)
        
        # Get incidents with current filters
        incidents = self.data_store.get_incidents(limit=1000)
        
        # Apply time filter
        cutoff = datetime.now() - timedelta(hours=self.time_window_hours)
        filtered_incidents = [inc for inc in incidents if inc.timestamp >= cutoff]
        
        # Apply severity filter
        if self.severity_filter:
            filtered_incidents = [inc for inc in filtered_incidents 
                                 if inc.severity.value in self.severity_filter]
        
        # Get statistics for the filtered data
        stats = self.data_store.get_statistics(time_window_hours=self.time_window_hours)
        
        # Render dashboard sections
        self._render_key_metrics(stats, len(filtered_incidents))
        self._render_charts(filtered_incidents, stats)
        self._render_active_alerts()
        self._render_recent_incidents(filtered_incidents)
        self._render_system_status()
    
    def _render_key_metrics(self, stats: Dict[str, Any], total_incidents: int):
        """Render key metrics cards at the top of the dashboard"""
        st.markdown("<h2 class='sub-header'>Key Metrics</h2>", unsafe_allow_html=True)
        
        # Create 4 columns for metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            # Total threats metric
            st.metric(
                label="Total Threats",
                value=total_incidents,
                delta=f"{stats.get('total_incidents', 0)} in window"
            )
        
        with col2:
            # Critical threats metric
            critical_count = stats.get('severity_distribution', {}).get('CRITICAL', 0)
            st.metric(
                label="Critical Threats",
                value=critical_count,
                delta_color="inverse"  # Red for negative/bad
            )
        
        with col3:
            # Resolution rate metric
            resolution_rate = stats.get('resolution_rate', 0) * 100
            st.metric(
                label="Resolution Rate",
                value=f"{resolution_rate:.1f}%",
                delta=f"{stats.get('avg_time_to_resolution_hours', 0):.1f}h avg"
            )
        
        with col4:
            # Active alerts metric
            active_alerts = len(self.data_store.get_active_alerts(unacknowledged_only=True))
            st.metric(
                label="Active Alerts",
                value=active_alerts,
                delta_color="inverse"  # Red for negative/bad
            )
    
    def _render_charts(self, incidents: List[ThreatIncident], stats: Dict[str, Any]):
        """Render visualization charts"""
        st.markdown("<h2 class='sub-header'>Threat Analytics</h2>", unsafe_allow_html=True)
        
        # First row of charts
        col1, col2 = st.columns(2)
        
        with col1:
            # Threat timeline chart
            fig_timeline = self.visualizations.create_threat_timeline(
                incidents, 
                time_window_hours=self.time_window_hours
            )
            st.plotly_chart(fig_timeline, use_container_width=True)
        
        with col2:
            # Severity distribution chart
            fig_distribution = self.visualizations.create_severity_distribution_chart(
                stats.get('severity_distribution', {})
            )
            st.plotly_chart(fig_distribution, use_container_width=True)
        
        # Second row of charts
        col3, col4 = st.columns(2)
        
        with col3:
            # Threat activity heatmap
            fig_heatmap = self.visualizations.create_heatmap(incidents)
            st.plotly_chart(fig_heatmap, use_container_width=True)
        
        with col4:
            # Request rate timeseries
            metrics_data = self.data_store.get_metrics_timeseries(
                'request_rate_per_second',
                time_window_hours=self.time_window_hours
            )
            fig_metrics = self.visualizations.create_metrics_timeseries(
                metrics_data,
                "Request Rate Over Time",
                "Requests/Second"
            )
            st.plotly_chart(fig_metrics, use_container_width=True)
    
    def _render_active_alerts(self):
        """Render active alerts section"""
        st.markdown("<h2 class='sub-header'>Active Alerts</h2>", unsafe_allow_html=True)
        
        # Get unacknowledged alerts
        alerts = self.data_store.get_active_alerts(unacknowledged_only=True)
        
        if not alerts:
            st.info("No active alerts at this time.")
            return
        
        # Display top 5 alerts
        for alert in alerts[:5]:
            # Determine CSS class based on priority
            if alert.priority == AlertPriority.CRITICAL:
                alert_class = "alert-critical"
            else:
                alert_class = "alert-high"
            
            # Render alert card
            st.markdown(f"""
            <div class="{alert_class}">
                <strong>{alert.title}</strong><br>
                {alert.message}<br>
                <small>Priority: {alert.priority.value} | Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</small>
            </div>
            """, unsafe_allow_html=True)
            
            # Acknowledge button
            col1, col2 = st.columns([3, 1])
            with col2:
                if st.button(f"Acknowledge", key=f"ack_{alert.id}"):
                    self.data_store.acknowledge_alert(alert.id, self.current_user['name'])
                    st.rerun()
        
        # Show count of additional alerts
        if len(alerts) > 5:
            st.info(f"... and {len(alerts) - 5} more alerts. Use the Incidents page to view all.")
    
    def _render_recent_incidents(self, incidents: List[ThreatIncident]):
        """Render recent incidents section"""
        st.markdown("<h2 class='sub-header'>Recent Threat Incidents</h2>", unsafe_allow_html=True)
        
        if not incidents:
            st.info("No threats detected in the selected time period.")
            return
        
        # Prepare data for display in table
        incident_data = []
        for incident in incidents[:10]:  # Show 10 most recent
            incident_data.append({
                'Time': incident.timestamp.strftime('%H:%M:%S'),
                'Date': incident.timestamp.strftime('%Y-%m-%d'),
                'Type': incident.threat_type,
                'Severity': incident.severity.value,
                'Source IP': incident.source_ip,
                'Status': incident.status.value,
                'ID': incident.id
            })
        
        # Create DataFrame
        df = pd.DataFrame(incident_data)
        
        # Function to color severity cells
        def color_severity(val):
            if val == 'CRITICAL':
                return 'background-color: #ffcccc'
            elif val == 'HIGH':
                return 'background-color: #ffe6cc'
            elif val == 'MEDIUM':
                return 'background-color: #ffffcc'
            elif val == 'LOW':
                return 'background-color: #ccffcc'
            else:
                return 'background-color: #cce6ff'
        
        # Apply styling to DataFrame
        styled_df = df.style.applymap(color_severity, subset=['Severity'])
        
        # Display styled DataFrame
        st.dataframe(
            styled_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                'ID': st.column_config.Column(width="small"),
                'Time': st.column_config.Column(width="small"),
                'Date': st.column_config.Column(width="small"),
                'Type': st.column_config.Column(width="medium"),
                'Severity': st.column_config.Column(width="small"),
                'Source IP': st.column_config.Column(width="medium"),
                'Status': st.column_config.Column(width="small")
            }
        )
        
        # Incident details viewer
        if len(incidents) > 0:
            incident_ids = [inc.id for inc in incidents[:10]]
            selected_id = st.selectbox("View incident details:", incident_ids)
            
            if selected_id:
                # Find and display selected incident
                incident = next((inc for inc in incidents if inc.id == selected_id), None)
                if incident:
                    self._render_incident_details(incident)
    
    def _render_incident_details(self, incident: ThreatIncident):
        """Render detailed view of a specific incident"""
        st.markdown("---")
        st.markdown(f"### Incident Details: {incident.id}")
        
        # Basic incident information in two columns
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown(f"**Threat Type:** {incident.threat_type}")
            st.markdown(f"**Severity:** {incident.severity.value}")
            st.markdown(f"**Status:** {incident.status.value}")
            st.markdown(f"**Confidence:** {incident.confidence:.1%}")
        
        with col2:
            st.markdown(f"**Source IP:** {incident.source_ip}")
            st.markdown(f"**Target URL:** {incident.target_url}")
            st.markdown(f"**Detected:** {incident.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
            if incident.assigned_to:
                st.markdown(f"**Assigned to:** {incident.assigned_to}")
        
        # Description section
        st.markdown("**Description:**")
        st.info(incident.description)
        
        # Evidence section
        if incident.evidence:
            st.markdown("**Evidence:**")
            st.json(incident.evidence)
        
        # Mitigation steps section
        if incident.mitigation_steps:
            st.markdown("**Mitigation Steps:**")
            for i, step in enumerate(incident.mitigation_steps, 1):
                st.markdown(f"{i}. {step}")
        
        # Notes section
        st.markdown("**Notes:**")
        if incident.notes:
            for note in incident.notes:
                st.markdown(f"**{note.get('user', 'Unknown')}** ({note.get('timestamp', '')}):")
                st.markdown(f"> {note.get('note', '')}")
        else:
            st.info("No notes yet.")
        
        # Add note form
        st.markdown("---")
        st.markdown("**Add Note:**")
        
        note_text = st.text_area("Note:", height=100)
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("Add Note", type="primary"):
                if note_text.strip():
                    self.data_store.add_note_to_incident(
                        incident.id, 
                        self.current_user['name'], 
                        note_text
                    )
                    st.success("Note added!")
                    st.rerun()
        
        with col2:
            # Status update dropdown
            new_status = st.selectbox(
                "Update Status:",
                [status.value for status in ThreatStatus]
            )
            
            if st.button("Update Status"):
                if self.data_store.update_incident(incident.id, {'status': new_status}):
                    st.success("Status updated!")
                    st.rerun()
    
    def _render_system_status(self):
        """Render system status section"""
        st.markdown("<h2 class='sub-header'>System Status</h2>", unsafe_allow_html=True)
        
        # Check if metrics are available
        if self.data_store.metrics_history:
            latest_metrics = self.data_store.metrics_history[-1]
            
            # Display system metrics in 4 columns
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric(
                    label="System Uptime",
                    value=f"{latest_metrics.system_uptime / 3600:.1f}h"
                )
            
            with col2:
                st.metric(
                    label="Memory Usage",
                    value=f"{latest_metrics.memory_usage_mb:.0f} MB"
                )
            
            with col3:
                st.metric(
                    label="CPU Usage",
                    value=f"{latest_metrics.cpu_usage_percent:.1f}%"
                )
            
            with col4:
                st.metric(
                    label="Active Connections",
                    value=latest_metrics.active_connections
                )
            
            # Agent health status
            st.markdown("**Agent Health:**")
            agent_count = len(latest_metrics.agent_health_status)
            agent_cols = st.columns(min(4, agent_count) if agent_count > 0 else 1)
            
            for idx, (agent_id, status) in enumerate(latest_metrics.agent_health_status.items()):
                col_idx = idx % 4
                with agent_cols[col_idx]:
                    # Display status with color indicator
                    if status == "healthy":
                        status_indicator = "Healthy"
                    elif status == "unhealthy":
                        status_indicator = "Unhealthy"
                    else:
                        status_indicator = "Unknown"
                    st.markdown(f"{agent_id}: {status_indicator}")
        else:
            st.info("No system metrics available yet.")
    
    def _export_data(self):
        """Export dashboard data (placeholder implementation)"""
        st.info("Export functionality would save data to CSV/JSON files.")
        # In a real implementation, this would create downloadable files
        # with timestamped exports of incidents, alerts, and metrics
    
    def _create_new_incident_modal(self):
        """Create modal for new incident reporting"""
        st.markdown("---")
        st.markdown("### Create New Incident")
        
        # Form for new incident creation
        with st.form("new_incident_form"):
            threat_type = st.selectbox(
                "Threat Type:",
                ["SQL Injection", "XSS", "CSRF", "SSRF", "Command Injection", 
                 "Path Traversal", "DDoS", "Malware", "Phishing", "Other"]
            )
            
            severity = st.selectbox(
                "Severity:",
                [s.value for s in ThreatSeverity]
            )
            
            source_ip = st.text_input("Source IP:", placeholder="e.g., 192.168.1.100")
            target_url = st.text_input("Target URL:", placeholder="e.g., https://example.com/api")
            description = st.text_area("Description:", height=100)
            
            submitted = st.form_submit_button("Create Incident", type="primary")
            
            if submitted:
                # Validate required fields
                if not description:
                    st.error("Description is required!")
                else:
                    # Create new incident
                    incident = ThreatIncident(
                        threat_type=threat_type,
                        severity=ThreatSeverity(severity),
                        source_ip=source_ip,
                        target_url=target_url,
                        description=description,
                        confidence=0.8,  # Default confidence
                        status=ThreatStatus.DETECTED
                    )
                    
                    # Add to data store
                    incident_id = self.data_store.add_incident(incident)
                    st.success(f"Incident created: {incident_id}")
                    st.rerun()


# ============================================================================
# API INTEGRATION - REST API for programmatic access
# ============================================================================

class DashboardAPI:
    """
    REST API for the security dashboard
    Allows programmatic access to dashboard data and functionality
    """
    
    def __init__(self, data_store: SecurityDataStore):
        """
        Initialize dashboard API
        
        Args:
            data_store: SecurityDataStore instance
        """
        self.data_store = data_store
        self.api_keys = {}  # In production, use proper authentication/authorization
    
    def get_incidents_api(self, 
                         filters: Optional[Dict[str, Any]] = None,
                         limit: int = 100,
                         offset: int = 0) -> Dict[str, Any]:
        """
        API endpoint to get incidents
        
        Args:
            filters: Filter criteria
            limit: Maximum incidents to return
            offset: Pagination offset
            
        Returns:
            JSON response with incidents
        """
        # Get incidents from data store
        incidents = self.data_store.get_incidents(filters, limit, offset)
        
        # Prepare response
        return {
            'status': 'success',
            'data': {
                'incidents': [incident.to_dict() for incident in incidents],
                'total': len(self.data_store.incidents),
                'limit': limit,
                'offset': offset
            },
            'timestamp': datetime.now().isoformat()
        }
    
    def get_alerts_api(self, 
                      unacknowledged_only: bool = True) -> Dict[str, Any]:
        """
        API endpoint to get alerts
        
        Args:
            unacknowledged_only: Only return unacknowledged alerts
            
        Returns:
            JSON response with alerts
        """
        # Get alerts from data store
        alerts = self.data_store.get_active_alerts(unacknowledged_only=unacknowledged_only)
        
        # Prepare response
        return {
            'status': 'success',
            'data': {
                'alerts': [alert.to_dict() for alert in alerts],
                'total': len(alerts)
            },
            'timestamp': datetime.now().isoformat()
        }
    
    def get_metrics_api(self, 
                       time_window_hours: int = 24) -> Dict[str, Any]:
        """
        API endpoint to get metrics
        
        Args:
            time_window_hours: Time window for metrics
            
        Returns:
            JSON response with metrics
        """
        # Get statistics from data store
        stats = self.data_store.get_statistics(time_window_hours)
        
        # Get timeseries data for request rate
        request_rate_data = self.data_store.get_metrics_timeseries(
            'request_rate_per_second',
            time_window_hours
        )
        
        # Prepare response
        return {
            'status': 'success',
            'data': {
                'statistics': stats,
                'timeseries': {
                    'request_rate': [
                        {'timestamp': ts.isoformat(), 'value': val}
                        for ts, val in request_rate_data
                    ]
                }
            },
            'timestamp': datetime.now().isoformat()
        }
    
    def create_incident_api(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        API endpoint to create a new incident
        
        Args:
            incident_data: Incident data
            
        Returns:
            JSON response with created incident
        """
        try:
            # Create incident from provided data
            incident = ThreatIncident(
                threat_type=incident_data.get('threat_type', 'Unknown'),
                severity=ThreatSeverity(incident_data.get('severity', 'MEDIUM')),
                source_ip=incident_data.get('source_ip', ''),
                target_url=incident_data.get('target_url', ''),
                description=incident_data.get('description', ''),
                confidence=float(incident_data.get('confidence', 0.5)),
                status=ThreatStatus(incident_data.get('status', 'DETECTED')),
                evidence=incident_data.get('evidence', {}),
                mitigation_steps=incident_data.get('mitigation_steps', []),
                tags=set(incident_data.get('tags', []))
            )
            
            # Add incident to data store
            incident_id = self.data_store.add_incident(incident)
            
            # Prepare success response
            return {
                'status': 'success',
                'data': {
                    'incident_id': incident_id,
                    'incident': incident.to_dict()
                },
                'message': 'Incident created successfully',
                'timestamp': datetime.now().isoformat()
            }
        
        except Exception as e:
            # Prepare error response
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }


# ============================================================================
# EXAMPLE USAGE AND DEMONSTRATION
# ============================================================================

def example_usage():
    """Example of how to use the security dashboard"""
    
    # Create data store instance
    data_store = SecurityDataStore()
    
    # Create dashboard instance
    dashboard = SecurityDashboard(data_store)
    
    # Add some example incidents for demonstration
    example_incidents = [
        ThreatIncident(
            threat_type="SQL Injection",
            severity=ThreatSeverity.CRITICAL,
            source_ip="192.168.1.100",
            target_url="https://example.com/login",
            description="SQL injection attempt detected in login form",
            confidence=0.95,
            evidence={"pattern": "' OR '1'='1", "parameter": "password"},
            mitigation_steps=["Block IP", "Review logs", "Update WAF rules"]
        ),
        ThreatIncident(
            threat_type="XSS",
            severity=ThreatSeverity.HIGH,
            source_ip="10.0.0.50",
            target_url="https://example.com/contact",
            description="Cross-site scripting attempt in contact form",
            confidence=0.85,
            evidence={"pattern": "<script>alert('xss')</script>", "parameter": "message"},
            mitigation_steps=["Sanitize input", "Implement CSP"]
        ),
        ThreatIncident(
            threat_type="DDoS",
            severity=ThreatSeverity.MEDIUM,
            source_ip="Multiple",
            target_url="https://example.com/api",
            description="Distributed Denial of Service attack detected",
            confidence=0.75,
            evidence={"request_rate": "5000 req/sec", "duration": "10 minutes"},
            mitigation_steps=["Enable rate limiting", "Activate CDN protection"]
        )
    ]
    
    # Add example incidents to data store
    for incident in example_incidents:
        data_store.add_incident(incident)
    
    # Create example alerts
    data_store.create_alert(
        title="Critical SQL Injection Detected",
        message="SQL injection attempt from 192.168.1.100",
        priority=AlertPriority.CRITICAL
    )
    
    data_store.create_alert(
        title="High Severity XSS Attack",
        message="XSS attempt detected in contact form",
        priority=AlertPriority.HIGH
    )
    
    # Add example metrics (simulating historical data)
    for i in range(100):
        metrics = DashboardMetrics(
            total_requests=1000 + i * 10,
            blocked_requests=50 + i,
            request_rate_per_second=10.0 + i * 0.1,
            total_threats=3,
            threats_by_severity={"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1},
            system_uptime=3600 + i * 60,
            memory_usage_mb=512.0,
            cpu_usage_percent=25.0 + i * 0.1,
            active_connections=100 + i,
            active_agents=3,
            agent_health_status={"agent1": "healthy", "agent2": "healthy", "agent3": "healthy"}
        )
        data_store.add_metrics(metrics)
    
    # Start dashboard if Streamlit is available
    if STREAMLIT_AVAILABLE:
        print("Starting Security Dashboard...")
        print("Open http://localhost:8080 in your browser")
        dashboard.start(port=8080)
    else:
        print("Warning: Streamlit not available. Dashboard UI disabled.")
        
        # Demonstrate API usage as alternative
        api = DashboardAPI(data_store)
        
        print("\nDashboard Statistics:")
        stats = data_store.get_statistics(time_window_hours=24)
        print(json.dumps(stats, indent=2, default=str))
        
        print("\nActive Alerts:")
        alerts = data_store.get_active_alerts()
        for alert in alerts:
            print(f"  • {alert.title} ({alert.priority.value})")
        
        print("\nRecent Incidents:")
        incidents = data_store.get_incidents(limit=5)
        for incident in incidents:
            print(f"  • {incident.threat_type} - {incident.severity.value}")


# Main entry point
if __name__ == "__main__":
    # Run the example usage demonstration
    example_usage()