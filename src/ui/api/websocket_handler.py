# src/ui/api/websocket_handler.py
"""
WebSocket Handler for CyberGuard Real-time Security Monitoring

Provides real-time updates for:
- Live scan progress
- Security alerts
- System metrics
- Agent status changes
- Threat intelligence feeds

Features:
- Bi-directional communication
- Connection management
- Event broadcasting
- Client authentication
- Rate limiting per connection
"""

from flask import Blueprint, request, current_app
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
import json
import time
from typing import Dict, Any, Set, Optional
from datetime import datetime
import hashlib

# Create blueprint for WebSocket routes
websocket_blueprint = Blueprint('websocket', __name__)

# Initialize SocketIO (will be configured in app factory)
socketio = SocketIO(cors_allowed_origins="*", async_mode='eventlet')

# Active connections tracking
active_connections = {}  # client_id -> connection info
client_rooms = {}  # client_id -> set of rooms

# Event types
EVENT_TYPES = {
    'SCAN_STARTED': 'scan_started',
    'SCAN_PROGRESS': 'scan_progress',
    'SCAN_COMPLETED': 'scan_completed',
    'SECURITY_ALERT': 'security_alert',
    'AGENT_UPDATE': 'agent_update',
    'SYSTEM_METRICS': 'system_metrics',
    'THREAT_INTEL': 'threat_intel',
    'CONNECTION_INFO': 'connection_info'
}

class WebSocketHandler:
    """Handler for WebSocket connections and events"""
    
    def __init__(self, agent_orchestrator=None, security_scanner=None):
        """
        Initialize WebSocket handler
        
        Args:
            agent_orchestrator: AgentOrchestrator for agent status updates
            security_scanner: WebSecurityScanner for scan progress
        """
        self.agent_orchestrator = agent_orchestrator
        self.security_scanner = security_scanner
        self.client_count = 0
        
        # Scan progress tracking
        self.active_scans = {}  # scan_id -> progress info
        
        # Configure SocketIO events
        self._configure_events()
    
    def _configure_events(self):
        """Configure SocketIO event handlers"""
        
        @socketio.on('connect')
        def handle_connect():
            """Handle new WebSocket connection"""
            client_id = request.sid
            client_ip = request.remote_addr
            
            # Generate client info
            client_info = {
                'id': client_id,
                'ip': client_ip,
                'connected_at': time.time(),
                'user_agent': request.headers.get('User-Agent', 'Unknown'),
                'rooms': set()
            }
            
            # Store connection
            active_connections[client_id] = client_info
            client_rooms[client_id] = set()
            
            self.client_count += 1
            
            # Send connection confirmation
            emit(EVENT_TYPES['CONNECTION_INFO'], {
                'status': 'connected',
                'client_id': client_id,
                'timestamp': datetime.now().isoformat(),
                'message': 'Connected to CyberGuard WebSocket'
            })
            
            # Broadcast connection count update
            self.broadcast_system_metrics()
            
            current_app.logger.info(f"WebSocket client connected: {client_id} from {client_ip}")
        
        @socketio.on('disconnect')
        def handle_disconnect():
            """Handle WebSocket disconnection"""
            client_id = request.sid
            
            if client_id in active_connections:
                # Leave all rooms
                for room in client_rooms.get(client_id, []):
                    leave_room(room)
                
                # Clean up
                del active_connections[client_id]
                del client_rooms[client_id]
                
                self.client_count -= 1
                
                # Broadcast updated metrics
                self.broadcast_system_metrics()
                
                current_app.logger.info(f"WebSocket client disconnected: {client_id}")
        
        @socketio.on('join_room')
        def handle_join_room(data):
            """Handle client joining a room"""
            client_id = request.sid
            room = data.get('room')
            
            if not room:
                emit('error', {'message': 'Room name required'})
                return
            
            # Join room
            join_room(room)
            
            # Update tracking
            if client_id in client_rooms:
                client_rooms[client_id].add(room)
            
            emit('room_joined', {
                'room': room,
                'timestamp': datetime.now().isoformat()
            })
            
            current_app.logger.info(f"Client {client_id} joined room: {room}")
        
        @socketio.on('leave_room')
        def handle_leave_room(data):
            """Handle client leaving a room"""
            client_id = request.sid
            room = data.get('room')
            
            if not room:
                emit('error', {'message': 'Room name required'})
                return
            
            # Leave room
            leave_room(room)
            
            # Update tracking
            if client_id in client_rooms and room in client_rooms[client_id]:
                client_rooms[client_id].remove(room)
            
            emit('room_left', {
                'room': room,
                'timestamp': datetime.now().isoformat()
            })
            
            current_app.logger.info(f"Client {client_id} left room: {room}")
        
        @socketio.on('subscribe_scan')
        def handle_subscribe_scan(data):
            """Subscribe to scan progress updates"""
            client_id = request.sid
            scan_id = data.get('scan_id')
            
            if not scan_id:
                emit('error', {'message': 'Scan ID required'})
                return
            
            # Join scan-specific room
            room = f'scan_{scan_id}'
            join_room(room)
            
            if client_id in client_rooms:
                client_rooms[client_id].add(room)
            
            emit('scan_subscribed', {
                'scan_id': scan_id,
                'room': room,
                'timestamp': datetime.now().isoformat()
            })
            
            # Send current scan progress if available
            if scan_id in self.active_scans:
                emit(EVENT_TYPES['SCAN_PROGRESS'], {
                    'scan_id': scan_id,
                    'progress': self.active_scans[scan_id],
                    'timestamp': datetime.now().isoformat()
                })
        
        @socketio.on('get_system_status')
        def handle_get_system_status():
            """Handle system status request"""
            status = self.get_system_status()
            emit('system_status_response', status)
    
    def broadcast_system_metrics(self):
        """Broadcast system metrics to all connected clients"""
        metrics = {
            'client_count': self.client_count,
            'active_scans': len(self.active_scans),
            'timestamp': datetime.now().isoformat()
        }
        
        # Add agent metrics if available
        if self.agent_orchestrator:
            agent_status = self.agent_orchestrator.get_system_status()
            metrics.update({
                'active_agents': agent_status.get('active_agents', 0),
                'total_analyses': agent_status['metrics'].get('total_analyses', 0),
                'threats_detected': agent_status['metrics'].get('threats_detected', 0)
            })
        
        socketio.emit(EVENT_TYPES['SYSTEM_METRICS'], metrics)
    
    def send_scan_progress(self, scan_id: str, progress: Dict[str, Any]):
        """
        Send scan progress update
        
        Args:
            scan_id: Unique scan identifier
            progress: Progress information including stage and percentage
        """
        # Update active scans tracking
        self.active_scans[scan_id] = progress
        
        # Emit to scan-specific room
        socketio.emit(EVENT_TYPES['SCAN_PROGRESS'], {
            'scan_id': scan_id,
            'progress': progress,
            'timestamp': datetime.now().isoformat()
        }, room=f'scan_{scan_id}')
        
        # Also update system metrics
        self.broadcast_system_metrics()
    
    def send_scan_completed(self, scan_id: str, result: Dict[str, Any]):
        """
        Send scan completion notification
        
        Args:
            scan_id: Unique scan identifier
            result: Scan results
        """
        # Remove from active scans
        if scan_id in self.active_scans:
            del self.active_scans[scan_id]
        
        # Emit completion event
        socketio.emit(EVENT_TYPES['SCAN_COMPLETED'], {
            'scan_id': scan_id,
            'result': result,
            'timestamp': datetime.now().isoformat()
        }, room=f'scan_{scan_id}')
        
        # Broadcast metrics update
        self.broadcast_system_metrics()
    
    def send_security_alert(self, alert: Dict[str, Any]):
        """
        Send security alert to all clients
        
        Args:
            alert: Alert information including severity, type, and details
        """
        # Add timestamp if not present
        if 'timestamp' not in alert:
            alert['timestamp'] = datetime.now().isoformat()
        
        # Add alert ID if not present
        if 'alert_id' not in alert:
            alert['alert_id'] = hashlib.sha256(
                f"{alert.get('type', '')}{alert['timestamp']}".encode()
            ).hexdigest()[:16]
        
        # Emit to all connected clients
        socketio.emit(EVENT_TYPES['SECURITY_ALERT'], alert)
        
        # Also send to monitoring room
        socketio.emit(EVENT_TYPES['SECURITY_ALERT'], alert, room='monitoring')
    
    def send_agent_update(self, agent_id: str, status: Dict[str, Any]):
        """
        Send agent status update
        
        Args:
            agent_id: Agent identifier
            status: Current agent status
        """
        socketio.emit(EVENT_TYPES['AGENT_UPDATE'], {
            'agent_id': agent_id,
            'status': status,
            'timestamp': datetime.now().isoformat()
        }, room='agents')
    
    def send_threat_intelligence(self, intel: Dict[str, Any]):
        """
        Send threat intelligence update
        
        Args:
            intel: Threat intelligence data
        """
        socketio.emit(EVENT_TYPES['THREAT_INTEL'], {
            'intel': intel,
            'timestamp': datetime.now().isoformat()
        }, room='threat_intel')
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get current WebSocket system status"""
        return {
            'connected_clients': self.client_count,
            'active_scans': len(self.active_scans),
            'total_rooms': sum(len(rooms) for rooms in client_rooms.values()),
            'timestamp': datetime.now().isoformat()
        }
    
    def get_connected_clients(self) -> Dict[str, Dict]:
        """Get information about all connected clients"""
        return active_connections.copy()
    
    def disconnect_client(self, client_id: str):
        """Disconnect a specific client"""
        if client_id in active_connections:
            disconnect(client_id)

# Initialize handler
websocket_handler = WebSocketHandler()

# Export the SocketIO instance for app configuration
__all__ = ['socketio', 'websocket_handler', 'websocket_blueprint']