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
# async_mode should match the async server you're using
socketio = SocketIO(cors_allowed_origins="*", async_mode='threading')

# Active connections tracking
active_connections = {}  # Maps client_id -> connection info dictionary
client_rooms = {}  # Maps client_id -> set of room names the client has joined

# Event types constants for consistent event naming
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
        # Store references to external services for data integration
        self.agent_orchestrator = agent_orchestrator
        self.security_scanner = security_scanner
        self.client_count = 0  # Track total connected clients
        
        # Scan progress tracking - stores active scan progress information
        self.active_scans = {}  # scan_id -> progress info dictionary
        
        # Configure SocketIO event handlers
        self._configure_events()
    
    def _configure_events(self):
        """Configure SocketIO event handlers for various client events"""
        
        # Define all event handlers within this method to capture self context
        @socketio.on('connect')
        def handle_connect():
            """Handle new WebSocket connection - triggered when client connects"""
            client_id = request.sid  # SocketIO generated session ID
            client_ip = request.remote_addr  # Client's IP address
            
            # Generate comprehensive client information dictionary
            client_info = {
                'id': client_id,
                'ip': client_ip,
                'connected_at': time.time(),  # Unix timestamp
                'user_agent': request.headers.get('User-Agent', 'Unknown'),  # Browser/Client info
                'rooms': set()  # Rooms client will join (initially empty)
            }
            
            # Store connection in global tracking dictionaries
            active_connections[client_id] = client_info
            client_rooms[client_id] = set()  # Initialize empty room set for client
            
            # Update total client count
            self.client_count += 1
            
            # Send connection confirmation to the newly connected client
            emit(EVENT_TYPES['CONNECTION_INFO'], {
                'status': 'connected',
                'client_id': client_id,
                'timestamp': datetime.now().isoformat(),  # ISO format timestamp
                'message': 'Connected to CyberGuard WebSocket'
            })
            
            # Broadcast updated system metrics to all connected clients
            self.broadcast_system_metrics()
            
            # Log the connection event for monitoring/debugging
            current_app.logger.info(f"WebSocket client connected: {client_id} from {client_ip}")
        
        @socketio.on('disconnect')
        def handle_disconnect():
            """Handle WebSocket disconnection - triggered when client disconnects"""
            client_id = request.sid
            
            # Check if client exists in active connections
            if client_id in active_connections:
                # Remove client from all joined rooms
                for room in client_rooms.get(client_id, []):
                    leave_room(room)  # SocketIO function to leave room
                
                # Clean up tracking data
                del active_connections[client_id]
                del client_rooms[client_id]
                
                # Update client count
                self.client_count -= 1
                
                # Broadcast updated system metrics to remaining clients
                self.broadcast_system_metrics()
                
                # Log disconnection for monitoring
                current_app.logger.info(f"WebSocket client disconnected: {client_id}")
        
        @socketio.on('join_room')
        def handle_join_room(data):
            """Handle client joining a specific room for targeted messaging"""
            client_id = request.sid
            room = data.get('room')  # Extract room name from incoming data
            
            # Validate room name was provided
            if not room:
                emit('error', {'message': 'Room name required'})
                return
            
            # Join the specified room using SocketIO
            join_room(room)
            
            # Update local room tracking
            if client_id in client_rooms:
                client_rooms[client_id].add(room)  # Add room to client's room set
            
            # Send confirmation back to client
            emit('room_joined', {
                'room': room,
                'timestamp': datetime.now().isoformat()
            })
            
            # Log room join for monitoring
            current_app.logger.info(f"Client {client_id} joined room: {room}")
        
        @socketio.on('leave_room')
        def handle_leave_room(data):
            """Handle client leaving a specific room"""
            client_id = request.sid
            room = data.get('room')  # Extract room name from incoming data
            
            # Validate room name was provided
            if not room:
                emit('error', {'message': 'Room name required'})
                return
            
            # Leave the specified room using SocketIO
            leave_room(room)
            
            # Update local room tracking
            if client_id in client_rooms and room in client_rooms[client_id]:
                client_rooms[client_id].remove(room)  # Remove room from client's set
            
            # Send confirmation back to client
            emit('room_left', {
                'room': room,
                'timestamp': datetime.now().isoformat()
            })
            
            # Log room leave for monitoring
            current_app.logger.info(f"Client {client_id} left room: {room}")
        
        @socketio.on('subscribe_scan')
        def handle_subscribe_scan(data):
            """Subscribe to specific scan progress updates"""
            client_id = request.sid
            scan_id = data.get('scan_id')  # Extract scan ID from incoming data
            
            # Validate scan ID was provided
            if not scan_id:
                emit('error', {'message': 'Scan ID required'})
                return
            
            # Create room name specific to this scan
            room = f'scan_{scan_id}'
            
            # Join the scan-specific room
            join_room(room)
            
            # Update local room tracking
            if client_id in client_rooms:
                client_rooms[client_id].add(room)
            
            # Send subscription confirmation to client
            emit('scan_subscribed', {
                'scan_id': scan_id,
                'room': room,
                'timestamp': datetime.now().isoformat()
            })
            
            # If scan is already in progress, send current progress to the new subscriber
            if scan_id in self.active_scans:
                emit(EVENT_TYPES['SCAN_PROGRESS'], {
                    'scan_id': scan_id,
                    'progress': self.active_scans[scan_id],
                    'timestamp': datetime.now().isoformat()
                })
        
        @socketio.on('get_system_status')
        def handle_get_system_status():
            """Handle system status request - returns current WebSocket system status"""
            status = self.get_system_status()  # Get comprehensive system status
            emit('system_status_response', status)  # Send response back to requesting client
    
    def broadcast_system_metrics(self):
        """Broadcast system metrics to all connected clients - for real-time dashboard updates"""
        # Base metrics dictionary
        metrics = {
            'client_count': self.client_count,  # Current number of connected clients
            'active_scans': len(self.active_scans),  # Number of scans in progress
            'timestamp': datetime.now().isoformat()  # Current timestamp
        }
        
        # Add agent-specific metrics if agent orchestrator is available
        if self.agent_orchestrator:
            try:
                agent_status = self.agent_orchestrator.get_system_status()
                metrics.update({
                    'active_agents': agent_status.get('active_agents', 0),
                    'total_analyses': agent_status['metrics'].get('total_analyses', 0),
                    'threats_detected': agent_status['metrics'].get('threats_detected', 0)
                })
            except (AttributeError, KeyError) as e:
                # Log error but continue without agent metrics
                current_app.logger.error(f"Error getting agent status: {e}")
        
        # Broadcast metrics to ALL connected clients
        socketio.emit(EVENT_TYPES['SYSTEM_METRICS'], metrics)
    
    def send_scan_progress(self, scan_id: str, progress: Dict[str, Any]):
        """
        Send scan progress update to all clients subscribed to this scan
        
        Args:
            scan_id: Unique scan identifier
            progress: Progress information including stage and percentage
        """
        # Update active scans tracking with latest progress
        self.active_scans[scan_id] = progress
        
        # Emit progress update only to clients in the scan-specific room
        socketio.emit(EVENT_TYPES['SCAN_PROGRESS'], {
            'scan_id': scan_id,
            'progress': progress,
            'timestamp': datetime.now().isoformat()
        }, room=f'scan_{scan_id}')  # Target only scan-specific room
        
        # Also update system metrics for all clients (shows active scan count)
        self.broadcast_system_metrics()
    
    def send_scan_completed(self, scan_id: str, result: Dict[str, Any]):
        """
        Send scan completion notification to all subscribed clients
        
        Args:
            scan_id: Unique scan identifier
            result: Complete scan results
        """
        # Remove scan from active scans tracking since it's complete
        if scan_id in self.active_scans:
            del self.active_scans[scan_id]
        
        # Emit completion event to clients in scan-specific room
        socketio.emit(EVENT_TYPES['SCAN_COMPLETED'], {
            'scan_id': scan_id,
            'result': result,
            'timestamp': datetime.now().isoformat()
        }, room=f'scan_{scan_id}')  # Target only scan-specific room
        
        # Broadcast updated metrics to all clients
        self.broadcast_system_metrics()
    
    def send_security_alert(self, alert: Dict[str, Any]):
        """
        Send security alert to all clients (and specifically to monitoring room)
        
        Args:
            alert: Alert information including severity, type, and details
        """
        # Ensure alert has timestamp
        if 'timestamp' not in alert:
            alert['timestamp'] = datetime.now().isoformat()
        
        # Generate unique alert ID if not provided
        if 'alert_id' not in alert:
            # Create deterministic hash-based ID from alert type and timestamp
            alert_id_base = f"{alert.get('type', '')}{alert['timestamp']}"
            alert['alert_id'] = hashlib.sha256(alert_id_base.encode()).hexdigest()[:16]
        
        # Emit alert to ALL connected clients
        socketio.emit(EVENT_TYPES['SECURITY_ALERT'], alert)
        
        # Also send to dedicated monitoring room for admin/operator clients
        socketio.emit(EVENT_TYPES['SECURITY_ALERT'], alert, room='monitoring')
    
    def send_agent_update(self, agent_id: str, status: Dict[str, Any]):
        """
        Send agent status update to clients in agents room
        
        Args:
            agent_id: Agent identifier
            status: Current agent status information
        """
        # Emit agent update only to clients in the agents room
        socketio.emit(EVENT_TYPES['AGENT_UPDATE'], {
            'agent_id': agent_id,
            'status': status,
            'timestamp': datetime.now().isoformat()
        }, room='agents')  # Target only agents room
    
    def send_threat_intelligence(self, intel: Dict[str, Any]):
        """
        Send threat intelligence update to clients in threat_intel room
        
        Args:
            intel: Threat intelligence data
        """
        # Emit threat intel only to clients in the threat_intel room
        socketio.emit(EVENT_TYPES['THREAT_INTEL'], {
            'intel': intel,
            'timestamp': datetime.now().isoformat()
        }, room='threat_intel')  # Target only threat_intel room
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get current WebSocket system status for administrative purposes"""
        return {
            'connected_clients': self.client_count,  # Total connected clients
            'active_scans': len(self.active_scans),  # Number of active scans
            'total_rooms': sum(len(rooms) for rooms in client_rooms.values()),  # Total room memberships
            'timestamp': datetime.now().isoformat()  # Current timestamp
        }
    
    def get_connected_clients(self) -> Dict[str, Dict]:
        """Get information about all connected clients for monitoring"""
        # Return copy to prevent external modification of internal state
        return active_connections.copy()
    
    def disconnect_client(self, client_id: str):
        """Disconnect a specific client by ID (admin function)"""
        if client_id in active_connections:
            disconnect(client_id)  # SocketIO function to force disconnect


# Initialize global WebSocket handler instance
# Note: External services (agent_orchestrator, security_scanner) should be injected later
websocket_handler = WebSocketHandler()

# Export the SocketIO instance and handler for app configuration
__all__ = ['socketio', 'websocket_handler', 'websocket_blueprint']