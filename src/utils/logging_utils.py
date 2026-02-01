"""
Logging Utilities for CyberGuard Web Security AI System.

This module provides comprehensive logging with security-focused features:
- Structured logging with JSON output
- Security event logging with threat levels
- Audit trail for compliance requirements
- Performance monitoring and metrics
- Log rotation and secure storage
- Integration with external SIEM systems

All logs follow the Common Event Format (CEF) for SIEM integration.
"""

import logging
import logging.handlers
import json
import sys
import os
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Union, Callable, Tuple  # Fixed: Added Tuple import
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import gzip
import queue
from pathlib import Path


class ThreatLevel(Enum):
    """Threat levels for security events."""
    CRITICAL = "CRITICAL"      # Immediate action required
    HIGH = "HIGH"              # High priority investigation
    MEDIUM = "MEDIUM"          # Medium priority review
    LOW = "LOW"                # Low priority monitoring
    INFORMATIONAL = "INFO"     # Information only
    DEBUG = "DEBUG"            # Debug information


class SecurityEventType(Enum):
    """Types of security events for categorization."""
    THREAT_DETECTED = "THREAT_DETECTED"
    ATTACK_BLOCKED = "ATTACK_BLOCKED"
    VULNERABILITY_FOUND = "VULNERABILITY_FOUND"
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    DATA_ACCESS = "DATA_ACCESS"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    SYSTEM_STARTUP = "SYSTEM_STARTUP"
    SYSTEM_SHUTDOWN = "SYSTEM_SHUTDOWN"
    AGENT_ACTIVITY = "AGENT_ACTIVITY"
    COMPLIANCE_CHECK = "COMPLIANCE_CHECK"
    AUDIT_TRAIL = "AUDIT_TRAIL"
    PERFORMANCE_METRIC = "PERFORMANCE_METRIC"


@dataclass
class SecurityEvent:
    """
    Structured security event for logging.
    
    Follows Common Event Format (CEF) standards for SIEM integration.
    """
    timestamp: str
    event_type: SecurityEventType
    threat_level: ThreatLevel
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user_id: Optional[str] = None
    agent_id: Optional[str] = None
    resource: Optional[str] = None
    action: Optional[str] = None
    outcome: Optional[str] = None
    description: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    correlation_id: Optional[str] = None
    session_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for JSON serialization."""
        data = asdict(self)
        data['event_type'] = self.event_type.value
        data['threat_level'] = self.threat_level.value
        return data
    
    def to_cef(self) -> str:
        """Convert to Common Event Format (CEF) string."""
        # CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        cef_version = "0"
        device_vendor = "CyberGuard"
        device_product = "WebSecurityAI"
        device_version = "1.0"
        signature_id = self.event_type.value
        name = self.event_type.value.replace("_", " ")
        severity = self._threat_level_to_severity()
        
        # Build extension fields
        extensions = []
        if self.source_ip:
            extensions.append(f"src={self.source_ip}")
        if self.destination_ip:
            extensions.append(f"dst={self.destination_ip}")
        if self.user_id:
            extensions.append(f"suser={self.user_id}")
        if self.agent_id:
            extensions.append(f"agent={self.agent_id}")
        if self.description:
            # Escape pipes and backslashes for CEF
            desc = self.description.replace("\\", "\\\\").replace("|", "\\|")
            extensions.append(f"msg={desc}")
        if self.outcome:
            extensions.append(f"outcome={self.outcome}")
        
        extension_str = " ".join(extensions)
        
        return f"CEF:{cef_version}|{device_vendor}|{device_product}|{device_version}|{signature_id}|{name}|{severity}|{extension_str}"
    
    def _threat_level_to_severity(self) -> int:
        """Convert threat level to CEF severity (0-10)."""
        severity_map = {
            ThreatLevel.CRITICAL: 10,
            ThreatLevel.HIGH: 8,
            ThreatLevel.MEDIUM: 5,
            ThreatLevel.LOW: 3,
            ThreatLevel.INFORMATIONAL: 1,
            ThreatLevel.DEBUG: 0
        }
        return severity_map.get(self.threat_level, 1)


class JSONFormatter(logging.Formatter):
    """
    JSON formatter for structured logging.
    
    Outputs logs in JSON format for easy parsing and SIEM integration.
    """
    
    def __init__(self, include_context: bool = True):
        """
        Initialize JSON formatter.
        
        Args:
            include_context: Whether to include thread/process context
        """
        super().__init__()
        self.include_context = include_context
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record as JSON.
        
        Args:
            record: Log record to format
            
        Returns:
            JSON string
        """
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields from record
        if hasattr(record, 'security_event'):
            log_entry['security_event'] = record.security_event.to_dict()
        
        # Add custom fields
        for key, value in record.__dict__.items():
            if key not in self.default_fields and not key.startswith('_'):
                if isinstance(value, (str, int, float, bool, type(None))):
                    log_entry[key] = value
                else:
                    log_entry[key] = str(value)
        
        # Add context information
        if self.include_context:
            log_entry.update({
                'thread': record.threadName,
                'thread_id': record.thread,
                'process': record.processName,
                'process_id': record.process,
            })
        
        return json.dumps(log_entry, ensure_ascii=False)
    
    @property
    def default_fields(self) -> set:
        """Default fields in LogRecord."""
        return {
            'args', 'asctime', 'created', 'exc_info', 'exc_text', 'filename',
            'funcName', 'levelname', 'levelno', 'lineno', 'module', 'msecs',
            'message', 'msg', 'name', 'pathname', 'process', 'processName',
            'relativeCreated', 'stack_info', 'thread', 'threadName'
        }


class SecurityLogger:
    """
    Security-focused logger with threat level categorization.
    
    This logger provides structured logging for security events
    with automatic threat level assignment and correlation.
    """
    
    def __init__(self, name: str = "CyberGuard.Security", 
                 log_file: Optional[str] = None,
                 log_level: str = "INFO"):
        """
        Initialize security logger.
        
        Args:
            name: Logger name
            log_file: Optional file path for logging
            log_level: Logging level
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, log_level.upper()))
        
        # Remove existing handlers to avoid duplicates
        self.logger.handlers.clear()
        
        # Create formatters
        json_formatter = JSONFormatter()
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # File handler (if specified)
        if log_file:
            # Ensure directory exists
            log_dir = os.path.dirname(log_file)
            if log_dir:  # Only create directory if path has a directory component
                os.makedirs(log_dir, exist_ok=True)
            
            # Create rotating file handler
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=10 * 1024 * 1024,  # 10MB
                backupCount=10,
                encoding='utf-8'
            )
            file_handler.setFormatter(json_formatter)
            self.logger.addHandler(file_handler)
        
        # Initialize correlation ID
        self.correlation_id = None
        self.session_id = self._generate_session_id()
        
        # Event queue for async processing
        self.event_queue = queue.Queue()
        self._start_async_processor()
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID."""
        timestamp = datetime.now().isoformat()
        random_bytes = os.urandom(16)
        return hashlib.sha256(f"{timestamp}{random_bytes}".encode()).hexdigest()[:32]
    
    def _start_async_processor(self):
        """Start async event processing thread."""
        def process_events():
            while True:
                try:
                    event = self.event_queue.get(timeout=1)
                    self._log_event_sync(event)
                    self.event_queue.task_done()
                except queue.Empty:
                    continue
                except Exception as e:
                    # Log error but continue processing
                    self.logger.error(f"Error processing security event: {e}")
        
        processor_thread = threading.Thread(
            target=process_events,
            daemon=True,
            name="SecurityEventProcessor"
        )
        processor_thread.start()
    
    def log_security_event(self, event: SecurityEvent):
        """
        Log security event asynchronously.
        
        Args:
            event: Security event to log
        """
        # Add correlation ID if not present
        if not event.correlation_id and self.correlation_id:
            event.correlation_id = self.correlation_id
        
        # Add session ID if not present
        if not event.session_id:
            event.session_id = self.session_id
        
        # Queue event for async processing
        self.event_queue.put(event)
    
    def _log_event_sync(self, event: SecurityEvent):
        """
        Synchronously log security event.
        
        Args:
            event: Security event to log
        """
        # Map threat level to logging level
        level_map = {
            ThreatLevel.CRITICAL: logging.CRITICAL,
            ThreatLevel.HIGH: logging.ERROR,
            ThreatLevel.MEDIUM: logging.WARNING,
            ThreatLevel.LOW: logging.INFO,
            ThreatLevel.INFORMATIONAL: logging.INFO,
            ThreatLevel.DEBUG: logging.DEBUG
        }
        
        log_level = level_map.get(event.threat_level, logging.INFO)
        
        # Create log record with security event
        extra = {'security_event': event}
        
        # Log message
        message = f"{event.event_type.value}: {event.description or 'Security event'}"
        
        self.logger.log(log_level, message, extra=extra)
    
    def set_correlation_id(self, correlation_id: str):
        """
        Set correlation ID for current context.
        
        Args:
            correlation_id: Correlation ID for request tracing
        """
        self.correlation_id = correlation_id
    
    def get_correlation_id(self) -> Optional[str]:
        """Get current correlation ID."""
        return self.correlation_id
    
    def log_threat_detected(self, threat_type: str, description: str, 
                          threat_level: ThreatLevel, details: Optional[Dict] = None,
                          source_ip: Optional[str] = None, resource: Optional[str] = None):
        """
        Log threat detection event.
        
        Args:
            threat_type: Type of threat detected
            description: Threat description
            threat_level: Threat severity level
            details: Additional threat details
            source_ip: Source IP address
            resource: Affected resource
        """
        # Create details dictionary with threat_type included
        event_details = details or {}
        if 'threat_type' not in event_details:
            event_details['threat_type'] = threat_type
        
        event = SecurityEvent(
            timestamp=datetime.now().isoformat(),
            event_type=SecurityEventType.THREAT_DETECTED,
            threat_level=threat_level,
            source_ip=source_ip,
            resource=resource,
            description=description,
            details=event_details,
            outcome="DETECTED"
        )
        
        self.log_security_event(event)
    
    def log_attack_blocked(self, attack_type: str, description: str,
                         threat_level: ThreatLevel, source_ip: Optional[str] = None,
                         resource: Optional[str] = None, action_taken: str = "BLOCKED"):
        """
        Log attack blocking event.
        
        Args:
            attack_type: Type of attack blocked
            description: Attack description
            threat_level: Threat severity level
            source_ip: Source IP address
            resource: Affected resource
            action_taken: Action taken (BLOCKED, CHALLENGED, etc.)
        """
        event = SecurityEvent(
            timestamp=datetime.now().isoformat(),
            event_type=SecurityEventType.ATTACK_BLOCKED,
            threat_level=threat_level,
            source_ip=source_ip,
            resource=resource,
            description=description,
            details={'attack_type': attack_type, 'action': action_taken},
            outcome=action_taken
        )
        
        self.log_security_event(event)
    
    def log_agent_activity(self, agent_id: str, activity: str, 
                         details: Optional[Dict] = None):
        """
        Log agent activity.
        
        Args:
            agent_id: Agent identifier
            activity: Activity description
            details: Additional activity details
        """
        event = SecurityEvent(
            timestamp=datetime.now().isoformat(),
            event_type=SecurityEventType.AGENT_ACTIVITY,
            threat_level=ThreatLevel.INFORMATIONAL,
            agent_id=agent_id,
            description=activity,
            details=details or {}
        )
        
        self.log_security_event(event)
    
    def flush(self):
        """Flush all pending log events."""
        self.event_queue.join()


class AuditLogger:
    """
    Audit logger for compliance requirements.
    
    Provides tamper-evident logging for audit trails with
    cryptographic verification capabilities.
    """
    
    def __init__(self, audit_log_path: str, 
                 signing_key: Optional[str] = None):
        """
        Initialize audit logger.
        
        Args:
            audit_log_path: Path to audit log file
            signing_key: Optional key for digital signatures
        """
        self.audit_log_path = Path(audit_log_path)
        self.signing_key = signing_key
        
        # Ensure directory exists
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize chain hash (for tamper detection)
        self.chain_hash = self._load_chain_hash()
        
        # Lock for thread-safe writing
        self._lock = threading.Lock()
    
    def _load_chain_hash(self) -> Optional[str]:
        """Load previous chain hash from log file."""
        if not self.audit_log_path.exists():
            return None
        
        try:
            with open(self.audit_log_path, 'r') as f:
                lines = f.readlines()
                if lines:
                    # Get last line and extract hash
                    last_line = lines[-1].strip()
                    if last_line:
                        try:
                            entry = json.loads(last_line)
                            return entry.get('chain_hash')
                        except json.JSONDecodeError:
                            pass
        except Exception:
            pass
        
        return None
    
    def log_audit_event(self, user_id: str, action: str, resource: str,
                       details: Dict[str, Any], outcome: str = "SUCCESS") -> str:
        """
        Log audit event with chain verification.
        
        Args:
            user_id: User who performed the action
            action: Action performed
            resource: Resource affected
            details: Additional details
            outcome: Outcome of the action
            
        Returns:
            Entry hash string
        """
        timestamp = datetime.now().isoformat()
        
        # Create audit entry
        entry = {
            'timestamp': timestamp,
            'user_id': user_id,
            'action': action,
            'resource': resource,
            'details': details,
            'outcome': outcome,
            'previous_hash': self.chain_hash
        }
        
        # Calculate hash for this entry
        entry_str = json.dumps(entry, sort_keys=True)
        entry_hash = hashlib.sha256(entry_str.encode()).hexdigest()
        
        # Add hash to entry
        entry['entry_hash'] = entry_hash
        
        # Calculate chain hash
        if self.chain_hash:
            chain_input = f"{self.chain_hash}{entry_hash}"
        else:
            chain_input = entry_hash
        
        chain_hash = hashlib.sha256(chain_input.encode()).hexdigest()
        entry['chain_hash'] = chain_hash
        
        # Update chain hash
        self.chain_hash = chain_hash
        
        # Write to audit log
        self._write_audit_entry(entry)
        
        return entry_hash
    
    def _write_audit_entry(self, entry: Dict[str, Any]):
        """Write audit entry to log file."""
        with self._lock:
            with open(self.audit_log_path, 'a') as f:
                json.dump(entry, f)
                f.write('\n')
    
    def verify_audit_trail(self) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Verify integrity of audit trail.
        
        Returns:
            Tuple[bool, List]: (is_valid, list_of_invalid_entries)
        """
        if not self.audit_log_path.exists():
            return True, []
        
        invalid_entries = []
        previous_hash = None
        
        try:
            with open(self.audit_log_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    if not line.strip():
                        continue
                    
                    try:
                        entry = json.loads(line)
                        
                        # Verify entry hash
                        entry_copy = entry.copy()
                        entry_hash = entry_copy.pop('entry_hash', None)
                        expected_hash = entry_copy.pop('chain_hash', None)
                        
                        # Recalculate entry hash
                        entry_str = json.dumps(entry_copy, sort_keys=True)
                        calculated_hash = hashlib.sha256(entry_str.encode()).hexdigest()
                        
                        if entry_hash != calculated_hash:
                            invalid_entries.append({
                                'line': line_num,
                                'reason': 'Entry hash mismatch',
                                'entry': entry
                            })
                            continue
                        
                        # Verify chain hash
                        if previous_hash:
                            chain_input = f"{previous_hash}{entry_hash}"
                            calculated_chain = hashlib.sha256(chain_input.encode()).hexdigest()
                            
                            if expected_hash != calculated_chain:
                                invalid_entries.append({
                                    'line': line_num,
                                    'reason': 'Chain hash mismatch',
                                    'entry': entry
                                })
                        
                        previous_hash = expected_hash
                        
                    except json.JSONDecodeError as e:
                        invalid_entries.append({
                            'line': line_num,
                            'reason': f'Invalid JSON: {str(e)}',
                            'line_content': line.strip()
                        })
        
        except Exception as e:
            return False, [{'reason': f'File read error: {str(e)}'}]
        
        return len(invalid_entries) == 0, invalid_entries
    
    def get_audit_report(self, start_date: Optional[datetime] = None,
                        end_date: Optional[datetime] = None) -> Dict[str, Any]:
        """
        Generate audit report for specified period.
        
        Args:
            start_date: Start date for report
            end_date: End date for report
            
        Returns:
            Audit report dictionary
        """
        if not self.audit_log_path.exists():
            return {'error': 'Audit log not found'}
        
        report = {
            'total_entries': 0,
            'by_user': {},
            'by_action': {},
            'by_outcome': {},
            'time_period': {
                'start': start_date.isoformat() if start_date else None,
                'end': end_date.isoformat() if end_date else None
            }
        }
        
        try:
            with open(self.audit_log_path, 'r') as f:
                for line in f:
                    if not line.strip():
                        continue
                    
                    try:
                        entry = json.loads(line)
                        
                        # Filter by date if specified
                        timestamp = datetime.fromisoformat(entry['timestamp'])
                        if start_date and timestamp < start_date:
                            continue
                        if end_date and timestamp > end_date:
                            continue
                        
                        # Update counters
                        report['total_entries'] += 1
                        
                        # Count by user
                        user_id = entry.get('user_id', 'UNKNOWN')
                        report['by_user'][user_id] = report['by_user'].get(user_id, 0) + 1
                        
                        # Count by action
                        action = entry.get('action', 'UNKNOWN')
                        report['by_action'][action] = report['by_action'].get(action, 0) + 1
                        
                        # Count by outcome
                        outcome = entry.get('outcome', 'UNKNOWN')
                        report['by_outcome'][outcome] = report['by_outcome'].get(outcome, 0) + 1
                        
                    except (json.JSONDecodeError, KeyError):
                        continue
        
        except Exception as e:
            report['error'] = str(e)
        
        return report


class PerformanceMonitor:
    """
    Performance monitoring and metrics collection.
    
    Tracks system performance, response times, and resource usage.
    """
    
    def __init__(self, metrics_file: Optional[str] = None):
        """
        Initialize performance monitor.
        
        Args:
            metrics_file: Optional file to store metrics
        """
        self.metrics_file = metrics_file
        self.metrics = {
            'response_times': [],
            'throughput': [],
            'error_rates': [],
            'resource_usage': [],
            'agent_performance': {}
        }
        
        self.start_time = time.time()
        self.request_count = 0
        self.error_count = 0
        
        # Lock for thread safety
        self._lock = threading.Lock()
        
        # Start background metrics collection
        self._running = True
        self._collector_thread = threading.Thread(
            target=self._collect_metrics,
            daemon=True,
            name="PerformanceCollector"
        )
        self._collector_thread.start()
    
    def record_response_time(self, endpoint: str, response_time: float):
        """
        Record API response time.
        
        Args:
            endpoint: API endpoint
            response_time: Response time in seconds
        """
        with self._lock:
            self.metrics['response_times'].append({
                'timestamp': time.time(),
                'endpoint': endpoint,
                'response_time': response_time
            })
            
            # Keep only last 1000 entries
            if len(self.metrics['response_times']) > 1000:
                self.metrics['response_times'] = self.metrics['response_times'][-1000:]
    
    def record_request(self, success: bool = True):
        """
        Record request for throughput calculation.
        
        Args:
            success: Whether request was successful
        """
        with self._lock:
            self.request_count += 1
            if not success:
                self.error_count += 1
    
    def record_agent_performance(self, agent_id: str, task: str, 
                               execution_time: float, success: bool = True):
        """
        Record agent performance metrics.
        
        Args:
            agent_id: Agent identifier
            task: Task performed
            execution_time: Execution time in seconds
            success: Whether task succeeded
        """
        with self._lock:
            if agent_id not in self.metrics['agent_performance']:
                self.metrics['agent_performance'][agent_id] = {
                    'total_tasks': 0,
                    'successful_tasks': 0,
                    'total_time': 0.0,
                    'avg_time': 0.0,
                    'tasks': []
                }
            
            agent_metrics = self.metrics['agent_performance'][agent_id]
            agent_metrics['total_tasks'] += 1
            agent_metrics['total_time'] += execution_time
            agent_metrics['avg_time'] = agent_metrics['total_time'] / agent_metrics['total_tasks']
            
            if success:
                agent_metrics['successful_tasks'] += 1
            
            # Record individual task
            agent_metrics['tasks'].append({
                'timestamp': time.time(),
                'task': task,
                'execution_time': execution_time,
                'success': success
            })
            
            # Keep only last 100 tasks per agent
            if len(agent_metrics['tasks']) > 100:
                agent_metrics['tasks'] = agent_metrics['tasks'][-100:]
    
    def _collect_metrics(self):
        """Background thread to collect system metrics."""
        import psutil  # Moved import inside function to avoid dependency issues
        
        while self._running:
            try:
                # Collect system metrics
                cpu_percent = psutil.cpu_percent(interval=1)
                memory_info = psutil.virtual_memory()
                disk_usage = psutil.disk_usage('/')
                
                metrics_entry = {
                    'timestamp': time.time(),
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory_info.percent,
                    'memory_used_gb': memory_info.used / (1024**3),
                    'disk_percent': disk_usage.percent,
                    'disk_used_gb': disk_usage.used / (1024**3)
                }
                
                with self._lock:
                    self.metrics['resource_usage'].append(metrics_entry)
                    
                    # Calculate throughput
                    current_time = time.time()
                    elapsed = current_time - self.start_time
                    
                    throughput = self.request_count / elapsed if elapsed > 0 else 0
                    error_rate = self.error_count / self.request_count if self.request_count > 0 else 0
                    
                    self.metrics['throughput'].append({
                        'timestamp': current_time,
                        'requests_per_second': throughput,
                        'total_requests': self.request_count,
                        'error_rate': error_rate
                    })
                    
                    # Keep only last 1000 entries
                    if len(self.metrics['resource_usage']) > 1000:
                        self.metrics['resource_usage'] = self.metrics['resource_usage'][-1000:]
                    if len(self.metrics['throughput']) > 1000:
                        self.metrics['throughput'] = self.metrics['throughput'][-1000:]
                
                # Save metrics to file if configured
                if self.metrics_file:
                    self._save_metrics()
                
                time.sleep(60)  # Collect every minute
                
            except Exception as e:
                # Log error but continue
                print(f"Error collecting metrics: {e}")
                time.sleep(60)
    
    def _save_metrics(self):
        """Save metrics to file."""
        try:
            with self._lock:
                metrics_copy = self.metrics.copy()
                
                # Convert to serializable format
                for key in metrics_copy:
                    if isinstance(metrics_copy[key], list):
                        metrics_copy[key] = metrics_copy[key][-100:]  # Keep last 100
                
            if self.metrics_file:  # Check if metrics_file is not None
                with open(self.metrics_file, 'w') as f:
                    json.dump(metrics_copy, f, indent=2)
                
        except Exception as e:
            print(f"Error saving metrics: {e}")
    
    def get_performance_report(self) -> Dict[str, Any]:
        """
        Generate performance report.
        
        Returns:
            Performance report dictionary
        """
        with self._lock:
            # Calculate statistics
            if self.metrics['response_times']:
                response_times = [rt['response_time'] for rt in self.metrics['response_times'][-100:]]
                avg_response_time = sum(response_times) / len(response_times)
                max_response_time = max(response_times)
                min_response_time = min(response_times)
            else:
                avg_response_time = max_response_time = min_response_time = 0
            
            if self.metrics['throughput']:
                recent_throughput = self.metrics['throughput'][-1]['requests_per_second']
                recent_error_rate = self.metrics['throughput'][-1]['error_rate']
            else:
                recent_throughput = recent_error_rate = 0
            
            # Agent performance summary
            agent_summary = {}
            for agent_id, metrics in self.metrics['agent_performance'].items():
                agent_summary[agent_id] = {
                    'total_tasks': metrics['total_tasks'],
                    'success_rate': metrics['successful_tasks'] / metrics['total_tasks'] if metrics['total_tasks'] > 0 else 0,
                    'avg_execution_time': metrics['avg_time']
                }
            
            # System uptime
            uptime = time.time() - self.start_time
            
            return {
                'uptime_seconds': uptime,
                'total_requests': self.request_count,
                'total_errors': self.error_count,
                'current_throughput': recent_throughput,
                'current_error_rate': recent_error_rate,
                'response_times': {
                    'average': avg_response_time,
                    'maximum': max_response_time,
                    'minimum': min_response_time,
                    'sample_size': len(self.metrics['response_times'])
                },
                'agent_performance': agent_summary,
                'system_metrics': self.metrics['resource_usage'][-1] if self.metrics['resource_usage'] else {}
            }
    
    def stop(self):
        """Stop performance monitoring."""
        self._running = False
        if self._collector_thread.is_alive():
            self._collector_thread.join(timeout=5)


# Global logger instances
_SECURITY_LOGGER: Optional[SecurityLogger] = None
_AUDIT_LOGGER: Optional[AuditLogger] = None
_PERFORMANCE_MONITOR: Optional[PerformanceMonitor] = None


def setup_logger(name: str = "CyberGuard", 
                log_file: Optional[str] = None,
                log_level: str = "INFO",
                enable_json: bool = True) -> logging.Logger:
    """
    Set up and configure logger.
    
    Args:
        name: Logger name
        log_file: Optional log file path
        log_level: Logging level
        enable_json: Whether to use JSON formatting
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    # Remove existing handlers to avoid duplicates
    if logger.handlers:
        return logger
    
    # Set log level
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Create formatters
    if enable_json:
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        # Ensure directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir:  # Only create directory if path has a directory component
            os.makedirs(log_dir, exist_ok=True)
        
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=10,
            encoding='utf-8'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str = "CyberGuard") -> logging.Logger:
    """
    Get logger instance.
    
    Args:
        name: Logger name
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)


def get_security_logger() -> SecurityLogger:
    """
    Get global security logger instance.
    
    Returns:
        SecurityLogger instance
    """
    global _SECURITY_LOGGER
    
    if _SECURITY_LOGGER is None:
        _SECURITY_LOGGER = SecurityLogger(
            name="CyberGuard.Security",
            log_file="logs/security/security.log",
            log_level="INFO"
        )
    
    return _SECURITY_LOGGER


def get_audit_logger() -> AuditLogger:
    """
    Get global audit logger instance.
    
    Returns:
        AuditLogger instance
    """
    global _AUDIT_LOGGER
    
    if _AUDIT_LOGGER is None:
        _AUDIT_LOGGER = AuditLogger(
            audit_log_path="logs/audit/audit.log"
        )
    
    return _AUDIT_LOGGER


def get_performance_monitor() -> PerformanceMonitor:
    """
    Get global performance monitor instance.
    
    Returns:
        PerformanceMonitor instance
    """
    global _PERFORMANCE_MONITOR
    
    if _PERFORMANCE_MONITOR is None:
        _PERFORMANCE_MONITOR = PerformanceMonitor(
            metrics_file="logs/performance/metrics.json"
        )
    
    return _PERFORMANCE_MONITOR


def log_security_event(event_type: SecurityEventType, 
                      threat_level: ThreatLevel,
                      description: str,
                      **kwargs):
    """
    Log security event using global security logger.
    
    Args:
        event_type: Type of security event
        threat_level: Threat severity level
        description: Event description
        **kwargs: Additional event fields
    """
    logger = get_security_logger()
    
    event = SecurityEvent(
        timestamp=datetime.now().isoformat(),
        event_type=event_type,
        threat_level=threat_level,
        description=description,
        **kwargs
    )
    
    logger.log_security_event(event)


def log_threat_detection(threat_type: str, description: str, 
                        threat_level: ThreatLevel, **kwargs):
    """
    Log threat detection event.
    
    Args:
        threat_type: Type of threat
        description: Threat description
        threat_level: Threat severity
        **kwargs: Additional details
    """
    logger = get_security_logger()
    logger.log_threat_detected(threat_type, description, threat_level, **kwargs)


def log_agent_activity(agent_id: str, activity: str, details: Optional[Dict] = None):
    """
    Log agent activity.
    
    Args:
        agent_id: Agent identifier
        activity: Activity description
        details: Additional details
    """
    logger = get_security_logger()
    logger.log_agent_activity(agent_id, activity, details)


def flush_logs():
    """Flush all pending log events."""
    if _SECURITY_LOGGER:
        _SECURITY_LOGGER.flush()


# Example usage
if __name__ == "__main__":
    # Setup basic logger
    logger = setup_logger("TestLogger")
    logger.info("Test message")
    
    # Security logging
    security_logger = get_security_logger()
    security_logger.log_threat_detected(
        threat_type="XSS",
        description="Cross-site scripting attempt detected",
        threat_level=ThreatLevel.HIGH,
        source_ip="192.168.1.100",
        resource="/login"
    )
    
    # Audit logging
    audit_logger = get_audit_logger()
    audit_hash = audit_logger.log_audit_event(
        user_id="admin",
        action="CONFIG_UPDATE",
        resource="/api/config",
        details={"parameter": "timeout", "value": 30}
    )
    print(f"Audit entry hash: {audit_hash}")
    
    # Verify audit trail
    is_valid, issues = audit_logger.verify_audit_trail()
    print(f"Audit trail valid: {is_valid}")
    
    # Performance monitoring
    perf_monitor = get_performance_monitor()
    perf_monitor.record_response_time("/api/scan", 0.125)
    perf_monitor.record_agent_performance("agent_001", "threat_analysis", 0.25, True)
    
    # Get performance report
    report = perf_monitor.get_performance_report()
    print(f"Uptime: {report['uptime_seconds']} seconds")
    
    # Flush logs before exit
    flush_logs()