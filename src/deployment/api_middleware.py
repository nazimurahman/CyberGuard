"""
API Middleware for CyberGuard - Production-grade security middleware
Purpose: Intercept, analyze, and protect web traffic in real-time
Features: Zero-trust security, rate limiting, threat detection, API protection
"""

import time
import json
import hashlib
import hmac
import asyncio
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import wraps
import inspect

# Import type hints for better documentation
from collections import defaultdict
from contextlib import asynccontextmanager
import logging
from pathlib import Path

# Third-party imports for production features
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    print("⚠️ Redis not available - using in-memory store (not production ready)")

try:
    from prometheus_client import Counter, Histogram, Gauge
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    print("⚠️ Prometheus not available - metrics disabled")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# DATA CLASSES FOR CONFIGURATION
# ============================================================================

@dataclass
class RateLimitConfig:
    """
    Rate limiting configuration for API protection
    Prevents brute force attacks, DoS, and API abuse
    """
    requests_per_minute: int = 100  # Default: 100 requests per minute per IP
    burst_limit: int = 10  # Allow bursts of up to 10 requests
    window_seconds: int = 60  # Time window for rate limiting (60 seconds)
    ban_threshold: int = 5  # Number of violations before temporary ban
    ban_duration_minutes: int = 15  # Duration of ban in minutes
    
    def validate(self) -> Tuple[bool, str]:
        """Validate configuration parameters"""
        if self.requests_per_minute <= 0:
            return False, "requests_per_minute must be positive"
        if self.burst_limit <= 0:
            return False, "burst_limit must be positive"
        if self.window_seconds <= 0:
            return False, "window_seconds must be positive"
        return True, "Configuration valid"

@dataclass
class SecurityHeadersConfig:
    """
    Security headers configuration for HTTP responses
    Implements OWASP security header recommendations
    """
    # Content Security Policy (CSP) - prevents XSS attacks
    content_security_policy: str = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';"
    
    # X-Frame-Options - prevents clickjacking
    x_frame_options: str = "DENY"
    
    # X-Content-Type-Options - prevents MIME type sniffing
    x_content_type_options: str = "nosniff"
    
    # X-XSS-Protection - legacy XSS protection for older browsers
    x_xss_protection: str = "1; mode=block"
    
    # Strict-Transport-Security (HSTS) - enforces HTTPS
    strict_transport_security: str = "max-age=31536000; includeSubDomains"
    
    # Referrer-Policy - controls referrer information
    referrer_policy: str = "strict-origin-when-cross-origin"
    
    # Permissions-Policy - controls browser features
    permissions_policy: str = "geolocation=(), microphone=(), camera=()"
    
    # Cross-Origin policies for modern browsers
    cross_origin_opener_policy: str = "same-origin"
    cross_origin_embedder_policy: str = "require-corp"
    cross_origin_resource_policy: str = "same-origin"

@dataclass
class ThreatDetectionConfig:
    """
    Real-time threat detection configuration
    Configures what threats to detect and their sensitivity
    """
    # Enable/disable specific threat detectors
    enable_sqli_detection: bool = True
    enable_xss_detection: bool = True
    enable_path_traversal: bool = True
    enable_command_injection: bool = True
    enable_ssrf_detection: bool = True
    
    # Sensitivity thresholds (0.0 to 1.0)
    sql_injection_threshold: float = 0.7
    xss_threshold: float = 0.6
    path_traversal_threshold: float = 0.8
    command_injection_threshold: float = 0.75
    ssrf_threshold: float = 0.7
    
    # Bot detection
    enable_bot_detection: bool = True
    bot_signature_file: str = "config/bot_signatures.json"
    
    # Behavioral analysis
    enable_behavioral_analysis: bool = True
    anomaly_detection_window: int = 100  # Requests to analyze
    anomaly_threshold: float = 3.0  # Standard deviations from mean

# ============================================================================
# CORE MIDDLEWARE CLASSES
# ============================================================================

class RateLimiter:
    """
    Distributed rate limiter with sliding window algorithm
    Uses Redis for distributed environments, falls back to in-memory
    """
    
    def __init__(self, config: RateLimitConfig, redis_client=None):
        """
        Initialize rate limiter with configuration
        
        Args:
            config: RateLimitConfig object with rate limiting parameters
            redis_client: Optional Redis client for distributed rate limiting
        """
        self.config = config
        self.redis_client = redis_client
        self.local_store = defaultdict(list)  # Fallback: {ip: [timestamp1, timestamp2...]}
        
        # Track bans
        self.bans = {}  # {ip: ban_until_timestamp}
        
        # Metrics for monitoring
        if PROMETHEUS_AVAILABLE:
            self.requests_counter = Counter(
                'cyberguard_rate_limit_requests_total',
                'Total requests processed by rate limiter',
                ['client_ip', 'status']
            )
            self.blocked_counter = Counter(
                'cyberguard_rate_limit_blocked_total',
                'Total requests blocked by rate limiter',
                ['client_ip', 'reason']
            )
    
    def is_rate_limited(self, client_ip: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if client has exceeded rate limits
        
        Args:
            client_ip: Client IP address to check
            
        Returns:
            Tuple of (is_limited, metadata)
        """
        current_time = time.time()
        
        # Check if IP is banned
        if client_ip in self.bans:
            ban_until = self.bans[client_ip]
            if current_time < ban_until:
                # Still banned
                if PROMETHEUS_AVAILABLE:
                    self.blocked_counter.labels(client_ip=client_ip, reason='banned').inc()
                return True, {
                    'reason': 'banned',
                    'ban_until': datetime.fromtimestamp(ban_until).isoformat(),
                    'retry_after': int(ban_until - current_time)
                }
            else:
                # Ban expired, remove from bans
                del self.bans[client_ip]
        
        # Get request timestamps for this IP
        if self.redis_client and REDIS_AVAILABLE:
            # Redis implementation for distributed environments
            key = f"rate_limit:{client_ip}"
            timestamps = self.redis_client.lrange(key, 0, -1)
            timestamps = [float(ts) for ts in timestamps]
            
            # Clean old timestamps (outside window)
            window_start = current_time - self.config.window_seconds
            recent_timestamps = [ts for ts in timestamps if ts > window_start]
            
            # Trim list in Redis
            self.redis_client.ltrim(key, -len(recent_timestamps), -1)
        else:
            # In-memory implementation (fallback)
            timestamps = self.local_store[client_ip]
            window_start = current_time - self.config.window_seconds
            recent_timestamps = [ts for ts in timestamps if ts > window_start]
            self.local_store[client_ip] = recent_timestamps
        
        # Check rate limits
        request_count = len(recent_timestamps)
        
        if request_count >= self.config.requests_per_minute:
            # Exceeded rate limit
            violations = self._track_violation(client_ip)
            
            if violations >= self.config.ban_threshold:
                # Too many violations, apply ban
                ban_until = current_time + (self.config.ban_duration_minutes * 60)
                self.bans[client_ip] = ban_until
                
                if PROMETHEUS_AVAILABLE:
                    self.blocked_counter.labels(client_ip=client_ip, reason='ban').inc()
                
                return True, {
                    'reason': 'ban',
                    'violations': violations,
                    'ban_until': datetime.fromtimestamp(ban_until).isoformat(),
                    'retry_after': self.config.ban_duration_minutes * 60
                }
            
            if PROMETHEUS_AVAILABLE:
                self.blocked_counter.labels(client_ip=client_ip, reason='rate_limit').inc()
            
            return True, {
                'reason': 'rate_limit',
                'request_count': request_count,
                'limit': self.config.requests_per_minute,
                'retry_after': self.config.window_seconds
            }
        
        # Check burst limit
        if recent_timestamps:
            time_since_last = current_time - recent_timestamps[-1]
            if time_since_last < (self.config.window_seconds / self.config.burst_limit):
                # Too many requests in burst
                if PROMETHEUS_AVAILABLE:
                    self.blocked_counter.labels(client_ip=client_ip, reason='burst').inc()
                
                return True, {
                    'reason': 'burst',
                    'time_since_last': time_since_last,
                    'retry_after': 1  # Wait 1 second
                }
        
        # Not rate limited, record this request
        if self.redis_client and REDIS_AVAILABLE:
            self.redis_client.rpush(f"rate_limit:{client_ip}", current_time)
            self.redis_client.expire(f"rate_limit:{client_ip}", self.config.window_seconds)
        else:
            self.local_store[client_ip].append(current_time)
            # Clean up old entries periodically
            if len(self.local_store[client_ip]) > self.config.requests_per_minute * 2:
                self.local_store[client_ip] = recent_timestamps
        
        if PROMETHEUS_AVAILABLE:
            self.requests_counter.labels(client_ip=client_ip, status='allowed').inc()
        
        return False, {
            'reason': 'allowed',
            'request_count': request_count + 1,
            'remaining': self.config.requests_per_minute - (request_count + 1)
        }
    
    def _track_violation(self, client_ip: str) -> int:
        """
        Track rate limit violations for an IP
        
        Args:
            client_ip: Client IP address
            
        Returns:
            Number of violations
        """
        violation_key = f"violations:{client_ip}"
        
        if self.redis_client and REDIS_AVAILABLE:
            violations = self.redis_client.incr(violation_key)
            self.redis_client.expire(violation_key, 3600)  # Expire after 1 hour
            return violations
        else:
            # In-memory tracking
            if client_ip not in self.local_store:
                self.local_store[client_ip] = []
            self.local_store[client_ip].append(time.time())
            return len([ts for ts in self.local_store[client_ip] 
                       if ts > time.time() - 3600])

class ThreatDetector:
    """
    Real-time threat detector for HTTP requests
    Analyzes headers, parameters, and body for security threats
    """
    
    def __init__(self, config: ThreatDetectionConfig):
        """
        Initialize threat detector with configuration
        
        Args:
            config: ThreatDetectionConfig object with detection parameters
        """
        self.config = config
        self.patterns = self._load_threat_patterns()
        self.bot_signatures = self._load_bot_signatures()
        
        # Behavioral analysis state
        self.request_patterns = defaultdict(list)  # {ip: [request_times]}
        
        # Metrics
        if PROMETHEUS_AVAILABLE:
            self.threats_detected = Counter(
                'cyberguard_threats_detected_total',
                'Total threats detected',
                ['threat_type', 'severity']
            )
    
    def _load_threat_patterns(self) -> Dict[str, List[str]]:
        """
        Load threat detection patterns from configuration
        These are regex patterns for detecting various attacks
        """
        # SQL Injection patterns
        sql_patterns = [
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # SQL meta-characters
            r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",  # Basic SQL injection
            r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",  # 'or' pattern
            r"((\%27)|(\'))union",  # UNION SQL injection
            r"exec(\s|\+)+(s|x)p\w+",  # MSSQL procedures
            r"\/\*.*\*\/",  # SQL comments
        ]
        
        # XSS patterns
        xss_patterns = [
            r"<script[^>]*>.*?</script>",  # Script tags
            r"javascript:",  # JavaScript protocol
            r"on\w+\s*=",  # Event handlers (onload, onerror, etc.)
            r"alert\s*\(",  # Alert function
            r"eval\s*\(",  # Eval function
            r"<iframe[^>]*>",  # Iframe tags
            r"<object[^>]*>",  # Object tags
            r"<embed[^>]*>",  # Embed tags
        ]
        
        # Path traversal patterns
        path_traversal_patterns = [
            r"\.\.\/",  # Directory traversal (Unix)
            r"\.\.\\",  # Directory traversal (Windows)
            r"\/etc\/passwd",  # Sensitive Unix file
            r"\/proc\/self\/",  # Linux proc access
            r"C:\\Windows\\",  # Windows system directory
        ]
        
        # Command injection patterns
        command_injection_patterns = [
            r";\s*\w+",  # Command separator
            r"\|\s*\w+",  # Pipe operator
            r"&\s*\w+",  # Background process
            r"`.*`",  # Backticks
            r"\$\(.*\)",  # Command substitution
            r"\|\|", r"&&",  # Logical operators
        ]
        
        # SSRF patterns
        ssrf_patterns = [
            r"localhost", r"127\.0\.0\.1", r"0\.0\.0\.0",  # Localhost
            r"169\.254\.169\.254",  # AWS metadata service
            r"192\.168\.", r"10\.", r"172\.(1[6-9]|2[0-9]|3[0-1])\.",  # Private IPs
            r"file:\/\/", r"gopher:\/\/", r"dict:\/\/",  # Dangerous protocols
        ]
        
        return {
            'sql_injection': sql_patterns,
            'xss': xss_patterns,
            'path_traversal': path_traversal_patterns,
            'command_injection': command_injection_patterns,
            'ssrf': ssrf_patterns
        }
    
    def _load_bot_signatures(self) -> List[str]:
        """
        Load bot/crawler user-agent signatures
        """
        common_bots = [
            "Googlebot", "Bingbot", "Slurp", "DuckDuckBot", "Baiduspider",
            "YandexBot", "Sogou", "Exabot", "facebookexternalhit", "Twitterbot",
            "rogerbot", "linkedinbot", "embedly", "quora link preview",
            "showyoubot", "outbrain", "pinterest", "slackbot", "vkShare",
            "W3C_Validator", "redditbot", "Applebot", "WhatsApp", "TelegramBot",
            "Discordbot", "Zoombot", "SkypeUriPreview"
        ]
        
        # Load from file if exists
        if Path(self.config.bot_signature_file).exists():
            try:
                with open(self.config.bot_signature_file, 'r') as f:
                    bot_data = json.load(f)
                    return bot_data.get('signatures', common_bots)
            except Exception as e:
                logger.warning(f"Could not load bot signatures: {e}")
        
        return common_bots
    
    def analyze_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze HTTP request for security threats
        
        Args:
            request_data: Dictionary containing request information
                - method: HTTP method
                - path: Request path
                - headers: Request headers
                - query_params: Query parameters
                - body: Request body (if any)
                - client_ip: Client IP address
                
        Returns:
            Dictionary with threat analysis results
        """
        threats = []
        threat_score = 0.0
        max_severity = "LOW"
        
        # Extract data
        method = request_data.get('method', '').upper()
        path = request_data.get('path', '')
        headers = request_data.get('headers', {})
        query_params = request_data.get('query_params', {})
        body = request_data.get('body', '')
        client_ip = request_data.get('client_ip', '')
        
        # 1. Check for SQL Injection
        if self.config.enable_sqli_detection:
            sql_threats = self._detect_sql_injection(path, query_params, body)
            threats.extend(sql_threats)
            if sql_threats:
                threat_score = max(threat_score, self.config.sql_injection_threshold)
                max_severity = self._get_highest_severity(sql_threats, max_severity)
        
        # 2. Check for XSS
        if self.config.enable_xss_detection:
            xss_threats = self._detect_xss(path, query_params, body, headers)
            threats.extend(xss_threats)
            if xss_threats:
                threat_score = max(threat_score, self.config.xss_threshold)
                max_severity = self._get_highest_severity(xss_threats, max_severity)
        
        # 3. Check for Path Traversal
        if self.config.enable_path_traversal:
            path_threats = self._detect_path_traversal(path)
            threats.extend(path_threats)
            if path_threats:
                threat_score = max(threat_score, self.config.path_traversal_threshold)
                max_severity = self._get_highest_severity(path_threats, max_severity)
        
        # 4. Check for Command Injection
        if self.config.enable_command_injection:
            cmd_threats = self._detect_command_injection(path, query_params, body)
            threats.extend(cmd_threats)
            if cmd_threats:
                threat_score = max(threat_score, self.config.command_injection_threshold)
                max_severity = self._get_highest_severity(cmd_threats, max_severity)
        
        # 5. Check for SSRF
        if self.config.enable_ssrf_detection:
            ssrf_threats = self._detect_ssrf(path, query_params, body, headers)
            threats.extend(ssrf_threats)
            if ssrf_threats:
                threat_score = max(threat_score, self.config.ssrf_threshold)
                max_severity = self._get_highest_severity(ssrf_threats, max_severity)
        
        # 6. Bot Detection
        if self.config.enable_bot_detection:
            is_bot = self._detect_bot(headers)
            if is_bot:
                threats.append({
                    'type': 'BOT',
                    'severity': 'LOW',
                    'description': 'Request from known bot/crawler',
                    'confidence': 0.8
                })
        
        # 7. Behavioral Analysis
        if self.config.enable_behavioral_analysis and client_ip:
            is_anomalous = self._analyze_behavior(client_ip, request_data)
            if is_anomalous:
                threats.append({
                    'type': 'BEHAVIORAL_ANOMALY',
                    'severity': 'MEDIUM',
                    'description': 'Anomalous request pattern detected',
                    'confidence': 0.6
                })
                threat_score = max(threat_score, 0.5)
        
        # Update metrics
        if PROMETHEUS_AVAILABLE and threats:
            for threat in threats:
                self.threats_detected.labels(
                    threat_type=threat.get('type', 'UNKNOWN'),
                    severity=threat.get('severity', 'LOW')
                ).inc()
        
        return {
            'threats_detected': threats,
            'threat_score': threat_score,
            'max_severity': max_severity,
            'requires_blocking': threat_score > 0.7 or max_severity in ['HIGH', 'CRITICAL'],
            'timestamp': datetime.now().isoformat()
        }
    
    def _detect_sql_injection(self, path: str, query_params: Dict, body: str) -> List[Dict]:
        """Detect SQL injection patterns"""
        threats = []
        
        # Check path
        for pattern in self.patterns['sql_injection']:
            if re.search(pattern, path, re.IGNORECASE):
                threats.append({
                    'type': 'SQL_INJECTION',
                    'severity': 'CRITICAL',
                    'description': f'SQL injection pattern in path: {pattern}',
                    'location': 'path',
                    'confidence': 0.9
                })
        
        # Check query parameters
        for param_name, param_value in query_params.items():
            if isinstance(param_value, str):
                for pattern in self.patterns['sql_injection']:
                    if re.search(pattern, param_value, re.IGNORECASE):
                        threats.append({
                            'type': 'SQL_INJECTION',
                            'severity': 'CRITICAL',
                            'description': f'SQL injection pattern in parameter {param_name}: {pattern}',
                            'location': f'query_param:{param_name}',
                            'confidence': 0.9
                        })
        
        # Check request body (if it's a string)
        if isinstance(body, str):
            for pattern in self.patterns['sql_injection']:
                if re.search(pattern, body, re.IGNORECASE):
                    threats.append({
                        'type': 'SQL_INJECTION',
                        'severity': 'CRITICAL',
                        'description': f'SQL injection pattern in request body: {pattern}',
                        'location': 'body',
                        'confidence': 0.8
                    })
        
        return threats
    
    def _detect_xss(self, path: str, query_params: Dict, body: str, headers: Dict) -> List[Dict]:
        """Detect Cross-Site Scripting (XSS) patterns"""
        threats = []
        
        # Check all inputs
        inputs_to_check = [
            ('path', path),
            ('headers', str(headers)),
            ('body', body if isinstance(body, str) else '')
        ]
        
        for location, value in inputs_to_check:
            for pattern in self.patterns['xss']:
                if re.search(pattern, value, re.IGNORECASE):
                    threats.append({
                        'type': 'XSS',
                        'severity': 'HIGH',
                        'description': f'XSS pattern in {location}: {pattern}',
                        'location': location,
                        'confidence': 0.8
                    })
        
        # Check query parameters
        for param_name, param_value in query_params.items():
            if isinstance(param_value, str):
                for pattern in self.patterns['xss']:
                    if re.search(pattern, param_value, re.IGNORECASE):
                        threats.append({
                            'type': 'XSS',
                            'severity': 'HIGH',
                            'description': f'XSS pattern in parameter {param_name}: {pattern}',
                            'location': f'query_param:{param_name}',
                            'confidence': 0.8
                        })
        
        return threats
    
    def _detect_path_traversal(self, path: str) -> List[Dict]:
        """Detect path traversal attempts"""
        threats = []
        
        for pattern in self.patterns['path_traversal']:
            if re.search(pattern, path, re.IGNORECASE):
                threats.append({
                    'type': 'PATH_TRAVERSAL',
                    'severity': 'HIGH',
                    'description': f'Path traversal pattern in path: {pattern}',
                    'location': 'path',
                    'confidence': 0.85
                })
        
        return threats
    
    def _detect_command_injection(self, path: str, query_params: Dict, body: str) -> List[Dict]:
        """Detect command injection attempts"""
        threats = []
        
        # Check path
        for pattern in self.patterns['command_injection']:
            if re.search(pattern, path):
                threats.append({
                    'type': 'COMMAND_INJECTION',
                    'severity': 'CRITICAL',
                    'description': f'Command injection pattern in path: {pattern}',
                    'location': 'path',
                    'confidence': 0.9
                })
        
        # Check query parameters
        for param_name, param_value in query_params.items():
            if isinstance(param_value, str):
                for pattern in self.patterns['command_injection']:
                    if re.search(pattern, param_value):
                        threats.append({
                            'type': 'COMMAND_INJECTION',
                            'severity': 'CRITICAL',
                            'description': f'Command injection pattern in parameter {param_name}: {pattern}',
                            'location': f'query_param:{param_name}',
                            'confidence': 0.9
                        })
        
        return threats
    
    def _detect_ssrf(self, path: str, query_params: Dict, body: str, headers: Dict) -> List[Dict]:
        """Detect Server-Side Request Forgery (SSRF) attempts"""
        threats = []
        
        # Check all inputs for SSRF patterns
        inputs_to_check = [
            ('path', path),
            ('headers', str(headers)),
            ('body', body if isinstance(body, str) else '')
        ]
        
        for location, value in inputs_to_check:
            for pattern in self.patterns['ssrf']:
                if re.search(pattern, value, re.IGNORECASE):
                    threats.append({
                        'type': 'SSRF',
                        'severity': 'HIGH',
                        'description': f'SSRF pattern in {location}: {pattern}',
                        'location': location,
                        'confidence': 0.75
                    })
        
        # Check query parameters
        for param_name, param_value in query_params.items():
            if isinstance(param_value, str):
                for pattern in self.patterns['ssrf']:
                    if re.search(pattern, param_value, re.IGNORECASE):
                        threats.append({
                            'type': 'SSRF',
                            'severity': 'HIGH',
                            'description': f'SSRF pattern in parameter {param_name}: {pattern}',
                            'location': f'query_param:{param_name}',
                            'confidence': 0.75
                        })
        
        return threats
    
    def _detect_bot(self, headers: Dict) -> bool:
        """Detect if request is from a known bot/crawler"""
        user_agent = headers.get('User-Agent', '').lower()
        
        for bot_signature in self.bot_signatures:
            if bot_signature.lower() in user_agent:
                return True
        
        return False
    
    def _analyze_behavior(self, client_ip: str, request_data: Dict) -> bool:
        """
        Analyze request behavior for anomalies
        Uses simple statistical analysis on request timing
        """
        current_time = time.time()
        
        # Store request time
        self.request_patterns[client_ip].append(current_time)
        
        # Keep only recent requests (last hour)
        cutoff = current_time - 3600
        self.request_patterns[client_ip] = [
            t for t in self.request_patterns[client_ip] if t > cutoff
        ]
        
        # Need enough data for analysis
        if len(self.request_patterns[client_ip]) < 10:
            return False
        
        # Calculate time differences between consecutive requests
        times = sorted(self.request_patterns[client_ip])
        if len(times) < 2:
            return False
        
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        
        # Calculate mean and standard deviation
        if not intervals:
            return False
        
        mean_interval = sum(intervals) / len(intervals)
        
        # Avoid division by zero
        if mean_interval == 0:
            return True  # Extremely fast requests
        
        # Calculate standard deviation
        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = variance ** 0.5
        
        # Check if current pattern is anomalous
        recent_intervals = intervals[-5:]  # Last 5 intervals
        if recent_intervals:
            avg_recent = sum(recent_intervals) / len(recent_intervals)
            
            # Check if significantly faster than normal
            if avg_recent < mean_interval - (self.config.anomaly_threshold * std_dev):
                return True
        
        return False
    
    def _get_highest_severity(self, threats: List[Dict], current_max: str) -> str:
        """Get the highest severity from a list of threats"""
        severity_order = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
        
        for threat in threats:
            threat_severity = threat.get('severity', 'LOW')
            if severity_order.get(threat_severity, 0) > severity_order.get(current_max, 0):
                current_max = threat_severity
        
        return current_max

class APISecurityMiddleware:
    """
    Main API Security Middleware class
    Integrates rate limiting, threat detection, and security headers
    """
    
    def __init__(self, 
                 rate_limit_config: Optional[RateLimitConfig] = None,
                 security_headers_config: Optional[SecurityHeadersConfig] = None,
                 threat_detection_config: Optional[ThreatDetectionConfig] = None,
                 redis_url: Optional[str] = None):
        """
        Initialize the API security middleware
        
        Args:
            rate_limit_config: Rate limiting configuration
            security_headers_config: Security headers configuration
            threat_detection_config: Threat detection configuration
            redis_url: Redis URL for distributed rate limiting (optional)
        """
        # Set defaults if not provided
        self.rate_limit_config = rate_limit_config or RateLimitConfig()
        self.security_headers_config = security_headers_config or SecurityHeadersConfig()
        self.threat_detection_config = threat_detection_config or ThreatDetectionConfig()
        
        # Initialize Redis client if URL provided
        self.redis_client = None
        if redis_url and REDIS_AVAILABLE:
            try:
                self.redis_client = redis.from_url(redis_url)
                logger.info(f"Connected to Redis at {redis_url}")
            except Exception as e:
                logger.warning(f"Could not connect to Redis: {e}")
        
        # Initialize components
        self.rate_limiter = RateLimiter(self.rate_limit_config, self.redis_client)
        self.threat_detector = ThreatDetector(self.threat_detection_config)
        
        # Request tracking for analytics
        self.request_counter = 0
        self.blocked_counter = 0
        
        # Metrics
        if PROMETHEUS_AVAILABLE:
            self.total_requests = Counter(
                'cyberguard_middleware_requests_total',
                'Total requests processed by middleware'
            )
            self.blocked_requests = Counter(
                'cyberguard_middleware_blocked_total',
                'Total requests blocked by middleware',
                ['block_reason']
            )
            self.processing_time = Histogram(
                'cyberguard_middleware_processing_seconds',
                'Time spent processing requests',
                buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
            )
    
    async def process_request(self, 
                            request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process an incoming HTTP request through security middleware
        
        Args:
            request_data: Dictionary containing request information
            
        Returns:
            Dictionary with processing results and security decision
        """
        start_time = time.time()
        self.request_counter += 1
        
        # Extract client IP (handle various header formats)
        client_ip = self._extract_client_ip(request_data)
        request_data['client_ip'] = client_ip
        
        # Step 1: Rate limiting
        is_rate_limited, rate_limit_info = self.rate_limiter.is_rate_limited(client_ip)
        
        if is_rate_limited:
            self.blocked_counter += 1
            if PROMETHEUS_AVAILABLE:
                self.blocked_requests.labels(block_reason=rate_limit_info.get('reason', 'unknown')).inc()
            
            return {
                'decision': 'BLOCK',
                'block_reason': 'rate_limit',
                'block_details': rate_limit_info,
                'processing_time': time.time() - start_time,
                'timestamp': datetime.now().isoformat()
            }
        
        # Step 2: Threat detection
        threat_analysis = self.threat_detector.analyze_request(request_data)
        
        if threat_analysis.get('requires_blocking', False):
            self.blocked_counter += 1
            block_reason = f"threat_{threat_analysis.get('max_severity', 'UNKNOWN').lower()}"
            
            if PROMETHEUS_AVAILABLE:
                self.blocked_requests.labels(block_reason=block_reason).inc()
            
            return {
                'decision': 'BLOCK',
                'block_reason': 'threat_detected',
                'threat_analysis': threat_analysis,
                'processing_time': time.time() - start_time,
                'timestamp': datetime.now().isoformat()
            }
        
        # Step 3: Add security headers
        security_headers = self._generate_security_headers()
        
        processing_time = time.time() - start_time
        
        if PROMETHEUS_AVAILABLE:
            self.total_requests.inc()
            self.processing_time.observe(processing_time)
        
        return {
            'decision': 'ALLOW',
            'security_headers': security_headers,
            'threat_analysis': threat_analysis,
            'rate_limit_info': rate_limit_info,
            'processing_time': processing_time,
            'timestamp': datetime.now().isoformat()
        }
    
    def _extract_client_ip(self, request_data: Dict) -> str:
        """
        Extract client IP address from request headers
        Handles proxies, load balancers, and CDNs
        """
        headers = request_data.get('headers', {})
        
        # Check common proxy headers (in order of trustworthiness)
        proxy_headers = [
            'X-Forwarded-For',
            'X-Real-IP',
            'CF-Connecting-IP',  # Cloudflare
            'True-Client-IP',    # Akamai
        ]
        
        for header in proxy_headers:
            if header in headers:
                # X-Forwarded-For can contain multiple IPs (client, proxy1, proxy2...)
                ips = headers[header].split(',')
                # First IP is the original client
                client_ip = ips[0].strip()
                if self._is_valid_ip(client_ip):
                    return client_ip
        
        # Fallback to remote address
        remote_addr = request_data.get('remote_addr', '')
        if remote_addr and self._is_valid_ip(remote_addr):
            return remote_addr
        
        # Default to placeholder
        return '0.0.0.0'
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _generate_security_headers(self) -> Dict[str, str]:
        """
        Generate security headers for HTTP response
        Implements OWASP security header recommendations
        """
        headers = {}
        
        # Add all configured security headers
        config_dict = self.security_headers_config.__dict__
        
        for header_name, header_value in config_dict.items():
            if header_value and not header_name.startswith('_'):
                # Convert snake_case to Header-Case
                header_key = ''.join(word.capitalize() for word in header_name.split('_'))
                header_key = header_key[0].lower() + header_key[1:]  # First letter lowercase
                
                # Special handling for X- headers
                if header_key.startswith(('x', 'X')):
                    header_key = 'X-' + header_key[2:] if header_key.startswith('x') else header_key
                
                headers[header_key] = header_value
        
        return headers
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get middleware performance metrics"""
        return {
            'total_requests': self.request_counter,
            'blocked_requests': self.blocked_counter,
            'block_rate': self.blocked_counter / max(self.request_counter, 1),
            'rate_limit_violations': len(self.rate_limiter.bans),
            'active_bots_detected': len([ip for ip, patterns in self.threat_detector.request_patterns.items() 
                                        if len(patterns) > 100]),  # High activity threshold
            'timestamp': datetime.now().isoformat()
        }
    
    def reset_metrics(self):
        """Reset all metrics (useful for testing)"""
        self.request_counter = 0
        self.blocked_counter = 0
        self.rate_limiter.bans.clear()
        self.threat_detector.request_patterns.clear()

# ============================================================================
# FASTAPI INTEGRATION
# ============================================================================

class FastAPISecurityMiddleware:
    """
    FastAPI-specific middleware wrapper
    Integrates with FastAPI applications seamlessly
    """
    
    def __init__(self, 
                 app,
                 api_middleware: APISecurityMiddleware,
                 exempt_paths: List[str] = None):
        """
        Initialize FastAPI security middleware
        
        Args:
            app: FastAPI application instance
            api_middleware: APISecurityMiddleware instance
            exempt_paths: List of path prefixes to exempt from security checks
        """
        self.app = app
        self.api_middleware = api_middleware
        self.exempt_paths = exempt_paths or ['/health', '/metrics', '/docs', '/redoc']
        
        # Add middleware to FastAPI app
        self._add_middleware_to_app()
    
    def _add_middleware_to_app(self):
        """Add security middleware to FastAPI application"""
        from fastapi import Request, Response
        from fastapi.middleware import Middleware
        from starlette.middleware.base import BaseHTTPMiddleware
        
        class SecurityMiddleware(BaseHTTPMiddleware):
            def __init__(self, app, parent):
                super().__init__(app)
                self.parent = parent
            
            async def dispatch(self, request: Request, call_next):
                # Check if path is exempt
                if any(request.url.path.startswith(path) for path in self.parent.exempt_paths):
                    return await call_next(request)
                
                # Prepare request data for security middleware
                request_data = {
                    'method': request.method,
                    'path': str(request.url.path),
                    'headers': dict(request.headers),
                    'query_params': dict(request.query_params),
                    'remote_addr': request.client.host if request.client else '0.0.0.0',
                    'body': await self._extract_body(request)
                }
                
                # Process through security middleware
                security_result = await self.parent.api_middleware.process_request(request_data)
                
                # Check if request should be blocked
                if security_result['decision'] == 'BLOCK':
                    # Create blocked response
                    block_reason = security_result.get('block_reason', 'security_violation')
                    block_details = security_result.get('block_details', {})
                    
                    response_data = {
                        'error': 'Request blocked',
                        'reason': block_reason,
                        'details': block_details,
                        'timestamp': datetime.now().isoformat(),
                        'request_id': request.headers.get('X-Request-ID', 'unknown')
                    }
                    
                    return Response(
                        content=json.dumps(response_data, indent=2),
                        status_code=429 if block_reason == 'rate_limit' else 403,
                        media_type='application/json',
                        headers={
                            'X-CyberGuard-Blocked': 'true',
                            'X-CyberGuard-Block-Reason': block_reason
                        }
                    )
                
                # Request allowed, add security headers to response
                response = await call_next(request)
                
                # Add security headers
                security_headers = security_result.get('security_headers', {})
                for header_name, header_value in security_headers.items():
                    response.headers[header_name] = header_value
                
                # Add custom headers for monitoring
                response.headers['X-CyberGuard-Processed'] = 'true'
                response.headers['X-CyberGuard-Threat-Score'] = str(
                    security_result.get('threat_analysis', {}).get('threat_score', 0.0)
                )
                response.headers['X-CyberGuard-Processing-Time'] = str(
                    security_result.get('processing_time', 0.0)
                )
                
                return response
            
            async def _extract_body(self, request: Request):
                """Extract request body for analysis"""
                try:
                    # Check content type
                    content_type = request.headers.get('content-type', '')
                    
                    if 'application/json' in content_type:
                        body = await request.json()
                        return json.dumps(body)
                    elif 'application/x-www-form-urlencoded' in content_type:
                        body = await request.form()
                        return str(dict(body))
                    elif 'multipart/form-data' in content_type:
                        # Don't parse large multipart data
                        return "[multipart/form-data]"
                    else:
                        # Try to read text for other content types
                        body = await request.body()
                        return body.decode('utf-8', errors='ignore')[:10000]  # Limit size
                except Exception as e:
                    logger.debug(f"Could not extract request body: {e}")
                    return ""
        
        # Add the middleware
        self.app.add_middleware(SecurityMiddleware, parent=self)
    
    def add_health_endpoint(self):
        """Add health check endpoint to FastAPI app"""
        from fastapi import APIRouter
        
        router = APIRouter()
        
        @router.get("/health")
        async def health_check():
            """Health check endpoint for monitoring"""
            return {
                'status': 'healthy',
                'timestamp': datetime.now().isoformat(),
                'metrics': self.api_middleware.get_metrics(),
                'version': '1.0.0'
            }
        
        @router.get("/metrics")
        async def metrics():
            """Prometheus metrics endpoint"""
            if PROMETHEUS_AVAILABLE:
                from prometheus_client import generate_latest
                from starlette.responses import Response
                return Response(
                    content=generate_latest(),
                    media_type='text/plain'
                )
            else:
                return {'error': 'Prometheus not available'}
        
        self.app.include_router(router)

# ============================================================================
# DECORATORS FOR ENDPOINT PROTECTION
# ============================================================================

def secure_endpoint(rate_limit: Optional[int] = None,
                    threat_check: bool = True,
                    require_auth: bool = False):
    """
    Decorator to add security checks to individual endpoints
    
    Args:
        rate_limit: Custom rate limit for this endpoint (requests/minute)
        threat_check: Enable threat detection for this endpoint
        require_auth: Require authentication for this endpoint
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get request object (assuming FastAPI)
            request = None
            for arg in args:
                if hasattr(arg, 'method') and hasattr(arg, 'headers'):
                    request = arg
                    break
            
            if request is None:
                for kwarg in kwargs.values():
                    if hasattr(kwarg, 'method') and hasattr(kwarg, 'headers'):
                        request = kwarg
                        break
            
            if request:
                # Here you would integrate with the security middleware
                # This is a simplified version
                pass
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator

# ============================================================================
# EXAMPLE USAGE
# ============================================================================

def example_usage():
    """Example of how to use the API middleware"""
    
    # Configuration
    rate_limit_config = RateLimitConfig(
        requests_per_minute=100,
        burst_limit=10,
        ban_threshold=5,
        ban_duration_minutes=15
    )
    
    security_headers_config = SecurityHeadersConfig(
        content_security_policy="default-src 'self'; script-src 'self'",
        x_frame_options="DENY",
        strict_transport_security="max-age=31536000; includeSubDomains"
    )
    
    threat_detection_config = ThreatDetectionConfig(
        enable_sqli_detection=True,
        enable_xss_detection=True,
        sql_injection_threshold=0.7,
        xss_threshold=0.6
    )
    
    # Create middleware instance
    middleware = APISecurityMiddleware(
        rate_limit_config=rate_limit_config,
        security_headers_config=security_headers_config,
        threat_detection_config=threat_detection_config,
        redis_url="redis://localhost:6379"  # Optional, for distributed rate limiting
    )
    
    # Example request
    example_request = {
        'method': 'POST',
        'path': '/api/login',
        'headers': {
            'User-Agent': 'Mozilla/5.0',
            'Content-Type': 'application/json',
            'X-Forwarded-For': '192.168.1.100, 10.0.0.1'
        },
        'query_params': {'username': 'admin'},
        'body': '{"password": "\' OR \'1\'=\'1"}',  # SQL injection attempt
        'remote_addr': '10.0.0.1'
    }
    
    # Process the request
    import asyncio
    
    async def process_example():
        result = await middleware.process_request(example_request)
        print("Security Result:", json.dumps(result, indent=2))
        
        # Get metrics
        metrics = middleware.get_metrics()
        print("\nMetrics:", json.dumps(metrics, indent=2))
    
    asyncio.run(process_example())

if __name__ == "__main__":
    # Run example
    example_usage()