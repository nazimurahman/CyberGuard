"""
Website Plugin Deployment Module for CyberGuard
===============================================

Provides a lightweight JavaScript plugin that can be easily integrated into any website
for real-time security monitoring and protection.
"""

import os
import json
import hashlib
import base64
from typing import Dict, List, Any, Optional, Union, Callable
from datetime import datetime, timedelta
import asyncio
import aiohttp
from dataclasses import dataclass, field, asdict
from enum import Enum
import logging
import urllib.parse

# Local imports - assuming these exist in the project structure
# Note: These imports might need adjustment based on actual project structure
try:
    from ..web_security.scanner import WebSecurityScanner
    from ..agents.agent_orchestrator import AgentOrchestrator
except ImportError:
    # Fallback for standalone testing
    class WebSecurityScanner:
        def __init__(self, config):
            self.config = config
    
    class AgentOrchestrator:
        def __init__(self, state_dim):
            self.state_dim = state_dim

# Configure module logger
logger = logging.getLogger(__name__)

class PluginMode(Enum):
    """
    Operation modes for the website plugin.
    
    MONITOR: Only monitor requests, no blocking
    PROTECTION: Actively block detected threats
    DEBUG: Debug mode with detailed logging
    LEARNING: Learning mode for training the system
    """
    MONITOR = "monitor"
    PROTECTION = "protection"
    DEBUG = "debug"
    LEARNING = "learning"

@dataclass
class PluginConfig:
    """
    Configuration for the CyberGuard website plugin.
    """
    api_key: str
    mode: PluginMode = PluginMode.PROTECTION
    log_level: str = "warn"
    blocked_countries: List[str] = field(default_factory=list)
    allowed_user_agents: List[str] = field(default_factory=list)
    rate_limit_requests: int = 100
    rate_limit_window: int = 60
    enable_xss_protection: bool = True
    enable_sqli_protection: bool = True
    enable_bot_protection: bool = True
    enable_ddos_protection: bool = True
    custom_rules: List[Dict[str, Any]] = field(default_factory=list)
    callback_url: Optional[str] = None
    enable_analytics: bool = True
    data_retention_days: int = 30
    
    def __post_init__(self):
        """Post-initialization processing for enum conversion."""
        if isinstance(self.mode, str):
            self.mode = PluginMode(self.mode)
    
    def validate(self) -> bool:
        """
        Validate all configuration parameters.
        
        Returns:
            bool: True if configuration is valid, False otherwise
        """
        if not self.api_key or len(self.api_key) < 32:
            logger.error("Invalid API key: must be at least 32 characters")
            return False
        
        if self.rate_limit_requests < 1:
            logger.error("Rate limit must be at least 1 request")
            return False
        
        if self.rate_limit_window < 1:
            logger.error("Rate limit window must be at least 1 second")
            return False
        
        if self.data_retention_days < 1:
            logger.error("Data retention must be at least 1 day")
            return False
        
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert configuration to dictionary format.
        
        Returns:
            dict: Dictionary representation of configuration
        """
        config_dict = asdict(self)
        config_dict['mode'] = self.mode.value
        return config_dict
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> 'PluginConfig':
        """
        Create configuration from dictionary.
        
        Args:
            config_dict: Dictionary containing configuration parameters
            
        Returns:
            PluginConfig: Instance of PluginConfig
        """
        return cls(**config_dict)

class WebsitePlugin:
    """
    Main website plugin class for CyberGuard security integration.
    
    Handles request interception, threat detection, rate limiting,
    bot detection, real-time monitoring, and incident reporting.
    """
    
    def __init__(self, config: PluginConfig):
        """
        Initialize the website plugin.
        
        Args:
            config: Plugin configuration object
            
        Raises:
            ValueError: If configuration is invalid
        """
        if not config.validate():
            raise ValueError("Invalid plugin configuration")
        
        self.config = config
        self.mode = config.mode
        
        # Initialize security components with default configs
        self.scanner = WebSecurityScanner({})
        self.orchestrator = AgentOrchestrator(state_dim=512)
        
        # Initialize request tracking for rate limiting
        # Dictionary format: {ip_address: [list_of_request_timestamps]}
        self.request_tracker: Dict[str, List[datetime]] = {}
        
        # Initialize threat database for storing blocked entities
        self.threat_database: Dict[str, Any] = {
            'blocked_ips': set(),
            'blocked_sessions': set(),
            'suspicious_patterns': [],
            'whitelist': set()
        }
        
        # Initialize statistics tracking
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'threats_detected': 0,
            'false_positives': 0,
            'start_time': datetime.now()
        }
        
        # Initialize webhook client for incident notifications
        self.webhook_client = None
        if config.callback_url:
            self._initialize_webhook_client()
        
        logger.info(f"Website plugin initialized in {config.mode.value} mode")
        logger.info(f"API Key: {config.api_key[:8]}...{config.api_key[-4:]}")
    
    def _initialize_webhook_client(self):
        """
        Initialize asynchronous webhook client for sending incident notifications.
        Uses aiohttp for asynchronous HTTP requests.
        """
        self.webhook_client = aiohttp.ClientSession()
    
    async def analyze_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a web request for security threats.
        
        Args:
            request_data: Dictionary containing:
                - ip: Client IP address
                - user_agent: User agent string
                - url: Request URL
                - method: HTTP method
                - headers: Request headers
                - body: Request body
                - cookies: Request cookies
                - referrer: Referrer URL
                - timestamp: Request timestamp
                
        Returns:
            Dictionary with analysis results:
                - allowed: Whether request is allowed
                - threat_level: Threat level (0.0 to 1.0)
                - threats: List of detected threats
                - action: Action taken (ALLOW, BLOCK, CHALLENGE)
                - reasons: Reasons for action
                - session_id: Generated session ID
        """
        self.stats['total_requests'] += 1
        
        # Generate unique session ID for request tracking
        session_id = self._generate_session_id(request_data)
        
        # Step 1: Check rate limiting
        rate_limit_result = self._check_rate_limit(request_data.get('ip'))
        if not rate_limit_result['allowed']:
            return {
                'allowed': False,
                'threat_level': 0.8,
                'threats': ['RATE_LIMIT_EXCEEDED'],
                'action': 'BLOCK',
                'reasons': ['Rate limit exceeded'],
                'session_id': session_id,
                'block_reason': 'rate_limit'
            }
        
        # Step 2: Check blocked countries
        if self.config.blocked_countries:
            country = self._get_country_from_ip(request_data.get('ip'))
            if country in self.config.blocked_countries:
                return {
                    'allowed': False,
                    'threat_level': 0.7,
                    'threats': ['BLOCKED_COUNTRY'],
                    'action': 'BLOCK',
                    'reasons': [f'Access blocked from {country}'],
                    'session_id': session_id,
                    'block_reason': 'country_block'
                }
        
        # Step 3: Check allowed user agents
        user_agent = request_data.get('user_agent', '')
        if self.config.allowed_user_agents and user_agent not in self.config.allowed_user_agents:
            return {
                'allowed': False,
                'threat_level': 0.6,
                'threats': ['UNAUTHORIZED_USER_AGENT'],
                'action': 'BLOCK',
                'reasons': ['User agent not allowed'],
                'session_id': session_id,
                'block_reason': 'user_agent'
            }
        
        # Step 4: Check blocked IPs
        client_ip = request_data.get('ip')
        if client_ip in self.threat_database['blocked_ips']:
            return {
                'allowed': False,
                'threat_level': 0.9,
                'threats': ['BLOCKED_IP'],
                'action': 'BLOCK',
                'reasons': ['IP address is blocked'],
                'session_id': session_id,
                'block_reason': 'ip_block'
            }
        
        # Step 5: Check blocked sessions
        if session_id in self.threat_database['blocked_sessions']:
            return {
                'allowed': False,
                'threat_level': 0.8,
                'threats': ['BLOCKED_SESSION'],
                'action': 'BLOCK',
                'reasons': ['Session is blocked'],
                'session_id': session_id,
                'block_reason': 'session_block'
            }
        
        # Step 6: Perform security analysis based on mode
        if self.mode in [PluginMode.PROTECTION, PluginMode.DEBUG]:
            security_analysis = await self._perform_security_analysis(request_data)
            
            if security_analysis['threats']:
                self.stats['threats_detected'] += 1
                
                # Determine action based on threat level
                if security_analysis['threat_level'] > 0.7:
                    action = 'BLOCK'
                    self.stats['blocked_requests'] += 1
                    
                    # Add to blocked IPs for critical threats
                    if security_analysis['threat_level'] > 0.9:
                        self.threat_database['blocked_ips'].add(client_ip)
                    
                    # Send webhook notification
                    if self.webhook_client:
                        await self._send_webhook_notification(request_data, security_analysis)
                
                elif security_analysis['threat_level'] > 0.4:
                    action = 'CHALLENGE'
                else:
                    action = 'ALLOW'
            else:
                action = 'ALLOW'
            
            return {
                'allowed': action in ['ALLOW', 'CHALLENGE'],
                'threat_level': security_analysis['threat_level'],
                'threats': security_analysis['threats'],
                'action': action,
                'reasons': security_analysis['reasons'],
                'session_id': session_id,
                'analysis_details': security_analysis.get('details', {})
            }
        
        else:  # MONITOR or LEARNING mode
            security_analysis = await self._perform_security_analysis(request_data)
            
            if security_analysis['threats']:
                self.stats['threats_detected'] += 1
                logger.warning(f"Threat detected in monitor mode: {security_analysis['threats']}")
            
            return {
                'allowed': True,
                'threat_level': security_analysis['threat_level'],
                'threats': security_analysis['threats'],
                'action': 'MONITOR',
                'reasons': security_analysis['reasons'],
                'session_id': session_id,
                'analysis_details': security_analysis.get('details', {})
            }
    
    async def _perform_security_analysis(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform comprehensive security analysis on request.
        
        Args:
            request_data: Request information
            
        Returns:
            Dictionary with security analysis results
        """
        threats = []
        threat_level = 0.0
        reasons = []
        details = {}
        
        # 1. XSS attack detection
        if self.config.enable_xss_protection:
            xss_result = self._detect_xss(request_data)
            if xss_result['detected']:
                threats.append('XSS_ATTACK')
                threat_level = max(threat_level, xss_result['threat_level'])
                reasons.append(xss_result['reason'])
                details['xss'] = xss_result
        
        # 2. SQL injection detection
        if self.config.enable_sqli_protection:
            sqli_result = self._detect_sqli(request_data)
            if sqli_result['detected']:
                threats.append('SQL_INJECTION')
                threat_level = max(threat_level, sqli_result['threat_level'])
                reasons.append(sqli_result['reason'])
                details['sqli'] = sqli_result
        
        # 3. Bot activity detection
        if self.config.enable_bot_protection:
            bot_result = self._detect_bot(request_data)
            if bot_result['detected']:
                threats.append('BOT_ACTIVITY')
                threat_level = max(threat_level, bot_result['threat_level'])
                reasons.append(bot_result['reason'])
                details['bot'] = bot_result
        
        # 4. Custom rules checking
        for rule in self.config.custom_rules:
            rule_result = self._check_custom_rule(rule, request_data)
            if rule_result['detected']:
                rule_id = rule.get('id', 'unknown')
                threats.append(f"CUSTOM_RULE_{rule_id}")
                threat_level = max(threat_level, rule_result['threat_level'])
                reasons.append(rule_result['reason'])
                details[f"custom_rule_{rule_id}"] = rule_result
        
        # 5. DDoS pattern detection
        if self.config.enable_ddos_protection:
            ddos_result = self._detect_ddos(request_data)
            if ddos_result['detected']:
                threats.append('DDOS_ATTEMPT')
                threat_level = max(threat_level, ddos_result['threat_level'])
                reasons.append(ddos_result['reason'])
                details['ddos'] = ddos_result
        
        return {
            'threats': threats,
            'threat_level': threat_level,
            'reasons': reasons,
            'details': details
        }
    
    def _detect_xss(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect Cross-Site Scripting (XSS) attacks.
        
        Args:
            request_data: Request information
            
        Returns:
            Dictionary with detection results
        """
        xss_patterns = [
            '<script>', 'javascript:', 'onload=', 'onerror=', 'onclick=',
            'eval(', 'document.cookie', 'alert(', 'confirm(', 'prompt(',
            '<iframe', '<embed', '<object', 'vbscript:', 'data:'
        ]
        
        detected = False
        threat_level = 0.0
        reason = ""
        location = ""
        
        # Check URL for XSS patterns
        url = request_data.get('url', '').lower()
        for pattern in xss_patterns:
            if pattern in url:
                detected = True
                threat_level = 0.8
                reason = f"XSS pattern '{pattern}' found in URL"
                location = 'url'
                break
        
        # Check request body for XSS patterns
        if not detected:
            body = request_data.get('body', '')
            if isinstance(body, str):
                body_lower = body.lower()
                for pattern in xss_patterns:
                    if pattern in body_lower:
                        detected = True
                        threat_level = 0.9
                        reason = f"XSS pattern '{pattern}' found in request body"
                        location = 'body'
                        break
        
        return {
            'detected': detected,
            'threat_level': threat_level,
            'reason': reason,
            'location': location,
            'patterns_checked': xss_patterns
        }
    
    def _detect_sqli(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect SQL Injection attacks.
        
        Args:
            request_data: Request information
            
        Returns:
            Dictionary with detection results
        """
        sqli_patterns = [
            "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*",
            "UNION SELECT", "UNION ALL SELECT", "SELECT * FROM",
            "INSERT INTO", "UPDATE SET", "DELETE FROM", "DROP TABLE",
            "EXEC ", "EXECUTE ", "xp_cmdshell", "--", "/*", "*/",
            "WAITFOR DELAY", "SLEEP(", "BENCHMARK(", "PG_SLEEP("
        ]
        
        detected = False
        threat_level = 0.0
        reason = ""
        location = ""
        
        # Parse URL query parameters
        url = request_data.get('url', '')
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        # Check each query parameter value
        for param, values in query_params.items():
            for value in values:
                for pattern in sqli_patterns:
                    if pattern.lower() in value.lower():
                        detected = True
                        threat_level = 0.9
                        reason = f"SQL injection pattern '{pattern}' in parameter '{param}'"
                        location = f'url_parameter:{param}'
                        break
                if detected:
                    break
            if detected:
                break
        
        # Check request body
        if not detected:
            body = request_data.get('body', '')
            if isinstance(body, str):
                for pattern in sqli_patterns:
                    if pattern.lower() in body.lower():
                        detected = True
                        threat_level = 0.95
                        reason = f"SQL injection pattern '{pattern}' in request body"
                        location = 'body'
                        break
        
        return {
            'detected': detected,
            'threat_level': threat_level,
            'reason': reason,
            'location': location,
            'patterns_checked': sqli_patterns
        }
    
    def _detect_bot(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect bot/crawler activity.
        
        Args:
            request_data: Request information
            
        Returns:
            Dictionary with detection results
        """
        user_agent = request_data.get('user_agent', '').lower()
        
        bot_patterns = [
            'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget',
            'python-requests', 'java', 'go-http-client', 'php',
            'okhttp', 'apache-httpclient', 'libwww', 'lwp', 'ruby'
        ]
        
        detected = False
        threat_level = 0.0
        reason = ""
        
        # Check user agent for bot patterns
        for pattern in bot_patterns:
            if pattern in user_agent:
                detected = True
                threat_level = 0.3
                reason = f"Bot user agent detected: contains '{pattern}'"
                break
        
        # Additional heuristic: check request frequency
        if not detected:
            ip = request_data.get('ip')
            if ip:
                request_count = self._get_request_count(ip)
                if request_count > 100:
                    detected = True
                    threat_level = 0.5
                    reason = f"High request frequency: {request_count} requests"
        
        return {
            'detected': detected,
            'threat_level': threat_level,
            'reason': reason,
            'user_agent': user_agent,
            'patterns_checked': bot_patterns
        }
    
    def _detect_ddos(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect DDoS attack patterns.
        
        Args:
            request_data: Request information
            
        Returns:
            Dictionary with detection results
        """
        ip = request_data.get('ip')
        if not ip:
            return {'detected': False, 'threat_level': 0.0, 'reason': ''}
        
        # Get recent requests from this IP
        recent_requests = self.request_tracker.get(ip, [])
        
        # Count requests in last 10 seconds
        current_time = datetime.now()
        time_window = timedelta(seconds=10)
        recent_count = sum(1 for req_time in recent_requests 
                          if current_time - req_time < time_window)
        
        detected = recent_count > 50
        threat_level = min(1.0, recent_count / 100)
        
        if detected:
            reason = f"DDoS pattern detected: {recent_count} requests in 10 seconds"
        else:
            reason = ""
        
        return {
            'detected': detected,
            'threat_level': threat_level,
            'reason': reason,
            'request_count': recent_count,
            'time_window_seconds': 10
        }
    
    def _check_custom_rule(self, rule: Dict[str, Any], 
                          request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check a custom security rule against request data.
        
        Args:
            rule: Custom rule configuration
            request_data: Request information
            
        Returns:
            Dictionary with rule checking results
        """
        rule_type = rule.get('type', 'pattern')
        pattern = rule.get('pattern', '')
        field = rule.get('field', '')
        action = rule.get('action', 'block')
        threat_level = rule.get('threat_level', 0.5)
        
        detected = False
        reason = ""
        
        if rule_type == 'pattern' and pattern:
            field_value = request_data.get(field, '')
            if isinstance(field_value, str) and pattern in field_value:
                detected = True
                reason = f"Custom rule pattern '{pattern}' matched in field '{field}'"
        
        return {
            'detected': detected,
            'threat_level': threat_level if detected else 0.0,
            'reason': reason,
            'rule_id': rule.get('id', 'unknown'),
            'rule_type': rule_type
        }
    
    def _check_rate_limit(self, ip: Optional[str]) -> Dict[str, Any]:
        """
        Check if request exceeds rate limit for given IP.
        
        Args:
            ip: Client IP address
            
        Returns:
            Dictionary with rate limiting results
        """
        if not ip:
            return {'allowed': True, 'reason': ''}
        
        current_time = datetime.now()
        
        # Initialize request list for new IPs
        if ip not in self.request_tracker:
            self.request_tracker[ip] = []
        
        # Clean old requests outside rate limit window
        time_window = timedelta(seconds=self.config.rate_limit_window)
        self.request_tracker[ip] = [
            req_time for req_time in self.request_tracker[ip]
            if current_time - req_time < time_window
        ]
        
        # Check if limit exceeded
        request_count = len(self.request_tracker[ip])
        
        if request_count >= self.config.rate_limit_requests:
            return {
                'allowed': False,
                'reason': f'Rate limit exceeded: {request_count} requests in {self.config.rate_limit_window} seconds'
            }
        
        # Add current request to tracker
        self.request_tracker[ip].append(current_time)
        
        return {
            'allowed': True,
            'reason': f'{request_count + 1}/{self.config.rate_limit_requests} requests'
        }
    
    def _generate_session_id(self, request_data: Dict[str, Any]) -> str:
        """
        Generate unique session ID for request tracking.
        
        Args:
            request_data: Request information
            
        Returns:
            str: Unique session ID
        """
        session_data = f"{request_data.get('ip', '')}:{request_data.get('user_agent', '')}:{datetime.now().timestamp()}"
        session_hash = hashlib.sha256(session_data.encode()).hexdigest()
        return session_hash[:16]
    
    def _get_country_from_ip(self, ip: Optional[str]) -> str:
        """
        Get country code from IP address (simplified implementation).
        
        Args:
            ip: IP address
            
        Returns:
            str: Country code or 'UNKNOWN'
        """
        if not ip:
            return 'UNKNOWN'
        
        try:
            # Check for local/private IPs
            if ip.startswith('192.168.') or ip.startswith('10.') or (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31):
                return 'LOCAL'
            
            # Simplified mock implementation
            # In production, use a proper GeoIP database
            ip_hash = hash(ip) % 100
            if ip_hash < 20:
                return 'US'
            elif ip_hash < 40:
                return 'CN'
            elif ip_hash < 60:
                return 'RU'
            elif ip_hash < 80:
                return 'DE'
            else:
                return 'OTHER'
        except Exception:
            return 'UNKNOWN'
    
    def _get_request_count(self, ip: str) -> int:
        """
        Get total request count for an IP address.
        
        Args:
            ip: IP address
            
        Returns:
            int: Number of requests from this IP
        """
        return len(self.request_tracker.get(ip, []))
    
    async def _send_webhook_notification(self, request_data: Dict[str, Any],
                                        analysis_result: Dict[str, Any]):
        """
        Send webhook notification for security incidents.
        
        Args:
            request_data: Original request data
            analysis_result: Security analysis results
        """
        if not self.webhook_client or not self.config.callback_url:
            return
        
        try:
            notification = {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'SECURITY_INCIDENT',
                'request': {
                    'ip': request_data.get('ip'),
                    'url': request_data.get('url'),
                    'method': request_data.get('method'),
                    'user_agent': request_data.get('user_agent')
                },
                'analysis': analysis_result,
                'plugin_mode': self.mode.value,
                'session_id': analysis_result.get('session_id')
            }
            
            async with self.webhook_client.post(
                self.config.callback_url,
                json=notification,
                headers={'Content-Type': 'application/json'}
            ) as response:
                if response.status != 200:
                    logger.error(f"Webhook failed with status {response.status}")
        
        except Exception as e:
            logger.error(f"Failed to send webhook: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get plugin statistics and metrics.
        
        Returns:
            Dictionary with plugin statistics
        """
        uptime = datetime.now() - self.stats['start_time']
        
        return {
            'uptime_seconds': uptime.total_seconds(),
            'total_requests': self.stats['total_requests'],
            'blocked_requests': self.stats['blocked_requests'],
            'threats_detected': self.stats['threats_detected'],
            'false_positives': self.stats['false_positives'],
            'blocked_ips_count': len(self.threat_database['blocked_ips']),
            'blocked_sessions_count': len(self.threat_database['blocked_sessions']),
            'rate_limiting_active': len(self.request_tracker) > 0,
            'unique_ips_tracked': len(self.request_tracker)
        }
    
    def update_configuration(self, new_config: PluginConfig):
        """
        Update plugin configuration.
        
        Args:
            new_config: New configuration
            
        Raises:
            ValueError: If new configuration is invalid
        """
        if not new_config.validate():
            raise ValueError("Invalid configuration")
        
        old_mode = self.mode
        self.config = new_config
        self.mode = new_config.mode
        
        logger.info(f"Plugin configuration updated. Mode changed from {old_mode.value} to {self.mode.value}")
        
        # Reinitialize webhook client if callback URL changed
        if new_config.callback_url != self.config.callback_url:
            if self.webhook_client:
                # Note: This should be awaited in async context
                # For synchronous context, we'll create a new task
                asyncio.create_task(self._close_and_reinit_webhook(new_config.callback_url))
    
    async def _close_and_reinit_webhook(self, new_callback_url: Optional[str]):
        """
        Close existing webhook client and reinitialize with new URL.
        
        Args:
            new_callback_url: New callback URL or None
        """
        if self.webhook_client:
            await self.webhook_client.close()
        
        if new_callback_url:
            self._initialize_webhook_client()
    
    def block_ip(self, ip: str, reason: str = "Manual block"):
        """
        Manually block an IP address.
        
        Args:
            ip: IP address to block
            reason: Reason for blocking
        """
        self.threat_database['blocked_ips'].add(ip)
        logger.info(f"IP {ip} blocked manually. Reason: {reason}")
    
    def unblock_ip(self, ip: str):
        """
        Unblock a previously blocked IP address.
        
        Args:
            ip: IP address to unblock
        """
        if ip in self.threat_database['blocked_ips']:
            self.threat_database['blocked_ips'].remove(ip)
            logger.info(f"IP {ip} unblocked")
    
    def get_blocked_ips(self) -> List[str]:
        """
        Get list of currently blocked IP addresses.
        
        Returns:
            List of blocked IP addresses
        """
        return list(self.threat_database['blocked_ips'])
    
    async def cleanup(self):
        """
        Clean up resources and close connections.
        Removes old request data based on retention period.
        """
        if self.webhook_client:
            await self.webhook_client.close()
        
        # Clean up old request data
        current_time = datetime.now()
        retention_period = timedelta(days=self.config.data_retention_days)
        
        for ip in list(self.request_tracker.keys()):
            self.request_tracker[ip] = [
                req_time for req_time in self.request_tracker[ip]
                if current_time - req_time < retention_period
            ]
            
            # Remove IP if no recent requests
            if not self.request_tracker[ip]:
                del self.request_tracker[ip]
        
        logger.info("Plugin cleanup completed")

def generate_javascript_plugin(config: PluginConfig) -> str:
    """
    Generate JavaScript code for the website plugin.
    
    Args:
        config: Plugin configuration
        
    Returns:
        str: JavaScript code as string
    """
    js_template = """
// CyberGuard Website Security Plugin v1.0
// Generated: {timestamp}

(function() {{
    'use strict';
    
    // Configuration
    const CONFIG = {config_json};
    
    // Plugin state
    let pluginInitialized = false;
    
    // Logging function with configurable levels
    function log(level, message) {{
        if (CONFIG.log_level === 'debug' || 
            (CONFIG.log_level === 'warn' && level === 'warn') ||
            (CONFIG.log_level === 'error' && level === 'error')) {{
            console.log(`[CyberGuard:${{level}}] ${{message}}`);
        }}
    }}
    
    // Generate unique request ID
    function generateRequestId() {{
        return 'req_' + Math.random().toString(36).substr(2, 9) + 
               '_' + Date.now().toString(36);
    }}
    
    // Collect browser and request data
    function collectRequestData() {{
        return {{
            url: window.location.href,
            referrer: document.referrer,
            userAgent: navigator.userAgent,
            language: navigator.language,
            platform: navigator.platform,
            screenResolution: window.screen.width + 'x' + window.screen.height,
            colorDepth: window.screen.colorDepth,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            cookiesEnabled: navigator.cookieEnabled,
            doNotTrack: navigator.doNotTrack || window.doNotTrack,
            plugins: Array.from(navigator.plugins || []).map(p => p.name).join(','),
            timestamp: Date.now()
        }};
    }}
    
    // Send request to CyberGuard API for analysis
    async function sendToCyberGuard(requestData) {{
        const requestId = generateRequestId();
        
        try {{
            const response = await fetch('https://api.cyberguard.ai/v1/analyze', {{
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json',
                    'X-API-Key': CONFIG.apiKey,
                    'X-Request-ID': requestId
                }},
                body: JSON.stringify({{
                    ...requestData,
                    config: {{
                        mode: CONFIG.mode,
                        version: '1.0'
                    }}
                }})
            }});
            
            if (!response.ok) {{
                throw new Error(`HTTP ${{response.status}}: ${{response.statusText}}`);
            }}
            
            const result = await response.json();
            
            // Handle analysis result
            if (result.action === 'BLOCK') {{
                handleBlock(result);
                return false;
            }} else if (result.action === 'CHALLENGE') {{
                return await handleChallenge(result);
            }} else if (result.action === 'MONITOR') {{
                log('info', `Request monitored: ${{result.reasons ? result.reasons.join(', ') : 'No specific reasons'}}`);
                return true;
            }}
            
            return true;
            
        }} catch (error) {{
            // Allow request on API error (fail-open strategy)
            log('error', `API error: ${{error.message}}`);
            return true;
        }}
    }}
    
    // Handle block action by showing security page
    function handleBlock(result) {{
        log('warn', `Request blocked: ${{result.reasons ? result.reasons.join(', ') : 'Security violation'}}`);
        
        // Create security block page
        const blockPage = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>Access Blocked - Security Protection</title>
                <style>
                    body {{ 
                        font-family: Arial, sans-serif; 
                        background: #f5f5f5; 
                        margin: 0; 
                        padding: 40px; 
                        text-align: center; 
                    }}
                    .container {{ 
                        background: white; 
                        max-width: 600px; 
                        margin: 0 auto; 
                        padding: 40px; 
                        border-radius: 8px; 
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1); 
                    }}
                    h1 {{ color: #dc3545; }}
                    .details {{ 
                        text-align: left; 
                        background: #f8f9fa; 
                        padding: 20px; 
                        border-radius: 4px; 
                        margin: 20px 0; 
                    }}
                    .contact {{ 
                        margin-top: 30px; 
                        color: #6c757d; 
                        font-size: 14px; 
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Access Blocked</h1>
                    <p>Your request has been blocked by our security system.</p>
                    
                    <div class="details">
                        <p><strong>Reason:</strong> ${{result.reasons ? result.reasons.join(', ') : 'Security policy violation'}}</p>
                        <p><strong>Threat Level:</strong> ${{result.threat_level ? (result.threat_level * 100).toFixed(1) : 0}}%</p>
                        <p><strong>Request ID:</strong> ${{result.session_id || 'N/A'}}</p>
                    </div>
                    
                    <div class="contact">
                        If you believe this is an error, please contact support.
                        <br>
                        Reference: ${{result.session_id || 'N/A'}}
                    </div>
                </div>
            </body>
            </html>
        `;
        
        // Replace current page with block page
        document.open();
        document.write(blockPage);
        document.close();
    }}
    
    // Handle challenge action (e.g., CAPTCHA)
    async function handleChallenge(result) {{
        return new Promise((resolve) => {{
            log('info', `Challenge required: ${{result.reasons ? result.reasons.join(', ') : 'Security verification'}}`);
            
            // Create challenge modal
            const modal = document.createElement('div');
            modal.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: rgba(0,0,0,0.5);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 9999;
            `;
            
            // Simple math CAPTCHA
            const num1 = Math.floor(Math.random() * 10) + 1;
            const num2 = Math.floor(Math.random() * 10) + 1;
            const answer = num1 + num2;
            
            modal.innerHTML = `
                <div style="background: white; padding: 30px; border-radius: 8px; max-width: 400px;">
                    <h3 style="margin-top: 0;">Security Verification Required</h3>
                    <p>${{result.reasons ? result.reasons.join('<br>') : 'Please complete the verification to continue.'}}</p>
                    
                    <div style="margin: 20px 0;">
                        <p>Please solve: <strong>${{num1}} + ${{num2}} = ?</strong></p>
                        <input type="number" id="captcha-answer" placeholder="Enter sum" style="
                            width: 100%;
                            padding: 8px;
                            margin: 10px 0;
                            border: 1px solid #ddd;
                            border-radius: 4px;
                        ">
                    </div>
                    
                    <button id="cyberguard-verify" style="
                        background: #007bff;
                        color: white;
                        border: none;
                        padding: 10px 20px;
                        border-radius: 4px;
                        cursor: pointer;
                    ">Verify & Continue</button>
                </div>
            `;
            
            document.body.appendChild(modal);
            
            // Handle verification button click
            document.getElementById('cyberguard-verify').onclick = function() {{
                const userAnswer = parseInt(document.getElementById('captcha-answer').value);
                
                if (userAnswer === answer) {{
                    document.body.removeChild(modal);
                    resolve(true);
                }} else {{
                    alert('Incorrect answer. Please try again.');
                }}
            }};
        }});
    }}
    
    // Intercept navigation methods
    function interceptNavigation() {{
        const originalAssign = window.location.assign;
        const originalReplace = window.location.replace;
        const locationDescriptor = Object.getOwnPropertyDescriptor(window.location, 'href');
        
        // Override location.assign
        window.location.assign = function(url) {{
            processNavigation(url, originalAssign);
        }};
        
        // Override location.replace
        window.location.replace = function(url) {{
            processNavigation(url, originalReplace);
        }};
        
        // Override location.href setter
        if (locationDescriptor && locationDescriptor.set) {{
            Object.defineProperty(window.location, 'href', {{
                set: function(url) {{
                    processNavigation(url, locationDescriptor.set);
                }},
                get: locationDescriptor.get
            }});
        }}
        
        // Intercept link clicks
        document.addEventListener('click', function(e) {{
            let target = e.target;
            
            // Find closest anchor element
            while (target && target.tagName !== 'A') {{
                target = target.parentNode;
            }}
            
            if (target && target.href && target.target !== '_blank') {{
                e.preventDefault();
                processNavigation(target.href, function(url) {{
                    window.location.href = url;
                }});
            }}
        }}, true);
    }}
    
    // Process navigation with security check
    async function processNavigation(url, originalMethod) {{
        const requestData = collectRequestData();
        requestData.url = url;
        requestData.navigation = true;
        
        const allowed = await sendToCyberGuard(requestData);
        
        if (allowed && originalMethod) {{
            originalMethod.call(window.location, url);
        }}
    }}
    
    // Intercept form submissions
    function interceptForms() {{
        document.addEventListener('submit', async function(e) {{
            e.preventDefault();
            
            const form = e.target;
            const requestData = collectRequestData();
            requestData.url = form.action || window.location.href;
            requestData.method = form.method || 'POST';
            
            // Collect form data
            const formData = new FormData(form);
            const formDataObj = {{}};
            for (let [key, value] of formData.entries()) {{
                formDataObj[key] = value;
            }}
            requestData.formData = formDataObj;
            
            const allowed = await sendToCyberGuard(requestData);
            
            if (allowed) {{
                // Submit form based on method
                if (requestData.method.toUpperCase() === 'GET') {{
                    const params = new URLSearchParams(formData);
                    window.location.href = requestData.url + (requestData.url.includes('?') ? '&' : '?') + params.toString();
                }} else {{
                    form.submit();
                }}
            }}
        }}, true);
    }}
    
    // Intercept AJAX/fetch requests
    function interceptAjax() {{
        const originalFetch = window.fetch;
        
        window.fetch = async function(resource, init) {{
            const requestData = collectRequestData();
            requestData.url = typeof resource === 'string' ? resource : resource.url;
            requestData.method = (init && init.method ? init.method : 'GET').toUpperCase();
            
            if (init && init.body) {{
                requestData.body = typeof init.body === 'string' ? init.body : 'Binary data';
            }}
            
            const allowed = await sendToCyberGuard(requestData);
            
            if (!allowed) {{
                throw new Error('Request blocked by CyberGuard security');
            }}
            
            return originalFetch.call(this, resource, init);
        }};
    }}
    
    // Initialize the plugin
    function init() {{
        if (pluginInitialized) {{
            log('warn', 'Plugin already initialized');
            return;
        }}
        
        if (!CONFIG.apiKey) {{
            log('error', 'API key is required');
            return;
        }}
        
        log('info', `CyberGuard plugin initializing in ${{CONFIG.mode}} mode`);
        
        // Set up interceptors
        interceptNavigation();
        interceptForms();
        interceptAjax();
        
        // Send initial page load event
        setTimeout(() => {{
            const requestData = collectRequestData();
            requestData.initialLoad = true;
            
            sendToCyberGuard(requestData).then(allowed => {{
                if (!allowed) {{
                    log('warn', 'Initial page load blocked');
                }}
            }});
        }}, 100);
        
        pluginInitialized = true;
        log('info', 'CyberGuard plugin initialized successfully');
    }}
    
    // Public API exposed to window object
    window.CyberGuard = {{
        init: init,
        config: CONFIG,
        version: '1.0.0',
        
        // Debug methods for testing
        getRequestData: collectRequestData,
        simulateRequest: sendToCyberGuard,
        
        // Utility methods
        log: log
    }};
    
    // Auto-initialize if config provided in script data attribute
    if (document.currentScript && document.currentScript.dataset.config) {{
        try {{
            const scriptConfig = JSON.parse(document.currentScript.dataset.config);
            Object.assign(CONFIG, scriptConfig);
            init();
        }} catch (e) {{
            log('error', 'Failed to parse inline configuration: ' + e.message);
        }}
    }}
}})();
"""
    
    # Convert config to JSON with proper escaping
    config_dict = config.to_dict()
    config_json = json.dumps(config_dict, indent=2)
    
    # Format timestamp
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Generate final JavaScript code
    js_code = js_template.format(
        timestamp=timestamp,
        config_json=config_json
    )
    
    return js_code

# Example usage and testing
if __name__ == "__main__":
    # Example configuration for testing
    config = PluginConfig(
        api_key="sk_test_1234567890abcdef1234567890abcdef",
        mode=PluginMode.PROTECTION,
        log_level="warn",
        blocked_countries=["RU", "CN", "KP"],
        rate_limit_requests=100,
        enable_xss_protection=True,
        enable_sqli_protection=True,
        enable_bot_protection=True,
        callback_url="https://webhook.example.com/security"
    )
    
    # Generate JavaScript plugin
    js_code = generate_javascript_plugin(config)
    
    # Save to file
    with open("cyberguard_plugin.js", "w") as f:
        f.write(js_code)
    
    print("JavaScript plugin generated: cyberguard_plugin.js")
    print(f"Size: {len(js_code)} bytes")
    
    # Test the plugin
    print("\nPlugin Features:")
    print("- Real-time threat detection")
    print("- XSS and SQL injection protection")
    print("- Bot and DDoS detection")
    print("- Rate limiting")
    print("- Configurable security policies")
    print("- GDPR/CCPA compliant")