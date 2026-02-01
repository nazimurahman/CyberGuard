"""
Reverse Proxy Security Layer for CyberGuard
============================================
A full-featured reverse proxy that provides comprehensive security protection
for web applications. Can be deployed as a standalone service or integrated
with existing proxy infrastructure.
"""

import asyncio
import aiohttp
import ssl
import json
import time
import hashlib
import base64
import os
import gzip
from typing import Dict, List, Any, Optional, Tuple, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from enum import Enum
import logging
import urllib.parse
import ipaddress
import re

# Local imports - Fixed import structure
try:
    from .website_plugin import WebsitePlugin
    from .plugin_config import PluginConfig, PluginMode  # Added missing import
    from ..web_security.scanner import WebSecurityScanner
    from ..agents.agent_orchestrator import AgentOrchestrator
    from ..utils.crypto_utils import generate_hmac, validate_signature
except ImportError:
    # Fallback for testing/example usage
    class WebsitePlugin:
        def __init__(self, config):
            self.config = config
        
        async def analyze_request(self, request):
            return {'allowed': True, 'threat_level': 'low', 'threats': [], 'action': 'allow'}
    
    class PluginConfig:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)
    
    class PluginMode(Enum):
        PROTECTION = "protection"
        MONITORING = "monitoring"
    
    class WebSecurityScanner:
        def __init__(self, config):
            self.config = config
    
    class AgentOrchestrator:
        def __init__(self, config):
            self.config = config

# Configure module logger
logger = logging.getLogger(__name__)

class ProxyMode(Enum):
    """Operation modes for the reverse proxy"""
    TRANSPARENT = "transparent"     # Pass-through with monitoring
    PROTECTIVE = "protective"       # Active protection with blocking
    LEARNING = "learning"          # Learn patterns without blocking
    MAINTENANCE = "maintenance"    # Maintenance mode with custom responses

class SSLConfig:
    """SSL/TLS configuration for the reverse proxy"""
    
    def __init__(self, cert_path: str, key_path: str, 
                 ca_path: Optional[str] = None):
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_path = ca_path
        
        # Validate paths exist
        self._validate_paths()
    
    def _validate_paths(self):
        """Validate that SSL certificate files exist"""
        if not os.path.exists(self.cert_path):
            raise FileNotFoundError(f"Certificate file not found: {self.cert_path}")
        
        if not os.path.exists(self.key_path):
            raise FileNotFoundError(f"Key file not found: {self.key_path}")
        
        if self.ca_path and not os.path.exists(self.ca_path):
            raise FileNotFoundError(f"CA file not found: {self.ca_path}")
    
    def create_ssl_context(self) -> ssl.SSLContext:
        """
        Create SSL context for secure connections.
        
        Returns:
            Configured SSL context
        """
        # Create SSL context with modern security settings
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(self.cert_path, self.key_path)
        
        if self.ca_path:
            ssl_context.load_verify_locations(self.ca_path)
        
        # Configure for maximum security
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20')
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        
        return ssl_context

@dataclass
class ProxyConfig:
    """
    Configuration for the reverse proxy security layer.
    
    Attributes:
        backend_url: URL of the backend server to protect
        mode: Proxy operation mode (default: PROTECTIVE)
        port: Port to listen on (default: 8080)
        ssl_config: SSL configuration for HTTPS (optional)
        enable_compression: Enable response compression (default: True)
        enable_caching: Enable response caching (default: True)
        cache_ttl: Cache TTL in seconds (default: 300)
        rate_limit_requests: Max requests per IP per minute (default: 100)
        rate_limit_window: Rate limit window in seconds (default: 60)
        max_request_size: Maximum request size in bytes (default: 10MB)
        max_response_size: Maximum response size in bytes (default: 100MB)
        timeout: Request timeout in seconds (default: 30)
        health_check_path: Path for health checks (default: /health)
        health_check_interval: Health check interval in seconds (default: 30)
        blocked_paths: List of paths to block
        allowed_methods: List of allowed HTTP methods
        custom_error_pages: Custom error pages for blocked requests
        enable_access_logs: Enable access logging (default: True)
        enable_security_logs: Enable security event logging (default: True)
        log_format: Log format string
    """
    backend_url: str
    mode: ProxyMode = ProxyMode.PROTECTIVE
    port: int = 8080
    ssl_config: Optional[SSLConfig] = None
    enable_compression: bool = True
    enable_caching: bool = True
    cache_ttl: int = 300
    rate_limit_requests: int = 100
    rate_limit_window: int = 60
    max_request_size: int = 10 * 1024 * 1024  # 10MB
    max_response_size: int = 100 * 1024 * 1024  # 100MB
    timeout: int = 30
    health_check_path: str = "/health"
    health_check_interval: int = 30
    blocked_paths: List[str] = field(default_factory=list)
    allowed_methods: List[str] = field(default_factory=lambda: [
        "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"
    ])
    custom_error_pages: Dict[int, str] = field(default_factory=dict)
    enable_access_logs: bool = True
    enable_security_logs: bool = True
    log_format: str = '%(asctime)s - %(client_ip)s - "%(request_line)s" - %(status_code)s - %(response_time)s'
    
    def validate(self) -> bool:
        """Validate configuration parameters"""
        # Validate backend URL
        try:
            parsed_url = urllib.parse.urlparse(self.backend_url)
            if not parsed_url.scheme or not parsed_url.netloc:
                logger.error("Invalid backend URL")
                return False
        except Exception as e:
            logger.error(f"Invalid backend URL format: {e}")
            return False
        
        # Validate port range
        if not 1 <= self.port <= 65535:
            logger.error(f"Invalid port: {self.port}")
            return False
        
        # Validate rate limiting parameters
        if self.rate_limit_requests < 1:
            logger.error("Rate limit must be at least 1")
            return False
        
        if self.rate_limit_window < 1:
            logger.error("Rate limit window must be at least 1 second")
            return False
        
        # Validate timeout values
        if self.timeout < 1:
            logger.error("Timeout must be at least 1 second")
            return False
        
        if self.health_check_interval < 1:
            logger.error("Health check interval must be at least 1 second")
            return False
        
        # Validate size limits
        if self.max_request_size < 1024:  # At least 1KB
            logger.error("Max request size must be at least 1KB")
            return False
        
        if self.max_response_size < 1024:
            logger.error("Max response size must be at least 1KB")
            return False
        
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        config_dict = asdict(self)
        config_dict['mode'] = self.mode.value
        
        # Handle SSL config serialization
        if self.ssl_config:
            config_dict['ssl_config'] = {
                'cert_path': self.ssl_config.cert_path,
                'key_path': self.ssl_config.key_path,
                'ca_path': self.ssl_config.ca_path
            }
        
        return config_dict

class ReverseProxySecurityLayer:
    """
    Reverse proxy with integrated security features.
    
    This class provides:
    - Request/response interception
    - Security analysis and filtering
    - Rate limiting and DDoS protection
    - SSL/TLS termination
    - Load balancing (future)
    - Health monitoring
    """
    
    def __init__(self, config: ProxyConfig):
        """
        Initialize the reverse proxy security layer.
        
        Args:
            config: Proxy configuration object
            
        Raises:
            ValueError: If configuration is invalid
        """
        # Validate configuration
        if not config.validate():
            raise ValueError("Invalid proxy configuration")
        
        self.config = config
        self.mode = config.mode
        
        # Parse backend URL to extract host and port
        self.backend_url = config.backend_url
        parsed_backend = urllib.parse.urlparse(self.backend_url)
        self.backend_host = parsed_backend.hostname
        self.backend_port = parsed_backend.port or (443 if parsed_backend.scheme == 'https' else 80)
        
        # Initialize security components with proper configuration
        try:
            # Use PluginMode from imports or fallback
            plugin_mode = getattr(PluginMode, 'PROTECTION', 'protection')
            plugin_config = PluginConfig(
                api_key="proxy_integration_key",
                mode=plugin_mode,
                rate_limit_requests=config.rate_limit_requests,
                rate_limit_window=config.rate_limit_window
            )
            self.security_plugin = WebsitePlugin(plugin_config)
        except Exception as e:
            logger.warning(f"Could not initialize security plugin: {e}")
            self.security_plugin = None
        
        # Initialize security scanner
        self.security_scanner = WebSecurityScanner({})
        
        # Initialize HTTP session for backend communication (will be created in start())
        self.backend_session = None
        
        # Initialize cache for storing responses
        self.cache = {}
        self.cache_hits = 0
        self.cache_misses = 0
        
        # Initialize rate limiting system
        self.rate_limiter = RateLimiter(
            requests_per_minute=config.rate_limit_requests,
            window_seconds=config.rate_limit_window
        )
        
        # Initialize request tracker for monitoring active requests
        self.request_tracker = RequestTracker()
        
        # Initialize health monitor for backend status checking
        self.health_monitor = HealthMonitor(
            backend_url=self.backend_url,
            check_interval=config.health_check_interval,
            health_check_path=config.health_check_path
        )
        
        # Initialize statistics collection
        self.stats = {
            'start_time': datetime.now(),
            'total_requests': 0,
            'blocked_requests': 0,
            'passed_requests': 0,
            'backend_errors': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'bytes_transferred': 0,
            'avg_response_time': 0.0
        }
        
        # Initialize middleware chain for request processing
        self.middleware_chain: List[Callable] = []
        
        # Initialize SSL context if configured
        self.ssl_context = None
        if config.ssl_config:
            try:
                self.ssl_context = config.ssl_config.create_ssl_context()
            except Exception as e:
                logger.error(f"Failed to create SSL context: {e}")
                raise
        
        logger.info(f"Reverse proxy initialized for backend: {self.backend_url}")
        logger.info(f"Mode: {self.mode.value}, Port: {config.port}")
        logger.info(f"SSL Enabled: {self.ssl_context is not None}")
    
    async def start(self):
        """Start the reverse proxy server."""
        try:
            # Start health monitoring in background
            asyncio.create_task(self.health_monitor.start())
            
            # Initialize backend HTTP session with timeout configuration
            self.backend_session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.config.timeout)
            )
            
            # Start HTTP/HTTPS server based on SSL configuration
            if self.ssl_context:
                # Start HTTPS server with SSL encryption
                server = await asyncio.start_server(
                    self.handle_request,
                    host='0.0.0.0',  # Listen on all interfaces
                    port=self.config.port,
                    ssl=self.ssl_context
                )
                logger.info(f"HTTPS reverse proxy started on port {self.config.port}")
            else:
                # Start HTTP server (no encryption)
                server = await asyncio.start_server(
                    self.handle_request,
                    host='0.0.0.0',
                    port=self.config.port
                )
                logger.info(f"HTTP reverse proxy started on port {self.config.port}")
            
            # Run server indefinitely until shutdown
            async with server:
                await server.serve_forever()
                
        except Exception as e:
            logger.error(f"Failed to start reverse proxy: {e}")
            raise
        finally:
            # Ensure cleanup on exit
            await self.cleanup()
    
    async def handle_request(self, reader: asyncio.StreamReader, 
                           writer: asyncio.StreamWriter):
        """
        Handle incoming HTTP request.
        
        Args:
            reader: Stream reader for incoming data
            writer: Stream writer for outgoing data
        """
        start_time = time.time()
        # Extract client IP from connection info
        client_ip = writer.get_extra_info('peername')[0] if writer.get_extra_info('peername') else 'unknown'
        
        try:
            # Parse HTTP request from incoming stream
            request_data = await self.parse_http_request(reader, client_ip)
            
            # Update total request count
            self.stats['total_requests'] += 1
            
            # Pre-process request to check if it should be allowed
            should_process = await self.pre_process_request(request_data, client_ip)
            
            if not should_process:
                # Send 403 Forbidden response for blocked requests
                await self.send_error_response(
                    writer, 403, "Request blocked by security policy", client_ip
                )
                self.stats['blocked_requests'] += 1
                return
            
            # Process request through middleware chain for modifications
            processed_request = await self.process_through_middleware(request_data)
            
            # Generate cache key for this request
            cache_key = self.generate_cache_key(processed_request)
            
            # Check cache if enabled
            cached_response = None
            if self.config.enable_caching:
                cached_response = self.cache.get(cache_key)
                if cached_response and time.time() - cached_response['timestamp'] < self.config.cache_ttl:
                    # Serve response from cache
                    response_data = cached_response['response']
                    self.stats['cache_hits'] += 1
                    logger.debug(f"Cache hit for {processed_request['path']}")
                else:
                    cached_response = None
            
            if not cached_response:
                # Forward request to backend server
                response_data = await self.forward_to_backend(processed_request)
                self.stats['cache_misses'] += 1
                
                # Cache response if appropriate
                if self.config.enable_caching and self.should_cache_response(response_data):
                    self.cache[cache_key] = {
                        'response': response_data,
                        'timestamp': time.time()
                    }
                    logger.debug(f"Cached response for {processed_request['path']}")
            
            # Process response through security checks and optimizations
            processed_response = await self.process_response(response_data, processed_request)
            
            # Send processed response back to client
            await self.send_response(writer, processed_response, client_ip)
            
            # Update performance statistics
            self.stats['passed_requests'] += 1
            response_time = time.time() - start_time
            self.stats['bytes_transferred'] += len(str(processed_response))
            # Calculate moving average for response time
            self.stats['avg_response_time'] = (
                self.stats['avg_response_time'] * 0.9 + response_time * 0.1
            )
            
            # Log access if enabled in configuration
            if self.config.enable_access_logs:
                self.log_access(request_data, processed_response, client_ip, response_time)
            
        except asyncio.TimeoutError:
            # Handle request timeout
            logger.warning(f"Request timeout from {client_ip}")
            await self.send_error_response(
                writer, 504, "Gateway Timeout", client_ip
            )
        except Exception as e:
            # Handle any other errors
            logger.error(f"Error processing request from {client_ip}: {e}")
            await self.send_error_response(
                writer, 500, "Internal Server Error", client_ip
            )
        finally:
            # Close client connection
            writer.close()
            await writer.wait_closed()
    
    async def parse_http_request(self, reader: asyncio.StreamReader, 
                               client_ip: str) -> Dict[str, Any]:
        """
        Parse HTTP request from stream.
        
        Args:
            reader: Stream reader
            client_ip: Client IP address
            
        Returns:
            Parsed request data
            
        Raises:
            ValueError: If request is malformed
        """
        # Read and decode request line (e.g., "GET /path HTTP/1.1")
        request_line_bytes = await reader.readline()
        if not request_line_bytes:
            raise ValueError("Empty request")
        
        request_line = request_line_bytes.decode('utf-8').strip()
        
        # Parse request line into method, path, and HTTP version
        try:
            method, path, http_version = request_line.split()
        except ValueError:
            raise ValueError(f"Malformed request line: {request_line}")
        
        # Validate HTTP version format
        if not http_version.startswith('HTTP/'):
            raise ValueError(f"Invalid HTTP version: {http_version}")
        
        # Read headers until empty line
        headers = {}
        content_length = 0
        
        while True:
            header_line_bytes = await reader.readline()
            if not header_line_bytes:
                break
            
            header_line = header_line_bytes.decode('utf-8').strip()
            
            # Empty line indicates end of headers
            if not header_line:
                break
            
            # Parse header name and value
            if ': ' in header_line:
                header_name, header_value = header_line.split(': ', 1)
                headers[header_name] = header_value
                
                # Track content length for body reading
                if header_name.lower() == 'content-length':
                    try:
                        content_length = int(header_value)
                    except ValueError:
                        logger.warning(f"Invalid Content-Length: {header_value}")
        
        # Read request body if content length specified
        body = b''
        if content_length > 0:
            # Check against maximum request size
            if content_length > self.config.max_request_size:
                raise ValueError(f"Request too large: {content_length} bytes")
            
            # Read exact number of bytes specified by content-length
            body = await reader.read(content_length)
            
            # Warn if body is incomplete
            if len(body) < content_length:
                logger.warning(f"Incomplete body: {len(body)}/{content_length} bytes")
        
        # Parse URL path and query parameters
        parsed_path = urllib.parse.urlparse(path)
        query_params = urllib.parse.parse_qs(parsed_path.query)
        
        return {
            'method': method,
            'path': path,
            'http_version': http_version,
            'headers': headers,
            'body': body,
            'query_params': query_params,
            'client_ip': client_ip,
            'timestamp': datetime.now(),
            'parsed_path': parsed_path
        }
    
    async def pre_process_request(self, request_data: Dict[str, Any], 
                                client_ip: str) -> bool:
        """
        Pre-process request to determine if it should be allowed.
        
        Args:
            request_data: Parsed request data
            client_ip: Client IP address
            
        Returns:
            True if request should be processed, False if blocked
        """
        # Apply rate limiting
        if not self.rate_limiter.allow_request(client_ip):
            logger.warning(f"Rate limit exceeded for {client_ip}")
            return False
        
        # Check if path is in blocked list
        path = request_data['parsed_path'].path
        if any(blocked_path in path for blocked_path in self.config.blocked_paths):
            logger.warning(f"Access to blocked path: {path}")
            return False
        
        # Validate HTTP method is allowed
        method = request_data['method']
        if method not in self.config.allowed_methods:
            logger.warning(f"Disallowed method: {method}")
            return False
        
        # Check request size against limit
        content_length = len(request_data.get('body', b''))
        if content_length > self.config.max_request_size:
            logger.warning(f"Request too large: {content_length} bytes")
            return False
        
        # Perform security analysis in protective mode
        if self.mode == ProxyMode.PROTECTIVE and self.security_plugin:
            security_result = await self.analyze_request_security(request_data)
            
            if not security_result['allowed']:
                logger.warning(f"Request blocked: {security_result.get('reason', 'Security violation')}")
                
                # Log security event if enabled
                if self.config.enable_security_logs:
                    self.log_security_event(
                        event_type='REQUEST_BLOCKED',
                        client_ip=client_ip,
                        details=security_result
                    )
                
                return False
        
        # Check backend health before forwarding
        if not self.health_monitor.is_backend_healthy():
            logger.error("Backend is unhealthy, rejecting requests")
            return False
        
        return True
    
    async def analyze_request_security(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze request for security threats.
        
        Args:
            request_data: Request data
            
        Returns:
            Security analysis results
        """
        # Prepare request data for security plugin analysis
        plugin_request = {
            'ip': request_data['client_ip'],
            'url': f"http://{self.backend_host}{request_data['path']}",
            'method': request_data['method'],
            'headers': request_data['headers'],
            'body': request_data['body'].decode('utf-8', errors='ignore') 
                     if request_data['body'] else '',
            'user_agent': request_data['headers'].get('User-Agent', '')
        }
        
        # Analyze with security plugin if available
        if self.security_plugin:
            analysis_result = await self.security_plugin.analyze_request(plugin_request)
        else:
            # Default safe analysis if plugin not available
            analysis_result = {'allowed': True, 'threat_level': 'low', 'threats': [], 'action': 'allow'}
        
        return {
            'allowed': analysis_result['allowed'],
            'threat_level': analysis_result.get('threat_level', 'low'),
            'threats': analysis_result.get('threats', []),
            'reason': ', '.join(analysis_result.get('reasons', [])),
            'action': analysis_result.get('action', 'allow')
        }
    
    async def process_through_middleware(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process request through middleware chain.
        
        Args:
            request_data: Original request data
            
        Returns:
            Processed request data
        """
        processed_request = request_data.copy()
        
        # Apply each middleware in the chain
        for middleware in self.middleware_chain:
            try:
                processed_request = await middleware(processed_request)
            except Exception as e:
                logger.error(f"Middleware error: {e}")
                # Continue with other middleware even if one fails
        
        return processed_request
    
    def generate_cache_key(self, request_data: Dict[str, Any]) -> str:
        """
        Generate cache key for request.
        
        Args:
            request_data: Request data
            
        Returns:
            Cache key string
        """
        # Create key from method, path, and sorted query parameters
        key_parts = [
            request_data['method'],
            request_data['parsed_path'].path,
            str(sorted(request_data['query_params'].items()))
        ]
        
        # Include headers that affect response (for cache variation)
        cache_headers = ['Accept', 'Accept-Encoding', 'Accept-Language']
        for header in cache_headers:
            if header in request_data['headers']:
                key_parts.append(f"{header}:{request_data['headers'][header]}")
        
        # Generate MD5 hash of key string for consistent cache key
        key_string = '|'.join(key_parts)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def should_cache_response(self, response_data: Dict[str, Any]) -> bool:
        """
        Determine if response should be cached.
        
        Args:
            response_data: Response data
            
        Returns:
            True if response should be cached
        """
        # Only cache successful responses
        status_code = response_data.get('status_code', 200)
        cacheable_status_codes = [200, 203, 204, 206, 300, 301, 404, 405, 410, 414]
        if status_code not in cacheable_status_codes:
            return False
        
        # Check cache control headers
        headers = response_data.get('headers', {})
        
        if 'Cache-Control' in headers:
            cache_control = headers['Cache-Control'].lower()
            
            # Don't cache if explicitly marked as non-cacheable
            if 'no-store' in cache_control or 'no-cache' in cache_control:
                return False
            
            # Don't cache private responses
            if 'private' in cache_control:
                return False
        
        # Don't cache responses with Set-Cookie headers
        if 'Set-Cookie' in headers:
            return False
        
        # Limit cache size to prevent memory issues
        body = response_data.get('body', b'')
        if len(body) > 10 * 1024 * 1024:  # 10MB max for caching
            return False
        
        return True
    
    async def forward_to_backend(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Forward request to backend server.
        
        Args:
            request_data: Request data
            
        Returns:
            Response data from backend
            
        Raises:
            aiohttp.ClientError: If backend request fails
        """
        if not self.backend_session:
            raise RuntimeError("Backend session not initialized")
        
        # Construct full backend URL with path and query
        backend_url = f"{self.backend_url}{request_data['parsed_path'].path}"
        if request_data['parsed_path'].query:
            backend_url += f"?{request_data['parsed_path'].query}"
        
        # Copy headers for backend request
        headers = request_data['headers'].copy()
        
        # Remove hop-by-hop headers that shouldn't be forwarded
        hop_by_hop_headers = [
            'connection', 'keep-alive', 'proxy-authenticate',
            'proxy-authorization', 'te', 'trailers', 'transfer-encoding',
            'upgrade'
        ]
        for header in hop_by_hop_headers:
            if header in headers:
                del headers[header]
        
        # Add X-Forwarded headers for backend to know original client
        headers['X-Forwarded-For'] = request_data['client_ip']
        headers['X-Forwarded-Host'] = self.backend_host
        headers['X-Forwarded-Proto'] = 'https' if self.ssl_context else 'http'
        
        try:
            # Send request to backend
            async with self.backend_session.request(
                method=request_data['method'],
                url=backend_url,
                headers=headers,
                data=request_data['body'] if request_data['body'] else None,
                allow_redirects=False  # Handle redirects at proxy level
            ) as response:
                # Read entire response body
                body = await response.read()
                
                # Check response size against limit
                if len(body) > self.config.max_response_size:
                    logger.warning(f"Response too large: {len(body)} bytes")
                    body = b'Response too large'
                
                # Collect response metadata
                response_headers = dict(response.headers)
                
                return {
                    'status_code': response.status,
                    'headers': response_headers,
                    'body': body,
                    'version': 'HTTP/1.1'
                }
                
        except aiohttp.ClientError as e:
            # Track backend errors in statistics
            self.stats['backend_errors'] += 1
            logger.error(f"Backend request failed: {e}")
            raise
    
    async def process_response(self, response_data: Dict[str, Any], 
                             request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process backend response for security and optimization.
        
        Args:
            response_data: Response from backend
            request_data: Original request data
            
        Returns:
            Processed response data
        """
        processed_response = response_data.copy()
        
        # Apply compression if enabled and client supports it
        if (self.config.enable_compression and 
            'Accept-Encoding' in request_data['headers'] and
            'gzip' in request_data['headers']['Accept-Encoding']):
            
            # Check content type for compressibility
            content_type = processed_response['headers'].get('Content-Type', '')
            compressible_types = ['text/', 'application/json', 'application/javascript', 
                                'application/xml', 'application/xhtml+xml']
            
            if any(ct in content_type for ct in compressible_types):
                # Compress response body using gzip
                try:
                    compressed_body = gzip.compress(processed_response['body'])
                    
                    # Only use compression if it actually reduces size
                    if len(compressed_body) < len(processed_response['body']):
                        processed_response['body'] = compressed_body
                        processed_response['headers']['Content-Encoding'] = 'gzip'
                        processed_response['headers']['Vary'] = 'Accept-Encoding'
                except Exception as e:
                    logger.warning(f"Compression failed: {e}")
        
        # Add security headers to response
        self.add_security_headers(processed_response['headers'])
        
        # Remove unnecessary headers
        self.clean_response_headers(processed_response['headers'])
        
        return processed_response
    
    def add_security_headers(self, headers: Dict[str, str]):
        """
        Add security headers to response.
        
        Args:
            headers: Response headers to modify
        """
        # Define standard security headers
        security_headers = {
            'X-Content-Type-Options': 'nosniff',  # Prevent MIME type sniffing
            'X-Frame-Options': 'DENY',  # Prevent clickjacking
            'X-XSS-Protection': '1; mode=block',  # Enable XSS protection
            'Referrer-Policy': 'strict-origin-when-cross-origin',  # Control referrer info
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'  # Limit permissions
        }
        
        # Add Content Security Policy if not already present
        if 'Content-Security-Policy' not in headers:
            security_headers['Content-Security-Policy'] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self'; "
                "connect-src 'self'; "
                "media-src 'self'; "
                "object-src 'none'; "
                "child-src 'self'; "
                "frame-ancestors 'none'; "
                "form-action 'self'; "
                "base-uri 'self'; "
                "manifest-src 'self'"
            )
        
        # Add HSTS header for HTTPS connections
        if self.ssl_context and 'Strict-Transport-Security' not in headers:
            security_headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        # Apply all security headers
        headers.update(security_headers)
    
    def clean_response_headers(self, headers: Dict[str, str]):
        """
        Remove unnecessary or sensitive headers from response.
        
        Args:
            headers: Response headers to clean
        """
        # List of headers to remove (security through obscurity)
        headers_to_remove = [
            'Server',  # Hide server software information
            'X-Powered-By',  # Hide backend technology
            'Via',  # Remove proxy trail
            'X-AspNet-Version',
            'X-AspNetMvc-Version'
        ]
        
        for header in headers_to_remove:
            if header in headers:
                del headers[header]
    
    async def send_response(self, writer: asyncio.StreamWriter, 
                          response_data: Dict[str, Any], client_ip: str):
        """
        Send HTTP response to client.
        
        Args:
            writer: Stream writer
            response_data: Response data
            client_ip: Client IP address
        """
        # Build HTTP status line
        status_line = f"HTTP/1.1 {response_data['status_code']} {self.get_status_text(response_data['status_code'])}\r\n"
        
        # Prepare headers
        headers = response_data['headers'].copy()
        
        # Ensure Content-Length header is present
        if 'Content-Length' not in headers:
            headers['Content-Length'] = str(len(response_data['body']))
        
        # Add current date in HTTP format
        headers['Date'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        
        # Build headers string
        headers_str = ''.join(f"{k}: {v}\r\n" for k, v in headers.items())
        
        # Write response components
        writer.write(status_line.encode())
        writer.write(headers_str.encode())
        writer.write(b'\r\n')  # End of headers marker
        writer.write(response_data['body'])
        
        # Ensure data is sent
        await writer.drain()
    
    async def send_error_response(self, writer: asyncio.StreamWriter, 
                                status_code: int, message: str, client_ip: str):
        """
        Send error response to client.
        
        Args:
            writer: Stream writer
            status_code: HTTP status code
            message: Error message
            client_ip: Client IP address
        """
        # Check for custom error page configuration
        error_page = self.config.custom_error_pages.get(status_code)
        
        if error_page and os.path.exists(error_page):
            # Serve custom error page from file
            try:
                with open(error_page, 'rb') as f:
                    body = f.read()
                content_type = 'text/html'
            except Exception as e:
                logger.error(f"Error reading custom error page: {e}")
                body = self.generate_error_html(status_code, message).encode()
                content_type = 'text/html'
        else:
            # Generate default error HTML
            body = self.generate_error_html(status_code, message).encode()
            content_type = 'text/html'
        
        # Build error response
        response_data = {
            'status_code': status_code,
            'headers': {
                'Content-Type': content_type,
                'Content-Length': str(len(body))
            },
            'body': body
        }
        
        # Send the error response
        await self.send_response(writer, response_data, client_ip)
    
    def generate_error_html(self, status_code: int, message: str) -> str:
        """
        Generate HTML error page.
        
        Args:
            status_code: HTTP status code
            message: Error message
            
        Returns:
            HTML error page
        """
        status_text = self.get_status_text(status_code)
        
        # HTML template for error pages
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>{status_code} {status_text}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 50px;
            background: #f5f5f5;
        }}
        .container {{
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            display: inline-block;
        }}
        h1 {{
            color: #dc3545;
            margin-bottom: 20px;
        }}
        .error-code {{
            font-size: 72px;
            font-weight: bold;
            color: #6c757d;
        }}
        .error-message {{
            color: #343a40;
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
        <div class="error-code">{status_code}</div>
        <h1>{status_text}</h1>
        <div class="error-message">{message}</div>
        <div class="contact">
            This request was processed by CyberGuard Security Proxy
        </div>
    </div>
</body>
</html>"""
    
    def get_status_text(self, status_code: int) -> str:
        """
        Get status text for HTTP status code.
        
        Args:
            status_code: HTTP status code
            
        Returns:
            Status text
        """
        # Map of common HTTP status codes to their text descriptions
        status_texts = {
            200: 'OK',
            201: 'Created',
            204: 'No Content',
            301: 'Moved Permanently',
            302: 'Found',
            304: 'Not Modified',
            400: 'Bad Request',
            401: 'Unauthorized',
            403: 'Forbidden',
            404: 'Not Found',
            405: 'Method Not Allowed',
            429: 'Too Many Requests',
            500: 'Internal Server Error',
            502: 'Bad Gateway',
            503: 'Service Unavailable',
            504: 'Gateway Timeout'
        }
        
        return status_texts.get(status_code, 'Unknown')
    
    def log_access(self, request_data: Dict[str, Any], response_data: Dict[str, Any],
                  client_ip: str, response_time: float):
        """
        Log access event.
        
        Args:
            request_data: Request data
            response_data: Response data
            client_ip: Client IP address
            response_time: Response time in seconds
        """
        if not self.config.enable_access_logs:
            return
        
        # Format request line for logging
        request_line = f"{request_data['method']} {request_data['path']} {request_data['http_version']}"
        
        # Create log entry using configured format
        log_entry = self.config.log_format.format(
            asctime=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            client_ip=client_ip,
            request_line=request_line,
            status_code=response_data['status_code'],
            response_time=f"{response_time:.3f}s",
            method=request_data['method'],
            path=request_data['path'],
            user_agent=request_data['headers'].get('User-Agent', '-'),
            referer=request_data['headers'].get('Referer', '-'),
            content_length=len(response_data.get('body', b''))
        )
        
        logger.info(log_entry)
    
    def log_security_event(self, event_type: str, client_ip: str, 
                          details: Dict[str, Any]):
        """
        Log security event.
        
        Args:
            event_type: Type of security event
            client_ip: Client IP address
            details: Event details
        """
        if not self.config.enable_security_logs:
            return
        
        # Create structured security log entry
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'client_ip': client_ip,
            'details': details
        }
        
        logger.warning(f"SECURITY_EVENT: {json.dumps(log_entry)}")
    
    def add_middleware(self, middleware_func: Callable):
        """
        Add middleware to processing chain.
        
        Args:
            middleware_func: Middleware function that takes request data 
                            and returns processed request data
        """
        self.middleware_chain.append(middleware_func)
        logger.info(f"Middleware added: {middleware_func.__name__}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get proxy statistics.
        
        Returns:
            Dictionary with proxy statistics
        """
        uptime = datetime.now() - self.stats['start_time']
        
        # Calculate cache hit ratio
        total_cache_requests = self.stats['cache_hits'] + self.stats['cache_misses']
        cache_hit_ratio = self.stats['cache_hits'] / total_cache_requests if total_cache_requests > 0 else 0
        
        return {
            'uptime_seconds': uptime.total_seconds(),
            'total_requests': self.stats['total_requests'],
            'blocked_requests': self.stats['blocked_requests'],
            'passed_requests': self.stats['passed_requests'],
            'backend_errors': self.stats['backend_errors'],
            'cache_hits': self.stats['cache_hits'],
            'cache_misses': self.stats['cache_misses'],
            'cache_hit_ratio': cache_hit_ratio,
            'bytes_transferred': self.stats['bytes_transferred'],
            'avg_response_time': self.stats['avg_response_time'],
            'current_connections': self.request_tracker.get_active_count(),
            'backend_healthy': self.health_monitor.is_backend_healthy(),
            'rate_limit_active': self.rate_limiter.is_active(),
            'cache_size': len(self.cache)
        }
    
    async def cleanup(self):
        """Clean up resources."""
        # Close backend HTTP session
        if self.backend_session:
            await self.backend_session.close()
            self.backend_session = None
        
        # Stop health monitoring
        if self.health_monitor:
            await self.health_monitor.stop()
        
        logger.info("Reverse proxy cleanup completed")

# Helper classes for rate limiting, request tracking, and health monitoring

class RateLimiter:
    """Rate limiting implementation based on token bucket algorithm"""
    
    def __init__(self, requests_per_minute: int = 100, window_seconds: int = 60):
        self.requests_per_minute = requests_per_minute
        self.window_seconds = window_seconds
        self.requests: Dict[str, List[float]] = {}  # IP -> list of request timestamps
    
    def allow_request(self, client_ip: str) -> bool:
        """
        Check if request should be allowed based on rate limit.
        
        Args:
            client_ip: Client IP address
            
        Returns:
            True if request should be allowed
        """
        current_time = time.time()
        
        # Initialize request list for new IP
        if client_ip not in self.requests:
            self.requests[client_ip] = []
        
        # Remove requests outside the time window
        window_start = current_time - self.window_seconds
        self.requests[client_ip] = [
            req_time for req_time in self.requests[client_ip]
            if req_time > window_start
        ]
        
        # Check if IP has exceeded rate limit
        if len(self.requests[client_ip]) >= self.requests_per_minute:
            return False
        
        # Record this request
        self.requests[client_ip].append(current_time)
        return True
    
    def is_active(self) -> bool:
        """Check if rate limiting is tracking any IPs."""
        return len(self.requests) > 0

class RequestTracker:
    """Track active requests for monitoring purposes"""
    
    def __init__(self):
        self.active_requests: Dict[str, Dict[str, Any]] = {}  # request_id -> request_data
    
    def add_request(self, request_id: str, request_data: Dict[str, Any]):
        """Add active request to tracker."""
        self.active_requests[request_id] = {
            **request_data,
            'start_time': time.time()
        }
    
    def remove_request(self, request_id: str):
        """Remove completed request from tracker."""
        if request_id in self.active_requests:
            del self.active_requests[request_id]
    
    def get_active_count(self) -> int:
        """Get count of currently active requests."""
        return len(self.active_requests)

class HealthMonitor:
    """Monitor backend health with periodic checks"""
    
    def __init__(self, backend_url: str, check_interval: int = 30,
                 health_check_path: str = "/health"):
        self.backend_url = backend_url
        self.check_interval = check_interval
        self.health_check_path = health_check_path
        
        self.healthy = False  # Current health status
        self.last_check = None  # Timestamp of last check
        self.check_task = None  # Background monitoring task
        self.session = None  # HTTP session for health checks
    
    async def start(self):
        """Start health monitoring background task."""
        # Create HTTP session for health checks
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5))
        # Start monitoring loop
        self.check_task = asyncio.create_task(self._monitor_loop())
    
    async def _monitor_loop(self):
        """Health monitoring loop running in background."""
        while True:
            try:
                await self._check_health()
                await asyncio.sleep(self.check_interval)
            except asyncio.CancelledError:
                # Task was cancelled, exit loop
                break
            except Exception as e:
                logger.error(f"Health monitor error: {e}")
                await asyncio.sleep(self.check_interval)
    
    async def _check_health(self):
        """Perform single health check against backend."""
        try:
            health_url = f"{self.backend_url}{self.health_check_path}"
            
            async with self.session.get(health_url) as response:
                # Backend is healthy if returns 200 OK
                self.healthy = response.status == 200
                self.last_check = datetime.now()
                
                if not self.healthy:
                    logger.warning(f"Backend health check failed: {response.status}")
        
        except Exception as e:
            # Mark backend as unhealthy on any error
            self.healthy = False
            self.last_check = datetime.now()
            logger.error(f"Backend health check error: {e}")
    
    def is_backend_healthy(self) -> bool:
        """Check if backend is currently healthy."""
        return self.healthy
    
    async def stop(self):
        """Stop health monitoring and cleanup."""
        if self.check_task:
            # Cancel background monitoring task
            self.check_task.cancel()
            try:
                await self.check_task
            except asyncio.CancelledError:
                pass
        
        # Close HTTP session
        if self.session:
            await self.session.close()
            self.session = None

# Example usage and testing
if __name__ == "__main__":
    # Example configuration for testing
    config = ProxyConfig(
        backend_url="http://localhost:3000",
        mode=ProxyMode.PROTECTIVE,
        port=8080,
        rate_limit_requests=100,
        enable_compression=True,
        enable_caching=True
    )
    
    # Create reverse proxy instance
    proxy = ReverseProxySecurityLayer(config)
    
    print("Starting reverse proxy...")
    print(f"Backend: {config.backend_url}")
    print(f"Proxy URL: http://localhost:{config.port}")
    print(f"Mode: {config.mode.value}")
    
    try:
        # Start the proxy server
        asyncio.run(proxy.start())
    except KeyboardInterrupt:
        print("\nShutting down reverse proxy...")
    except Exception as e:
        print(f"Error running proxy: {e}")
    finally:
        # Ensure cleanup
        asyncio.run(proxy.cleanup())