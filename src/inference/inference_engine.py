# src/inference/inference_engine.py
"""
Main Inference Engine for CyberGuard Web Security AI System

This module orchestrates the complete inference pipeline:
1. Input validation and preprocessing
2. Feature extraction and encoding
3. Multi-model inference with ensemble voting
4. mHC-based agent coordination
5. Result aggregation and confidence calibration
6. Threat level calculation and severity assessment

Key Features:
- Parallel inference across multiple security models
- Real-time threat detection with low latency
- Confidence-based decision making
- Explainable AI with evidence tracing
- Graceful degradation under load
"""

import asyncio
import threading
import time
from typing import Dict, List, Any, Optional, Tuple, Union, Callable
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, Future, TimeoutError
from queue import Queue, Empty
import numpy as np
import torch
import torch.nn.functional as F
from datetime import datetime, timedelta
import logging
import json

# Local imports
from ..core.mhc_architecture import ManifoldConstrainedHyperConnections
from ..core.gqa_transformer import SecurityGQATransformer
from ..agents.agent_orchestrator import AgentOrchestrator
from .threat_inference import ThreatInference
from .response_parser import ResponseParser
from . import InferenceResult, InferenceRequest

# Configure module logger
logger = logging.getLogger(__name__)

@dataclass
class InferenceMetrics:
    """
    Performance metrics for inference engine.
    Tracks latency, accuracy, throughput, and resource usage.
    """
    total_inferences: int = 0
    successful_inferences: int = 0
    failed_inferences: int = 0
    avg_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    min_latency_ms: float = float('inf')
    throughput_per_second: float = 0.0
    memory_usage_mb: float = 0.0
    gpu_utilization: float = 0.0
    confidence_distribution: List[float] = field(default_factory=list)
    threat_level_distribution: List[float] = field(default_factory=list)
    
    def update(self, latency_ms: float, success: bool = True, 
               confidence: float = 0.0, threat_level: float = 0.0):
        """Update metrics with new inference result"""
        self.total_inferences += 1
        
        if success:
            self.successful_inferences += 1
        else:
            self.failed_inferences += 1
        
        # Update latency statistics using exponential moving average
        if self.avg_latency_ms == 0.0:
            self.avg_latency_ms = latency_ms
        else:
            self.avg_latency_ms = 0.9 * self.avg_latency_ms + 0.1 * latency_ms
        
        self.max_latency_ms = max(self.max_latency_ms, latency_ms)
        self.min_latency_ms = min(self.min_latency_ms, latency_ms)
        
        # Store distributions for analysis
        if confidence > 0:
            self.confidence_distribution.append(confidence)
            if len(self.confidence_distribution) > 1000:  # Keep last 1000
                self.confidence_distribution = self.confidence_distribution[-1000:]
        
        if threat_level > 0:
            self.threat_level_distribution.append(threat_level)
            if len(self.threat_level_distribution) > 1000:
                self.threat_level_distribution = self.threat_level_distribution[-1000:]
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics"""
        return {
            'total_inferences': self.total_inferences,
            'success_rate': self.successful_inferences / max(1, self.total_inferences),
            'avg_latency_ms': self.avg_latency_ms,
            'max_latency_ms': self.max_latency_ms,
            'min_latency_ms': self.min_latency_ms if self.min_latency_ms != float('inf') else 0.0,
            'avg_confidence': np.mean(self.confidence_distribution) if self.confidence_distribution else 0.0,
            'avg_threat_level': np.mean(self.threat_level_distribution) if self.threat_level_distribution else 0.0
        }

class InferenceCache:
    """
    LRU Cache for inference results to improve performance.
    Caches results based on request hash with TTL expiration.
    """
    
    def __init__(self, max_size: int = 1000, ttl_seconds: int = 300):
        """
        Initialize inference cache.
        
        Args:
            max_size: Maximum number of items to cache
            ttl_seconds: Time-to-live for cache entries in seconds
        """
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.cache: Dict[str, Tuple[InferenceResult, float]] = {}
        self.access_order: List[str] = []
        self.hits = 0
        self.misses = 0
    
    def _generate_key(self, request_data: Dict[str, Any]) -> str:
        """Generate cache key from request data"""
        import hashlib
        # Create deterministic string representation
        data_str = json.dumps(request_data, sort_keys=True)
        return hashlib.sha256(data_str.encode()).hexdigest()[:32]
    
    def get(self, request_data: Dict[str, Any]) -> Optional[InferenceResult]:
        """
        Get cached inference result if available and not expired.
        
        Args:
            request_data: Request data dictionary
        
        Returns:
            Cached InferenceResult or None if not found/expired
        """
        key = self._generate_key(request_data)
        
        if key not in self.cache:
            self.misses += 1
            return None
        
        # Check if entry is expired
        result, timestamp = self.cache[key]
        current_time = time.time()
        
        if current_time - timestamp > self.ttl_seconds:
            # Entry expired, remove it
            del self.cache[key]
            self.access_order.remove(key)
            self.misses += 1
            return None
        
        # Update access order (move to end for LRU)
        self.access_order.remove(key)
        self.access_order.append(key)
        
        self.hits += 1
        return result
    
    def set(self, request_data: Dict[str, Any], result: InferenceResult):
        """
        Cache inference result.
        
        Args:
            request_data: Request data dictionary
            result: InferenceResult to cache
        """
        key = self._generate_key(request_data)
        current_time = time.time()
        
        # Remove if already exists
        if key in self.cache:
            self.access_order.remove(key)
        
        # Add to cache
        self.cache[key] = (result, current_time)
        self.access_order.append(key)
        
        # Enforce max size (LRU eviction)
        if len(self.cache) > self.max_size:
            oldest_key = self.access_order.pop(0)
            del self.cache[oldest_key]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total = self.hits + self.misses
        hit_rate = self.hits / max(1, total)
        
        return {
            'size': len(self.cache),
            'max_size': self.max_size,
            'hits': self.hits,
            'misses': self.misses,
            'hit_rate': hit_rate,
            'ttl_seconds': self.ttl_seconds
        }

class InferenceEngine:
    """
    Main Inference Engine for CyberGuard.
    
    Orchestrates the complete inference pipeline from input processing to
    threat decision making. Uses ensemble of models and agents with
    mHC-based coordination for stable, explainable decisions.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize Inference Engine with configuration.
        
        Args:
            config: Engine configuration dictionary. If None, uses defaults.
        """
        # Load configuration with defaults
        self.config = config or self._get_default_config()
        
        # Initialize components
        self._initialize_components()
        
        # Performance tracking
        self.metrics = InferenceMetrics()
        self.cache = InferenceCache(
            max_size=self.config['cache_size'],
            ttl_seconds=self.config['cache_ttl_seconds']
        )
        
        # Thread pool for parallel processing
        self.thread_pool = ThreadPoolExecutor(
            max_workers=self.config['max_workers'],
            thread_name_prefix='inference_worker'
        )
        
        # Request queue for batch processing
        self.request_queue = Queue(maxsize=self.config['queue_size'])
        
        # Worker thread for processing queued requests
        self._worker_thread = None
        self._running = False
        
        # Model warmup
        self._warmup_models()
        
        logger.info(f"InferenceEngine initialized with config: {self.config}")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default engine configuration"""
        return {
            'use_gpu': torch.cuda.is_available(),
            'batch_size': 32,
            'max_sequence_length': 2048,
            'confidence_threshold': 0.7,
            'threat_threshold_critical': 0.9,
            'threat_threshold_high': 0.7,
            'threat_threshold_medium': 0.5,
            'threat_threshold_low': 0.3,
            'max_workers': 4,
            'queue_size': 1000,
            'timeout_seconds': 10.0,
            'cache_size': 1000,
            'cache_ttl_seconds': 300,
            'enable_explanations': True,
            'enable_mitigations': True,
            'log_level': 'INFO'
        }
    
    def _initialize_components(self):
        """Initialize all engine components"""
        logger.info("Initializing inference engine components...")
        
        # Initialize GQA Transformer model for security analysis
        try:
            self.gqa_model = SecurityGQATransformer(
                vocab_size=self.config.get('vocab_size', 50257),
                d_model=self.config.get('d_model', 512),
                n_layers=self.config.get('n_layers', 6),
                n_heads=self.config.get('n_heads', 8),
                n_groups=self.config.get('n_groups', 2),
                max_seq_len=self.config.get('max_sequence_length', 2048),
                dropout=self.config.get('dropout', 0.1),
                num_threat_classes=self.config.get('num_threat_classes', 10)
            )
            
            # Move to GPU if available and configured
            if self.config['use_gpu'] and torch.cuda.is_available():
                self.gqa_model = self.gqa_model.cuda()
                logger.info("GQA model moved to GPU")
            else:
                logger.info("GQA model running on CPU")
            
            # Set model to evaluation mode
            self.gqa_model.eval()
            
        except Exception as e:
            logger.error(f"Failed to initialize GQA model: {e}")
            raise
        
        # Initialize Threat Inference module
        self.threat_inference = ThreatInference(self.config)
        
        # Initialize Response Parser
        self.response_parser = ResponseParser(self.config)
        
        # Initialize mHC for agent coordination
        self.mhc = ManifoldConstrainedHyperConnections(
            n_agents=1,  # Will be updated when agents are registered
            state_dim=self.config.get('mhc_state_dim', 512),
            temperature=self.config.get('mhc_temperature', 1.0)
        )
        
        # Initialize Agent Orchestrator
        self.agent_orchestrator = AgentOrchestrator(
            state_dim=self.config.get('mhc_state_dim', 512)
        )
        
        logger.info("All components initialized successfully")
    
    def _warmup_models(self):
        """Warm up models with dummy data to improve first inference speed"""
        logger.info("Warming up models...")
        
        try:
            # Create dummy input for warmup
            dummy_input = torch.randint(
                0, 1000, 
                (1, min(32, self.config['max_sequence_length'])),
                dtype=torch.long
            )
            
            if self.config['use_gpu'] and torch.cuda.is_available():
                dummy_input = dummy_input.cuda()
            
            # Warm up GQA model
            with torch.no_grad():
                _ = self.gqa_model(dummy_input)
            
            logger.info("Models warmed up successfully")
            
        except Exception as e:
            logger.warning(f"Model warmup failed: {e}")
    
    def infer(self, request: Union[InferenceRequest, Dict[str, Any]]) -> InferenceResult:
        """
        Main inference method. Processes security inference request.
        
        Args:
            request: Inference request or raw data dictionary
        
        Returns:
            InferenceResult with threat analysis
        
        Raises:
            ValueError: If request is invalid
            TimeoutError: If inference times out
            RuntimeError: If inference fails
        """
        start_time = time.time()
        
        try:
            # Convert dict to InferenceRequest if needed
            if isinstance(request, dict):
                request = InferenceRequest(request_data=request)
            
            # Validate input
            if not self._validate_request(request):
                raise ValueError("Invalid inference request")
            
            # Check cache first
            if self.config.get('enable_caching', True):
                cached_result = self.cache.get(request.request_data)
                if cached_result:
                    logger.debug("Cache hit for inference request")
                    latency = (time.time() - start_time) * 1000
                    self.metrics.update(latency, success=True)
                    return cached_result
            
            logger.debug(f"Processing inference request: {request.request_data.get('url', 'unknown')}")
            
            # Process based on inference mode
            if request.inference_mode == "realtime":
                result = self._infer_realtime(request)
            elif request.inference_mode == "batch":
                result = self._infer_batch(request)
            elif request.inference_mode == "deep_scan":
                result = self._infer_deep_scan(request)
            else:
                raise ValueError(f"Unknown inference mode: {request.inference_mode}")
            
            # Update cache
            if self.config.get('enable_caching', True):
                self.cache.set(request.request_data, result)
            
            # Update metrics
            latency_ms = (time.time() - start_time) * 1000
            self.metrics.update(
                latency_ms, 
                success=True,
                confidence=result.confidence,
                threat_level=result.threat_level
            )
            
            logger.info(f"Inference completed in {latency_ms:.2f}ms. "
                       f"Threat: {result.threat_level:.2f}, "
                       f"Confidence: {result.confidence:.2f}")
            
            return result
            
        except Exception as e:
            # Update metrics with failure
            latency_ms = (time.time() - start_time) * 1000
            self.metrics.update(latency_ms, success=False)
            
            logger.error(f"Inference failed: {e}", exc_info=True)
            
            # Return error result
            return InferenceResult(
                threat_level=0.0,
                confidence=0.0,
                threat_type="ERROR",
                severity="INFO",
                evidence=[{
                    'type': 'ERROR',
                    'description': f'Inference failed: {str(e)}',
                    'severity': 'INFO'
                }],
                metadata={'error': str(e), 'success': False}
            )
    
    def _validate_request(self, request: InferenceRequest) -> bool:
        """
        Validate inference request.
        
        Args:
            request: Inference request to validate
        
        Returns:
            bool: True if valid, False otherwise
        """
        # Check request type
        if not isinstance(request, InferenceRequest):
            logger.error(f"Invalid request type: {type(request)}")
            return False
        
        # Check request data
        if not isinstance(request.request_data, dict):
            logger.error("Request data must be a dictionary")
            return False
        
        # Check for required fields based on inference mode
        data = request.request_data
        
        if 'url' in data:
            # URL validation
            import re
            url_pattern = re.compile(
                r'^https?://'  # http:// or https://
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
                r'localhost|'  # localhost
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP address
                r'(?::\d+)?'  # optional port
                r'(?:/?|[/?]\S+)$', re.IGNORECASE
            )
            
            if not url_pattern.match(data['url']):
                logger.error(f"Invalid URL format: {data['url']}")
                return False
        
        elif 'headers' in data or 'body' in data:
            # HTTP request validation
            if 'method' in data:
                valid_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
                if data['method'] not in valid_methods:
                    logger.error(f"Invalid HTTP method: {data['method']}")
                    return False
        
        else:
            logger.error("Request must contain 'url' or 'headers/body'")
            return False
        
        # Check timeout
        if request.timeout <= 0:
            logger.error(f"Invalid timeout: {request.timeout}")
            return False
        
        # Check priority
        if not 1 <= request.priority <= 5:
            logger.error(f"Invalid priority: {request.priority}. Must be 1-5")
            return False
        
        return True
    
    def _infer_realtime(self, request: InferenceRequest) -> InferenceResult:
        """
        Perform real-time inference with low latency.
        Optimized for speed over thoroughness.
        
        Args:
            request: Inference request
        
        Returns:
            InferenceResult with real-time analysis
        """
        logger.debug(f"Starting real-time inference for priority {request.priority}")
        
        # Extract features from request
        features = self._extract_features(request.request_data)
        
        # Encode features for model input
        encoded_features = self._encode_features(features)
        
        # Run GQA model inference
        with torch.no_grad():
            model_output = self.gqa_model(encoded_features)
        
        # Extract threat predictions
        threat_logits = model_output['threat_logits']
        severity_score = model_output['severity_score']
        
        # Convert to probabilities
        threat_probs = F.softmax(threat_logits, dim=-1)
        
        # Get top threat
        top_threat_prob, top_threat_idx = torch.max(threat_probs, dim=-1)
        threat_level = severity_score.item()
        
        # Map threat index to threat type
        threat_types = [
            'XSS', 'SQL_INJECTION', 'CSRF', 'SSRF', 'COMMAND_INJECTION',
            'PATH_TRAVERSAL', 'XXE', 'DESERIALIZATION', 'IDOR', 'BROKEN_AUTH'
        ]
        threat_type = threat_types[top_threat_idx.item()] if top_threat_idx.item() < len(threat_types) else 'UNKNOWN'
        
        # Calculate confidence
        confidence = (top_threat_prob.item() + threat_level) / 2
        
        # Generate evidence
        evidence = self._generate_evidence(
            features, 
            threat_type, 
            threat_level,
            confidence
        )
        
        # Generate recommendations if enabled
        recommendations = []
        if request.require_explanation and self.config['enable_mitigations']:
            recommendations = self.response_parser.generate_recommendations(
                threat_type, 
                threat_level,
                evidence
            )
        
        # Determine severity
        severity = self._determine_severity(threat_level, confidence)
        
        return InferenceResult(
            threat_level=threat_level,
            confidence=confidence,
            threat_type=threat_type,
            severity=severity,
            evidence=evidence,
            recommendations=recommendations,
            metadata={
                'inference_mode': 'realtime',
                'model_used': 'gqa_transformer',
                'feature_count': len(features),
                'priority': request.priority
            }
        )
    
    def _infer_batch(self, request: InferenceRequest) -> InferenceResult:
        """
        Perform batch inference with multiple models.
        More thorough but slower than real-time.
        
        Args:
            request: Inference request
        
        Returns:
            InferenceResult with batch analysis
        """
        logger.debug("Starting batch inference")
        
        # Extract features
        features = self._extract_features(request.request_data)
        
        # Run multiple inference strategies in parallel
        futures = []
        
        # 1. GQA model inference
        futures.append(
            self.thread_pool.submit(self._run_gqa_inference, features)
        )
        
        # 2. Threat inference module
        futures.append(
            self.thread_pool.submit(self.threat_inference.infer, features)
        )
        
        # 3. Agent-based analysis (if agents are registered)
        if len(self.agent_orchestrator.agents) > 0:
            futures.append(
                self.thread_pool.submit(
                    self.agent_orchestrator.coordinate_analysis,
                    {'features': features, **request.request_data}
                )
            )
        
        # Wait for results with timeout
        results = []
        for future in futures:
            try:
                result = future.result(timeout=request.timeout / len(futures))
                results.append(result)
            except TimeoutError:
                logger.warning("Inference strategy timed out")
            except Exception as e:
                logger.error(f"Inference strategy failed: {e}")
        
        # Aggregate results using mHC-based ensemble
        final_result = self._aggregate_results(results, features)
        
        return final_result
    
    def _infer_deep_scan(self, request: InferenceRequest) -> InferenceResult:
        """
        Perform deep security scan with comprehensive analysis.
        Includes vulnerability scanning, code analysis, and threat intelligence.
        
        Args:
            request: Inference request
        
        Returns:
            InferenceResult with deep scan analysis
        """
        logger.debug("Starting deep scan inference")
        
        # This would integrate with the web security scanner
        # For now, use batch inference with additional checks
        
        result = self._infer_batch(request)
        
        # Enhance with additional deep scan features
        if 'url' in request.request_data:
            try:
                # Import scanner module
                from ..web_security.scanner import WebSecurityScanner
                
                # Perform deep scan
                scanner = WebSecurityScanner(self.config)
                scan_results = scanner.scan_website(request.request_data['url'])
                
                # Enhance result with scan findings
                result = self._enhance_with_scan(result, scan_results)
                
            except ImportError:
                logger.warning("Web security scanner not available")
            except Exception as e:
                logger.error(f"Deep scan failed: {e}")
        
        return result
    
    def _extract_features(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract security-relevant features from request data.
        
        Args:
            request_data: Raw request data
        
        Returns:
            Dictionary of extracted features
        """
        features = {
            'basic': {},
            'headers': {},
            'parameters': {},
            'patterns': {},
            'metadata': {}
        }
        
        # Extract URL features
        if 'url' in request_data:
            url = request_data['url']
            features['basic']['url'] = url
            
            # Parse URL components
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            
            features['basic']['scheme'] = parsed.scheme
            features['basic']['domain'] = parsed.netloc
            features['basic']['path'] = parsed.path
            features['basic']['query'] = parsed.query
            
            # Extract query parameters
            query_params = parse_qs(parsed.query)
            features['parameters']['query_params'] = query_params
            
            # Check for suspicious patterns in URL
            suspicious_patterns = [
                ('<script>', 'xss_pattern'),
                ("' OR '1'='1", 'sql_pattern'),
                ('../', 'path_traversal'),
                (';', 'command_injection'),
                ('${', 'template_injection'),
                ('eval(', 'javascript_eval'),
                ('document.cookie', 'cookie_access'),
                ('window.location', 'redirect')
            ]
            
            for pattern, pattern_type in suspicious_patterns:
                if pattern in url.lower():
                    features['patterns'][pattern_type] = features['patterns'].get(pattern_type, 0) + 1
        
        # Extract header features
        if 'headers' in request_data:
            headers = request_data['headers']
            features['headers'] = headers
            
            # Check for security headers
            security_headers = [
                'Content-Security-Policy',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Strict-Transport-Security'
            ]
            
            missing_security_headers = []
            for header in security_headers:
                if header not in headers:
                    missing_security_headers.append(header)
            
            features['patterns']['missing_security_headers'] = len(missing_security_headers)
        
        # Extract body features
        if 'body' in request_data:
            body = request_data['body']
            if isinstance(body, str):
                # Check for suspicious patterns in body
                body_patterns = [
                    ('<script>', 'xss_pattern'),
                    ('union select', 'sql_pattern'),
                    ('system(', 'command_injection'),
                    ('exec(', 'code_execution'),
                    ('base64_decode', 'obfuscation'),
                    ('eval(', 'javascript_eval')
                ]
                
                for pattern, pattern_type in body_patterns:
                    if pattern in body.lower():
                        features['patterns'][pattern_type] = features['patterns'].get(pattern_type, 0) + 1
        
        # Extract method and metadata
        if 'method' in request_data:
            features['basic']['method'] = request_data['method']
        
        # Add timestamp
        features['metadata']['extraction_time'] = datetime.now().isoformat()
        features['metadata']['feature_count'] = sum(
            len(v) if isinstance(v, dict) else 1 
            for v in features.values()
        )
        
        return features
    
    def _encode_features(self, features: Dict[str, Any]) -> torch.Tensor:
        """
        Encode features into tensor format for model input.
        
        Args:
            features: Extracted features dictionary
        
        Returns:
            Tensor of encoded features
        """
        # This is a simplified encoding - in production, use proper feature engineering
        encoded_features = []
        
        # Encode URL patterns
        patterns = features.get('patterns', {})
        pattern_features = [
            patterns.get('xss_pattern', 0),
            patterns.get('sql_pattern', 0),
            patterns.get('path_traversal', 0),
            patterns.get('command_injection', 0),
            patterns.get('missing_security_headers', 0)
        ]
        encoded_features.extend(pattern_features)
        
        # Encode method (one-hot)
        method = features.get('basic', {}).get('method', 'GET')
        method_encoding = {
            'GET': [1, 0, 0, 0],
            'POST': [0, 1, 0, 0],
            'PUT': [0, 0, 1, 0],
            'DELETE': [0, 0, 0, 1]
        }
        encoded_features.extend(method_encoding.get(method, [0, 0, 0, 0]))
        
        # Pad or truncate to fixed size
        target_size = min(32, self.config['max_sequence_length'])
        if len(encoded_features) < target_size:
            encoded_features.extend([0] * (target_size - len(encoded_features)))
        else:
            encoded_features = encoded_features[:target_size]
        
        # Convert to tensor
        tensor = torch.tensor([encoded_features], dtype=torch.long)
        
        # Move to GPU if configured
        if self.config['use_gpu'] and torch.cuda.is_available():
            tensor = tensor.cuda()
        
        return tensor
    
    def _run_gqa_inference(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run inference using GQA transformer model.
        
        Args:
            features: Extracted features
        
        Returns:
            Model inference results
        """
        try:
            encoded = self._encode_features(features)
            
            with torch.no_grad():
                output = self.gqa_model(encoded)
            
            return {
                'model': 'gqa_transformer',
                'threat_logits': output['threat_logits'].cpu().numpy(),
                'severity_score': output['severity_score'].cpu().numpy(),
                'hidden_states': output['hidden_states'].cpu().numpy() if 'hidden_states' in output else None,
                'success': True
            }
        except Exception as e:
            logger.error(f"GQA inference failed: {e}")
            return {
                'model': 'gqa_transformer',
                'error': str(e),
                'success': False
            }
    
    def _generate_evidence(self, features: Dict[str, Any], 
                          threat_type: str, 
                          threat_level: float,
                          confidence: float) -> List[Dict[str, Any]]:
        """
        Generate evidence for inference decision.
        
        Args:
            features: Extracted features
            threat_type: Detected threat type
            threat_level: Threat severity score
            confidence: Model confidence
        
        Returns:
            List of evidence dictionaries
        """
        evidence = []
        
        # Add pattern-based evidence
        patterns = features.get('patterns', {})
        for pattern_type, count in patterns.items():
            if count > 0:
                evidence.append({
                    'type': 'PATTERN_DETECTION',
                    'description': f'Found {count} {pattern_type} pattern(s)',
                    'severity': 'MEDIUM' if count > 1 else 'LOW',
                    'confidence': min(confidence * 0.8, 0.9)
                })
        
        # Add threat-specific evidence
        if threat_type != 'UNKNOWN' and threat_level > 0.3:
            evidence.append({
                'type': 'THREAT_DETECTION',
                'description': f'Detected {threat_type} threat with level {threat_level:.2f}',
                'severity': 'HIGH' if threat_level > 0.7 else 'MEDIUM',
                'confidence': confidence
            })
        
        # Add header evidence
        headers = features.get('headers', {})
        if 'missing_security_headers' in patterns and patterns['missing_security_headers'] > 0:
            evidence.append({
                'type': 'SECURITY_HEADERS',
                'description': f'Missing {patterns["missing_security_headers"]} security headers',
                'severity': 'MEDIUM',
                'confidence': 0.7
            })
        
        # Limit evidence items
        if len(evidence) > MAX_EVIDENCE_ITEMS:
            # Sort by severity and confidence, keep top items
            severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
            evidence.sort(key=lambda x: (
                severity_order.get(x.get('severity', 'INFO'), 0),
                x.get('confidence', 0)
            ), reverse=True)
            evidence = evidence[:MAX_EVIDENCE_ITEMS]
        
        return evidence
    
    def _determine_severity(self, threat_level: float, confidence: float) -> str:
        """
        Determine severity level based on threat level and confidence.
        
        Args:
            threat_level: Threat score (0.0 to 1.0)
            confidence: Model confidence (0.0 to 1.0)
        
        Returns:
            Severity string (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        """
        # Adjust threat level by confidence
        adjusted_threat = threat_level * confidence
        
        if adjusted_threat >= self.config['threat_threshold_critical']:
            return 'CRITICAL'
        elif adjusted_threat >= self.config['threat_threshold_high']:
            return 'HIGH'
        elif adjusted_threat >= self.config['threat_threshold_medium']:
            return 'MEDIUM'
        elif adjusted_threat >= self.config['threat_threshold_low']:
            return 'LOW'
        else:
            return 'INFO'
    
    def _aggregate_results(self, results: List[Any], 
                          features: Dict[str, Any]) -> InferenceResult:
        """
        Aggregate results from multiple inference strategies.
        
        Args:
            results: List of inference results
            features: Original features
        
        Returns:
            Aggregated InferenceResult
        """
        if not results:
            return InferenceResult(
                threat_level=0.0,
                confidence=0.0,
                threat_type='UNKNOWN',
                severity='INFO',
                evidence=[{
                    'type': 'NO_RESULTS',
                    'description': 'No inference results available',
                    'severity': 'INFO'
                }]
            )
        
        # Extract threat levels and confidences
        threat_levels = []
        confidences = []
        threat_types = []
        all_evidence = []
        
        for result in results:
            if isinstance(result, dict) and result.get('success', False):
                # GQA model result
                if 'severity_score' in result:
                    threat_levels.append(float(result['severity_score'][0]))
                    confidences.append(0.8)  # Default confidence for model
                    threat_types.append('MODEL_PREDICTION')
            
            elif isinstance(result, InferenceResult):
                # InferenceResult object
                threat_levels.append(result.threat_level)
                confidences.append(result.confidence)
                threat_types.append(result.threat_type)
                all_evidence.extend(result.evidence)
            
            elif isinstance(result, dict) and 'final_decision' in result:
                # Agent orchestration result
                decision = result['final_decision']
                threat_levels.append(decision.get('threat_level', 0.0))
                confidences.append(decision.get('confidence', 0.0))
                threat_types.append('AGENT_ENSEMBLE')
                if 'evidence' in decision:
                    all_evidence.extend(decision['evidence'])
        
        # Calculate weighted average
        if threat_levels:
            weights = np.array(confidences) / (np.sum(confidences) + 1e-8)
            avg_threat = np.average(threat_levels, weights=weights)
            avg_confidence = np.mean(confidences)
        else:
            avg_threat = 0.0
            avg_confidence = 0.0
        
        # Determine most common threat type
        if threat_types:
            from collections import Counter
            threat_counter = Counter(threat_types)
            most_common = threat_counter.most_common(1)[0][0]
            
            # Map to standard threat types
            threat_type_map = {
                'MODEL_PREDICTION': 'MULTI_THREAT',
                'AGENT_ENSEMBLE': 'COMPLEX_ATTACK',
                'UNKNOWN': 'UNKNOWN'
            }
            final_threat_type = threat_type_map.get(most_common, most_common)
        else:
            final_threat_type = 'UNKNOWN'
        
        # Determine severity
        severity = self._determine_severity(avg_threat, avg_confidence)
        
        # Generate recommendations
        recommendations = self.response_parser.generate_recommendations(
            final_threat_type, 
            avg_threat,
            all_evidence
        )
        
        return InferenceResult(
            threat_level=float(avg_threat),
            confidence=float(avg_confidence),
            threat_type=final_threat_type,
            severity=severity,
            evidence=all_evidence[:MAX_EVIDENCE_ITEMS],
            recommendations=recommendations,
            metadata={
                'aggregation_method': 'weighted_average',
                'num_strategies': len(results),
                'strategies_used': [type(r).__name__ for r in results]
            }
        )
    
    def _enhance_with_scan(self, result: InferenceResult, 
                          scan_results: Dict[str, Any]) -> InferenceResult:
        """
        Enhance inference result with web scan findings.
        
        Args:
            result: Original inference result
            scan_results: Web security scan results
        
        Returns:
            Enhanced InferenceResult
        """
        # Extract vulnerabilities from scan
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        # Add scan findings to evidence
        scan_evidence = []
        for vuln in vulnerabilities[:5]:  # Limit to top 5
            scan_evidence.append({
                'type': 'SCAN_FINDING',
                'description': vuln.get('description', 'Unknown vulnerability'),
                'severity': vuln.get('severity', 'MEDIUM'),
                'source': 'web_scanner',
                'confidence': 0.8
            })
        
        # Update threat level based on scan
        risk_score = scan_results.get('risk_score', 0.0)
        enhanced_threat = max(result.threat_level, risk_score)
        
        # Update confidence (scan adds confidence)
        enhanced_confidence = min(1.0, result.confidence * 1.1)
        
        # Add scan evidence
        all_evidence = result.evidence + scan_evidence
        
        # Update recommendations with scan findings
        scan_recommendations = scan_results.get('recommendations', [])
        all_recommendations = result.recommendations + [
            self.response_parser.SecurityRecommendation(
                title=f"Scan: {rec}",
                description=rec,
                priority="MEDIUM",
                category="scan_finding"
            ) for rec in scan_recommendations[:3]
        ]
        
        # Update result
        result.threat_level = enhanced_threat
        result.confidence = enhanced_confidence
        result.evidence = all_evidence[:MAX_EVIDENCE_ITEMS]
        result.recommendations = all_recommendations[:10]  # Limit to 10
        result.metadata['scan_integrated'] = True
        result.metadata['scan_risk_score'] = risk_score
        
        return result
    
    def start_worker(self):
        """Start background worker for processing queued requests"""
        if self._worker_thread is not None and self._worker_thread.is_alive():
            logger.warning("Worker thread already running")
            return
        
        self._running = True
        self._worker_thread = threading.Thread(
            target=self._process_queue,
            name="inference_worker",
            daemon=True
        )
        self._worker_thread.start()
        logger.info("Inference worker thread started")
    
    def stop_worker(self):
        """Stop background worker"""
        self._running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=5.0)
            logger.info("Inference worker thread stopped")
    
    def _process_queue(self):
        """Process inference requests from queue"""
        logger.info("Starting queue processing")
        
        while self._running:
            try:
                # Get request from queue with timeout
                request = self.request_queue.get(timeout=1.0)
                
                # Process request
                result = self.infer(request)
                
                # Store result if callback provided
                if hasattr(request, 'callback') and callable(request.callback):
                    try:
                        request.callback(result)
                    except Exception as e:
                        logger.error(f"Callback failed: {e}")
                
                # Mark task as done
                self.request_queue.task_done()
                
            except Empty:
                # Queue empty, continue
                continue
            except Exception as e:
                logger.error(f"Queue processing error: {e}")
    
    def queue_request(self, request: InferenceRequest, 
                     callback: Optional[Callable] = None) -> bool:
        """
        Queue inference request for background processing.
        
        Args:
            request: Inference request
            callback: Optional callback function for result
        
        Returns:
            bool: True if queued successfully
        """
        # Add callback to request
        if callback:
            request.callback = callback
        
        try:
            self.request_queue.put(request, block=False)
            return True
        except Exception as e:
            logger.error(f"Failed to queue request: {e}")
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """Get engine status and metrics"""
        return {
            'engine': {
                'config': self.config,
                'components_initialized': all([
                    hasattr(self, 'gqa_model'),
                    hasattr(self, 'threat_inference'),
                    hasattr(self, 'response_parser'),
                    hasattr(self, 'agent_orchestrator')
                ]),
                'worker_running': self._worker_thread is not None and self._worker_thread.is_alive(),
                'queue_size': self.request_queue.qsize()
            },
            'metrics': self.metrics.get_summary(),
            'cache': self.cache.get_stats(),
            'system': {
                'gpu_available': torch.cuda.is_available(),
                'gpu_in_use': self.config['use_gpu'] and torch.cuda.is_available(),
                'python_version': sys.version,
                'pytorch_version': torch.__version__
            }
        }
    
    def cleanup(self):
        """Cleanup resources"""
        logger.info("Cleaning up inference engine resources...")
        
        # Stop worker thread
        self.stop_worker()
        
        # Shutdown thread pool
        self.thread_pool.shutdown(wait=True)
        
        # Clear cache
        self.cache.clear()
        
        # Clear model from GPU
        if hasattr(self, 'gqa_model'):
            if self.config['use_gpu'] and torch.cuda.is_available():
                self.gqa_model.cpu()
                torch.cuda.empty_cache()
        
        logger.info("Inference engine cleanup complete")

# Utility function for quick inference
def create_default_engine() -> InferenceEngine:
    """Create inference engine with default configuration"""
    return InferenceEngine()

# Async inference support
async def async_infer(request: InferenceRequest, 
                     engine: Optional[InferenceEngine] = None) -> InferenceResult:
    """
    Perform inference asynchronously.
    
    Args:
        request: Inference request
        engine: Optional inference engine
    
    Returns:
        InferenceResult
    """
    if engine is None:
        engine = create_default_engine()
    
    # Run inference in thread pool
    loop = asyncio.get_event_loop()
    
    try:
        result = await loop.run_in_executor(
            engine.thread_pool,
            engine.infer,
            request
        )
        return result
    except Exception as e:
        logger.error(f"Async inference failed: {e}")
        return InferenceResult(
            threat_level=0.0,
            confidence=0.0,
            threat_type='ERROR',
            severity='INFO',
            evidence=[{
                'type': 'ASYNC_ERROR',
                'description': f'Async inference failed: {str(e)}'
            }],
            metadata={'error': str(e), 'success': False}
        )