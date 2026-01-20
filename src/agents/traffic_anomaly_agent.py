# src/agents/traffic_anomaly_agent.py
"""
Traffic Anomaly Detection Agent
Purpose: Detects abnormal traffic patterns, DDoS attacks, rate limiting violations, and behavioral anomalies
Techniques: Statistical analysis, machine learning, time-series analysis, behavioral profiling
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime, timedelta
import torch
import torch.nn as nn
from dataclasses import dataclass
import json
import hashlib
from collections import deque, defaultdict
import time

# Import base agent class
from .base_agent import SecurityAgent, AgentCapability

@dataclass
class TrafficMetrics:
    """Data class for storing traffic metrics"""
    request_count: int = 0
    request_rate: float = 0.0  # requests per second
    avg_response_time: float = 0.0
    error_rate: float = 0.0
    unique_ips: int = 0
    data_transferred: float = 0.0  # in MB
    request_entropy: float = 0.0  # randomness measure of requests

class TrafficAnomalyAgent(SecurityAgent):
    """
    Traffic Anomaly Detection Agent
    
    This agent monitors web traffic patterns and detects:
    1. DDoS/DoS attacks
    2. Brute force attempts
    3. Rate limiting violations
    4. Unusual access patterns
    5. Geographic anomalies
    6. Time-based anomalies
    7. Protocol anomalies
    8. Behavioral anomalies
    
    Architecture: Uses statistical analysis, ML models, and behavioral profiling
    """
    
    def __init__(self, agent_id: str = "traffic_anomaly_001"):
        # Initialize base agent with Traffic Anomaly capability
        super().__init__(
            agent_id=agent_id,
            name="Traffic Anomaly Detection Agent",
            state_dim=512  # Embedding dimension for traffic patterns
        )
        
        # Add specific capability
        self.capabilities.append(AgentCapability.TRAFFIC_ANOMALY)
        
        # Traffic window configuration
        self.window_size = 1000  # Number of requests to keep in memory
        self.time_windows = {
            'short': timedelta(seconds=60),    # 1 minute window
            'medium': timedelta(minutes=5),    # 5 minute window
            'long': timedelta(minutes=15)      # 15 minute window
        }
        
        # Traffic statistics storage
        self.traffic_history = deque(maxlen=self.window_size)
        self.ip_profiles = {}  # Store behavior profiles for IP addresses
        self.user_agents = {}  # Store user agent patterns
        
        # Anomaly detection thresholds (configurable)
        self.thresholds = {
            'request_rate': 100,      # Requests per second
            'error_rate': 0.5,        # 50% error rate threshold
            'burst_threshold': 1000,  # Burst requests in 10 seconds
            'geo_anomaly': 0.8,       # Geographic anomaly score
            'behavior_anomaly': 2.5,  # Z-score for behavior
        }
        
        # Initialize ML models for anomaly detection
        self._initialize_models()
        
        # Baseline traffic patterns (learned over time)
        self.baselines = self._load_baselines()
        
        # Attack signature database
        self.attack_signatures = self._load_attack_signatures()
        
        # Rate limiting rules
        self.rate_limits = {
            'ip': {'limit': 100, 'window': 60},      # 100 requests/minute per IP
            'endpoint': {'limit': 500, 'window': 60}, # 500 requests/minute per endpoint
            'user': {'limit': 50, 'window': 60},     # 50 requests/minute per user
        }
        
        # Metrics tracking
        self.metrics = {
            'total_requests': 0,
            'anomalies_detected': 0,
            'false_positives': 0,
            'avg_processing_time': 0.0,
        }
    
    def _initialize_models(self):
        """
        Initialize machine learning models for anomaly detection
        
        Models used:
        1. Autoencoder for unsupervised anomaly detection
        2. Isolation Forest for outlier detection
        3. LSTM for time-series prediction
        4. Random Forest for classification
        """
        try:
            # Autoencoder for traffic pattern reconstruction
            self.autoencoder = self._create_autoencoder()
            # Note: In production, these would be pre-trained models
            print(f"✅ {self.name}: ML models initialized")
        except Exception as e:
            print(f"⚠️ {self.name}: Model initialization failed: {e}")
            # Fallback to statistical methods
            self.autoencoder = None
    
    def _create_autoencoder(self) -> nn.Module:
        """
        Create autoencoder neural network for anomaly detection
        
        Autoencoders learn to reconstruct normal traffic patterns.
        Anomalies have high reconstruction error.
        """
        class TrafficAutoencoder(nn.Module):
            def __init__(self, input_dim=10, encoding_dim=3):
                super().__init__()
                # Encoder: Compress input to lower dimension
                self.encoder = nn.Sequential(
                    nn.Linear(input_dim, 7),
                    nn.ReLU(),
                    nn.Linear(7, 5),
                    nn.ReLU(),
                    nn.Linear(5, encoding_dim),
                    nn.ReLU()
                )
                # Decoder: Reconstruct from compressed representation
                self.decoder = nn.Sequential(
                    nn.Linear(encoding_dim, 5),
                    nn.ReLU(),
                    nn.Linear(5, 7),
                    nn.ReLU(),
                    nn.Linear(7, input_dim),
                    nn.Sigmoid()  # Output between 0-1
                )
            
            def forward(self, x):
                encoded = self.encoder(x)
                decoded = self.decoder(encoded)
                return decoded, encoded
        
        return TrafficAutoencoder()
    
    def _load_baselines(self) -> Dict[str, Any]:
        """
        Load or compute baseline traffic patterns
        
        Baselines are learned from historical data and represent
        normal traffic behavior for this application
        """
        return {
            'hourly_pattern': np.zeros(24),  # Requests per hour
            'daily_pattern': np.zeros(7),    # Requests per day of week
            'endpoint_patterns': {},         # Normal traffic per endpoint
            'geo_patterns': {},              # Geographic distribution
            'user_agent_patterns': {}        # Normal user agent distribution
        }
    
    def _load_attack_signatures(self) -> Dict[str, List[str]]:
        """
        Load known attack signatures for pattern matching
        
        These signatures help identify common attack patterns:
        - DDoS traffic patterns
        - Scanner fingerprints
        - Bot behavior
        - Exploit kit signatures
        """
        return {
            'ddos': [
                'SYN flood', 'UDP flood', 'ICMP flood', 
                'HTTP flood', 'Slowloris', 'RUDY'
            ],
            'scanner': [
                'nmap', 'nikto', 'sqlmap', 'wpscan', 
                'dirbuster', 'gobuster', 'burpsuite'
            ],
            'bot': [
                'headless browser', 'automated tool',
                'request burst', 'no javascript',
                'missing cookies'
            ],
            'exploit': [
                'buffer overflow pattern',
                'command injection attempt',
                'path traversal attempt'
            ]
        }
    
    def analyze(self, security_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze traffic data for anomalies
        
        Process flow:
        1. Extract traffic features
        2. Compute metrics
        3. Check against baselines
        4. Apply ML models
        5. Check rate limits
        6. Generate findings
        
        Args:
            security_data: Dictionary containing traffic data
                Required keys: 'request', 'response', 'timestamp', 'ip_address'
                Optional keys: 'user_agent', 'endpoint', 'method', 'headers'
        
        Returns:
            Dictionary with analysis results
        """
        start_time = time.time()
        
        try:
            # Step 1: Validate and extract data
            if not self._validate_traffic_data(security_data):
                return self._error_response("Invalid traffic data")
            
            # Extract features from traffic data
            features = self._extract_features(security_data)
            
            # Step 2: Update traffic history and metrics
            self._update_traffic_history(security_data, features)
            
            # Step 3: Compute current metrics
            current_metrics = self._compute_metrics(features)
            
            # Step 4: Check for anomalies using multiple techniques
            anomalies = []
            
            # 4a. Statistical anomaly detection
            stat_anomalies = self._detect_statistical_anomalies(current_metrics)
            anomalies.extend(stat_anomalies)
            
            # 4b. ML-based anomaly detection
            ml_anomalies = self._detect_ml_anomalies(features)
            anomalies.extend(ml_anomalies)
            
            # 4c. Rate limiting checks
            rate_anomalies = self._check_rate_limits(security_data)
            anomalies.extend(rate_anomalies)
            
            # 4d. Behavioral anomaly detection
            behavior_anomalies = self._detect_behavioral_anomalies(security_data)
            anomalies.extend(behavior_anomalies)
            
            # 4e. Geographic anomaly detection
            geo_anomalies = self._detect_geographic_anomalies(security_data)
            anomalies.extend(geo_anomalies)
            
            # 4f. Time-based anomaly detection
            time_anomalies = self._detect_time_anomalies(security_data)
            anomalies.extend(time_anomalies)
            
            # Step 5: Compute threat level and confidence
            threat_level, confidence = self._compute_threat_level(anomalies)
            
            # Step 6: Update agent confidence
            self.update_confidence({'certainty': confidence})
            
            # Step 7: Update metrics
            processing_time = time.time() - start_time
            self._update_metrics(processing_time, len(anomalies) > 0)
            
            # Prepare response
            response = {
                'agent_id': self.agent_id,
                'agent_name': self.name,
                'analysis_timestamp': datetime.now().isoformat(),
                'processing_time': processing_time,
                'metrics': current_metrics.__dict__,
                'anomalies': anomalies,
                'threat_level': threat_level,
                'confidence': confidence,
                'recommended_action': self._get_recommended_action(anomalies, threat_level),
                'rate_limit_status': self._get_rate_limit_status(security_data),
                'behavioral_insights': self._get_behavioral_insights(security_data),
                'reasoning_state': self.get_reasoning_state(),
                'decision': {
                    'threat_level': threat_level,
                    'confidence': confidence,
                    'evidence': anomalies[:5]  # Top 5 anomalies as evidence
                }
            }
            
            return response
            
        except Exception as e:
            print(f"❌ {self.name}: Analysis error: {e}")
            return self._error_response(str(e))
    
    def _validate_traffic_data(self, data: Dict) -> bool:
        """
        Validate that traffic data has required fields
        
        Returns:
            True if data is valid, False otherwise
        """
        required_fields = ['request', 'timestamp', 'ip_address']
        
        for field in required_fields:
            if field not in data:
                print(f"⚠️ Missing required field: {field}")
                return False
        
        # Validate timestamp format
        try:
            datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
        except (ValueError, TypeError):
            print(f"⚠️ Invalid timestamp format: {data['timestamp']}")
            return False
        
        # Validate IP address format
        ip = data['ip_address']
        if not (isinstance(ip, str) and 7 <= len(ip) <= 45):
            print(f"⚠️ Invalid IP address: {ip}")
            return False
        
        return True
    
    def _extract_features(self, data: Dict) -> Dict[str, Any]:
        """
        Extract numerical features from traffic data for analysis
        
        Features are normalized and prepared for ML models
        """
        features = {}
        
        # Request features
        request = data.get('request', {})
        features['request_size'] = len(str(request)) / 1000  # Normalized KB
        features['method'] = self._encode_method(request.get('method', 'GET'))
        features['endpoint_complexity'] = self._compute_endpoint_complexity(
            request.get('endpoint', '')
        )
        
        # Temporal features
        timestamp = datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
        features['hour_of_day'] = timestamp.hour / 24.0  # Normalized 0-1
        features['day_of_week'] = timestamp.weekday() / 7.0  # Normalized 0-1
        features['minute_of_hour'] = timestamp.minute / 60.0  # Normalized 0-1
        
        # IP-based features
        ip = data['ip_address']
        features['ip_reputation'] = self._get_ip_reputation(ip)
        features['ip_frequency'] = self._get_ip_frequency(ip)
        
        # User agent features
        user_agent = data.get('user_agent', '')
        features['ua_length'] = len(user_agent) / 1000  # Normalized
        features['ua_entropy'] = self._compute_entropy(user_agent)
        features['is_browser'] = self._is_browser_user_agent(user_agent)
        
        # Response features (if available)
        response = data.get('response', {})
        features['response_size'] = response.get('size', 0) / 1000  # KB
        features['response_time'] = response.get('time', 0) / 1000  # Seconds
        features['status_code'] = response.get('status', 200) / 500.0  # Normalized
        
        # Protocol features
        features['is_https'] = 1.0 if data.get('protocol') == 'HTTPS' else 0.0
        features['has_referer'] = 1.0 if data.get('referer') else 0.0
        features['has_cookies'] = 1.0 if data.get('cookies') else 0.0
        
        return features
    
    def _encode_method(self, method: str) -> float:
        """
        Encode HTTP method as numerical value
        
        Some methods are more suspicious than others:
        - DELETE, PUT, PATCH: Higher risk
        - POST: Medium risk
        - GET, HEAD: Lower risk
        """
        method_risk = {
            'DELETE': 1.0, 'PUT': 0.9, 'PATCH': 0.8,
            'POST': 0.6, 'OPTIONS': 0.4, 
            'GET': 0.2, 'HEAD': 0.1
        }
        return method_risk.get(method.upper(), 0.5)
    
    def _compute_endpoint_complexity(self, endpoint: str) -> float:
        """
        Compute complexity score for endpoint
        
        Complex endpoints (API routes, parameters) are more 
        likely to be targeted by attacks
        """
        if not endpoint:
            return 0.0
        
        complexity = 0.0
        
        # Add complexity for API endpoints
        if '/api/' in endpoint:
            complexity += 0.3
        
        # Add complexity for parameters
        if '?' in endpoint:
            complexity += 0.2
            # More parameters = more complex
            params = endpoint.split('?')[1]
            param_count = len(params.split('&'))
            complexity += min(0.3, param_count * 0.05)
        
        # Add complexity for deep paths
        path_depth = endpoint.count('/')
        complexity += min(0.2, path_depth * 0.05)
        
        # Add complexity for special characters
        special_chars = sum(1 for c in endpoint if c in '{}[]().*+?|\\')
        complexity += min(0.2, special_chars * 0.05)
        
        return min(1.0, complexity)
    
    def _get_ip_reputation(self, ip: str) -> float:
        """
        Get IP reputation score (0.0 = bad, 1.0 = good)
        
        In production, this would query external reputation services
        """
        # Check internal blacklist/whitelist
        if hasattr(self, 'ip_blacklist') and ip in self.ip_blacklist:
            return 0.0
        
        if hasattr(self, 'ip_whitelist') and ip in self.ip_whitelist:
            return 1.0
        
        # Default: unknown reputation
        return 0.5
    
    def _get_ip_frequency(self, ip: str) -> float:
        """
        Get frequency of this IP in recent traffic (normalized)
        """
        if not self.traffic_history:
            return 0.0
        
        # Count occurrences in last window
        recent_ips = [entry['ip'] for entry in self.traffic_history 
                     if time.time() - entry['timestamp'] < 300]  # 5 minutes
        
        if not recent_ips:
            return 0.0
        
        ip_count = recent_ips.count(ip)
        return min(1.0, ip_count / len(recent_ips))
    
    def _compute_entropy(self, text: str) -> float:
        """
        Compute Shannon entropy of text
        
        Higher entropy = more random/compressed data
        Useful for detecting encoded/obfuscated payloads
        """
        if not text:
            return 0.0
        
        # Count character frequencies
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        # Compute entropy
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            probability = count / length
            entropy -= probability * np.log2(probability)
        
        # Normalize to 0-1 range
        max_entropy = np.log2(len(set(text))) if text else 0
        return entropy / max_entropy if max_entropy > 0 else 0.0
    
    def _is_browser_user_agent(self, ua: str) -> float:
        """
        Determine if user agent appears to be a real browser
        
        Returns confidence score (0.0 to 1.0)
        """
        if not ua:
            return 0.0
        
        ua_lower = ua.lower()
        
        # Real browser indicators
        browser_keywords = [
            'chrome', 'firefox', 'safari', 'edge', 'opera',
            'mozilla', 'webkit', 'gecko', 'trident'
        ]
        
        # Bot/scanner indicators
        bot_keywords = [
            'bot', 'crawler', 'spider', 'scanner',
            'headless', 'python', 'curl', 'wget',
            'java', 'php', 'ruby'
        ]
        
        # Check for browser keywords
        browser_score = sum(1 for kw in browser_keywords if kw in ua_lower)
        
        # Check for bot keywords
        bot_score = sum(1 for kw in bot_keywords if kw in ua_lower)
        
        # Compute confidence
        total = browser_score + bot_score
        if total == 0:
            return 0.5  # Unknown
        
        return browser_score / total
    
    def _update_traffic_history(self, data: Dict, features: Dict):
        """
        Update traffic history with new request
        """
        entry = {
            'timestamp': time.time(),
            'ip': data['ip_address'],
            'endpoint': data.get('request', {}).get('endpoint', ''),
            'method': data.get('request', {}).get('method', 'GET'),
            'status': data.get('response', {}).get('status', 200),
            'response_time': data.get('response', {}).get('time', 0),
            'user_agent': data.get('user_agent', ''),
            'features': features
        }
        
        self.traffic_history.append(entry)
        
        # Update IP profile
        ip = data['ip_address']
        if ip not in self.ip_profiles:
            self.ip_profiles[ip] = {
                'request_count': 0,
                'last_seen': 0,
                'endpoints': set(),
                'user_agents': set()
            }
        
        profile = self.ip_profiles[ip]
        profile['request_count'] += 1
        profile['last_seen'] = time.time()
        profile['endpoints'].add(data.get('request', {}).get('endpoint', ''))
        profile['user_agents'].add(data.get('user_agent', ''))
    
    def _compute_metrics(self, features: Dict) -> TrafficMetrics:
        """
        Compute comprehensive traffic metrics
        """
        if not self.traffic_history:
            return TrafficMetrics()
        
        # Get recent traffic (last 5 minutes)
        recent_traffic = [
            entry for entry in self.traffic_history
            if time.time() - entry['timestamp'] < 300
        ]
        
        if not recent_traffic:
            return TrafficMetrics()
        
        # Compute metrics
        request_count = len(recent_traffic)
        request_rate = request_count / 300  # per second
        
        # Average response time
        response_times = [entry['response_time'] for entry in recent_traffic 
                         if entry['response_time'] > 0]
        avg_response_time = np.mean(response_times) if response_times else 0
        
        # Error rate
        error_count = sum(1 for entry in recent_traffic 
                         if entry['status'] >= 400)
        error_rate = error_count / request_count if request_count > 0 else 0
        
        # Unique IPs
        unique_ips = len(set(entry['ip'] for entry in recent_traffic))
        
        # Data transferred (estimate)
        data_transferred = sum(
            len(str(entry)) / 1024 / 1024  # MB
            for entry in recent_traffic
        )
        
        # Request entropy
        endpoints = [entry['endpoint'] for entry in recent_traffic]
        request_entropy = self._compute_entropy(''.join(endpoints))
        
        return TrafficMetrics(
            request_count=request_count,
            request_rate=request_rate,
            avg_response_time=avg_response_time,
            error_rate=error_rate,
            unique_ips=unique_ips,
            data_transferred=data_transferred,
            request_entropy=request_entropy
        )
    
    def _detect_statistical_anomalies(self, metrics: TrafficMetrics) -> List[Dict]:
        """
        Detect anomalies using statistical methods
        """
        anomalies = []
        
        # 1. Check request rate threshold
        if metrics.request_rate > self.thresholds['request_rate']:
            anomalies.append({
                'type': 'HIGH_REQUEST_RATE',
                'severity': 'HIGH',
                'description': f'Request rate ({metrics.request_rate:.1f}/s) exceeds threshold',
                'metric': 'request_rate',
                'value': metrics.request_rate,
                'threshold': self.thresholds['request_rate']
            })
        
        # 2. Check error rate threshold
        if metrics.error_rate > self.thresholds['error_rate']:
            anomalies.append({
                'type': 'HIGH_ERROR_RATE',
                'severity': 'MEDIUM',
                'description': f'Error rate ({metrics.error_rate:.1%}) exceeds threshold',
                'metric': 'error_rate',
                'value': metrics.error_rate,
                'threshold': self.thresholds['error_rate']
            })
        
        # 3. Check for traffic bursts
        if len(self.traffic_history) >= 10:
            recent_counts = []
            for i in range(0, len(self.traffic_history), 10):
                window = list(self.traffic_history)[i:i+10]
                if window:
                    recent_counts.append(len(window))
            
            if recent_counts:
                avg_count = np.mean(recent_counts)
                std_count = np.std(recent_counts)
                latest_count = recent_counts[-1] if recent_counts else 0
                
                if std_count > 0 and latest_count > avg_count + 2 * std_count:
                    anomalies.append({
                        'type': 'TRAFFIC_BURST',
                        'severity': 'MEDIUM',
                        'description': f'Traffic burst detected: {latest_count} requests in window',
                        'metric': 'burst_size',
                        'value': latest_count,
                        'average': avg_count
                    })
        
        # 4. Check unique IP ratio
        if metrics.request_count > 0:
            ip_ratio = metrics.unique_ips / metrics.request_count
            if ip_ratio > 0.8:  # Many unique IPs (possible DDoS)
                anomalies.append({
                    'type': 'HIGH_UNIQUE_IP_RATIO',
                    'severity': 'HIGH',
                    'description': f'High unique IP ratio ({ip_ratio:.1%}) - possible DDoS',
                    'metric': 'unique_ip_ratio',
                    'value': ip_ratio,
                    'threshold': 0.8
                })
        
        return anomalies
    
    def _detect_ml_anomalies(self, features: Dict) -> List[Dict]:
        """
        Detect anomalies using machine learning models
        """
        anomalies = []
        
        if self.autoencoder is not None:
            try:
                # Prepare features for autoencoder
                feature_vector = self._create_feature_vector(features)
                
                # Convert to tensor
                features_tensor = torch.tensor([feature_vector], dtype=torch.float32)
                
                # Get reconstruction
                self.autoencoder.eval()
                with torch.no_grad():
                    reconstructed, _ = self.autoencoder(features_tensor)
                
                # Compute reconstruction error
                reconstruction_error = torch.mean(
                    (features_tensor - reconstructed) ** 2
                ).item()
                
                # If error is high, it's an anomaly
                if reconstruction_error > 0.1:  # Threshold
                    anomalies.append({
                        'type': 'ML_ANOMALY',
                        'severity': 'MEDIUM',
                        'description': f'ML model detected anomaly (error: {reconstruction_error:.3f})',
                        'model': 'autoencoder',
                        'error': reconstruction_error,
                        'threshold': 0.1
                    })
                    
            except Exception as e:
                print(f"⚠️ ML anomaly detection failed: {e}")
        
        return anomalies
    
    def _create_feature_vector(self, features: Dict) -> List[float]:
        """
        Create normalized feature vector for ML models
        """
        # Select key features for anomaly detection
        key_features = [
            features.get('request_size', 0),
            features.get('method', 0),
            features.get('endpoint_complexity', 0),
            features.get('hour_of_day', 0),
            features.get('ip_reputation', 0.5),
            features.get('ip_frequency', 0),
            features.get('ua_entropy', 0),
            features.get('is_browser', 0.5),
            features.get('response_time', 0),
            features.get('status_code', 0.4)
        ]
        
        # Normalize to 0-1 range
        normalized = []
        for value in key_features:
            if isinstance(value, (int, float)):
                normalized.append(min(1.0, max(0.0, value)))
            else:
                normalized.append(0.0)
        
        return normalized
    
    def _check_rate_limits(self, data: Dict) -> List[Dict]:
        """
        Check if request violates rate limits
        """
        anomalies = []
        
        ip = data['ip_address']
        endpoint = data.get('request', {}).get('endpoint', '')
        user = data.get('user', {}).get('id', 'anonymous')
        
        current_time = time.time()
        
        # Check IP rate limit
        ip_key = f"ip:{ip}"
        if self._is_rate_limited(ip_key, 'ip', current_time):
            anomalies.append({
                'type': 'IP_RATE_LIMIT',
                'severity': 'MEDIUM',
                'description': f'IP {ip} exceeded rate limit',
                'limit_type': 'ip',
                'ip': ip
            })
        
        # Check endpoint rate limit
        endpoint_key = f"endpoint:{endpoint}"
        if self._is_rate_limited(endpoint_key, 'endpoint', current_time):
            anomalies.append({
                'type': 'ENDPOINT_RATE_LIMIT',
                'severity': 'MEDIUM',
                'description': f'Endpoint {endpoint} exceeded rate limit',
                'limit_type': 'endpoint',
                'endpoint': endpoint
            })
        
        # Check user rate limit
        user_key = f"user:{user}"
        if self._is_rate_limited(user_key, 'user', current_time):
            anomalies.append({
                'type': 'USER_RATE_LIMIT',
                'severity': 'MEDIUM',
                'description': f'User {user} exceeded rate limit',
                'limit_type': 'user',
                'user': user
            })
        
        return anomalies
    
    def _is_rate_limited(self, key: str, limit_type: str, current_time: float) -> bool:
        """
        Check if a key is rate limited
        
        Implements sliding window rate limiting
        """
        if not hasattr(self, 'rate_limit_windows'):
            self.rate_limit_windows = {}
        
        if key not in self.rate_limit_windows:
            self.rate_limit_windows[key] = []
        
        # Get window configuration
        config = self.rate_limits.get(limit_type, {'limit': 100, 'window': 60})
        limit = config['limit']
        window_seconds = config['window']
        
        # Clean old entries outside window
        window_start = current_time - window_seconds
        self.rate_limit_windows[key] = [
            ts for ts in self.rate_limit_windows[key]
            if ts > window_start
        ]
        
        # Check if limit exceeded
        if len(self.rate_limit_windows[key]) >= limit:
            return True
        
        # Add current request
        self.rate_limit_windows[key].append(current_time)
        return False
    
    def _detect_behavioral_anomalies(self, data: Dict) -> List[Dict]:
        """
        Detect behavioral anomalies (unusual patterns for this IP/user)
        """
        anomalies = []
        ip = data['ip_address']
        
        if ip in self.ip_profiles:
            profile = self.ip_profiles[ip]
            
            # Check for sudden change in behavior
            current_endpoint = data.get('request', {}).get('endpoint', '')
            current_ua = data.get('user_agent', '')
            
            # Endpoint anomaly: accessing new/different endpoints
            if (current_endpoint and 
                current_endpoint not in profile['endpoints'] and
                len(profile['endpoints']) > 5):  # Has established pattern
                
                anomalies.append({
                    'type': 'NEW_ENDPOINT_ACCESS',
                    'severity': 'LOW',
                    'description': f'IP {ip} accessed new endpoint: {current_endpoint}',
                    'ip': ip,
                    'endpoint': current_endpoint,
                    'known_endpoints': list(profile['endpoints'])[:5]  # First 5
                })
            
            # User agent anomaly: sudden change in UA
            if (current_ua and 
                current_ua not in profile['user_agents'] and
                len(profile['user_agents']) > 2):
                
                anomalies.append({
                    'type': 'USER_AGENT_CHANGE',
                    'severity': 'LOW',
                    'description': f'IP {ip} changed user agent',
                    'ip': ip,
                    'new_user_agent': current_ua[:100],  # Truncate
                    'known_user_agents': list(profile['user_agents'])
                })
            
            # Request frequency anomaly
            request_count = profile['request_count']
            time_since_first = time.time() - profile.get('first_seen', time.time())
            
            if time_since_first > 3600:  # More than 1 hour of data
                avg_rate = request_count / time_since_first
                recent_rate = self._get_recent_request_rate(ip)
                
                if recent_rate > avg_rate * 3:  # 3x increase
                    anomalies.append({
                        'type': 'REQUEST_FREQUENCY_SPIKE',
                        'severity': 'MEDIUM',
                        'description': f'IP {ip} increased request rate 3x',
                        'ip': ip,
                        'avg_rate': avg_rate,
                        'recent_rate': recent_rate
                    })
        
        return anomalies
    
    def _get_recent_request_rate(self, ip: str, window_seconds: int = 300) -> float:
        """
        Get request rate for IP in recent window
        """
        recent_requests = [
            entry for entry in self.traffic_history
            if entry['ip'] == ip and 
            time.time() - entry['timestamp'] < window_seconds
        ]
        
        return len(recent_requests) / window_seconds if window_seconds > 0 else 0
    
    def _detect_geographic_anomalies(self, data: Dict) -> List[Dict]:
        """
        Detect geographic anomalies (requests from unusual locations)
        """
        anomalies = []
        
        # In production, this would use GeoIP database
        ip = data['ip_address']
        
        # Mock geographic check (replace with real GeoIP)
        suspect_countries = ['CN', 'RU', 'KP', 'IR']  # Example
        mock_country = self._get_mock_country(ip)
        
        if mock_country in suspect_countries:
            anomalies.append({
                'type': 'SUSPECT_GEO_LOCATION',
                'severity': 'LOW',
                'description': f'Request from suspicious country: {mock_country}',
                'ip': ip,
                'country': mock_country,
                'note': 'Country in watchlist'
            })
        
        # Check for geographic hopping (if we had location history)
        if hasattr(self, 'ip_locations') and ip in self.ip_locations:
            current_location = mock_country
            previous_locations = self.ip_locations[ip]
            
            if (current_location not in previous_locations and
                len(previous_locations) > 0):
                
                anomalies.append({
                    'type': 'GEOGRAPHIC_HOPPING',
                    'severity': 'MEDIUM',
                    'description': f'IP {ip} changed country from {previous_locations[-1]} to {current_location}',
                    'ip': ip,
                    'previous_country': previous_locations[-1],
                    'current_country': current_location
                })
        
        return anomalies
    
    def _get_mock_country(self, ip: str) -> str:
        """
        Mock GeoIP lookup (replace with real GeoIP service)
        """
        # Simple hash-based mock
        hash_val = int(hashlib.md5(ip.encode()).hexdigest(), 16)
        countries = ['US', 'GB', 'DE', 'FR', 'JP', 'CN', 'RU', 'IN', 'BR', 'AU']
        return countries[hash_val % len(countries)]
    
    def _detect_time_anomalies(self, data: Dict) -> List[Dict]:
        """
        Detect time-based anomalies (unusual access times)
        """
        anomalies = []
        
        timestamp = datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
        hour = timestamp.hour
        
        # Check if outside normal business hours
        if hour < 6 or hour > 22:  # 10PM to 6AM
            anomalies.append({
                'type': 'AFTER_HOURS_ACCESS',
                'severity': 'LOW',
                'description': f'Access during off-hours: {hour}:00',
                'hour': hour,
                'note': 'Outside typical business hours (6AM-10PM)'
            })
        
        # Check weekend access (if applicable)
        if timestamp.weekday() >= 5:  # Saturday or Sunday
            anomalies.append({
                'type': 'WEEKEND_ACCESS',
                'severity': 'LOW',
                'description': 'Access on weekend',
                'day': timestamp.strftime('%A'),
                'note': 'Weekend access pattern'
            })
        
        return anomalies
    
    def _compute_threat_level(self, anomalies: List[Dict]) -> Tuple[float, float]:
        """
        Compute overall threat level and confidence
        
        Threat level: 0.0 (safe) to 1.0 (critical)
        Confidence: 0.0 (uncertain) to 1.0 (certain)
        """
        if not anomalies:
            return 0.1, 0.8  # Low threat, high confidence
        
        # Weight anomalies by severity
        severity_weights = {
            'CRITICAL': 1.0,
            'HIGH': 0.7,
            'MEDIUM': 0.4,
            'LOW': 0.1
        }
        
        total_weight = 0.0
        max_possible_weight = 0.0
        
        for anomaly in anomalies:
            severity = anomaly.get('severity', 'LOW')
            weight = severity_weights.get(severity, 0.1)
            total_weight += weight
            max_possible_weight += 1.0  # Max if all were CRITICAL
        
        # Compute threat level (normalized)
        threat_level = min(1.0, total_weight / max_possible_weight)
        
        # Compute confidence based on number and severity of anomalies
        confidence_factors = []
        
        # More anomalies = higher confidence
        anomaly_count_factor = min(1.0, len(anomalies) / 10)
        confidence_factors.append(anomaly_count_factor)
        
        # Higher severity anomalies = higher confidence
        high_severity_count = sum(1 for a in anomalies 
                                 if a.get('severity') in ['HIGH', 'CRITICAL'])
        severity_factor = min(1.0, high_severity_count / 3)
        confidence_factors.append(severity_factor)
        
        # Agent's own confidence
        confidence_factors.append(self.confidence)
        
        # Average confidence factors
        confidence = np.mean(confidence_factors)
        
        return threat_level, confidence
    
    def _get_recommended_action(self, anomalies: List[Dict], threat_level: float) -> str:
        """
        Get recommended action based on anomalies and threat level
        """
        if threat_level < 0.3:
            return "MONITOR - Continue monitoring traffic patterns"
        
        # Count high severity anomalies
        high_severity = [a for a in anomalies 
                        if a.get('severity') in ['HIGH', 'CRITICAL']]
        
        if threat_level > 0.8 or len(high_severity) >= 3:
            return "BLOCK - Critical threat detected, block source IP"
        
        if threat_level > 0.6 or len(high_severity) >= 1:
            return "CHALLENGE - Apply CAPTCHA or rate limiting"
        
        if threat_level > 0.4:
            return "ALERT - Notify security team for investigation"
        
        return "LOG - Record anomaly for future analysis"
    
    def _get_rate_limit_status(self, data: Dict) -> Dict[str, Any]:
        """
        Get current rate limit status for this request
        """
        ip = data['ip_address']
        endpoint = data.get('request', {}).get('endpoint', '')
        
        status = {
            'ip': ip,
            'endpoint': endpoint,
            'limits': {}
        }
        
        for limit_type, config in self.rate_limits.items():
            key = f"{limit_type}:{ip if limit_type == 'ip' else endpoint}"
            
            if hasattr(self, 'rate_limit_windows') and key in self.rate_limit_windows:
                requests = len(self.rate_limit_windows[key])
                remaining = max(0, config['limit'] - requests)
                
                status['limits'][limit_type] = {
                    'requests': requests,
                    'limit': config['limit'],
                    'remaining': remaining,
                    'window_seconds': config['window'],
                    'percentage': (requests / config['limit']) * 100
                }
        
        return status
    
    def _get_behavioral_insights(self, data: Dict) -> Dict[str, Any]:
        """
        Get behavioral insights for this request
        """
        ip = data['ip_address']
        
        if ip not in self.ip_profiles:
            return {'ip': ip, 'status': 'No profile yet'}
        
        profile = self.ip_profiles[ip]
        
        return {
            'ip': ip,
            'request_count': profile['request_count'],
            'endpoint_diversity': len(profile['endpoints']),
            'user_agent_diversity': len(profile['user_agents']),
            'last_seen': datetime.fromtimestamp(profile['last_seen']).isoformat(),
            'is_returning': profile['request_count'] > 1,
            'behavior_stability': self._compute_behavior_stability(profile)
        }
    
    def _compute_behavior_stability(self, profile: Dict) -> float:
        """
        Compute behavior stability score (0.0 to 1.0)
        
        Higher score = more stable/consistent behavior
        """
        if profile['request_count'] < 3:
            return 0.5  # Not enough data
        
        # More requests = more established pattern
        request_factor = min(1.0, profile['request_count'] / 100)
        
        # Fewer endpoints = more focused behavior
        if profile['request_count'] > 0:
            endpoint_factor = 1.0 - min(1.0, len(profile['endpoints']) / 20)
        else:
            endpoint_factor = 0.5
        
        # Fewer user agents = more consistent
        ua_factor = 1.0 - min(1.0, len(profile['user_agents']) / 5)
        
        # Weighted average
        stability = (request_factor * 0.4 + 
                    endpoint_factor * 0.3 + 
                    ua_factor * 0.3)
        
        return stability
    
    def _update_metrics(self, processing_time: float, anomaly_detected: bool):
        """
        Update agent metrics
        """
        self.metrics['total_requests'] += 1
        
        # Update average processing time (exponential moving average)
        alpha = 0.1
        self.metrics['avg_processing_time'] = (
            alpha * processing_time + 
            (1 - alpha) * self.metrics['avg_processing_time']
        )
        
        if anomaly_detected:
            self.metrics['anomalies_detected'] += 1
    
    def _error_response(self, error_message: str) -> Dict[str, Any]:
        """
        Generate error response when analysis fails
        """
        return {
            'agent_id': self.agent_id,
            'agent_name': self.name,
            'error': error_message,
            'threat_level': 0.5,  # Medium threat when uncertain
            'confidence': 0.1,    # Low confidence due to error
            'anomalies': [],
            'recommended_action': 'INVESTIGATE - Agent analysis failed',
            'reasoning_state': self.get_reasoning_state(),
            'decision': {
                'threat_level': 0.5,
                'confidence': 0.1,
                'evidence': [{'type': 'AGENT_ERROR', 'description': error_message}]
            }
        }
    
    def get_agent_status(self) -> Dict[str, Any]:
        """
        Get comprehensive agent status
        """
        return {
            'agent_id': self.agent_id,
            'name': self.name,
            'status': 'ACTIVE',
            'confidence': self.confidence,
            'metrics': self.metrics,
            'traffic_stats': {
                'history_size': len(self.traffic_history),
                'unique_ips_tracked': len(self.ip_profiles),
                'rate_limits_active': len(getattr(self, 'rate_limit_windows', {})),
                'avg_processing_time': self.metrics['avg_processing_time']
            },
            'config': {
                'window_size': self.window_size,
                'thresholds': self.thresholds,
                'rate_limits': self.rate_limits
            }
        }