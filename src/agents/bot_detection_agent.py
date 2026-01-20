# src/agents/bot_detection_agent.py
"""
Bot Detection Agent
Purpose: Detects automated bots, scrapers, headless browsers, and malicious automation
Techniques: Behavioral analysis, fingerprinting, ML models, CAPTCHA challenges
"""

import re
import hashlib
from typing import Dict, List, Any, Set
import numpy as np
from datetime import datetime
import time
from collections import defaultdict
import json

from .base_agent import SecurityAgent, AgentCapability

class BotDetectionAgent(SecurityAgent):
    """
    Bot Detection Agent
    
    This agent specializes in detecting:
    1. Web scrapers and crawlers
    2. Headless browsers
    3. Automated tools (curl, wget, python requests)
    4. Malicious bots (credential stuffers, vulnerability scanners)
    5. DDoS bots
    6. SEO spam bots
    7. Click fraud bots
    8. API abuse bots
    
    Techniques used:
    - User agent analysis
    - Behavioral fingerprinting
    - JavaScript execution detection
    - Mouse movement analysis
    - Timing analysis
    - Header analysis
    - CAPTCHA challenges
    """
    
    def __init__(self, agent_id: str = "bot_detection_001"):
        super().__init__(
            agent_id=agent_id,
            name="Bot Detection Agent",
            state_dim=256
        )
        
        # Add bot detection capability
        self.capabilities.append(AgentCapability.BOT_DETECTION)
        
        # Known bot signatures database
        self.bot_signatures = self._load_bot_signatures()
        
        # Headless browser detection patterns
        self.headless_patterns = [
            r'HeadlessChrome',
            r'PhantomJS',
            r'Nightmare',
            r'CasperJS',
            r'SlimerJS',
            r'HtmlUnit',
            r'Trident.*Headless',
            r'WebDriver',
            r'Selenium'
        ]
        
        # Automated tool patterns
        self.automated_tools = [
            r'curl/', r'wget/', r'python-requests/',
            r'python-urllib/', r'Java/', r'Go-http-client/',
            r'Ruby', r'Perl', r'PHP', r'node-fetch/',
            r'axios/', r'okhttp/'
        ]
        
        # Malicious bot patterns
        self.malicious_bots = [
            r'sqlmap', r'nmap', r'nikto', r'wpscan',
            r'dirbuster', r'gobuster', r'ffuf',
            r'burpsuite', r'zap', r'metasploit',
            r'nessus', r'openvas', r'acunetix'
        ]
        
        # Behavioral tracking
        self.behavior_profiles = {}  # IP -> behavior profile
        self.js_execution_rates = {}  # IP -> JS execution success rate
        self.mouse_tracking = {}     # IP -> mouse movement patterns
        
        # Detection thresholds
        self.thresholds = {
            'bot_confidence': 0.7,
            'headless_confidence': 0.8,
            'automated_confidence': 0.6,
            'malicious_confidence': 0.9,
            'behavior_anomaly': 0.75,
            'js_execution_threshold': 0.3,  # <30% JS execution = bot
            'request_timing_threshold': 0.5  # Too consistent timing = bot
        }
        
        # CAPTCHA configuration
        self.captcha_config = {
            'enabled': True,
            'difficulty': 'medium',
            'failure_limit': 3,
            'challenge_types': ['image', 'math', 'invisible']
        }
        
        # Metrics
        self.metrics = {
            'total_requests': 0,
            'bots_detected': 0,
            'false_positives': 0,
            'captchas_served': 0,
            'captchas_passed': 0,
            'captchas_failed': 0
        }
        
        # Bot fingerprint database
        self.bot_fingerprints = set()
        
        # Load ML model for bot detection
        self._load_ml_model()
    
    def _load_bot_signatures(self) -> Dict[str, List[str]]:
        """
        Load known bot signatures from database
        
        Categories:
        - Search engine bots (Googlebot, Bingbot)
        - Social media bots (Twitterbot, FacebookExternalHit)
        - Monitoring bots (Pingdom, UptimeRobot)
        - Malicious bots (scrapers, attackers)
        """
        return {
            'search_engine': [
                'Googlebot', 'Bingbot', 'Slurp', 'DuckDuckBot',
                'Baiduspider', 'YandexBot', 'Sogou', 'Exabot'
            ],
            'social_media': [
                'Twitterbot', 'FacebookExternalHit',
                'LinkedInBot', 'Pinterest'
            ],
            'monitoring': [
                'Pingdom', 'UptimeRobot', 'StatusCake',
                'NewRelic', 'Datadog'
            ],
            'analytics': [
                'GoogleAnalytics', 'Mixpanel', 'Hotjar',
                'Matomo', 'Amplitude'
            ],
            'good_bots': [
                'AhrefsBot', 'SEMrushBot', 'MJ12bot',
                'DotBot', 'CCBot'
            ]
        }
    
    def _load_ml_model(self):
        """
        Load machine learning model for bot detection
        
        Model features:
        - User agent analysis
        - Header patterns
        - Request timing
        - Behavioral patterns
        - JavaScript execution
        """
        # In production, load pre-trained model
        # self.model = joblib.load('models/bot_detection_model.pkl')
        self.model = None
        print(f"✅ {self.name}: Bot detection ML model placeholder initialized")
    
    def analyze(self, security_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze request for bot activity
        
        Multi-stage detection:
        1. User agent analysis
        2. Header analysis
        3. Behavioral analysis
        4. JavaScript detection
        5. Timing analysis
        6. ML model prediction
        """
        start_time = time.time()
        
        try:
            # Extract request data
            request = security_data.get('request', {})
            headers = security_data.get('headers', {})
            ip = security_data.get('ip_address', '')
            user_agent = headers.get('User-Agent', '')
            
            # Update metrics
            self.metrics['total_requests'] += 1
            
            # Initialize detection results
            detections = []
            bot_confidence = 0.0
            bot_type = "unknown"
            
            # Stage 1: User Agent Analysis
            ua_detection = self._analyze_user_agent(user_agent)
            if ua_detection['is_bot']:
                detections.append({
                    'stage': 'user_agent',
                    'type': ua_detection['bot_type'],
                    'confidence': ua_detection['confidence'],
                    'evidence': ua_detection['evidence']
                })
                bot_confidence = max(bot_confidence, ua_detection['confidence'])
                bot_type = ua_detection['bot_type']
            
            # Stage 2: Header Analysis
            header_detection = self._analyze_headers(headers)
            if header_detection['is_bot']:
                detections.append({
                    'stage': 'headers',
                    'type': header_detection['bot_type'],
                    'confidence': header_detection['confidence'],
                    'evidence': header_detection['evidence']
                })
                bot_confidence = max(bot_confidence, header_detection['confidence'])
                if bot_type == "unknown":
                    bot_type = header_detection['bot_type']
            
            # Stage 3: Behavioral Analysis (if IP known)
            if ip and ip in self.behavior_profiles:
                behavior_detection = self._analyze_behavior(ip, security_data)
                if behavior_detection['is_bot']:
                    detections.append({
                        'stage': 'behavior',
                        'type': behavior_detection['bot_type'],
                        'confidence': behavior_detection['confidence'],
                        'evidence': behavior_detection['evidence']
                    })
                    bot_confidence = max(bot_confidence, behavior_detection['confidence'])
            
            # Stage 4: JavaScript Execution Analysis
            js_detection = self._analyze_javascript(ip, security_data)
            if js_detection['is_bot']:
                detections.append({
                    'stage': 'javascript',
                    'type': js_detection['bot_type'],
                    'confidence': js_detection['confidence'],
                    'evidence': js_detection['evidence']
                })
                bot_confidence = max(bot_confidence, js_detection['confidence'])
            
            # Stage 5: Timing Analysis
            timing_detection = self._analyze_timing(ip, security_data)
            if timing_detection['is_bot']:
                detections.append({
                    'stage': 'timing',
                    'type': timing_detection['bot_type'],
                    'confidence': timing_detection['confidence'],
                    'evidence': timing_detection['evidence']
                })
                bot_confidence = max(bot_confidence, timing_detection['confidence'])
            
            # Stage 6: ML Model Prediction (if available)
            if self.model:
                ml_detection = self._ml_predict(security_data)
                if ml_detection['is_bot']:
                    detections.append({
                        'stage': 'ml_model',
                        'type': ml_detection['bot_type'],
                        'confidence': ml_detection['confidence'],
                        'evidence': ml_detection['evidence']
                    })
                    bot_confidence = max(bot_confidence, ml_detection['confidence'])
            
            # Update behavior profile
            self._update_behavior_profile(ip, security_data, detections)
            
            # Determine final bot status
            is_bot = bot_confidence > self.thresholds['bot_confidence']
            
            if is_bot:
                self.metrics['bots_detected'] += 1
            
            # Generate response
            response = {
                'agent_id': self.agent_id,
                'agent_name': self.name,
                'analysis_timestamp': datetime.now().isoformat(),
                'processing_time': time.time() - start_time,
                'is_bot': is_bot,
                'bot_confidence': bot_confidence,
                'bot_type': bot_type,
                'detection_stages': detections,
                'captcha_required': self._should_serve_captcha(ip, bot_confidence),
                'recommended_action': self._get_recommended_action(is_bot, bot_confidence, bot_type),
                'fingerprint': self._generate_fingerprint(security_data),
                'behavior_profile': self.behavior_profiles.get(ip, {}),
                'reasoning_state': self.get_reasoning_state(),
                'decision': {
                    'is_bot': is_bot,
                    'confidence': bot_confidence,
                    'bot_type': bot_type,
                    'evidence': detections[:3]  # Top 3 detections
                }
            }
            
            # Update agent confidence
            certainty = 0.5 + (bot_confidence * 0.5) if is_bot else 0.5
            self.update_confidence({'certainty': certainty})
            
            return response
            
        except Exception as e:
            print(f"❌ {self.name}: Bot detection error: {e}")
            return self._error_response(str(e))
    
    def _analyze_user_agent(self, user_agent: str) -> Dict[str, Any]:
        """
        Analyze user agent string for bot signatures
        
        Returns detection results with confidence score
        """
        if not user_agent:
            return {
                'is_bot': False,
                'bot_type': 'unknown',
                'confidence': 0.1,
                'evidence': 'No user agent provided'
            }
        
        ua_lower = user_agent.lower()
        evidence = []
        bot_type = "unknown"
        confidence = 0.0
        
        # Check for known good bots first
        for category, signatures in self.bot_signatures.items():
            for signature in signatures:
                if signature.lower() in ua_lower:
                    return {
                        'is_bot': True,
                        'bot_type': f'known_{category}',
                        'confidence': 0.9,
                        'evidence': f'Known {category} bot: {signature}'
                    }
        
        # Check for headless browsers
        for pattern in self.headless_patterns:
            if re.search(pattern, user_agent, re.IGNORECASE):
                evidence.append(f'Headless browser detected: {pattern}')
                bot_type = 'headless_browser'
                confidence = max(confidence, self.thresholds['headless_confidence'])
        
        # Check for automated tools
        for tool in self.automated_tools:
            if re.search(tool, user_agent, re.IGNORECASE):
                evidence.append(f'Automated tool detected: {tool}')
                bot_type = 'automated_tool'
                confidence = max(confidence, self.thresholds['automated_confidence'])
        
        # Check for malicious bots
        for malicious in self.malicious_bots:
            if re.search(malicious, user_agent, re.IGNORECASE):
                evidence.append(f'Malicious tool detected: {malicious}')
                bot_type = 'malicious_bot'
                confidence = max(confidence, self.thresholds['malicious_confidence'])
        
        # Check for common bot patterns
        if any(pattern in ua_lower for pattern in ['bot', 'crawler', 'spider', 'scraper']):
            if not evidence:
                evidence.append('Generic bot/crawler pattern in user agent')
                bot_type = 'generic_bot'
                confidence = max(confidence, 0.5)
        
        # Check for suspicious patterns
        suspicious_patterns = [
            (r'[0-9]{10}', 'Numeric user agent (likely bot)'),
            (r'mozilla/.*\s+.*\s+.*\s+.*\s+.*', 'Overly specific Mozilla string'),
            (r'\(.*;.*;.*;.*;.*\)', 'Excessive semicolons in UA string'),
            (r'[A-Z]{5,}', 'Excessive uppercase (common in bots)')
        ]
        
        for pattern, description in suspicious_patterns:
            if re.search(pattern, user_agent):
                evidence.append(description)
                confidence = max(confidence, 0.4)
        
        # Check user agent length (very short or very long)
        ua_length = len(user_agent)
        if ua_length < 20:
            evidence.append(f'Very short user agent ({ua_length} chars)')
            confidence = max(confidence, 0.6)
        elif ua_length > 500:
            evidence.append(f'Very long user agent ({ua_length} chars)')
            confidence = max(confidence, 0.5)
        
        # Determine if bot based on evidence
        is_bot = len(evidence) > 0 and confidence > 0.3
        
        return {
            'is_bot': is_bot,
            'bot_type': bot_type if is_bot else 'human',
            'confidence': confidence if is_bot else 1.0 - confidence,
            'evidence': ' | '.join(evidence) if evidence else 'Appears human'
        }
    
    def _analyze_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Analyze HTTP headers for bot patterns
        
        Bots often have missing or unusual headers
        """
        evidence = []
        confidence = 0.0
        bot_type = "unknown"
        
        # Check for missing headers that browsers typically have
        missing_headers = []
        
        expected_headers = [
            'Accept', 'Accept-Language', 'Accept-Encoding',
            'Connection', 'Upgrade-Insecure-Requests'
        ]
        
        for header in expected_headers:
            if header not in headers:
                missing_headers.append(header)
        
        if missing_headers:
            evidence.append(f'Missing typical browser headers: {missing_headers}')
            confidence = max(confidence, 0.4)
        
        # Check Accept header (bots often accept all)
        accept = headers.get('Accept', '')
        if accept == '*/*':
            evidence.append('Accept: */* (bots often accept all)')
            confidence = max(confidence, 0.3)
        
        # Check for bot-specific headers
        if 'X-Forwarded-For' in headers and not headers.get('Via'):
            evidence.append('X-Forwarded-For without Via (common in proxies/bots)')
            confidence = max(confidence, 0.5)
        
        # Check for no referrer (bots often don't send referrer)
        if 'Referer' not in headers:
            evidence.append('No Referer header (common in bots)')
            confidence = max(confidence, 0.3)
        
        # Check for unusual header combinations
        if 'Accept-Encoding' in headers and 'gzip' not in headers['Accept-Encoding']:
            evidence.append('No gzip encoding accepted (unusual for browsers)')
            confidence = max(confidence, 0.4)
        
        # Check for cookie presence
        if 'Cookie' not in headers:
            evidence.append('No cookies (could be first request or bot)')
            confidence = max(confidence, 0.2)
        
        # Check for cache control
        cache_control = headers.get('Cache-Control', '')
        if 'no-cache' in cache_control.lower() or 'max-age=0' in cache_control:
            evidence.append('Aggressive no-cache (common in scrapers)')
            confidence = max(confidence, 0.3)
        
        # Determine if bot
        is_bot = len(evidence) > 0 and confidence > 0.3
        
        return {
            'is_bot': is_bot,
            'bot_type': 'header_anomaly' if is_bot else 'normal',
            'confidence': confidence if is_bot else 1.0 - confidence,
            'evidence': ' | '.join(evidence) if evidence else 'Normal headers'
        }
    
    def _analyze_behavior(self, ip: str, security_data: Dict) -> Dict[str, Any]:
        """
        Analyze behavioral patterns for bot detection
        
        Humans have random patterns, bots are systematic
        """
        if ip not in self.behavior_profiles:
            return {
                'is_bot': False,
                'bot_type': 'unknown',
                'confidence': 0.1,
                'evidence': 'No behavior history'
            }
        
        profile = self.behavior_profiles[ip]
        evidence = []
        confidence = 0.0
        
        # Check request rate consistency (bots are very consistent)
        if 'request_times' in profile and len(profile['request_times']) > 5:
            times = profile['request_times']
            intervals = np.diff(times)
            
            if len(intervals) > 1:
                cv = np.std(intervals) / np.mean(intervals) if np.mean(intervals) > 0 else 0
                
                # Low coefficient of variation = consistent timing = bot
                if cv < self.thresholds['request_timing_threshold']:
                    evidence.append(f'Consistent request timing (CV={cv:.3f})')
                    confidence = max(confidence, 0.6)
        
        # Check endpoint access patterns
        if 'endpoints' in profile and len(profile['endpoints']) > 10:
            endpoints = list(profile['endpoints'])
            
            # Bots often access endpoints in specific patterns
            # Check for sequential or systematic access
            if self._is_systematic_access(endpoints):
                evidence.append('Systematic endpoint access pattern')
                confidence = max(confidence, 0.7)
            
            # Check for breadth-first crawling
            if self._is_breadth_first_crawl(endpoints):
                evidence.append('Breadth-first crawling pattern')
                confidence = max(confidence, 0.8)
        
        # Check for lack of human-like behavior
        if 'mouse_movements' in profile:
            movements = profile['mouse_movements']
            if len(movements) > 10:
                # Humans have curved, random movements
                # Bots have straight, efficient movements
                linearity = self._compute_mouse_linearity(movements)
                if linearity > 0.8:  # Very linear movement
                    evidence.append(f'Linear mouse movement (linearity={linearity:.2f})')
                    confidence = max(confidence, 0.7)
        
        # Check for rapid, continuous requests
        if 'request_count' in profile and 'first_seen' in profile:
            total_time = time.time() - profile['first_seen']
            if total_time > 0:
                request_rate = profile['request_count'] / total_time
                if request_rate > 10:  # More than 10 requests per second
                    evidence.append(f'High sustained request rate ({request_rate:.1f}/s)')
                    confidence = max(confidence, 0.8)
        
        is_bot = len(evidence) > 0 and confidence > 0.4
        
        return {
            'is_bot': is_bot,
            'bot_type': 'behavioral_bot' if is_bot else 'human_behavior',
            'confidence': confidence if is_bot else 1.0 - confidence,
            'evidence': ' | '.join(evidence) if evidence else 'Human-like behavior'
        }
    
    def _is_systematic_access(self, endpoints: List[str]) -> bool:
        """
        Detect systematic endpoint access patterns
        
        Bots often access endpoints in predictable sequences
        """
        if len(endpoints) < 5:
            return False
        
        # Check for numeric sequences in URLs
        numeric_patterns = 0
        for endpoint in endpoints:
            # Extract numbers from endpoint
            numbers = re.findall(r'\d+', endpoint)
            if numbers:
                numeric_patterns += 1
        
        # If most endpoints have numbers, might be systematic
        return numeric_patterns / len(endpoints) > 0.7
    
    def _is_breadth_first_crawl(self, endpoints: List[str]) -> bool:
        """
        Detect breadth-first crawling pattern
        
        Bots often crawl all links at one level before going deeper
        """
        if len(endpoints) < 10:
            return False
        
        # Group by path depth
        depth_groups = defaultdict(list)
        for endpoint in endpoints:
            depth = endpoint.count('/')
            depth_groups[depth].append(endpoint)
        
        # Check if requests were made in depth order
        depths = sorted(depth_groups.keys())
        if len(depths) < 2:
            return False
        
        # Get request counts by depth
        depth_counts = [(depth, len(depth_groups[depth])) for depth in depths]
        
        # Bots often have decreasing counts as depth increases
        # (breadth-first: many shallow, few deep)
        is_decreasing = all(
            depth_counts[i][1] >= depth_counts[i+1][1]
            for i in range(len(depth_counts)-1)
        )
        
        return is_decreasing
    
    def _compute_mouse_linearity(self, movements: List[Dict]) -> float:
        """
        Compute linearity of mouse movements
        
        Returns 0.0 (curved/random) to 1.0 (perfectly linear)
        """
        if len(movements) < 3:
            return 0.5
        
        # Extract movement vectors
        vectors = []
        for i in range(1, len(movements)):
            prev = movements[i-1]
            curr = movements[i]
            
            if 'x' in prev and 'y' in prev and 'x' in curr and 'y' in curr:
                dx = curr['x'] - prev['x']
                dy = curr['y'] - prev['y']
                vectors.append((dx, dy))
        
        if len(vectors) < 2:
            return 0.5
        
        # Compute angle consistency
        angles = []
        for i in range(1, len(vectors)):
            v1 = vectors[i-1]
            v2 = vectors[i]
            
            # Compute dot product
            dot = v1[0]*v2[0] + v1[1]*v2[1]
            norm1 = np.sqrt(v1[0]**2 + v1[1]**2)
            norm2 = np.sqrt(v2[0]**2 + v2[1]**2)
            
            if norm1 > 0 and norm2 > 0:
                cos_angle = dot / (norm1 * norm2)
                # Clamp to valid range
                cos_angle = max(-1.0, min(1.0, cos_angle))
                angle = np.arccos(cos_angle)
                angles.append(angle)
        
        if not angles:
            return 0.5
        
        # Linear movements have small angle changes
        avg_angle_change = np.mean(angles)
        # Convert to linearity score (0-1)
        linearity = 1.0 - min(1.0, avg_angle_change / (np.pi/2))
        
        return linearity
    
    def _analyze_javascript(self, ip: str, security_data: Dict) -> Dict[str, Any]:
        """
        Analyze JavaScript execution patterns
        
        Bots often don't execute JavaScript or do it poorly
        """
        evidence = []
        confidence = 0.0
        
        # Check if JavaScript execution data is available
        js_data = security_data.get('javascript', {})
        
        if not js_data:
            # No JS data - can't analyze
            return {
                'is_bot': False,
                'bot_type': 'unknown',
                'confidence': 0.1,
                'evidence': 'No JavaScript execution data'
            }
        
        # Update JS execution rate for this IP
        if ip not in self.js_execution_rates:
            self.js_execution_rates[ip] = {'success': 0, 'total': 0}
        
        js_rate = self.js_execution_rates[ip]
        
        # Check JS execution success
        executed = js_data.get('executed', False)
        js_rate['total'] += 1
        if executed:
            js_rate['success'] += 1
        
        # Compute success rate
        success_rate = js_rate['success'] / js_rate['total'] if js_rate['total'] > 0 else 0
        
        # Bots often have low JS execution rates
        if success_rate < self.thresholds['js_execution_threshold']:
            evidence.append(f'Low JavaScript execution rate ({success_rate:.1%})')
            confidence = max(confidence, 0.7)
        
        # Check for specific JS failures
        if 'errors' in js_data and js_data['errors']:
            evidence.append(f'JavaScript errors: {len(js_data["errors"])}')
            confidence = max(confidence, 0.5)
        
        # Check for missing Web APIs that browsers have
        missing_apis = js_data.get('missing_apis', [])
        if missing_apis:
            evidence.append(f'Missing browser APIs: {missing_apis[:3]}')
            confidence = max(confidence, 0.6)
        
        # Check for headless browser detection
        if 'headless_detected' in js_data and js_data['headless_detected']:
            evidence.append('Headless browser detected via JavaScript')
            confidence = max(confidence, 0.9)
        
        is_bot = len(evidence) > 0 and confidence > 0.4
        
        return {
            'is_bot': is_bot,
            'bot_type': 'js_failure_bot' if is_bot else 'js_capable',
            'confidence': confidence if is_bot else 1.0 - confidence,
            'evidence': ' | '.join(evidence) if evidence else 'Normal JavaScript execution'
        }
    
    def _analyze_timing(self, ip: str, security_data: Dict) -> Dict[str, Any]:
        """
        Analyze request timing patterns
        
        Bots often have precise, non-human timing
        """
        evidence = []
        confidence = 0.0
        
        # Get timing data
        timing = security_data.get('timing', {})
        
        if not timing:
            return {
                'is_bot': False,
                'bot_type': 'unknown',
                'confidence': 0.1,
                'evidence': 'No timing data'
            }
        
        # Check for sub-millisecond precision (bots)
        request_time = timing.get('request_time', 0)
        if request_time > 0:
            # Check if time has millisecond precision (common in bots)
            time_str = str(request_time)
            if '.' in time_str:
                decimal_part = time_str.split('.')[1]
                if len(decimal_part) >= 6:  # Microsecond precision
                    evidence.append('Microsecond precision timing (bot-like)')
                    confidence = max(confidence, 0.5)
        
        # Check for consistent intervals between requests
        if 'previous_request_time' in timing:
            interval = request_time - timing['previous_request_time']
            
            # Very short intervals (<100ms) are bot-like
            if interval < 0.1:  # 100ms
                evidence.append(f'Very short request interval ({interval:.3f}s)')
                confidence = max(confidence, 0.6)
            
            # Perfectly consistent intervals are bot-like
            if ip in self.behavior_profiles and 'last_interval' in self.behavior_profiles[ip]:
                last_interval = self.behavior_profiles[ip]['last_interval']
                if abs(interval - last_interval) < 0.001:  # Within 1ms
                    evidence.append('Perfectly consistent request interval')
                    confidence = max(confidence, 0.7)
            
            # Store this interval
            if ip in self.behavior_profiles:
                self.behavior_profiles[ip]['last_interval'] = interval
        
        # Check for lack of human delay patterns
        if 'think_time' in timing:
            think_time = timing['think_time']
            # Humans have variable think times, bots often don't
            if think_time < 0.5:  # Less than 500ms think time
                evidence.append(f'Short think time ({think_time:.3f}s)')
                confidence = max(confidence, 0.4)
        
        is_bot = len(evidence) > 0 and confidence > 0.3
        
        return {
            'is_bot': is_bot,
            'bot_type': 'timing_bot' if is_bot else 'human_timing',
            'confidence': confidence if is_bot else 1.0 - confidence,
            'evidence': ' | '.join(evidence) if evidence else 'Human-like timing'
        }
    
    def _ml_predict(self, security_data: Dict) -> Dict[str, Any]:
        """
        Use ML model to predict if request is from a bot
        
        This is a placeholder for actual ML implementation
        """
        # In production, extract features and run through model
        features = self._extract_ml_features(security_data)
        
        # Placeholder: Random prediction for demo
        # Replace with actual model prediction
        is_bot = np.random.random() > 0.7  # 30% chance of bot
        confidence = np.random.random()
        
        return {
            'is_bot': is_bot,
            'bot_type': 'ml_predicted_bot' if is_bot else 'ml_predicted_human',
            'confidence': confidence,
            'evidence': f'ML model prediction (confidence: {confidence:.2f})'
        }
    
    def _extract_ml_features(self, security_data: Dict) -> List[float]:
        """
        Extract features for ML model
        
        Features include:
        - User agent characteristics
        - Header patterns
        - Timing features
        - Behavioral features
        """
        features = []
        
        # User agent features
        ua = security_data.get('headers', {}).get('User-Agent', '')
        features.append(len(ua) / 1000)  # Normalized length
        features.append(self._compute_entropy(ua))
        
        # Header features
        headers = security_data.get('headers', {})
        features.append(len(headers) / 50)  # Normalized header count
        features.append(1.0 if 'Cookie' in headers else 0.0)
        features.append(1.0 if 'Referer' in headers else 0.0)
        
        # Timing features
        timing = security_data.get('timing', {})
        features.append(timing.get('request_time', 0) % 1.0)  # Decimal part
        features.append(min(1.0, timing.get('think_time', 0) / 10))
        
        # Add more features as needed
        
        return features
    
    def _compute_entropy(self, text: str) -> float:
        """Compute Shannon entropy of text"""
        if not text:
            return 0.0
        
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            probability = count / length
            entropy -= probability * np.log2(probability)
        
        return entropy / 8.0  # Normalize by max entropy for bytes
    
    def _update_behavior_profile(self, ip: str, security_data: Dict, detections: List[Dict]):
        """
        Update behavior profile for IP address
        """
        if not ip:
            return
        
        if ip not in self.behavior_profiles:
            self.behavior_profiles[ip] = {
                'request_count': 0,
                'first_seen': time.time(),
                'last_seen': time.time(),
                'endpoints': set(),
                'detections': [],
                'mouse_movements': [],
                'request_times': []
            }
        
        profile = self.behavior_profiles[ip]
        profile['request_count'] += 1
        profile['last_seen'] = time.time()
        
        # Store endpoint
        endpoint = security_data.get('request', {}).get('endpoint', '')
        if endpoint:
            profile['endpoints'].add(endpoint)
        
        # Store detection results
        profile['detections'].append({
            'timestamp': time.time(),
            'is_bot': any(d.get('stage') == 'user_agent' and 
                         d.get('confidence', 0) > 0.5 for d in detections),
            'confidence': max((d.get('confidence', 0) for d in detections), default=0)
        })
        
        # Store request time for timing analysis
        profile['request_times'].append(time.time())
        if len(profile['request_times']) > 1000:
            profile['request_times'] = profile['request_times'][-1000:]
        
        # Store mouse movements if available
        mouse_data = security_data.get('mouse_movements', [])
        if mouse_data:
            profile['mouse_movements'].extend(mouse_data[-10:])  # Keep last 10
            if len(profile['mouse_movements']) > 100:
                profile['mouse_movements'] = profile['mouse_movements'][-100:]
    
    def _should_serve_captcha(self, ip: str, bot_confidence: float) -> bool:
        """
        Determine if CAPTCHA should be served
        
        Conditions:
        1. Bot confidence above threshold
        2. IP not recently passed CAPTCHA
        3. Not too many CAPTCHAS recently
        """
        if not self.captcha_config['enabled']:
            return False
        
        if bot_confidence < self.thresholds['bot_confidence']:
            return False
        
        # Check CAPTCHA history for this IP
        captcha_key = f"captcha:{ip}"
        if hasattr(self, 'captcha_history') and captcha_key in self.captcha_history:
            history = self.captcha_history[captcha_key]
            
            # Check if recently passed
            if history.get('last_passed', 0) > time.time() - 3600:  # 1 hour
                return False
            
            # Check failure limit
            if history.get('failures', 0) >= self.captcha_config['failure_limit']:
                return False
        
        return True
    
    def _get_recommended_action(self, is_bot: bool, confidence: float, bot_type: str) -> str:
        """
        Get recommended action based on bot detection
        """
        if not is_bot:
            return "ALLOW - Appears to be human traffic"
        
        if confidence > 0.9 and 'malicious' in bot_type:
            return "BLOCK - Malicious bot detected"
        
        if confidence > 0.8:
            return "CHALLENGE - Serve CAPTCHA to verify human"
        
        if confidence > 0.6:
            return "LIMIT - Apply rate limiting to suspected bot"
        
        return "MONITOR - Suspected bot, monitor behavior"
    
    def _generate_fingerprint(self, security_data: Dict) -> str:
        """
        Generate fingerprint for this request
        
        Used to identify repeat offenders
        """
        fingerprint_data = []
        
        # Include key identifying information
        headers = security_data.get('headers', {})
        
        fingerprint_data.append(headers.get('User-Agent', ''))
        fingerprint_data.append(headers.get('Accept', ''))
        fingerprint_data.append(headers.get('Accept-Language', ''))
        fingerprint_data.append(headers.get('Accept-Encoding', ''))
        
        # Add IP information
        fingerprint_data.append(security_data.get('ip_address', ''))
        
        # Create hash of fingerprint data
        fingerprint_str = '|'.join(str(d) for d in fingerprint_data)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]
    
    def _error_response(self, error_message: str) -> Dict[str, Any]:
        """
        Generate error response
        """
        return {
            'agent_id': self.agent_id,
            'agent_name': self.name,
            'error': error_message,
            'is_bot': False,
            'bot_confidence': 0.1,
            'bot_type': 'unknown',
            'recommended_action': 'INVESTIGATE - Bot detection failed',
            'reasoning_state': self.get_reasoning_state(),
            'decision': {
                'is_bot': False,
                'confidence': 0.1,
                'bot_type': 'unknown',
                'evidence': [{'type': 'AGENT_ERROR', 'description': error_message}]
            }
        }
    
    def serve_captcha(self, ip: str, captcha_type: str = None) -> Dict[str, Any]:
        """
        Serve a CAPTCHA challenge
        
        Returns CAPTCHA data including:
        - Image or challenge text
        - Expected answer
        - Expiry time
        - Token for verification
        """
        if not captcha_type:
            captcha_type = np.random.choice(self.captcha_config['challenge_types'])
        
        # Generate CAPTCHA
        if captcha_type == 'image':
            captcha_data = self._generate_image_captcha()
        elif captcha_type == 'math':
            captcha_data = self._generate_math_captcha()
        else:  # invisible
            captcha_data = self._generate_invisible_captcha()
        
        # Update metrics
        self.metrics['captchas_served'] += 1
        
        # Store CAPTCHA challenge
        challenge_id = hashlib.sha256(f"{ip}{time.time()}".encode()).hexdigest()[:16]
        
        if not hasattr(self, 'captcha_challenges'):
            self.captcha_challenges = {}
        
        self.captcha_challenges[challenge_id] = {
            'ip': ip,
            'expected_answer': captcha_data['answer'],
            'expiry': time.time() + 300,  # 5 minutes
            'type': captcha_type
        }
        
        # Return CAPTCHA to client
        return {
            'challenge_id': challenge_id,
            'captcha_type': captcha_type,
            'challenge': captcha_data['challenge'],
            'expires_in': 300
        }
    
    def _generate_image_captcha(self) -> Dict[str, Any]:
        """
        Generate image-based CAPTCHA
        
        In production, use a CAPTCHA library
        """
        # Placeholder - in production, generate actual image
        return {
            'challenge': 'Please enter the text shown in the image',
            'answer': 'ABCD1234'  # Generated answer
        }
    
    def _generate_math_captcha(self) -> Dict[str, Any]:
        """
        Generate math-based CAPTCHA
        """
        # Simple math problem
        a = np.random.randint(1, 10)
        b = np.random.randint(1, 10)
        operation = np.random.choice(['+', '-', '*'])
        
        if operation == '+':
            answer = a + b
        elif operation == '-':
            answer = a - b
        else:  # '*'
            answer = a * b
        
        return {
            'challenge': f'What is {a} {operation} {b}?',
            'answer': str(answer)
        }
    
    def _generate_invisible_captcha(self) -> Dict[str, Any]:
        """
        Generate invisible CAPTCHA (honeypot field)
        """
        # Invisible CAPTCHA uses honeypot fields
        field_name = f'hp_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}'
        
        return {
            'challenge': f'<input type="text" name="{field_name}" style="display:none">',
            'answer': ''  # Should be empty if human
        }
    
    def verify_captcha(self, challenge_id: str, user_answer: str) -> Dict[str, Any]:
        """
        Verify CAPTCHA response
        """
        if not hasattr(self, 'captcha_challenges') or challenge_id not in self.captcha_challenges:
            return {
                'success': False,
                'message': 'Invalid challenge ID'
            }
        
        challenge = self.captcha_challenges[challenge_id]
        
        # Check expiry
        if time.time() > challenge['expiry']:
            del self.captcha_challenges[challenge_id]
            return {
                'success': False,
                'message': 'CAPTCHA expired'
            }
        
        # Verify answer
        expected = challenge['expected_answer']
        ip = challenge['ip']
        
        # Update CAPTCHA history
        if not hasattr(self, 'captcha_history'):
            self.captcha_history = {}
        
        captcha_key = f"captcha:{ip}"
        if captcha_key not in self.captcha_history:
            self.captcha_history[captcha_key] = {
                'attempts': 0,
                'successes': 0,
                'failures': 0,
                'last_attempt': 0
            }
        
        history = self.captcha_history[captcha_key]
        history['attempts'] += 1
        history['last_attempt'] = time.time()
        
        # Check answer (case-insensitive for text, exact for invisible)
        if challenge['type'] == 'invisible':
            # Invisible CAPTCHA should be empty
            success = user_answer == ''
        else:
            success = user_answer.lower() == expected.lower()
        
        if success:
            history['successes'] += 1
            history['last_passed'] = time.time()
            self.metrics['captchas_passed'] += 1
            message = 'CAPTCHA passed'
        else:
            history['failures'] += 1
            self.metrics['captchas_failed'] += 1
            message = 'CAPTCHA failed'
        
        # Clean up challenge
        del self.captcha_challenges[challenge_id]
        
        return {
            'success': success,
            'message': message,
            'attempts': history['attempts'],
            'successes': history['successes'],
            'failures': history['failures']
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
            'detection_stats': {
                'profiles_tracked': len(self.behavior_profiles),
                'known_bot_signatures': sum(len(sigs) for sigs in self.bot_signatures.values()),
                'active_captchas': len(getattr(self, 'captcha_challenges', {})),
                'js_tracking': len(self.js_execution_rates)
            },
            'config': {
                'thresholds': self.thresholds,
                'captcha_enabled': self.captcha_config['enabled'],
                'signature_categories': list(self.bot_signatures.keys())
            }
        }