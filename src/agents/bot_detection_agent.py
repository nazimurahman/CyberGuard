# src/agents/bot_detection_agent.py
"""
Bot Detection Agent
Purpose: Detects automated bots, scrapers, headless browsers, and malicious automation
Techniques: Behavioral analysis, fingerprinting, ML models, CAPTCHA challenges
"""

# Import standard Python libraries for various functionalities
import re  # Regular expressions for pattern matching in strings
import hashlib  # Cryptographic hash functions for fingerprinting
import time  # Time functions for timing analysis and profiling
import json  # JSON parsing and serialization (currently unused but imported)
from typing import Dict, List, Any, Set, Optional, Tuple, DefaultDict  # Type hints for better code documentation
from datetime import datetime  # Date and time manipulation
from collections import defaultdict  # Dictionary with default values for missing keys
import numpy as np  # Numerical computing library for mathematical operations

# Import base agent class - this assumes base_agent.py exists in the same directory
from .base_agent import SecurityAgent, AgentCapability  # Import parent class and capability enum

# Define the main BotDetectionAgent class that inherits from SecurityAgent
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
    
    # Constructor method - called when creating a new instance of BotDetectionAgent
    def __init__(self, agent_id: str = "bot_detection_001"):
        # Call parent class constructor with initialization parameters
        super().__init__(
            agent_id=agent_id,  # Unique identifier for this agent instance
            name="Bot Detection Agent",  # Human-readable name
            description="Detects automated bots and malicious automation",  # Description of agent's purpose
            capabilities=[AgentCapability.BOT_DETECTION],  # List of agent capabilities
            state_dim=256  # Dimensionality of agent's state representation (for ML)
        )
        
        # Load known bot signatures from internal database or configuration
        self.bot_signatures = self._load_bot_signatures()
        
        # Regular expression patterns to detect headless browsers
        # Headless browsers run without GUI and are often used by bots
        self.headless_patterns = [
            r'HeadlessChrome',  # Google Chrome without GUI
            r'PhantomJS',  # Headless WebKit browser
            r'Nightmare',  # Electron-based automation framework
            r'CasperJS',  # Navigation scripting and testing tool
            r'SlimerJS',  # Gecko-based headless browser
            r'HtmlUnit',  # Java-based headless browser
            r'Trident.*Headless',  # IE/Edge headless mode
            r'WebDriver',  # Selenium WebDriver automation
            r'Selenium'  # Popular browser automation framework
        ]
        
        # Patterns for automated HTTP client tools
        # These tools are legitimate but can be used for scraping
        self.automated_tools = [
            r'curl/',  # Command line HTTP client
            r'wget/',  # Command line download utility
            r'python-requests/',  # Python HTTP library
            r'python-urllib/',  # Python standard HTTP library
            r'Java/',  # Java HTTP clients
            r'Go-http-client/',  # Go language HTTP client
            r'Ruby',  # Ruby HTTP clients
            r'Perl',  # Perl HTTP clients
            r'PHP',  # PHP HTTP clients
            r'node-fetch/',  # Node.js fetch implementation
            r'axios/',  # Promise-based HTTP client
            r'okhttp/'  # Square's HTTP client for Java/Android
        ]
        
        # Patterns for known malicious security scanning and attack tools
        self.malicious_bots = [
            r'sqlmap',  # SQL injection testing tool
            r'nmap',  # Network scanning tool
            r'nikto',  # Web server scanner
            r'wpscan',  # WordPress vulnerability scanner
            r'dirbuster',  # Directory brute force tool
            r'gobuster',  # Directory/file brute force tool
            r'ffuf',  # Web fuzzing tool
            r'burpsuite',  # Web vulnerability scanner
            r'zap',  # OWASP Zed Attack Proxy
            r'metasploit',  # Penetration testing framework
            r'nessus',  # Vulnerability scanner
            r'openvas',  # Open source vulnerability scanner
            r'acunetix'  # Web vulnerability scanner
        ]
        
        # Behavioral tracking dictionaries
        self.behavior_profiles: Dict[str, Dict] = {}  # IP address -> detailed behavior profile
        self.js_execution_rates: Dict[str, Dict] = {}  # IP address -> JavaScript execution statistics
        self.mouse_tracking: Dict[str, List] = {}  # IP address -> mouse movement data
        
        # Detection confidence thresholds for different bot types
        # These values determine when something is classified as a bot
        self.thresholds = {
            'bot_confidence': 0.7,  # Overall bot confidence threshold
            'headless_confidence': 0.8,  # Confidence for headless browser detection
            'automated_confidence': 0.6,  # Confidence for automated tool detection
            'malicious_confidence': 0.9,  # Confidence for malicious bot detection
            'behavior_anomaly': 0.75,  # Threshold for behavioral anomalies
            'js_execution_threshold': 0.3,  # Minimum JS execution rate to be considered human
            'request_timing_threshold': 0.5  # Maximum timing consistency to be considered human
        }
        
        # Configuration for CAPTCHA challenge system
        self.captcha_config = {
            'enabled': True,  # Whether CAPTCHA challenges are active
            'difficulty': 'medium',  # Difficulty level of CAPTCHAs
            'failure_limit': 3,  # Maximum allowed CAPTCHA failures before blocking
            'challenge_types': ['image', 'math', 'invisible']  # Types of CAPTCHAs to use
        }
        
        # Performance and detection metrics tracking
        self.metrics = {
            'total_requests': 0,  # Total number of requests analyzed
            'bots_detected': 0,  # Number of requests classified as bots
            'false_positives': 0,  # Number of human requests incorrectly flagged (placeholder)
            'captchas_served': 0,  # Number of CAPTCHA challenges served
            'captchas_passed': 0,  # Number of successful CAPTCHA completions
            'captchas_failed': 0  # Number of failed CAPTCHA attempts
        }
        
        # Set to store unique bot fingerprints
        self.bot_fingerprints: Set[str] = set()
        
        # CAPTCHA tracking structures initialized here
        self.captcha_challenges: Dict[str, Dict] = {}  # challenge_id -> challenge details
        self.captcha_history: Dict[str, Dict] = {}  # IP address -> CAPTCHA attempt history
        
        # Load machine learning model for bot detection
        self.model = self._load_ml_model()  # Currently returns None as placeholder
    
    # Load bot signatures from internal database
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
            'search_engine': [  # Legitimate search engine crawlers
                'Googlebot', 'Bingbot', 'Slurp', 'DuckDuckBot',
                'Baiduspider', 'YandexBot', 'Sogou', 'Exabot'
            ],
            'social_media': [  # Social media link preview bots
                'Twitterbot', 'FacebookExternalHit',
                'LinkedInBot', 'Pinterest'
            ],
            'monitoring': [  # Uptime and performance monitoring bots
                'Pingdom', 'UptimeRobot', 'StatusCake',
                'NewRelic', 'Datadog'
            ],
            'analytics': [  # Web analytics and tracking bots
                'GoogleAnalytics', 'Mixpanel', 'Hotjar',
                'Matomo', 'Amplitude'
            ],
            'good_bots': [  # Other legitimate bots (SEO tools, etc.)
                'AhrefsBot', 'SEMrushBot', 'MJ12bot',
                'DotBot', 'CCBot'
            ]
        }
    
    # Placeholder for ML model loading
    def _load_ml_model(self) -> Optional[Any]:
        """
        Load machine learning model for bot detection
        
        Model features:
        - User agent analysis
        - Header patterns
        - Request timing
        - Behavioral patterns
        - JavaScript execution
        """
        # In production, this would load a pre-trained model from disk
        print("Bot Detection Agent: Bot detection ML model placeholder initialized")
        return None  # Return None as placeholder for actual model
    
    # Main analysis method called by the security system
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
        start_time = time.time()  # Record start time for performance measurement
        
        try:
            # Extract key data from security_data dictionary
            request = security_data.get('request', {})  # HTTP request details
            headers = security_data.get('headers', {})  # HTTP headers
            ip = security_data.get('ip_address', '')  # Client IP address
            user_agent = headers.get('User-Agent', '')  # User-Agent header value
            
            # Update total request count metric
            self.metrics['total_requests'] += 1
            
            # Initialize detection tracking variables
            detections = []  # List to store detection results from all stages
            bot_confidence = 0.0  # Overall confidence that request is from a bot
            bot_type = "unknown"  # Type of bot detected
            
            # Stage 1: User Agent Analysis
            ua_detection = self._analyze_user_agent(user_agent)
            if ua_detection['is_bot']:
                detections.append({
                    'stage': 'user_agent',  # Which detection stage
                    'type': ua_detection['bot_type'],  # Type of bot detected
                    'confidence': ua_detection['confidence'],  # Confidence score
                    'evidence': ua_detection['evidence']  # Detection evidence
                })
                bot_confidence = max(bot_confidence, ua_detection['confidence'])  # Take highest confidence
                bot_type = ua_detection['bot_type']  # Set bot type
            
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
                if bot_type == "unknown":  # Only update if not already set
                    bot_type = header_detection['bot_type']
            
            # Stage 3: Behavioral Analysis (only if we have history for this IP)
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
            
            # Stage 6: ML Model Prediction (if model is available)
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
            
            # Update behavior profile with current detection results
            self._update_behavior_profile(ip, security_data, detections)
            
            # Determine final bot status based on confidence threshold
            is_bot = bot_confidence > self.thresholds['bot_confidence']
            
            if is_bot:
                self.metrics['bots_detected'] += 1  # Update detection metric
            
            # Build comprehensive response dictionary
            response = {
                'agent_id': self.agent_id,  # Agent identifier
                'agent_name': self.name,  # Agent name
                'analysis_timestamp': datetime.now().isoformat(),  # ISO format timestamp
                'processing_time': time.time() - start_time,  # Time taken for analysis
                'is_bot': is_bot,  # Final bot determination
                'bot_confidence': bot_confidence,  # Overall confidence score
                'bot_type': bot_type,  # Type of bot detected
                'detection_stages': detections,  # Detailed results from all stages
                'captcha_required': self._should_serve_captcha(ip, bot_confidence),  # CAPTCHA decision
                'recommended_action': self._get_recommended_action(is_bot, bot_confidence, bot_type),
                'fingerprint': self._generate_fingerprint(security_data),  # Unique request fingerprint
                'behavior_profile': self.behavior_profiles.get(ip, {}),  # Behavior data for IP
                'reasoning_state': self.get_reasoning_state(),  # Agent's reasoning state
                'decision': {  # Summary decision for easy consumption
                    'is_bot': is_bot,
                    'confidence': bot_confidence,
                    'bot_type': bot_type,
                    'evidence': detections[:3]  # Top 3 detection evidences
                }
            }
            
            # Update agent's own confidence based on detection results
            certainty = 0.5 + (bot_confidence * 0.5) if is_bot else 0.5
            self.update_confidence({'certainty': certainty})
            
            return response  # Return analysis results
            
        except Exception as e:
            # Handle any exceptions during analysis
            print(f"Bot Detection Agent: Bot detection error: {e}")
            return self._error_response(str(e))  # Return error response
    
    # User Agent analysis method
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
        
        ua_lower = user_agent.lower()  # Convert to lowercase for case-insensitive matching
        evidence = []  # List of detection evidence strings
        bot_type = "unknown"  # Type of bot detected
        confidence = 0.0  # Detection confidence score
        
        # Check for known good bots first (legitimate crawlers)
        for category, signatures in self.bot_signatures.items():
            for signature in signatures:
                if signature.lower() in ua_lower:
                    return {
                        'is_bot': True,
                        'bot_type': f'known_{category}',  # Known bot category
                        'confidence': 0.9,  # High confidence for known bots
                        'evidence': f'Known {category} bot: {signature}'
                    }
        
        # Check for headless browser patterns
        for pattern in self.headless_patterns:
            if re.search(pattern, user_agent, re.IGNORECASE):  # Case-insensitive regex search
                evidence.append(f'Headless browser detected: {pattern}')
                bot_type = 'headless_browser'
                confidence = max(confidence, self.thresholds['headless_confidence'])
        
        # Check for automated tool patterns
        for tool in self.automated_tools:
            if re.search(tool, user_agent, re.IGNORECASE):
                evidence.append(f'Automated tool detected: {tool}')
                bot_type = 'automated_tool'
                confidence = max(confidence, self.thresholds['automated_confidence'])
        
        # Check for malicious bot patterns
        for malicious in self.malicious_bots:
            if re.search(malicious, user_agent, re.IGNORECASE):
                evidence.append(f'Malicious tool detected: {malicious}')
                bot_type = 'malicious_bot'
                confidence = max(confidence, self.thresholds['malicious_confidence'])
        
        # Check for generic bot indicators in user agent
        if any(pattern in ua_lower for pattern in ['bot', 'crawler', 'spider', 'scraper']):
            if not evidence:  # Only add if no specific evidence already found
                evidence.append('Generic bot/crawler pattern in user agent')
                bot_type = 'generic_bot'
                confidence = max(confidence, 0.5)  # Medium confidence for generic detection
        
        # Check for suspicious patterns that indicate automated requests
        suspicious_patterns = [
            (r'[0-9]{10}', 'Numeric user agent (likely bot)'),  # 10-digit numbers
            (r'mozilla/.*\s+.*\s+.*\s+.*\s+.*', 'Overly specific Mozilla string'),  # Too many tokens
            (r'\(.*;.*;.*;.*;.*\)', 'Excessive semicolons in UA string'),  # Too many semicolons
            (r'[A-Z]{5,}', 'Excessive uppercase (common in bots)')  # Too many consecutive uppercase
        ]
        
        for pattern, description in suspicious_patterns:
            if re.search(pattern, user_agent):
                evidence.append(description)
                confidence = max(confidence, 0.4)  # Low confidence for suspicious patterns
        
        # Check user agent length anomalies
        ua_length = len(user_agent)
        if ua_length < 20:  # Very short user agents are suspicious
            evidence.append(f'Very short user agent ({ua_length} chars)')
            confidence = max(confidence, 0.6)  # Medium-high confidence
        elif ua_length > 500:  # Very long user agents are suspicious
            evidence.append(f'Very long user agent ({ua_length} chars)')
            confidence = max(confidence, 0.5)  # Medium confidence
        
        # Determine if bot based on accumulated evidence
        is_bot = len(evidence) > 0 and confidence > 0.3
        
        return {
            'is_bot': is_bot,
            'bot_type': bot_type if is_bot else 'human',  # Return 'human' if not bot
            'confidence': confidence if is_bot else 1.0 - confidence,  # Invert confidence for humans
            'evidence': ' | '.join(evidence) if evidence else 'Appears human'
        }
    
    # HTTP header analysis method
    def _analyze_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Analyze HTTP headers for bot patterns
        
        Bots often have missing or unusual headers
        """
        evidence = []  # List of header-based detection evidence
        confidence = 0.0  # Detection confidence
        bot_type = "unknown"  # Type of bot detected
        
        # Check for missing headers that normal browsers typically send
        missing_headers = []
        
        expected_headers = [
            'Accept',  # Content types client accepts
            'Accept-Language',  # Language preferences
            'Accept-Encoding',  # Compression formats accepted
            'Connection',  # Connection type
            'Upgrade-Insecure-Requests'  # HTTPS upgrade preference
        ]
        
        for header in expected_headers:
            if header not in headers:
                missing_headers.append(header)
        
        if missing_headers:
            evidence.append(f'Missing typical browser headers: {missing_headers}')
            confidence = max(confidence, 0.4)  # Medium confidence
        
        # Check Accept header value
        accept = headers.get('Accept', '')
        if accept == '*/*':  # Bots often accept all content types
            evidence.append('Accept: */* (bots often accept all)')
            confidence = max(confidence, 0.3)  # Low confidence
        
        # Check for proxy headers without Via header
        if 'X-Forwarded-For' in headers and not headers.get('Via'):
            evidence.append('X-Forwarded-For without Via (common in proxies/bots)')
            confidence = max(confidence, 0.5)  # Medium confidence
        
        # Check for missing Referer header
        if 'Referer' not in headers:
            evidence.append('No Referer header (common in bots)')
            confidence = max(confidence, 0.3)  # Low confidence
        
        # Check Accept-Encoding header
        if 'Accept-Encoding' in headers and 'gzip' not in headers['Accept-Encoding']:
            evidence.append('No gzip encoding accepted (unusual for browsers)')
            confidence = max(confidence, 0.4)  # Medium confidence
        
        # Check for Cookie header presence
        if 'Cookie' not in headers:
            evidence.append('No cookies (could be first request or bot)')
            confidence = max(confidence, 0.2)  # Very low confidence
        
        # Check Cache-Control header
        cache_control = headers.get('Cache-Control', '')
        if 'no-cache' in cache_control.lower() or 'max-age=0' in cache_control:
            evidence.append('Aggressive no-cache (common in scrapers)')
            confidence = max(confidence, 0.3)  # Low confidence
        
        # Determine if bot based on header evidence
        is_bot = len(evidence) > 0 and confidence > 0.3
        
        return {
            'is_bot': is_bot,
            'bot_type': 'header_anomaly' if is_bot else 'normal',
            'confidence': confidence if is_bot else 1.0 - confidence,
            'evidence': ' | '.join(evidence) if evidence else 'Normal headers'
        }
    
    # Behavioral analysis method
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
        
        profile = self.behavior_profiles[ip]  # Get behavior profile for this IP
        evidence = []  # Behavioral evidence list
        confidence = 0.0  # Detection confidence
        
        # Check request rate consistency using coefficient of variation
        if 'request_times' in profile and len(profile['request_times']) > 5:
            times = profile['request_times']
            times_array = np.array(times)  # Convert to numpy array for calculations
            intervals = np.diff(times_array)  # Calculate time intervals between requests
            
            if len(intervals) > 1:
                mean_interval = np.mean(intervals)  # Average time between requests
                if mean_interval > 0:
                    cv = np.std(intervals) / mean_interval  # Coefficient of variation
                else:
                    cv = 0
                
                # Low CV indicates consistent timing (bot-like)
                if cv < self.thresholds['request_timing_threshold']:
                    evidence.append(f'Consistent request timing (CV={cv:.3f})')
                    confidence = max(confidence, 0.6)  # Medium-high confidence
        
        # Check endpoint access patterns
        if 'endpoints' in profile and len(profile['endpoints']) > 10:
            endpoints = list(profile['endpoints'])
            
            # Check for systematic endpoint access
            if self._is_systematic_access(endpoints):
                evidence.append('Systematic endpoint access pattern')
                confidence = max(confidence, 0.7)  # High confidence
            
            # Check for breadth-first crawling pattern
            if self._is_breadth_first_crawl(endpoints):
                evidence.append('Breadth-first crawling pattern')
                confidence = max(confidence, 0.8)  # Very high confidence
        
        # Analyze mouse movement patterns if available
        if 'mouse_movements' in profile:
            movements = profile['mouse_movements']
            if len(movements) > 10:
                # Compute linearity of mouse movements
                linearity = self._compute_mouse_linearity(movements)
                if linearity > 0.8:  # Very linear movement indicates bot
                    evidence.append(f'Linear mouse movement (linearity={linearity:.2f})')
                    confidence = max(confidence, 0.7)  # High confidence
        
        # Check for sustained high request rates
        if 'request_count' in profile and 'first_seen' in profile:
            total_time = time.time() - profile['first_seen']
            if total_time > 0:
                request_rate = profile['request_count'] / total_time  # Requests per second
                if request_rate > 10:  # More than 10 requests per second
                    evidence.append(f'High sustained request rate ({request_rate:.1f}/s)')
                    confidence = max(confidence, 0.8)  # Very high confidence
        
        # Determine if behavioral patterns indicate bot
        is_bot = len(evidence) > 0 and confidence > 0.4
        
        return {
            'is_bot': is_bot,
            'bot_type': 'behavioral_bot' if is_bot else 'human_behavior',
            'confidence': confidence if is_bot else 1.0 - confidence,
            'evidence': ' | '.join(evidence) if evidence else 'Human-like behavior'
        }
    
    # Helper method to detect systematic endpoint access
    def _is_systematic_access(self, endpoints: List[str]) -> bool:
        """
        Detect systematic endpoint access patterns
        
        Bots often access endpoints in predictable sequences
        """
        if len(endpoints) < 5:  # Need enough endpoints for pattern detection
            return False
        
        # Check for numeric sequences in URLs (e.g., /page/1, /page/2)
        numeric_patterns = 0
        for endpoint in endpoints:
            numbers = re.findall(r'\d+', endpoint)  # Extract all numbers
            if numbers:
                numeric_patterns += 1
        
        # If most endpoints have numbers, might be systematic access
        return numeric_patterns / len(endpoints) > 0.7  # 70% threshold
    
    # Helper method to detect breadth-first crawling
    def _is_breadth_first_crawl(self, endpoints: List[str]) -> bool:
        """
        Detect breadth-first crawling pattern
        
        Bots often crawl all links at one level before going deeper
        """
        if len(endpoints) < 10:  # Need enough endpoints for pattern detection
            return False
        
        # Group endpoints by URL path depth
        depth_groups = defaultdict(list)  # depth -> list of endpoints
        for endpoint in endpoints:
            depth = endpoint.count('/')  # Count slashes to determine depth
            depth_groups[depth].append(endpoint)
        
        # Check if we have multiple depth levels
        depths = sorted(depth_groups.keys())
        if len(depths) < 2:
            return False
        
        # Count endpoints at each depth
        depth_counts = [(depth, len(depth_groups[depth])) for depth in depths]
        
        # Check if counts decrease with depth (breadth-first pattern)
        is_decreasing = all(
            depth_counts[i][1] >= depth_counts[i+1][1]
            for i in range(len(depth_counts)-1)
        )
        
        return is_decreasing
    
    # Helper method to compute mouse movement linearity
    def _compute_mouse_linearity(self, movements: List[Dict]) -> float:
        """
        Compute linearity of mouse movements
        
        Returns 0.0 (curved/random) to 1.0 (perfectly linear)
        """
        if len(movements) < 3:  # Need at least 3 points for linearity calculation
            return 0.5  # Neutral value
        
        # Extract movement vectors between consecutive points
        vectors = []
        for i in range(1, len(movements)):
            prev = movements[i-1]
            curr = movements[i]
            
            if 'x' in prev and 'y' in prev and 'x' in curr and 'y' in curr:
                dx = curr['x'] - prev['x']  # X movement component
                dy = curr['y'] - prev['y']  # Y movement component
                vectors.append((dx, dy))
        
        if len(vectors) < 2:  # Need at least 2 vectors
            return 0.5
        
        # Compute angle changes between consecutive vectors
        angles = []
        for i in range(1, len(vectors)):
            v1 = vectors[i-1]  # Previous vector
            v2 = vectors[i]    # Current vector
            
            # Compute dot product for angle calculation
            dot = v1[0]*v2[0] + v1[1]*v2[1]  # v1·v2 = |v1||v2|cosθ
            norm1 = np.sqrt(v1[0]**2 + v1[1]**2)  # |v1|
            norm2 = np.sqrt(v2[0]**2 + v2[1]**2)  # |v2|
            
            if norm1 > 0 and norm2 > 0:
                cos_angle = dot / (norm1 * norm2)  # cosθ
                cos_angle = max(-1.0, min(1.0, cos_angle))  # Clamp to valid range
                angle = np.arccos(cos_angle)  # θ in radians
                angles.append(angle)
        
        if not angles:
            return 0.5
        
        # Compute average angle change
        avg_angle_change = np.mean(angles)
        # Convert to linearity score (small angles = high linearity)
        linearity = 1.0 - min(1.0, avg_angle_change / (np.pi/2))
        
        return linearity
    
    # JavaScript execution analysis method
    def _analyze_javascript(self, ip: str, security_data: Dict) -> Dict[str, Any]:
        """
        Analyze JavaScript execution patterns
        
        Bots often don't execute JavaScript or do it poorly
        """
        evidence = []
        confidence = 0.0
        
        # Get JavaScript execution data from security_data
        js_data = security_data.get('javascript', {})
        
        if not js_data:
            return {
                'is_bot': False,
                'bot_type': 'unknown',
                'confidence': 0.1,
                'evidence': 'No JavaScript execution data'
            }
        
        # Initialize JavaScript execution tracking for this IP
        if ip not in self.js_execution_rates:
            self.js_execution_rates[ip] = {'success': 0, 'total': 0}
        
        js_rate = self.js_execution_rates[ip]
        
        # Update execution statistics
        executed = js_data.get('executed', False)  # Whether JS executed successfully
        js_rate['total'] += 1
        if executed:
            js_rate['success'] += 1
        
        # Compute JavaScript execution success rate
        success_rate = js_rate['success'] / js_rate['total'] if js_rate['total'] > 0 else 0
        
        # Low JS execution rate indicates bot
        if success_rate < self.thresholds['js_execution_threshold']:
            evidence.append(f'Low JavaScript execution rate ({success_rate:.1%})')
            confidence = max(confidence, 0.7)  # High confidence
        
        # Check for JavaScript errors
        if 'errors' in js_data and js_data['errors']:
            evidence.append(f'JavaScript errors: {len(js_data["errors"])}')
            confidence = max(confidence, 0.5)  # Medium confidence
        
        # Check for missing browser APIs
        missing_apis = js_data.get('missing_apis', [])
        if missing_apis:
            evidence.append(f'Missing browser APIs: {missing_apis[:3]}')  # Show first 3
            confidence = max(confidence, 0.6)  # Medium-high confidence
        
        # Check for headless browser detection via JavaScript
        if 'headless_detected' in js_data and js_data['headless_detected']:
            evidence.append('Headless browser detected via JavaScript')
            confidence = max(confidence, 0.9)  # Very high confidence
        
        is_bot = len(evidence) > 0 and confidence > 0.4
        
        return {
            'is_bot': is_bot,
            'bot_type': 'js_failure_bot' if is_bot else 'js_capable',
            'confidence': confidence if is_bot else 1.0 - confidence,
            'evidence': ' | '.join(evidence) if evidence else 'Normal JavaScript execution'
        }
    
    # Timing analysis method
    def _analyze_timing(self, ip: str, security_data: Dict) -> Dict[str, Any]:
        """
        Analyze request timing patterns
        
        Bots often have precise, non-human timing
        """
        evidence = []
        confidence = 0.0
        
        # Get timing data from security_data
        timing = security_data.get('timing', {})
        
        if not timing:
            return {
                'is_bot': False,
                'bot_type': 'unknown',
                'confidence': 0.1,
                'evidence': 'No timing data'
            }
        
        # Check timestamp precision
        request_time = timing.get('request_time', 0)
        if request_time > 0:
            time_str = str(request_time)
            if '.' in time_str:
                decimal_part = time_str.split('.')[1]
                if len(decimal_part) >= 6:  # Microsecond precision
                    evidence.append('Microsecond precision timing (bot-like)')
                    confidence = max(confidence, 0.5)  # Medium confidence
        
        # Check request intervals
        if 'previous_request_time' in timing:
            interval = request_time - timing['previous_request_time']
            
            # Very short intervals indicate bot
            if interval < 0.1:  # Less than 100ms
                evidence.append(f'Very short request interval ({interval:.3f}s)')
                confidence = max(confidence, 0.6)  # Medium-high confidence
            
            # Perfectly consistent intervals indicate bot
            if ip in self.behavior_profiles and 'last_interval' in self.behavior_profiles[ip]:
                last_interval = self.behavior_profiles[ip]['last_interval']
                if abs(interval - last_interval) < 0.001:  # Within 1ms
                    evidence.append('Perfectly consistent request interval')
                    confidence = max(confidence, 0.7)  # High confidence
            
            # Store current interval for next comparison
            if ip in self.behavior_profiles:
                self.behavior_profiles[ip]['last_interval'] = interval
        
        # Check think time (time between page load and action)
        if 'think_time' in timing:
            think_time = timing['think_time']
            if think_time < 0.5:  # Less than 500ms
                evidence.append(f'Short think time ({think_time:.3f}s)')
                confidence = max(confidence, 0.4)  # Low-medium confidence
        
        is_bot = len(evidence) > 0 and confidence > 0.3
        
        return {
            'is_bot': is_bot,
            'bot_type': 'timing_bot' if is_bot else 'human_timing',
            'confidence': confidence if is_bot else 1.0 - confidence,
            'evidence': ' | '.join(evidence) if evidence else 'Human-like timing'
        }
    
    # Machine learning prediction placeholder
    def _ml_predict(self, security_data: Dict) -> Dict[str, Any]:
        """
        Use ML model to predict if request is from a bot
        
        This is a placeholder for actual ML implementation
        """
        # Extract features for ML model
        features = self._extract_ml_features(security_data)
        
        # Placeholder: Random prediction for demo purposes
        is_bot = np.random.random() > 0.7  # 30% chance of bot
        confidence = np.random.random()  # Random confidence
        
        return {
            'is_bot': is_bot,
            'bot_type': 'ml_predicted_bot' if is_bot else 'ml_predicted_human',
            'confidence': confidence,
            'evidence': f'ML model prediction (confidence: {confidence:.2f})'
        }
    
    # Feature extraction for ML model
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
        features.append(len(ua) / 1000)  # Normalized length feature
        features.append(self._compute_entropy(ua))  # Entropy feature
        
        # Header features
        headers = security_data.get('headers', {})
        features.append(len(headers) / 50)  # Normalized header count
        features.append(1.0 if 'Cookie' in headers else 0.0)  # Cookie presence
        features.append(1.0 if 'Referer' in headers else 0.0)  # Referer presence
        
        # Timing features
        timing = security_data.get('timing', {})
        features.append(timing.get('request_time', 0) % 1.0)  # Decimal part of timestamp
        features.append(min(1.0, timing.get('think_time', 0) / 10))  # Normalized think time
        
        return features
    
    # Helper method to compute Shannon entropy
    def _compute_entropy(self, text: str) -> float:
        """Compute Shannon entropy of text"""
        if not text:
            return 0.0
        
        freq: Dict[str, int] = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            probability = count / length
            entropy -= probability * np.log2(probability)  # Shannon entropy formula
        
        return entropy / 8.0  # Normalize by maximum entropy for bytes (8 bits)
    
    # Update behavior profile for IP address
    def _update_behavior_profile(self, ip: str, security_data: Dict, detections: List[Dict]):
        """
        Update behavior profile for IP address
        """
        if not ip:  # Skip if no IP address
            return
        
        # Create new profile if IP not seen before
        if ip not in self.behavior_profiles:
            self.behavior_profiles[ip] = {
                'request_count': 0,  # Total requests from this IP
                'first_seen': time.time(),  # First request timestamp
                'last_seen': time.time(),  # Last request timestamp
                'endpoints': set(),  # Unique endpoints accessed
                'detections': [],  # Historical detection results
                'mouse_movements': [],  # Mouse movement data
                'request_times': []  # Timestamps of requests
            }
        
        profile = self.behavior_profiles[ip]
        profile['request_count'] += 1  # Increment request count
        profile['last_seen'] = time.time()  # Update last seen timestamp
        
        # Store endpoint if available
        endpoint = security_data.get('request', {}).get('endpoint', '')
        if endpoint:
            profile['endpoints'].add(endpoint)  # Add to set (unique endpoints)
        
        # Store detection results
        profile['detections'].append({
            'timestamp': time.time(),
            'is_bot': any(d.get('stage') == 'user_agent' and 
                         d.get('confidence', 0) > 0.5 for d in detections),
            'confidence': max((d.get('confidence', 0) for d in detections), default=0)
        })
        
        # Store request timestamp for timing analysis
        profile['request_times'].append(time.time())
        if len(profile['request_times']) > 1000:  # Keep only last 1000 timestamps
            profile['request_times'] = profile['request_times'][-1000:]
        
        # Store mouse movement data if available
        mouse_data = security_data.get('mouse_movements', [])
        if mouse_data:
            profile['mouse_movements'].extend(mouse_data[-10:])  # Keep last 10 movements
            if len(profile['mouse_movements']) > 100:  # Keep only last 100 movements
                profile['mouse_movements'] = profile['mouse_movements'][-100:]
    
    # Determine if CAPTCHA should be served
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
        if captcha_key in self.captcha_history:
            history = self.captcha_history[captcha_key]
            
            # Skip if recently passed CAPTCHA (within 1 hour)
            if history.get('last_passed', 0) > time.time() - 3600:
                return False
            
            # Skip if too many failures
            if history.get('failures', 0) >= self.captcha_config['failure_limit']:
                return False
        
        return True
    
    # Get recommended action based on detection results
    def _get_recommended_action(self, is_bot: bool, confidence: float, bot_type: str) -> str:
        """
        Get recommended action based on bot detection
        """
        if not is_bot:
            return "ALLOW - Appears to be human traffic"
        
        # High confidence malicious bots should be blocked
        if confidence > 0.9 and 'malicious' in bot_type:
            return "BLOCK - Malicious bot detected"
        
        # High confidence bots should get CAPTCHA challenge
        if confidence > 0.8:
            return "CHALLENGE - Serve CAPTCHA to verify human"
        
        # Medium confidence bots should be rate limited
        if confidence > 0.6:
            return "LIMIT - Apply rate limiting to suspected bot"
        
        # Low confidence bots should be monitored
        return "MONITOR - Suspected bot, monitor behavior"
    
    # Generate unique fingerprint for request
    def _generate_fingerprint(self, security_data: Dict) -> str:
        """
        Generate fingerprint for this request
        
        Used to identify repeat offenders
        """
        fingerprint_data = []
        
        headers = security_data.get('headers', {})
        
        # Include key headers in fingerprint
        fingerprint_data.append(headers.get('User-Agent', ''))
        fingerprint_data.append(headers.get('Accept', ''))
        fingerprint_data.append(headers.get('Accept-Language', ''))
        fingerprint_data.append(headers.get('Accept-Encoding', ''))
        
        # Include IP address
        fingerprint_data.append(security_data.get('ip_address', ''))
        
        # Create SHA256 hash of fingerprint data
        fingerprint_str = '|'.join(str(d) for d in fingerprint_data)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]  # First 16 chars
    
    # Generate error response
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
    
    # Serve CAPTCHA challenge to client
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
        
        # Generate appropriate CAPTCHA type
        if captcha_type == 'image':
            captcha_data = self._generate_image_captcha()
        elif captcha_type == 'math':
            captcha_data = self._generate_math_captcha()
        else:  # invisible
            captcha_data = self._generate_invisible_captcha()
        
        # Update CAPTCHA metrics
        self.metrics['captchas_served'] += 1
        
        # Create unique challenge ID
        challenge_id = hashlib.sha256(f"{ip}{time.time()}".encode()).hexdigest()[:16]
        
        # Store challenge for verification
        self.captcha_challenges[challenge_id] = {
            'ip': ip,
            'expected_answer': captcha_data['answer'],
            'expiry': time.time() + 300,  # 5 minutes expiry
            'type': captcha_type
        }
        
        # Return CAPTCHA data to client
        return {
            'challenge_id': challenge_id,
            'captcha_type': captcha_type,
            'challenge': captcha_data['challenge'],
            'expires_in': 300  # 5 minutes in seconds
        }
    
    # Generate image-based CAPTCHA
    def _generate_image_captcha(self) -> Dict[str, Any]:
        """
        Generate image-based CAPTCHA
        
        In production, use a CAPTCHA library
        """
        return {
            'challenge': 'Please enter the text shown in the image',
            'answer': 'ABCD1234'  # Placeholder answer
        }
    
    # Generate math-based CAPTCHA
    def _generate_math_captcha(self) -> Dict[str, Any]:
        """
        Generate math-based CAPTCHA
        """
        a = np.random.randint(1, 10)  # Random number 1-9
        b = np.random.randint(1, 10)  # Random number 1-9
        operation = np.random.choice(['+', '-', '*'])  # Random operation
        
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
    
    # Generate invisible CAPTCHA (honeypot)
    def _generate_invisible_captcha(self) -> Dict[str, Any]:
        """
        Generate invisible CAPTCHA (honeypot field)
        """
        # Create unique field name for honeypot
        field_name = f'hp_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}'
        
        return {
            'challenge': f'<input type="text" name="{field_name}" style="display:none">',
            'answer': ''  # Should be empty for human users
        }
    
    # Verify CAPTCHA response
    def verify_captcha(self, challenge_id: str, user_answer: str) -> Dict[str, Any]:
        """
        Verify CAPTCHA response
        """
        if challenge_id not in self.captcha_challenges:
            return {
                'success': False,
                'message': 'Invalid challenge ID'
            }
        
        challenge = self.captcha_challenges[challenge_id]
        
        # Check if CAPTCHA has expired
        if time.time() > challenge['expiry']:
            del self.captcha_challenges[challenge_id]
            return {
                'success': False,
                'message': 'CAPTCHA expired'
            }
        
        expected = challenge['expected_answer']
        ip = challenge['ip']
        
        # Update CAPTCHA history for this IP
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
        
        # Verify answer based on CAPTCHA type
        if challenge['type'] == 'invisible':
            success = user_answer == ''  # Honeypot should be empty
        else:
            success = user_answer.lower() == expected.lower()  # Case-insensitive
        
        # Update metrics and history
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
    
    # Get agent status and metrics
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
                'active_captchas': len(self.captcha_challenges),
                'js_tracking': len(self.js_execution_rates)
            },
            'config': {
                'thresholds': self.thresholds,
                'captcha_enabled': self.captcha_config['enabled'],
                'signature_categories': list(self.bot_signatures.keys())
            }
        }