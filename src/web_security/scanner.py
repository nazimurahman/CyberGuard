"""
scanner.py - Comprehensive Web Security Scanner
Primary orchestrator for website security analysis
Implements multi-phase scanning with vulnerability correlation
"""

import asyncio
import aiohttp
import urllib.parse
from typing import Dict, List, Any, Optional, Tuple
import re
import time
import json
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import ssl
import warnings
import html
from bs4 import BeautifulSoup

# Disable SSL warnings for internal testing (not for production)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Define missing classes that were referenced but not defined
# These would normally be imported from other modules
class VulnerabilityDetector:
    """Placeholder for vulnerability detection module"""
    async def detect_advanced(self, url, session):
        return []

class APIAnalyzer:
    """Placeholder for API analysis module"""
    async def analyze_apis(self, url, session):
        return []

class TrafficParser:
    """Placeholder for traffic analysis module"""
    async def analyze_traffic(self, url):
        return []

class JavaScriptAnalyzer:
    """Placeholder for JavaScript analysis module"""
    async def analyze_javascript(self, url, session):
        return []

class FormValidator:
    """Placeholder for form validation module"""
    async def analyze_forms(self, url, session):
        return []

class HeaderAnalyzer:
    """Placeholder for header analysis module"""
    async def analyze_headers(self, url, session):
        return []

class ScanPhase(Enum):
    """Enumeration of scanning phases for structured workflow"""
    INITIALIZATION = "initialization"
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_SCAN = "vulnerability_scan"
    DEEP_ANALYSIS = "deep_analysis"
    REPORTING = "reporting"

class ScanSeverity(Enum):
    """Standardized severity levels for security findings"""
    CRITICAL = "critical"      # Immediate threat, requires urgent action
    HIGH = "high"              # Significant risk, prioritize remediation
    MEDIUM = "medium"          # Moderate risk, schedule for fixing
    LOW = "low"                # Minor issue, consider fixing
    INFORMATIONAL = "info"     # No immediate risk, security best practice

@dataclass
class SecurityFinding:
    """Structured data class for security findings with metadata"""
    id: str                     # Unique identifier for the finding
    type: str                   # Vulnerability type (XSS, SQLi, etc.)
    severity: ScanSeverity      # Severity level from ScanSeverity enum
    location: str               # Where the issue was found (URL, parameter, etc.)
    description: str            # Human-readable description of the issue
    evidence: str               # Technical evidence or proof of concept
    recommendation: str         # How to fix the issue
    confidence: float = 0.0     # Confidence score from 0.0 to 1.0
    cwe_id: str = ""           # Common Weakness Enumeration ID
    cvss_score: float = 0.0    # CVSS v3.1 base score
    timestamp: float = field(default_factory=time.time)  # When found
    metadata: Dict[str, Any] = field(default_factory=dict)  # Additional data
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'type': self.type,
            'severity': self.severity.value,  # Use .value to get string from enum
            'location': self.location,
            'description': self.description,
            'evidence': self.evidence,
            'recommendation': self.recommendation,
            'confidence': self.confidence,
            'cwe_id': self.cwe_id,
            'cvss_score': self.cvss_score,
            'timestamp': self.timestamp,
            'metadata': self.metadata
        }

class WebSecurityScanner:
    """
    Main orchestrator for comprehensive web security scanning
    Coordinates multiple scanning modules and correlates findings
    Implements phased scanning approach with parallel execution
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize scanner with configuration and dependencies
        Args:
            config: Dictionary containing scanner configuration options
        """
        # Default configuration with safe values
        self.config = config or {
            'timeout': 30,                      # Request timeout in seconds
            'max_redirects': 10,                # Maximum redirects to follow
            'user_agent': 'CyberGuard-Security-Scanner/2.0',  # Scanner identity
            'concurrent_requests': 5,           # Parallel requests for efficiency
            'scan_depth': 3,                    # How deep to crawl (1=single page)
            'enable_javascript': False,         # JS execution (requires headless browser)
            'verify_ssl': True,                 # Validate SSL certificates
            'respect_robots_txt': True,         # Honor robots.txt restrictions
            'rate_limit_delay': 1.0,            # Delay between requests to avoid DoS
            'max_response_size': 10 * 1024 * 1024,  # 10MB max response size
        }
        
        # Initialize scanning modules (using placeholder classes)
        self.vulnerability_detector = VulnerabilityDetector()
        self.api_analyzer = APIAnalyzer()
        self.traffic_parser = TrafficParser()
        self.javascript_analyzer = JavaScriptAnalyzer()
        self.form_validator = FormValidator()
        self.header_analyzer = HeaderAnalyzer()
        
        # Session management
        self.session = None                     # Will be initialized in async context
        self.visited_urls = set()               # Track visited URLs to avoid duplicates
        self.findings = []                      # Accumulated security findings
        self.scan_statistics = {                # Performance and result metrics
            'total_requests': 0,
            'failed_requests': 0,
            'total_findings': 0,
            'start_time': 0,
            'end_time': 0,
            'phases_completed': []
        }
        
        # Cache for performance optimization
        self.response_cache = {}                # Cache responses to avoid duplicate requests
        self.hash_cache = {}                    # Content hashes for change detection
    
    async def initialize_session(self):
        """
        Initialize HTTP session with security headers and configuration
        Must be called before starting any scans
        """
        # Create SSL context with modern security settings
        ssl_context = ssl.create_default_context()
        if not self.config.get('verify_ssl', True):
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        
        # Configure timeout with connection and read timeouts
        timeout = aiohttp.ClientTimeout(
            total=self.config['timeout'],
            connect=10,
            sock_read=25
        )
        
        # Create session with security headers
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=aiohttp.TCPConnector(
                ssl=ssl_context,
                limit=self.config['concurrent_requests'],
                force_close=True
            ),
            headers={
                'User-Agent': self.config['user_agent'],
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',                     # Do Not Track header
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1'
            }
        )
        
        print("Session initialized with " + str(self.config['concurrent_requests']) + " concurrent connections")
    
    async def scan_website(self, url: str) -> Dict[str, Any]:
        """
        Main entry point for website security scanning
        Orchestrates the complete scanning workflow
        
        Args:
            url: Target website URL to scan
            
        Returns:
            Dictionary containing complete scan results with findings
        """
        # Validate and normalize URL
        normalized_url = self._normalize_url(url)
        if not normalized_url:
            return {'error': 'Invalid URL provided', 'url': url}
        
        # Initialize scanning session
        await self.initialize_session()
        
        # Start timing the scan
        self.scan_statistics['start_time'] = time.time()
        
        try:
            print("Starting comprehensive security scan of: " + normalized_url)
            print("=" * 80)
            
            # Phase 1: Initial reconnaissance
            print("\nPhase 1: " + ScanPhase.RECONNAISSANCE.value.replace('_', ' ').title())
            await self._perform_reconnaissance(normalized_url)
            
            # Phase 2: Vulnerability scanning
            print("\nPhase 2: " + ScanPhase.VULNERABILITY_SCAN.value.replace('_', ' ').title())
            await self._perform_vulnerability_scan(normalized_url)
            
            # Phase 3: Deep analysis
            print("\nPhase 3: " + ScanPhase.DEEP_ANALYSIS.value.replace('_', ' ').title())
            await self._perform_deep_analysis(normalized_url)
            
            # Phase 4: Generate report
            print("\nPhase 4: " + ScanPhase.REPORTING.value.title())
            report = await self._generate_report(normalized_url)
            
            # Record completion time
            self.scan_statistics['end_time'] = time.time()
            self.scan_statistics['total_findings'] = len(self.findings)
            
            # Add statistics to report
            report['statistics'] = self.scan_statistics
            report['scan_duration'] = self.scan_statistics['end_time'] - self.scan_statistics['start_time']
            
            print("\nScan completed in " + str(round(report['scan_duration'], 2)) + " seconds")
            print("Found " + str(len(self.findings)) + " security findings")
            
            return report
            
        except Exception as e:
            print("Scan failed with error: " + str(e))
            return {
                'error': str(e),
                'url': normalized_url,
                'partial_findings': [f.to_dict() for f in self.findings]
            }
            
        finally:
            # Always close session to free resources
            if self.session:
                await self.session.close()
    
    async def _perform_reconnaissance(self, base_url: str):
        """
        Perform initial reconnaissance to understand the target
        Gathers information about the website structure and technologies
        
        Args:
            base_url: Root URL to start reconnaissance from
        """
        print("  Fetching initial page...")
        
        try:
            # Fetch the main page
            main_response = await self._safe_fetch(base_url)
            if not main_response:
                print("  Failed to fetch main page")
                return
            
            # Parse HTML content
            soup = BeautifulSoup(main_response['content'], 'html.parser')
            
            # Analyze basic information
            title = soup.title.string if soup.title else 'No title'
            print("  Title: " + title)
            print("  Status: " + str(main_response['status']))
            print("  Content-Type: " + main_response['headers'].get('Content-Type', 'unknown'))
            print("  Server: " + main_response['headers'].get('Server', 'unknown'))
            
            # Extract and analyze links
            print("  Discovering links...")
            links = await self._extract_links(base_url, soup)
            print("  Found " + str(len(links)) + " unique links")
            
            # Check robots.txt
            if self.config.get('respect_robots_txt', True):
                robots_txt = await self._check_robots_txt(base_url)
                if robots_txt:
                    print("  robots.txt: Found (" + str(len(robots_txt)) + " bytes)")
            
            # Check sitemap.xml
            sitemap = await self._check_sitemap(base_url)
            if sitemap:
                print("  sitemap.xml: Found")
            
            self.scan_statistics['phases_completed'].append(ScanPhase.RECONNAISSANCE.value)
            
        except Exception as e:
            print("  Reconnaissance error: " + str(e))
    
    async def _perform_vulnerability_scan(self, base_url: str):
        """
        Perform active vulnerability scanning
        Tests for common web vulnerabilities
        
        Args:
            base_url: Target URL to scan for vulnerabilities
        """
        print("  Testing for OWASP Top 10 vulnerabilities...")
        
        try:
            # Get initial response for analysis
            response = await self._safe_fetch(base_url)
            if not response:
                return
            
            # Run vulnerability checks in parallel for efficiency
            tasks = [
                self._check_xss_vulnerabilities(base_url, response),
                self._check_sql_injection(base_url, response),
                self._check_command_injection(base_url),
                self._check_path_traversal(base_url),
                self._check_insecure_direct_object_references(base_url),
                self._check_security_misconfigurations(response),
                self._check_sensitive_data_exposure(response),
                self._check_missing_function_level_access_control(base_url),
                self._check_cross_site_request_forgery(base_url, response),
                self._check_using_components_with_known_vulnerabilities(base_url, response)
            ]
            
            # Execute all vulnerability checks concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for result in results:
                if isinstance(result, Exception):
                    print("  Vulnerability check error: " + str(result))
                elif result:
                    self.findings.extend(result)
            
            print("  Vulnerability scanning completed: " + str(len(self.findings)) + " findings")
            self.scan_statistics['phases_completed'].append(ScanPhase.VULNERABILITY_SCAN.value)
            
        except Exception as e:
            print("  Vulnerability scan error: " + str(e))
    
    async def _perform_deep_analysis(self, base_url: str):
        """
        Perform deep analysis of the website
        Includes advanced checks and correlation of findings
        
        Args:
            base_url: Target URL for deep analysis
        """
        print("  Performing deep analysis...")
        
        try:
            # Analyze security headers
            print("  Analyzing security headers...")
            header_findings = await self.header_analyzer.analyze_headers(base_url, self.session)
            self.findings.extend(header_findings)
            
            # Analyze JavaScript for security issues
            print("  Analyzing JavaScript...")
            js_findings = await self.javascript_analyzer.analyze_javascript(base_url, self.session)
            self.findings.extend(js_findings)
            
            # Analyze forms for security issues
            print("  Analyzing forms...")
            form_findings = await self.form_validator.analyze_forms(base_url, self.session)
            self.findings.extend(form_findings)
            
            # Look for API endpoints
            print("  Discovering API endpoints...")
            api_findings = await self.api_analyzer.analyze_apis(base_url, self.session)
            self.findings.extend(api_findings)
            
            # Parse and analyze traffic patterns
            print("  Analyzing traffic patterns...")
            traffic_findings = await self.traffic_parser.analyze_traffic(base_url)
            self.findings.extend(traffic_findings)
            
            # Run vulnerability detector for advanced patterns
            print("  Running advanced vulnerability detection...")
            advanced_findings = await self.vulnerability_detector.detect_advanced(base_url, self.session)
            self.findings.extend(advanced_findings)
            
            # Correlate findings to identify attack patterns
            print("  Correlating findings...")
            correlated_findings = self._correlate_findings()
            self.findings.extend(correlated_findings)
            
            # Count high-confidence findings
            high_confidence_count = len([f for f in self.findings if f.confidence > 0.7])
            print("  Deep analysis completed: " + str(high_confidence_count) + " high-confidence findings")
            self.scan_statistics['phases_completed'].append(ScanPhase.DEEP_ANALYSIS.value)
            
        except Exception as e:
            print("  Deep analysis error: " + str(e))
    
    async def _generate_report(self, url: str) -> Dict[str, Any]:
        """
        Generate comprehensive security report
        
        Args:
            url: Original scanned URL
            
        Returns:
            Structured report with findings, statistics, and recommendations
        """
        print("  Generating security report...")
        
        # Calculate risk score based on findings
        risk_score = self._calculate_risk_score()
        
        # Group findings by severity
        findings_by_severity = {
            'critical': [f for f in self.findings if f.severity == ScanSeverity.CRITICAL],
            'high': [f for f in self.findings if f.severity == ScanSeverity.HIGH],
            'medium': [f for f in self.findings if f.severity == ScanSeverity.MEDIUM],
            'low': [f for f in self.findings if f.severity == ScanSeverity.LOW],
            'informational': [f for f in self.findings if f.severity == ScanSeverity.INFORMATIONAL]
        }
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(risk_score, findings_by_severity)
        
        # Generate remediation recommendations
        recommendations = self._generate_recommendations()
        
        # Generate technical details
        technical_details = self._generate_technical_details()
        
        report = {
            'metadata': {
                'scan_id': hashlib.md5(f"{url}{time.time()}".encode()).hexdigest()[:16],
                'target_url': url,
                'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
                'scanner_version': 'CyberGuard 2.0',
                'risk_score': risk_score,
                'risk_level': self._get_risk_level(risk_score)
            },
            'executive_summary': executive_summary,
            'findings_summary': {
                'total_findings': len(self.findings),
                'critical': len(findings_by_severity['critical']),
                'high': len(findings_by_severity['high']),
                'medium': len(findings_by_severity['medium']),
                'low': len(findings_by_severity['low']),
                'informational': len(findings_by_severity['informational'])
            },
            'findings': [finding.to_dict() for finding in sorted(
                self.findings, 
                key=lambda x: (x.severity.value, x.confidence), 
                reverse=True
            )],
            'recommendations': recommendations,
            'technical_details': technical_details,
            'appendix': {
                'methodology': 'OWASP Testing Guide v4.2',
                'references': [
                    'https://owasp.org/www-project-top-ten/',
                    'https://cheatsheetseries.owasp.org/',
                    'https://cwe.mitre.org/'
                ]
            }
        }
        
        self.scan_statistics['phases_completed'].append(ScanPhase.REPORTING.value)
        
        return report
    
    async def _safe_fetch(self, url: str, method: str = 'GET', 
                         data: Any = None) -> Optional[Dict[str, Any]]:
        """
        Safely fetch URL with error handling and rate limiting
        
        Args:
            url: URL to fetch
            method: HTTP method (GET, POST, etc.)
            data: Request data for POST/PUT methods
            
        Returns:
            Dictionary with response details or None if failed
        """
        # Check cache first to avoid duplicate requests
        cache_key = f"{method}:{url}:{hash(str(data) if data else '')}"
        if cache_key in self.response_cache:
            return self.response_cache[cache_key]
        
        # Rate limiting to avoid overwhelming the target
        await asyncio.sleep(self.config.get('rate_limit_delay', 1.0))
        
        try:
            self.scan_statistics['total_requests'] += 1
            
            async with self.session.request(
                method=method,
                url=url,
                data=data,
                allow_redirects=True,
                max_redirects=self.config['max_redirects']
            ) as response:
                # Check response size limit
                content_length = int(response.headers.get('Content-Length', 0))
                if content_length > self.config['max_response_size']:
                    print("  Response too large: " + str(content_length) + " bytes, skipping")
                    return None
                
                # Read response with size limit
                content = await response.read()
                if len(content) > self.config['max_response_size']:
                    content = content[:self.config['max_response_size']]
                    print("  Truncated response to " + str(self.config['max_response_size']) + " bytes")
                
                result = {
                    'url': str(response.url),
                    'status': response.status,
                    'headers': dict(response.headers),
                    'content': content,
                    'content_type': response.headers.get('Content-Type', ''),
                    'elapsed': 0,  # Would need timing implementation
                    'method': method
                }
                
                # Cache successful responses
                if response.status < 400:
                    self.response_cache[cache_key] = result
                
                return result
                
        except asyncio.TimeoutError:
            print("  Timeout fetching " + url)
            self.scan_statistics['failed_requests'] += 1
            return None
        except aiohttp.ClientError as e:
            print("  Client error fetching " + url + ": " + str(e))
            self.scan_statistics['failed_requests'] += 1
            return None
        except Exception as e:
            print("  Unexpected error fetching " + url + ": " + str(e))
            self.scan_statistics['failed_requests'] += 1
            return None
    
    async def _extract_links(self, base_url: str, soup: BeautifulSoup) -> List[str]:
        """
        Extract all unique links from HTML content
        
        Args:
            base_url: Base URL for resolving relative links
            soup: BeautifulSoup parsed HTML
            
        Returns:
            List of unique absolute URLs found in the page
        """
        links = set()
        
        # Find all anchor tags with href attribute
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            absolute_url = urllib.parse.urljoin(base_url, href)
            
            # Filter out non-HTTP URLs and mailto links
            if absolute_url.startswith(('http://', 'https://')):
                # Normalize URL to avoid duplicates
                normalized = self._normalize_url(absolute_url)
                if normalized:
                    links.add(normalized)
        
        # Find all form actions
        for form in soup.find_all('form', action=True):
            action = form['action']
            absolute_url = urllib.parse.urljoin(base_url, action)
            if absolute_url.startswith(('http://', 'https://')):
                normalized = self._normalize_url(absolute_url)
                if normalized:
                    links.add(normalized)
        
        # Find all script and link tags with src/href
        for tag in soup.find_all(['script', 'img', 'link'], src=True):
            src = tag.get('src') or tag.get('href')
            if src:
                absolute_url = urllib.parse.urljoin(base_url, src)
                if absolute_url.startswith(('http://', 'https://')):
                    normalized = self._normalize_url(absolute_url)
                    if normalized:
                        links.add(normalized)
        
        return list(links)
    
    async def _check_xss_vulnerabilities(self, url: str, 
                                        response: Dict[str, Any]) -> List[SecurityFinding]:
        """
        Check for Cross-Site Scripting (XSS) vulnerabilities
        
        Args:
            url: Target URL to test
            response: Previous response for context
            
        Returns:
            List of XSS-related security findings
        """
        findings = []
        
        # Common XSS payloads for testing
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg/onload=alert("XSS")>',
            '\'"><script>alert(document.domain)</script>',
            'javascript:alert("XSS")',
            '<body onload=alert("XSS")>',
            '<iframe src="javascript:alert(`XSS`)">',
            '<input onfocus=alert("XSS") autofocus>',
            '<video><source onerror=alert("XSS")>',
            '<marquee onstart=alert("XSS")>'
        ]
        
        try:
            # Parse URL parameters
            parsed_url = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            # Test each parameter with XSS payloads
            for param_name, param_values in query_params.items():
                for payload in xss_payloads:
                    # Create modified URL with XSS payload
                    modified_params = query_params.copy()
                    modified_params[param_name] = [payload]
                    modified_query = urllib.parse.urlencode(modified_params, doseq=True)
                    
                    test_url = urllib.parse.urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        modified_query,
                        parsed_url.fragment
                    ))
                    
                    # Send request with payload
                    test_response = await self._safe_fetch(test_url)
                    if test_response and payload in str(test_response['content']):
                        finding = SecurityFinding(
                            id=f"xss_{hashlib.md5(f'{param_name}{payload}'.encode()).hexdigest()[:8]}",
                            type="Cross-Site Scripting (XSS)",
                            severity=ScanSeverity.HIGH,
                            location=f"URL parameter: {param_name}",
                            description=f"Reflected XSS vulnerability found in parameter '{param_name}'",
                            evidence=f"Payload '{html.escape(payload[:50])}...' was reflected in response",
                            recommendation="Implement proper input validation and output encoding",
                            confidence=0.85,
                            cwe_id="CWE-79",
                            cvss_score=6.1,
                            metadata={
                                'parameter': param_name,
                                'payload': payload,
                                'test_url': test_url
                            }
                        )
                        findings.append(finding)
                        break  # Stop testing this parameter after first finding
            
            # Check for stored XSS in forms
            if 'content' in response:
                content_str = response['content']
                if isinstance(content_str, bytes):
                    content_str = content_str.decode('utf-8', errors='ignore')
                soup = BeautifulSoup(content_str, 'html.parser')
                forms = soup.find_all('form')
                
                for form in forms:
                    form_action = form.get('action', '')
                    if form_action:
                        # Test form with XSS payload
                        form_data = {}
                        for input_tag in form.find_all(['input', 'textarea']):
                            input_name = input_tag.get('name')
                            if input_name:
                                form_data[input_name] = xss_payloads[0]
                        
                        if form_data:
                            form_url = urllib.parse.urljoin(url, form_action)
                            form_method = form.get('method', 'GET').upper()
                            form_response = await self._safe_fetch(
                                form_url, 
                                method=form_method,
                                data=form_data
                            )
                            
                            if form_response and xss_payloads[0] in str(form_response['content']):
                                finding = SecurityFinding(
                                    id=f"xss_form_{hashlib.md5(form_action.encode()).hexdigest()[:8]}",
                                    type="Cross-Site Scripting (XSS)",
                                    severity=ScanSeverity.HIGH,
                                    location=f"Form: {form_action}",
                                    description=f"Potential XSS vulnerability in form submission",
                                    evidence=f"XSS payload reflected in form response",
                                    recommendation="Implement CSRF tokens and input validation",
                                    confidence=0.75,
                                    cwe_id="CWE-79",
                                    cvss_score=6.1
                                )
                                findings.append(finding)
        
        except Exception as e:
            print("  XSS check error: " + str(e))
        
        return findings
    
    async def _check_sql_injection(self, url: str, 
                                  response: Dict[str, Any]) -> List[SecurityFinding]:
        """
        Check for SQL Injection vulnerabilities
        
        Args:
            url: Target URL to test
            response: Previous response for context
            
        Returns:
            List of SQL injection-related security findings
        """
        findings = []
        
        # Common SQL injection payloads
        sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "admin' #",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL, NULL--",
            "' AND 1=1",
            "' AND 1=2",
            "' OR EXISTS(SELECT * FROM information_schema.tables) --",
            "' OR SLEEP(5) --"
        ]
        
        # SQL error patterns to detect
        sql_error_patterns = [
            r"You have an error in your SQL syntax",
            r"Warning: mysql",
            r"Unclosed quotation mark",
            r"Microsoft OLE DB Provider",
            r"ODBC Driver",
            r"PostgreSQL.*ERROR",
            r"SQLite.*Exception",
            r"SQL Server.*Driver",
            r"ORA-[0-9]{5}",
            r"PL/SQL.*error"
        ]
        
        try:
            parsed_url = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            for param_name, param_values in query_params.items():
                for payload in sql_payloads:
                    modified_params = query_params.copy()
                    modified_params[param_name] = [payload]
                    modified_query = urllib.parse.urlencode(modified_params, doseq=True)
                    
                    test_url = urllib.parse.urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        modified_query,
                        parsed_url.fragment
                    ))
                    
                    test_response = await self._safe_fetch(test_url)
                    if test_response:
                        content_str = str(test_response['content'])
                        
                        # Check for SQL errors
                        for pattern in sql_error_patterns:
                            if re.search(pattern, content_str, re.IGNORECASE):
                                finding = SecurityFinding(
                                    id=f"sqli_{hashlib.md5(f'{param_name}{payload}'.encode()).hexdigest()[:8]}",
                                    type="SQL Injection",
                                    severity=ScanSeverity.CRITICAL,
                                    location=f"URL parameter: {param_name}",
                                    description=f"SQL injection vulnerability found in parameter '{param_name}'",
                                    evidence=f"SQL error detected with payload: {html.escape(payload[:50])}...",
                                    recommendation="Use parameterized queries or prepared statements",
                                    confidence=0.9,
                                    cwe_id="CWE-89",
                                    cvss_score=9.8,
                                    metadata={
                                        'parameter': param_name,
                                        'payload': payload,
                                        'error_pattern': pattern
                                    }
                                )
                                findings.append(finding)
                                break
        
        except Exception as e:
            print("  SQL injection check error: " + str(e))
        
        return findings
    
    async def _check_command_injection(self, url: str) -> List[SecurityFinding]:
        """
        Check for Command Injection vulnerabilities
        
        Args:
            url: Target URL to test
            
        Returns:
            List of command injection-related security findings
        """
        findings = []
        
        # Command injection payloads
        command_payloads = [
            '; ls',
            '| cat /etc/passwd',
            '`id`',
            '$(whoami)',
            '; ping -c 1 127.0.0.1',
            '| dir',
            '; netstat -an',
            '$(cat /etc/passwd)',
            '; ps aux',
            '| type %SYSTEMROOT%\\win.ini'
        ]
        
        try:
            parsed_url = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            # Time-based detection
            base_time = time.time()
            base_response = await self._safe_fetch(url)
            
            if base_response:
                for param_name, param_values in query_params.items():
                    for payload in ['; sleep 5', '| sleep 5', '`sleep 5`', '$(sleep 5)']:
                        modified_params = query_params.copy()
                        modified_params[param_name] = [payload]
                        modified_query = urllib.parse.urlencode(modified_params, doseq=True)
                        
                        test_url = urllib.parse.urlunparse((
                            parsed_url.scheme,
                            parsed_url.netloc,
                            parsed_url.path,
                            parsed_url.params,
                            modified_query,
                            parsed_url.fragment
                        ))
                        
                        start_time = time.time()
                        test_response = await self._safe_fetch(test_url)
                        elapsed = time.time() - start_time
                        
                        # If response took significantly longer, possible command injection
                        if elapsed > 4:  # More than 4 seconds delay
                            finding = SecurityFinding(
                                id=f"cmd_inj_{hashlib.md5(f'{param_name}{payload}'.encode()).hexdigest()[:8]}",
                                type="Command Injection",
                                severity=ScanSeverity.CRITICAL,
                                location=f"URL parameter: {param_name}",
                                description=f"Potential command injection vulnerability found",
                                evidence=f"Response delay of {elapsed:.2f} seconds with payload: {html.escape(payload)}",
                                recommendation="Validate and sanitize all user inputs, use allowlists",
                                confidence=0.7,
                                cwe_id="CWE-78",
                                cvss_score=9.8
                            )
                            findings.append(finding)
                            break
        
        except Exception as e:
            print("  Command injection check error: " + str(e))
        
        return findings
    
    async def _check_path_traversal(self, url: str) -> List[SecurityFinding]:
        """
        Check for Path Traversal vulnerabilities
        
        Args:
            url: Target URL to test
            
        Returns:
            List of path traversal-related security findings
        """
        findings = []
        
        # Path traversal payloads
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\windows\\win.ini',
            '../../../../../../etc/passwd',
            '....//....//etc/passwd',
            '%2e%2e%2fetc%2fpasswd',
            '..%252f..%252fetc%252fpasswd',
            '%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd'
        ]
        
        try:
            parsed_url = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            # Common sensitive file indicators
            sensitive_patterns = [
                r'root:.*:0:0:',
                r'\[fonts\]',
                r'\[extensions\]',
                r'\[mail\]',
                r'DatabaseType=mysql',
                r'define.*DB_PASSWORD'
            ]
            
            for param_name, param_values in query_params.items():
                for payload in traversal_payloads:
                    modified_params = query_params.copy()
                    modified_params[param_name] = [payload]
                    modified_query = urllib.parse.urlencode(modified_params, doseq=True)
                    
                    test_url = urllib.parse.urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        modified_query,
                        parsed_url.fragment
                    ))
                    
                    test_response = await self._safe_fetch(test_url)
                    if test_response:
                        content_str = str(test_response['content'])
                        
                        # Check for sensitive file contents
                        for pattern in sensitive_patterns:
                            if re.search(pattern, content_str, re.IGNORECASE):
                                finding = SecurityFinding(
                                    id=f"path_trav_{hashlib.md5(f'{param_name}{payload}'.encode()).hexdigest()[:8]}",
                                    type="Path Traversal",
                                    severity=ScanSeverity.HIGH,
                                    location=f"URL parameter: {param_name}",
                                    description=f"Path traversal vulnerability found",
                                    evidence=f"Sensitive file content detected with payload: {html.escape(payload)}",
                                    recommendation="Validate file paths, use allowlists, implement proper access controls",
                                    confidence=0.8,
                                    cwe_id="CWE-22",
                                    cvss_score=7.5
                                )
                                findings.append(finding)
                                break
        
        except Exception as e:
            print("  Path traversal check error: " + str(e))
        
        return findings
    
    async def _check_insecure_direct_object_references(self, url: str) -> List[SecurityFinding]:
        """
        Check for Insecure Direct Object References (IDOR)
        
        Args:
            url: Target URL to test
            
        Returns:
            List of IDOR-related security findings
        """
        findings = []
        
        # Common IDOR parameter patterns
        idor_patterns = [
            r'id=(\d+)',
            r'user=(\d+)',
            r'account=(\d+)',
            r'file=([^&]+)',
            r'document=(\d+)',
            r'order=(\d+)'
        ]
        
        try:
            parsed_url = urllib.parse.urlparse(url)
            query_string = parsed_url.query
            
            for pattern in idor_patterns:
                match = re.search(pattern, query_string)
                if match:
                    param_name = match.group().split('=')[0]
                    param_value = match.group(1)
                    
                    # Try to access other objects by changing the ID
                    if param_value.isdigit():
                        test_values = [
                            str(int(param_value) - 1),
                            str(int(param_value) + 1),
                            '1',
                            '0',
                            '999999'
                        ]
                        
                        for test_value in test_values:
                            test_query = query_string.replace(
                                f"{param_name}={param_value}",
                                f"{param_name}={test_value}"
                            )
                            
                            test_url = urllib.parse.urlunparse((
                                parsed_url.scheme,
                                parsed_url.netloc,
                                parsed_url.path,
                                parsed_url.params,
                                test_query,
                                parsed_url.fragment
                            ))
                            
                            test_response = await self._safe_fetch(test_url)
                            if test_response and test_response['status'] == 200:
                                finding = SecurityFinding(
                                    id=f"idor_{hashlib.md5(f'{param_name}{test_value}'.encode()).hexdigest()[:8]}",
                                    type="Insecure Direct Object Reference",
                                    severity=ScanSeverity.HIGH,
                                    location=f"URL parameter: {param_name}",
                                    description=f"IDOR vulnerability found - unauthorized access to object {test_value}",
                                    evidence=f"Successfully accessed object ID {test_value} without authorization",
                                    recommendation="Implement access control checks, use indirect object references",
                                    confidence=0.75,
                                    cwe_id="CWE-639",
                                    cvss_score=7.5
                                )
                                findings.append(finding)
                                break
        
        except Exception as e:
            print("  IDOR check error: " + str(e))
        
        return findings
    
    async def _check_security_misconfigurations(self, 
                                               response: Dict[str, Any]) -> List[SecurityFinding]:
        """
        Check for security misconfigurations
        
        Args:
            response: HTTP response to analyze
            
        Returns:
            List of security misconfiguration findings
        """
        findings = []
        
        try:
            headers = response.get('headers', {})
            
            # Check for exposed server information
            server_header = headers.get('Server', '')
            if server_header and not re.match(r'^$|^[\s]*$', server_header):
                finding = SecurityFinding(
                    id=f"info_leak_server_{hashlib.md5(server_header.encode()).hexdigest()[:8]}",
                    type="Information Disclosure",
                    severity=ScanSeverity.LOW,
                    location="HTTP Headers",
                    description=f"Server version exposed: {server_header}",
                    evidence=f"Server header: {server_header}",
                    recommendation="Remove or obfuscate Server header",
                    confidence=1.0,
                    cwe_id="CWE-200",
                    cvss_score=3.7
                )
                findings.append(finding)
            
            # Check for exposed technology via X-Powered-By
            powered_by = headers.get('X-Powered-By', '')
            if powered_by:
                finding = SecurityFinding(
                    id=f"info_leak_powered_{hashlib.md5(powered_by.encode()).hexdigest()[:8]}",
                    type="Information Disclosure",
                    severity=ScanSeverity.LOW,
                    location="HTTP Headers",
                    description=f"Technology stack exposed: {powered_by}",
                    evidence=f"X-Powered-By header: {powered_by}",
                    recommendation="Remove X-Powered-By header",
                    confidence=1.0,
                    cwe_id="CWE-200",
                    cvss_score=3.7
                )
                findings.append(finding)
            
            # Check for directory listing enabled
            if 'content' in response:
                content_str = str(response['content'])
                if '<title>Index of' in content_str and '<a href=' in content_str:
                    finding = SecurityFinding(
                        id=f"dir_listing_{hashlib.md5(content_str[:100].encode()).hexdigest()[:8]}",
                        type="Directory Listing",
                        severity=ScanSeverity.MEDIUM,
                        location="Directory",
                        description="Directory listing enabled",
                        evidence="Directory index page accessible",
                        recommendation="Disable directory listing in web server configuration",
                        confidence=0.9,
                        cwe_id="CWE-548",
                        cvss_score=5.3
                    )
                    findings.append(finding)
        
        except Exception as e:
            print("  Security misconfiguration check error: " + str(e))
        
        return findings
    
    async def _check_sensitive_data_exposure(self, 
                                            response: Dict[str, Any]) -> List[SecurityFinding]:
        """
        Check for sensitive data exposure
        
        Args:
            response: HTTP response to analyze
            
        Returns:
            List of sensitive data exposure findings
        """
        findings = []
        
        try:
            if 'content' in response:
                content_str = str(response['content']).lower()
                
                # Patterns for sensitive data
                sensitive_patterns = {
                    'password': r'password\s*[=:]\s*["\']?[^"\'\s>]+["\']?',
                    'api_key': r'api[_-]?key\s*[=:]\s*["\']?[a-zA-Z0-9]{10,}["\']?',
                    'secret': r'secret\s*[=:]\s*["\']?[a-zA-Z0-9]{10,}["\']?',
                    'token': r'token\s*[=:]\s*["\']?[a-zA-Z0-9]{10,}["\']?',
                    'private_key': r'-----BEGIN (RSA|DSA|EC|PRIVATE) KEY-----',
                    'credit_card': r'\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}',
                    'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                }
                
                for data_type, pattern in sensitive_patterns.items():
                    matches = re.findall(pattern, content_str, re.IGNORECASE)
                    if matches:
                        # Don't show actual sensitive data in evidence
                        evidence_sample = matches[0][:50] + '...' if len(matches[0]) > 50 else matches[0]
                        finding = SecurityFinding(
                            id=f"sensitive_data_{data_type}_{hashlib.md5(evidence_sample.encode()).hexdigest()[:8]}",
                            type="Sensitive Data Exposure",
                            severity=ScanSeverity.HIGH if data_type in ['password', 'api_key', 'secret'] else ScanSeverity.MEDIUM,
                            location="Page Content",
                            description=f"Potential {data_type.replace('_', ' ')} exposure",
                            evidence=f"Found pattern matching {data_type}: {html.escape(evidence_sample)}",
                            recommendation="Remove sensitive data from client-side code and responses",
                            confidence=0.6,
                            cwe_id="CWE-312",
                            cvss_score=5.9 if data_type in ['password', 'api_key', 'secret'] else 4.3
                        )
                        findings.append(finding)
        
        except Exception as e:
            print("  Sensitive data exposure check error: " + str(e))
        
        return findings
    
    async def _check_missing_function_level_access_control(self, 
                                                          url: str) -> List[SecurityFinding]:
        """
        Check for Missing Function Level Access Control
        
        Args:
            url: Target URL to test
            
        Returns:
            List of access control findings
        """
        findings = []
        
        # Common admin/privileged endpoints
        privileged_endpoints = [
            '/admin',
            '/administrator',
            '/wp-admin',
            '/manager',
            '/phpmyadmin',
            '/server-status',
            '/debug',
            '/console',
            '/api/admin',
            '/admin/api'
        ]
        
        try:
            parsed_url = urllib.parse.urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            for endpoint in privileged_endpoints:
                test_url = urllib.parse.urljoin(base_url, endpoint)
                test_response = await self._safe_fetch(test_url)
                
                if test_response and test_response['status'] < 400:
                    # Check if it looks like an admin interface
                    content_str = str(test_response['content']).lower()
                    admin_indicators = ['login', 'admin', 'dashboard', 'control panel', 'manage']
                    
                    if any(indicator in content_str for indicator in admin_indicators):
                        finding = SecurityFinding(
                            id=f"access_control_{hashlib.md5(test_url.encode()).hexdigest()[:8]}",
                            type="Missing Access Control",
                            severity=ScanSeverity.HIGH,
                            location=f"Endpoint: {endpoint}",
                            description=f"Privileged endpoint accessible without authentication",
                            evidence=f"Endpoint {test_url} returned status {test_response['status']}",
                            recommendation="Implement proper authentication and authorization checks",
                            confidence=0.7,
                            cwe_id="CWE-284",
                            cvss_score=8.8
                        )
                        findings.append(finding)
        
        except Exception as e:
            print("  Access control check error: " + str(e))
        
        return findings
    
    async def _check_cross_site_request_forgery(self, url: str, 
                                               response: Dict[str, Any]) -> List[SecurityFinding]:
        """
        Check for Cross-Site Request Forgery (CSRF) vulnerabilities
        
        Args:
            url: Target URL to test
            response: HTTP response to analyze
            
        Returns:
            List of CSRF-related findings
        """
        findings = []
        
        try:
            if 'content' in response:
                content_str = response['content']
                if isinstance(content_str, bytes):
                    content_str = content_str.decode('utf-8', errors='ignore')
                soup = BeautifulSoup(content_str, 'html.parser')
                forms = soup.find_all('form')
                
                for form in forms:
                    form_action = form.get('action', '')
                    form_method = form.get('method', 'GET').upper()
                    
                    # Only check state-changing methods
                    if form_method in ['POST', 'PUT', 'DELETE', 'PATCH']:
                        # Look for CSRF tokens
                        csrf_inputs = form.find_all('input', {
                            'type': 'hidden',
                            'name': lambda x: x and any(token in x.lower() for token in ['csrf', 'token', 'nonce'])
                        })
                        
                        if not csrf_inputs:
                            # Check for anti-CSRF headers in form
                            has_anti_csrf = False
                            form_attrs = form.attrs
                            
                            # Check for Angular CSRF protection
                            if 'ng-submit' in form_attrs or 'data-ng-submit' in form_attrs:
                                has_anti_csrf = True
                            
                            # Check for Django CSRF middleware
                            django_csrf = form.find('input', {'name': 'csrfmiddlewaretoken'})
                            if django_csrf:
                                has_anti_csrf = True
                            
                            if not has_anti_csrf:
                                finding = SecurityFinding(
                                    id=f"csrf_{hashlib.md5(f'{form_action}{form_method}'.encode()).hexdigest()[:8]}",
                                    type="Cross-Site Request Forgery",
                                    severity=ScanSeverity.MEDIUM,
                                    location=f"Form: {form_action}",
                                    description=f"Form missing CSRF protection",
                                    evidence=f"Form uses {form_method} method without CSRF token",
                                    recommendation="Implement CSRF tokens or use SameSite cookies",
                                    confidence=0.65,
                                    cwe_id="CWE-352",
                                    cvss_score=8.8
                                )
                                findings.append(finding)
        
        except Exception as e:
            print("  CSRF check error: " + str(e))
        
        return findings
    
    async def _check_using_components_with_known_vulnerabilities(self, 
                                                                url: str, 
                                                                response: Dict[str, Any]) -> List[SecurityFinding]:
        """
        Check for outdated or vulnerable components
        
        Args:
            url: Target URL to test
            response: HTTP response to analyze
            
        Returns:
            List of vulnerable component findings
        """
        findings = []
        
        try:
            if 'content' in response:
                content_str = str(response['content'])
                
                # Check for common JavaScript libraries with known vulnerabilities
                js_libraries = {
                    'jquery': [
                        (r'jquery[.-]?([0-9.]+)\.js', 'jQuery'),
                        (r'jquery-([0-9.]+)\.min\.js', 'jQuery')
                    ],
                    'angular': [
                        (r'angular[.-]?([0-9.]+)\.js', 'AngularJS'),
                        (r'angular\.js\?v=([0-9.]+)', 'AngularJS')
                    ],
                    'react': [
                        (r'react[.-]?([0-9.]+)\.js', 'React'),
                        (r'react-dom[.-]?([0-9.]+)\.js', 'React DOM')
                    ],
                    'vue': [
                        (r'vue[.-]?([0-9.]+)\.js', 'Vue.js'),
                        (r'vue\.min\.js\?v=([0-9.]+)', 'Vue.js')
                    ],
                    'bootstrap': [
                        (r'bootstrap[.-]?([0-9.]+)\.js', 'Bootstrap JS'),
                        (r'bootstrap[.-]?([0-9.]+)\.css', 'Bootstrap CSS')
                    ]
                }
                
                for lib_name, patterns in js_libraries.items():
                    for pattern, component_name in patterns:
                        match = re.search(pattern, content_str, re.IGNORECASE)
                        if match:
                            version = match.group(1)
                            finding = SecurityFinding(
                                id=f"vuln_component_{lib_name}_{hashlib.md5(version.encode()).hexdigest()[:8]}",
                                type="Vulnerable Component",
                                severity=ScanSeverity.MEDIUM,
                                location="JavaScript Libraries",
                                description=f"Potentially outdated {component_name} version: {version}",
                                evidence=f"Found {component_name} version {version}",
                                recommendation="Update to latest secure version, monitor for security advisories",
                                confidence=0.5,
                                cwe_id="CWE-1104",
                                cvss_score=6.5
                            )
                            findings.append(finding)
                            break
        
        except Exception as e:
            print("  Vulnerable component check error: " + str(e))
        
        return findings
    
    async def _check_robots_txt(self, base_url: str) -> Optional[str]:
        """
        Check for robots.txt file
        
        Args:
            base_url: Base URL to check
            
        Returns:
            Contents of robots.txt if found, None otherwise
        """
        robots_url = urllib.parse.urljoin(base_url, '/robots.txt')
        response = await self._safe_fetch(robots_url)
        
        if response and response['status'] == 200:
            content = response['content']
            if isinstance(content, bytes):
                return content.decode('utf-8', errors='ignore')
            return str(content)
        
        return None
    
    async def _check_sitemap(self, base_url: str) -> Optional[Dict[str, Any]]:
        """
        Check for sitemap.xml file
        
        Args:
            base_url: Base URL to check
            
        Returns:
            Sitemap data if found, None otherwise
        """
        sitemap_url = urllib.parse.urljoin(base_url, '/sitemap.xml')
        response = await self._safe_fetch(sitemap_url)
        
        if response and response['status'] == 200:
            try:
                # Try to parse as XML
                content = response['content']
                if isinstance(content, bytes):
                    content = content.decode('utf-8', errors='ignore')
                return {'url': sitemap_url, 'content': content[:1000]}  # Truncate for reporting
            except:
                pass
        
        return None
    
    def _normalize_url(self, url: str) -> Optional[str]:
        """
        Normalize URL to standard format
        
        Args:
            url: URL to normalize
            
        Returns:
            Normalized URL or None if invalid
        """
        try:
            parsed = urllib.parse.urlparse(url)
            
            # Ensure scheme
            if not parsed.scheme:
                url = 'https://' + url
                parsed = urllib.parse.urlparse(url)
            
            # Ensure netloc
            if not parsed.netloc:
                return None
            
            # Normalize path
            path = parsed.path
            if not path:
                path = '/'
            
            # Remove default ports
            netloc = parsed.netloc
            if parsed.scheme == 'http' and netloc.endswith(':80'):
                netloc = netloc[:-3]
            elif parsed.scheme == 'https' and netloc.endswith(':443'):
                netloc = netloc[:-4]
            
            # Reconstruct URL
            normalized = urllib.parse.urlunparse((
                parsed.scheme,
                netloc,
                path,
                parsed.params,
                parsed.query,
                parsed.fragment
            ))
            
            return normalized.rstrip('/')
        
        except Exception:
            return None
    
    def _correlate_findings(self) -> List[SecurityFinding]:
        """
        Correlate individual findings to identify attack patterns
        
        Returns:
            List of correlated findings
        """
        correlated = []
        
        # Example correlation: XSS + CSRF = More severe finding
        xss_findings = [f for f in self.findings if 'XSS' in f.type]
        csrf_findings = [f for f in self.findings if 'CSRF' in f.type]
        
        if xss_findings and csrf_findings:
            finding = SecurityFinding(
                id=f"correlated_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}",
                type="Correlated Attack Pattern",
                severity=ScanSeverity.HIGH,
                location="Multiple Components",
                description="Combination of XSS and CSRF vulnerabilities increases attack surface",
                evidence=f"Found {len(xss_findings)} XSS and {len(csrf_findings)} CSRF vulnerabilities",
                recommendation="Address both XSS and CSRF vulnerabilities to prevent combined attacks",
                confidence=0.8,
                cwe_id="Multiple",
                cvss_score=8.5
            )
            correlated.append(finding)
        
        return correlated
    
    def _calculate_risk_score(self) -> float:
        """
        Calculate overall risk score based on findings
        
        Returns:
            Risk score from 0.0 to 10.0
        """
        if not self.findings:
            return 0.0
        
        # Weighted scoring based on severity
        weights = {
            ScanSeverity.CRITICAL: 10.0,
            ScanSeverity.HIGH: 7.5,
            ScanSeverity.MEDIUM: 5.0,
            ScanSeverity.LOW: 2.5,
            ScanSeverity.INFORMATIONAL: 1.0
        }
        
        total_score = 0.0
        max_possible = 0.0
        
        for finding in self.findings:
            weight = weights.get(finding.severity, 1.0)
            score = weight * finding.confidence
            total_score += score
            max_possible += weight
        
        if max_possible == 0:
            return 0.0
        
        # Normalize to 0-10 scale
        normalized_score = (total_score / max_possible) * 10
        
        return min(10.0, normalized_score)
    
    def _get_risk_level(self, risk_score: float) -> str:
        """
        Convert numeric risk score to risk level
        
        Args:
            risk_score: Numeric risk score
            
        Returns:
            Human-readable risk level
        """
        if risk_score >= 8.0:
            return "CRITICAL"
        elif risk_score >= 6.0:
            return "HIGH"
        elif risk_score >= 4.0:
            return "MEDIUM"
        elif risk_score >= 2.0:
            return "LOW"
        else:
            return "INFORMATIONAL"
    
    def _generate_executive_summary(self, risk_score: float, 
                                   findings_by_severity: Dict[str, List[SecurityFinding]]) -> Dict[str, Any]:
        """
        Generate executive summary for non-technical stakeholders
        
        Args:
            risk_score: Calculated risk score
            findings_by_severity: Findings grouped by severity
            
        Returns:
            Executive summary dictionary
        """
        risk_level = self._get_risk_level(risk_score)
        
        # Generate risk description
        if risk_level == "CRITICAL":
            risk_description = "Immediate remediation required. Critical security vulnerabilities present significant business risk."
        elif risk_level == "HIGH":
            risk_description = "Urgent attention needed. High-risk vulnerabilities could be exploited to compromise systems."
        elif risk_level == "MEDIUM":
            risk_description = "Address within reasonable timeframe. Medium-risk issues should be prioritized for remediation."
        elif risk_level == "LOW":
            risk_description = "Monitor and address as resources allow. Low-risk findings represent security improvements."
        else:
            risk_description = "Good security posture. Informational findings represent best practice recommendations."
        
        return {
            'risk_level': risk_level,
            'risk_score': round(risk_score, 1),
            'risk_description': risk_description,
            'critical_findings': len(findings_by_severity['critical']),
            'high_findings': len(findings_by_severity['high']),
            'total_findings': len(self.findings),
            'overall_assessment': f"Website security posture is {risk_level.lower()} risk",
            'key_concerns': [
                f.type for f in findings_by_severity['critical'][:3]
            ] if findings_by_severity['critical'] else ["No critical findings"]
        }
    
    def _generate_recommendations(self) -> List[Dict[str, Any]]:
        """
        Generate actionable remediation recommendations
        
        Returns:
            List of recommendation dictionaries
        """
        recommendations = []
        
        # Group findings by type for targeted recommendations
        findings_by_type = {}
        for finding in self.findings:
            if finding.type not in findings_by_type:
                findings_by_type[finding.type] = []
            findings_by_type[finding.type].append(finding)
        
        # Generate recommendations for each vulnerability type
        for vuln_type, findings in findings_by_type.items():
            count = len(findings)
            max_severity = max(f.severity.value for f in findings)
            
            # Get appropriate remediation based on vulnerability type
            remediation = self._get_remediation_for_vuln_type(vuln_type)
            
            recommendations.append({
                'type': vuln_type,
                'count': count,
                'max_severity': max_severity,
                'description': remediation['description'],
                'actions': remediation['actions'],
                'priority': 'High' if max_severity in ['critical', 'high'] else 'Medium'
            })
        
        # Sort by priority and count
        recommendations.sort(key=lambda x: (x['priority'] == 'High', x['count']), reverse=True)
        
        return recommendations[:10]  # Top 10 recommendations
    
    def _get_remediation_for_vuln_type(self, vuln_type: str) -> Dict[str, Any]:
        """
        Get remediation guidance for specific vulnerability type
        
        Args:
            vuln_type: Type of vulnerability
            
        Returns:
            Remediation guidance dictionary
        """
        # Comprehensive remediation guidance for common vulnerabilities
        remediation_guide = {
            "Cross-Site Scripting (XSS)": {
                "description": "Prevent malicious script execution in user's browser",
                "actions": [
                    "Implement Content Security Policy (CSP) headers",
                    "Validate and sanitize all user inputs",
                    "Use context-aware output encoding",
                    "Enable XSS protection headers (X-XSS-Protection)",
                    "Use modern frameworks with built-in XSS protection"
                ]
            },
            "SQL Injection": {
                "description": "Prevent unauthorized database access",
                "actions": [
                    "Use parameterized queries or prepared statements",
                    "Implement proper input validation",
                    "Apply principle of least privilege to database accounts",
                    "Use stored procedures with validation",
                    "Implement Web Application Firewall (WAF) rules"
                ]
            },
            "Command Injection": {
                "description": "Prevent unauthorized system command execution",
                "actions": [
                    "Validate and sanitize all user inputs",
                    "Use allowlists for permitted commands",
                    "Implement proper escaping for shell commands",
                    "Run services with minimal privileges",
                    "Use safe APIs instead of shell commands"
                ]
            },
            "Path Traversal": {
                "description": "Prevent unauthorized file system access",
                "actions": [
                    "Validate file paths against allowlists",
                    "Use chroot jails or containerization",
                    "Implement proper access controls",
                    "Use indexed file references instead of user-supplied paths",
                    "Sanitize ../ and similar sequences"
                ]
            },
            "Cross-Site Request Forgery": {
                "description": "Prevent unauthorized actions on behalf of authenticated users",
                "actions": [
                    "Implement CSRF tokens for state-changing requests",
                    "Use SameSite cookie attribute",
                    "Validate Origin and Referer headers",
                    "Implement double-submit cookie pattern",
                    "Use anti-CSRF libraries/framework features"
                ]
            }
        }
        
        # Default remediation for unknown vulnerability types
        default_remediation = {
            "description": "Address security vulnerability",
            "actions": [
                "Review vulnerability details",
                "Implement appropriate security controls",
                "Test fixes thoroughly",
                "Monitor for similar issues"
            ]
        }
        
        return remediation_guide.get(vuln_type, default_remediation)
    
    def _generate_technical_details(self) -> Dict[str, Any]:
        """
        Generate technical details for security teams
        
        Returns:
            Technical details dictionary
        """
        # Analyze finding patterns
        vuln_types = {}
        for finding in self.findings:
            if finding.type not in vuln_types:
                vuln_types[finding.type] = 0
            vuln_types[finding.type] += 1
        
        # Get top vulnerability types
        top_vulns = sorted(vuln_types.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Analyze confidence distribution
        confidence_stats = {
            'high_confidence': len([f for f in self.findings if f.confidence >= 0.8]),
            'medium_confidence': len([f for f in self.findings if 0.5 <= f.confidence < 0.8]),
            'low_confidence': len([f for f in self.findings if f.confidence < 0.5])
        }
        
        return {
            'scan_metadata': {
                'phases_completed': self.scan_statistics['phases_completed'],
                'total_requests': self.scan_statistics['total_requests'],
                'failed_requests': self.scan_statistics['failed_requests'],
                'unique_urls_tested': len(self.visited_urls)
            },
            'vulnerability_distribution': dict(top_vulns),
            'confidence_breakdown': confidence_stats,
            'methodology_notes': [
                'OWASP Testing Guide v4.2 compliant',
                'Automated scanning with manual verification recommended',
                'False positives possible - validate findings',
                'Dynamic analysis limited to accessible endpoints'
            ],
            'limitations': [
                'JavaScript-heavy applications may require manual testing',
                'Authentication-dependent functionality not tested',
                'Business logic vulnerabilities may not be detected',
                'Rate limiting may affect scan completeness'
            ]
        }  