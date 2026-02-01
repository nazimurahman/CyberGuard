"""
api_analyzer.py - API Security Analysis Module
Specialized analysis for REST APIs, GraphQL, and web services
"""

import json
import re
import hashlib
import asyncio
import html
from typing import Dict, List, Any, Optional, Set, Tuple
import aiohttp
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
import yaml

# Check if yaml module is available, provide fallback if not
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


class APIType(Enum):
    """Enumeration of API types that can be analyzed"""
    REST = "rest"
    GRAPHQL = "graphql"
    SOAP = "soap"
    RPC = "rpc"
    WEBHOOK = "webhook"
    UNKNOWN = "unknown"


class APIVulnerability(Enum):
    """Enumeration of API-specific vulnerability types based on OWASP API Security Top 10"""
    BROKEN_OBJECT_LEVEL_AUTHORIZATION = "bola"
    BROKEN_USER_AUTHENTICATION = "bua"
    EXCESSIVE_DATA_EXPOSURE = "ede"
    LACK_OF_RESOURCES_RATE_LIMITING = "lrrl"
    BROKEN_FUNCTION_LEVEL_AUTHORIZATION = "bfla"
    MASS_ASSIGNMENT = "mass_assignment"
    SECURITY_MISCONFIGURATION = "security_misconfig"
    INJECTION = "injection"
    IMPROPER_ASSET_MANAGEMENT = "improper_asset_management"
    INSECURE_DESIGN = "insecure_design"


@dataclass
class APIEndpoint:
    """Data class representing an API endpoint with its metadata and characteristics"""
    url: str  # Full URL of the endpoint
    method: str  # HTTP method (GET, POST, etc.)
    parameters: List[Dict[str, Any]] = field(default_factory=list)  # List of parameters the endpoint accepts
    request_headers: Dict[str, str] = field(default_factory=dict)  # Headers sent in request
    response_headers: Dict[str, str] = field(default_factory=dict)  # Headers received in response
    status_code: int = 0  # HTTP status code of response
    response_time: float = 0.0  # Time taken for response in seconds
    response_size: int = 0  # Size of response in bytes
    content_type: str = ""  # Content-Type header value
    requires_auth: bool = False  # Whether endpoint requires authentication
    rate_limited: bool = False  # Whether endpoint has rate limiting
    description: str = ""  # Description of endpoint functionality
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the endpoint object to a dictionary for serialization or reporting"""
        return {
            'url': self.url,
            'method': self.method,
            'parameters': self.parameters,
            'request_headers': self.request_headers,
            'response_headers': self.response_headers,
            'status_code': self.status_code,
            'response_time': self.response_time,
            'response_size': self.response_size,
            'content_type': self.content_type,
            'requires_auth': self.requires_auth,
            'rate_limited': self.rate_limited,
            'description': self.description
        }


class APIAnalyzer:
    """
    Main class for API security testing, focusing on OWASP API Security Top 10 vulnerabilities
    Provides methods for discovering endpoints, analyzing authentication, and testing for vulnerabilities
    """
    
    def __init__(self):
        """Initialize the API analyzer with detection rules, patterns, and test payloads"""
        # Load various detection patterns
        self.api_patterns = self._load_api_patterns()
        self.auth_patterns = self._load_auth_patterns()
        self.rate_limit_patterns = self._load_rate_limit_patterns()
        self.sensitive_data_patterns = self._load_sensitive_data_patterns()
        
        # State tracking for discovered endpoints and API characteristics
        self.discovered_endpoints: List[APIEndpoint] = []
        self.api_type: APIType = APIType.UNKNOWN
        self.auth_scheme: Optional[str] = None
        
        # Test payloads for various vulnerability types
        self.test_payloads = self._load_test_payloads()
    
    def _load_api_patterns(self) -> Dict[str, List[str]]:
        """
        Load regex patterns for identifying different types of APIs from responses and URLs
        
        Returns:
            Dictionary mapping API type names to lists of regex patterns
        """
        return {
            'rest': [
                r'/api/v[0-9]+/',  # Versioned API paths like /api/v1/
                r'/rest/',  # REST indicator in path
                r'/v[0-9]/',  # Version indicator
                r'\.(json|xml)$',  # JSON or XML file extensions
                r'Content-Type: application/json',  # JSON content type header
                r'Content-Type: application/xml'  # XML content type header
            ],
            'graphql': [
                r'/graphql',  # GraphQL endpoint path
                r'/graphiql',  # GraphQL IDE path
                r'query\s*{',  # GraphQL query syntax
                r'mutation\s*{',  # GraphQL mutation syntax
                r'__typename',  # GraphQL introspection field
                r'Content-Type: application/graphql'  # GraphQL content type
            ],
            'soap': [
                r'SOAPAction',  # SOAP action header
                r'<soap:',  # SOAP XML namespace
                r'<s:',  # SOAP envelope
                r'xmlns:soap=',  # SOAP namespace declaration
                r'Content-Type: text/xml'  # SOAP content type
            ],
            'swagger': [
                r'/swagger',  # Swagger UI path
                r'/swagger-ui',  # Swagger UI alternative path
                r'/api-docs',  # API documentation path
                r'swagger\.json',  # Swagger JSON file
                r'swagger\.yaml',  # Swagger YAML file
                r'OpenAPI'  # OpenAPI specification indicator
            ]
        }
    
    def _load_auth_patterns(self) -> Dict[str, List[str]]:
        """
        Load regex patterns for identifying authentication schemes in headers and responses
        
        Returns:
            Dictionary mapping auth scheme names to lists of regex patterns
        """
        return {
            'jwt': [
                r'Authorization: Bearer eyJ',  # JWT token in Authorization header
                r'\.(eyJ[A-Za-z0-9-_]+\.){2}[A-Za-z0-9-_]*',  # JWT token pattern
                r'alg:\s*["\'](HS256|RS256)["\']'  # JWT algorithm specification
            ],
            'basic': [
                r'Authorization: Basic [A-Za-z0-9+/=]+',  # Basic auth header
                r'WWW-Authenticate: Basic'  # Basic auth challenge
            ],
            'oauth': [
                r'oauth_',  # OAuth parameter prefix
                r'access_token=',  # OAuth access token in URL
                r'Authorization: Bearer [a-f0-9]{32,}',  # OAuth bearer token
                r'/oauth/'  # OAuth endpoint path
            ],
            'api_key': [
                r'api_key=',  # API key in URL parameter
                r'apikey=',  # Alternative API key parameter
                r'X-API-Key:',  # API key in custom header
                r'Authorization: ApiKey'  # API key in Authorization header
            ]
        }
    
    def _load_rate_limit_patterns(self) -> Dict[str, List[str]]:
        """
        Load patterns that indicate rate limiting is implemented
        
        Returns:
            Dictionary with header patterns and response message patterns
        """
        return {
            'headers': [
                r'X-RateLimit-Limit',  # Rate limit header
                r'X-RateLimit-Remaining',  # Remaining requests header
                r'X-RateLimit-Reset',  # Reset time header
                r'Retry-After',  # Retry timing header
                r'RateLimit-Limit'  # Alternative rate limit header
            ],
            'responses': [
                r'429 Too Many Requests',  # HTTP 429 status message
                r'Rate limit exceeded',  # Rate limit error message
                r'Too many requests',  # Generic rate limit message
                r'Quota exceeded'  # Quota limit message
            ]
        }
    
    def _load_sensitive_data_patterns(self) -> Dict[str, str]:
        """
        Load regex patterns for detecting sensitive data in API responses
        
        Returns:
            Dictionary mapping data type names to regex patterns
        """
        return {
            'password': r'["\']?password["\']?\s*:\s*["\'][^"\']+["\']',  # Password in JSON
            'token': r'["\']?(access_|refresh_)?token["\']?\s*:\s*["\'][^"\']+["\']',  # Tokens
            'secret': r'["\']?secret["\']?\s*:\s*["\'][^"\']+["\']',  # Secret keys
            'api_key': r'["\']?api[_-]?key["\']?\s*:\s*["\'][^"\']+["\']',  # API keys
            'private_key': r'-----BEGIN (RSA|DSA|EC|PRIVATE) KEY-----',  # Private key headers
            'credit_card': r'\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}',  # Credit card numbers
            'ssn': r'\d{3}-\d{2}-\d{4}',  # Social Security Number pattern
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'  # Email addresses
        }
    
    def _load_test_payloads(self) -> Dict[str, List[Any]]:
        """
        Load test payloads for various API vulnerability tests
        
        Returns:
            Dictionary mapping vulnerability types to lists of test payloads
        """
        return {
            'idor': ['1', '0', '-1', '999999', 'admin', 'test'],  # IDOR test IDs
            'sqli': ["' OR '1'='1", "' UNION SELECT NULL--", "' AND SLEEP(5)--"],  # SQL injection payloads
            'xss': ['<script>alert(1)</script>', '" onmouseover="alert(1)'],  # XSS payloads
            'command': ['; ls', '| cat /etc/passwd', '`id`'],  # Command injection payloads
            'path_traversal': ['../../../etc/passwd', '..\\..\\windows\\win.ini'],  # Path traversal payloads
            'mass_assignment': ['{"admin": true}', '{"role": "admin"}'],  # Mass assignment payloads
            'json_injection': ['{"$ne": 1}', '{"$where": "1==1"}'],  # JSON injection payloads
            'jwt_tampering': ['none', 'HS256', 'RS256', 'none', 'undefined']  # JWT tampering payloads
        }
    
    async def analyze_apis(self, base_url: str, session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """
        Main entry point for API security analysis workflow
        
        Args:
            base_url: Base URL to scan for APIs
            session: HTTP session for making requests
            
        Returns:
            List of API security findings with details
        """
        findings = []  # Initialize empty findings list
        
        try:
            print(f"Analyzing APIs on {base_url}")
            
            # Phase 1: Discover API endpoints using various techniques
            print(f"Discovering API endpoints...")
            await self._discover_endpoints(base_url, session)
            
            if not self.discovered_endpoints:
                print(f"No API endpoints discovered")
                return findings  # Return empty if no endpoints found
            
            print(f"Discovered {len(self.discovered_endpoints)} API endpoints")
            
            # Phase 2: Identify API type and authentication mechanisms
            print(f"Analyzing authentication...")
            await self._analyze_authentication(session)
            
            # Phase 3: Test each discovered endpoint for vulnerabilities
            print(f"Testing endpoints for vulnerabilities...")
            for endpoint in self.discovered_endpoints:
                endpoint_findings = await self._test_endpoint(endpoint, session)
                findings.extend(endpoint_findings)
            
            # Phase 4: Test for API-specific vulnerabilities
            print(f"Testing API-specific vulnerabilities...")
            api_specific_findings = await self._test_api_specific_vulnerabilities(base_url, session)
            findings.extend(api_specific_findings)
            
            print(f"API analysis completed: {len(findings)} findings")
            
            return findings
            
        except Exception as e:
            print(f"API analysis error: {str(e)}")
            return findings
    
    async def _discover_endpoints(self, base_url: str, session: aiohttp.ClientSession) -> None:
        """
        Discover API endpoints through various techniques including common paths,
        JavaScript analysis, documentation discovery, and OpenAPI parsing
        
        Args:
            base_url: Base URL to scan
            session: HTTP session for making requests
        """
        discovered_urls = set()  # Track discovered URLs to avoid duplicates
        
        # Technique 1: Check common API paths
        common_api_paths = [
            '/api',
            '/api/v1',
            '/api/v2',
            '/rest',
            '/graphql',
            '/graphiql',
            '/swagger',
            '/swagger-ui',
            '/api-docs',
            '/docs',
            '/v1',
            '/v2',
            '/oauth',
            '/auth'
        ]
        
        # Test each common API path
        for path in common_api_paths:
            test_url = urllib.parse.urljoin(base_url, path)
            try:
                # Attempt to access the potential API endpoint
                async with session.get(test_url, timeout=10) as response:
                    if response.status < 400:  # If request is successful
                        await self._analyze_response_for_endpoints(test_url, 'GET', response)
                        discovered_urls.add(test_url)
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue  # Skip if request fails or times out
        
        # Technique 2: Look for API references in JavaScript files
        js_endpoints = await self._find_js_api_references(base_url, session)
        for endpoint in js_endpoints:
            if endpoint not in discovered_urls:
                discovered_urls.add(endpoint)
                # Test the discovered JavaScript-referenced endpoint
                try:
                    async with session.get(endpoint, timeout=10) as response:
                        await self._analyze_response_for_endpoints(endpoint, 'GET', response)
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue
        
        # Technique 3: Check robots.txt for API path disclosures
        robots_url = urllib.parse.urljoin(base_url, '/robots.txt')
        try:
            async with session.get(robots_url, timeout=10) as response:
                if response.status == 200:
                    content = await response.text()
                    # Look for API paths in robots.txt entries
                    for line in content.split('\n'):
                        if 'api' in line.lower() or 'rest' in line.lower():
                            # Extract path from robots.txt line
                            if ':' in line:
                                path = line.split(':', 1)[1].strip()
                            else:
                                path = line.strip()
                            if path.startswith('/'):
                                api_url = urllib.parse.urljoin(base_url, path)
                                if api_url not in discovered_urls:
                                    discovered_urls.add(api_url)
                                    try:
                                        async with session.get(api_url, timeout=10) as api_response:
                                            await self._analyze_response_for_endpoints(api_url, 'GET', api_response)
                                    except (aiohttp.ClientError, asyncio.TimeoutError):
                                        continue
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass  # robots.txt not accessible
        
        # Technique 4: Check for OpenAPI/Swagger documentation
        swagger_paths = [
            '/swagger.json',
            '/swagger.yaml',
            '/swagger.yml',
            '/openapi.json',
            '/openapi.yaml',
            '/openapi.yml',
            '/api/swagger.json',
            '/api/openapi.json'
        ]
        
        for path in swagger_paths:
            swagger_url = urllib.parse.urljoin(base_url, path)
            try:
                async with session.get(swagger_url, timeout=10) as response:
                    if response.status == 200:
                        content_type = response.headers.get('Content-Type', '')
                        if 'json' in content_type or 'yaml' in content_type:
                            content = await response.text()
                            swagger_endpoints = await self._parse_swagger_docs(swagger_url, content, session)
                            for endpoint in swagger_endpoints:
                                if endpoint.url not in discovered_urls:
                                    self.discovered_endpoints.append(endpoint)
                                    discovered_urls.add(endpoint.url)
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue
    
    async def _analyze_response_for_endpoints(self, url: str, method: str, 
                                             response: aiohttp.ClientResponse) -> None:
        """
        Analyze HTTP response to determine if it's an API endpoint and extract metadata
        
        Args:
            url: Request URL
            method: HTTP method used
            response: HTTP response object
        """
        try:
            content_type = response.headers.get('Content-Type', '')
            content = await response.text()
            
            # Check if this looks like an API response based on content type and content
            is_api_response = False
            
            # Check content type for API indicators
            if any(api_type in content_type for api_type in ['json', 'xml', 'graphql']):
                is_api_response = True
            
            # Check content patterns for structured data
            if ('{' in content and '}' in content) or ('<' in content and '>' in content):
                is_api_response = True
            
            # Check for API indicators in response text
            api_indicators = ['api', 'rest', 'graphql', 'endpoint', 'resource', 'collection']
            if any(indicator in content.lower() for indicator in api_indicators):
                is_api_response = True
            
            # If determined to be API response, create endpoint object
            if is_api_response:
                endpoint = APIEndpoint(
                    url=url,
                    method=method,
                    response_headers=dict(response.headers),
                    status_code=response.status,
                    content_type=content_type,
                    response_size=len(content.encode('utf-8'))
                )
                
                # Determine if authentication is required based on status codes
                if response.status in [401, 403]:
                    endpoint.requires_auth = True
                
                # Check for rate limiting headers
                rate_limit_headers = [h for h in response.headers.keys() 
                                     if 'rate' in h.lower() or 'limit' in h.lower()]
                if rate_limit_headers:
                    endpoint.rate_limited = True
                
                # Parse query parameters from URL
                parsed_url = urllib.parse.urlparse(url)
                query_params = urllib.parse.parse_qs(parsed_url.query)
                if query_params:
                    for param_name, param_values in query_params.items():
                        endpoint.parameters.append({
                            'name': param_name,
                            'in': 'query',
                            'required': False,
                            'values': param_values
                        })
                
                self.discovered_endpoints.append(endpoint)
                
                # Determine API type from response content
                await self._determine_api_type(content, content_type)
        
        except Exception as e:
            print(f"Error analyzing response: {str(e)}")
    
    async def _find_js_api_references(self, base_url: str, 
                                     session: aiohttp.ClientSession) -> Set[str]:
        """
        Find API endpoint references in JavaScript files by analyzing script sources
        and JavaScript content for API URL patterns
        
        Args:
            base_url: Base URL to scan
            session: HTTP session
            
        Returns:
            Set of discovered API URLs from JavaScript analysis
        """
        api_urls = set()
        
        try:
            # Get main page to find referenced JavaScript files
            async with session.get(base_url, timeout=10) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Find all script tags in HTML
                    script_pattern = r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>'
                    script_matches = re.findall(script_pattern, content, re.IGNORECASE)
                    
                    for script_src in script_matches:
                        script_url = urllib.parse.urljoin(base_url, script_src)
                        
                        # Only process local JS files (same domain)
                        if base_url in script_url:
                            try:
                                async with session.get(script_url, timeout=10) as js_response:
                                    if js_response.status == 200:
                                        js_content = await js_response.text()
                                        
                                        # Patterns for API URLs in JavaScript code
                                        url_patterns = [
                                            r'["\'](/api/[^"\']+)["\']',  # /api/ endpoints
                                            r'["\'](/rest/[^"\']+)["\']',  # /rest/ endpoints
                                            r'["\'](/v[0-9]/[^"\']+)["\']',  # Versioned endpoints
                                            r'["\'](https?://[^"\']+/api/[^"\']+)["\']',  # Full API URLs
                                            r'fetch\(["\']([^"\']+)["\']',  # Fetch API calls
                                            r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']',  # Axios calls
                                            r'\.ajax\([^)]*url:\s*["\']([^"\']+)["\']'  # jQuery AJAX
                                        ]
                                        
                                        for pattern in url_patterns:
                                            matches = re.findall(pattern, js_content, re.IGNORECASE)
                                            for match in matches:
                                                # Handle tuple matches (some patterns capture groups)
                                                if isinstance(match, tuple):
                                                    match = match[-1]  # Get the URL from last capture group
                                                
                                                # Convert relative URLs to absolute URLs
                                                if match.startswith('/'):
                                                    api_url = urllib.parse.urljoin(base_url, match)
                                                elif match.startswith('http'):
                                                    api_url = match
                                                else:
                                                    api_url = urllib.parse.urljoin(base_url, '/' + match)
                                                
                                                # Only include same-domain APIs for security
                                                if base_url in api_url:
                                                    api_urls.add(api_url)
                            except (aiohttp.ClientError, asyncio.TimeoutError):
                                continue  # Skip if JS file can't be loaded
        
        except Exception as e:
            print(f"JS analysis error: {str(e)}")
        
        return api_urls
    
    async def _parse_swagger_docs(self, swagger_url: str, content: str, 
                                 session: aiohttp.ClientSession) -> List[APIEndpoint]:
        """
        Parse Swagger/OpenAPI documentation to discover API endpoints and their metadata
        
        Args:
            swagger_url: URL of Swagger/OpenAPI documentation
            content: Documentation content (JSON or YAML)
            session: HTTP session for testing discovered endpoints
            
        Returns:
            List of discovered API endpoints with metadata
        """
        endpoints = []
        
        try:
            spec = None
            
            # Parse JSON format OpenAPI spec
            if swagger_url.endswith('.json') or 'application/json' in swagger_url:
                try:
                    spec = json.loads(content)
                except json.JSONDecodeError:
                    return endpoints  # Return empty if JSON parsing fails
            
            # Parse YAML format OpenAPI spec
            elif swagger_url.endswith(('.yaml', '.yml')) or 'application/yaml' in swagger_url:
                if not YAML_AVAILABLE:
                    print(f"YAML module not available, skipping YAML parsing")
                    return endpoints
                try:
                    spec = yaml.safe_load(content)
                except yaml.YAMLError:
                    return endpoints  # Return empty if YAML parsing fails
            
            if not spec:
                return endpoints  # Return empty if no spec parsed
            
            # Extract base URL from OpenAPI specification
            base_path = spec.get('basePath', '')
            if not base_path and 'servers' in spec:
                servers = spec.get('servers', [])
                if servers and isinstance(servers, list) and len(servers) > 0:
                    if isinstance(servers[0], dict) and 'url' in servers[0]:
                        base_path = servers[0]['url']
            
            # Fallback to swagger URL directory if no base path in spec
            if not base_path:
                parsed_url = urllib.parse.urlparse(swagger_url)
                base_path = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            # Parse paths defined in OpenAPI spec
            paths = spec.get('paths', {})
            for path, methods in paths.items():
                if not isinstance(methods, dict):
                    continue
                    
                for method, details in methods.items():
                    if method.lower() in ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']:
                        # Construct full URL from base path and endpoint path
                        if base_path.endswith('/') and path.startswith('/'):
                            full_url = base_path + path[1:]
                        elif not base_path.endswith('/') and not path.startswith('/'):
                            full_url = base_path + '/' + path
                        else:
                            full_url = base_path + path
                        
                        # Create endpoint object with metadata from OpenAPI spec
                        endpoint = APIEndpoint(
                            url=full_url,
                            method=method.upper(),
                            description=details.get('summary', details.get('description', ''))
                        )
                        
                        # Parse parameters defined in OpenAPI spec
                        parameters = details.get('parameters', [])
                        if isinstance(parameters, list):
                            for param in parameters:
                                if isinstance(param, dict):
                                    param_info = {
                                        'name': param.get('name', ''),
                                        'in': param.get('in', ''),
                                        'required': param.get('required', False),
                                        'type': param.get('type', param.get('schema', {}).get('type', ''))
                                    }
                                    endpoint.parameters.append(param_info)
                        
                        endpoints.append(endpoint)
        
        except Exception as e:
            print(f"Swagger parsing error: {str(e)}")
        
        return endpoints
    
    async def _determine_api_type(self, content: str, content_type: str) -> None:
        """
        Determine the type of API based on response content and content-type
        
        Args:
            content: Response content as string
            content_type: Content-Type header value
        """
        content_lower = content.lower()
        
        # Check for GraphQL indicators
        if 'graphql' in content_lower or '__typename' in content_lower:
            self.api_type = APIType.GRAPHQL
        # Check for SOAP indicators
        elif 'soap' in content_lower or '<soap:' in content_lower:
            self.api_type = APIType.SOAP
        # Check for JSON-RPC indicators
        elif ('jsonrpc' in content_lower or 'method' in content_lower) and 'params' in content_lower:
            self.api_type = APIType.RPC
        # Default to REST for JSON content
        elif 'application/json' in content_type or ('{' in content and '}' in content):
            self.api_type = APIType.REST
        else:
            self.api_type = APIType.UNKNOWN
    
    async def _analyze_authentication(self, session: aiohttp.ClientSession) -> None:
        """
        Analyze authentication schemes used by discovered API endpoints
        
        Args:
            session: HTTP session for testing authentication
        """
        if not self.discovered_endpoints:
            return
        
        # Find endpoints that appear to require authentication
        auth_endpoints = [ep for ep in self.discovered_endpoints if ep.requires_auth]
        
        # Test first 3 auth endpoints to identify scheme
        for endpoint in auth_endpoints[:3]:
            try:
                # Test endpoint without authentication
                async with session.request(endpoint.method, endpoint.url, timeout=10) as response:
                    if response.status == 401:
                        auth_header = response.headers.get('WWW-Authenticate', '')
                        
                        # Check authentication scheme from WWW-Authenticate header
                        for scheme, patterns in self.auth_patterns.items():
                            for pattern in patterns:
                                if re.search(pattern, auth_header, re.IGNORECASE):
                                    self.auth_scheme = scheme
                                    print(f"Detected {scheme.upper()} authentication")
                                    return
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue
        
        # Check for API key patterns in URLs
        for endpoint in self.discovered_endpoints:
            if any(key in endpoint.url.lower() for key in ['api_key', 'apikey', 'token']):
                self.auth_scheme = 'api_key'
                print(f"Detected API key authentication")
                return
    
    async def _test_endpoint(self, endpoint: APIEndpoint, 
                           session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """
        Comprehensive testing of a single API endpoint for multiple vulnerability types
        
        Args:
            endpoint: API endpoint to test
            session: HTTP session for making test requests
            
        Returns:
            List of vulnerability findings for this endpoint
        """
        findings = []
        
        try:
            print(f"Testing {endpoint.method} {endpoint.url}")
            
            # Test 1: Broken Object Level Authorization (BOLA/IDOR)
            bola_findings = await self._test_broken_object_authorization(endpoint, session)
            findings.extend(bola_findings)
            
            # Test 2: Broken User Authentication
            auth_findings = await self._test_broken_authentication(endpoint, session)
            findings.extend(auth_findings)
            
            # Test 3: Excessive Data Exposure
            data_exposure_findings = await self._test_excessive_data_exposure(endpoint, session)
            findings.extend(data_exposure_findings)
            
            # Test 4: Lack of Resources & Rate Limiting
            rate_limit_findings = await self._test_rate_limiting(endpoint, session)
            findings.extend(rate_limit_findings)
            
            # Test 5: Broken Function Level Authorization
            function_auth_findings = await self._test_function_level_authorization(endpoint, session)
            findings.extend(function_auth_findings)
            
            # Test 6: Mass Assignment
            mass_assignment_findings = await self._test_mass_assignment(endpoint, session)
            findings.extend(mass_assignment_findings)
            
            # Test 7: Security Misconfiguration
            misconfig_findings = await self._test_security_misconfiguration(endpoint, session)
            findings.extend(misconfig_findings)
            
            # Test 8: Injection
            injection_findings = await self._test_injection(endpoint, session)
            findings.extend(injection_findings)
            
        except Exception as e:
            print(f"Endpoint test error: {str(e)}")
        
        return findings
    
    async def _test_broken_object_authorization(self, endpoint: APIEndpoint, 
                                              session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """
        Test for Broken Object Level Authorization (BOLA/IDOR) vulnerabilities
        where users can access objects they shouldn't have permission to access
        
        Args:
            endpoint: API endpoint to test
            session: HTTP session
            
        Returns:
            List of BOLA findings
        """
        findings = []
        
        try:
            url = endpoint.url
            
            # Patterns for common object ID formats in URLs
            id_patterns = [
                r'/(\d+)/?$',           # /users/123
                r'/(\d+)/[^/]+/?$',     # /users/123/profile
                r'id=(\d+)',            # ?id=123
                r'userId=(\d+)',        # ?userId=123
                r'user_id=(\d+)',       # ?user_id=123
            ]
            
            # Search for object IDs in URL
            for pattern in id_patterns:
                match = re.search(pattern, url)
                if match:
                    object_id = match.group(1)
                    
                    # Only test numeric IDs
                    if object_id.isdigit():
                        # Test with different IDs that might bypass authorization
                        test_ids = ['1', '0', '999999', str(int(object_id) + 1), str(int(object_id) - 1)]
                        
                        for test_id in test_ids:
                            # Replace original ID with test ID
                            test_url = re.sub(r'\b' + re.escape(object_id) + r'\b', test_id, url)
                            
                            # Skip if URL didn't change (pattern didn't match as expected)
                            if test_url == url:
                                continue
                                
                            # Test access with different ID
                            async with session.request(endpoint.method, test_url, timeout=10) as response:
                                if response.status == 200:
                                    content = await response.text()
                                    
                                    # Heuristic: If we get structured data back, might be IDOR
                                    if len(content) > 50 and ('{' in content or '[' in content):
                                        finding = {
                                            'id': f"bola_{hashlib.md5(test_url.encode()).hexdigest()[:8]}",
                                            'type': "Broken Object Level Authorization",
                                            'severity': "high",
                                            'location': endpoint.url,
                                            'description': f"Object ID {test_id} accessible without authorization",
                                            'evidence': f"Accessed object {test_id} with status {response.status}",
                                            'confidence': 0.7,
                                            'remediation': "Implement proper authorization checks for object access"
                                        }
                                        findings.append(finding)
                                        break
                    break  # Only test first pattern match
        
        except Exception as e:
            print(f"BOLA test error: {str(e)}")
        
        return findings
    
    async def _test_broken_authentication(self, endpoint: APIEndpoint, 
                                        session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """
        Test for Broken User Authentication vulnerabilities including
        missing authentication and weak/default credentials
        
        Args:
            endpoint: API endpoint to test
            session: HTTP session
            
        Returns:
            List of authentication findings
        """
        findings = []
        
        try:
            # Check if sensitive endpoints don't require authentication
            sensitive_patterns = [
                'admin', 'user', 'account', 'profile', 'settings',
                'password', 'token', 'secret', 'config', 'database'
            ]
            
            url_lower = endpoint.url.lower()
            is_sensitive = any(pattern in url_lower for pattern in sensitive_patterns)
            
            # Test if sensitive endpoint is accessible without authentication
            if is_sensitive and not endpoint.requires_auth:
                async with session.request(endpoint.method, endpoint.url, timeout=10) as response:
                    if response.status < 400:
                        finding = {
                            'id': f"auth_missing_{hashlib.md5(endpoint.url.encode()).hexdigest()[:8]}",
                            'type': "Missing Authentication",
                            'severity': "high",
                            'location': endpoint.url,
                            'description': "Sensitive endpoint accessible without authentication",
                            'evidence': f"Endpoint returned status {response.status} without authentication",
                            'confidence': 0.8,
                            'remediation': "Require authentication for sensitive endpoints"
                        }
                        findings.append(finding)
            
            # Test for default/weak credentials on login/auth endpoints
            if 'login' in url_lower or 'auth' in url_lower:
                common_credentials = [
                    ('admin', 'admin'),
                    ('admin', 'password'),
                    ('root', 'root'),
                    ('test', 'test'),
                    ('user', 'user')
                ]
                
                # Test first 2 common credential pairs
                for username, password in common_credentials[:2]:
                    auth_data = {'username': username, 'password': password}
                    
                    try:
                        async with session.post(endpoint.url, json=auth_data, timeout=10) as response:
                            if response.status == 200:
                                content = await response.text()
                                # Check for success indicators in response
                                if 'token' in content.lower() or 'success' in content.lower():
                                    finding = {
                                        'id': f"weak_creds_{hashlib.md5(f'{username}{password}'.encode()).hexdigest()[:8]}",
                                        'type': "Weak Default Credentials",
                                        'severity': "critical",
                                        'location': endpoint.url,
                                        'description': f"Default credentials {username}:{password} accepted",
                                        'evidence': f"Login successful with default credentials",
                                        'confidence': 0.9,
                                        'remediation': "Change default credentials, implement strong password policies"
                                    }
                                    findings.append(finding)
                                    break
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        continue
        
        except Exception as e:
            print(f"Authentication test error: {str(e)}")
        
        return findings
    
    async def _test_excessive_data_exposure(self, endpoint: APIEndpoint, 
                                          session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """
        Test for Excessive Data Exposure where APIs return more data than needed
        
        Args:
            endpoint: API endpoint to test
            session: HTTP session
            
        Returns:
            List of data exposure findings
        """
        findings = []
        
        try:
            # Request endpoint to analyze response data
            async with session.request(endpoint.method, endpoint.url, timeout=10) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Check for sensitive data patterns in response
                    for data_type, pattern in self.sensitive_data_patterns.items():
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            # Sanitize evidence to avoid exposing sensitive data
                            evidence_sample = matches[0]
                            if len(evidence_sample) > 50:
                                evidence_sample = evidence_sample[:50] + '...'
                            
                            # Determine severity based on data type
                            severity = "high" if data_type in ['password', 'token', 'secret', 'api_key'] else "medium"
                            
                            finding = {
                                'id': f"data_exposure_{data_type}_{hashlib.md5(endpoint.url.encode()).hexdigest()[:8]}",
                                'type': "Excessive Data Exposure",
                                'severity': severity,
                                'location': endpoint.url,
                                'description': f"Sensitive {data_type} data exposed in response",
                                'evidence': f"Found {data_type} pattern: {html.escape(evidence_sample)}",
                                'confidence': 0.85,
                                'remediation': "Implement data filtering, return only necessary fields"
                            }
                            findings.append(finding)
                    
                    # Check for excessively large responses (potential data dump)
                    if len(content) > 100000:  # 100KB threshold
                        finding = {
                            'id': f"large_response_{hashlib.md5(endpoint.url.encode()).hexdigest()[:8]}",
                            'type': "Large Data Exposure",
                            'severity': "medium",
                            'location': endpoint.url,
                            'description': "Endpoint returns excessively large responses",
                            'evidence': f"Response size: {len(content)} bytes",
                            'confidence': 0.6,
                            'remediation': "Implement pagination, limit response size"
                        }
                        findings.append(finding)
        
        except Exception as e:
            print(f"Data exposure test error: {str(e)}")
        
        return findings
    
    async def _test_rate_limiting(self, endpoint: APIEndpoint, 
                                session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """
        Test for Lack of Resources & Rate Limiting vulnerabilities
        
        Args:
            endpoint: API endpoint to test
            session: HTTP session
            
        Returns:
            List of rate limiting findings
        """
        findings = []
        
        try:
            # Make multiple rapid requests to test rate limiting
            requests_count = 20
            successful_requests = 0
            
            for i in range(requests_count):
                try:
                    async with session.request(endpoint.method, endpoint.url, timeout=5) as response:
                        if response.status < 400:
                            successful_requests += 1
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    break  # Stop if requests start failing
            
            # If all requests succeeded, check for rate limiting indicators
            if successful_requests == requests_count:
                # Check response headers for rate limiting indicators
                async with session.request(endpoint.method, endpoint.url, timeout=10) as response:
                    headers = response.headers
                    
                    # Check for rate limiting headers
                    has_rate_limit_headers = any(
                        'rate' in h.lower() or 'limit' in h.lower() 
                        for h in headers.keys()
                    )
                    
                    # If no rate limiting headers found, report vulnerability
                    if not has_rate_limit_headers:
                        finding = {
                            'id': f"no_rate_limit_{hashlib.md5(endpoint.url.encode()).hexdigest()[:8]}",
                            'type': "Missing Rate Limiting",
                            'severity': "medium",
                            'location': endpoint.url,
                            'description': "No rate limiting detected on endpoint",
                            'evidence': f"{requests_count} rapid requests all succeeded",
                            'confidence': 0.7,
                            'remediation': "Implement rate limiting to prevent abuse"
                        }
                        findings.append(finding)
        
        except Exception as e:
            print(f"Rate limiting test error: {str(e)}")
        
        return findings
    
    async def _test_function_level_authorization(self, endpoint: APIEndpoint, 
                                               session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """
        Test for Broken Function Level Authorization where users can access
        privileged functions without proper authorization
        
        Args:
            endpoint: API endpoint to test
            session: HTTP session
            
        Returns:
            List of function authorization findings
        """
        findings = []
        
        try:
            # Identify privileged function patterns in URL
            privileged_patterns = [
                'admin', 'manage', 'delete', 'update', 'create',
                'reset', 'config', 'settings', 'user', 'role'
            ]
            
            url_lower = endpoint.url.lower()
            method = endpoint.method.upper()
            
            # Check if endpoint appears to be privileged and state-changing
            is_privileged = any(pattern in url_lower for pattern in privileged_patterns)
            is_state_changing = method in ['POST', 'PUT', 'DELETE', 'PATCH']
            
            # Test privileged state-changing endpoints without authentication
            if is_privileged and is_state_changing:
                async with session.request(method, endpoint.url, timeout=10) as response:
                    if response.status < 400:
                        finding = {
                            'id': f"bfla_{hashlib.md5(endpoint.url.encode()).hexdigest()[:8]}",
                            'type': "Broken Function Level Authorization",
                            'severity': "high",
                            'location': endpoint.url,
                            'description': "Privileged function accessible without proper authorization",
                            'evidence': f"{method} request to privileged endpoint succeeded with status {response.status}",
                            'confidence': 0.75,
                            'remediation': "Implement proper role-based access control"
                        }
                        findings.append(finding)
        
        except Exception as e:
            print(f"Function authorization test error: {str(e)}")
        
        return findings
    
    async def _test_mass_assignment(self, endpoint: APIEndpoint, 
                                  session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """
        Test for Mass Assignment vulnerabilities where users can set
        privileged fields they shouldn't have access to
        
        Args:
            endpoint: API endpoint to test
            session: HTTP session
            
        Returns:
            List of mass assignment findings
        """
        findings = []
        
        try:
            # Only test endpoints that accept JSON payloads (POST, PUT, PATCH)
            if endpoint.method in ['POST', 'PUT', 'PATCH']:
                # Test payloads with privileged fields
                test_payloads = [
                    {'admin': True, 'role': 'admin', 'is_admin': True},
                    {'privileged': True, 'access_level': 'admin'},
                    {'active': True, 'verified': True, 'email_verified': True}
                ]
                
                # Test each payload
                for payload in test_payloads:
                    try:
                        async with session.request(
                            endpoint.method, 
                            endpoint.url, 
                            json=payload,
                            timeout=10
                        ) as response:
                            
                            if response.status < 400:
                                content = await response.text()
                                
                                # Check if privileged fields were accepted/processed
                                for field in payload.keys():
                                    if field in content.lower():
                                        finding = {
                                            'id': f"mass_assign_{hashlib.md5(str(payload).encode()).hexdigest()[:8]}",
                                            'type': "Mass Assignment",
                                            'severity': "high",
                                            'location': endpoint.url,
                                            'description': "Privileged fields accepted in request",
                                            'evidence': f"Field '{field}' appears to have been processed",
                                            'confidence': 0.65,
                                            'remediation': "Use allowlists for accepted fields, implement proper validation"
                                        }
                                        findings.append(finding)
                                        break
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        continue
        
        except Exception as e:
            print(f"Mass assignment test error: {str(e)}")
        
        return findings
    
    async def _test_security_misconfiguration(self, endpoint: APIEndpoint, 
                                            session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """
        Test for Security Misconfiguration vulnerabilities including
        missing security headers and verbose error messages
        
        Args:
            endpoint: API endpoint to test
            session: HTTP session
            
        Returns:
            List of security misconfiguration findings
        """
        findings = []
        
        try:
            # Request endpoint to analyze headers and error messages
            async with session.request(endpoint.method, endpoint.url, timeout=10) as response:
                headers = response.headers
                
                # Check for missing security headers
                security_headers = [
                    'Content-Security-Policy',
                    'X-Frame-Options',
                    'X-Content-Type-Options',
                    'X-XSS-Protection',
                    'Strict-Transport-Security',
                    'Referrer-Policy'
                ]
                
                missing_headers = []
                for header in security_headers:
                    if header not in headers:
                        missing_headers.append(header)
                
                # Report missing security headers
                if missing_headers:
                    finding = {
                        'id': f"missing_headers_{hashlib.md5(endpoint.url.encode()).hexdigest()[:8]}",
                        'type': "Security Headers Missing",
                        'severity': "low",
                        'location': endpoint.url,
                        'description': f"Missing security headers: {', '.join(missing_headers[:3])}",
                        'evidence': f"Security headers not present in response",
                        'confidence': 1.0,
                        'remediation': "Add appropriate security headers to API responses"
                    }
                    findings.append(finding)
                
                # Check for verbose error messages in error responses
                if response.status >= 400:
                    content = await response.text()
                    error_indicators = [
                        'stack trace', 'exception', 'error at line',
                        'in /', 'traceback', 'mysql_', 'postgresql',
                        'microsoft', 'oracle', 'database'
                    ]
                    
                    # Check for sensitive error information
                    if any(indicator in content.lower() for indicator in error_indicators):
                        finding = {
                            'id': f"verbose_errors_{hashlib.md5(endpoint.url.encode()).hexdigest()[:8]}",
                            'type': "Verbose Error Messages",
                            'severity': "medium",
                            'location': endpoint.url,
                            'description': "Detailed error information exposed",
                            'evidence': "Error response contains stack trace or sensitive information",
                            'confidence': 0.8,
                            'remediation': "Disable detailed error messages in production"
                        }
                        findings.append(finding)
        
        except Exception as e:
            print(f"Security misconfiguration test error: {str(e)}")
        
        return findings
    
    async def _test_injection(self, endpoint: APIEndpoint, 
                            session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """
        Test for Injection vulnerabilities including SQL injection and NoSQL injection
        
        Args:
            endpoint: API endpoint to test
            session: HTTP session
            
        Returns:
            List of injection findings
        """
        findings = []
        
        try:
            # Test SQL injection in query parameters
            if endpoint.parameters:
                for param in endpoint.parameters[:2]:  # Test first 2 parameters
                    param_name = param.get('name', '')
                    param_location = param.get('in', 'query')
                    
                    # Test SQL injection in query parameters
                    if param_location == 'query':
                        parsed_url = urllib.parse.urlparse(endpoint.url)
                        query_params = urllib.parse.parse_qs(parsed_url.query)
                        
                        if param_name in query_params:
                            # Test with SQL injection payloads
                            sql_payloads = self.test_payloads['sqli'][:2]  # First 2 payloads
                            
                            for payload in sql_payloads:
                                test_params = query_params.copy()
                                test_params[param_name] = [payload]
                                test_query = urllib.parse.urlencode(test_params, doseq=True)
                                
                                # Reconstruct URL with injected parameter
                                test_url = urllib.parse.urlunparse((
                                    parsed_url.scheme,
                                    parsed_url.netloc,
                                    parsed_url.path,
                                    parsed_url.params,
                                    test_query,
                                    parsed_url.fragment
                                ))
                                
                                # Test the injection
                                async with session.request(endpoint.method, test_url, timeout=10) as response:
                                    content = await response.text()
                                    
                                    # Check for SQL error messages in response
                                    sql_errors = [
                                        'SQL syntax', 'mysql_fetch', 'ORA-',
                                        'PostgreSQL ERROR', 'SQLite3 error'
                                    ]
                                    
                                    if any(error in content for error in sql_errors):
                                        finding = {
                                            'id': f"sqli_api_{param_name}_{hashlib.md5(payload.encode()).hexdigest()[:8]}",
                                            'type': "SQL Injection",
                                            'severity': "critical",
                                            'location': f"Parameter: {param_name}",
                                            'description': "SQL injection vulnerability in API parameter",
                                            'evidence': f"SQL error with payload: {html.escape(payload[:50])}...",
                                            'confidence': 0.9,
                                            'remediation': "Use parameterized queries or prepared statements"
                                        }
                                        findings.append(finding)
                                        break
            
            # Test for NoSQL injection in JSON payloads
            if endpoint.method in ['POST', 'PUT', 'PATCH']:
                nosql_payloads = [
                    {'$ne': 1},
                    {'$where': '1==1'},
                    {'username': {'$ne': None}},
                    {'password': {'$regex': '.*'}}
                ]
                
                # Test first 2 NoSQL injection payloads
                for payload in nosql_payloads[:2]:
                    try:
                        async with session.request(
                            endpoint.method, 
                            endpoint.url, 
                            json=payload,
                            timeout=10
                        ) as response:
                            
                            if response.status < 400:
                                content = await response.text()
                                
                                # Check if payload bypassed authentication or validation
                                if 'success' in content.lower() or 'authenticated' in content.lower():
                                    finding = {
                                        'id': f"nosql_{hashlib.md5(str(payload).encode()).hexdigest()[:8]}",
                                        'type': "NoSQL Injection",
                                        'severity': "high",
                                        'location': endpoint.url,
                                        'description': "Potential NoSQL injection vulnerability",
                                        'evidence': f"Special MongoDB operator accepted: {list(payload.keys())[0]}",
                                        'confidence': 0.7,
                                        'remediation': "Validate and sanitize all input, use parameterized queries"
                                    }
                                    findings.append(finding)
                                    break
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        continue
        
        except Exception as e:
            print(f"Injection test error: {str(e)}")
        
        return findings
    
    async def _test_api_specific_vulnerabilities(self, base_url: str, 
                                               session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """
        Test for API-specific vulnerabilities based on detected API type
        
        Args:
            base_url: Base URL
            session: HTTP session
            
        Returns:
            List of API-specific findings
        """
        findings = []
        
        try:
            # Test for GraphQL-specific vulnerabilities if GraphQL detected
            if self.api_type == APIType.GRAPHQL:
                graphql_findings = await self._test_graphql_vulnerabilities(base_url, session)
                findings.extend(graphql_findings)
            
            # Test for batch operations vulnerabilities
            batch_findings = await self._test_batch_operations(base_url, session)
            findings.extend(batch_findings)
            
            # Test for improper assets management
            asset_findings = await self._test_improper_asset_management(base_url, session)
            findings.extend(asset_findings)
        
        except Exception as e:
            print(f"API-specific test error: {str(e)}")
        
        return findings
    
    async def _test_graphql_vulnerabilities(self, base_url: str, 
                                          session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """
        Test for GraphQL-specific vulnerabilities including introspection
        and deep query attacks
        
        Args:
            base_url: Base URL
            session: HTTP session
            
        Returns:
            List of GraphQL findings
        """
        findings = []
        
        try:
            # Find GraphQL endpoints
            graphql_endpoints = [ep for ep in self.discovered_endpoints 
                               if 'graphql' in ep.url.lower()]
            
            if not graphql_endpoints:
                return findings
            
            endpoint = graphql_endpoints[0]
            
            # Test 1: Introspection query (information disclosure)
            introspection_query = {
                'query': '''
                    query IntrospectionQuery {
                        __schema {
                            types {
                                name
                                kind
                                description
                                fields {
                                    name
                                    description
                                    args {
                                        name
                                        description
                                        type {
                                            name
                                            kind
                                            ofType {
                                                name
                                                kind
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                '''
            }
            
            try:
                async with session.post(
                    endpoint.url, 
                    json=introspection_query,
                    timeout=10
                ) as response:
                    
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check if introspection is enabled
                        if '__schema' in content and 'types' in content:
                            finding = {
                                'id': f"graphql_introspection_{hashlib.md5(endpoint.url.encode()).hexdigest()[:8]}",
                                'type': "GraphQL Introspection Enabled",
                                'severity': "medium",
                                'location': endpoint.url,
                                'description': "GraphQL introspection query enabled",
                                'evidence': "Introspection query returned schema information",
                                'confidence': 0.9,
                                'remediation': "Disable introspection in production"
                            }
                            findings.append(finding)
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass
            
            # Test 2: Query depth/complexity (DoS)
            deep_query = {
                'query': '''
                    query DeepQuery {
                        users {
                            posts {
                                comments {
                                    author {
                                        posts {
                                            comments {
                                                author {
                                                    name
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                '''
            }
            
            try:
                async with session.post(
                    endpoint.url, 
                    json=deep_query,
                    timeout=10
                ) as response:
                    
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check if deep query was processed without limits
                        if 'users' in content and 'posts' in content:
                            finding = {
                                'id': f"graphql_depth_{hashlib.md5(endpoint.url.encode()).hexdigest()[:8]}",
                                'type': "GraphQL Depth Limit Missing",
                                'severity': "medium",
                                'location': endpoint.url,
                                'description': "No query depth limiting detected",
                                'evidence': "Deep nested query processed successfully",
                                'confidence': 0.7,
                                'remediation': "Implement query depth and complexity limiting"
                            }
                            findings.append(finding)
            except asyncio.TimeoutError:
                # Timeout indicates potential DoS vulnerability
                finding = {
                    'id': f"graphql_dos_{hashlib.md5(endpoint.url.encode()).hexdigest()[:8]}",
                    'type': "GraphQL DoS Vulnerability",
                    'severity': "medium",
                    'location': endpoint.url,
                    'description': "Complex query causes timeout",
                    'evidence': "Deep query caused request timeout",
                    'confidence': 0.6,
                    'remediation': "Implement query cost analysis and limits"
                }
                findings.append(finding)
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass
        
        except Exception as e:
            print(f"GraphQL test error: {str(e)}")
        
        return findings
    
    async def _test_batch_operations(self, base_url: str, 
                                   session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """
        Test for batch operation vulnerabilities where multiple API calls
        can be made in a single request
        
        Args:
            base_url: Base URL
            session: HTTP session
            
        Returns:
            List of batch operation findings
        """
        findings = []
        
        try:
            # Look for batch operation endpoints
            batch_patterns = ['/batch', '/bulk', '/batch/']
            
            for pattern in batch_patterns:
                batch_url = urllib.parse.urljoin(base_url, pattern)
                
                try:
                    async with session.get(batch_url, timeout=10) as response:
                        if response.status < 400:
                            # Test batch operation with multiple requests
                            batch_payload = [
                                {'method': 'GET', 'url': '/api/users/1'},
                                {'method': 'GET', 'url': '/api/users/2'},
                                {'method': 'POST', 'url': '/api/users', 'body': {'username': 'test'}}
                            ]
                            
                            try:
                                async with session.post(batch_url, json=batch_payload, timeout=10) as batch_response:
                                    if batch_response.status == 200:
                                        finding = {
                                            'id': f"batch_operations_{hashlib.md5(batch_url.encode()).hexdigest()[:8]}",
                                            'type': "Batch Operations Enabled",
                                            'severity': "medium",
                                            'location': batch_url,
                                            'description': "Batch operations endpoint accessible",
                                            'evidence': "Batch request processed successfully",
                                            'confidence': 0.8,
                                            'remediation': "Secure batch operations, implement rate limiting"
                                        }
                                        findings.append(finding)
                            except (aiohttp.ClientError, asyncio.TimeoutError):
                                pass
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue
        
        except Exception as e:
            print(f"Batch operations test error: {str(e)}")
        
        return findings
    
    async def _test_improper_asset_management(self, base_url: str, 
                                            session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """
        Test for Improper Assets Management including exposed documentation
        and old API versions
        
        Args:
            base_url: Base URL
            session: HTTP session
            
        Returns:
            List of asset management findings
        """
        findings = []
        
        try:
            # Check for exposed API documentation
            doc_endpoints = [
                '/swagger-ui.html',
                '/api-docs',
                '/docs',
                '/redoc',
                '/explorer',
                '/graphiql',
                '/playground'
            ]
            
            for endpoint in doc_endpoints:
                doc_url = urllib.parse.urljoin(base_url, endpoint)
                
                try:
                    async with session.get(doc_url, timeout=10) as response:
                        if response.status < 400:
                            content = await response.text()
                            
                            # Check if it's actual documentation
                            if any(doc in content.lower() for doc in ['swagger', 'openapi', 'api', 'documentation']):
                                finding = {
                                    'id': f"exposed_docs_{hashlib.md5(doc_url.encode()).hexdigest()[:8]}",
                                    'type': "Exposed API Documentation",
                                    'severity': "low",
                                    'location': doc_url,
                                    'description': "API documentation exposed in production",
                                    'evidence': f"Documentation accessible at {doc_url}",
                                    'confidence': 0.9,
                                    'remediation': "Restrict access to API documentation in production"
                                }
                                findings.append(finding)
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue
            
            # Check for old API versions that should be deprecated
            version_patterns = ['/v1/', '/v2/', '/v3/', '/api/v1/', '/api/v2/']
            
            for pattern in version_patterns:
                version_url = urllib.parse.urljoin(base_url, pattern)
                
                try:
                    async with session.get(version_url, timeout=10) as response:
                        if response.status < 400:
                            finding = {
                                'id': f"old_api_version_{pattern.replace('/', '_')}_{hashlib.md5(version_url.encode()).hexdigest()[:8]}",
                                'type': "Old API Version Active",
                                'severity': "low",
                                'location': version_url,
                                'description': f"Old API version {pattern} still active",
                                'evidence': f"API version accessible at {version_url}",
                                'confidence': 0.8,
                                'remediation': "Deprecate old API versions, migrate users to current version"
                            }
                            findings.append(finding)
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue
        
        except Exception as e:
            print(f"Asset management test error: {str(e)}")
        
        return findings