"""
api_analyzer.py - API Security Analysis Module
Specialized analysis for REST APIs, GraphQL, and web services
"""

import json
import re
import hashlib
from typing import Dict, List, Any, Optional, Set
import aiohttp
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
import yaml

class APIType(Enum):
    """Types of APIs that can be analyzed"""
    REST = "rest"
    GRAPHQL = "graphql"
    SOAP = "soap"
    RPC = "rpc"
    WEBHOOK = "webhook"
    UNKNOWN = "unknown"

class APIVulnerability(Enum):
    """API-specific vulnerability types"""
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
    """Represents an API endpoint with metadata"""
    url: str
    method: str
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    request_headers: Dict[str, str] = field(default_factory=dict)
    response_headers: Dict[str, str] = field(default_factory=dict)
    status_code: int = 0
    response_time: float = 0.0
    response_size: int = 0
    content_type: str = ""
    requires_auth: bool = False
    rate_limited: bool = False
    description: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
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
    Specialized analyzer for API security testing
    Focuses on OWASP API Security Top 10 vulnerabilities
    """
    
    def __init__(self):
        """Initialize API analyzer with detection rules and patterns"""
        self.api_patterns = self._load_api_patterns()
        self.auth_patterns = self._load_auth_patterns()
        self.rate_limit_patterns = self._load_rate_limit_patterns()
        self.sensitive_data_patterns = self._load_sensitive_data_patterns()
        
        # State tracking
        self.discovered_endpoints: List[APIEndpoint] = []
        self.api_type: APIType = APIType.UNKNOWN
        self.auth_scheme: Optional[str] = None
        
        # Test configurations
        self.test_payloads = self._load_test_payloads()
    
    def _load_api_patterns(self) -> Dict[str, List[str]]:
        """
        Load patterns for identifying and analyzing APIs
        
        Returns:
            Dictionary of API patterns
        """
        return {
            'rest': [
                r'/api/v[0-9]+/',
                r'/rest/',
                r'/v[0-9]/',
                r'\.(json|xml)$',
                r'Content-Type: application/json',
                r'Content-Type: application/xml'
            ],
            'graphql': [
                r'/graphql',
                r'/graphiql',
                r'query\s*{',
                r'mutation\s*{',
                r'__typename',
                r'Content-Type: application/graphql'
            ],
            'soap': [
                r'SOAPAction',
                r'<soap:',
                r'<s:',
                r'xmlns:soap=',
                r'Content-Type: text/xml'
            ],
            'swagger': [
                r'/swagger',
                r'/swagger-ui',
                r'/api-docs',
                r'swagger\.json',
                r'swagger\.yaml',
                r'OpenAPI'
            ]
        }
    
    def _load_auth_patterns(self) -> Dict[str, List[str]]:
        """
        Load authentication scheme patterns
        
        Returns:
            Dictionary of authentication patterns
        """
        return {
            'jwt': [
                r'Authorization: Bearer eyJ',
                r'\.(eyJ[A-Za-z0-9-_]+\.){2}[A-Za-z0-9-_]*',
                r'alg:\s*["\'](HS256|RS256)["\']'
            ],
            'basic': [
                r'Authorization: Basic [A-Za-z0-9+/=]+',
                r'WWW-Authenticate: Basic'
            ],
            'oauth': [
                r'oauth_',
                r'access_token=',
                r'Authorization: Bearer [a-f0-9]{32,}',
                r'/oauth/'
            ],
            'api_key': [
                r'api_key=',
                r'apikey=',
                r'X-API-Key:',
                r'Authorization: ApiKey'
            ]
        }
    
    def _load_rate_limit_patterns(self) -> Dict[str, List[str]]:
        """
        Load rate limiting indicator patterns
        
        Returns:
            Dictionary of rate limit patterns
        """
        return {
            'headers': [
                r'X-RateLimit-Limit',
                r'X-RateLimit-Remaining',
                r'X-RateLimit-Reset',
                r'Retry-After',
                r'RateLimit-Limit'
            ],
            'responses': [
                r'429 Too Many Requests',
                r'Rate limit exceeded',
                r'Too many requests',
                r'Quota exceeded'
            ]
        }
    
    def _load_sensitive_data_patterns(self) -> Dict[str, str]:
        """
        Load patterns for sensitive data in API responses
        
        Returns:
            Dictionary of sensitive data patterns
        """
        return {
            'password': r'["\']?password["\']?\s*:\s*["\'][^"\']+["\']',
            'token': r'["\']?(access_|refresh_)?token["\']?\s*:\s*["\'][^"\']+["\']',
            'secret': r'["\']?secret["\']?\s*:\s*["\'][^"\']+["\']',
            'api_key': r'["\']?api[_-]?key["\']?\s*:\s*["\'][^"\']+["\']',
            'private_key': r'-----BEGIN (RSA|DSA|EC|PRIVATE) KEY-----',
            'credit_card': r'\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}',
            'ssn': r'\d{3}-\d{2}-\d{4}',
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        }
    
    def _load_test_payloads(self) -> Dict[str, List[str]]:
        """
        Load test payloads for API security testing
        
        Returns:
            Dictionary of test payloads by vulnerability type
        """
        return {
            'idor': ['1', '0', '-1', '999999', 'admin', 'test'],
            'sqli': ["' OR '1'='1", "' UNION SELECT NULL--", "' AND SLEEP(5)--"],
            'xss': ['<script>alert(1)</script>', '" onmouseover="alert(1)'],
            'command': ['; ls', '| cat /etc/passwd', '`id`'],
            'path_traversal': ['../../../etc/passwd', '..\\..\\windows\\win.ini'],
            'mass_assignment': ['{"admin": true}', '{"role": "admin"}'],
            'json_injection': ['{"$ne": 1}', '{"$where": "1==1"}'],
            'jwt_tampering': ['none', 'HS256', 'RS256', 'none', 'undefined']
        }
    
    async def analyze_apis(self, base_url: str, session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """
        Main entry point for API security analysis
        
        Args:
            base_url: Base URL to scan for APIs
            session: HTTP session for making requests
            
        Returns:
            List of API security findings
        """
        findings = []
        
        try:
            print(f"  🔍 Analyzing APIs on {base_url}")
            
            # Phase 1: Discover API endpoints
            print(f"    📡 Discovering API endpoints...")
            await self._discover_endpoints(base_url, session)
            
            if not self.discovered_endpoints:
                print(f"    ℹ️ No API endpoints discovered")
                return findings
            
            print(f"    ✅ Discovered {len(self.discovered_endpoints)} API endpoints")
            
            # Phase 2: Identify API type and authentication
            print(f"    🔑 Analyzing authentication...")
            await self._analyze_authentication(session)
            
            # Phase 3: Test each endpoint for vulnerabilities
            print(f"    🧪 Testing endpoints for vulnerabilities...")
            for endpoint in self.discovered_endpoints:
                endpoint_findings = await self._test_endpoint(endpoint, session)
                findings.extend(endpoint_findings)
            
            # Phase 4: Test for API-specific vulnerabilities
            print(f"    🎯 Testing API-specific vulnerabilities...")
            api_specific_findings = await self._test_api_specific_vulnerabilities(base_url, session)
            findings.extend(api_specific_findings)
            
            print(f"    ✅ API analysis completed: {len(findings)} findings")
            
            return findings
            
        except Exception as e:
            print(f"    ⚠️ API analysis error: {str(e)}")
            return findings
    
    async def _discover_endpoints(self, base_url: str, session: aiohttp.ClientSession):
        """
        Discover API endpoints through various techniques
        
        Args:
            base_url: Base URL to scan
            session: HTTP session for making requests
        """
        discovered_urls = set()
        
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
        
        for path in common_api_paths:
            test_url = urllib.parse.urljoin(base_url, path)
            try:
                async with session.get(test_url) as response:
                    if response.status < 400:
                        await self._analyze_response_for_endpoints(test_url, 'GET', response)
                        discovered_urls.add(test_url)
            except:
                pass
        
        # Technique 2: Look for API references in JavaScript files
        js_endpoints = await self._find_js_api_references(base_url, session)
        for endpoint in js_endpoints:
            if endpoint not in discovered_urls:
                discovered_urls.add(endpoint)
                # Test the endpoint
                try:
                    async with session.get(endpoint) as response:
                        await self._analyze_response_for_endpoints(endpoint, 'GET', response)
                except:
                    pass
        
        # Technique 3: Check robots.txt and sitemap.xml
        robots_url = urllib.parse.urljoin(base_url, '/robots.txt')
        try:
            async with session.get(robots_url) as response:
                if response.status == 200:
                    content = await response.text()
                    # Look for API paths in robots.txt
                    for line in content.split('\n'):
                        if 'api' in line.lower() or 'rest' in line.lower():
                            path = line.split(':')[1].strip() if ':' in line else line.strip()
                            if path.startswith('/'):
                                api_url = urllib.parse.urljoin(base_url, path)
                                if api_url not in discovered_urls:
                                    discovered_urls.add(api_url)
                                    try:
                                        async with session.get(api_url) as api_response:
                                            await self._analyze_response_for_endpoints(api_url, 'GET', api_response)
                                    except:
                                        pass
        except:
            pass
        
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
                async with session.get(swagger_url) as response:
                    if response.status == 200:
                        content_type = response.headers.get('Content-Type', '')
                        if 'json' in content_type or 'yaml' in content_type:
                            content = await response.text()
                            swagger_endpoints = await self._parse_swagger_docs(swagger_url, content, session)
                            for endpoint in swagger_endpoints:
                                if endpoint.url not in discovered_urls:
                                    self.discovered_endpoints.append(endpoint)
                                    discovered_urls.add(endpoint.url)
            except:
                pass
    
    async def _analyze_response_for_endpoints(self, url: str, method: str, response: aiohttp.ClientResponse):
        """
        Analyze HTTP response for API endpoint information
        
        Args:
            url: Request URL
            method: HTTP method used
            response: HTTP response object
        """
        try:
            content_type = response.headers.get('Content-Type', '')
            content = await response.text()
            
            # Check if this looks like an API response
            is_api_response = False
            
            # Check content type
            if any(api_type in content_type for api_type in ['json', 'xml', 'graphql']):
                is_api_response = True
            
            # Check content patterns
            if ('{' in content and '}' in content) or ('<' in content and '>' in content):
                is_api_response = True
            
            # Check for API indicators in response
            api_indicators = ['api', 'rest', 'graphql', 'endpoint', 'resource', 'collection']
            if any(indicator in content.lower() for indicator in api_indicators):
                is_api_response = True
            
            if is_api_response:
                endpoint = APIEndpoint(
                    url=url,
                    method=method,
                    response_headers=dict(response.headers),
                    status_code=response.status,
                    content_type=content_type,
                    response_size=len(content.encode('utf-8'))
                )
                
                # Try to determine if authentication is required
                if response.status == 401 or response.status == 403:
                    endpoint.requires_auth = True
                
                # Check for rate limiting headers
                rate_limit_headers = [h for h in response.headers.keys() 
                                    if 'rate' in h.lower() or 'limit' in h.lower()]
                if rate_limit_headers:
                    endpoint.rate_limited = True
                
                # Try to parse parameters from URL
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
                
                # Determine API type
                await self._determine_api_type(content, content_type)
        
        except Exception as e:
            print(f"      ⚠️ Error analyzing response: {str(e)}")
    
    async def _find_js_api_references(self, base_url: str, 
                                     session: aiohttp.ClientSession) -> Set[str]:
        """
        Find API endpoint references in JavaScript files
        
        Args:
            base_url: Base URL to scan
            session: HTTP session
            
        Returns:
            Set of discovered API URLs
        """
        api_urls = set()
        
        try:
            # First, get the main page to find JS files
            async with session.get(base_url) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Find all script tags
                    import re
                    script_pattern = r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>'
                    script_matches = re.findall(script_pattern, content, re.IGNORECASE)
                    
                    for script_src in script_matches:
                        script_url = urllib.parse.urljoin(base_url, script_src)
                        
                        # Only process local JS files
                        if base_url in script_url:
                            try:
                                async with session.get(script_url) as js_response:
                                    if js_response.status == 200:
                                        js_content = await js_response.text()
                                        
                                        # Look for API URL patterns in JS
                                        url_patterns = [
                                            r'["\'](/api/[^"\']+)["\']',
                                            r'["\'](/rest/[^"\']+)["\']',
                                            r'["\'](/v[0-9]/[^"\']+)["\']',
                                            r'["\'](https?://[^"\']+/api/[^"\']+)["\']',
                                            r'fetch\(["\']([^"\']+)["\']',
                                            r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']',
                                            r'\.ajax\([^)]*url:\s*["\']([^"\']+)["\']'
                                        ]
                                        
                                        for pattern in url_patterns:
                                            matches = re.findall(pattern, js_content, re.IGNORECASE)
                                            for match in matches:
                                                if isinstance(match, tuple):
                                                    match = match[-1]  # Get the URL from tuple
                                                
                                                # Convert to absolute URL
                                                if match.startswith('/'):
                                                    api_url = urllib.parse.urljoin(base_url, match)
                                                elif match.startswith('http'):
                                                    api_url = match
                                                else:
                                                    api_url = urllib.parse.urljoin(base_url, '/' + match)
                                                
                                                if base_url in api_url:  # Only include same-domain APIs
                                                    api_urls.add(api_url)
                            except:
                                pass
        
        except Exception as e:
            print(f"      ⚠️ JS analysis error: {str(e)}")
        
        return api_urls
    
    async def _parse_swagger_docs(self, swagger_url: str, content: str, 
                                 session: aiohttp.ClientSession) -> List[APIEndpoint]:
        """
        Parse Swagger/OpenAPI documentation to discover endpoints
        
        Args:
            swagger_url: URL of Swagger docs
            content: Documentation content
            session: HTTP session
            
        Returns:
            List of discovered API endpoints
        """
        endpoints = []
        
        try:
            # Parse JSON or YAML
            if swagger_url.endswith('.json') or 'application/json' in swagger_url:
                try:
                    spec = json.loads(content)
                except:
                    return endpoints
            elif swagger_url.endswith(('.yaml', '.yml')) or 'application/yaml' in swagger_url:
                try:
                    spec = yaml.safe_load(content)
                except:
                    return endpoints
            else:
                return endpoints
            
            # Get base URL from spec
            base_path = spec.get('basePath', '')
            if not base_path and 'servers' in spec:
                servers = spec.get('servers', [])
                if servers and 'url' in servers[0]:
                    base_path = servers[0]['url']
            
            # If no base path in spec, use the directory of swagger URL
            if not base_path:
                parsed_url = urllib.parse.urlparse(swagger_url)
                base_path = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            # Parse paths
            paths = spec.get('paths', {})
            for path, methods in paths.items():
                for method, details in methods.items():
                    if method.lower() in ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']:
                        # Construct full URL
                        if base_path.endswith('/') and path.startswith('/'):
                            full_url = base_path + path[1:]
                        elif not base_path.endswith('/') and not path.startswith('/'):
                            full_url = base_path + '/' + path
                        else:
                            full_url = base_path + path
                        
                        endpoint = APIEndpoint(
                            url=full_url,
                            method=method.upper(),
                            description=details.get('summary', details.get('description', ''))
                        )
                        
                        # Parse parameters
                        parameters = details.get('parameters', [])
                        for param in parameters:
                            param_info = {
                                'name': param.get('name', ''),
                                'in': param.get('in', ''),
                                'required': param.get('required', False),
                                'type': param.get('type', param.get('schema', {}).get('type', ''))
                            }
                            endpoint.parameters.append(param_info)
                        
                        endpoints.append(endpoint)
        
        except Exception as e:
            print(f"      ⚠️ Swagger parsing error: {str(e)}")
        
        return endpoints
    
    async def _determine_api_type(self, content: str, content_type: str):
        """
        Determine the type of API based on response content
        
        Args:
            content: Response content
            content_type: Content-Type header
        """
        content_lower = content.lower()
        
        # Check for GraphQL
        if 'graphql' in content_lower or '__typename' in content_lower:
            self.api_type = APIType.GRAPHQL
        # Check for SOAP
        elif 'soap' in content_lower or '<soap:' in content_lower:
            self.api_type = APIType.SOAP
        # Check for JSON-RPC
        elif ('jsonrpc' in content_lower or 'method' in content_lower) and 'params' in content_lower:
            self.api_type = APIType.RPC
        # Default to REST
        elif 'application/json' in content_type or ('{' in content and '}' in content):
            self.api_type = APIType.REST
        else:
            self.api_type = APIType.UNKNOWN
    
    async def _analyze_authentication(self, session: aiohttp.ClientSession):
        """
        Analyze authentication schemes used by the API
        
        Args:
            session: HTTP session for testing
        """
        if not self.discovered_endpoints:
            return
        
        # Test endpoints that require auth
        auth_endpoints = [ep for ep in self.discovered_endpoints if ep.requires_auth]
        
        for endpoint in auth_endpoints[:3]:  # Test first 3 auth endpoints
            try:
                # Test without authentication
                async with session.request(endpoint.method, endpoint.url) as response:
                    if response.status == 401:
                        auth_header = response.headers.get('WWW-Authenticate', '')
                        
                        # Check authentication scheme
                        for scheme, patterns in self.auth_patterns.items():
                            for pattern in patterns:
                                if re.search(pattern, auth_header, re.IGNORECASE):
                                    self.auth_scheme = scheme
                                    print(f"      🔐 Detected {scheme.upper()} authentication")
                                    return
            except:
                pass
        
        # If no auth header, check for API key patterns
        for endpoint in self.discovered_endpoints:
            if any(key in endpoint.url.lower() for key in ['api_key', 'apikey', 'token']):
                self.auth_scheme = 'api_key'
                print(f"      🔐 Detected API key authentication")
                return
    
    async def _test_endpoint(self, endpoint: APIEndpoint, 
                           session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """
        Test a single API endpoint for vulnerabilities
        
        Args:
            endpoint: API endpoint to test
            session: HTTP session
            
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        try:
            print(f"      Testing {endpoint.method} {endpoint.url}")
            
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
            print(f"      ⚠️ Endpoint test error: {str(e)}")
        
        return findings
    
    async def _test_broken_object_authorization(self, endpoint: APIEndpoint, 
                                              session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """
        Test for Broken Object Level Authorization (BOLA/IDOR)
        
        Args:
            endpoint: API endpoint to test
            session: HTTP session
            
        Returns:
            List of BOLA findings
        """
        findings = []
        
        try:
            # Look for object IDs in URL
            url = endpoint.url
            
            # Pattern for common object ID formats
            id_patterns = [
                r'/(\d+)/?$',           # /users/123
                r'/(\d+)/[^/]+/?$',     # /users/123/profile
                r'id=(\d+)',            # ?id=123
                r'userId=(\d+)',        # ?userId=123
                r'user_id=(\d+)',       # ?user_id=123
            ]
            
            for pattern in id_patterns:
                match = re.search(pattern, url)
                if match:
                    object_id = match.group(1)
                    
                    if object_id.isdigit():
                        # Test with different IDs
                        test_ids = ['1', '0', '999999', str(int(object_id) + 1), str(int(object_id) - 1)]
                        
                        for test_id in test_ids:
                            test_url = url.replace(object_id, test_id)
                            
                            # Make request with test ID
                            async with session.request(endpoint.method, test_url) as response:
                                if response.status == 200:
                                    # Check if we got similar data (potential IDOR)
                                    content = await response.text()
                                    
                                    # Simple heuristic: similar structure to original
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
            print(f"        ⚠️ BOLA test error: {str(e)}")
        
        return findings
    
    async def _test_broken_authentication(self, endpoint: APIEndpoint, 
                                        session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """
        Test for Broken User Authentication
        
        Args:
            endpoint: API endpoint to test
            session: HTTP session
            
        Returns:
            List of authentication findings
        """
        findings = []
        
        try:
            # Test 1: Check if sensitive endpoints don't require authentication
            sensitive_patterns = [
                'admin', 'user', 'account', 'profile', 'settings',
                'password', 'token', 'secret', 'config', 'database'
            ]
            
            url_lower = endpoint.url.lower()
            is_sensitive = any(pattern in url_lower for pattern in sensitive_patterns)
            
            if is_sensitive and not endpoint.requires_auth:
                # Make request to check if it's actually accessible
                async with session.request(endpoint.method, endpoint.url) as response:
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
            
            # Test 2: Check for default/weak credentials (simplified)
            if 'login' in url_lower or 'auth' in url_lower:
                common_credentials = [
                    ('admin', 'admin'),
                    ('admin', 'password'),
                    ('root', 'root'),
                    ('test', 'test'),
                    ('user', 'user')
                ]
                
                for username, password in common_credentials[:2]:  # Test first 2
                    auth_data = {'username': username, 'password': password}
                    
                    try:
                        async with session.post(endpoint.url, json=auth_data) as response:
                            if response.status == 200:
                                content = await response.text()
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
                    except:
                        continue
        
        except Exception as e:
            print(f"        ⚠️ Authentication test error: {str(e)}")
        
        return findings
    
    async def _test_excessive_data_exposure(self, endpoint: APIEndpoint, 
                                          session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """
        Test for Excessive Data Exposure
        
        Args:
            endpoint: API endpoint to test
            session: HTTP session
            
        Returns:
            List of data exposure findings
        """
        findings = []
        
        try:
            # Make request to endpoint
            async with session.request(endpoint.method, endpoint.url) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Check for sensitive data patterns
                    for data_type, pattern in self.sensitive_data_patterns.items():
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            # Don't show actual sensitive data
                            evidence_sample = matches[0][:50] + '...' if len(matches[0]) > 50 else matches[0]
                            
                            finding = {
                                'id': f"data_exposure_{data_type}_{hashlib.md5(endpoint.url.encode()).hexdigest()[:8]}",
                                'type': "Excessive Data Exposure",
                                'severity': "high" if data_type in ['password', 'token', 'secret', 'api_key'] else "medium",
                                'location': endpoint.url,
                                'description': f"Sensitive {data_type} data exposed in response",
                                'evidence': f"Found {data_type} pattern: {html.escape(evidence_sample)}",
                                'confidence': 0.85,
                                'remediation': "Implement data filtering, return only necessary fields"
                            }
                            findings.append(finding)
                    
                    # Check for large response size (potential data dump)
                    if len(content) > 100000:  # 100KB
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
            print(f"        ⚠️ Data exposure test error: {str(e)}")
        
        return findings
    
    async def _test_rate_limiting(self, endpoint: APIEndpoint, 
                                session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """
        Test for Lack of Resources & Rate Limiting
        
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
                except:
                    break
            
            # If all requests succeeded, potential lack of rate limiting
            if successful_requests == requests_count:
                # Check response headers for rate limiting indicators
                async with session.request(endpoint.method, endpoint.url) as response:
                    headers = response.headers
                    
                    has_rate_limit_headers = any(
                        'rate' in h.lower() or 'limit' in h.lower() 
                        for h in headers.keys()
                    )
                    
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
            print(f"        ⚠️ Rate limiting test error: {str(e)}")
        
        return findings
    
    async def _test_function_level_authorization(self, endpoint: APIEndpoint, 
                                               session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """
        Test for Broken Function Level Authorization
        
        Args:
            endpoint: API endpoint to test
            session: HTTP session
            
        Returns:
            List of function authorization findings
        """
        findings = []
        
        try:
            # Test for admin/privileged functions accessible without admin rights
            privileged_patterns = [
                'admin', 'manage', 'delete', 'update', 'create',
                'reset', 'config', 'settings', 'user', 'role'
            ]
            
            url_lower = endpoint.url.lower()
            method = endpoint.method.upper()
            
            # Check if this looks like a privileged function
            is_privileged = any(pattern in url_lower for pattern in privileged_patterns)
            is_state_changing = method in ['POST', 'PUT', 'DELETE', 'PATCH']
            
            if is_privileged and is_state_changing:
                # Try to access without admin authentication
                async with session.request(method, endpoint.url) as response:
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
            print(f"        ⚠️ Function authorization test error: {str(e)}")
        
        return findings
    
    async def _test_mass_assignment(self, endpoint: APIEndpoint, 
                                  session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """
        Test for Mass Assignment vulnerabilities
        
        Args:
            endpoint: API endpoint to test
            session: HTTP session
            
        Returns:
            List of mass assignment findings
        """
        findings = []
        
        try:
            # Only test POST/PUT/PATCH endpoints that likely accept JSON
            if endpoint.method in ['POST', 'PUT', 'PATCH']:
                # Try to add privileged fields to request
                test_payloads = [
                    {'admin': True, 'role': 'admin', 'is_admin': True},
                    {'privileged': True, 'access_level': 'admin'},
                    {'active': True, 'verified': True, 'email_verified': True}
                ]
                
                for payload in test_payloads:
                    try:
                        async with session.request(
                            endpoint.method, 
                            endpoint.url, 
                            json=payload
                        ) as response:
                            
                            if response.status < 400:
                                # Check if privileged fields were accepted
                                content = await response.text()
                                
                                # Look for indications that fields were processed
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
                    except:
                        continue
        
        except Exception as e:
            print(f"        ⚠️ Mass assignment test error: {str(e)}")
        
        return findings
    
    async def _test_security_misconfiguration(self, endpoint: APIEndpoint, 
                                            session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """
        Test for Security Misconfiguration
        
        Args:
            endpoint: API endpoint to test
            session: HTTP session
            
        Returns:
            List of security misconfiguration findings
        """
        findings = []
        
        try:
            # Make request to check for misconfigurations
            async with session.request(endpoint.method, endpoint.url) as response:
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
                
                # Check for verbose error messages
                if response.status >= 400:
                    content = await response.text()
                    error_indicators = [
                        'stack trace', 'exception', 'error at line',
                        'in /', 'traceback', 'mysql_', 'postgresql',
                        'microsoft', 'oracle', 'database'
                    ]
                    
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
            print(f"        ⚠️ Security misconfiguration test error: {str(e)}")
        
        return findings
    
    async def _test_injection(self, endpoint: APIEndpoint, 
                            session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """
        Test for Injection vulnerabilities
        
        Args:
            endpoint: API endpoint to test
            session: HTTP session
            
        Returns:
            List of injection findings
        """
        findings = []
        
        try:
            # Test SQL injection in parameters
            if endpoint.parameters:
                for param in endpoint.parameters[:2]:  # Test first 2 parameters
                    param_name = param.get('name', '')
                    param_location = param.get('in', 'query')
                    
                    if param_location == 'query':
                        # Build test URL with SQL injection payload
                        parsed_url = urllib.parse.urlparse(endpoint.url)
                        query_params = urllib.parse.parse_qs(parsed_url.query)
                        
                        if param_name in query_params:
                            # Test with SQL injection payloads
                            sql_payloads = self.test_payloads['sqli'][:2]  # First 2 payloads
                            
                            for payload in sql_payloads:
                                test_params = query_params.copy()
                                test_params[param_name] = [payload]
                                test_query = urllib.parse.urlencode(test_params, doseq=True)
                                
                                test_url = urllib.parse.urlunparse((
                                    parsed_url.scheme,
                                    parsed_url.netloc,
                                    parsed_url.path,
                                    parsed_url.params,
                                    test_query,
                                    parsed_url.fragment
                                ))
                                
                                async with session.request(endpoint.method, test_url) as response:
                                    content = await response.text()
                                    
                                    # Check for SQL errors
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
            
            # Test for NoSQL injection (if API accepts JSON)
            if endpoint.method in ['POST', 'PUT', 'PATCH']:
                nosql_payloads = [
                    {'$ne': 1},
                    {'$where': '1==1'},
                    {'username': {'$ne': null}},
                    {'password': {'$regex': '.*'}}
                ]
                
                for payload in nosql_payloads[:2]:  # First 2 payloads
                    try:
                        async with session.request(
                            endpoint.method, 
                            endpoint.url, 
                            json=payload
                        ) as response:
                            
                            if response.status < 400:
                                content = await response.text()
                                
                                # Check if payload bypassed something
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
                    except:
                        continue
        
        except Exception as e:
            print(f"        ⚠️ Injection test error: {str(e)}")
        
        return findings
    
    async def _test_api_specific_vulnerabilities(self, base_url: str, 
                                               session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """
        Test for API-specific vulnerabilities
        
        Args:
            base_url: Base URL
            session: HTTP session
            
        Returns:
            List of API-specific findings
        """
        findings = []
        
        try:
            # Test for GraphQL-specific vulnerabilities
            if self.api_type == APIType.GRAPHQL:
                graphql_findings = await self._test_graphql_vulnerabilities(base_url, session)
                findings.extend(graphql_findings)
            
            # Test for batch operations/request smuggling
            batch_findings = await self._test_batch_operations(base_url, session)
            findings.extend(batch_findings)
            
            # Test for improper assets management
            asset_findings = await self._test_improper_asset_management(base_url, session)
            findings.extend(asset_findings)
        
        except Exception as e:
            print(f"      ⚠️ API-specific test error: {str(e)}")
        
        return findings
    
    async def _test_graphql_vulnerabilities(self, base_url: str, 
                                          session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """
        Test for GraphQL-specific vulnerabilities
        
        Args:
            base_url: Base URL
            session: HTTP session
            
        Returns:
            List of GraphQL findings
        """
        findings = []
        
        try:
            # Find GraphQL endpoint
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
                    json=introspection_query
                ) as response:
                    
                    if response.status == 200:
                        content = await response.text()
                        
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
            except:
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
                        
                        # Check if deep query was processed
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
            except:
                pass
        
        except Exception as e:
            print(f"        ⚠️ GraphQL test error: {str(e)}")
        
        return findings
    
    async def _test_batch_operations(self, base_url: str, 
                                   session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """
        Test for batch operation vulnerabilities
        
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
                    async with session.get(batch_url) as response:
                        if response.status < 400:
                            # Test batch operation with multiple requests
                            batch_payload = [
                                {'method': 'GET', 'url': '/api/users/1'},
                                {'method': 'GET', 'url': '/api/users/2'},
                                {'method': 'POST', 'url': '/api/users', 'body': {'username': 'test'}}
                            ]
                            
                            try:
                                async with session.post(batch_url, json=batch_payload) as batch_response:
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
                            except:
                                pass
                except:
                    continue
        
        except Exception as e:
            print(f"        ⚠️ Batch operations test error: {str(e)}")
        
        return findings
    
    async def _test_improper_asset_management(self, base_url: str, 
                                            session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """
        Test for Improper Assets Management
        
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
                    async with session.get(doc_url) as response:
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
                except:
                    continue
            
            # Check for old API versions
            version_patterns = ['/v1/', '/v2/', '/v3/', '/api/v1/', '/api/v2/']
            
            for pattern in version_patterns:
                version_url = urllib.parse.urljoin(base_url, pattern)
                
                try:
                    async with session.get(version_url) as response:
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
                except:
                    continue
        
        except Exception as e:
            print(f"        ⚠️ Asset management test error: {str(e)}")
        
        return findings