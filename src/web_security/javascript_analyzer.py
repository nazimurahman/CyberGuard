# src/web_security/javascript_analyzer.py
"""
JavaScript Security Analyzer for CyberGuard
Analyzes client-side JavaScript for security vulnerabilities and malicious code
Features: AST parsing, vulnerability detection, obfuscation analysis, dependency scanning
"""

import re
import ast
import json
import hashlib
import base64
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass
import warnings
import html

@dataclass
class JavaScriptAnalysis:
    """Comprehensive JavaScript analysis results"""
    file_hash: str                     # MD5 hash of JavaScript content
    file_size: int                     # Size in bytes
    line_count: int                    # Number of lines
    char_count: int                    # Number of characters
    vulnerabilities: List[Dict[str, Any]]  # Detected vulnerabilities
    suspicious_patterns: List[Dict[str, Any]]  # Suspicious code patterns
    external_resources: List[str]      # External scripts, images, etc.
    dom_manipulations: List[Dict[str, Any]]  # DOM manipulation functions
    event_listeners: List[Dict[str, Any]]    # Event listeners attached
    encoded_strings: List[Dict[str, Any]]    # Encoded/obfuscated strings
    api_calls: List[Dict[str, Any]]          # API calls made
    cookies_accessed: List[str]        # Cookies accessed
    localStorage_usage: List[Dict[str, Any]] # localStorage/sessionStorage usage
    eval_calls: List[Dict[str, Any]]         # eval() and similar function calls
    security_score: float              # Overall security score (0.0 to 1.0)
    obfuscation_score: float           # Obfuscation detection score (0.0 to 1.0)

class JavaScriptAnalyzer:
    """
    Advanced JavaScript security analyzer
    Detects: XSS vulnerabilities, data exfiltration, obfuscated code, malicious patterns
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize JavaScript analyzer with configuration
        
        Args:
            config: Configuration dictionary containing analysis rules
        """
        self.config = config
        
        # Dangerous JavaScript functions/patterns
        self.dangerous_functions = {
            'eval': 'CRITICAL',
            'Function': 'CRITICAL',
            'setTimeout with string': 'HIGH',
            'setInterval with string': 'HIGH',
            'execScript': 'CRITICAL',
            'document.write': 'MEDIUM',
            'innerHTML': 'MEDIUM',
            'outerHTML': 'MEDIUM',
            'insertAdjacentHTML': 'MEDIUM',
            'createContextualFragment': 'MEDIUM',
        }
        
        # XSS sink functions (places where untrusted data can become code)
        self.xss_sinks = [
            'innerHTML', 'outerHTML', 'insertAdjacentHTML',
            'document.write', 'document.writeln',
            'eval', 'setTimeout', 'setInterval',
            'location.assign', 'location.replace',
            'window.open', 'window.navigate',
            'element.setAttribute', 'element.src',
            'element.href', 'element.action',
        ]
        
        # Data exfiltration patterns
        self.exfiltration_patterns = [
            ('XMLHttpRequest', 'NETWORK_EXFILTRATION'),
            ('fetch', 'NETWORK_EXFILTRATION'),
            ('WebSocket', 'NETWORK_EXFILTRATION'),
            ('navigator.sendBeacon', 'NETWORK_EXFILTRATION'),
            ('Image().src', 'DATA_EXFILTRATION'),
            ('new Audio().src', 'DATA_EXFILTRATION'),
            ('document.cookie', 'COOKIE_ACCESS'),
            ('localStorage', 'STORAGE_ACCESS'),
            ('sessionStorage', 'STORAGE_ACCESS'),
            ('navigator.clipboard', 'CLIPBOARD_ACCESS'),
            ('document.execCommand("copy")', 'CLIPBOARD_ACCESS'),
        ]
        
        # Obfuscation detection patterns
        self.obfuscation_patterns = [
            (r'eval\(.*atob\(', 'BASE64_EVAL'),           # eval(atob(...))
            (r'String\.fromCharCode\(', 'CHARCODE_OBFUSCATION'),
            (r'\\x[0-9a-fA-F]{2}', 'HEX_ESCAPE'),
            (r'\\u[0-9a-fA-F]{4}', 'UNICODE_ESCAPE'),
            (r'\[][+\-*/%&|^]', 'ARRAY_OBFUSCATION'),     # []+!+[]
            (r'\(!\[\]\+\[\]\)', 'BOOLEAN_OBFUSCATION'),  # (![]+[])
            (r'window\[', 'WINDOW_INDEXING'),             # window['alert']
            (r'document\[', 'DOCUMENT_INDEXING'),         # document['getElementById']
        ]
        
        # Regular expressions for pattern matching
        self.regex_patterns = {
            'url_pattern': re.compile(r'https?://[^\s\'"]+', re.IGNORECASE),
            'ip_address': re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
            'email_pattern': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'base64_pattern': re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'),
            'hex_string': re.compile(r'\\x[0-9a-fA-F]{2}', re.IGNORECASE),
            'unicode_escape': re.compile(r'\\u[0-9a-fA-F]{4}', re.IGNORECASE),
            'json_pattern': re.compile(r'\{.*:.*\}', re.DOTALL),
            'minified_detection': re.compile(r'^[^{}]*\{[^{}]*\}[^{}]*$', re.DOTALL),
        }
        
        # Whitelisted domains (safe external resources)
        self.whitelisted_domains = {
            'ajax.googleapis.com',
            'cdnjs.cloudflare.com',
            'code.jquery.com',
            'maxcdn.bootstrapcdn.com',
            'unpkg.com',
            'fonts.googleapis.com',
            'fonts.gstatic.com',
        }
        
        # Statistics
        self.stats = {
            'files_analyzed': 0,
            'vulnerabilities_found': 0,
            'malicious_files': 0,
            'obfuscated_files': 0,
        }
    
    def analyze_javascript(self, js_code: str, filename: str = 'unknown.js') -> JavaScriptAnalysis:
        """
        Perform comprehensive security analysis of JavaScript code
        
        Args:
            js_code: Raw JavaScript code string
            filename: Original filename for context
            
        Returns:
            JavaScriptAnalysis object with analysis results
        """
        # Basic file metrics
        file_hash = hashlib.md5(js_code.encode()).hexdigest()
        file_size = len(js_code)
        line_count = js_code.count('\n') + 1
        char_count = len(js_code)
        
        # Initialize results containers
        vulnerabilities = []
        suspicious_patterns = []
        external_resources = []
        dom_manipulations = []
        event_listeners = []
        encoded_strings = []
        api_calls = []
        cookies_accessed = []
        localStorage_usage = []
        eval_calls = []
        
        # Clean the code for analysis
        cleaned_code = self._clean_javascript(js_code)
        
        # 1. Detect dangerous functions
        vulnerabilities.extend(self._detect_dangerous_functions(cleaned_code))
        
        # 2. Detect XSS vulnerabilities
        vulnerabilities.extend(self._detect_xss_vulnerabilities(cleaned_code))
        
        # 3. Detect data exfiltration
        vulnerabilities.extend(self._detect_data_exfiltration(cleaned_code))
        
        # 4. Detect obfuscated code
        obfuscation_results = self._detect_obfuscation(cleaned_code)
        suspicious_patterns.extend(obfuscation_results)
        
        # 5. Extract external resources
        external_resources = self._extract_external_resources(cleaned_code)
        
        # 6. Analyze DOM manipulations
        dom_manipulations = self._analyze_dom_manipulations(cleaned_code)
        
        # 7. Extract event listeners
        event_listeners = self._extract_event_listeners(cleaned_code)
        
        # 8. Detect encoded strings
        encoded_strings = self._detect_encoded_strings(cleaned_code)
        
        # 9. Extract API calls
        api_calls = self._extract_api_calls(cleaned_code)
        
        # 10. Detect cookie access
        cookies_accessed = self._detect_cookie_access(cleaned_code)
        
        # 11. Detect localStorage usage
        localStorage_usage = self._detect_localstorage_usage(cleaned_code)
        
        # 12. Detect eval calls
        eval_calls = self._detect_eval_calls(cleaned_code)
        
        # 13. Check for minified code
        if self._is_minified(cleaned_code):
            suspicious_patterns.append({
                'type': 'MINIFIED_CODE',
                'severity': 'LOW',
                'description': 'JavaScript appears to be minified',
                'location': 'File',
                'recommendation': 'Consider providing source maps for debugging'
            })
        
        # Calculate scores
        security_score = self._calculate_security_score(vulnerabilities)
        obfuscation_score = self._calculate_obfuscation_score(obfuscation_results)
        
        # Update statistics
        self.stats['files_analyzed'] += 1
        if vulnerabilities:
            self.stats['vulnerabilities_found'] += len(vulnerabilities)
        if obfuscation_score > 0.7:
            self.stats['obfuscated_files'] += 1
        if security_score < 0.3:
            self.stats['malicious_files'] += 1
        
        return JavaScriptAnalysis(
            file_hash=file_hash,
            file_size=file_size,
            line_count=line_count,
            char_count=char_count,
            vulnerabilities=vulnerabilities,
            suspicious_patterns=suspicious_patterns,
            external_resources=external_resources,
            dom_manipulations=dom_manipulations,
            event_listeners=event_listeners,
            encoded_strings=encoded_strings,
            api_calls=api_calls,
            cookies_accessed=cookies_accessed,
            localStorage_usage=localStorage_usage,
            eval_calls=eval_calls,
            security_score=security_score,
            obfuscation_score=obfuscation_score
        )
    
    def _clean_javascript(self, js_code: str) -> str:
        """
        Clean JavaScript code for analysis
        
        Args:
            js_code: Raw JavaScript code
            
        Returns:
            Cleaned JavaScript code
        """
        # Remove comments (single-line and multi-line)
        # Single-line comments
        lines = js_code.split('\n')
        cleaned_lines = []
        for line in lines:
            # Remove single-line comments, but be careful with URLs
            if '//' in line:
                # Check if // is in a string
                in_string = False
                string_char = None
                for i, char in enumerate(line):
                    if char in ('"', "'") and (i == 0 or line[i-1] != '\\'):
                        if not in_string:
                            in_string = True
                            string_char = char
                        elif string_char == char:
                            in_string = False
                            string_char = None
                    
                    if not in_string and line[i:i+2] == '//':
                        line = line[:i]
                        break
            cleaned_lines.append(line)
        
        cleaned = '\n'.join(cleaned_lines)
        
        # Remove multi-line comments /* ... */
        while '/*' in cleaned and '*/' in cleaned:
            start = cleaned.find('/*')
            end = cleaned.find('*/', start)
            if end == -1:
                break
            cleaned = cleaned[:start] + cleaned[end+2:]
        
        # Normalize whitespace (but preserve string content)
        # This is a simplified approach - in production, use proper parser
        cleaned = re.sub(r'\s+', ' ', cleaned)
        
        return cleaned.strip()
    
    def _detect_dangerous_functions(self, js_code: str) -> List[Dict[str, Any]]:
        """
        Detect dangerous JavaScript function usage
        
        Args:
            js_code: Cleaned JavaScript code
            
        Returns:
            List of dangerous function vulnerabilities
        """
        vulnerabilities = []
        
        for func_name, severity in self.dangerous_functions.items():
            # Create pattern for function detection
            if func_name == 'eval':
                pattern = r'\beval\s*\([^)]*\)'
            elif func_name == 'Function':
                pattern = r'\bFunction\s*\([^)]*\)'
            elif 'setTimeout' in func_name:
                pattern = r'setTimeout\s*\(\s*["\'][^"\']+["\']'
            elif 'setInterval' in func_name:
                pattern = r'setInterval\s*\(\s*["\'][^"\']+["\']'
            elif func_name == 'execScript':
                pattern = r'\bexecScript\s*\([^)]*\)'
            else:
                pattern = fr'\b{re.escape(func_name)}\s*\([^)]*\)'
            
            matches = re.finditer(pattern, js_code, re.IGNORECASE | re.DOTALL)
            for match in matches:
                context = match.group(0)
                # Get some context around the match
                start = max(0, match.start() - 50)
                end = min(len(js_code), match.end() + 50)
                context_snippet = js_code[start:end]
                
                vulnerabilities.append({
                    'type': 'DANGEROUS_FUNCTION',
                    'severity': severity,
                    'description': f'Dangerous function used: {func_name}',
                    'location': f'Function call: {func_name}',
                    'context': context_snippet,
                    'recommendation': f'Avoid using {func_name}, use safer alternatives'
                })
        
        return vulnerabilities
    
    def _detect_xss_vulnerabilities(self, js_code: str) -> List[Dict[str, Any]]:
        """
        Detect Cross-Site Scripting (XSS) vulnerabilities in JavaScript
        
        Args:
            js_code: Cleaned JavaScript code
            
        Returns:
            List of XSS vulnerabilities
        """
        vulnerabilities = []
        
        # Pattern to find user input sources (simplified)
        user_input_patterns = [
            r'location\.(search|hash)',
            r'document\.URL',
            r'document\.location',
            r'window\.name',
            r'document\.referrer',
            r'document\.cookie',
            r'localStorage\.getItem',
            r'sessionStorage\.getItem',
            r'new\s+URLSearchParams',
        ]
        
        # Find user input sources
        user_inputs = []
        for pattern in user_input_patterns:
            matches = re.finditer(pattern, js_code, re.IGNORECASE)
            for match in matches:
                user_inputs.append({
                    'source': match.group(0),
                    'start': match.start(),
                    'end': match.end()
                })
        
        # Find XSS sinks
        for sink in self.xss_sinks:
            pattern = fr'\b{re.escape(sink)}\s*\([^)]*\)'
            matches = re.finditer(pattern, js_code, re.IGNORECASE | re.DOTALL)
            
            for match in matches:
                # Check if any user input flows into this sink
                sink_context = match.group(0)
                sink_start = match.start()
                
                # Look for user inputs that might flow into this sink
                # This is a simplified taint analysis
                for user_input in user_inputs:
                    # Check if user input appears before the sink and might flow into it
                    if user_input['end'] < sink_start:
                        # Simple check: see if user_input variable name appears in sink arguments
                        # Extract variable name from user input source
                        var_match = re.search(r'(\w+)(?:\.|\[)', user_input['source'])
                        if var_match:
                            var_name = var_match.group(1)
                            if var_name in sink_context:
                                vulnerabilities.append({
                                    'type': 'POTENTIAL_XSS',
                                    'severity': 'HIGH',
                                    'description': f'User input from {user_input["source"]} flows into XSS sink {sink}',
                                    'location': f'XSS sink: {sink}',
                                    'context': sink_context[:100],
                                    'recommendation': 'Validate and sanitize user input before using in DOM'
                                })
        
        # Also check for direct assignment to dangerous properties
        dangerous_assignments = [
            (r'\.innerHTML\s*=', 'DIRECT_INNERHTML_ASSIGNMENT'),
            (r'\.outerHTML\s*=', 'DIRECT_OUTERHTML_ASSIGNMENT'),
            (r'\.src\s*=', 'DIRECT_SRC_ASSIGNMENT'),
            (r'\.href\s*=', 'DIRECT_HREF_ASSIGNMENT'),
        ]
        
        for pattern, vuln_type in dangerous_assignments:
            matches = re.finditer(pattern, js_code, re.IGNORECASE)
            for match in matches:
                # Get context
                start = max(0, match.start() - 50)
                end = min(len(js_code), match.end() + 50)
                context = js_code[start:end]
                
                vulnerabilities.append({
                    'type': vuln_type,
                    'severity': 'MEDIUM',
                    'description': f'Direct assignment to dangerous property',
                    'location': f'Assignment: {match.group(0)}',
                    'context': context,
                    'recommendation': 'Use safe DOM manipulation methods'
                })
        
        return vulnerabilities
    
    def _detect_data_exfiltration(self, js_code: str) -> List[Dict[str, Any]]:
        """
        Detect data exfiltration patterns
        
        Args:
            js_code: Cleaned JavaScript code
            
        Returns:
            List of data exfiltration vulnerabilities
        """
        vulnerabilities = []
        
        # Check for sensitive data collection
        sensitive_data_patterns = [
            (r'document\.cookie', 'COOKIE_COLLECTION'),
            (r'localStorage\.getItem', 'LOCALSTORAGE_COLLECTION'),
            (r'sessionStorage\.getItem', 'SESSIONSTORAGE_COLLECTION'),
            (r'\.value', 'FORM_DATA_COLLECTION'),
            (r'\.textContent', 'TEXT_CONTENT_COLLECTION'),
            (r'\.innerText', 'INNER_TEXT_COLLECTION'),
        ]
        
        # Check for network requests with suspicious patterns
        network_patterns = [
            (r'XMLHttpRequest', 'XMLHTTPREQUEST'),
            (r'fetch\s*\(', 'FETCH_API'),
            (r'new\s+WebSocket', 'WEBSOCKET'),
            (r'navigator\.sendBeacon', 'BEACON_API'),
        ]
        
        # Combine sensitive data patterns with network requests
        # This is a simplified taint analysis
        
        # First, find all sensitive data accesses
        sensitive_accesses = []
        for pattern, data_type in sensitive_data_patterns:
            matches = re.finditer(pattern, js_code, re.IGNORECASE)
            for match in matches:
                sensitive_accesses.append({
                    'type': data_type,
                    'match': match.group(0),
                    'start': match.start(),
                    'end': match.end()
                })
        
        # Then, find all network requests
        network_requests = []
        for pattern, request_type in network_patterns:
            matches = re.finditer(pattern, js_code, re.IGNORECASE)
            for match in matches:
                network_requests.append({
                    'type': request_type,
                    'match': match.group(0),
                    'start': match.start(),
                    'end': match.end()
                })
        
        # Look for correlations (simplified)
        for network_req in network_requests:
            for sensitive_data in sensitive_accesses:
                # Check if sensitive data access happens before network request
                # and they're reasonably close (simplified data flow)
                if sensitive_data['end'] < network_req['start']:
                    # Look for variable names that might connect them
                    # Extract context around each
                    sensitive_context = js_code[max(0, sensitive_data['start']-30):sensitive_data['end']+30]
                    network_context = js_code[max(0, network_req['start']-30):network_req['end']+30]
                    
                    # Check for common variable names (simplified)
                    var_pattern = r'\b([a-zA-Z_$][a-zA-Z0-9_$]*)\b'
                    sensitive_vars = set(re.findall(var_pattern, sensitive_context))
                    network_vars = set(re.findall(var_pattern, network_context))
                    
                    common_vars = sensitive_vars.intersection(network_vars)
                    if common_vars:
                        vulnerabilities.append({
                            'type': 'POTENTIAL_DATA_EXFILTRATION',
                            'severity': 'HIGH',
                            'description': f'{sensitive_data["type"]} data may be sent via {network_req["type"]}',
                            'location': f'Network request: {network_req["match"]}',
                            'common_variables': list(common_vars),
                            'recommendation': 'Review data collection and transmission'
                        })
        
        # Also check for direct image-based exfiltration
        image_exfil_pattern = r'new\s+Image\(\)\.src\s*=\s*[^;]+document\.cookie'
        if re.search(image_exfil_pattern, js_code, re.IGNORECASE):
            vulnerabilities.append({
                'type': 'IMAGE_BASED_EXFILTRATION',
                'severity': 'CRITICAL',
                'description': 'Image-based data exfiltration detected',
                'location': 'Image.src assignment with cookie data',
                'recommendation': 'Block this pattern entirely'
            })
        
        return vulnerabilities
    
    def _detect_obfuscation(self, js_code: str) -> List[Dict[str, Any]]:
        """
        Detect obfuscated JavaScript code
        
        Args:
            js_code: Cleaned JavaScript code
            
        Returns:
            List of obfuscation patterns found
        """
        suspicious_patterns = []
        
        # Check for each obfuscation pattern
        for pattern, pattern_type in self.obfuscation_patterns:
            matches = re.finditer(pattern, js_code, re.IGNORECASE | re.DOTALL)
            for match in matches:
                # Get context
                start = max(0, match.start() - 30)
                end = min(len(js_code), match.end() + 30)
                context = js_code[start:end]
                
                suspicious_patterns.append({
                    'type': pattern_type,
                    'severity': 'MEDIUM',
                    'description': f'Obfuscation pattern detected: {pattern_type}',
                    'location': f'Pattern: {pattern}',
                    'context': context,
                    'recommendation': 'Review code for malicious intent'
                })
        
        # Check for excessive string concatenation (common in obfuscation)
        concat_pattern = r'["\'][^"\']*["\']\s*\+\s*["\'][^"\']*["\']'
        concat_matches = list(re.finditer(concat_pattern, js_code))
        if len(concat_matches) > 5:  # More than 5 string concatenations
            suspicious_patterns.append({
                'type': 'EXCESSIVE_STRING_CONCATENATION',
                'severity': 'LOW',
                'description': 'Excessive string concatenation detected (common in obfuscation)',
                'location': 'Multiple locations',
                'count': len(concat_matches),
                'recommendation': 'Consider if this is legitimate or obfuscated code'
            })
        
        # Check for encoded strings (base64, hex, etc.)
        # Base64 detection
        base64_matches = self.regex_patterns['base64_pattern'].findall(js_code)
        if len(base64_matches) > 3:  # More than 3 base64 strings
            # Check if they're being decoded
            decoded = False
            for match in base64_matches[:3]:  # Check first 3
                if f'atob("{match}")' in js_code or f"atob('{match}')" in js_code:
                    decoded = True
                    break
            
            if decoded:
                suspicious_patterns.append({
                    'type': 'BASE64_DECODING',
                    'severity': 'HIGH',
                    'description': 'Multiple base64 strings being decoded',
                    'location': 'Base64 decoding operations',
                    'count': len(base64_matches),
                    'recommendation': 'Review decoded content for malicious code'
                })
        
        return suspicious_patterns
    
    def _extract_external_resources(self, js_code: str) -> List[str]:
        """
        Extract external resources loaded by JavaScript
        
        Args:
            js_code: Cleaned JavaScript code
            
        Returns:
            List of external resource URLs
        """
        resources = []
        
        # Find URLs in strings
        url_matches = self.regex_patterns['url_pattern'].findall(js_code)
        for url in url_matches:
            # Filter out common false positives
            if '://' in url and len(url) > 10:
                # Check if it's likely a resource URL
                if any(ext in url.lower() for ext in ['.js', '.css', '.png', '.jpg', '.gif', '.ico']):
                    resources.append(url)
                # Also include API endpoints
                elif '/api/' in url or '/ajax/' in url:
                    resources.append(url)
        
        # Find dynamic script loading
        script_patterns = [
            r'document\.createElement\s*\(\s*["\']script["\']\s*\)',
            r'new\s+Script\(\)',
            r'\.src\s*=\s*["\'][^"\']+\.js',
        ]
        
        for pattern in script_patterns:
            matches = re.finditer(pattern, js_code, re.IGNORECASE)
            for match in matches:
                # Extract URL from assignment
                context = js_code[max(0, match.start()-100):match.end()+100]
                # Look for URL assignment
                url_match = self.regex_patterns['url_pattern'].search(context)
                if url_match:
                    resources.append(url_match.group(0))
        
        # Deduplicate and return
        return list(set(resources))
    
    def _analyze_dom_manipulations(self, js_code: str) -> List[Dict[str, Any]]:
        """
        Analyze DOM manipulation patterns
        
        Args:
            js_code: Cleaned JavaScript code
            
        Returns:
            List of DOM manipulation operations
        """
        dom_operations = []
        
        # DOM query methods
        query_methods = [
            ('getElementById', 'ID_QUERY'),
            ('getElementsByClassName', 'CLASS_QUERY'),
            ('getElementsByTagName', 'TAG_QUERY'),
            ('querySelector', 'CSS_QUERY'),
            ('querySelectorAll', 'CSS_QUERY_ALL'),
        ]
        
        for method, operation_type in query_methods:
            pattern = fr'document\.{re.escape(method)}\s*\([^)]*\)'
            matches = re.finditer(pattern, js_code, re.IGNORECASE)
            for match in matches:
                dom_operations.append({
                    'type': operation_type,
                    'method': method,
                    'context': match.group(0),
                    'location': f'DOM query: {method}'
                })
        
        # DOM modification methods
        modification_methods = [
            ('appendChild', 'APPEND_ELEMENT'),
            ('insertBefore', 'INSERT_ELEMENT'),
            ('removeChild', 'REMOVE_ELEMENT'),
            ('replaceChild', 'REPLACE_ELEMENT'),
            ('setAttribute', 'SET_ATTRIBUTE'),
            ('removeAttribute', 'REMOVE_ATTRIBUTE'),
            ('addEventListener', 'ADD_EVENT_LISTENER'),
            ('removeEventListener', 'REMOVE_EVENT_LISTENER'),
        ]
        
        for method, operation_type in modification_methods:
            pattern = fr'\.{re.escape(method)}\s*\([^)]*\)'
            matches = re.finditer(pattern, js_code, re.IGNORECASE)
            for match in matches:
                dom_operations.append({
                    'type': operation_type,
                    'method': method,
                    'context': match.group(0),
                    'location': f'DOM modification: {method}'
                })
        
        return dom_operations
    
    def _extract_event_listeners(self, js_code: str) -> List[Dict[str, Any]]:
        """
        Extract event listeners from JavaScript code
        
        Args:
            js_code: Cleaned JavaScript code
            
        Returns:
            List of event listeners
        """
        event_listeners = []
        
        # Pattern for addEventListener
        pattern = r'\.addEventListener\s*\(\s*["\']([^"\']+)["\'][^)]*\)'
        matches = re.finditer(pattern, js_code, re.IGNORECASE)
        
        for match in matches:
            event_type = match.group(1)
            # Get some context
            start = max(0, match.start() - 50)
            end = min(len(js_code), match.end() + 50)
            context = js_code[start:end]
            
            event_listeners.append({
                'event_type': event_type,
                'context': context,
                'method': 'addEventListener'
            })
        
        # Also check for inline event handlers (onclick, onload, etc.)
        inline_pattern = r'on(\w+)\s*=\s*[^;\n]+'
        matches = re.finditer(inline_pattern, js_code, re.IGNORECASE)
        
        for match in matches:
            event_type = match.group(1)
            context = match.group(0)
            
            event_listeners.append({
                'event_type': event_type,
                'context': context,
                'method': 'inline_handler'
            })
        
        return event_listeners
    
    def _detect_encoded_strings(self, js_code: str) -> List[Dict[str, Any]]:
        """
        Detect encoded strings in JavaScript
        
        Args:
            js_code: Cleaned JavaScript code
            
        Returns:
            List of encoded strings found
        """
        encoded_strings = []
        
        # Check for hex escapes
        hex_matches = self.regex_patterns['hex_string'].findall(js_code)
        if hex_matches:
            encoded_strings.append({
                'type': 'HEX_ESCAPE',
                'count': len(hex_matches),
                'examples': hex_matches[:3],  # First 3 examples
                'description': 'Hexadecimal escape sequences found'
            })
        
        # Check for unicode escapes
        unicode_matches = self.regex_patterns['unicode_escape'].findall(js_code)
        if unicode_matches:
            encoded_strings.append({
                'type': 'UNICODE_ESCAPE',
                'count': len(unicode_matches),
                'examples': unicode_matches[:3],
                'description': 'Unicode escape sequences found'
            })
        
        # Check for String.fromCharCode usage
        charcode_pattern = r'String\.fromCharCode\s*\([^)]+\)'
        charcode_matches = re.findall(charcode_pattern, js_code, re.IGNORECASE)
        if charcode_matches:
            encoded_strings.append({
                'type': 'CHARCODE_CONSTRUCTION',
                'count': len(charcode_matches),
                'examples': charcode_matches[:3],
                'description': 'String construction from character codes'
            })
        
        # Check for atob (base64 decoding)
        atob_pattern = r'atob\s*\(\s*["\'][^"\']+["\']\s*\)'
        atob_matches = re.findall(atob_pattern, js_code, re.IGNORECASE)
        if atob_matches:
            encoded_strings.append({
                'type': 'BASE64_DECODING',
                'count': len(atob_matches),
                'examples': atob_matches[:3],
                'description': 'Base64 decoding operations'
            })
        
        return encoded_strings
    
    def _extract_api_calls(self, js_code: str) -> List[Dict[str, Any]]:
        """
        Extract API calls from JavaScript
        
        Args:
            js_code: Cleaned JavaScript code
            
        Returns:
            List of API calls
        """
        api_calls = []
        
        # Common API patterns
        api_patterns = [
            (r'fetch\s*\(\s*["\'][^"\']+["\']', 'FETCH_API'),
            (r'\.ajax\s*\(', 'JQUERY_AJAX'),
            (r'\.getJSON\s*\(', 'JQUERY_GETJSON'),
            (r'\.post\s*\(', 'JQUERY_POST'),
            (r'XMLHttpRequest', 'XMLHTTPREQUEST'),
            (r'\.load\s*\(', 'JQUERY_LOAD'),
            (r'axios\.', 'AXIOS'),
        ]
        
        for pattern, api_type in api_patterns:
            matches = re.finditer(pattern, js_code, re.IGNORECASE)
            for match in matches:
                # Get context
                start = max(0, match.start() - 50)
                end = min(len(js_code), match.end() + 50)
                context = js_code[start:end]
                
                # Try to extract URL
                url_match = self.regex_patterns['url_pattern'].search(context)
                url = url_match.group(0) if url_match else 'Unknown'
                
                api_calls.append({
                    'type': api_type,
                    'context': context,
                    'url': url,
                    'location': f'API call: {api_type}'
                })
        
        return api_calls
    
    def _detect_cookie_access(self, js_code: str) -> List[str]:
        """
        Detect cookie access in JavaScript
        
        Args:
            js_code: Cleaned JavaScript code
            
        Returns:
            List of cookie access patterns
        """
        cookie_accesses = []
        
        # Direct cookie access
        if 'document.cookie' in js_code:
            cookie_accesses.append('document.cookie')
        
        # Cookie manipulation libraries/patterns
        cookie_patterns = [
            r'js-cookie',
            r'Cookies\.',
            r'cookie\.',
            r'\.cookie\s*=',
            r'\.cookie\s*[+\-*/]',
        ]
        
        for pattern in cookie_patterns:
            if re.search(pattern, js_code, re.IGNORECASE):
                cookie_accesses.append(pattern)
        
        return list(set(cookie_accesses))
    
    def _detect_localstorage_usage(self, js_code: str) -> List[Dict[str, Any]]:
        """
        Detect localStorage and sessionStorage usage
        
        Args:
            js_code: Cleaned JavaScript code
            
        Returns:
            List of storage operations
        """
        storage_ops = []
        
        storage_patterns = [
            (r'localStorage\.getItem', 'LOCALSTORAGE_GET'),
            (r'localStorage\.setItem', 'LOCALSTORAGE_SET'),
            (r'localStorage\.removeItem', 'LOCALSTORAGE_REMOVE'),
            (r'localStorage\.clear', 'LOCALSTORAGE_CLEAR'),
            (r'sessionStorage\.getItem', 'SESSIONSTORAGE_GET'),
            (r'sessionStorage\.setItem', 'SESSIONSTORAGE_SET'),
            (r'sessionStorage\.removeItem', 'SESSIONSTORAGE_REMOVE'),
            (r'sessionStorage\.clear', 'SESSIONSTORAGE_CLEAR'),
        ]
        
        for pattern, op_type in storage_patterns:
            matches = re.finditer(pattern, js_code, re.IGNORECASE)
            for match in matches:
                # Get context
                start = max(0, match.start() - 50)
                end = min(len(js_code), match.end() + 50)
                context = js_code[start:end]
                
                storage_ops.append({
                    'type': op_type,
                    'context': context,
                    'location': f'Storage operation: {op_type}'
                })
        
        return storage_ops
    
    def _detect_eval_calls(self, js_code: str) -> List[Dict[str, Any]]:
        """
        Detect eval and similar function calls
        
        Args:
            js_code: Cleaned JavaScript code
            
        Returns:
            List of eval calls
        """
        eval_calls = []
        
        eval_patterns = [
            (r'\beval\s*\([^)]*\)', 'EVAL_DIRECT'),
            (r'\bFunction\s*\([^)]*\)', 'FUNCTION_CONSTRUCTOR'),
            (r'setTimeout\s*\(\s*["\'][^"\']+["\']', 'SETTIMEOUT_STRING'),
            (r'setInterval\s*\(\s*["\'][^"\']+["\']', 'SETINTERVAL_STRING'),
            (r'execScript\s*\([^)]*\)', 'EXECSCRIPT'),
        ]
        
        for pattern, eval_type in eval_patterns:
            matches = re.finditer(pattern, js_code, re.IGNORECASE)
            for match in matches:
                # Get context
                start = max(0, match.start() - 50)
                end = min(len(js_code), match.end() + 50)
                context = js_code[start:end]
                
                eval_calls.append({
                    'type': eval_type,
                    'context': context,
                    'severity': 'HIGH',
                    'location': f'Dynamic code execution: {eval_type}'
                })
        
        return eval_calls
    
    def _is_minified(self, js_code: str) -> bool:
        """
        Check if JavaScript code is minified
        
        Args:
            js_code: Cleaned JavaScript code
            
        Returns:
            True if code appears minified
        """
        # Minified code typically has:
        # 1. Very long lines
        # 2. No comments
        # 3. Removed whitespace
        # 4. Short variable names
        
        lines = js_code.split('\n')
        
        # Check average line length
        avg_line_length = sum(len(line) for line in lines) / max(len(lines), 1)
        
        # Check for comments (minified code usually has them removed)
        comment_density = js_code.count('//') + js_code.count('/*')
        
        # Check for whitespace ratio
        whitespace_ratio = sum(1 for c in js_code if c.isspace()) / max(len(js_code), 1)
        
        # Heuristic: minified if average line length > 100 and low comment density
        return avg_line_length > 100 and comment_density < 3 and whitespace_ratio < 0.1
    
    def _calculate_security_score(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """
        Calculate security score based on detected vulnerabilities
        
        Args:
            vulnerabilities: List of detected vulnerabilities
            
        Returns:
            Security score between 0.0 (worst) and 1.0 (best)
        """
        if not vulnerabilities:
            return 1.0
        
        # Severity weights
        severity_weights = {
            'CRITICAL': 0.9,
            'HIGH': 0.7,
            'MEDIUM': 0.4,
            'LOW': 0.1,
        }
        
        # Calculate penalty
        penalty = 0.0
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            weight = severity_weights.get(severity, 0.1)
            penalty += weight
        
        # Normalize penalty (diminishing returns for multiple vulnerabilities)
        normalized_penalty = min(penalty / (1 + len(vulnerabilities) * 0.3), 1.0)
        
        # Security score is inverse of penalty
        security_score = 1.0 - normalized_penalty
        
        return max(0.0, min(1.0, security_score))
    
    def _calculate_obfuscation_score(self, obfuscation_patterns: List[Dict[str, Any]]) -> float:
        """
        Calculate obfuscation score
        
        Args:
            obfuscation_patterns: List of detected obfuscation patterns
            
        Returns:
            Obfuscation score between 0.0 (no obfuscation) and 1.0 (heavily obfuscated)
        """
        if not obfuscation_patterns:
            return 0.0
        
        # Pattern weights
        pattern_weights = {
            'BASE64_EVAL': 0.9,
            'CHARCODE_OBFUSCATION': 0.8,
            'HEX_ESCAPE': 0.6,
            'UNICODE_ESCAPE': 0.6,
            'ARRAY_OBFUSCATION': 0.7,
            'BOOLEAN_OBFUSCATION': 0.7,
            'WINDOW_INDEXING': 0.5,
            'DOCUMENT_INDEXING': 0.5,
            'BASE64_DECODING': 0.8,
            'EXCESSIVE_STRING_CONCATENATION': 0.4,
            'MINIFIED_CODE': 0.3,
        }
        
        # Calculate score
        score = 0.0
        for pattern in obfuscation_patterns:
            pattern_type = pattern.get('type', '')
            weight = pattern_weights.get(pattern_type, 0.3)
            score += weight
        
        # Normalize with diminishing returns
        normalized_score = min(score / (1 + len(obfuscation_patterns) * 0.2), 1.0)
        
        return normalized_score
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get analyzer statistics
        
        Returns:
            Dictionary of statistics
        """
        return self.stats.copy()