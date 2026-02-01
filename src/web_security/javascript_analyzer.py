# src/web_security/javascript_analyzer.py
"""
JavaScript Security Analyzer for CyberGuard
Analyzes client-side JavaScript for security vulnerabilities and malicious code
Features: AST parsing, vulnerability detection, obfuscation analysis, dependency scanning
"""

import re
import hashlib
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
        
        # Dangerous JavaScript functions/patterns with severity levels
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
        
        # XSS sink functions where untrusted data can become executable code
        self.xss_sinks = [
            'innerHTML', 'outerHTML', 'insertAdjacentHTML',
            'document.write', 'document.writeln',
            'eval', 'setTimeout', 'setInterval',
            'location.assign', 'location.replace',
            'window.open', 'window.navigate',
            'element.setAttribute', 'element.src',
            'element.href', 'element.action',
        ]
        
        # Data exfiltration patterns with classification
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
        
        # Obfuscation detection patterns with regex and type identifier
        self.obfuscation_patterns = [
            (r'eval\(.*atob\(', 'BASE64_EVAL'),           # Pattern for eval(atob(...))
            (r'String\.fromCharCode\(', 'CHARCODE_OBFUSCATION'),  # Character code obfuscation
            (r'\\x[0-9a-fA-F]{2}', 'HEX_ESCAPE'),        # Hexadecimal escape sequences
            (r'\\u[0-9a-fA-F]{4}', 'UNICODE_ESCAPE'),    # Unicode escape sequences
            (r'\[][+\-*/%&|^]', 'ARRAY_OBFUSCATION'),     # Array-based obfuscation like []+!+[]
            (r'\(!\[\]\+\[\]\)', 'BOOLEAN_OBFUSCATION'),  # Boolean conversion obfuscation
            (r'window\[', 'WINDOW_INDEXING'),             # Window property indexing
            (r'document\[', 'DOCUMENT_INDEXING'),         # Document property indexing
        ]
        
        # Regular expressions for pattern matching in JavaScript code
        self.regex_patterns = {
            'url_pattern': re.compile(r'https?://[^\s\'"]+', re.IGNORECASE),  # HTTP/HTTPS URLs
            'ip_address': re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),  # IP addresses
            'email_pattern': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),  # Email addresses
            'base64_pattern': re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'),  # Base64 encoded strings
            'hex_string': re.compile(r'\\x[0-9a-fA-F]{2}', re.IGNORECASE),  # Hex escape sequences
            'unicode_escape': re.compile(r'\\u[0-9a-fA-F]{4}', re.IGNORECASE),  # Unicode escapes
            'json_pattern': re.compile(r'\{.*:.*\}', re.DOTALL),  # JSON-like objects
            'minified_detection': re.compile(r'^[^{}]*\{[^{}]*\}[^{}]*$', re.DOTALL),  # Minified code pattern
        }
        
        # Whitelisted domains for safe external resources
        self.whitelisted_domains = {
            'ajax.googleapis.com',
            'cdnjs.cloudflare.com',
            'code.jquery.com',
            'maxcdn.bootstrapcdn.com',
            'unpkg.com',
            'fonts.googleapis.com',
            'fonts.gstatic.com',
        }
        
        # Statistics tracking for analyzer performance
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
        # Calculate basic file metrics for analysis report
        file_hash = hashlib.md5(js_code.encode()).hexdigest()  # MD5 hash for file identification
        file_size = len(js_code)  # File size in bytes
        line_count = js_code.count('\n') + 1  # Count lines (add 1 for last line without newline)
        char_count = len(js_code)  # Total character count
        
        # Initialize empty containers for analysis results
        vulnerabilities = []  # Store security vulnerabilities
        suspicious_patterns = []  # Store suspicious code patterns
        external_resources = []  # Store external resource URLs
        dom_manipulations = []  # Store DOM manipulation operations
        event_listeners = []  # Store event listener attachments
        encoded_strings = []  # Store encoded/obfuscated strings
        api_calls = []  # Store API call patterns
        cookies_accessed = []  # Store cookie access patterns
        localStorage_usage = []  # Store localStorage operations
        eval_calls = []  # Store eval-like function calls
        
        # Clean the JavaScript code by removing comments and normalizing whitespace
        cleaned_code = self._clean_javascript(js_code)
        
        # Perform various security checks on the cleaned code
        # 1. Detect dangerous JavaScript functions
        vulnerabilities.extend(self._detect_dangerous_functions(cleaned_code))
        
        # 2. Detect Cross-Site Scripting (XSS) vulnerabilities
        vulnerabilities.extend(self._detect_xss_vulnerabilities(cleaned_code))
        
        # 3. Detect data exfiltration patterns
        vulnerabilities.extend(self._detect_data_exfiltration(cleaned_code))
        
        # 4. Detect obfuscated code patterns
        obfuscation_results = self._detect_obfuscation(cleaned_code)
        suspicious_patterns.extend(obfuscation_results)
        
        # 5. Extract external resources referenced in code
        external_resources = self._extract_external_resources(cleaned_code)
        
        # 6. Analyze DOM manipulation operations
        dom_manipulations = self._analyze_dom_manipulations(cleaned_code)
        
        # 7. Extract event listener attachments
        event_listeners = self._extract_event_listeners(cleaned_code)
        
        # 8. Detect encoded strings (base64, hex, etc.)
        encoded_strings = self._detect_encoded_strings(cleaned_code)
        
        # 9. Extract API calls (fetch, XMLHttpRequest, etc.)
        api_calls = self._extract_api_calls(cleaned_code)
        
        # 10. Detect cookie access patterns
        cookies_accessed = self._detect_cookie_access(cleaned_code)
        
        # 11. Detect localStorage and sessionStorage usage
        localStorage_usage = self._detect_localstorage_usage(cleaned_code)
        
        # 12. Detect eval() and similar dynamic code execution
        eval_calls = self._detect_eval_calls(cleaned_code)
        
        # 13. Check if code appears to be minified
        if self._is_minified(cleaned_code):
            suspicious_patterns.append({
                'type': 'MINIFIED_CODE',
                'severity': 'LOW',
                'description': 'JavaScript appears to be minified',
                'location': 'File',
                'recommendation': 'Consider providing source maps for debugging'
            })
        
        # Calculate overall security score based on vulnerabilities found
        security_score = self._calculate_security_score(vulnerabilities)
        
        # Calculate obfuscation score based on obfuscation patterns found
        obfuscation_score = self._calculate_obfuscation_score(obfuscation_results)
        
        # Update analyzer statistics
        self.stats['files_analyzed'] += 1  # Increment files analyzed counter
        if vulnerabilities:
            self.stats['vulnerabilities_found'] += len(vulnerabilities)  # Count vulnerabilities
        if obfuscation_score > 0.7:  # Threshold for considering file obfuscated
            self.stats['obfuscated_files'] += 1
        if security_score < 0.3:  # Threshold for considering file malicious
            self.stats['malicious_files'] += 1
        
        # Return comprehensive analysis results
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
        Clean JavaScript code by removing comments and normalizing whitespace
        
        Args:
            js_code: Raw JavaScript code
            
        Returns:
            Cleaned JavaScript code without comments and normalized whitespace
        """
        # Remove single-line comments (//) while preserving URLs and string literals
        lines = js_code.split('\n')
        cleaned_lines = []
        
        for line in lines:
            # Check for single-line comments, but avoid removing URLs containing //
            if '//' in line:
                in_string = False  # Track if we're inside a string literal
                string_char = None  # Track the string delimiter (' or ")
                
                # Iterate through each character in the line
                for i, char in enumerate(line):
                    # Check for string delimiters, ignoring escaped quotes
                    if char in ('"', "'") and (i == 0 or line[i-1] != '\\'):
                        if not in_string:
                            # Entering a string literal
                            in_string = True
                            string_char = char
                        elif string_char == char:
                            # Exiting a string literal
                            in_string = False
                            string_char = None
                    
                    # If we find // outside a string, truncate the line
                    if not in_string and i < len(line)-1 and line[i:i+2] == '//':
                        line = line[:i]  # Keep only the part before comment
                        break
            cleaned_lines.append(line)
        
        # Join lines back together
        cleaned = '\n'.join(cleaned_lines)
        
        # Remove multi-line comments (/* ... */) using iterative approach
        while True:
            # Find the start of a multi-line comment
            start_index = cleaned.find('/*')
            if start_index == -1:
                break  # No more multi-line comments
            
            # Find the end of this multi-line comment
            end_index = cleaned.find('*/', start_index + 2)
            if end_index == -1:
                break  # Unclosed comment, break to avoid infinite loop
            
            # Remove the comment from the string
            cleaned = cleaned[:start_index] + cleaned[end_index + 2:]
        
        # Normalize whitespace: replace multiple whitespace characters with single space
        # This preserves string content but reduces analysis complexity
        cleaned = re.sub(r'\s+', ' ', cleaned)
        
        return cleaned.strip()  # Remove leading/trailing whitespace
    
    def _detect_dangerous_functions(self, js_code: str) -> List[Dict[str, Any]]:
        """
        Detect dangerous JavaScript function usage
        
        Args:
            js_code: Cleaned JavaScript code
            
        Returns:
            List of dangerous function vulnerabilities with details
        """
        vulnerabilities = []  # Store detected vulnerabilities
        
        # Iterate through each dangerous function in the predefined list
        for func_name, severity in self.dangerous_functions.items():
            # Define regex pattern based on function type
            if func_name == 'eval':
                pattern = r'\beval\s*\([^)]*\)'  # Match eval(...)
            elif func_name == 'Function':
                pattern = r'\bFunction\s*\([^)]*\)'  # Match Function(...)
            elif 'setTimeout' in func_name:
                pattern = r'setTimeout\s*\(\s*["\'][^"\']+["\']'  # Match setTimeout("string"...)
            elif 'setInterval' in func_name:
                pattern = r'setInterval\s*\(\s*["\'][^"\']+["\']'  # Match setInterval("string"...)
            elif func_name == 'execScript':
                pattern = r'\bexecScript\s*\([^)]*\)'  # Match execScript(...)
            else:
                # Generic pattern for other dangerous functions
                pattern = fr'\b{re.escape(func_name)}\s*\([^)]*\)'
            
            # Search for all occurrences of the pattern in the code
            matches = re.finditer(pattern, js_code, re.IGNORECASE | re.DOTALL)
            for match in matches:
                context = match.group(0)  # The actual matched text
                # Extract surrounding context for better analysis (50 chars before/after)
                start_pos = max(0, match.start() - 50)
                end_pos = min(len(js_code), match.end() + 50)
                context_snippet = js_code[start_pos:end_pos]
                
                # Create vulnerability entry
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
            List of XSS vulnerabilities with source-to-sink mappings
        """
        vulnerabilities = []  # Store XSS vulnerabilities
        
        # Patterns for identifying user input sources (potential XSS vectors)
        user_input_patterns = [
            r'location\.(search|hash)',  # URL parameters/fragments
            r'document\.URL',  # Current URL
            r'document\.location',  # Document location
            r'window\.name',  # Window name property
            r'document\.referrer',  # Referrer URL
            r'document\.cookie',  # Browser cookies
            r'localStorage\.getItem',  # Local storage access
            r'sessionStorage\.getItem',  # Session storage access
            r'new\s+URLSearchParams',  # URL search parameters
        ]
        
        # Find all user input sources in the code
        user_inputs = []
        for pattern in user_input_patterns:
            matches = re.finditer(pattern, js_code, re.IGNORECASE)
            for match in matches:
                user_inputs.append({
                    'source': match.group(0),  # The matched source pattern
                    'start': match.start(),  # Start position in code
                    'end': match.end()  # End position in code
                })
        
        # Find XSS sinks (places where user input could become executable)
        for sink in self.xss_sinks:
            pattern = fr'\b{re.escape(sink)}\s*\([^)]*\)'  # Pattern for sink function call
            matches = re.finditer(pattern, js_code, re.IGNORECASE | re.DOTALL)
            
            for match in matches:
                sink_context = match.group(0)  # The sink function call
                sink_start = match.start()  # Start position of sink
                
                # Check if any user input might flow into this sink
                for user_input in user_inputs:
                    # Check if user input appears before the sink (potential data flow)
                    if user_input['end'] < sink_start:
                        # Extract variable name from user input source
                        var_match = re.search(r'(\w+)(?:\.|\[)', user_input['source'])
                        if var_match:
                            var_name = var_match.group(1)  # Extract variable name
                            # Check if this variable appears in the sink context
                            if var_name in sink_context:
                                # Potential XSS vulnerability found
                                vulnerabilities.append({
                                    'type': 'POTENTIAL_XSS',
                                    'severity': 'HIGH',
                                    'description': f'User input from {user_input["source"]} flows into XSS sink {sink}',
                                    'location': f'XSS sink: {sink}',
                                    'context': sink_context[:100],  # First 100 chars for context
                                    'recommendation': 'Validate and sanitize user input before using in DOM'
                                })
        
        # Check for direct assignments to dangerous DOM properties
        dangerous_assignments = [
            (r'\.innerHTML\s*=', 'DIRECT_INNERHTML_ASSIGNMENT'),  # innerHTML assignment
            (r'\.outerHTML\s*=', 'DIRECT_OUTERHTML_ASSIGNMENT'),  # outerHTML assignment
            (r'\.src\s*=', 'DIRECT_SRC_ASSIGNMENT'),  # src attribute assignment
            (r'\.href\s*=', 'DIRECT_HREF_ASSIGNMENT'),  # href attribute assignment
        ]
        
        for pattern, vuln_type in dangerous_assignments:
            matches = re.finditer(pattern, js_code, re.IGNORECASE)
            for match in matches:
                # Extract context around the assignment
                start_pos = max(0, match.start() - 50)
                end_pos = min(len(js_code), match.end() + 50)
                context = js_code[start_pos:end_pos]
                
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
        Detect data exfiltration patterns in JavaScript code
        
        Args:
            js_code: Cleaned JavaScript code
            
        Returns:
            List of data exfiltration vulnerabilities
        """
        vulnerabilities = []  # Store exfiltration vulnerabilities
        
        # Patterns for sensitive data collection
        sensitive_data_patterns = [
            (r'document\.cookie', 'COOKIE_COLLECTION'),  # Cookie access
            (r'localStorage\.getItem', 'LOCALSTORAGE_COLLECTION'),  # Local storage
            (r'sessionStorage\.getItem', 'SESSIONSTORAGE_COLLECTION'),  # Session storage
            (r'\.value', 'FORM_DATA_COLLECTION'),  # Form field values
            (r'\.textContent', 'TEXT_CONTENT_COLLECTION'),  # Text content
            (r'\.innerText', 'INNER_TEXT_COLLECTION'),  # Inner text
        ]
        
        # Patterns for network communication
        network_patterns = [
            (r'XMLHttpRequest', 'XMLHTTPREQUEST'),  # XHR requests
            (r'fetch\s*\(', 'FETCH_API'),  # Fetch API
            (r'new\s+WebSocket', 'WEBSOCKET'),  # WebSocket connections
            (r'navigator\.sendBeacon', 'BEACON_API'),  # Beacon API
        ]
        
        # Find all sensitive data accesses in the code
        sensitive_accesses = []
        for pattern, data_type in sensitive_data_patterns:
            matches = re.finditer(pattern, js_code, re.IGNORECASE)
            for match in matches:
                sensitive_accesses.append({
                    'type': data_type,
                    'match': match.group(0),  # Matched pattern
                    'start': match.start(),  # Start position
                    'end': match.end()  # End position
                })
        
        # Find all network requests in the code
        network_requests = []
        for pattern, request_type in network_patterns:
            matches = re.finditer(pattern, js_code, re.IGNORECASE)
            for match in matches:
                network_requests.append({
                    'type': request_type,
                    'match': match.group(0),  # Matched pattern
                    'start': match.start(),  # Start position
                    'end': match.end()  # End position
                })
        
        # Perform simplified taint analysis to find data exfiltration
        for network_req in network_requests:
            for sensitive_data in sensitive_accesses:
                # Check if sensitive data is accessed before network request
                if sensitive_data['end'] < network_req['start']:
                    # Extract context around both patterns
                    sensitive_context = js_code[max(0, sensitive_data['start']-30):sensitive_data['end']+30]
                    network_context = js_code[max(0, network_req['start']-30):network_req['end']+30]
                    
                    # Extract variable names from both contexts
                    var_pattern = r'\b([a-zA-Z_$][a-zA-Z0-9_$]*)\b'  # JavaScript variable pattern
                    sensitive_vars = set(re.findall(var_pattern, sensitive_context))
                    network_vars = set(re.findall(var_pattern, network_context))
                    
                    # Find common variables between sensitive access and network request
                    common_vars = sensitive_vars.intersection(network_vars)
                    if common_vars:
                        # Potential data exfiltration detected
                        vulnerabilities.append({
                            'type': 'POTENTIAL_DATA_EXFILTRATION',
                            'severity': 'HIGH',
                            'description': f'{sensitive_data["type"]} data may be sent via {network_req["type"]}',
                            'location': f'Network request: {network_req["match"]}',
                            'common_variables': list(common_vars),  # Shared variables
                            'recommendation': 'Review data collection and transmission'
                        })
        
        # Check for direct image-based exfiltration (common technique)
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
        Detect obfuscated JavaScript code patterns
        
        Args:
            js_code: Cleaned JavaScript code
            
        Returns:
            List of obfuscation patterns found
        """
        suspicious_patterns = []  # Store obfuscation patterns
        
        # Check for predefined obfuscation patterns
        for pattern, pattern_type in self.obfuscation_patterns:
            matches = re.finditer(pattern, js_code, re.IGNORECASE | re.DOTALL)
            for match in matches:
                # Extract context around the match
                start_pos = max(0, match.start() - 30)
                end_pos = min(len(js_code), match.end() + 30)
                context = js_code[start_pos:end_pos]
                
                suspicious_patterns.append({
                    'type': pattern_type,
                    'severity': 'MEDIUM',
                    'description': f'Obfuscation pattern detected: {pattern_type}',
                    'location': f'Pattern: {pattern}',
                    'context': context,
                    'recommendation': 'Review code for malicious intent'
                })
        
        # Check for excessive string concatenation (common obfuscation technique)
        concat_pattern = r'["\'][^"\']*["\']\s*\+\s*["\'][^"\']*["\']'  # String concatenation
        concat_matches = list(re.finditer(concat_pattern, js_code))
        if len(concat_matches) > 5:  # Threshold: more than 5 concatenations
            suspicious_patterns.append({
                'type': 'EXCESSIVE_STRING_CONCATENATION',
                'severity': 'LOW',
                'description': 'Excessive string concatenation detected (common in obfuscation)',
                'location': 'Multiple locations',
                'count': len(concat_matches),
                'recommendation': 'Consider if this is legitimate or obfuscated code'
            })
        
        # Check for base64 encoded strings
        base64_matches = self.regex_patterns['base64_pattern'].findall(js_code)
        if len(base64_matches) > 3:  # Threshold: more than 3 base64 strings
            # Check if base64 strings are being decoded
            decoded = False
            for match in base64_matches[:3]:  # Check first 3 matches
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
        Extract external resources loaded by JavaScript code
        
        Args:
            js_code: Cleaned JavaScript code
            
        Returns:
            List of external resource URLs
        """
        resources = []  # Store external resource URLs
        
        # Find URLs in the JavaScript code
        url_matches = self.regex_patterns['url_pattern'].findall(js_code)
        for url in url_matches:
            # Filter out likely resource URLs
            if '://' in url and len(url) > 10:  # Basic URL validation
                # Check for common resource file extensions
                if any(ext in url.lower() for ext in ['.js', '.css', '.png', '.jpg', '.gif', '.ico']):
                    resources.append(url)
                # Check for API endpoints
                elif '/api/' in url or '/ajax/' in url:
                    resources.append(url)
        
        # Find dynamic script loading patterns
        script_patterns = [
            r'document\.createElement\s*\(\s*["\']script["\']\s*\)',  # createElement('script')
            r'new\s+Script\(\)',  # new Script()
            r'\.src\s*=\s*["\'][^"\']+\.js',  # .src = "...js"
        ]
        
        for pattern in script_patterns:
            matches = re.finditer(pattern, js_code, re.IGNORECASE)
            for match in matches:
                # Extract context to find the URL
                context = js_code[max(0, match.start()-100):match.end()+100]
                url_match = self.regex_patterns['url_pattern'].search(context)
                if url_match:
                    resources.append(url_match.group(0))  # Add found URL
        
        # Return unique resources only
        return list(set(resources))
    
    def _analyze_dom_manipulations(self, js_code: str) -> List[Dict[str, Any]]:
        """
        Analyze DOM manipulation patterns in JavaScript
        
        Args:
            js_code: Cleaned JavaScript code
            
        Returns:
            List of DOM manipulation operations
        """
        dom_operations = []  # Store DOM operations
        
        # DOM query methods for finding elements
        query_methods = [
            ('getElementById', 'ID_QUERY'),  # Get element by ID
            ('getElementsByClassName', 'CLASS_QUERY'),  # Get elements by class
            ('getElementsByTagName', 'TAG_QUERY'),  # Get elements by tag name
            ('querySelector', 'CSS_QUERY'),  # CSS selector (single)
            ('querySelectorAll', 'CSS_QUERY_ALL'),  # CSS selector (all)
        ]
        
        for method, operation_type in query_methods:
            pattern = fr'document\.{re.escape(method)}\s*\([^)]*\)'  # Pattern for method call
            matches = re.finditer(pattern, js_code, re.IGNORECASE)
            for match in matches:
                dom_operations.append({
                    'type': operation_type,
                    'method': method,  # Method name
                    'context': match.group(0),  # Full method call
                    'location': f'DOM query: {method}'  # Location description
                })
        
        # DOM modification methods for changing elements
        modification_methods = [
            ('appendChild', 'APPEND_ELEMENT'),  # Append child element
            ('insertBefore', 'INSERT_ELEMENT'),  # Insert element before
            ('removeChild', 'REMOVE_ELEMENT'),  # Remove child element
            ('replaceChild', 'REPLACE_ELEMENT'),  # Replace child element
            ('setAttribute', 'SET_ATTRIBUTE'),  # Set element attribute
            ('removeAttribute', 'REMOVE_ATTRIBUTE'),  # Remove element attribute
            ('addEventListener', 'ADD_EVENT_LISTENER'),  # Add event listener
            ('removeEventListener', 'REMOVE_EVENT_LISTENER'),  # Remove event listener
        ]
        
        for method, operation_type in modification_methods:
            pattern = fr'\.{re.escape(method)}\s*\([^)]*\)'  # Pattern for method call
            matches = re.finditer(pattern, js_code, re.IGNORECASE)
            for match in matches:
                dom_operations.append({
                    'type': operation_type,
                    'method': method,  # Method name
                    'context': match.group(0),  # Full method call
                    'location': f'DOM modification: {method}'  # Location description
                })
        
        return dom_operations
    
    def _extract_event_listeners(self, js_code: str) -> List[Dict[str, Any]]:
        """
        Extract event listeners from JavaScript code
        
        Args:
            js_code: Cleaned JavaScript code
            
        Returns:
            List of event listeners with details
        """
        event_listeners = []  # Store event listeners
        
        # Pattern for addEventListener method calls
        pattern = r'\.addEventListener\s*\(\s*["\']([^"\']+)["\'][^)]*\)'
        matches = re.finditer(pattern, js_code, re.IGNORECASE)
        
        for match in matches:
            event_type = match.group(1)  # Extract event type (click, load, etc.)
            # Extract context around the match
            start_pos = max(0, match.start() - 50)
            end_pos = min(len(js_code), match.end() + 50)
            context = js_code[start_pos:end_pos]
            
            event_listeners.append({
                'event_type': event_type,  # Type of event
                'context': context,  # Surrounding code
                'method': 'addEventListener'  # Method used
            })
        
        # Also check for inline event handlers (onclick, onload, etc.)
        inline_pattern = r'on(\w+)\s*=\s*[^;\n]+'  # Pattern for onEvent=...
        matches = re.finditer(inline_pattern, js_code, re.IGNORECASE)
        
        for match in matches:
            event_type = match.group(1)  # Extract event type from "on" prefix
            context = match.group(0)  # Full inline handler assignment
            
            event_listeners.append({
                'event_type': event_type,  # Type of event
                'context': context,  # Full assignment
                'method': 'inline_handler'  # Method used (inline)
            })
        
        return event_listeners
    
    def _detect_encoded_strings(self, js_code: str) -> List[Dict[str, Any]]:
        """
        Detect encoded strings in JavaScript code
        
        Args:
            js_code: Cleaned JavaScript code
            
        Returns:
            List of encoded strings found
        """
        encoded_strings = []  # Store encoded string patterns
        
        # Check for hexadecimal escape sequences (\xXX)
        hex_matches = self.regex_patterns['hex_string'].findall(js_code)
        if hex_matches:
            encoded_strings.append({
                'type': 'HEX_ESCAPE',
                'count': len(hex_matches),  # Number of occurrences
                'examples': hex_matches[:3],  # First 3 examples
                'description': 'Hexadecimal escape sequences found'
            })
        
        # Check for Unicode escape sequences (\uXXXX)
        unicode_matches = self.regex_patterns['unicode_escape'].findall(js_code)
        if unicode_matches:
            encoded_strings.append({
                'type': 'UNICODE_ESCAPE',
                'count': len(unicode_matches),  # Number of occurrences
                'examples': unicode_matches[:3],  # First 3 examples
                'description': 'Unicode escape sequences found'
            })
        
        # Check for String.fromCharCode usage (character code construction)
        charcode_pattern = r'String\.fromCharCode\s*\([^)]+\)'
        charcode_matches = re.findall(charcode_pattern, js_code, re.IGNORECASE)
        if charcode_matches:
            encoded_strings.append({
                'type': 'CHARCODE_CONSTRUCTION',
                'count': len(charcode_matches),  # Number of occurrences
                'examples': charcode_matches[:3],  # First 3 examples
                'description': 'String construction from character codes'
            })
        
        # Check for atob() function calls (base64 decoding)
        atob_pattern = r'atob\s*\(\s*["\'][^"\']+["\']\s*\)'
        atob_matches = re.findall(atob_pattern, js_code, re.IGNORECASE)
        if atob_matches:
            encoded_strings.append({
                'type': 'BASE64_DECODING',
                'count': len(atob_matches),  # Number of occurrences
                'examples': atob_matches[:3],  # First 3 examples
                'description': 'Base64 decoding operations'
            })
        
        return encoded_strings
    
    def _extract_api_calls(self, js_code: str) -> List[Dict[str, Any]]:
        """
        Extract API calls from JavaScript code
        
        Args:
            js_code: Cleaned JavaScript code
            
        Returns:
            List of API call patterns
        """
        api_calls = []  # Store API call patterns
        
        # Common API calling patterns
        api_patterns = [
            (r'fetch\s*\(\s*["\'][^"\']+["\']', 'FETCH_API'),  # Fetch API calls
            (r'\.ajax\s*\(', 'JQUERY_AJAX'),  # jQuery AJAX
            (r'\.getJSON\s*\(', 'JQUERY_GETJSON'),  # jQuery getJSON
            (r'\.post\s*\(', 'JQUERY_POST'),  # jQuery post
            (r'XMLHttpRequest', 'XMLHTTPREQUEST'),  # XMLHttpRequest
            (r'\.load\s*\(', 'JQUERY_LOAD'),  # jQuery load
            (r'axios\.', 'AXIOS'),  # Axios library
        ]
        
        for pattern, api_type in api_patterns:
            matches = re.finditer(pattern, js_code, re.IGNORECASE)
            for match in matches:
                # Extract context around the API call
                start_pos = max(0, match.start() - 50)
                end_pos = min(len(js_code), match.end() + 50)
                context = js_code[start_pos:end_pos]
                
                # Try to extract URL from the context
                url_match = self.regex_patterns['url_pattern'].search(context)
                url = url_match.group(0) if url_match else 'Unknown'  # URL or Unknown
                
                api_calls.append({
                    'type': api_type,  # Type of API call
                    'context': context,  # Surrounding code
                    'url': url,  # Extracted URL
                    'location': f'API call: {api_type}'  # Location description
                })
        
        return api_calls
    
    def _detect_cookie_access(self, js_code: str) -> List[str]:
        """
        Detect cookie access in JavaScript code
        
        Args:
            js_code: Cleaned JavaScript code
            
        Returns:
            List of cookie access patterns
        """
        cookie_accesses = []  # Store cookie access patterns
        
        # Direct cookie access via document.cookie
        if 'document.cookie' in js_code:
            cookie_accesses.append('document.cookie')
        
        # Patterns for cookie manipulation libraries
        cookie_patterns = [
            r'js-cookie',  # js-cookie library
            r'Cookies\.',  # Cookies object
            r'cookie\.',  # cookie object
            r'\.cookie\s*=',  # Cookie assignment
            r'\.cookie\s*[+\-*/]',  # Cookie manipulation
        ]
        
        for pattern in cookie_patterns:
            if re.search(pattern, js_code, re.IGNORECASE):
                cookie_accesses.append(pattern)  # Add pattern
        
        # Return unique patterns only
        return list(set(cookie_accesses))
    
    def _detect_localstorage_usage(self, js_code: str) -> List[Dict[str, Any]]:
        """
        Detect localStorage and sessionStorage usage
        
        Args:
            js_code: Cleaned JavaScript code
            
        Returns:
            List of storage operations
        """
        storage_ops = []  # Store storage operations
        
        # Storage operation patterns
        storage_patterns = [
            (r'localStorage\.getItem', 'LOCALSTORAGE_GET'),  # Get from localStorage
            (r'localStorage\.setItem', 'LOCALSTORAGE_SET'),  # Set to localStorage
            (r'localStorage\.removeItem', 'LOCALSTORAGE_REMOVE'),  # Remove from localStorage
            (r'localStorage\.clear', 'LOCALSTORAGE_CLEAR'),  # Clear localStorage
            (r'sessionStorage\.getItem', 'SESSIONSTORAGE_GET'),  # Get from sessionStorage
            (r'sessionStorage\.setItem', 'SESSIONSTORAGE_SET'),  # Set to sessionStorage
            (r'sessionStorage\.removeItem', 'SESSIONSTORAGE_REMOVE'),  # Remove from sessionStorage
            (r'sessionStorage\.clear', 'SESSIONSTORAGE_CLEAR'),  # Clear sessionStorage
        ]
        
        for pattern, op_type in storage_patterns:
            matches = re.finditer(pattern, js_code, re.IGNORECASE)
            for match in matches:
                # Extract context around storage operation
                start_pos = max(0, match.start() - 50)
                end_pos = min(len(js_code), match.end() + 50)
                context = js_code[start_pos:end_pos]
                
                storage_ops.append({
                    'type': op_type,  # Operation type
                    'context': context,  # Surrounding code
                    'location': f'Storage operation: {op_type}'  # Location description
                })
        
        return storage_ops
    
    def _detect_eval_calls(self, js_code: str) -> List[Dict[str, Any]]:
        """
        Detect eval and similar dynamic code execution calls
        
        Args:
            js_code: Cleaned JavaScript code
            
        Returns:
            List of eval-like function calls
        """
        eval_calls = []  # Store eval calls
        
        # Patterns for dynamic code execution
        eval_patterns = [
            (r'\beval\s*\([^)]*\)', 'EVAL_DIRECT'),  # Direct eval()
            (r'\bFunction\s*\([^)]*\)', 'FUNCTION_CONSTRUCTOR'),  # Function constructor
            (r'setTimeout\s*\(\s*["\'][^"\']+["\']', 'SETTIMEOUT_STRING'),  # setTimeout with string
            (r'setInterval\s*\(\s*["\'][^"\']+["\']', 'SETINTERVAL_STRING'),  # setInterval with string
            (r'execScript\s*\([^)]*\)', 'EXECSCRIPT'),  # execScript()
        ]
        
        for pattern, eval_type in eval_patterns:
            matches = re.finditer(pattern, js_code, re.IGNORECASE)
            for match in matches:
                # Extract context around eval call
                start_pos = max(0, match.start() - 50)
                end_pos = min(len(js_code), match.end() + 50)
                context = js_code[start_pos:end_pos]
                
                eval_calls.append({
                    'type': eval_type,  # Type of eval-like call
                    'context': context,  # Surrounding code
                    'severity': 'HIGH',  # Severity level
                    'location': f'Dynamic code execution: {eval_type}'  # Location description
                })
        
        return eval_calls
    
    def _is_minified(self, js_code: str) -> bool:
        """
        Check if JavaScript code is minified
        
        Args:
            js_code: Cleaned JavaScript code
            
        Returns:
            True if code appears minified based on heuristics
        """
        # Split code into lines for analysis
        lines = js_code.split('\n')
        
        # Calculate average line length (minified code has long lines)
        if len(lines) > 0:
            avg_line_length = sum(len(line) for line in lines) / len(lines)
        else:
            avg_line_length = 0
        
        # Count comments (minified code typically has comments removed)
        comment_density = js_code.count('//') + js_code.count('/*')
        
        # Calculate whitespace ratio (minified code has minimal whitespace)
        if len(js_code) > 0:
            whitespace_ratio = sum(1 for c in js_code if c.isspace()) / len(js_code)
        else:
            whitespace_ratio = 0
        
        # Heuristic: Code is likely minified if:
        # 1. Average line length > 100 characters
        # 2. Few comments (< 3)
        # 3. Low whitespace ratio (< 10%)
        return avg_line_length > 100 and comment_density < 3 and whitespace_ratio < 0.1
    
    def _calculate_security_score(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """
        Calculate security score based on detected vulnerabilities
        
        Args:
            vulnerabilities: List of detected vulnerabilities
            
        Returns:
            Security score between 0.0 (worst) and 1.0 (best)
        """
        # If no vulnerabilities, return perfect score
        if not vulnerabilities:
            return 1.0
        
        # Define weights for different severity levels
        severity_weights = {
            'CRITICAL': 0.9,  # Critical vulnerabilities
            'HIGH': 0.7,      # High severity
            'MEDIUM': 0.4,    # Medium severity
            'LOW': 0.1,       # Low severity
        }
        
        # Calculate total penalty based on vulnerability severity
        penalty = 0.0
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW')  # Default to LOW if not specified
            weight = severity_weights.get(severity, 0.1)  # Get weight or default
            penalty += weight  # Add to total penalty
        
        # Normalize penalty with diminishing returns (multiple vulnerabilities)
        # Formula prevents single vulnerability from reducing score to 0
        normalized_penalty = min(penalty / (1 + len(vulnerabilities) * 0.3), 1.0)
        
        # Security score is inverse of penalty
        security_score = 1.0 - normalized_penalty
        
        # Ensure score is within bounds [0.0, 1.0]
        return max(0.0, min(1.0, security_score))
    
    def _calculate_obfuscation_score(self, obfuscation_patterns: List[Dict[str, Any]]) -> float:
        """
        Calculate obfuscation score
        
        Args:
            obfuscation_patterns: List of detected obfuscation patterns
            
        Returns:
            Obfuscation score between 0.0 (no obfuscation) and 1.0 (heavily obfuscated)
        """
        # If no obfuscation patterns, return 0.0
        if not obfuscation_patterns:
            return 0.0
        
        # Define weights for different obfuscation pattern types
        pattern_weights = {
            'BASE64_EVAL': 0.9,                     # eval(atob(...)) pattern
            'CHARCODE_OBFUSCATION': 0.8,            # String.fromCharCode
            'HEX_ESCAPE': 0.6,                      # \xXX escapes
            'UNICODE_ESCAPE': 0.6,                  # \uXXXX escapes
            'ARRAY_OBFUSCATION': 0.7,               # []+!+[] patterns
            'BOOLEAN_OBFUSCATION': 0.7,             # (![]+[]) patterns
            'WINDOW_INDEXING': 0.5,                 # window['alert']
            'DOCUMENT_INDEXING': 0.5,               # document['getElementById']
            'BASE64_DECODING': 0.8,                 # atob() calls
            'EXCESSIVE_STRING_CONCATENATION': 0.4,  # Many string concatenations
            'MINIFIED_CODE': 0.3,                   # Minified code detection
        }
        
        # Calculate total obfuscation score
        score = 0.0
        for pattern in obfuscation_patterns:
            pattern_type = pattern.get('type', '')  # Get pattern type
            weight = pattern_weights.get(pattern_type, 0.3)  # Get weight or default
            score += weight  # Add to total score
        
        # Normalize score with diminishing returns
        # Prevents excessive scoring from many low-weight patterns
        normalized_score = min(score / (1 + len(obfuscation_patterns) * 0.2), 1.0)
        
        return normalized_score
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get analyzer statistics
        
        Returns:
            Dictionary of statistics including files analyzed and findings
        """
        # Return a copy to prevent external modification
        return self.stats.copy()