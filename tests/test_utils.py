"""
JavaScript Security Analyzer Module
Purpose: Analyze JavaScript files and inline scripts for security vulnerabilities
"""

import re
import json
import ast
from typing import Dict, List, Any, Optional, Tuple, Set
import logging
from urllib.parse import urlparse
import hashlib

# Set up logging
logger = logging.getLogger(__name__)

class JavaScriptAnalyzer:
    """
    Security analyzer for JavaScript code
    Detects vulnerabilities in JavaScript files and inline scripts
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the JavaScript analyzer
        
        Args:
            config: Optional configuration dictionary
        """
        # Default configuration
        self.config = config or {
            'enable_ast_analysis': True,
            'enable_regex_analysis': True,
            'max_script_size': 100000,  # 100KB max script size
            'dangerous_functions': [
                'eval',
                'Function',
                'setTimeout',
                'setInterval',
                'execScript',
                'document.write',
                'document.writeln',
                'innerHTML',
                'outerHTML',
                'insertAdjacentHTML',
                'createContextualFragment',
                'location.replace',
                'location.assign',
                'location.href',
                'window.open',
                '$.globalEval'
            ],
            'dangerous_sinks': [
                'innerHTML',
                'outerHTML',
                'document.write',
                'document.writeln',
                'eval',
                'Function',
                'setTimeout',
                'setInterval'
            ],
            'sensitive_data_patterns': [
                r'password\s*[:=]',
                r'api[_-]?key\s*[:=]',
                r'secret\s*[:=]',
                r'token\s*[:=]',
                r'credential\s*[:=]'
            ]
        }
        
        # Compile regex patterns for efficiency
        self._compile_patterns()
        
        # Cache for analyzed scripts to avoid redundant analysis
        self.analysis_cache = {}
        
    def _compile_patterns(self) -> None:
        """Compile all regex patterns for better performance"""
        
        # Pattern for detecting inline event handlers
        self.inline_event_pattern = re.compile(
            r'\b(on\w+)\s*=\s*["\']([^"\']+)["\']',
            re.IGNORECASE | re.MULTILINE
        )
        
        # Pattern for detecting script tags
        self.script_tag_pattern = re.compile(
            r'<script\b[^>]*>([\s\S]*?)</script>',
            re.IGNORECASE
        )
        
        # Pattern for detecting external script sources
        self.external_script_pattern = re.compile(
            r'<script\b[^>]*src\s*=\s*["\']([^"\']+)["\'][^>]*>',
            re.IGNORECASE
        )
        
        # Pattern for detecting dangerous JavaScript functions
        self.dangerous_func_pattern = re.compile(
            r'\b(' + '|'.join(self.config['dangerous_functions']) + r')\s*\(',
            re.IGNORECASE
        )
        
        # Pattern for detecting DOM-based XSS sinks
        self.xss_sink_pattern = re.compile(
            r'\.(' + '|'.join(self.config['dangerous_sinks']) + r')\s*=',
            re.IGNORECASE
        )
        
        # Pattern for detecting sensitive data in JavaScript
        self.sensitive_data_pattern = re.compile(
            '|'.join(self.config['sensitive_data_patterns']),
            re.IGNORECASE
        )
        
        # Pattern for detecting JSONP callbacks (potential JSON hijacking)
        self.jsonp_pattern = re.compile(
            r'callback\s*=\s*\w+',
            re.IGNORECASE
        )
        
        # Pattern for detecting insecure DOM manipulations
        self.dom_manipulation_pattern = re.compile(
            r'document\.(getElementById|getElementsByClassName|'
            r'getElementsByTagName|querySelector|querySelectorAll)\s*\(',
            re.IGNORECASE
        )
        
    def analyze_javascript(self, javascript_code: str, source_url: str = '') -> Dict[str, Any]:
        """
        Analyze JavaScript code for security vulnerabilities
        
        Args:
            javascript_code: The JavaScript code to analyze
            source_url: URL where the script originated from
            
        Returns:
            Dictionary containing analysis results and findings
        """
        # Validate input
        if not javascript_code or not isinstance(javascript_code, str):
            logger.warning("Invalid JavaScript code provided for analysis")
            return self._create_empty_result(source_url)
        
        # Check cache for previously analyzed code
        cache_key = self._generate_cache_key(javascript_code, source_url)
        if cache_key in self.analysis_cache:
            logger.debug(f"Returning cached analysis for {source_url}")
            return self.analysis_cache[cache_key]
        
        # Initialize results structure
        results = {
            'source_url': source_url,
            'script_hash': hashlib.sha256(javascript_code.encode()).hexdigest(),
            'script_length': len(javascript_code),
            'vulnerabilities': [],
            'warnings': [],
            'informational': [],
            'security_score': 100,  # Start with perfect score
            'analysis_methods': [],
            'metadata': {}
        }
        
        # Check script size
        if len(javascript_code) > self.config['max_script_size']:
            results['warnings'].append({
                'type': 'LARGE_SCRIPT',
                'severity': 'LOW',
                'description': f'Script size ({len(javascript_code)} bytes) exceeds recommended limit',
                'line': 0,
                'column': 0
            })
            results['security_score'] -= 5
        
        # Perform regex-based analysis
        if self.config['enable_regex_analysis']:
            self._regex_analysis(javascript_code, results)
            results['analysis_methods'].append('regex_analysis')
        
        # Perform AST-based analysis (if enabled and possible)
        if self.config['enable_ast_analysis']:
            try:
                self._ast_analysis(javascript_code, results)
                results['analysis_methods'].append('ast_analysis')
            except SyntaxError as e:
                logger.warning(f"AST analysis failed due to syntax error: {e}")
                results['warnings'].append({
                    'type': 'SYNTAX_ERROR',
                    'severity': 'LOW',
                    'description': f'JavaScript syntax error: {str(e)}',
                    'line': getattr(e, 'lineno', 0),
                    'column': getattr(e, 'offset', 0)
                })
            except Exception as e:
                logger.error(f"AST analysis failed: {e}")
        
        # Calculate final security score
        results['security_score'] = max(0, min(100, results['security_score']))
        
        # Determine overall risk level
        results['risk_level'] = self._calculate_risk_level(results)
        
        # Cache the results
        self.analysis_cache[cache_key] = results
        
        return results
    
    def analyze_html_for_scripts(self, html_content: str, base_url: str = '') -> Dict[str, Any]:
        """
        Extract and analyze JavaScript from HTML content
        
        Args:
            html_content: HTML content to analyze
            base_url: Base URL for resolving relative script URLs
            
        Returns:
            Dictionary containing analysis of all scripts found
        """
        if not html_content or not isinstance(html_content, str):
            return {
                'total_scripts': 0,
                'inline_scripts': [],
                'external_scripts': [],
                'inline_event_handlers': [],
                'overall_risk': 'LOW',
                'findings': []
            }
        
        results = {
            'total_scripts': 0,
            'inline_scripts': [],
            'external_scripts': [],
            'inline_event_handlers': [],
            'overall_risk': 'LOW',
            'findings': []
        }
        
        try:
            # Find all script tags
            script_tags = self.script_tag_pattern.finditer(html_content)
            
            for match in script_tags:
                script_content = match.group(1).strip()
                if script_content:  # Only analyze non-empty scripts
                    script_analysis = self.analyze_javascript(script_content, base_url)
                    results['inline_scripts'].append(script_analysis)
                    results['total_scripts'] += 1
            
            # Find external scripts
            external_scripts = self.external_script_pattern.finditer(html_content)
            for match in external_scripts:
                script_src = match.group(1)
                # Resolve relative URLs
                if base_url and not urlparse(script_src).netloc:
                    script_src = self._resolve_url(base_url, script_src)
                
                results['external_scripts'].append({
                    'src': script_src,
                    'resolved_url': script_src if script_src.startswith('http') else '',
                    'line': html_content[:match.start()].count('\n') + 1
                })
                results['total_scripts'] += 1
            
            # Find inline event handlers
            inline_events = self.inline_event_pattern.finditer(html_content)
            for match in inline_events:
                event_name = match.group(1)
                event_code = match.group(2)
                
                event_analysis = self.analyze_javascript(event_code, base_url)
                results['inline_event_handlers'].append({
                    'event': event_name,
                    'code': event_code,
                    'analysis': event_analysis,
                    'line': html_content[:match.start()].count('\n') + 1
                })
            
            # Calculate overall risk
            if results['inline_scripts'] or results['inline_event_handlers']:
                highest_risk = 'LOW'
                for script in results['inline_scripts']:
                    script_risk = script.get('risk_level', 'LOW')
                    if self._is_higher_risk(script_risk, highest_risk):
                        highest_risk = script_risk
                
                for event in results['inline_event_handlers']:
                    event_risk = event['analysis'].get('risk_level', 'LOW')
                    if self._is_higher_risk(event_risk, highest_risk):
                        highest_risk = event_risk
                
                results['overall_risk'] = highest_risk
            
        except Exception as e:
            logger.error(f"Error analyzing HTML for scripts: {e}")
            results['findings'].append({
                'type': 'ANALYSIS_ERROR',
                'severity': 'MEDIUM',
                'description': f'Error during script analysis: {str(e)}'
            })
        
        return results
    
    def _regex_analysis(self, javascript_code: str, results: Dict[str, Any]) -> None:
        """
        Perform regex-based security analysis on JavaScript code
        
        Args:
            javascript_code: JavaScript code to analyze
            results: Dictionary to store analysis results
        """
        try:
            lines = javascript_code.split('\n')
            
            # Check for dangerous functions
            for i, line in enumerate(lines):
                line_number = i + 1
                
                # Check for dangerous functions
                dangerous_matches = self.dangerous_func_pattern.finditer(line)
                for match in dangerous_matches:
                    func_name = match.group(1)
                    results['vulnerabilities'].append({
                        'type': 'DANGEROUS_FUNCTION',
                        'severity': 'HIGH',
                        'description': f'Use of dangerous function: {func_name}',
                        'line': line_number,
                        'column': match.start(),
                        'function': func_name,
                        'code_snippet': line.strip()[:100]
                    })
                    results['security_score'] -= 10
                
                # Check for XSS sinks
                xss_matches = self.xss_sink_pattern.finditer(line)
                for match in xss_matches:
                    sink_name = match.group(1)
                    results['vulnerabilities'].append({
                        'type': 'XSS_SINK',
                        'severity': 'HIGH',
                        'description': f'Potential XSS sink: {sink_name}',
                        'line': line_number,
                        'column': match.start(),
                        'sink': sink_name,
                        'code_snippet': line.strip()[:100]
                    })
                    results['security_score'] -= 15
                
                # Check for sensitive data exposure
                sensitive_matches = self.sensitive_data_pattern.finditer(line)
                for match in sensitive_matches:
                    pattern = match.group(0)
                    results['warnings'].append({
                        'type': 'SENSITIVE_DATA',
                        'severity': 'MEDIUM',
                        'description': f'Potential sensitive data exposure: {pattern}',
                        'line': line_number,
                        'column': match.start(),
                        'pattern': pattern,
                        'code_snippet': line.strip()[:100]
                    })
                    results['security_score'] -= 5
                
                # Check for JSONP callbacks
                jsonp_matches = self.jsonp_pattern.search(line)
                if jsonp_matches:
                    results['warnings'].append({
                        'type': 'JSONP_CALLBACK',
                        'severity': 'MEDIUM',
                        'description': 'JSONP callback detected - potential JSON hijacking vulnerability',
                        'line': line_number,
                        'column': jsonp_matches.start(),
                        'code_snippet': line.strip()[:100]
                    })
                    results['security_score'] -= 8
            
            # Count total occurrences for statistics
            total_dangerous_funcs = len([v for v in results['vulnerabilities'] 
                                       if v['type'] == 'DANGEROUS_FUNCTION'])
            total_xss_sinks = len([v for v in results['vulnerabilities'] 
                                 if v['type'] == 'XSS_SINK'])
            
            if total_dangerous_funcs > 0 or total_xss_sinks > 0:
                results['metadata']['dangerous_patterns_found'] = {
                    'dangerous_functions': total_dangerous_funcs,
                    'xss_sinks': total_xss_sinks
                }
                
        except Exception as e:
            logger.error(f"Error during regex analysis: {e}")
            results['warnings'].append({
                'type': 'ANALYSIS_ERROR',
                'severity': 'LOW',
                'description': f'Regex analysis error: {str(e)}'
            })
    
    def _ast_analysis(self, javascript_code: str, results: Dict[str, Any]) -> None:
        """
        Perform AST-based security analysis (simplified version)
        
        Note: Full JavaScript AST parsing requires specialized libraries.
        This is a simplified implementation.
        
        Args:
            javascript_code: JavaScript code to analyze
            results: Dictionary to store analysis results
        """
        try:
            # Note: In production, use a proper JavaScript parser like esprima
            # This is a simplified placeholder implementation
            
            # Check for common patterns that AST would catch
            
            # Pattern: direct eval with user input
            eval_with_input_pattern = re.compile(
                r'eval\s*\(\s*(?:window\.location|document\.location|'
                r'location\.hash|location\.search|'
                r'document\.URL|document\.documentURI|'
                r'document\.referrer|document\.cookie)',
                re.IGNORECASE
            )
            
            matches = eval_with_input_pattern.finditer(javascript_code)
            for match in matches:
                results['vulnerabilities'].append({
                    'type': 'EVAL_WITH_USER_INPUT',
                    'severity': 'CRITICAL',
                    'description': 'eval() called with potentially user-controlled input',
                    'line': javascript_code[:match.start()].count('\n') + 1,
                    'column': match.start() - javascript_code[:match.start()].rfind('\n'),
                    'code_snippet': match.group(0),
                    'recommendation': 'Avoid using eval() with user input. Use JSON.parse() for JSON data.'
                })
                results['security_score'] -= 20
            
            # Pattern: insecure setTimeout/setInterval with string argument
            insecure_timer_pattern = re.compile(
                r'(setTimeout|setInterval)\s*\(\s*["\']',
                re.IGNORECASE
            )
            
            matches = insecure_timer_pattern.finditer(javascript_code)
            for match in matches:
                func_name = match.group(1)
                results['vulnerabilities'].append({
                    'type': 'INSECURE_TIMER',
                    'severity': 'HIGH',
                    'description': f'{func_name}() called with string argument (potential code injection)',
                    'line': javascript_code[:match.start()].count('\n') + 1,
                    'column': match.start() - javascript_code[:match.start()].rfind('\n'),
                    'function': func_name,
                    'code_snippet': match.group(0),
                    'recommendation': f'Pass function reference to {func_name}() instead of string'
                })
                results['security_score'] -= 12
            
            # Pattern: Function constructor with user input
            function_constructor_pattern = re.compile(
                r'new\s+Function\s*\([^)]*(?:location|document|window)[^)]*\)',
                re.IGNORECASE
            )
            
            matches = function_constructor_pattern.finditer(javascript_code)
            for match in matches:
                results['vulnerabilities'].append({
                    'type': 'FUNCTION_CONSTRUCTOR',
                    'severity': 'CRITICAL',
                    'description': 'Function constructor called with potentially unsafe input',
                    'line': javascript_code[:match.start()].count('\n') + 1,
                    'column': match.start() - javascript_code[:match.start()].rfind('\n'),
                    'code_snippet': match.group(0),
                    'recommendation': 'Avoid using Function constructor with dynamic input'
                })
                results['security_score'] -= 20
            
            # Check for missing "use strict"
            if '"use strict"' not in javascript_code and "'use strict'" not in javascript_code:
                results['informational'].append({
                    'type': 'NO_STRICT_MODE',
                    'severity': 'LOW',
                    'description': 'JavaScript not using strict mode',
                    'line': 1,
                    'column': 0,
                    'recommendation': 'Add "use strict" directive to enable strict mode'
                })
                results['security_score'] -= 2
                
        except Exception as e:
            logger.error(f"Error during AST analysis: {e}")
            results['warnings'].append({
                'type': 'AST_ANALYSIS_ERROR',
                'severity': 'LOW',
                'description': f'AST analysis error: {str(e)}'
            })
    
    def _generate_cache_key(self, javascript_code: str, source_url: str) -> str:
        """
        Generate cache key for JavaScript analysis
        
        Args:
            javascript_code: JavaScript code
            source_url: Source URL
            
        Returns:
            Cache key string
        """
        # Create a hash of the code and URL for caching
        content_hash = hashlib.md5(javascript_code.encode()).hexdigest()
        url_hash = hashlib.md5(source_url.encode()).hexdigest()
        return f"{content_hash}:{url_hash}"
    
    def _create_empty_result(self, source_url: str) -> Dict[str, Any]:
        """
        Create empty analysis result structure
        
        Args:
            source_url: Source URL
            
        Returns:
            Empty results dictionary
        """
        return {
            'source_url': source_url,
            'script_hash': '',
            'script_length': 0,
            'vulnerabilities': [],
            'warnings': [],
            'informational': [],
            'security_score': 0,
            'analysis_methods': [],
            'metadata': {},
            'risk_level': 'UNKNOWN'
        }
    
    def _calculate_risk_level(self, results: Dict[str, Any]) -> str:
        """
        Calculate overall risk level based on analysis results
        
        Args:
            results: Analysis results dictionary
            
        Returns:
            Risk level string (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL)
        """
        # Count vulnerabilities by severity
        critical_count = len([v for v in results['vulnerabilities'] 
                            if v.get('severity') == 'CRITICAL'])
        high_count = len([v for v in results['vulnerabilities'] 
                         if v.get('severity') == 'HIGH'])
        medium_count = len([v for v in results['vulnerabilities'] 
                          if v.get('severity') == 'MEDIUM'])
        
        # Determine risk level based on counts
        if critical_count > 0:
            return 'CRITICAL'
        elif high_count > 0:
            return 'HIGH'
        elif medium_count > 0:
            return 'MEDIUM'
        elif results.get('security_score', 100) < 70:
            return 'MEDIUM'
        elif results.get('security_score', 100) < 85:
            return 'LOW'
        else:
            return 'INFORMATIONAL'
    
    def _resolve_url(self, base_url: str, relative_url: str) -> str:
        """
        Resolve relative URL against base URL
        
        Args:
            base_url: Base URL
            relative_url: Relative URL
            
        Returns:
            Resolved absolute URL
        """
        try:
            if not base_url:
                return relative_url
            
            # Simple URL resolution
            if relative_url.startswith(('http://', 'https://', '//')):
                return relative_url
            
            # Remove query string and fragment from base URL
            base_parts = urlparse(base_url)
            base_path = base_parts.path
            
            if relative_url.startswith('/'):
                # Absolute path
                return f"{base_parts.scheme}://{base_parts.netloc}{relative_url}"
            else:
                # Relative path
                base_dir = base_path[:base_path.rfind('/') + 1] if '/' in base_path else '/'
                return f"{base_parts.scheme}://{base_parts.netloc}{base_dir}{relative_url}"
                
        except Exception as e:
            logger.warning(f"Error resolving URL {relative_url} against base {base_url}: {e}")
            return relative_url
    
    def _is_higher_risk(self, risk1: str, risk2: str) -> bool:
        """
        Check if risk1 is higher than risk2
        
        Args:
            risk1: First risk level
            risk2: Second risk level
            
        Returns:
            True if risk1 is higher than risk2
        """
        risk_levels = {
            'CRITICAL': 4,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1,
            'INFORMATIONAL': 0,
            'UNKNOWN': 0
        }
        
        return risk_levels.get(risk1.upper(), 0) > risk_levels.get(risk2.upper(), 0)
    
    def clear_cache(self) -> None:
        """Clear the analysis cache"""
        self.analysis_cache.clear()
        logger.info("JavaScript analyzer cache cleared")
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get analyzer statistics
        
        Returns:
            Dictionary containing analyzer statistics
        """
        return {
            'cache_size': len(self.analysis_cache),
            'config': {
                'enable_ast_analysis': self.config['enable_ast_analysis'],
                'enable_regex_analysis': self.config['enable_regex_analysis'],
                'max_script_size': self.config['max_script_size']
            },
            'patterns_loaded': {
                'dangerous_functions': len(self.config['dangerous_functions']),
                'dangerous_sinks': len(self.config['dangerous_sinks']),
                'sensitive_patterns': len(self.config['sensitive_data_patterns'])
            }
        }


# Helper function for standalone analysis
def analyze_javascript_file(file_path: str) -> Dict[str, Any]:
    """
    Analyze JavaScript file from disk
    
    Args:
        file_path: Path to JavaScript file
        
    Returns:
        Analysis results
    """
    analyzer = JavaScriptAnalyzer()
    
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            javascript_code = file.read()
        
        return analyzer.analyze_javascript(javascript_code, f"file://{file_path}")
        
    except FileNotFoundError:
        logger.error(f"JavaScript file not found: {file_path}")
        return analyzer._create_empty_result(f"file://{file_path}")
    except UnicodeDecodeError:
        logger.error(f"Encoding error reading file: {file_path}")
        return analyzer._create_empty_result(f"file://{file_path}")
    except Exception as e:
        logger.error(f"Error analyzing JavaScript file {file_path}: {e}")
        return analyzer._create_empty_result(f"file://{file_path}")


# Example usage and testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Example JavaScript code with vulnerabilities
    test_javascript = """
    // Dangerous JavaScript example
    var userInput = location.hash.substring(1);
    eval(userInput);  // Critical vulnerability
    
    document.getElementById("content").innerHTML = userInput;  // XSS sink
    
    var password = "secret123";  // Sensitive data exposure
    
    setTimeout("alert('Hello')", 1000);  // Insecure timer
    """
    
    # Create analyzer
    analyzer = JavaScriptAnalyzer()
    
    # Analyze the JavaScript
    results = analyzer.analyze_javascript(test_javascript, "test://example.js")
    
    # Print results
    print("JavaScript Analysis Results:")
    print(f"Security Score: {results['security_score']}/100")
    print(f"Risk Level: {results['risk_level']}")
    print(f"Total Vulnerabilities: {len(results['vulnerabilities'])}")
    print(f"Total Warnings: {len(results['warnings'])}")
    
    # Print vulnerabilities
    if results['vulnerabilities']:
        print("\nVulnerabilities Found:")
        for vuln in results['vulnerabilities']:
            print(f"  - {vuln['type']}: {vuln['description']} (Line {vuln['line']})")
    
    # Print warnings
    if results['warnings']:
        print("\nWarnings:")
        for warning in results['warnings']:
            print(f"  - {warning['type']}: {warning['description']} (Line {warning['line']})")