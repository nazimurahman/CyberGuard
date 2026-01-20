# src/agents/code_review_agent.py
"""
Secure Code Review Agent
Specialized agent for static code analysis and secure coding practices
Detects security vulnerabilities in source code before deployment
"""

import torch
import re
import ast
import tokenize
import io
from typing import Dict, List, Any, Optional, Tuple, Set
from datetime import datetime
from enum import Enum
import hashlib
from dataclasses import dataclass, asdict

# Enum for code vulnerability severity
class VulnerabilitySeverity(Enum):
    """Code vulnerability severity levels"""
    CRITICAL = "critical"    # Immediate remediation required
    HIGH = "high"           # High priority remediation
    MEDIUM = "medium"       # Should be addressed
    LOW = "low"            # Consider addressing
    INFO = "info"          # Informational only

# Enum for programming languages
class ProgrammingLanguage(Enum):
    """Supported programming languages for code analysis"""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    JAVA = "java"
    PHP = "php"
    GO = "go"
    RUBY = "ruby"
    CSHARP = "csharp"
    CPP = "cpp"
    TYPESCRIPT = "typescript"

# Data class for code vulnerability
@dataclass
class CodeVulnerability:
    """Individual code vulnerability finding"""
    vulnerability_id: str           # Unique identifier
    severity: VulnerabilitySeverity # Severity level
    category: str                  # Vulnerability category
    language: ProgrammingLanguage  # Programming language
    file_path: str                # File where found
    line_number: int              # Line number
    code_snippet: str             # Vulnerable code snippet
    description: str              # Description of vulnerability
    cwe_id: Optional[str]         # Common Weakness Enumeration ID
    cvss_score: Optional[float]   # CVSS score if available
    fix_recommendation: str       # How to fix
    safe_example: str             # Safe code example
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['language'] = self.language.value
        return data

# Data class for code review result
@dataclass
class CodeReviewResult:
    """Complete code review result"""
    review_id: str
    timestamp: datetime
    files_reviewed: int
    vulnerabilities_found: int
    vulnerability_distribution: Dict[str, int]  # severity -> count
    total_lines: int
    security_score: float  # 0.0 to 1.0
    recommendations: List[str]
    vulnerabilities: List[CodeVulnerability]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['vulnerabilities'] = [v.to_dict() for v in self.vulnerabilities]
        return data

class SecureCodeReviewAgent:
    """
    Secure Code Review Agent
    Performs static analysis of source code for security vulnerabilities
    Supports multiple programming languages
    """
    
    def __init__(self, agent_id: str = "code_review_001"):
        """
        Initialize Secure Code Review Agent
        
        Args:
            agent_id: Unique identifier for this agent instance
        """
        self.agent_id = agent_id
        self.name = "Secure Code Review Agent"
        
        # Language-specific analyzers
        self.analyzers = {
            ProgrammingLanguage.PYTHON: self._analyze_python_code,
            ProgrammingLanguage.JAVASCRIPT: self._analyze_javascript_code,
            ProgrammingLanguage.JAVA: self._analyze_java_code,
            ProgrammingLanguage.PHP: self._analyze_php_code
        }
        
        # Vulnerability patterns database
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        
        # Secure coding standards
        self.coding_standards = self._load_coding_standards()
        
        # Review history
        self.review_history: List[CodeReviewResult] = []
        self.max_history = 50
        
        # Performance metrics
        self.confidence = 0.85
        self.reviews_completed = 0
        self.vulnerabilities_detected = 0
        self.false_positives = 0
        self.average_security_score = 0.0
        
        # Language detection patterns
        self.language_patterns = {
            ProgrammingLanguage.PYTHON: ['.py', '#!/usr/bin/env python', '#!/usr/bin/python'],
            ProgrammingLanguage.JAVASCRIPT: ['.js', '.jsx', '#!/usr/bin/env node'],
            ProgrammingLanguage.JAVA: ['.java', 'public class', 'import java.'],
            ProgrammingLanguage.PHP: ['.php', '<?php', '#!/usr/bin/env php'],
            ProgrammingLanguage.GO: ['.go', 'package main', 'import "'],
            ProgrammingLanguage.RUBY: ['.rb', '#!/usr/bin/env ruby', 'require '],
            ProgrammingLanguage.CSHARP: ['.cs', 'using System;', 'namespace '],
            ProgrammingLanguage.CPP: ['.cpp', '.hpp', '#include <', 'using namespace'],
            ProgrammingLanguage.TYPESCRIPT: ['.ts', '.tsx', 'import {', 'export ']
        }
    
    def _load_vulnerability_patterns(self) -> Dict[ProgrammingLanguage, List[Dict[str, Any]]]:
        """
        Load vulnerability patterns for each language
        
        Returns:
            Dictionary mapping languages to vulnerability patterns
        """
        patterns = {}
        
        # Python vulnerability patterns
        patterns[ProgrammingLanguage.PYTHON] = [
            {
                'id': 'PY-SQLI-001',
                'name': 'SQL Injection',
                'pattern': r'(?:execute|executemany|callproc)\s*\(.*?\%.*?\)',
                'description': 'Potential SQL injection via string formatting',
                'severity': VulnerabilitySeverity.CRITICAL,
                'cwe': 'CWE-89',
                'cvss': 9.8,
                'fix': 'Use parameterized queries or ORM',
                'example': {
                    'bad': 'cursor.execute("SELECT * FROM users WHERE id = %s" % user_input)',
                    'good': 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))'
                }
            },
            {
                'id': 'PY-CMD-001',
                'name': 'Command Injection',
                'pattern': r'(?:os\.system|subprocess\.call|subprocess\.Popen)\s*\(.*?\+.*?\)',
                'description': 'Potential command injection via string concatenation',
                'severity': VulnerabilitySeverity.CRITICAL,
                'cwe': 'CWE-78',
                'cvss': 9.1,
                'fix': 'Use subprocess with shell=False and validate inputs',
                'example': {
                    'bad': 'os.system("ls " + user_input)',
                    'good': 'subprocess.run(["ls", sanitized_input], shell=False)'
                }
            },
            {
                'id': 'PY-XSS-001',
                'name': 'Cross-Site Scripting',
                'pattern': r'print\s*\(.*?\+.*?\)|return\s+.*?\+.*?',
                'description': 'Potential XSS in web applications',
                'severity': VulnerabilitySeverity.HIGH,
                'cwe': 'CWE-79',
                'cvss': 8.2,
                'fix': 'Escape HTML output, use template engines',
                'example': {
                    'bad': 'return "<div>" + user_input + "</div>"',
                    'good': 'return "<div>" + html.escape(user_input) + "</div>"'
                }
            },
            {
                'id': 'PY-PICKLE-001',
                'name': 'Insecure Deserialization',
                'pattern': r'(?:pickle\.loads|pickle\.load|cPickle\.)',
                'description': 'Insecure deserialization can lead to RCE',
                'severity': VulnerabilitySeverity.CRITICAL,
                'cwe': 'CWE-502',
                'cvss': 9.8,
                'fix': 'Avoid pickle for untrusted data, use JSON or signed serialization',
                'example': {
                    'bad': 'data = pickle.loads(user_input)',
                    'good': 'data = json.loads(user_input)'
                }
            },
            {
                'id': 'PY-PATH-001',
                'name': 'Path Traversal',
                'pattern': r'open\s*\(.*?\+.*?\)|with\s+open\s*\(.*?\+.*?\)',
                'description': 'Potential path traversal vulnerability',
                'severity': VulnerabilitySeverity.HIGH,
                'cwe': 'CWE-22',
                'cvss': 7.5,
                'fix': 'Validate and sanitize file paths, use os.path.join',
                'example': {
                    'bad': 'open("/var/www/" + filename)',
                    'good': 'safe_path = os.path.join("/var/www/", os.path.basename(filename))'
                }
            },
            {
                'id': 'PY-HARDCODED-001',
                'name': 'Hardcoded Secrets',
                'pattern': r'(?:password|secret|key|token)\s*=\s*[\'"][^\'"]{8,}[\'"]',
                'description': 'Hardcoded passwords or API keys',
                'severity': VulnerabilitySeverity.HIGH,
                'cwe': 'CWE-798',
                'cvss': 7.5,
                'fix': 'Use environment variables or secret management',
                'example': {
                    'bad': 'API_KEY = "sk_live_1234567890abcdef"',
                    'good': 'API_KEY = os.environ.get("API_KEY")'
                }
            },
            {
                'id': 'PY-SSL-001',
                'name': 'SSL Verification Disabled',
                'pattern': r'verify\s*=\s*False|ssl\._create_unverified_context',
                'description': 'SSL certificate verification disabled',
                'severity': VulnerabilitySeverity.HIGH,
                'cwe': 'CWE-295',
                'cvss': 7.4,
                'fix': 'Always verify SSL certificates',
                'example': {
                    'bad': 'requests.get(url, verify=False)',
                    'good': 'requests.get(url, verify=True)'
                }
            }
        ]
        
        # JavaScript vulnerability patterns
        patterns[ProgrammingLanguage.JAVASCRIPT] = [
            {
                'id': 'JS-EVAL-001',
                'name': 'Unsafe eval() Usage',
                'pattern': r'eval\s*\(|Function\s*\(|setTimeout\s*\([^,]+\)|setInterval\s*\([^,]+\)',
                'description': 'Unsafe eval() can lead to code injection',
                'severity': VulnerabilitySeverity.CRITICAL,
                'cwe': 'CWE-95',
                'cvss': 9.8,
                'fix': 'Avoid eval(), use JSON.parse() for JSON',
                'example': {
                    'bad': 'eval(userInput)',
                    'good': 'JSON.parse(userInput)'
                }
            },
            {
                'id': 'JS-INNERHTML-001',
                'name': 'Unsafe innerHTML Assignment',
                'pattern': r'innerHTML\s*=\s*',
                'description': 'Potential XSS via innerHTML',
                'severity': VulnerabilitySeverity.HIGH,
                'cwe': 'CWE-79',
                'cvss': 8.2,
                'fix': 'Use textContent or sanitize input',
                'example': {
                    'bad': 'element.innerHTML = userInput',
                    'good': 'element.textContent = userInput'
                }
            }
        ]
        
        # Java vulnerability patterns
        patterns[ProgrammingLanguage.JAVA] = [
            {
                'id': 'JAVA-SQLI-001',
                'name': 'SQL Injection',
                'pattern': r'\.executeQuery\s*\(.*?\+\).*?|\.executeUpdate\s*\(.*?\+\).*?',
                'description': 'SQL injection via string concatenation',
                'severity': VulnerabilitySeverity.CRITICAL,
                'cwe': 'CWE-89',
                'cvss': 9.8,
                'fix': 'Use PreparedStatement with parameterized queries',
                'example': {
                    'bad': 'stmt.executeQuery("SELECT * FROM users WHERE id = " + input)',
                    'good': 'PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?")'
                }
            }
        ]
        
        return patterns
    
    def _load_coding_standards(self) -> Dict[str, List[str]]:
        """
        Load secure coding standards
        
        Returns:
            Dictionary of coding standards by category
        """
        return {
            'authentication': [
                'Implement strong password policies',
                'Use multi-factor authentication',
                'Secure password storage (bcrypt, Argon2)',
                'Implement account lockout mechanisms',
                'Secure password reset flows'
            ],
            'authorization': [
                'Implement principle of least privilege',
                'Use role-based access control (RBAC)',
                'Validate permissions on every request',
                'Implement proper session management',
                'Log access control failures'
            ],
            'input_validation': [
                'Validate all user inputs',
                'Use allow lists over block lists',
                'Validate data type, length, range, format',
                'Sanitize output for different contexts',
                'Use parameterized queries for databases'
            ],
            'cryptography': [
                'Use strong, standard algorithms (AES-256, RSA-2048+)',
                'Use cryptographically secure random number generators',
                'Protect encryption keys',
                'Use TLS 1.2+ for data in transit',
                'Regularly update cryptographic libraries'
            ],
            'error_handling': [
                'Use generic error messages for users',
                'Log detailed errors for administrators',
                'Avoid exposing stack traces',
                'Implement proper exception handling',
                'Fail securely'
            ],
            'logging': [
                'Log security events (logins, failures, access)',
                'Protect log files from unauthorized access',
                'Regularly review logs',
                'Implement log rotation',
                'Use immutable logging where possible'
            ]
        }
    
    def detect_language(self, code: str, filename: str = '') -> Optional[ProgrammingLanguage]:
        """
        Detect programming language from code and filename
        
        Args:
            code: Source code content
            filename: Optional filename with extension
            
        Returns:
            Detected ProgrammingLanguage or None
        """
        # First check filename extension
        if filename:
            for lang, patterns in self.language_patterns.items():
                for pattern in patterns:
                    if pattern.startswith('.') and filename.endswith(pattern):
                        return lang
        
        # Check code content for language signatures
        code_lower = code.lower()
        
        for lang, patterns in self.language_patterns.items():
            for pattern in patterns:
                if not pattern.startswith('.') and pattern.lower() in code_lower:
                    return lang
        
        # Try to detect by common syntax
        if 'def ' in code_lower and 'import ' in code_lower:
            return ProgrammingLanguage.PYTHON
        elif 'function ' in code_lower and 'var ' in code_lower:
            return ProgrammingLanguage.JAVASCRIPT
        elif 'public class ' in code_lower and 'import ' in code_lower:
            return ProgrammingLanguage.JAVA
        elif '<?php' in code_lower:
            return ProgrammingLanguage.PHP
        
        return None
    
    def analyze(self, security_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze code for security vulnerabilities
        
        Args:
            security_data: Dictionary containing:
                - code: Source code to analyze
                - filename: Optional filename
                - language: Optional programming language
                - context: Optional context (web, api, cli, etc.)
                
        Returns:
            Dictionary with code analysis results
        """
        import time
        start_time = time.time()
        
        # Extract code data
        code = security_data.get('code', '')
        filename = security_data.get('filename', 'unknown')
        specified_language = security_data.get('language')
        context = security_data.get('context', 'general')
        
        if not code:
            return {
                'error': 'No code provided for analysis',
                'agent_id': self.agent_id,
                'agent_name': self.name
            }
        
        # Detect or determine language
        if specified_language:
            try:
                language = ProgrammingLanguage(specified_language.lower())
            except ValueError:
                language = self.detect_language(code, filename)
        else:
            language = self.detect_language(code, filename)
        
        if not language:
            return {
                'error': f'Could not detect programming language for: {filename}',
                'agent_id': self.agent_id,
                'agent_name': self.name
            }
        
        # Step 1: Analyze code for vulnerabilities
        vulnerabilities = self._analyze_code(code, language, filename, context)
        
        # Step 2: Calculate security score
        security_score = self._calculate_security_score(vulnerabilities, len(code.split('\n')))
        
        # Step 3: Generate recommendations
        recommendations = self._generate_recommendations(vulnerabilities, language, context)
        
        # Step 4: Create review result
        review_id = self._generate_review_id(code)
        review_result = CodeReviewResult(
            review_id=review_id,
            timestamp=datetime.now(),
            files_reviewed=1,
            vulnerabilities_found=len(vulnerabilities),
            vulnerability_distribution=self._count_vulnerabilities_by_severity(vulnerabilities),
            total_lines=len(code.split('\n')),
            security_score=security_score,
            recommendations=recommendations,
            vulnerabilities=vulnerabilities
        )
        
        # Store in history
        self.review_history.append(review_result)
        if len(self.review_history) > self.max_history:
            self.review_history = self.review_history[-self.max_history:]
        
        # Step 5: Update metrics
        self.reviews_completed += 1
        self.vulnerabilities_detected += len(vulnerabilities)
        self.average_security_score = (
            self.average_security_score * 0.9 + security_score * 0.1
        )
        
        # Update confidence
        self._update_confidence(len(vulnerabilities), security_score)
        
        processing_time = time.time() - start_time
        
        return {
            'agent_id': self.agent_id,
            'agent_name': self.name,
            'language': language.value,
            'filename': filename,
            'review_id': review_id,
            'security_score': security_score,
            'security_status': self._get_security_status(security_score),
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerability_distribution': review_result.vulnerability_distribution,
            'critical_vulnerabilities': len([v for v in vulnerabilities 
                                           if v.severity == VulnerabilitySeverity.CRITICAL]),
            'recommendations': recommendations[:5],  # Top 5 recommendations
            'processing_time': processing_time,
            'confidence': self.confidence,
            'reasoning_state': self._get_reasoning_state(),
            'decision': {
                'risk_level': 1.0 - security_score,  # Invert for risk
                'confidence': self.confidence,
                'evidence': [v.description for v in vulnerabilities[:3]]  # Top 3
            },
            'detailed_results': review_result.to_dict()
        }
    
    def _analyze_code(self, code: str, language: ProgrammingLanguage,
                     filename: str, context: str) -> List[CodeVulnerability]:
        """
        Analyze code for vulnerabilities
        
        Args:
            code: Source code to analyze
            language: Programming language
            filename: Source filename
            context: Application context
            
        Returns:
            List of found vulnerabilities
        """
        vulnerabilities = []
        
        # Get language-specific analyzer
        analyzer = self.analyzers.get(language)
        if analyzer:
            vulnerabilities.extend(analyzer(code, filename, context))
        else:
            # Generic analysis for unsupported languages
            vulnerabilities.extend(self._generic_code_analysis(code, language, filename))
        
        # Check for hardcoded secrets (language-agnostic)
        vulnerabilities.extend(self._check_hardcoded_secrets(code, language, filename))
        
        # Check for insecure dependencies/comments
        vulnerabilities.extend(self._check_code_quality(code, language, filename))
        
        return vulnerabilities
    
    def _analyze_python_code(self, code: str, filename: str, 
                           context: str) -> List[CodeVulnerability]:
        """
        Analyze Python code for security vulnerabilities
        
        Args:
            code: Python source code
            filename: Source filename
            context: Application context
            
        Returns:
            List of Python vulnerabilities
        """
        vulnerabilities = []
        lines = code.split('\n')
        
        # Get Python-specific patterns
        patterns = self.vulnerability_patterns.get(ProgrammingLanguage.PYTHON, [])
        
        # Pattern matching
        for i, line in enumerate(lines, 1):
            line_lower = line.lower()
            
            for pattern_info in patterns:
                pattern = pattern_info['pattern']
                if re.search(pattern, line, re.IGNORECASE):
                    # Found potential vulnerability
                    vuln = CodeVulnerability(
                        vulnerability_id=pattern_info['id'],
                        severity=pattern_info['severity'],
                        category=pattern_info['name'],
                        language=ProgrammingLanguage.PYTHON,
                        file_path=filename,
                        line_number=i,
                        code_snippet=line.strip(),
                        description=pattern_info['description'],
                        cwe_id=pattern_info.get('cwe'),
                        cvss_score=pattern_info.get('cvss'),
                        fix_recommendation=pattern_info['fix'],
                        safe_example=pattern_info['example']['good']
                    )
                    vulnerabilities.append(vuln)
        
        # AST-based analysis for more complex patterns
        try:
            tree = ast.parse(code)
            vulnerabilities.extend(self._analyze_python_ast(tree, filename, context))
        except SyntaxError:
            # If code has syntax errors, can't parse AST
            pass
        
        return vulnerabilities
    
    def _analyze_python_ast(self, tree: ast.AST, filename: str,
                          context: str) -> List[CodeVulnerability]:
        """
        Analyze Python AST for complex vulnerabilities
        
        Args:
            tree: Python AST
            filename: Source filename
            context: Application context
            
        Returns:
            List of vulnerabilities found via AST
        """
        vulnerabilities = []
        
        class SecurityVisitor(ast.NodeVisitor):
            def __init__(self, filename):
                self.filename = filename
                self.vulnerabilities = []
            
            def visit_Call(self, node):
                # Check for dangerous function calls
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    
                    # Check for eval
                    if func_name == 'eval' and node.args:
                        vuln = CodeVulnerability(
                            vulnerability_id='PY-EVAL-001',
                            severity=VulnerabilitySeverity.CRITICAL,
                            category='Dangerous Function',
                            language=ProgrammingLanguage.PYTHON,
                            file_path=self.filename,
                            line_number=node.lineno,
                            code_snippet=ast.unparse(node),
                            description='eval() function can execute arbitrary code',
                            cwe_id='CWE-95',
                            cvss_score=9.8,
                            fix_recommendation='Avoid eval(), use safer alternatives',
                            safe_example='json.loads() for JSON, ast.literal_eval() for literals'
                        )
                        self.vulnerabilities.append(vuln)
                
                self.generic_visit(node)
        
        visitor = SecurityVisitor(filename)
        visitor.visit(tree)
        vulnerabilities.extend(visitor.vulnerabilities)
        
        return vulnerabilities
    
    def _analyze_javascript_code(self, code: str, filename: str,
                               context: str) -> List[CodeVulnerability]:
        """
        Analyze JavaScript code for security vulnerabilities
        
        Args:
            code: JavaScript source code
            filename: Source filename
            context: Application context
            
        Returns:
            List of JavaScript vulnerabilities
        """
        vulnerabilities = []
        lines = code.split('\n')
        
        # Get JavaScript patterns
        patterns = self.vulnerability_patterns.get(ProgrammingLanguage.JAVASCRIPT, [])
        
        for i, line in enumerate(lines, 1):
            for pattern_info in patterns:
                pattern = pattern_info['pattern']
                if re.search(pattern, line, re.IGNORECASE):
                    vuln = CodeVulnerability(
                        vulnerability_id=pattern_info['id'],
                        severity=pattern_info['severity'],
                        category=pattern_info['name'],
                        language=ProgrammingLanguage.JAVASCRIPT,
                        file_path=filename,
                        line_number=i,
                        code_snippet=line.strip(),
                        description=pattern_info['description'],
                        cwe_id=pattern_info.get('cwe'),
                        cvss_score=pattern_info.get('cvss'),
                        fix_recommendation=pattern_info['fix'],
                        safe_example=pattern_info['example']['good']
                    )
                    vulnerabilities.append(vuln)
        
        # Additional checks for web context
        if context == 'web':
            vulnerabilities.extend(self._check_javascript_web_context(code, filename))
        
        return vulnerabilities
    
    def _analyze_java_code(self, code: str, filename: str,
                         context: str) -> List[CodeVulnerability]:
        """Analyze Java code"""
        vulnerabilities = []
        lines = code.split('\n')
        
        patterns = self.vulnerability_patterns.get(ProgrammingLanguage.JAVA, [])
        
        for i, line in enumerate(lines, 1):
            for pattern_info in patterns:
                pattern = pattern_info['pattern']
                if re.search(pattern, line, re.IGNORECASE):
                    vuln = CodeVulnerability(
                        vulnerability_id=pattern_info['id'],
                        severity=pattern_info['severity'],
                        category=pattern_info['name'],
                        language=ProgrammingLanguage.JAVA,
                        file_path=filename,
                        line_number=i,
                        code_snippet=line.strip(),
                        description=pattern_info['description'],
                        cwe_id=pattern_info.get('cwe'),
                        cvss_score=pattern_info.get('cvss'),
                        fix_recommendation=pattern_info['fix'],
                        safe_example=pattern_info['example']['good']
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _analyze_php_code(self, code: str, filename: str,
                        context: str) -> List[CodeVulnerability]:
        """Analyze PHP code"""
        vulnerabilities = []
        
        # Common PHP vulnerabilities
        php_patterns = [
            {
                'pattern': r'eval\s*\(.*?\$',
                'description': 'Unsafe eval() with user input',
                'severity': VulnerabilitySeverity.CRITICAL,
                'category': 'Code Injection'
            },
            {
                'pattern': r'system\s*\(.*?\$|exec\s*\(.*?\$|shell_exec\s*\(.*?\$',
                'description': 'Command injection vulnerability',
                'severity': VulnerabilitySeverity.CRITICAL,
                'category': 'Command Injection'
            },
            {
                'pattern': r'\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\[.*?\]\s*\.',
                'description': 'Potential SQL injection via concatenation',
                'severity': VulnerabilitySeverity.HIGH,
                'category': 'SQL Injection'
            }
        ]
        
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            for pattern_info in php_patterns:
                if re.search(pattern_info['pattern'], line, re.IGNORECASE):
                    vuln = CodeVulnerability(
                        vulnerability_id=f'PHP-{hashlib.md5(pattern_info["pattern"].encode()).hexdigest()[:8]}',
                        severity=pattern_info['severity'],
                        category=pattern_info['category'],
                        language=ProgrammingLanguage.PHP,
                        file_path=filename,
                        line_number=i,
                        code_snippet=line.strip(),
                        description=pattern_info['description'],
                        cwe_id='CWE-78',
                        cvss_score=9.1,
                        fix_recommendation='Use prepared statements, validate inputs',
                        safe_example='$stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");'
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _generic_code_analysis(self, code: str, language: ProgrammingLanguage,
                             filename: str) -> List[CodeVulnerability]:
        """Generic code analysis for unsupported languages"""
        vulnerabilities = []
        lines = code.split('\n')
        
        # Look for common dangerous patterns
        dangerous_patterns = [
            (r'eval\s*\(', 'Code Injection', VulnerabilitySeverity.CRITICAL),
            (r'system\s*\(|exec\s*\(', 'Command Injection', VulnerabilitySeverity.CRITICAL),
            (r'SELECT.*?\+\s*|INSERT.*?\+\s*', 'SQL Injection', VulnerabilitySeverity.CRITICAL),
            (r'password\s*=\s*[\'\"].*?[\'\"]', 'Hardcoded Password', VulnerabilitySeverity.HIGH),
            (r'secret\s*=\s*[\'\"].*?[\'\"]', 'Hardcoded Secret', VulnerabilitySeverity.HIGH),
            (r'key\s*=\s*[\'\"].*?[\'\"]', 'Hardcoded API Key', VulnerabilitySeverity.HIGH),
            (r'http://', 'Insecure HTTP', VulnerabilitySeverity.MEDIUM)
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern, category, severity in dangerous_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vuln = CodeVulnerability(
                        vulnerability_id=f'GEN-{hashlib.md5(pattern.encode()).hexdigest()[:8]}',
                        severity=severity,
                        category=category,
                        language=language,
                        file_path=filename,
                        line_number=i,
                        code_snippet=line.strip(),
                        description=f'Potential {category.lower()} vulnerability',
                        cwe_id='CWE-20',  # Improper Input Validation
                        cvss_score=7.5 if severity == VulnerabilitySeverity.CRITICAL else 5.0,
                        fix_recommendation='Validate and sanitize all inputs',
                        safe_example='Use parameterized queries and input validation'
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_hardcoded_secrets(self, code: str, language: ProgrammingLanguage,
                               filename: str) -> List[CodeVulnerability]:
        """Check for hardcoded secrets in code"""
        vulnerabilities = []
        lines = code.split('\n')
        
        # Common secret patterns
        secret_patterns = [
            (r'api[_-]?key\s*=\s*[\'\"][A-Za-z0-9_-]{20,}[\'\"]', 'API Key', VulnerabilitySeverity.HIGH),
            (r'access[_-]?token\s*=\s*[\'\"][A-Za-z0-9_-]{20,}[\'\"]', 'Access Token', VulnerabilitySeverity.HIGH),
            (r'secret[_-]?key\s*=\s*[\'\"][A-Za-z0-9_-]{20,}[\'\"]', 'Secret Key', VulnerabilitySeverity.HIGH),
            (r'password\s*=\s*[\'\"].{8,}[\'\"]', 'Password', VulnerabilitySeverity.HIGH),
            (r'private[_-]?key\s*=\s*[\'\"].{20,}[\'\"]', 'Private Key', VulnerabilitySeverity.CRITICAL),
            (r'aws[_-]?(?:access[_-]?key|secret[_-]?key)\s*=\s*[\'\"].{20,}[\'\"]', 'AWS Credentials', VulnerabilitySeverity.CRITICAL)
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern, secret_type, severity in secret_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Mask the secret in the code snippet
                    masked_line = re.sub(r'[\'\"][A-Za-z0-9_-]{20,}[\'\"]', '\'***MASKED***\'', line)
                    
                    vuln = CodeVulnerability(
                        vulnerability_id=f'SECRET-{hashlib.md5(pattern.encode()).hexdigest()[:8]}',
                        severity=severity,
                        category='Hardcoded Secret',
                        language=language,
                        file_path=filename,
                        line_number=i,
                        code_snippet=masked_line.strip(),
                        description=f'Hardcoded {secret_type} found in code',
                        cwe_id='CWE-798',
                        cvss_score=7.5,
                        fix_recommendation=f'Remove hardcoded {secret_type}, use environment variables or secret management',
                        safe_example=f'{secret_type} = os.environ.get("{secret_type.upper().replace(" ", "_")}")'
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_javascript_web_context(self, code: str, filename: str) -> List[CodeVulnerability]:
        """Additional checks for JavaScript in web context"""
        vulnerabilities = []
        lines = code.split('\n')
        
        # DOM-based XSS patterns
        dom_xss_patterns = [
            (r'document\.write\s*\(.*?\+.*?\)', 'document.write with concatenation', VulnerabilitySeverity.HIGH),
            (r'\.src\s*=\s*.+?\+', 'Dynamic script src with concatenation', VulnerabilitySeverity.HIGH),
            (r'location\.(?:href|hash|search)\s*=\s*.+?\+', 'Dynamic location assignment', VulnerabilitySeverity.MEDIUM),
            (r'innerHTML\s*=\s*.+?\+', 'innerHTML with concatenation', VulnerabilitySeverity.HIGH)
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern, description, severity in dom_xss_patterns:
                if re.search(pattern, line):
                    vuln = CodeVulnerability(
                        vulnerability_id=f'JS-DOM-{hashlib.md5(pattern.encode()).hexdigest()[:8]}',
                        severity=severity,
                        category='DOM-based XSS',
                        language=ProgrammingLanguage.JAVASCRIPT,
                        file_path=filename,
                        line_number=i,
                        code_snippet=line.strip(),
                        description=description,
                        cwe_id='CWE-79',
                        cvss_score=8.2,
                        fix_recommendation='Validate and sanitize all DOM inputs, use textContent instead of innerHTML',
                        safe_example='element.textContent = sanitizedInput'
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_code_quality(self, code: str, language: ProgrammingLanguage,
                          filename: str) -> List[CodeVulnerability]:
        """Check for code quality issues that impact security"""
        vulnerabilities = []
        lines = code.split('\n')
        
        # Look for TODO/FIXME comments with security implications
        for i, line in enumerate(lines, 1):
            line_lower = line.lower()
            if 'todo' in line_lower or 'fixme' in line_lower:
                # Check if it's security-related
                security_keywords = ['security', 'vulnerability', 'injection', 'xss', 
                                   'sql', 'auth', 'encrypt', 'ssl', 'tls']
                
                if any(keyword in line_lower for keyword in security_keywords):
                    vuln = CodeVulnerability(
                        vulnerability_id=f'QUALITY-{i}',
                        severity=VulnerabilitySeverity.MEDIUM,
                        category='Security Todo',
                        language=language,
                        file_path=filename,
                        line_number=i,
                        code_snippet=line.strip(),
                        description='Security-related TODO/FIXME comment found',
                        cwe_id='CWE-546',
                        cvss_score=3.5,
                        fix_recommendation='Address the security TODO/FIXME comment',
                        safe_example='Implement the security fix described in the comment'
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _calculate_security_score(self, vulnerabilities: List[CodeVulnerability],
                                total_lines: int) -> float:
        """
        Calculate security score for the code
        
        Args:
            vulnerabilities: List of found vulnerabilities
            total_lines: Total lines of code
            
        Returns:
            Security score from 0.0 to 1.0
        """
        if total_lines == 0:
            return 1.0  # Empty code is perfectly secure?
        
        # Weight vulnerabilities by severity
        severity_weights = {
            VulnerabilitySeverity.CRITICAL: 10.0,
            VulnerabilitySeverity.HIGH: 5.0,
            VulnerabilitySeverity.MEDIUM: 2.0,
            VulnerabilitySeverity.LOW: 0.5,
            VulnerabilitySeverity.INFO: 0.1
        }
        
        # Calculate vulnerability density
        total_weight = sum(severity_weights[v.severity] for v in vulnerabilities)
        
        # Normalize by code size (vulnerabilities per 100 lines)
        density = (total_weight / max(total_lines, 1)) * 100
        
        # Convert to score (0.0 to 1.0)
        # Exponential decay: score = e^(-density/10)
        import math
        score = math.exp(-density / 10.0)
        
        return max(0.0, min(1.0, score))
    
    def _count_vulnerabilities_by_severity(self, 
                                         vulnerabilities: List[CodeVulnerability]) -> Dict[str, int]:
        """Count vulnerabilities by severity level"""
        counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for vuln in vulnerabilities:
            severity_key = vuln.severity.value
            if severity_key in counts:
                counts[severity_key] += 1
        
        return counts
    
    def _generate_recommendations(self, vulnerabilities: List[CodeVulnerability],
                                language: ProgrammingLanguage,
                                context: str) -> List[str]:
        """
        Generate security recommendations
        
        Args:
            vulnerabilities: List of found vulnerabilities
            language: Programming language
            context: Application context
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        # Add recommendations based on vulnerabilities
        if vulnerabilities:
            # Group by category
            categories = {}
            for vuln in vulnerabilities:
                if vuln.severity in [VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH]:
                    if vuln.category not in categories:
                        categories[vuln.category] = []
                    categories[vuln.category].append(vuln)
            
            # Generate category-based recommendations
            for category, vulns in categories.items():
                count = len(vulns)
                recommendations.append(f"🚨 Address {count} {category} vulnerabilities (critical/high severity)")
            
            # Top 3 specific fixes
            critical_vulns = [v for v in vulnerabilities 
                            if v.severity == VulnerabilitySeverity.CRITICAL]
            if critical_vulns:
                for vuln in critical_vulns[:3]:
                    recommendations.append(f"• {vuln.fix_recommendation}")
        
        # Add context-specific recommendations
        if context == 'web':
            recommendations.extend([
                "🔒 Implement Content Security Policy (CSP)",
                "🛡️ Add security headers (X-Frame-Options, X-Content-Type-Options)",
                "🔐 Use HTTPS and enforce HSTS",
                "🧹 Sanitize all user inputs and outputs"
            ])
        elif context == 'api':
            recommendations.extend([
                "🔐 Implement proper authentication (JWT, OAuth2)",
                "🎯 Use rate limiting to prevent abuse",
                "📝 Validate all input against schemas",
                "🔒 Encrypt sensitive data in transit and at rest"
            ])
        
        # Add language-specific best practices
        lang_recommendations = {
            ProgrammingLanguage.PYTHON: [
                "🐍 Use virtual environments for dependency isolation",
                "📦 Keep dependencies updated and scan for vulnerabilities",
                "🔧 Use type hints and static analysis tools",
                "🚫 Avoid pickle for untrusted data"
            ],
            ProgrammingLanguage.JAVASCRIPT: [
                "🌐 Use strict mode ('use strict')",
                "🔒 Implement CORS properly",
                "🛡️ Use Content Security Policy for web apps",
                "🚫 Avoid eval() and innerHTML with user input"
            ],
            ProgrammingLanguage.JAVA: [
                "☕ Use prepared statements for database queries",
                "🔐 Implement proper input validation",
                "🛡️ Use security manager for sandboxing",
                "📝 Keep Java runtime updated"
            ]
        }
        
        if language in lang_recommendations:
            recommendations.extend(lang_recommendations[language])
        
        # Ensure unique recommendations
        return list(set(recommendations))[:10]  # Top 10 unique recommendations
    
    def _get_security_status(self, security_score: float) -> str:
        """Get human-readable security status"""
        if security_score >= 0.9:
            return "✅ EXCELLENT SECURITY"
        elif security_score >= 0.7:
            return "⚠️  GOOD SECURITY (Some improvements needed)"
        elif security_score >= 0.5:
            return "🔶 MODERATE SECURITY (Needs attention)"
        elif security_score >= 0.3:
            return "🔴 POOR SECURITY (Immediate action required)"
        else:
            return "🚨 CRITICAL SECURITY ISSUES"
    
    def _generate_review_id(self, code: str) -> str:
        """Generate unique review ID from code hash"""
        code_hash = hashlib.md5(code.encode()).hexdigest()[:16]
        timestamp = datetime.now().strftime("%Y%m%d%H%M")
        return f"REVIEW-{timestamp}-{code_hash}"
    
    def _update_confidence(self, vulnerabilities_found: int, 
                          security_score: float):
        """
        Update agent confidence based on review quality
        
        Args:
            vulnerabilities_found: Number of vulnerabilities found
            security_score: Overall security score
        """
        # Confidence increases when finding real issues
        if vulnerabilities_found > 0 and security_score < 0.7:
            # Found issues in insecure code (good detection)
            self.confidence = min(1.0, self.confidence * 1.05)
        elif vulnerabilities_found == 0 and security_score >= 0.9:
            # No issues in secure code (good system)
            self.confidence = min(1.0, self.confidence * 1.02)
        elif vulnerabilities_found == 0 and security_score < 0.5:
            # No issues but code is insecure (potentially missed issues)
            self.confidence = max(0.1, self.confidence * 0.9)
        else:
            # Maintain current confidence
            self.confidence = self.confidence * 0.99
    
    def _get_reasoning_state(self) -> torch.Tensor:
        """Get current reasoning state for mHC coordination"""
        features = []
        
        # Performance features
        features.append(self.confidence)
        features.append(self.reviews_completed / 1000.0)  # Normalized
        features.append(self.vulnerabilities_detected / 1000.0)  # Normalized
        features.append(self.average_security_score)
        
        # Recent review patterns
        recent_reviews = self.review_history[-5:] if self.review_history else []
        if recent_reviews:
            avg_vulns = sum(r.vulnerabilities_found for r in recent_reviews) / len(recent_reviews)
            avg_score = sum(r.security_score for r in recent_reviews) / len(recent_reviews)
            features.append(avg_vulns / 20.0)  # Normalized
            features.append(avg_score)
        else:
            features.extend([0.0, 0.5])
        
        # Language expertise distribution (simplified)
        features.append(0.8)  # Python expertise
        features.append(0.6)  # JavaScript expertise
        features.append(0.4)  # Other languages
        
        # Pad to 512 dimensions
        while len(features) < 512:
            features.append(0.0)
        
        return torch.tensor(features[:512], dtype=torch.float32)
    
    def get_agent_status(self) -> Dict[str, Any]:
        """Get current agent status and metrics"""
        return {
            'agent_id': self.agent_id,
            'agent_name': self.name,
            'confidence': self.confidence,
            'reviews_completed': self.reviews_completed,
            'vulnerabilities_detected': self.vulnerabilities_detected,
            'false_positives': self.false_positives,
            'average_security_score': self.average_security_score,
            'languages_supported': len(self.analyzers),
            'vulnerability_patterns_loaded': sum(len(patterns) 
                                               for patterns in self.vulnerability_patterns.values()),
            'recent_reviews': len(self.review_history)
        }