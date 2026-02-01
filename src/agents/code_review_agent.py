# src/agents/code_review_agent.py
"""
Secure Code Review Agent
Specialized agent for static code analysis and secure coding practices
Detects security vulnerabilities in source code before deployment
"""

# Standard library imports
import torch  # PyTorch for tensor operations and neural network support
import re  # Regular expressions for pattern matching
import ast  # Abstract Syntax Tree for parsing Python code
import json  # JSON processing for safe deserialization examples
import math  # Mathematical functions for security score calculations
import tokenize  # Tokenization for code parsing (though not heavily used)
import io  # Input/output operations
import time  # Time measurement for performance tracking
from typing import Dict, List, Any, Optional, Tuple, Set, Union  # Type hints for better code documentation
from datetime import datetime  # Timestamp generation
from enum import Enum  # Enumerations for type safety
import hashlib  # Hashing functions for unique ID generation
from dataclasses import dataclass, asdict  # Data classes for structured data storage

# Enum for code vulnerability severity levels
class VulnerabilitySeverity(Enum):
    """Code vulnerability severity levels"""
    CRITICAL = "critical"    # Immediate remediation required - highest severity
    HIGH = "high"           # High priority remediation
    MEDIUM = "medium"       # Should be addressed in next release
    LOW = "low"            # Consider addressing when possible
    INFO = "info"          # Informational only - no immediate security risk

# Enum for supported programming languages
class ProgrammingLanguage(Enum):
    """Supported programming languages for code analysis"""
    PYTHON = "python"        # Python programming language
    JAVASCRIPT = "javascript" # JavaScript programming language
    JAVA = "java"           # Java programming language
    PHP = "php"             # PHP programming language
    GO = "go"               # Go programming language
    RUBY = "ruby"           # Ruby programming language
    CSHARP = "csharp"       # C# programming language
    CPP = "cpp"             # C++ programming language
    TYPESCRIPT = "typescript" # TypeScript programming language

# Data class representing an individual code vulnerability finding
@dataclass  # Decorator to automatically generate boilerplate methods
class CodeVulnerability:
    """Individual code vulnerability finding with all relevant details"""
    vulnerability_id: str           # Unique identifier for the vulnerability
    severity: VulnerabilitySeverity # Severity level from the Enum
    category: str                  # Vulnerability category (SQLi, XSS, etc.)
    language: ProgrammingLanguage  # Programming language where found
    file_path: str                # File path where vulnerability was detected
    line_number: int              # Line number in the source file
    code_snippet: str             # Actual code containing the vulnerability
    description: str              # Detailed description of the vulnerability
    cwe_id: Optional[str]         # Common Weakness Enumeration ID for reference
    cvss_score: Optional[float]   # CVSS score for severity quantification
    fix_recommendation: str       # How to fix the vulnerability
    safe_example: str             # Example of safe code implementation
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert vulnerability object to dictionary for JSON serialization"""
        data = asdict(self)  # Convert dataclass to dictionary
        data['severity'] = self.severity.value  # Convert enum to string value
        data['language'] = self.language.value  # Convert enum to string value
        return data  # Return serializable dictionary

# Data class representing complete code review results
@dataclass
class CodeReviewResult:
    """Complete code review result containing all findings and metrics"""
    review_id: str  # Unique identifier for this review
    timestamp: datetime  # When the review was performed
    files_reviewed: int  # Number of files analyzed
    vulnerabilities_found: int  # Total vulnerabilities discovered
    vulnerability_distribution: Dict[str, int]  # Count of vulnerabilities by severity
    total_lines: int  # Total lines of code analyzed
    security_score: float  # Overall security score (0.0 to 1.0)
    recommendations: List[str]  # List of security recommendations
    vulnerabilities: List[CodeVulnerability]  # Detailed vulnerability findings
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert review result to dictionary for JSON serialization"""
        data = asdict(self)  # Convert dataclass to dictionary
        data['timestamp'] = self.timestamp.isoformat()  # Convert datetime to ISO string
        # Convert each vulnerability to dictionary format
        data['vulnerabilities'] = [v.to_dict() for v in self.vulnerabilities]
        return data  # Return serializable dictionary

# Main Secure Code Review Agent class
class SecureCodeReviewAgent:
    """
    Secure Code Review Agent
    Performs static analysis of source code for security vulnerabilities
    Supports multiple programming languages with pattern-based detection
    """
    
    def __init__(self, agent_id: str = "code_review_001"):
        """
        Initialize Secure Code Review Agent with default configuration
        
        Args:
            agent_id: Unique identifier for this agent instance
        """
        self.agent_id = agent_id  # Store agent ID
        self.name = "Secure Code Review Agent"  # Human-readable agent name
        
        # Dictionary mapping programming languages to their specific analysis functions
        self.analyzers = {
            ProgrammingLanguage.PYTHON: self._analyze_python_code,
            ProgrammingLanguage.JAVASCRIPT: self._analyze_javascript_code,
            ProgrammingLanguage.JAVA: self._analyze_java_code,
            ProgrammingLanguage.PHP: self._analyze_php_code
        }
        
        # Load vulnerability patterns for each supported language
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        
        # Load secure coding standards for generating recommendations
        self.coding_standards = self._load_coding_standards()
        
        # List to store history of code review results
        self.review_history: List[CodeReviewResult] = []
        self.max_history = 50  # Maximum number of reviews to keep in history
        
        # Performance and confidence metrics
        self.confidence = 0.85  # Agent's confidence level (0.0 to 1.0)
        self.reviews_completed = 0  # Counter for total reviews performed
        self.vulnerabilities_detected = 0  # Counter for total vulnerabilities found
        self.false_positives = 0  # Counter for false positives (for future improvement)
        self.average_security_score = 0.0  # Running average of security scores
        
        # Language detection patterns - file extensions and code signatures
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
        Load vulnerability patterns for each language from internal database
        
        Returns:
            Dictionary mapping languages to list of vulnerability patterns
        """
        patterns = {}  # Initialize empty dictionary
        
        # Python vulnerability patterns - SQL injection, command injection, etc.
        patterns[ProgrammingLanguage.PYTHON] = [
            {
                'id': 'PY-SQLI-001',
                'name': 'SQL Injection',
                'pattern': r'(?:execute|executemany|callproc)\s*\(.*?%.*?\)',
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
            # Additional Python patterns omitted for brevity but follow same structure
            # Each pattern includes: id, name, regex pattern, description, severity, CWE, CVSS, fix, and examples
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
            # Additional JavaScript patterns
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
        
        return patterns  # Return complete patterns dictionary
    
    def _load_coding_standards(self) -> Dict[str, List[str]]:
        """
        Load secure coding standards for generating recommendations
        
        Returns:
            Dictionary of coding standards organized by category
        """
        # Dictionary mapping security categories to lists of best practices
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
        Detect programming language from code and filename using multiple strategies
        
        Args:
            code: Source code content
            filename: Optional filename with extension for better detection
            
        Returns:
            Detected ProgrammingLanguage or None if cannot determine
        """
        # First strategy: Check filename extension
        if filename:
            for lang, patterns in self.language_patterns.items():
                for pattern in patterns:
                    # Check for file extension patterns (start with dot)
                    if pattern.startswith('.') and filename.endswith(pattern):
                        return lang  # Return detected language
        
        # Second strategy: Check code content for language-specific signatures
        code_lower = code.lower()  # Convert to lowercase for case-insensitive matching
        
        for lang, patterns in self.language_patterns.items():
            for pattern in patterns:
                # Check for code signature patterns (don't start with dot)
                if not pattern.startswith('.') and pattern.lower() in code_lower:
                    return lang  # Return detected language
        
        # Third strategy: Heuristic detection by common syntax patterns
        if 'def ' in code_lower and 'import ' in code_lower:
            return ProgrammingLanguage.PYTHON  # Python detection
        elif 'function ' in code_lower and ('var ' in code_lower or 'let ' in code_lower or 'const ' in code_lower):
            return ProgrammingLanguage.JAVASCRIPT  # JavaScript detection
        elif 'public class ' in code_lower and 'import ' in code_lower:
            return ProgrammingLanguage.JAVA  # Java detection
        elif '<?php' in code_lower:
            return ProgrammingLanguage.PHP  # PHP detection
        
        return None  # Could not determine language
    
    def analyze(self, security_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main analysis method - analyzes code for security vulnerabilities
        
        Args:
            security_data: Dictionary containing:
                - code: Source code to analyze (required)
                - filename: Optional filename for language detection
                - language: Optional pre-specified programming language
                - context: Optional context (web, api, cli, etc.)
                
        Returns:
            Dictionary with comprehensive code analysis results
        """
        start_time = time.time()  # Record start time for performance measurement
        
        # Extract input data with default values
        code = security_data.get('code', '')  # Get code from input, default to empty string
        filename = security_data.get('filename', 'unknown.py')  # Get filename with default
        specified_language = security_data.get('language')  # Get optionally specified language
        context = security_data.get('context', 'general')  # Get context with default
        
        # Validate input - ensure code is provided and is a string
        if not code or not isinstance(code, str):
            return {
                'error': 'No code provided for analysis or invalid code format',
                'agent_id': self.agent_id,
                'agent_name': self.name,
                'timestamp': datetime.now().isoformat()
            }
        
        # Language detection logic
        language = None  # Initialize language variable
        if specified_language:  # If language is explicitly specified
            try:
                # Try to convert string to ProgrammingLanguage enum
                language = ProgrammingLanguage(specified_language.lower())
            except ValueError:
                # Invalid language specified, fall back to auto-detection
                language = self.detect_language(code, filename)
        else:
            # No language specified, use auto-detection
            language = self.detect_language(code, filename)
        
        # Handle case where language cannot be detected
        if not language:
            return {
                'error': f'Could not detect programming language for: {filename}',
                'agent_id': self.agent_id,
                'agent_name': self.name,
                'suggestions': [
                    'Specify language explicitly using "language" parameter',
                    'Add proper file extension to filename',
                    'Ensure code contains language-specific signatures'
                ]
            }
        
        # Step 1: Analyze code for vulnerabilities using language-specific analyzer
        vulnerabilities = self._analyze_code(code, language, filename, context)
        
        # Step 2: Calculate security score based on found vulnerabilities
        security_score = self._calculate_security_score(vulnerabilities, len(code.split('\n')))
        
        # Step 3: Generate actionable recommendations
        recommendations = self._generate_recommendations(vulnerabilities, language, context)
        
        # Step 4: Create comprehensive review result object
        review_id = self._generate_review_id(code)  # Generate unique review ID
        review_result = CodeReviewResult(
            review_id=review_id,
            timestamp=datetime.now(),
            files_reviewed=1,  # Currently analyzes single file
            vulnerabilities_found=len(vulnerabilities),
            vulnerability_distribution=self._count_vulnerabilities_by_severity(vulnerabilities),
            total_lines=len(code.split('\n')),  # Count lines of code
            security_score=security_score,
            recommendations=recommendations,
            vulnerabilities=vulnerabilities
        )
        
        # Store review in history with size limit management
        self.review_history.append(review_result)
        if len(self.review_history) > self.max_history:
            # Keep only the most recent reviews if history exceeds limit
            self.review_history = self.review_history[-self.max_history:]
        
        # Step 5: Update agent performance metrics
        self.reviews_completed += 1  # Increment review counter
        self.vulnerabilities_detected += len(vulnerabilities)  # Update vulnerability count
        # Update running average of security scores (exponential moving average)
        self.average_security_score = (self.average_security_score * 0.9 + security_score * 0.1)
        
        # Update agent confidence based on analysis quality
        self._update_confidence(len(vulnerabilities), security_score)
        
        # Calculate total processing time
        processing_time = time.time() - start_time
        
        # Construct and return comprehensive results dictionary
        return {
            'agent_id': self.agent_id,
            'agent_name': self.name,
            'language': language.value,
            'filename': filename,
            'review_id': review_id,
            'security_score': round(security_score, 4),  # Round for readability
            'security_status': self._get_security_status(security_score),
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerability_distribution': review_result.vulnerability_distribution,
            'critical_vulnerabilities': len([v for v in vulnerabilities 
                                           if v.severity == VulnerabilitySeverity.CRITICAL]),
            'recommendations': recommendations[:5],  # Return top 5 recommendations
            'processing_time': round(processing_time, 4),  # Round processing time
            'confidence': round(self.confidence, 4),  # Round confidence score
            'reasoning_state': self._get_reasoning_state().tolist(),  # Convert tensor to list
            'decision': {
                'risk_level': round(1.0 - security_score, 4),  # Invert score for risk assessment
                'confidence': round(self.confidence, 4),
                'evidence': [v.description for v in vulnerabilities[:3]]  # Top 3 vulnerabilities as evidence
            },
            'detailed_results': review_result.to_dict()  # Full detailed results
        }
    
    def _analyze_code(self, code: str, language: ProgrammingLanguage,
                     filename: str, context: str) -> List[CodeVulnerability]:
        """
        Core code analysis method - coordinates language-specific analysis
        
        Args:
            code: Source code to analyze
            language: Programming language of the code
            filename: Source filename for context
            context: Application context (web, api, etc.)
            
        Returns:
            List of all found vulnerabilities
        """
        vulnerabilities = []  # Initialize empty list for vulnerabilities
        
        # Get language-specific analyzer function from dictionary
        analyzer = self.analyzers.get(language)
        if analyzer:
            # Run language-specific analysis if available
            vulnerabilities.extend(analyzer(code, filename, context))
        else:
            # Fall back to generic analysis for unsupported languages
            vulnerabilities.extend(self._generic_code_analysis(code, language, filename))
        
        # Apply language-agnostic checks to all code
        vulnerabilities.extend(self._check_hardcoded_secrets(code, language, filename))
        vulnerabilities.extend(self._check_code_quality(code, language, filename))
        
        return vulnerabilities  # Return all found vulnerabilities
    
    def _analyze_python_code(self, code: str, filename: str, 
                           context: str) -> List[CodeVulnerability]:
        """
        Analyze Python code for security vulnerabilities using regex and AST
        
        Args:
            code: Python source code
            filename: Source filename
            context: Application context
            
        Returns:
            List of Python-specific vulnerabilities
        """
        vulnerabilities = []  # Initialize list for Python vulnerabilities
        lines = code.split('\n')  # Split code into lines for line-by-line analysis
        
        # Get Python-specific vulnerability patterns
        patterns = self.vulnerability_patterns.get(ProgrammingLanguage.PYTHON, [])
        
        # Step 1: Regex-based pattern matching on each line
        for i, line in enumerate(lines, 1):  # Start line numbers at 1
            line_stripped = line.strip()  # Remove leading/trailing whitespace
            
            for pattern_info in patterns:
                pattern = pattern_info['pattern']  # Get regex pattern
                # Search for pattern in current line (case-insensitive)
                if re.search(pattern, line, re.IGNORECASE):
                    # Create vulnerability object for found pattern
                    vuln = CodeVulnerability(
                        vulnerability_id=pattern_info['id'],
                        severity=pattern_info['severity'],
                        category=pattern_info['name'],
                        language=ProgrammingLanguage.PYTHON,
                        file_path=filename,
                        line_number=i,
                        code_snippet=line_stripped[:100],  # Limit snippet length to 100 chars
                        description=pattern_info['description'],
                        cwe_id=pattern_info.get('cwe'),  # Use .get() for optional fields
                        cvss_score=pattern_info.get('cvss'),
                        fix_recommendation=pattern_info['fix'],
                        safe_example=pattern_info['example']['good']
                    )
                    vulnerabilities.append(vuln)  # Add vulnerability to list
        
        # Step 2: AST-based analysis for more complex patterns
        try:
            tree = ast.parse(code)  # Parse Python code into AST
            vulnerabilities.extend(self._analyze_python_ast(tree, filename, context))
        except SyntaxError as e:
            # If code has syntax errors, can't parse AST
            # Create vulnerability object for syntax error
            vuln = CodeVulnerability(
                vulnerability_id='PY-SYNTAX-001',
                severity=VulnerabilitySeverity.MEDIUM,
                category='Syntax Error',
                language=ProgrammingLanguage.PYTHON,
                file_path=filename,
                line_number=getattr(e, 'lineno', 1),  # Get line number from error if available
                code_snippet=str(e),  # Error message as code snippet
                description='Python syntax error prevents full analysis',
                cwe_id='CWE-1104',
                cvss_score=2.0,
                fix_recommendation='Fix syntax errors to enable complete security analysis',
                safe_example='Valid Python syntax'
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities  # Return all Python vulnerabilities found
    
    def _analyze_python_ast(self, tree: ast.AST, filename: str,
                          context: str) -> List[CodeVulnerability]:
        """
        Analyze Python Abstract Syntax Tree for complex vulnerabilities
        
        Args:
            tree: Python AST parsed from code
            filename: Source filename
            context: Application context
            
        Returns:
            List of vulnerabilities found via AST analysis
        """
        vulnerabilities = []  # Initialize list for AST vulnerabilities
        
        # Define custom AST visitor class to detect security vulnerabilities
        class SecurityVisitor(ast.NodeVisitor):
            """AST visitor that detects security vulnerabilities"""
            def __init__(self, filename):
                self.filename = filename  # Store filename for reporting
                self.vulnerabilities = []  # Initialize list for vulnerabilities
            
            def visit_Call(self, node):
                """Visit function call nodes to check for dangerous functions"""
                # Check for eval() function calls (common security issue)
                if isinstance(node.func, ast.Name) and node.func.id == 'eval':
                    if node.args:  # eval() with arguments is dangerous
                        # Create vulnerability for eval() usage
                        vuln = CodeVulnerability(
                            vulnerability_id='PY-EVAL-001',
                            severity=VulnerabilitySeverity.CRITICAL,
                            category='Dangerous Function',
                            language=ProgrammingLanguage.PYTHON,
                            file_path=self.filename,
                            line_number=node.lineno if hasattr(node, 'lineno') else 0,
                            # Use ast.unparse if available (Python 3.9+), else string representation
                            code_snippet=ast.unparse(node) if hasattr(ast, 'unparse') else str(node),
                            description='eval() function can execute arbitrary code from strings',
                            cwe_id='CWE-95',
                            cvss_score=9.8,
                            fix_recommendation='Avoid eval(), use safer alternatives like json.loads() or ast.literal_eval()',
                            safe_example='data = json.loads(user_input)  # For JSON data'
                        )
                        self.vulnerabilities.append(vuln)
                
                # Continue visiting child nodes in the AST
                self.generic_visit(node)
        
        # Create visitor instance and traverse the AST
        visitor = SecurityVisitor(filename)
        visitor.visit(tree)  # Start AST traversal
        vulnerabilities.extend(visitor.vulnerabilities)  # Add found vulnerabilities
        
        return vulnerabilities  # Return vulnerabilities found via AST analysis
    
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
        vulnerabilities = []  # Initialize list for JavaScript vulnerabilities
        lines = code.split('\n')  # Split code into lines
        
        # Get JavaScript-specific vulnerability patterns
        patterns = self.vulnerability_patterns.get(ProgrammingLanguage.JAVASCRIPT, [])
        
        # Pattern matching for each line of JavaScript code
        for i, line in enumerate(lines, 1):  # Start line numbers at 1
            line_stripped = line.strip()  # Remove whitespace
            for pattern_info in patterns:
                pattern = pattern_info['pattern']  # Get regex pattern
                # Search for pattern in current line
                if re.search(pattern, line, re.IGNORECASE):
                    # Create vulnerability object
                    vuln = CodeVulnerability(
                        vulnerability_id=pattern_info['id'],
                        severity=pattern_info['severity'],
                        category=pattern_info['name'],
                        language=ProgrammingLanguage.JAVASCRIPT,
                        file_path=filename,
                        line_number=i,
                        code_snippet=line_stripped[:100],  # Limit snippet length
                        description=pattern_info['description'],
                        cwe_id=pattern_info.get('cwe'),
                        cvss_score=pattern_info.get('cvss'),
                        fix_recommendation=pattern_info['fix'],
                        safe_example=pattern_info['example']['good']
                    )
                    vulnerabilities.append(vuln)  # Add to vulnerabilities list
        
        # Additional checks for web applications (context-specific)
        if context == 'web':
            vulnerabilities.extend(self._check_javascript_web_context(code, filename))
        
        return vulnerabilities  # Return all JavaScript vulnerabilities found
    
    def _analyze_java_code(self, code: str, filename: str,
                         context: str) -> List[CodeVulnerability]:
        """
        Analyze Java code for security vulnerabilities
        
        Args:
            code: Java source code
            filename: Source filename
            context: Application context
            
        Returns:
            List of Java vulnerabilities
        """
        vulnerabilities = []  # Initialize list for Java vulnerabilities
        lines = code.split('\n')  # Split code into lines
        
        patterns = self.vulnerability_patterns.get(ProgrammingLanguage.JAVA, [])
        
        # Pattern matching for each line of Java code
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()  # Remove whitespace
            for pattern_info in patterns:
                pattern = pattern_info['pattern']  # Get regex pattern
                if re.search(pattern, line, re.IGNORECASE):
                    # Create vulnerability object
                    vuln = CodeVulnerability(
                        vulnerability_id=pattern_info['id'],
                        severity=pattern_info['severity'],
                        category=pattern_info['name'],
                        language=ProgrammingLanguage.JAVA,
                        file_path=filename,
                        line_number=i,
                        code_snippet=line_stripped[:100],  # Limit snippet length
                        description=pattern_info['description'],
                        cwe_id=pattern_info.get('cwe'),
                        cvss_score=pattern_info.get('cvss'),
                        fix_recommendation=pattern_info['fix'],
                        safe_example=pattern_info['example']['good']
                    )
                    vulnerabilities.append(vuln)  # Add to vulnerabilities list
        
        return vulnerabilities  # Return all Java vulnerabilities found
    
    def _analyze_php_code(self, code: str, filename: str,
                        context: str) -> List[CodeVulnerability]:
        """
        Analyze PHP code for security vulnerabilities
        
        Args:
            code: PHP source code
            filename: Source filename
            context: Application context
            
        Returns:
            List of PHP vulnerabilities
        """
        vulnerabilities = []  # Initialize list for PHP vulnerabilities
        
        # Common PHP vulnerability patterns (defined inline since not in main patterns)
        php_patterns = [
            {
                'pattern': r'eval\s*\(.*?\$',  # Pattern for eval with variable
                'description': 'Unsafe eval() with user input - can lead to code injection',
                'severity': VulnerabilitySeverity.CRITICAL,
                'category': 'Code Injection'
            },
            {
                'pattern': r'system\s*\(.*?\$|exec\s*\(.*?\$|shell_exec\s*\(.*?\$',
                'description': 'Command injection vulnerability via shell commands',
                'severity': VulnerabilitySeverity.CRITICAL,
                'category': 'Command Injection'
            },
            {
                'pattern': r'\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\[.*?\]\s*\.',
                'description': 'Potential SQL injection via superglobal concatenation',
                'severity': VulnerabilitySeverity.HIGH,
                'category': 'SQL Injection'
            }
        ]
        
        lines = code.split('\n')  # Split code into lines
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()  # Remove whitespace
            for pattern_info in php_patterns:
                # Search for pattern in current line
                if re.search(pattern_info['pattern'], line, re.IGNORECASE):
                    # Generate unique ID from pattern hash
                    pattern_hash = hashlib.md5(pattern_info['pattern'].encode()).hexdigest()[:8]
                    # Create vulnerability object
                    vuln = CodeVulnerability(
                        vulnerability_id=f'PHP-{pattern_hash}',
                        severity=pattern_info['severity'],
                        category=pattern_info['category'],
                        language=ProgrammingLanguage.PHP,
                        file_path=filename,
                        line_number=i,
                        code_snippet=line_stripped[:100],  # Limit snippet length
                        description=pattern_info['description'],
                        cwe_id='CWE-78',  # Default CWE for command injection
                        cvss_score=9.1,  # Default CVSS score
                        fix_recommendation='Use prepared statements, validate and sanitize all inputs',
                        safe_example='$stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");'
                    )
                    vulnerabilities.append(vuln)  # Add to vulnerabilities list
        
        return vulnerabilities  # Return all PHP vulnerabilities found
    
    def _generic_code_analysis(self, code: str, language: ProgrammingLanguage,
                             filename: str) -> List[CodeVulnerability]:
        """
        Generic code analysis for languages without specific analyzers
        
        Args:
            code: Source code in any language
            language: Detected programming language
            filename: Source filename
            
        Returns:
            List of generic vulnerabilities
        """
        vulnerabilities = []  # Initialize list for generic vulnerabilities
        lines = code.split('\n')  # Split code into lines
        
        # Common dangerous patterns across multiple languages
        dangerous_patterns = [
            (r'eval\s*\(', 'Code Injection', VulnerabilitySeverity.CRITICAL),
            (r'system\s*\(|exec\s*\(', 'Command Injection', VulnerabilitySeverity.CRITICAL),
            (r'SELECT.*?\+\s*|INSERT.*?\+\s*', 'SQL Injection', VulnerabilitySeverity.CRITICAL),
            (r'password\s*=\s*[\'\"].*?[\'\"]', 'Hardcoded Password', VulnerabilitySeverity.HIGH),
            (r'secret\s*=\s*[\'\"].*?[\'\"]', 'Hardcoded Secret', VulnerabilitySeverity.HIGH),
            (r'key\s*=\s*[\'\"].*?[\'\"]', 'Hardcoded API Key', VulnerabilitySeverity.HIGH),
            (r'http://', 'Insecure HTTP', VulnerabilitySeverity.MEDIUM)
        ]
        
        # Check each line for dangerous patterns
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()  # Remove whitespace
            for pattern, category, severity in dangerous_patterns:
                # Search for pattern in current line
                if re.search(pattern, line, re.IGNORECASE):
                    # Generate unique ID from pattern hash
                    pattern_hash = hashlib.md5(pattern.encode()).hexdigest()[:8]
                    # Create vulnerability object
                    vuln = CodeVulnerability(
                        vulnerability_id=f'GEN-{pattern_hash}',
                        severity=severity,
                        category=category,
                        language=language,
                        file_path=filename,
                        line_number=i,
                        code_snippet=line_stripped[:100],  # Limit snippet length
                        description=f'Potential {category.lower()} vulnerability',
                        cwe_id='CWE-20',  # CWE for Improper Input Validation
                        cvss_score=7.5 if severity == VulnerabilitySeverity.CRITICAL else 5.0,
                        fix_recommendation='Validate and sanitize all inputs, use secure alternatives',
                        safe_example='Use parameterized queries and input validation'
                    )
                    vulnerabilities.append(vuln)  # Add to vulnerabilities list
        
        return vulnerabilities  # Return all generic vulnerabilities found
    
    def _check_hardcoded_secrets(self, code: str, language: ProgrammingLanguage,
                               filename: str) -> List[CodeVulnerability]:
        """
        Check for hardcoded secrets like API keys, passwords, tokens
        
        Args:
            code: Source code to check
            language: Programming language
            filename: Source filename
            
        Returns:
            List of hardcoded secret vulnerabilities
        """
        vulnerabilities = []  # Initialize list for secret vulnerabilities
        lines = code.split('\n')  # Split code into lines
        
        # Common secret patterns with regex
        secret_patterns = [
            (r'api[_-]?key\s*=\s*[\'\"][A-Za-z0-9_-]{20,}[\'\"]', 'API Key', VulnerabilitySeverity.HIGH),
            (r'access[_-]?token\s*=\s*[\'\"][A-Za-z0-9_-]{20,}[\'\"]', 'Access Token', VulnerabilitySeverity.HIGH),
            (r'secret[_-]?key\s*=\s*[\'\"][A-Za-z0-9_-]{20,}[\'\"]', 'Secret Key', VulnerabilitySeverity.HIGH),
            (r'password\s*=\s*[\'\"].{8,}[\'\"]', 'Password', VulnerabilitySeverity.HIGH),
            (r'private[_-]?key\s*=\s*[\'\"].{20,}[\'\"]', 'Private Key', VulnerabilitySeverity.CRITICAL),
            (r'aws[_-]?(?:access[_-]?key|secret[_-]?key)\s*=\s*[\'\"].{20,}[\'\"]', 'AWS Credentials', VulnerabilitySeverity.CRITICAL)
        ]
        
        # Check each line for secret patterns
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()  # Remove whitespace
            for pattern, secret_type, severity in secret_patterns:
                # Search for pattern in current line
                if re.search(pattern, line, re.IGNORECASE):
                    # Mask the secret in the displayed code snippet for security
                    masked_line = re.sub(r'[\'\"][A-Za-z0-9_-]{20,}[\'\"]', '\'***MASKED***\'', line)
                    
                    # Create vulnerability object for hardcoded secret
                    vuln = CodeVulnerability(
                        vulnerability_id=f'SECRET-{hashlib.md5(pattern.encode()).hexdigest()[:8]}',
                        severity=severity,
                        category='Hardcoded Secret',
                        language=language,
                        file_path=filename,
                        line_number=i,
                        code_snippet=masked_line.strip()[:100],  # Use masked snippet
                        description=f'Hardcoded {secret_type} found in code - exposes sensitive credentials',
                        cwe_id='CWE-798',  # CWE for Use of Hard-coded Credentials
                        cvss_score=7.5,  # Standard CVSS for hardcoded secrets
                        fix_recommendation=f'Remove hardcoded {secret_type}, use environment variables or secret management service',
                        safe_example=f'{secret_type.replace(" ", "_").upper()} = os.environ.get("{secret_type.replace(" ", "_").upper()}")  # Using environment variable'
                    )
                    vulnerabilities.append(vuln)  # Add to vulnerabilities list
        
        return vulnerabilities  # Return all hardcoded secret vulnerabilities found
    
    def _check_javascript_web_context(self, code: str, filename: str) -> List[CodeVulnerability]:
        """
        Additional security checks for JavaScript in web browser context
        
        Args:
            code: JavaScript code
            filename: Source filename
            
        Returns:
            List of DOM-based vulnerabilities
        """
        vulnerabilities = []  # Initialize list for DOM vulnerabilities
        lines = code.split('\n')  # Split code into lines
        
        # DOM-based XSS patterns specific to web context
        dom_xss_patterns = [
            (r'document\.write\s*\(.*?\+.*?\)', 'document.write with concatenation', VulnerabilitySeverity.HIGH),
            (r'\.src\s*=\s*.+?\+', 'Dynamic script src with concatenation', VulnerabilitySeverity.HIGH),
            (r'location\.(?:href|hash|search)\s*=\s*.+?\+', 'Dynamic location assignment', VulnerabilitySeverity.MEDIUM),
            (r'innerHTML\s*=\s*.+?\+', 'innerHTML with concatenation', VulnerabilitySeverity.HIGH)
        ]
        
        # Check each line for DOM XSS patterns
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()  # Remove whitespace
            for pattern, description, severity in dom_xss_patterns:
                if re.search(pattern, line):  # Search for pattern
                    # Create vulnerability object
                    vuln = CodeVulnerability(
                        vulnerability_id=f'JS-DOM-{hashlib.md5(pattern.encode()).hexdigest()[:8]}',
                        severity=severity,
                        category='DOM-based XSS',
                        language=ProgrammingLanguage.JAVASCRIPT,
                        file_path=filename,
                        line_number=i,
                        code_snippet=line_stripped[:100],  # Limit snippet length
                        description=f'{description} - can lead to Cross-Site Scripting',
                        cwe_id='CWE-79',  # CWE for Cross-site Scripting
                        cvss_score=8.2,  # CVSS for XSS vulnerabilities
                        fix_recommendation='Validate and sanitize all DOM inputs, use textContent instead of innerHTML when possible',
                        safe_example='element.textContent = sanitizedInput  // Safe alternative to innerHTML'
                    )
                    vulnerabilities.append(vuln)  # Add to vulnerabilities list
        
        return vulnerabilities  # Return all DOM vulnerabilities found
    
    def _check_code_quality(self, code: str, language: ProgrammingLanguage,
                          filename: str) -> List[CodeVulnerability]:
        """
        Check for code quality issues that could impact security
        
        Args:
            code: Source code
            language: Programming language
            filename: Source filename
            
        Returns:
            List of code quality vulnerabilities
        """
        vulnerabilities = []  # Initialize list for quality vulnerabilities
        lines = code.split('\n')  # Split code into lines
        
        # Look for TODO/FIXME comments with security implications
        for i, line in enumerate(lines, 1):
            line_lower = line.lower()  # Convert to lowercase for case-insensitive matching
            
            # Check if line contains TODO or FIXME
            if 'todo' in line_lower or 'fixme' in line_lower:
                # Security-related keywords to look for in comments
                security_keywords = ['security', 'vulnerability', 'injection', 'xss', 
                                   'sql', 'auth', 'encrypt', 'ssl', 'tls', 'harden']
                
                # Check if any security keyword is in the comment
                if any(keyword in line_lower for keyword in security_keywords):
                    # Create vulnerability object for security TODO
                    vuln = CodeVulnerability(
                        vulnerability_id=f'QUALITY-{i:04d}',  # Pad line number with zeros
                        severity=VulnerabilitySeverity.MEDIUM,
                        category='Security Todo',
                        language=language,
                        file_path=filename,
                        line_number=i,
                        code_snippet=line.strip()[:100],  # Limit snippet length
                        description='Security-related TODO/FIXME comment found - indicates incomplete security implementation',
                        cwe_id='CWE-546',  # CWE for Suspicious Comment
                        cvss_score=3.5,  # Low CVSS as it's informational
                        fix_recommendation='Address the security TODO/FIXME comment before deployment',
                        safe_example='// TODO: Implement input validation - DONE: Added input validation on line 42'
                    )
                    vulnerabilities.append(vuln)  # Add to vulnerabilities list
        
        return vulnerabilities  # Return all code quality vulnerabilities found
    
    def _calculate_security_score(self, vulnerabilities: List[CodeVulnerability],
                                total_lines: int) -> float:
        """
        Calculate overall security score based on vulnerability density and severity
        
        Args:
            vulnerabilities: List of found vulnerabilities
            total_lines: Total lines of code analyzed
            
        Returns:
            Security score from 0.0 (insecure) to 1.0 (secure)
        """
        # Handle edge case: empty code is considered secure
        if total_lines == 0:
            return 1.0  # Perfect score for empty code
        
        # Weight vulnerabilities by severity - critical issues weigh more
        severity_weights = {
            VulnerabilitySeverity.CRITICAL: 10.0,  # Highest weight for critical issues
            VulnerabilitySeverity.HIGH: 5.0,       # High weight
            VulnerabilitySeverity.MEDIUM: 2.0,     # Medium weight
            VulnerabilitySeverity.LOW: 0.5,        # Low weight
            VulnerabilitySeverity.INFO: 0.1        # Minimal weight for info
        }
        
        # Calculate total weighted vulnerability score
        total_weight = sum(severity_weights[v.severity] for v in vulnerabilities)
        
        # Normalize by code size - calculate vulnerabilities per 100 lines
        density = (total_weight / max(total_lines, 1)) * 100
        
        # Convert density to security score using exponential decay
        # score = e^(-density/10) - more density = lower score
        # This gives scores that decay exponentially with vulnerability density
        score = math.exp(-density / 10.0)
        
        # Ensure score is within bounds [0.0, 1.0]
        return max(0.0, min(1.0, score))
    
    def _count_vulnerabilities_by_severity(self, 
                                         vulnerabilities: List[CodeVulnerability]) -> Dict[str, int]:
        """
        Count and categorize vulnerabilities by severity level
        
        Args:
            vulnerabilities: List of vulnerability objects
            
        Returns:
            Dictionary with counts for each severity level
        """
        # Initialize counts dictionary with all severity levels
        counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        # Count each vulnerability by its severity
        for vuln in vulnerabilities:
            severity_key = vuln.severity.value  # Get string value from enum
            if severity_key in counts:
                counts[severity_key] += 1  # Increment count for this severity
        
        return counts  # Return counts dictionary
    
    def _generate_recommendations(self, vulnerabilities: List[CodeVulnerability],
                                language: ProgrammingLanguage,
                                context: str) -> List[str]:
        """
        Generate actionable security recommendations based on findings
        
        Args:
            vulnerabilities: List of found vulnerabilities
            language: Programming language
            context: Application context
            
        Returns:
            List of prioritized security recommendations
        """
        recommendations = []  # Initialize list for recommendations
        
        # Step 1: Recommendations based on found vulnerabilities
        if vulnerabilities:
            # Group vulnerabilities by category for targeted recommendations
            categories = {}
            for vuln in vulnerabilities:
                # Focus on critical and high severity issues
                if vuln.severity in [VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH]:
                    if vuln.category not in categories:
                        categories[vuln.category] = []  # Initialize category list
                    categories[vuln.category].append(vuln)  # Add vulnerability to category
            
            # Generate specific recommendations for each problem category
            for category, vulns in categories.items():
                count = len(vulns)  # Count vulnerabilities in category
                # Determine highest severity in category
                severity_level = 'CRITICAL' if any(v.severity == VulnerabilitySeverity.CRITICAL for v in vulns) else 'HIGH'
                # Add category-based recommendation
                recommendations.append(f"Address {count} {category} vulnerabilities ({severity_level} severity)")
            
            # Add top 3 specific fixes for critical vulnerabilities
            critical_vulns = [v for v in vulnerabilities 
                            if v.severity == VulnerabilitySeverity.CRITICAL]
            if critical_vulns:
                for vuln in critical_vulns[:3]:  # Limit to top 3
                    recommendations.append(f"- {vuln.fix_recommendation}")
        
        # Step 2: Context-specific recommendations
        if context == 'web':
            recommendations.extend([
                "Implement Content Security Policy (CSP) headers",
                "Add security headers (X-Frame-Options, X-Content-Type-Options, X-XSS-Protection)",
                "Use HTTPS and enforce HTTP Strict Transport Security (HSTS)",
                "Sanitize all user inputs and encode outputs"
            ])
        elif context == 'api':
            recommendations.extend([
                "Implement proper authentication (JWT with secure storage, OAuth2)",
                "Use rate limiting and throttling to prevent abuse",
                "Validate all input against JSON schemas or strict type checking",
                "Encrypt sensitive data in transit (TLS) and at rest (encryption)"
            ])
        elif context == 'cli':
            recommendations.extend([
                "Validate and sanitize all command-line arguments",
                "Store configuration securely (not in plain text files)",
                "Implement proper privilege separation",
                "Audit all file system and network operations"
            ])
        
        # Step 3: Language-specific best practices
        lang_recommendations = {
            ProgrammingLanguage.PYTHON: [
                "Use virtual environments or containers for dependency isolation",
                "Keep dependencies updated and regularly scan for vulnerabilities",
                "Use type hints and static analysis tools (mypy, bandit, safety)",
                "Avoid pickle for untrusted data, use JSON with validation"
            ],
            ProgrammingLanguage.JAVASCRIPT: [
                "Use strict mode ('use strict') in all files",
                "Implement proper CORS configuration for APIs",
                "Use Content Security Policy for web applications",
                "Avoid eval() and innerHTML with untrusted user input"
            ],
            ProgrammingLanguage.JAVA: [
                "Use PreparedStatement with parameterized queries for database access",
                "Implement comprehensive input validation frameworks",
                "Use security manager or module system for sandboxing",
                "Keep Java runtime and dependencies updated with security patches"
            ],
            ProgrammingLanguage.PHP: [
                "Use prepared statements with PDO or MySQLi",
                "Enable strict mode and error reporting in development",
                "Implement proper session security and CSRF tokens",
                "Keep PHP version updated and use Composer for dependency management"
            ]
        }
        
        # Add language-specific recommendations if available
        if language in lang_recommendations:
            recommendations.extend(lang_recommendations[language])
        
        # Step 4: General security best practices (always applicable)
        recommendations.extend([
            "Conduct regular security audits and penetration testing",
            "Implement security training for development teams",
            "Establish secure SDLC processes with security gates",
            "Set up security monitoring and incident response procedures"
        ])
        
        # Remove duplicates and limit to top 15 recommendations
        unique_recommendations = []
        seen = set()  # Use set for O(1) lookup
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)  # Add to seen set
                unique_recommendations.append(rec)  # Add to unique list
        
        return unique_recommendations[:15]  # Return top 15 unique recommendations
    
    def _get_security_status(self, security_score: float) -> str:
        """
        Convert numerical security score to human-readable status
        
        Args:
            security_score: Score from 0.0 to 1.0
            
        Returns:
            Human-readable security status
        """
        # Define thresholds for different security status levels
        if security_score >= 0.9:
            return "EXCELLENT SECURITY - Minimal risks identified"
        elif security_score >= 0.7:
            return "GOOD SECURITY - Some improvements recommended"
        elif security_score >= 0.5:
            return "MODERATE SECURITY - Needs attention soon"
        elif security_score >= 0.3:
            return "POOR SECURITY - Immediate action required"
        else:
            return "CRITICAL SECURITY ISSUES - Do not deploy without fixes"
    
    def _generate_review_id(self, code: str) -> str:
        """
        Generate unique review ID from code hash and timestamp
        
        Args:
            code: Source code to generate hash from
            
        Returns:
            Unique review identifier
        """
        # Create hash of code for uniqueness (first 16 chars of MD5)
        code_hash = hashlib.md5(code.encode()).hexdigest()[:16]
        # Add timestamp for sorting and uniqueness (YYYYMMDDHHMM format)
        timestamp = datetime.now().strftime("%Y%m%d%H%M")
        # Combine timestamp and hash for unique ID
        return f"REVIEW-{timestamp}-{code_hash}"
    
    def _update_confidence(self, vulnerabilities_found: int, 
                          security_score: float):
        """
        Update agent confidence based on review quality and findings
        
        Args:
            vulnerabilities_found: Number of vulnerabilities found
            security_score: Overall security score (0.0-1.0)
        """
        # Confidence adjustment logic:
        if vulnerabilities_found > 0 and security_score < 0.7:
            # Found issues in insecure code - good detection
            self.confidence = min(1.0, self.confidence * 1.05)  # Increase confidence
        elif vulnerabilities_found == 0 and security_score >= 0.9:
            # No issues in secure code - good system
            self.confidence = min(1.0, self.confidence * 1.02)  # Slight increase
        elif vulnerabilities_found == 0 and security_score < 0.5:
            # No issues but code is insecure - potentially missed issues
            self.confidence = max(0.1, self.confidence * 0.9)  # Decrease confidence
        else:
            # Maintain current confidence with slight decay
            self.confidence = max(0.1, self.confidence * 0.99)  # Minimal decay
    
    def _get_reasoning_state(self) -> torch.Tensor:
        """
        Get current reasoning state tensor for multi-agent coordination
        
        Returns:
            PyTorch tensor with agent state features (512 dimensions)
        """
        features = []  # Initialize list for feature values
        
        # 1. Performance features (4 dimensions)
        features.append(self.confidence)  # Current confidence level
        features.append(min(self.reviews_completed / 1000.0, 1.0))  # Normalized review count
        features.append(min(self.vulnerabilities_detected / 1000.0, 1.0))  # Normalized vulnerability count
        features.append(self.average_security_score)  # Average security score
        
        # 2. Recent review patterns (2 dimensions)
        recent_reviews = self.review_history[-5:] if self.review_history else []
        if recent_reviews:
            # Calculate average vulnerabilities in recent reviews
            avg_vulns = sum(r.vulnerabilities_found for r in recent_reviews) / len(recent_reviews)
            # Calculate average security score in recent reviews
            avg_score = sum(r.security_score for r in recent_reviews) / len(recent_reviews)
            features.append(min(avg_vulns / 20.0, 1.0))  # Normalized average vulnerabilities
            features.append(avg_score)  # Average security score
        else:
            features.extend([0.0, 0.5])  # Default values if no recent reviews
        
        # 3. Language expertise distribution (simplified, 3 dimensions)
        features.append(0.8)  # Python expertise (primary language)
        features.append(0.6)  # JavaScript expertise (secondary language)
        features.append(0.4)  # Other languages expertise (tertiary)
        
        # 4. Current load and capacity (2 dimensions)
        current_load = len(self.review_history) / self.max_history  # Load factor
        features.append(current_load)  # Current load (0.0 to 1.0)
        features.append(1.0 - current_load)  # Available capacity
        
        # Pad to 512 dimensions with zeros for compatibility with neural networks
        while len(features) < 512:
            features.append(0.0)  # Add zero padding
        
        # Convert to PyTorch tensor with float32 dtype
        return torch.tensor(features[:512], dtype=torch.float32)
    
    def get_agent_status(self) -> Dict[str, Any]:
        """
        Get current agent status, metrics, and capabilities
        
        Returns:
            Dictionary with agent status information
        """
        return {
            'agent_id': self.agent_id,
            'agent_name': self.name,
            'confidence': round(self.confidence, 4),  # Rounded confidence
            'reviews_completed': self.reviews_completed,  # Total reviews
            'vulnerabilities_detected': self.vulnerabilities_detected,  # Total vulnerabilities
            'false_positives': self.false_positives,  # False positives count
            'average_security_score': round(self.average_security_score, 4),  # Average score
            'languages_supported': len(self.analyzers),  # Number of supported languages
            'vulnerability_patterns_loaded': sum(len(patterns) 
                                               for patterns in self.vulnerability_patterns.values()),
            'recent_reviews': len(self.review_history),  # Reviews in history
            'max_history': self.max_history,  # Maximum history size
            'analyzers_available': [lang.value for lang in self.analyzers.keys()],  # Available analyzers
            'last_review_time': self.review_history[-1].timestamp.isoformat() if self.review_history else None
        }

# Test function to demonstrate the agent's capabilities
def test_secure_code_review_agent():
    """Test function to demonstrate the agent's capabilities"""
    # Create agent instance with default ID
    agent = SecureCodeReviewAgent()
    
    # Test with vulnerable Python code containing multiple security issues
    vulnerable_python_code = """
import os
import pickle

def unsafe_function(user_input):
    # SQL Injection vulnerability
    cursor.execute("SELECT * FROM users WHERE id = %s" % user_input)
    
    # Command Injection vulnerability
    os.system("ls " + user_input)
    
    # Insecure deserialization
    data = pickle.loads(user_input)
    
    # Hardcoded secret
    API_KEY = "sk_live_1234567890abcdef"
    
    return "Processed: " + user_input
"""
    
    # Analyze the code using the agent
    result = agent.analyze({
        'code': vulnerable_python_code,  # Code to analyze
        'filename': 'vulnerable_app.py',  # Filename for context
        'language': 'python',  # Specify language
        'context': 'web'  # Context for additional checks
    })
    
    # Print test results
    print("=== Secure Code Review Agent Test ===")
    print(f"Agent: {result['agent_name']}")
    print(f"Language: {result['language']}")
    print(f"Security Score: {result['security_score']}")
    print(f"Security Status: {result['security_status']}")
    print(f"Vulnerabilities Found: {result['vulnerabilities_found']}")
    print(f"Critical Vulnerabilities: {result['critical_vulnerabilities']}")
    
    print("\nTop Recommendations:")
    for i, rec in enumerate(result['recommendations'], 1):
        print(f"{i}. {rec}")
    
    print(f"\nProcessing Time: {result['processing_time']} seconds")
    print(f"Agent Confidence: {result['confidence']}")
    
    # Get and print agent status
    status = agent.get_agent_status()
    print(f"\nAgent Status:")
    print(f"Reviews Completed: {status['reviews_completed']}")
    print(f"Average Security Score: {status['average_security_score']}")

# Entry point for standalone execution
if __name__ == "__main__":
    test_secure_code_review_agent()  # Run test function