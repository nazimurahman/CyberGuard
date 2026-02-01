# src/ui/frontend/tutor_mode.py
"""
Security Tutor Mode for CyberGuard

Educational component that teaches developers about:
- Web security vulnerabilities
- Secure coding practices
- Threat mitigation strategies
- Compliance requirements

Features:
- Interactive vulnerability explanations
- Real attack examples
- Fix instructions with code snippets
- Quizzes and knowledge checks
- Progress tracking
"""

from flask import Blueprint, render_template, request, jsonify, session, current_app
from flask_login import login_required
import json
from typing import Dict, List, Any, Optional
from enum import Enum
import hashlib
from datetime import datetime

# Create blueprint for tutor mode routes
tutor_blueprint = Blueprint('tutor', __name__, url_prefix='/tutor')

class VulnerabilityCategory(Enum):
    """Vulnerability categories for tutor mode"""
    OWASP_TOP_10 = 'owasp_top_10'
    API_SECURITY = 'api_security'
    INFRASTRUCTURE = 'infrastructure'
    CODE_QUALITY = 'code_quality'
    COMPLIANCE = 'compliance'

class DifficultyLevel(Enum):
    """Difficulty levels for educational content"""
    BEGINNER = 'beginner'
    INTERMEDIATE = 'intermediate'
    ADVANCED = 'advanced'
    EXPERT = 'expert'

class TutorMode:
    """Security tutor mode for educational content"""
    
    def __init__(self):
        """Initialize tutor mode with educational content"""
        self.vulnerabilities = self._load_vulnerability_content()
        self.lessons = self._load_lesson_content()
        self.quizzes = self._load_quiz_content()
        self.user_progress = {}  # In production, use database
        
        # Learning paths - predefined sequences of vulnerabilities for different roles
        self.learning_paths = {
            'web_developer': [
                'xss', 'sql_injection', 'csrf', 'authentication',  # Changed from 'xss_basics' to 'xss' to match content
                'session_management', 'input_validation'
            ],
            'api_developer': [
                'api_authentication', 'api_rate_limiting', 'api_input_validation',
                'api_error_handling', 'api_versioning'
            ],
            'devops': [
                'container_security', 'infrastructure_hardening',
                'secrets_management', 'logging_monitoring'
            ]
        }
    
    def _load_vulnerability_content(self) -> Dict[str, Any]:
        """Load vulnerability educational content"""
        return {
            'xss': {
                'id': 'xss',
                'name': 'Cross-Site Scripting (XSS)',
                'category': VulnerabilityCategory.OWASP_TOP_10.value,
                'difficulty': DifficultyLevel.INTERMEDIATE.value,
                'description': 'XSS allows attackers to inject malicious scripts into web pages viewed by other users.',
                'impact': 'Can lead to session hijacking, defacement, or malware distribution.',
                'examples': [
                    {
                        'title': 'Reflected XSS in search form',
                        'code': 'https://example.com/search?q=<script>alert("XSS")</script>',
                        'explanation': 'The search parameter is directly reflected in the response without sanitization.'
                    },
                    {
                        'title': 'Stored XSS in comment section',
                        'code': 'Comment: <img src="x" onerror="stealCookies()">',
                        'explanation': 'Malicious script stored in database and executed when other users view comments.'
                    }
                ],
                'prevention': [
                    'Validate and sanitize all user inputs',
                    'Use Content Security Policy (CSP) headers',
                    'Encode output before rendering',
                    'Use HTTP-only cookies for session management'
                ],
                'code_snippets': {
                    'python': {
                        'flask': '''
from flask import escape

# Safe output rendering
@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Always escape user input
    return f'Results for: {escape(query)}'
                        ''',
                        'django': '''
# Django templates auto-escape by default
<h1>Search: {{ query }}</h1>

# Manual escaping if needed
from django.utils.html import escape
safe_query = escape(user_input)
                        '''
                    },
                    'javascript': {
                        'react': '''
// React automatically escapes content
function SearchResults({ query }) {
    return <h1>Results for: {query}</h1>;
}

// Dangerous HTML needs explicit handling
<div dangerouslySetInnerHTML={{__html: sanitizedHTML}} />
                        ''',
                        'vanilla': '''
// Always encode special characters
function encodeHTML(text) {
    return text.replace(/[&<>"']/g, function(m) {
        return {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        }[m];
    });
}
                        '''
                    }
                },
                'resources': [
                    {
                        'title': 'OWASP XSS Prevention Cheat Sheet',
                        'url': 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
                    },
                    {
                        'title': 'MDN Web Docs: XSS',
                        'url': 'https://developer.mozilla.org/en-US/docs/Glossary/Cross-site_scripting'
                    }
                ]
            },
            'sql_injection': {
                'id': 'sql_injection',
                'name': 'SQL Injection',
                'category': VulnerabilityCategory.OWASP_TOP_10.value,
                'difficulty': DifficultyLevel.BEGINNER.value,
                'description': 'SQL injection allows attackers to execute malicious SQL statements that control a web application\'s database.',
                'impact': 'Can lead to data theft, data modification, or complete database compromise.',
                'examples': [
                    {
                        'title': 'Classic SQL injection',
                        'code': "SELECT * FROM users WHERE username = 'admin' OR '1'='1' -- AND password = '...'",
                        'explanation': "The 'OR 1=1' condition makes the WHERE clause always true, bypassing authentication."
                    }
                ],
                'prevention': [
                    'Use parameterized queries (prepared statements)',
                    'Use ORM with built-in protection',
                    'Validate and sanitize all inputs',
                    'Apply principle of least privilege to database accounts'
                ],
                'code_snippets': {
                    'python': {
                        'sqlalchemy': '''
# Using SQLAlchemy ORM (safe)
user = session.query(User).filter(
    User.username == username,
    User.password == password_hash
).first()

# Using parameterized queries
query = "SELECT * FROM users WHERE username = ? AND password = ?"
cursor.execute(query, (username, password_hash))
                        ''',
                        'django': '''
# Django ORM (safe)
from django.db import connection

with connection.cursor() as cursor:
    cursor.execute("SELECT * FROM users WHERE username = %s", [username])
    row = cursor.fetchone()
                        '''
                    }
                }
            },
            # Added missing vulnerability definitions referenced in learning paths
            'csrf': {
                'id': 'csrf',
                'name': 'Cross-Site Request Forgery',
                'category': VulnerabilityCategory.OWASP_TOP_10.value,
                'difficulty': DifficultyLevel.INTERMEDIATE.value,
                'description': 'CSRF tricks users into performing unwanted actions on a web application where they are authenticated.',
                'impact': 'Can lead to unauthorized state changes like fund transfers or profile updates.',
                'prevention': ['Use CSRF tokens', 'Implement SameSite cookies', 'Check Origin headers']
            },
            'authentication': {
                'id': 'authentication',
                'name': 'Authentication Vulnerabilities',
                'category': VulnerabilityCategory.OWASP_TOP_10.value,
                'difficulty': DifficultyLevel.INTERMEDIATE.value,
                'description': 'Weaknesses in authentication mechanisms that allow unauthorized access.',
                'impact': 'Account takeover and unauthorized access to sensitive data.',
                'prevention': ['Implement multi-factor authentication', 'Use strong password policies', 'Secure password storage']
            },
            'security_headers_misconfig': {
                'id': 'security_headers_misconfig',
                'name': 'Security Headers Misconfiguration',
                'category': VulnerabilityCategory.INFRASTRUCTURE.value,
                'difficulty': DifficultyLevel.BEGINNER.value,
                'description': 'Missing or improperly configured security headers that expose applications to attacks.',
                'impact': 'Increased attack surface and reduced browser security protections.',
                'prevention': ['Implement CSP', 'Set X-Frame-Options', 'Enable HSTS']
            }
        }
    
    def _load_lesson_content(self) -> Dict[str, Any]:
        """Load lesson content for structured learning"""
        return {
            'web_security_fundamentals': {
                'id': 'web_security_fundamentals',
                'title': 'Web Security Fundamentals',
                'description': 'Learn the basics of web security and common vulnerabilities',
                'modules': [
                    {
                        'id': 'http_basics',
                        'title': 'HTTP Protocol Basics',
                        'content': 'Understanding HTTP requests, responses, headers, and methods.',
                        'duration': '15 minutes',
                        'completed': False
                    },
                    {
                        'id': 'authentication',
                        'title': 'Authentication & Authorization',
                        'content': 'Learn about secure authentication methods and authorization controls.',
                        'duration': '20 minutes',
                        'completed': False
                    }
                ],
                'prerequisites': [],
                'target_audience': ['developers', 'students'],
                'difficulty': DifficultyLevel.BEGINNER.value
            }
        }
    
    def _load_quiz_content(self) -> Dict[str, Any]:
        """Load quiz questions for knowledge assessment"""
        return {
            'xss_quiz': {
                'id': 'xss_quiz',
                'title': 'XSS Knowledge Check',
                'vulnerability_id': 'xss',
                'questions': [
                    {
                        'id': 'q1',
                        'question': 'Which type of XSS occurs when malicious script is stored in the database?',
                        'options': [
                            'Reflected XSS',
                            'Stored XSS',
                            'DOM-based XSS',
                            'Blind XSS'
                        ],
                        'correct_answer': 1,  # Index of correct answer (0-based)
                        'explanation': 'Stored XSS (also called persistent XSS) occurs when malicious script is stored on the server (e.g., in a database) and then served to other users.'
                    },
                    {
                        'id': 'q2',
                        'question': 'What is the primary defense against XSS attacks?',
                        'options': [
                            'Input validation',
                            'Output encoding',
                            'Both input validation and output encoding',
                            'Using HTTPS'
                        ],
                        'correct_answer': 2,  # Index of correct answer
                        'explanation': 'Both input validation (to reject malicious input) and output encoding (to neutralize any malicious input that gets through) are necessary for comprehensive XSS protection.'
                    }
                ],
                'passing_score': 70  # Percentage required to pass
            }
        }
    
    def get_vulnerability_info(self, vuln_id: str, 
                              user_context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Get educational information about a specific vulnerability
        
        Args:
            vuln_id: Vulnerability identifier
            user_context: Optional user context for personalized learning
        
        Returns:
            Vulnerability information with educational content
        """
        if vuln_id not in self.vulnerabilities:
            raise ValueError(f"Unknown vulnerability: {vuln_id}")
        
        vuln_info = self.vulnerabilities[vuln_id].copy()  # Create copy to avoid modifying original
        
        # Add personalized recommendations if user context provided
        if user_context:
            # Add context-specific examples based on user's language/framework
            language = user_context.get('primary_language')
            framework = user_context.get('primary_framework')
            
            if language and language in vuln_info.get('code_snippets', {}):
                # Store language-specific snippets
                vuln_info['recommended_snippets'] = vuln_info['code_snippets'][language]
                
                if framework and framework in vuln_info['code_snippets'][language]:
                    # Store specific framework snippet
                    vuln_info['recommended_snippet'] = vuln_info['code_snippets'][language][framework]
        
        # Add quiz information if available for this vulnerability
        related_quizzes = [
            quiz_id for quiz_id, quiz in self.quizzes.items()
            if quiz.get('vulnerability_id') == vuln_id
        ]
        
        if related_quizzes:
            vuln_info['related_quizzes'] = related_quizzes
        
        return vuln_info
    
    def analyze_scan_for_education(self, scan_results: Dict) -> List[Dict[str, Any]]:
        """
        Analyze scan results for educational opportunities
        
        Args:
            scan_results: Security scan results
        
        Returns:
            List of educational recommendations based on findings
        """
        educational_items = []
        
        # Check for vulnerabilities in scan results
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', '').lower()
            
            # Map common vulnerability types to educational content IDs
            vuln_mapping = {
                'xss': 'xss',
                'sql_injection': 'sql_injection',
                'csrf': 'csrf',
                'security_headers': 'security_headers_misconfig'
            }
            
            if vuln_type in vuln_mapping:
                educational_items.append({
                    'type': 'vulnerability_education',
                    'vulnerability_id': vuln_mapping[vuln_type],
                    'title': f'Learn about {vuln_type.upper()}',
                    'description': f'Your scan found {vuln_type.upper()} issues. Learn how to fix them.',
                    'severity': vuln.get('severity', 'MEDIUM'),
                    'context': {
                        'finding': vuln,
                        'recommended_action': 'Study prevention techniques'
                    }
                })
        
        # Check for security header issues
        security_headers = scan_results.get('security_headers', {})
        missing_headers = [
            header for header, info in security_headers.items()
            if not info.get('present', False)
        ]
        
        if missing_headers:
            educational_items.append({
                'type': 'security_headers_education',
                'title': 'Missing Security Headers',
                'description': f'Your website is missing {len(missing_headers)} important security headers.',
                'severity': 'MEDIUM',
                'content': {
                    'missing_headers': missing_headers,
                    'tutorial': 'Learn how to implement security headers for better protection.'
                }
            })
        
        return educational_items
    
    def generate_fix_instructions(self, vuln_id: str, 
                                 context: Dict) -> Dict[str, Any]:
        """
        Generate specific fix instructions for a vulnerability
        
        Args:
            vuln_id: Vulnerability identifier
            context: Context information (language, framework, specific issue)
        
        Returns:
            Step-by-step fix instructions
        """
        if vuln_id not in self.vulnerabilities:
            raise ValueError(f"Unknown vulnerability: {vuln_id}")
        
        vuln_info = self.vulnerabilities[vuln_id]
        
        # Extract context for personalized instructions
        language = context.get('language')
        framework = context.get('framework')
        specific_issue = context.get('specific_issue')
        
        instructions = {
            'vulnerability': vuln_info['name'],
            'severity': context.get('severity', 'MEDIUM'),
            'steps': []
        }
        
        # Generic educational steps applicable to any vulnerability
        instructions['steps'].extend([
            {
                'step': 1,
                'title': 'Understand the vulnerability',
                'description': f'Learn how {vuln_info["name"]} works and why it\'s dangerous.',
                'resources': vuln_info.get('resources', [])[:2]  # Limit to 2 resources
            },
            {
                'step': 2,
                'title': 'Identify vulnerable code',
                'description': 'Locate the code that processes user input without proper validation.',
                'action': 'Search for user input handling in your codebase'
            }
        ])
        
        # Add language/framework specific implementation steps
        if language and language in vuln_info.get('code_snippets', {}):
            lang_snippets = vuln_info['code_snippets'][language]
            
            if framework and framework in lang_snippets:
                instructions['steps'].append({
                    'step': 3,
                    'title': 'Implement secure code',
                    'description': f'Use this {framework}-specific pattern to fix the issue:',
                    'code_snippet': lang_snippets[framework],
                    'language': language
                })
            else:
                # Use first available snippet for the language
                first_framework = next(iter(lang_snippets))
                instructions['steps'].append({
                    'step': 3,
                    'title': 'Implement secure code',
                    'description': f'Use this {language} pattern to fix the issue:',
                    'code_snippet': lang_snippets[first_framework],
                    'language': language
                })
        
        # Add testing steps
        instructions['steps'].append({
            'step': 4,
            'title': 'Test your fix',
            'description': 'Verify that the vulnerability is fixed by testing with malicious inputs.',
            'action': 'Use the original attack payload to confirm it no longer works'
        })
        
        # Add prevention steps to avoid future issues
        instructions['steps'].append({
            'step': 5,
            'title': 'Prevent future issues',
            'description': 'Implement these preventive measures:',
            'checklist': vuln_info.get('prevention', [])[:3]  # Top 3 prevention measures
        })
        
        return instructions
    
    def take_quiz(self, quiz_id: str, answers: Dict[str, int]) -> Dict[str, Any]:
        """
        Take a quiz and get results
        
        Args:
            quiz_id: Quiz identifier
            answers: Dictionary of question_id -> answer_index (0-based)
        
        Returns:
            Quiz results with score and feedback
        """
        if quiz_id not in self.quizzes:
            raise ValueError(f"Unknown quiz: {quiz_id}")
        
        quiz = self.quizzes[quiz_id]
        questions = quiz['questions']
        
        # Calculate score
        correct = 0
        total = len(questions)
        
        detailed_results = []
        
        for question in questions:
            qid = question['id']
            user_answer = answers.get(qid)
            correct_answer = question['correct_answer']
            
            is_correct = user_answer == correct_answer
            
            if is_correct:
                correct += 1
            
            detailed_results.append({
                'question_id': qid,
                'question': question['question'],
                'user_answer': user_answer,
                'correct_answer': correct_answer,
                'is_correct': is_correct,
                'explanation': question.get('explanation', '')
            })
        
        # Calculate percentage score
        score = (correct / total) * 100 if total > 0 else 0
        passed = score >= quiz.get('passing_score', 70)
        
        # Update user progress if user is logged in
        user_id = session.get('user_id')
        if user_id:
            self._update_user_progress(user_id, quiz_id, score, passed)
        
        return {
            'quiz_id': quiz_id,
            'score': score,
            'passed': passed,
            'correct_answers': correct,
            'total_questions': total,
            'detailed_results': detailed_results,
            'recommendations': self._generate_quiz_recommendations(score, quiz)
        }
    
    def _update_user_progress(self, user_id: str, quiz_id: str, 
                             score: float, passed: bool):
        """Update user progress in learning"""
        if user_id not in self.user_progress:
            # Initialize user progress data structure
            self.user_progress[user_id] = {
                'completed_quizzes': [],
                'scores': {},
                'learning_paths': {}
            }
        
        user_data = self.user_progress[user_id]
        
        # Track completed quizzes
        if quiz_id not in user_data['completed_quizzes']:
            user_data['completed_quizzes'].append(quiz_id)
        
        # Store quiz score
        user_data['scores'][quiz_id] = score
        
        # Update learning path progress if applicable
        for path_name, quizzes in self.learning_paths.items():
            if quiz_id in quizzes:
                if path_name not in user_data['learning_paths']:
                    user_data['learning_paths'][path_name] = {
                        'completed': [],
                        'progress': 0
                    }
                
                # Add quiz to completed list for this path
                if quiz_id not in user_data['learning_paths'][path_name]['completed']:
                    user_data['learning_paths'][path_name]['completed'].append(quiz_id)
                
                # Calculate progress percentage for this learning path
                total_in_path = len(quizzes)
                completed_in_path = len(user_data['learning_paths'][path_name]['completed'])
                progress = (completed_in_path / total_in_path) * 100
                user_data['learning_paths'][path_name]['progress'] = progress
    
    def _generate_quiz_recommendations(self, score: float, quiz: Dict) -> List[str]:
        """Generate learning recommendations based on quiz score"""
        recommendations = []
        
        if score < 50:
            recommendations.extend([
                'Review the basic concepts of this vulnerability',
                'Study the provided examples more carefully',
                'Take the beginner lesson before retrying this quiz'
            ])
        elif score < 70:
            recommendations.extend([
                'Review the questions you answered incorrectly',
                'Practice with the code examples',
                'Consider taking the intermediate lesson'
            ])
        elif score < 90:
            recommendations.extend([
                'Good understanding, consider advanced topics',
                'Try implementing the fixes in a practice project',
                'Explore related vulnerabilities'
            ])
        else:
            recommendations.extend([
                'Excellent understanding!',
                'Consider helping others learn about this topic',
                'Move on to more advanced security topics'
            ])
        
        return recommendations
    
    def get_user_progress(self, user_id: str) -> Dict[str, Any]:
        """Get user learning progress"""
        if user_id not in self.user_progress:
            # Return default progress for new users
            return {
                'completed_quizzes': [],
                'average_score': 0,
                'learning_paths': {}
            }
        
        user_data = self.user_progress[user_id]
        
        # Calculate average score across all quizzes taken
        scores = list(user_data.get('scores', {}).values())
        average_score = sum(scores) / len(scores) if scores else 0
        
        return {
            'completed_quizzes': user_data.get('completed_quizzes', []),
            'average_score': average_score,
            'learning_paths': user_data.get('learning_paths', {}),
            'total_quizzes_taken': len(scores)
        }

# Initialize tutor mode globally
tutor_mode = TutorMode()

# Tutor mode routes
@tutor_blueprint.route('/')
@login_required
def tutor_home():
    """Tutor mode home page - shows learning dashboard"""
    # Get user progress from session or use demo user
    user_id = session.get('user_id', 'demo_user')
    progress = tutor_mode.get_user_progress(user_id)
    
    # Get recommended learning paths
    learning_paths = tutor_mode.learning_paths
    
    # Render tutor home template with context data
    return render_template(
        'tutor/home.html',
        title='Security Tutor',
        progress=progress,
        learning_paths=learning_paths,
        difficulty_levels=[d.value for d in DifficultyLevel]  # Convert Enum values to strings
    )

@tutor_blueprint.route('/vulnerability/<vuln_id>')
@login_required
def vulnerability_detail(vuln_id):
    """Vulnerability educational page - detailed view"""
    try:
        # Get user context from session for personalized learning
        user_context = {
            'primary_language': session.get('primary_language', 'python'),
            'primary_framework': session.get('primary_framework', 'flask')
        }
        
        # Retrieve vulnerability information with personalization
        vuln_info = tutor_mode.get_vulnerability_info(vuln_id, user_context)
        
        # Render vulnerability detail template
        return render_template(
            'tutor/vulnerability_detail.html',
            title=f"Learn: {vuln_info['name']}",
            vulnerability=vuln_info,
            user_context=user_context
        )
        
    except ValueError as e:
        # Handle invalid vulnerability ID
        return render_template('errors/404.html'), 404

@tutor_blueprint.route('/scan/<scan_id>/learn')
@login_required
def learn_from_scan(scan_id):
    """Learn from specific scan results - connects scanning with education"""
    # In production, would fetch scan from database
    # For demonstration, use sample scan data
    
    sample_scan = {
        'vulnerabilities': [
            {
                'type': 'XSS',
                'severity': 'HIGH',
                'description': 'Reflected XSS in search parameter',
                'location': 'https://example.com/search?q='
            }
        ],
        'security_headers': {
            'Content-Security-Policy': {'present': False},
            'X-Frame-Options': {'present': True}
        }
    }
    
    # Analyze scan results for educational opportunities
    educational_items = tutor_mode.analyze_scan_for_education(sample_scan)
    
    # Render learn from scan template
    return render_template(
        'tutor/learn_from_scan.html',
        title='Learn from Scan Results',
        scan_id=scan_id,
        educational_items=educational_items
    )

@tutor_blueprint.route('/quiz/<quiz_id>')
@login_required
def take_quiz_page(quiz_id):
    """Quiz taking page - displays quiz questions"""
    if quiz_id not in tutor_mode.quizzes:
        # Handle invalid quiz ID
        return render_template('errors/404.html'), 404
    
    quiz = tutor_mode.quizzes[quiz_id]
    
    # Render quiz template
    return render_template(
        'tutor/quiz.html',
        title=f"Quiz: {quiz['title']}",
        quiz=quiz
    )

@tutor_blueprint.route('/fix-instructions')
@login_required
def fix_instructions():
    """Generate fix instructions for a vulnerability - educational remediation guide"""
    # Extract parameters from query string
    vuln_id = request.args.get('vulnerability')
    language = request.args.get('language', 'python')
    framework = request.args.get('framework', 'flask')
    severity = request.args.get('severity', 'MEDIUM')
    
    # Validate required parameter
    if not vuln_id:
        return jsonify({
            'status': 'error',
            'message': 'Vulnerability ID is required'
        }), 400
    
    try:
        # Create context for fix instructions
        context = {
            'language': language,
            'framework': framework,
            'severity': severity
        }
        
        # Generate step-by-step fix instructions
        instructions = tutor_mode.generate_fix_instructions(vuln_id, context)
        
        # Render fix instructions template
        return render_template(
            'tutor/fix_instructions.html',
            title=f"Fix: {instructions['vulnerability']}",
            instructions=instructions
        )
        
    except ValueError as e:
        # Handle invalid vulnerability ID
        return render_template('errors/404.html'), 404

@tutor_blueprint.route('/api/quiz/<quiz_id>/submit', methods=['POST'])
@login_required
def api_submit_quiz(quiz_id):
    """API endpoint to submit quiz answers - handles AJAX requests"""
    try:
        # Parse JSON request body
        data = request.get_json()
        
        # Validate request data
        if not data or 'answers' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Answers are required'
            }), 400
        
        answers = data['answers']
        
        # Process quiz submission and calculate results
        results = tutor_mode.take_quiz(quiz_id, answers)
        
        # Return success response with quiz results
        return jsonify({
            'status': 'success',
            'data': results
        })
        
    except ValueError as e:
        # Handle invalid quiz ID or data
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400
    except Exception as e:
        # Log unexpected errors
        current_app.logger.error(f"Quiz submission error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error'
        }), 500

@tutor_blueprint.route('/api/progress')
@login_required
def api_get_progress():
    """API endpoint to get user progress - for AJAX updates"""
    user_id = session.get('user_id', 'demo_user')
    progress = tutor_mode.get_user_progress(user_id)
    
    # Return JSON response with progress data
    return jsonify({
        'status': 'success',
        'data': progress
    })

@tutor_blueprint.route('/api/recommendations')
@login_required
def api_get_recommendations():
    """API endpoint to get learning recommendations - personalized suggestions"""
    user_id = session.get('user_id', 'demo_user')
    progress = tutor_mode.get_user_progress(user_id)
    
    # Generate personalized recommendations based on user progress
    recommendations = []
    
    completed = set(progress.get('completed_quizzes', []))
    
    # Recommend quizzes not yet taken
    for quiz_id, quiz in tutor_mode.quizzes.items():
        if quiz_id not in completed:
            recommendations.append({
                'type': 'quiz',
                'id': quiz_id,
                'title': quiz['title'],
                'reason': 'New topic to learn',
                'priority': 'medium'
            })
    
    # Recommend vulnerabilities based on user's primary programming language
    primary_language = session.get('primary_language', 'python')
    
    for vuln_id, vuln_info in tutor_mode.vulnerabilities.items():
        if primary_language in vuln_info.get('code_snippets', {}):
            recommendations.append({
                'type': 'vulnerability',
                'id': vuln_id,
                'title': vuln_info['name'],
                'reason': f'Relevant to your {primary_language} projects',
                'priority': 'high'
            })
    
    # Return top 5 recommendations
    return jsonify({
        'status': 'success',
        'data': {
            'recommendations': recommendations[:5],
            'total_recommendations': len(recommendations)
        }
    })

# Export blueprint and tutor mode for use in other modules
__all__ = ['tutor_blueprint', 'TutorMode']