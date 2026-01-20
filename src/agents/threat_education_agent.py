# src/agents/threat_education_agent.py
"""
Threat Education Agent
Specialized agent for security education, training, and awareness
Provides explanations, examples, and remediation guidance for security issues
"""

import torch
import json
import random
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, asdict
import markdown
from pathlib import Path

# Enum for education levels
class EducationLevel(Enum):
    """Security education proficiency levels"""
    BEGINNER = "beginner"        # No prior security knowledge
    INTERMEDIATE = "intermediate" # Basic security understanding
    ADVANCED = "advanced"        # Security professional
    EXPERT = "expert"           # Security specialist

# Enum for learning styles
class LearningStyle(Enum):
    """Different learning style preferences"""
    VISUAL = "visual"      # Prefers diagrams, charts, visuals
    AUDITORY = "auditory"  # Prefers explanations, audio
    READ_WRITE = "read_write"  # Prefers text, documentation
    KINESTHETIC = "kinesthetic" # Prefers hands-on, examples

# Data class for security lesson
@dataclass
class SecurityLesson:
    """Individual security lesson/topic"""
    lesson_id: str
    title: str
    category: str                    # OWASP, Network, Crypto, etc.
    difficulty: EducationLevel       # Target difficulty level
    estimated_time: int              # Minutes to complete
    learning_objectives: List[str]   # What learner will achieve
    content: Dict[str, Any]         # Lesson content by style
    examples: List[Dict[str, Any]]   # Real-world examples
    exercises: List[Dict[str, Any]]  # Practice exercises
    references: List[Dict[str, Any]] # Additional resources
    last_updated: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['difficulty'] = self.difficulty.value
        data['last_updated'] = self.last_updated.isoformat()
        return data

# Data class for threat explanation
@dataclass
class ThreatExplanation:
    """Comprehensive threat explanation"""
    threat_name: str
    threat_type: str
    risk_level: str                  # Critical, High, Medium, Low
    description: str                 # What it is
    how_it_works: str               # Technical explanation
    real_world_examples: List[str]  # Famous incidents
    attack_vectors: List[str]       # How attackers exploit
    prevention: List[str]           # How to prevent
    detection: List[str]            # How to detect
    remediation: List[str]          # How to fix if found
    code_examples: Dict[str, str]   # Vulnerable vs secure code
    tools_for_testing: List[str]    # Testing tools
    compliance_requirements: List[str] # Regulatory requirements
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)

class ThreatEducationAgent:
    """
    Threat Education Agent
    Provides security education, explanations, and remediation guidance
    Adapts to different learning styles and proficiency levels
    """
    
    def __init__(self, agent_id: str = "threat_education_001"):
        """
        Initialize Threat Education Agent
        
        Args:
            agent_id: Unique identifier for this agent instance
        """
        self.agent_id = agent_id
        self.name = "Threat Education Agent"
        
        # Education database
        self.lessons = self._load_security_lessons()
        self.threat_explanations = self._load_threat_explanations()
        
        # User profiles (in production, would be persistent)
        self.user_profiles: Dict[str, Dict[str, Any]] = {}
        
        # Learning analytics
        self.analytics = {
            'lessons_delivered': 0,
            'explanations_provided': 0,
            'users_educated': 0,
            'average_engagement': 0.0,
            'knowledge_gap_identified': 0
        }
        
        # Agent confidence
        self.confidence = 0.9  # High confidence for education
        
        # Adaptive learning parameters
        self.adaptive_parameters = {
            'difficulty_scaling': 0.1,  # How quickly to increase difficulty
            'reinforcement_frequency': 3,  # Reinforce concepts every N lessons
            'style_preference_weight': 0.7  # How much to weight learning style
        }
    
    def _load_security_lessons(self) -> Dict[str, SecurityLesson]:
        """
        Load security lessons database
        
        Returns:
            Dictionary of lessons keyed by lesson_id
        """
        lessons = {}
        
        # OWASP Top-10 Lessons
        owasp_lessons = [
            SecurityLesson(
                lesson_id="OWASP-A01",
                title="Broken Access Control",
                category="OWASP Top-10",
                difficulty=EducationLevel.INTERMEDIATE,
                estimated_time=45,
                learning_objectives=[
                    "Understand access control principles",
                    "Identify broken access control vulnerabilities",
                    "Implement proper access control mechanisms",
                    "Test for access control weaknesses"
                ],
                content={
                    "visual": "Flowchart showing proper vs improper access control",
                    "auditory": "Audio explanation of access control concepts",
                    "read_write": "Detailed text explanation with examples",
                    "kinesthetic": "Interactive access control simulation"
                },
                examples=[
                    {
                        "title": "IDOR Vulnerability",
                        "description": "Direct object reference without authorization",
                        "scenario": "User can access other users' data by changing ID parameter",
                        "impact": "Data breach, privacy violation"
                    },
                    {
                        "title": "Privilege Escalation",
                        "description": "User gains unauthorized privileges",
                        "scenario": "Regular user accesses admin functions",
                        "impact": "System compromise, data manipulation"
                    }
                ],
                exercises=[
                    {
                        "type": "multiple_choice",
                        "question": "Which is NOT a valid access control mechanism?",
                        "options": ["RBAC", "ABAC", "IBAC", "PBAC (Public Based)"],
                        "answer": 3,
                        "explanation": "PBAC (Public Based Access Control) is not a standard access control model"
                    },
                    {
                        "type": "code_review",
                        "task": "Identify the access control vulnerability",
                        "code": "if user_id == requested_id:\n    return user_data",
                        "vulnerability": "Missing authentication check",
                        "fix": "Add role-based permission check"
                    }
                ],
                references=[
                    {
                        "title": "OWASP Access Control Guide",
                        "url": "https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls",
                        "type": "guide"
                    },
                    {
                        "title": "NIST Access Control Publication",
                        "url": "https://csrc.nist.gov/projects/access-control",
                        "type": "standard"
                    }
                ],
                last_updated=datetime.now()
            ),
            SecurityLesson(
                lesson_id="OWASP-A02",
                title="Cryptographic Failures",
                category="OWASP Top-10",
                difficulty=EducationLevel.ADVANCED,
                estimated_time=60,
                learning_objectives=[
                    "Understand cryptographic principles",
                    "Identify common crypto mistakes",
                    "Implement proper encryption",
                    "Manage cryptographic keys securely"
                ],
                content={
                    "visual": "Encryption/decryption flow diagrams",
                    "auditory": "Podcast-style explanation of crypto concepts",
                    "read_write": "Technical paper on crypto implementations",
                    "kinesthetic": "Hands-on crypto implementation exercise"
                },
                examples=[
                    {
                        "title": "Weak Encryption Algorithm",
                        "description": "Using deprecated algorithms like MD5 or SHA-1",
                        "scenario": "Password hashed with MD5",
                        "impact": "Easy password cracking, data compromise"
                    },
                    {
                        "title": "Improper Key Management",
                        "description": "Hardcoded encryption keys in source code",
                        "scenario": "API keys stored in GitHub repository",
                        "impact": "Complete system compromise"
                    }
                ],
                exercises=[
                    {
                        "type": "true_false",
                        "question": "AES-128 is considered insecure for most applications",
                        "answer": False,
                        "explanation": "AES-128 is still considered secure for most applications, though AES-256 is recommended for highly sensitive data"
                    }
                ],
                references=[
                    {
                        "title": "Cryptographic Right Answers",
                        "url": "https://latacora.micro.blog/2018/04/03/cryptographic-right-answers.html",
                        "type": "guide"
                    }
                ],
                last_updated=datetime.now()
            )
        ]
        
        for lesson in owasp_lessons:
            lessons[lesson.lesson_id] = lesson
        
        # Web Security Fundamentals
        web_lessons = [
            SecurityLesson(
                lesson_id="WEB-101",
                title="Cross-Site Scripting (XSS)",
                category="Web Security",
                difficulty=EducationLevel.INTERMEDIATE,
                estimated_time=50,
                learning_objectives=[
                    "Understand XSS attack vectors",
                    "Identify XSS vulnerabilities in code",
                    "Implement XSS prevention techniques",
                    "Use security headers for XSS protection"
                ],
                content={
                    "visual": "XSS attack flow animation",
                    "auditory": "XSS exploitation walkthrough",
                    "read_write": "XSS prevention checklist",
                    "kinesthetic": "XSS attack simulation lab"
                },
                examples=[
                    {
                        "title": "Stored XSS in Comments",
                        "description": "Malicious script stored in database",
                        "scenario": "Attackers post script in comment field",
                        "impact": "All users who view comments get infected"
                    },
                    {
                        "title": "Reflected XSS in Search",
                        "description": "Script reflected in search results",
                        "scenario": "Search term includes script that executes",
                        "impact": "Users clicking malicious links get compromised"
                    }
                ],
                exercises=[
                    {
                        "type": "code_fix",
                        "task": "Fix this XSS vulnerability",
                        "vulnerable_code": "<div><?php echo $_GET['input']; ?></div>",
                        "secure_code": "<div><?php echo htmlspecialchars($_GET['input'], ENT_QUOTES, 'UTF-8'); ?></div>",
                        "explanation": "Use htmlspecialchars to escape HTML entities"
                    }
                ],
                references=[
                    {
                        "title": "XSS Prevention Cheat Sheet",
                        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                        "type": "cheat_sheet"
                    }
                ],
                last_updated=datetime.now()
            )
        ]
        
        for lesson in web_lessons:
            lessons[lesson.lesson_id] = lesson
        
        return lessons
    
    def _load_threat_explanations(self) -> Dict[str, ThreatExplanation]:
        """
        Load comprehensive threat explanations
        
        Returns:
            Dictionary of threat explanations keyed by threat name
        """
        explanations = {}
        
        # OWASP Top-10 Threats
        explanations["SQL Injection"] = ThreatExplanation(
            threat_name="SQL Injection",
            threat_type="Injection",
            risk_level="Critical",
            description="SQL Injection occurs when untrusted data is sent to an interpreter as part of a command or query, tricking the interpreter into executing unintended commands or accessing unauthorized data.",
            how_it_works="Attackers insert malicious SQL code into application inputs. When the application concatenates this input directly into SQL queries without proper sanitization, the database executes the malicious code.",
            real_world_examples=[
                "2011 Sony Pictures Hack - 77 million accounts compromised",
                "2009 Heartland Payment Systems - 130 million credit cards stolen",
                "2017 Equifax breach - 147 million records exposed"
            ],
            attack_vectors=[
                "User input fields (login, search, forms)",
                "URL parameters",
                "HTTP headers",
                "Cookie values"
            ],
            prevention=[
                "Use parameterized queries (prepared statements)",
                "Implement proper input validation",
                "Use stored procedures",
                "Apply the principle of least privilege to database accounts",
                "Use ORM frameworks with built-in protection"
            ],
            detection=[
                "Static code analysis for string concatenation in SQL",
                "Dynamic testing with SQL injection payloads",
                "Database log monitoring for unusual queries",
                "Web Application Firewall (WAF) alerts"
            ],
            remediation=[
                "Immediately patch vulnerable code",
                "Rotate database credentials",
                "Review database logs for evidence of exploitation",
                "Implement Web Application Firewall rules"
            ],
            code_examples={
                "vulnerable": "cursor.execute(\"SELECT * FROM users WHERE username = '\" + username + \"' AND password = '\" + password + \"'\")",
                "secure": "cursor.execute(\"SELECT * FROM users WHERE username = %s AND password = %s\", (username, password))"
            },
            tools_for_testing=[
                "sqlmap - Automated SQL injection tool",
                "Burp Suite - Manual testing proxy",
                "OWASP ZAP - Automated security scanner",
                "Acunetix - Web vulnerability scanner"
            ],
            compliance_requirements=[
                "PCI-DSS Requirement 6.5.1",
                "ISO 27001 A.14.2.5",
                "HIPAA Security Rule §164.312"
            ]
        )
        
        explanations["Cross-Site Scripting (XSS)"] = ThreatExplanation(
            threat_name="Cross-Site Scripting (XSS)",
            threat_type="Client-side",
            risk_level="High",
            description="XSS allows attackers to inject client-side scripts into web pages viewed by other users, potentially stealing cookies, session tokens, or other sensitive information.",
            how_it_works="Attackers inject malicious JavaScript into web applications. When other users visit the compromised page, their browsers execute the malicious script in the context of the vulnerable site.",
            real_world_examples=[
                "2005 MySpace XSS worm - affected 1 million users",
                "2010 Twitter XSS worm - spread through tweets",
                "2018 British Airways - payment data stolen via XSS"
            ],
            attack_vectors=[
                "Unsanitized user input in HTML output",
                "JavaScript eval() with user input",
                "innerHTML assignments with untrusted data",
                "URL parameters reflected without encoding"
            ],
            prevention=[
                "Implement Content Security Policy (CSP)",
                "Escape all untrusted data based on output context",
                "Use template engines with auto-escaping",
                "Validate and sanitize all user inputs",
                "Use HTTP-only cookies for session management"
            ],
            detection=[
                "Static analysis for unsafe JavaScript functions",
                "Dynamic testing with XSS payloads",
                "CSP violation reports",
                "Browser security headers analysis"
            ],
            remediation=[
                "Implement proper output encoding",
                "Add security headers (X-XSS-Protection, CSP)",
                "Sanitize existing user-generated content",
                "Use safe JavaScript functions"
            ],
            code_examples={
                "vulnerable": "document.getElementById('output').innerHTML = userInput;",
                "secure": "document.getElementById('output').textContent = userInput;"
            },
            tools_for_testing=[
                "Burp Suite with XSS payloads",
                "OWASP ZAP XSS scanner",
                "XSStrike - Advanced XSS detection",
                "DOM-based XSS scanners"
            ],
            compliance_requirements=[
                "PCI-DSS Requirement 6.5.7",
                "OWASP Top-10 A03:2021",
                "ISO 27001 A.14.2.5"
            ]
        )
        
        explanations["Cross-Site Request Forgery (CSRF)"] = ThreatExplanation(
            threat_name="Cross-Site Request Forgery (CSRF)",
            threat_type="Client-side",
            risk_level="Medium",
            description="CSRF tricks a victim into submitting a malicious request to a web application where they're authenticated, performing actions without their consent.",
            how_it_works="Attackers create malicious websites or links that submit requests to vulnerable applications. If the victim is logged into the vulnerable site, these requests are made with the victim's credentials.",
            real_world_examples=[
                "2007 Gmail CSRF attack - allowed email forwarding",
                "2008 Netflix CSRF - changed shipping addresses",
                "2015 YouTube CSRF - allowed video deletion"
            ],
            attack_vectors=[
                "Malicious links in emails or forums",
                "Compromised websites with auto-submitting forms",
                "Social engineering to click links"
            ],
            prevention=[
                "Implement CSRF tokens for state-changing requests",
                "Use SameSite cookie attribute",
                "Validate Origin and Referer headers",
                "Require re-authentication for sensitive actions"
            ],
            detection=[
                "Check for missing CSRF tokens",
                "Review authentication flows",
                "Test state-changing endpoints",
                "Analyze security headers"
            ],
            remediation=[
                "Add CSRF tokens to all forms and AJAX requests",
                "Implement double-submit cookie pattern",
                "Add security middleware for CSRF protection",
                "Update session management"
            ],
            code_examples={
                "vulnerable": "<form action=\"/transfer\" method=\"POST\">\n  <input type=\"hidden\" name=\"amount\" value=\"1000\">\n</form>",
                "secure": "<form action=\"/transfer\" method=\"POST\">\n  <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token }}\">\n  <input type=\"hidden\" name=\"amount\" value=\"1000\">\n</form>"
            },
            tools_for_testing=[
                "Burp Suite CSRF scanner",
                "OWASP ZAP",
                "Custom CSRF testing scripts"
            ],
            compliance_requirements=[
                "PCI-DSS Requirement 6.5.9",
                "OWASP Top-10 A05:2021"
            ]
        )
        
        return explanations
    
    def analyze(self, security_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze security data and provide educational content
        
        Args:
            security_data: Dictionary containing:
                - threat_type: Type of threat detected
                - threat_level: Severity score
                - evidence: Evidence of threat
                - user_context: Optional user information
                - learning_style: Optional preferred learning style
                - education_level: Optional user's education level
                
        Returns:
            Dictionary with educational content and guidance
        """
        import time
        start_time = time.time()
        
        # Extract parameters
        threat_type = security_data.get('threat_type', 'GENERAL_SECURITY')
        threat_level = security_data.get('threat_level', 0.5)
        evidence = security_data.get('evidence', [])
        user_context = security_data.get('user_context', {})
        learning_style_str = security_data.get('learning_style')
        education_level_str = security_data.get('education_level')
        
        # Determine user profile
        user_id = user_context.get('user_id', 'anonymous')
        if user_id not in self.user_profiles:
            self.user_profiles[user_id] = self._create_user_profile(user_context)
        
        user_profile = self.user_profiles[user_id]
        
        # Determine learning style
        if learning_style_str:
            try:
                learning_style = LearningStyle(learning_style_str.lower())
            except ValueError:
                learning_style = user_profile['preferred_style']
        else:
            learning_style = user_profile['preferred_style']
        
        # Determine education level
        if education_level_str:
            try:
                education_level = EducationLevel(education_level_str.lower())
            except ValueError:
                education_level = user_profile['education_level']
        else:
            education_level = user_profile['education_level']
        
        # Step 1: Provide threat explanation
        threat_explanation = self._get_threat_explanation(threat_type, education_level)
        
        # Step 2: Provide tailored lesson
        lesson = self._get_tailored_lesson(threat_type, education_level, learning_style)
        
        # Step 3: Generate actionable guidance
        guidance = self._generate_guidance(threat_type, threat_level, evidence, education_level)
        
        # Step 4: Update user profile with this interaction
        self._update_user_profile(user_id, threat_type, education_level)
        
        # Step 5: Update analytics
        self.analytics['explanations_provided'] += 1
        if user_id == 'anonymous':
            self.analytics['users_educated'] += 1
        
        processing_time = time.time() - start_time
        
        return {
            'agent_id': self.agent_id,
            'agent_name': self.name,
            'threat_type': threat_type,
            'threat_level': threat_level,
            'education_level': education_level.value,
            'learning_style': learning_style.value,
            'threat_explanation': threat_explanation.to_dict() if threat_explanation else None,
            'tailored_lesson': lesson.to_dict() if lesson else None,
            'actionable_guidance': guidance,
            'user_profile_updated': True,
            'processing_time': processing_time,
            'confidence': self.confidence,
            'reasoning_state': self._get_reasoning_state(),
            'decision': {
                'educational_value': 0.8,
                'confidence': self.confidence,
                'evidence': [f"Provided {education_level.value} level education on {threat_type}"]
            }
        }
    
    def _create_user_profile(self, user_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create new user profile
        
        Args:
            user_context: User information
            
        Returns:
            User profile dictionary
        """
        # Default to intermediate level if not specified
        default_level = EducationLevel.INTERMEDIATE
        
        # Try to infer from context
        if 'role' in user_context:
            role = user_context['role'].lower()
            if 'developer' in role or 'engineer' in role:
                default_level = EducationLevel.ADVANCED
            elif 'manager' in role or 'business' in role:
                default_level = EducationLevel.BEGINNER
            elif 'security' in role or 'analyst' in role:
                default_level = EducationLevel.EXPERT
        
        # Random learning style (in production, would use assessment)
        styles = list(LearningStyle)
        preferred_style = random.choice(styles)
        
        return {
            'user_id': user_context.get('user_id', 'anonymous'),
            'education_level': default_level,
            'preferred_style': preferred_style,
            'topics_studied': [],
            'knowledge_gaps': [],
            'interaction_history': [],
            'last_active': datetime.now(),
            'engagement_score': 0.5,
            'completion_rate': 0.0,
            'adaptive_difficulty': default_level
        }
    
    def _get_threat_explanation(self, threat_type: str,
                              education_level: EducationLevel) -> Optional[ThreatExplanation]:
        """
        Get threat explanation tailored to education level
        
        Args:
            threat_type: Type of threat
            education_level: User's education level
            
        Returns:
            Tailored threat explanation or None
        """
        # Find matching threat explanation
        threat_key = None
        for key in self.threat_explanations.keys():
            if threat_type.lower() in key.lower() or key.lower() in threat_type.lower():
                threat_key = key
                break
        
        if not threat_key:
            # Create generic explanation
            return self._create_generic_explanation(threat_type, education_level)
        
        explanation = self.threat_explanations[threat_key]
        
        # Tailor explanation to education level
        tailored_explanation = self._tailor_explanation(explanation, education_level)
        
        return tailored_explanation
    
    def _create_generic_explanation(self, threat_type: str,
                                  education_level: EducationLevel) -> ThreatExplanation:
        """
        Create generic threat explanation for unknown threats
        
        Args:
            threat_type: Type of threat
            education_level: User's education level
            
        Returns:
            Generic threat explanation
        """
        # Adjust complexity based on education level
        if education_level == EducationLevel.BEGINNER:
            description = f"{threat_type} is a security issue that could harm computer systems."
            how_it_works = "Attackers find weaknesses in software to cause problems."
        elif education_level == EducationLevel.INTERMEDIATE:
            description = f"{threat_type} is a vulnerability that attackers can exploit to compromise systems."
            how_it_works = f"Attackers leverage specific techniques to exploit {threat_type} vulnerabilities."
        else:
            description = f"{threat_type} represents a security vulnerability class with specific attack vectors."
            how_it_works = f"Technical exploitation of {threat_type} involves specific patterns and techniques."
        
        return ThreatExplanation(
            threat_name=threat_type,
            threat_type="General Security",
            risk_level="Medium",
            description=description,
            how_it_works=how_it_works,
            real_world_examples=["Various documented incidents"],
            attack_vectors=["Multiple potential vectors"],
            prevention=["Follow security best practices", "Regular security testing"],
            detection=["Security monitoring", "Vulnerability scanning"],
            remediation=["Patch systems", "Update security controls"],
            code_examples={
                "vulnerable": "// Example of insecure code",
                "secure": "// Example of secure code"
            },
            tools_for_testing=["General security scanners"],
            compliance_requirements=["General security standards"]
        )
    
    def _tailor_explanation(self, explanation: ThreatExplanation,
                          education_level: EducationLevel) -> ThreatExplanation:
        """
        Tailor explanation to education level
        
        Args:
            explanation: Original threat explanation
            education_level: Target education level
            
        Returns:
            Tailored threat explanation
        """
        # Create a copy to modify
        import copy
        tailored = copy.deepcopy(explanation)
        
        # Simplify for beginners
        if education_level == EducationLevel.BEGINNER:
            tailored.description = self._simplify_text(explanation.description, 2)
            tailored.how_it_works = self._simplify_text(explanation.how_it_works, 2)
            tailored.real_world_examples = explanation.real_world_examples[:1]
            tailored.attack_vectors = explanation.attack_vectors[:2]
            tailored.prevention = explanation.prevention[:3]
            tailored.remediation = explanation.remediation[:2]
        
        # Expand for experts
        elif education_level == EducationLevel.EXPERT:
            # Add technical details
            tailored.description += "\n\nTechnical Classification: CWE-based analysis available."
            tailored.how_it_works += "\n\nAdvanced exploitation techniques include memory corruption and protocol manipulation."
        
        return tailored
    
    def _simplify_text(self, text: str, sentence_count: int) -> str:
        """
        Simplify text to specified number of sentences
        
        Args:
            text: Original text
            sentence_count: Number of sentences to keep
            
        Returns:
            Simplified text
        """
        sentences = text.split('. ')
        simplified = '. '.join(sentences[:sentence_count])
        if simplified and not simplified.endswith('.'):
            simplified += '.'
        return simplified
    
    def _get_tailored_lesson(self, threat_type: str,
                           education_level: EducationLevel,
                           learning_style: LearningStyle) -> Optional[SecurityLesson]:
        """
        Get tailored lesson based on threat and user preferences
        
        Args:
            threat_type: Type of threat
            education_level: User's education level
            learning_style: Preferred learning style
            
        Returns:
            Tailored security lesson or None
        """
        # Find relevant lessons
        relevant_lessons = []
        for lesson_id, lesson in self.lessons.items():
            # Match by threat type in title or category
            if (threat_type.lower() in lesson.title.lower() or
                threat_type.lower() in lesson.category.lower()):
                relevant_lessons.append(lesson)
        
        if not relevant_lessons:
            # Create dynamic lesson
            return self._create_dynamic_lesson(threat_type, education_level, learning_style)
        
        # Select lesson closest to user's education level
        selected_lesson = min(
            relevant_lessons,
            key=lambda l: abs(l.difficulty.value - education_level.value)
        )
        
        # Tailor content to learning style
        tailored_lesson = self._tailor_lesson_content(selected_lesson, learning_style)
        
        return tailored_lesson
    
    def _create_dynamic_lesson(self, threat_type: str,
                             education_level: EducationLevel,
                             learning_style: LearningStyle) -> SecurityLesson:
        """
        Create dynamic lesson for unknown threats
        
        Args:
            threat_type: Type of threat
            education_level: User's education level
            learning_style: Preferred learning style
            
        Returns:
            Dynamic security lesson
        """
        # Generate lesson ID
        lesson_id = f"DYN-{hashlib.md5(threat_type.encode()).hexdigest()[:8]}"
        
        # Create content based on learning style
        content_templates = {
            LearningStyle.VISUAL: {
                "visual": f"Diagram showing {threat_type} attack flow",
                "auditory": f"Audio overview of {threat_type}",
                "read_write": f"Text explanation of {threat_type}",
                "kinesthetic": f"Interactive {threat_type} exercise"
            },
            LearningStyle.AUDITORY: {
                "visual": f"Simple diagram of {threat_type}",
                "auditory": f"Detailed podcast about {threat_type}",
                "read_write": f"Transcript of {threat_type} explanation",
                "kinesthetic": f"Audio-guided {threat_type} exercise"
            },
            LearningStyle.READ_WRITE: {
                "visual": f"Text-based diagram of {threat_type}",
                "auditory": f"Text-to-speech {threat_type} explanation",
                "read_write": f"Comprehensive article on {threat_type}",
                "kinesthetic": f"Written {threat_type} exercise"
            },
            LearningStyle.KINESTHETIC: {
                "visual": f"Interactive diagram of {threat_type}",
                "auditory": f"Exercise instructions for {threat_type}",
                "read_write": f"Exercise documentation for {threat_type}",
                "kinesthetic": f"Hands-on {threat_type} lab"
            }
        }
        
        return SecurityLesson(
            lesson_id=lesson_id,
            title=f"Understanding {threat_type}",
            category="Dynamic Lesson",
            difficulty=education_level,
            estimated_time=30,
            learning_objectives=[
                f"Understand {threat_type} basics",
                f"Identify {threat_type} vulnerabilities",
                f"Prevent {threat_type} attacks"
            ],
            content=content_templates.get(learning_style, content_templates[LearningStyle.READ_WRITE]),
            examples=[
                {
                    "title": f"Example {threat_type} Scenario",
                    "description": f"Real-world {threat_type} example",
                    "scenario": f"How {threat_type} might occur",
                    "impact": "Potential damage from this threat"
                }
            ],
            exercises=[
                {
                    "type": "multiple_choice",
                    "question": f"What is the primary risk of {threat_type}?",
                    "options": ["Data theft", "System crash", "Performance issues", "All of the above"],
                    "answer": 3,
                    "explanation": f"{threat_type} can have multiple impacts depending on context"
                }
            ],
            references=[
                {
                    "title": f"{threat_type} Security Guide",
                    "url": "https://owasp.org/",
                    "type": "guide"
                }
            ],
            last_updated=datetime.now()
        )
    
    def _tailor_lesson_content(self, lesson: SecurityLesson,
                             learning_style: LearningStyle) -> SecurityLesson:
        """
        Tailor lesson content to learning style
        
        Args:
            lesson: Original lesson
            learning_style: Preferred learning style
            
        Returns:
            Lesson with tailored content emphasis
        """
        import copy
        tailored = copy.deepcopy(lesson)
        
        # Reorder content based on learning style preference
        if learning_style in tailored.content:
            # Move preferred style to front in description
            preferred_content = tailored.content[learning_style.value]
            other_content = {k: v for k, v in tailored.content.items() 
                           if k != learning_style.value}
            
            # Create new content dict with preferred first
            new_content = {learning_style.value: preferred_content}
            new_content.update(other_content)
            tailored.content = new_content
        
        # Adjust examples based on style
        if learning_style == LearningStyle.VISUAL:
            # Add visual descriptions
            for example in tailored.examples:
                example['visual_hint'] = "Look for visual patterns in the attack flow"
        
        elif learning_style == LearningStyle.AUDITORY:
            # Add auditory hints
            for example in tailored.examples:
                example['audio_hint'] = "Listen for suspicious patterns in system logs"
        
        return tailored
    
    def _generate_guidance(self, threat_type: str, threat_level: float,
                         evidence: List[Dict], education_level: EducationLevel) -> Dict[str, Any]:
        """
        Generate actionable security guidance
        
        Args:
            threat_type: Type of threat
            threat_level: Severity score
            evidence: Evidence of threat
            education_level: User's education level
            
        Returns:
            Actionable guidance dictionary
        """
        # Determine guidance level based on threat level
        if threat_level >= 0.8:
            urgency = "IMMEDIATE ACTION REQUIRED"
            timeline = "Within 24 hours"
            priority = "Critical"
        elif threat_level >= 0.6:
            urgency = "HIGH PRIORITY ACTION"
            timeline = "Within 3 days"
            priority = "High"
        elif threat_level >= 0.4:
            urgency = "MEDIUM PRIORITY ACTION"
            timeline = "Within 1 week"
            priority = "Medium"
        else:
            urgency = "STANDARD ACTION"
            timeline = "Within 2 weeks"
            priority = "Low"
        
        # Generate step-by-step guidance
        steps = []
        
        # Step 1: Assessment
        steps.append({
            "step": 1,
            "title": "Assessment",
            "actions": [
                "Review the evidence provided",
                "Identify affected systems",
                "Determine scope of impact",
                "Document current state"
            ],
            "tools": ["Notepad", "Spreadsheet", "Diagram tool"],
            "time_estimate": "30 minutes"
        })
        
        # Step 2: Containment
        if threat_level >= 0.5:
            steps.append({
                "step": 2,
                "title": "Containment",
                "actions": [
                    "Isolate affected systems if possible",
                    "Block malicious IP addresses",
                    "Disable compromised accounts",
                    "Implement temporary security controls"
                ],
                "tools": ["Firewall", "IDS/IPS", "Access control system"],
                "time_estimate": "1-2 hours"
            })
        
        # Step 3: Remediation
        remediation_actions = []
        
        if threat_type == "SQL Injection":
            remediation_actions = [
                "Implement parameterized queries",
                "Update database access controls",
                "Review and sanitize all user inputs",
                "Rotate database credentials"
            ]
        elif threat_type == "XSS":
            remediation_actions = [
                "Implement output encoding",
                "Add Content Security Policy headers",
                "Sanitize user-generated content",
                "Update web application frameworks"
            ]
        else:
            remediation_actions = [
                "Apply security patches",
                "Update security configurations",
                "Review access controls",
                "Implement monitoring"
            ]
        
        steps.append({
            "step": 3,
            "title": "Remediation",
            "actions": remediation_actions,
            "tools": ["Code editor", "Security scanner", "Configuration management"],
            "time_estimate": "2-4 hours"
        })
        
        # Step 4: Verification
        steps.append({
            "step": 4,
            "title": "Verification",
            "actions": [
                "Test fixes in staging environment",
                "Verify security controls are working",
                "Conduct security scan",
                "Document remediation"
            ],
            "tools": ["Security testing tools", "Monitoring systems"],
            "time_estimate": "1-2 hours"
        })
        
        # Step 5: Prevention (for future)
        steps.append({
            "step": 5,
            "title": "Prevention",
            "actions": [
                "Implement security training",
                "Establish security review process",
                "Set up continuous monitoring",
                "Create incident response plan"
            ],
            "tools": ["Security training platform", "Monitoring tools"],
            "time_estimate": "Ongoing"
        })
        
        # Adjust guidance based on education level
        if education_level == EducationLevel.BEGINNER:
            # Simplify language, provide more hand-holding
            for step in steps:
                step['simplified'] = True
                step['actions'] = [a + " (ask for help if needed)" for a in step['actions']]
        
        return {
            "urgency": urgency,
            "priority": priority,
            "timeline": timeline,
            "threat_type": threat_type,
            "threat_level": threat_level,
            "evidence_summary": [e.get('type', 'Unknown') for e in evidence[:3]],
            "steps": steps,
            "resources": [
                f"OWASP {threat_type} Prevention Guide",
                f"NIST {threat_type} Mitigation Recommendations",
                "Security training materials"
            ],
            "support_channels": [
                "Security team contact",
                "Vendor support (if applicable)",
                "Online security communities"
            ]
        }
    
    def _update_user_profile(self, user_id: str, threat_type: str,
                           education_level: EducationLevel):
        """
        Update user profile with learning interaction
        
        Args:
            user_id: User identifier
            threat_type: Threat studied
            education_level: Current education level
        """
        if user_id not in self.user_profiles:
            return
        
        profile = self.user_profiles[user_id]
        
        # Record interaction
        interaction = {
            "timestamp": datetime.now().isoformat(),
            "threat_type": threat_type,
            "education_level": education_level.value,
            "duration": random.randint(5, 30)  # Simulated
        }
        
        profile['interaction_history'].append(interaction)
        
        # Update topics studied
        if threat_type not in profile['topics_studied']:
            profile['topics_studied'].append(threat_type)
        
        # Update engagement score
        profile['engagement_score'] = min(1.0, profile['engagement_score'] * 1.05)
        
        # Update last active
        profile['last_active'] = datetime.now()
        
        # Check for knowledge gaps (simplified)
        if len(profile['interaction_history']) > 3:
            recent_topics = [i['threat_type'] for i in profile['interaction_history'][-3:]]
            if len(set(recent_topics)) == 1:  # Same topic repeatedly
                profile['knowledge_gaps'].append({
                    "topic": threat_type,
                    "gap": "Needs reinforcement",
                    "suggested_action": "Try different learning approach"
                })
                self.analytics['knowledge_gap_identified'] += 1
    
    def _get_reasoning_state(self) -> torch.Tensor:
        """Get current reasoning state for mHC coordination"""
        features = []
        
        # Education metrics
        features.append(self.confidence)
        features.append(self.analytics['lessons_delivered'] / 1000.0)
        features.append(self.analytics['explanations_provided'] / 1000.0)
        features.append(self.analytics['users_educated'] / 100.0)
        features.append(self.analytics['average_engagement'])
        
        # Knowledge base metrics
        features.append(len(self.lessons) / 100.0)
        features.append(len(self.threat_explanations) / 50.0)
        features.append(len(self.user_profiles) / 50.0)
        
        # Learning effectiveness (simulated)
        recent_engagement = 0.0
        for profile in self.user_profiles.values():
            recent_engagement += profile.get('engagement_score', 0.0)
        
        if self.user_profiles:
            recent_engagement /= len(self.user_profiles)
        
        features.append(recent_engagement)
        
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
            'lessons_available': len(self.lessons),
            'threat_explanations': len(self.threat_explanations),
            'active_users': len(self.user_profiles),
            'analytics': self.analytics,
            'education_levels_supported': [level.value for level in EducationLevel],
            'learning_styles_supported': [style.value for style in LearningStyle]
        }