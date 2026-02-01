# src/web_security/form_validator.py
"""
Web Form Security Validator for CyberGuard
Analyzes HTML forms for security vulnerabilities and validation issues
Features: Form structure analysis, input validation, CSRF detection, security header checks
"""

import re
import json
import hashlib
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from bs4 import BeautifulSoup
import urllib.parse
import html

@dataclass
class FormAnalysis:
    """Comprehensive form analysis results"""
    form_id: str                      # Unique form identifier (hash)
    form_action: str                  # Form action URL
    form_method: str                  # HTTP method (GET, POST, etc.)
    form_enctype: str                 # Encoding type
    inputs: List[Dict[str, Any]]      # Form input fields
    vulnerabilities: List[Dict[str, Any]]  # Detected vulnerabilities
    missing_validations: List[Dict[str, Any]]  # Missing input validations
    security_headers: Dict[str, Any]  # Security headers present
    csrf_protection: Dict[str, Any]   # CSRF protection status
    file_uploads: List[Dict[str, Any]]  # File upload fields
    password_fields: List[Dict[str, Any]]  # Password input fields
    hidden_fields: List[Dict[str, Any]]   # Hidden input fields
    security_score: float             # Overall security score (0.0 to 1.0)

@dataclass
class FormInput:
    """Structured form input field"""
    name: str                         # Input name attribute
    input_type: str                   # Input type (text, password, email, etc.)
    required: bool                    # Required attribute
    pattern: Optional[str] = None     # Pattern attribute (regex)
    maxlength: Optional[int] = None   # Maxlength attribute
    minlength: Optional[int] = None   # Minlength attribute
    placeholder: Optional[str] = None # Placeholder text
    value: Optional[str] = None      # Default value
    autocomplete: Optional[str] = None # Autocomplete attribute
    attributes: Dict[str, str] = field(default_factory=dict)  # All other attributes

class FormValidator:
    """
    Advanced web form security validator
    Detects: Missing validations, CSRF vulnerabilities, insecure configurations
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize form validator with configuration
        
        Args:
            config: Configuration dictionary containing validation rules (optional)
        """
        self.config = config or {}  # Handle None config
        
        # Input types that require special validation with their severity levels
        self.sensitive_input_types = {
            'password': 'CRITICAL',
            'email': 'MEDIUM',
            'tel': 'LOW',
            'number': 'LOW',
            'date': 'LOW',
            'creditcard': 'CRITICAL',
            'ssn': 'CRITICAL',
        }
        
        # Common CSRF token names to check for
        self.csrf_token_names = {
            'csrf_token', 'csrfmiddlewaretoken', '_token',
            'authenticity_token', 'csrf', 'anticsrf',
            '__RequestVerificationToken', 'X-CSRF-Token',
        }
        
        # File upload security constraints
        self.file_upload_checks = {
            'accept': ['image/*', '.pdf', '.doc', '.docx', '.txt'],
            'max_size_mb': 10,
            'dangerous_extensions': ['.exe', '.bat', '.sh', '.php', '.jar'],
        }
        
        # Input validation patterns for common data types
        self.validation_patterns = {
            'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
            'phone': r'^[\d\s\(\)\-+]{10,20}$',
            'url': r'^https?://[^\s]+$',
            'creditcard': r'^\d{13,19}$',
            'ssn': r'^\d{3}-\d{2}-\d{4}$',
            'zipcode': r'^\d{5}(-\d{4})?$',
        }
        
        # Security headers to check for in HTTP responses
        self.security_headers = [
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Referrer-Policy',
        ]
        
        # Statistics tracking for validator usage
        self.stats = {
            'forms_analyzed': 0,
            'vulnerabilities_found': 0,
            'insecure_forms': 0,
            'csrf_vulnerabilities': 0,
        }
    
    def analyze_form(self, html_content: str, form_element = None) -> FormAnalysis:
        """
        Analyze HTML form for security issues
        
        Args:
            html_content: HTML content containing the form
            form_element: Optional pre-extracted form element
            
        Returns:
            FormAnalysis object with analysis results
            
        Raises:
            ValueError: If no forms found in HTML content
        """
        # Parse HTML content using BeautifulSoup
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Extract form if not provided
        if form_element is None:
            forms = soup.find_all('form')
            if not forms:
                raise ValueError("No forms found in HTML content")
            form_element = forms[0]  # Analyze first form by default
        
        # Extract form attributes with defaults
        form_action = form_element.get('action', '')
        form_method = form_element.get('method', 'GET').upper()
        form_enctype = form_element.get('enctype', 'application/x-www-form-urlencoded')
        
        # Generate unique form ID based on form characteristics
        form_id = self._generate_form_id(form_element)
        
        # Extract all input fields from the form
        inputs = self._extract_input_fields(form_element)
        
        # Initialize results containers for different analysis categories
        vulnerabilities = []
        missing_validations = []
        file_uploads = []
        password_fields = []
        hidden_fields = []
        
        # 1. Check for CSRF protection in the form
        csrf_analysis = self._analyze_csrf_protection(form_element, inputs)
        if not csrf_analysis['protected']:
            vulnerabilities.append({
                'type': 'MISSING_CSRF_PROTECTION',
                'severity': 'HIGH',
                'description': 'Form lacks CSRF protection',
                'location': 'Form security',
                'recommendation': 'Add CSRF token to form'
            })
            self.stats['csrf_vulnerabilities'] += 1
        
        # 2. Analyze each input field individually
        for form_input in inputs:
            # Check for input-specific security vulnerabilities
            input_vulns = self._analyze_input_field(form_input, form_method)
            vulnerabilities.extend(input_vulns)
            
            # Check for missing input validations
            missing = self._check_missing_validations(form_input)
            if missing:
                missing_validations.extend(missing)
            
            # Categorize special input types for detailed analysis
            if form_input.input_type == 'file':
                file_uploads.append({
                    'name': form_input.name,
                    'attributes': form_input.attributes,
                    'security_checks': self._analyze_file_upload(form_input)
                })
            
            elif form_input.input_type == 'password':
                password_fields.append({
                    'name': form_input.name,
                    'attributes': form_input.attributes,
                    'security_checks': self._analyze_password_field(form_input)
                })
            
            elif form_input.input_type == 'hidden':
                hidden_fields.append({
                    'name': form_input.name,
                    'value': form_input.value,
                    'attributes': form_input.attributes,
                    'security_check': self._analyze_hidden_field(form_input)
                })
        
        # 3. Check form-level security issues
        form_vulns = self._analyze_form_level_security(form_element, form_method, form_action)
        vulnerabilities.extend(form_vulns)
        
        # 4. Check security headers (would normally come from HTTP response)
        # Currently using empty dict as placeholder
        security_headers = self._check_security_headers({})
        
        # 5. Calculate overall security score based on findings
        security_score = self._calculate_security_score(vulnerabilities, missing_validations)
        
        # Update statistics based on analysis results
        self.stats['forms_analyzed'] += 1
        if vulnerabilities:
            self.stats['vulnerabilities_found'] += len(vulnerabilities)
        if security_score < 0.5:
            self.stats['insecure_forms'] += 1
        
        # Return comprehensive analysis object
        return FormAnalysis(
            form_id=form_id,
            form_action=form_action,
            form_method=form_method,
            form_enctype=form_enctype,
            inputs=[self._input_to_dict(inp) for inp in inputs],
            vulnerabilities=vulnerabilities,
            missing_validations=missing_validations,
            security_headers=security_headers,
            csrf_protection=csrf_analysis,
            file_uploads=file_uploads,
            password_fields=password_fields,
            hidden_fields=hidden_fields,
            security_score=security_score
        )
    
    def _generate_form_id(self, form_element) -> str:
        """
        Generate unique ID for form based on its characteristics
        
        Args:
            form_element: BeautifulSoup form element
            
        Returns:
            Unique form ID string (16-character hex)
        """
        # Create identifying string from form attributes
        id_parts = [
            form_element.get('action', ''),
            form_element.get('method', ''),
            form_element.get('id', ''),
            form_element.get('name', ''),
        ]
        
        # Add input names to make ID more unique
        input_names = [inp.get('name', '') for inp in form_element.find_all('input')]
        id_parts.extend(input_names)
        
        # Join parts and create MD5 hash
        id_string = ':'.join(id_parts)
        return hashlib.md5(id_string.encode()).hexdigest()[:16]
    
    def _extract_input_fields(self, form_element) -> List[FormInput]:
        """
        Extract all input fields from form
        
        Args:
            form_element: BeautifulSoup form element
            
        Returns:
            List of FormInput objects representing each input field
        """
        inputs = []
        
        # Find all form input elements (input, textarea, select)
        input_elements = form_element.find_all(['input', 'textarea', 'select'])
        
        for element in input_elements:
            tag_name = element.name
            
            # Determine input type based on tag
            if tag_name == 'input':
                input_type = element.get('type', 'text').lower()
            elif tag_name == 'textarea':
                input_type = 'textarea'
            elif tag_name == 'select':
                input_type = 'select'
            else:
                input_type = 'unknown'
            
            # Extract common attributes
            name = element.get('name', '')
            required = element.get('required') is not None
            pattern = element.get('pattern')
            maxlength = element.get('maxlength')
            minlength = element.get('minlength')
            placeholder = element.get('placeholder')
            value = element.get('value')
            autocomplete = element.get('autocomplete')
            
            # Convert string length attributes to integers safely
            try:
                if maxlength is not None:
                    maxlength = int(maxlength)
            except (ValueError, TypeError):
                maxlength = None
                
            try:
                if minlength is not None:
                    minlength = int(minlength)
            except (ValueError, TypeError):
                minlength = None
            
            # Extract all attributes for complete analysis
            attributes = {}
            if hasattr(element, 'attrs'):
                for attr, val in element.attrs.items():
                    # Convert list values to string for consistency
                    if isinstance(val, list):
                        val = ' '.join(val)
                    attributes[attr] = val
            
            # Create FormInput object with extracted data
            form_input = FormInput(
                name=name,
                input_type=input_type,
                required=required,
                pattern=pattern,
                maxlength=maxlength,
                minlength=minlength,
                placeholder=placeholder,
                value=value,
                autocomplete=autocomplete,
                attributes=attributes
            )
            
            inputs.append(form_input)
        
        return inputs
    
    def _analyze_csrf_protection(self, form_element, inputs: List[FormInput]) -> Dict[str, Any]:
        """
        Analyze CSRF protection in form
        
        Args:
            form_element: BeautifulSoup form element
            inputs: List of form inputs
            
        Returns:
            CSRF protection analysis results
        """
        # Initialize analysis results
        csrf_token_found = False
        csrf_token_name = None
        csrf_token_value = None
        
        # Check for CSRF token in hidden input fields
        for form_input in inputs:
            if form_input.input_type == 'hidden':
                # Case-insensitive check against known CSRF token names
                if form_input.name and form_input.name.lower() in [name.lower() for name in self.csrf_token_names]:
                    csrf_token_found = True
                    csrf_token_name = form_input.name
                    csrf_token_value = form_input.value
                    break
        
        # Check for meta tags containing CSRF tokens (common in some frameworks)
        if not csrf_token_found:
            # Get parent element to search for meta tags
            parent = form_element.find_parent()
            if parent:
                meta_tags = parent.find_all('meta')
                for meta in meta_tags:
                    name = meta.get('name', '').lower()
                    content = meta.get('content', '')
                    
                    # Check if meta tag contains CSRF-related information
                    if 'csrf' in name or 'token' in name:
                        csrf_token_found = True
                        csrf_token_name = name
                        csrf_token_value = content
                        break
        
        # Prepare recommendation based on findings
        recommendation = 'Use CSRF tokens for all state-changing forms'
        if csrf_token_found:
            recommendation = 'CSRF protection appears adequate'
            
            # Truncate long token values for display
            if csrf_token_value and len(csrf_token_value) > 50:
                csrf_token_value = csrf_token_value[:50] + '...'
        
        return {
            'protected': csrf_token_found,
            'token_name': csrf_token_name,
            'token_value': csrf_token_value,
            'recommendation': recommendation
        }
    
    def _analyze_input_field(self, form_input: FormInput, form_method: str) -> List[Dict[str, Any]]:
        """
        Analyze individual input field for security issues
        
        Args:
            form_input: FormInput object
            form_method: Form HTTP method
            
        Returns:
            List of input-specific vulnerabilities found
        """
        vulnerabilities = []
        
        # Skip unnamed fields (they can't be submitted)
        if not form_input.name:
            return vulnerabilities
        
        # 1. Check for sensitive data indicators in field names
        sensitive_keywords = ['password', 'passwd', 'pwd', 'creditcard', 'cc', 'ssn', 'social']
        for keyword in sensitive_keywords:
            if keyword in form_input.name.lower():
                vulnerabilities.append({
                    'type': 'SENSITIVE_FIELD_NAME',
                    'severity': 'MEDIUM',
                    'description': f'Input field name suggests sensitive data: {form_input.name}',
                    'location': f'Input field: {form_input.name}',
                    'recommendation': 'Use generic field names for sensitive data'
                })
                break  # Only report once per field
        
        # 2. Check for autocomplete on password fields
        if form_input.input_type == 'password' and form_input.autocomplete != 'off':
            vulnerabilities.append({
                'type': 'PASSWORD_AUTOCOMPLETE',
                'severity': 'LOW',
                'description': 'Password field allows autocomplete',
                'location': f'Password field: {form_input.name}',
                'recommendation': 'Add autocomplete="off" to password fields'
            })
        
        # 3. Check for missing maxlength on text-based inputs
        if form_input.input_type in ['text', 'textarea', 'search', 'url', 'email']:
            if form_input.maxlength is None:
                vulnerabilities.append({
                    'type': 'MISSING_MAXLENGTH',
                    'severity': 'LOW',
                    'description': f'Text input missing maxlength attribute: {form_input.name}',
                    'location': f'Input field: {form_input.name}',
                    'recommendation': 'Add maxlength attribute to prevent overflow'
                })
        
        # 4. Check for file upload security issues
        if form_input.input_type == 'file':
            # Check for missing accept attribute
            if 'accept' not in form_input.attributes:
                vulnerabilities.append({
                    'type': 'MISSING_FILE_TYPE_RESTRICTION',
                    'severity': 'MEDIUM',
                    'description': f'File upload missing accept attribute: {form_input.name}',
                    'location': f'File upload: {form_input.name}',
                    'recommendation': 'Add accept attribute to restrict file types'
                })
        
        # 5. Check for generic input types that should be more specific
        if form_input.input_type == 'text':
            field_name = form_input.name.lower()
            
            # Suggest email type for email fields
            if 'email' in field_name:
                vulnerabilities.append({
                    'type': 'GENERIC_EMAIL_FIELD',
                    'severity': 'LOW',
                    'description': f'Email field should use type="email": {form_input.name}',
                    'location': f'Input field: {form_input.name}',
                    'recommendation': 'Change type from "text" to "email"'
                })
            
            # Suggest tel type for phone fields
            elif 'tel' in field_name or 'phone' in field_name:
                vulnerabilities.append({
                    'type': 'GENERIC_PHONE_FIELD',
                    'severity': 'LOW',
                    'description': f'Phone field should use type="tel": {form_input.name}',
                    'location': f'Input field: {form_input.name}',
                    'recommendation': 'Change type from "text" to "tel"'
                })
            
            # Suggest url type for URL fields
            elif 'url' in field_name or 'website' in field_name:
                vulnerabilities.append({
                    'type': 'GENERIC_URL_FIELD',
                    'severity': 'LOW',
                    'description': f'URL field should use type="url": {form_input.name}',
                    'location': f'Input field: {form_input.name}',
                    'recommendation': 'Change type from "text" to "url"'
                })
        
        return vulnerabilities
    
    def _check_missing_validations(self, form_input: FormInput) -> List[Dict[str, Any]]:
        """
        Check for missing input validations
        
        Args:
            form_input: FormInput object
            
        Returns:
            List of missing validations found
        """
        missing = []
        
        # Skip unnamed fields
        if not form_input.name:
            return missing
        
        # 1. Required fields should have appropriate validation
        if form_input.required:
            if not form_input.pattern and form_input.input_type == 'text':
                field_name = form_input.name.lower()
                
                # Suggest email validation pattern for email fields
                if 'email' in field_name:
                    missing.append({
                        'type': 'MISSING_EMAIL_VALIDATION',
                        'severity': 'MEDIUM',
                        'description': f'Required email field missing validation: {form_input.name}',
                        'location': f'Input field: {form_input.name}',
                        'recommendation': f'Add pattern="{self.validation_patterns["email"]}"'
                    })
        
        # 2. Password fields should have complexity requirements
        if form_input.input_type == 'password':
            if not form_input.pattern:
                missing.append({
                    'type': 'MISSING_PASSWORD_COMPLEXITY',
                    'severity': 'MEDIUM',
                    'description': f'Password field missing complexity validation: {form_input.name}',
                    'location': f'Password field: {form_input.name}',
                    'recommendation': 'Add pattern requiring uppercase, lowercase, numbers, and special characters'
                })
        
        # 3. Check for missing length constraints on text-based fields
        if form_input.input_type in ['text', 'textarea', 'password']:
            if form_input.maxlength is None:
                missing.append({
                    'type': 'MISSING_LENGTH_CONSTRAINT',
                    'severity': 'LOW',
                    'description': f'Text field missing maxlength: {form_input.name}',
                    'location': f'Input field: {form_input.name}',
                    'recommendation': 'Add maxlength attribute'
                })
        
        return missing
    
    def _analyze_file_upload(self, form_input: FormInput) -> Dict[str, Any]:
        """
        Analyze file upload field security
        
        Args:
            form_input: File upload FormInput object
            
        Returns:
            File upload security analysis results
        """
        # Initialize security checks
        checks = {
            'has_accept_attribute': False,
            'accept_value': None,
            'dangerous_extensions_allowed': False,
            'recommendations': []
        }
        
        # Check for accept attribute
        accept_value = form_input.attributes.get('accept')
        if accept_value:
            checks['has_accept_attribute'] = True
            checks['accept_value'] = accept_value
            
            # Check if dangerous file extensions are allowed
            for dangerous_ext in self.file_upload_checks['dangerous_extensions']:
                if dangerous_ext in accept_value:
                    checks['dangerous_extensions_allowed'] = True
                    checks['recommendations'].append(f'Remove {dangerous_ext} from accept attribute')
        else:
            # Recommend adding accept attribute if missing
            checks['recommendations'].append('Add accept attribute to restrict file types')
        
        # Check for multiple attribute (allows multiple file uploads)
        if 'multiple' in form_input.attributes:
            checks['recommendations'].append('Consider limiting to single file upload for security')
        
        return checks
    
    def _analyze_password_field(self, form_input: FormInput) -> Dict[str, Any]:
        """
        Analyze password field security
        
        Args:
            form_input: Password FormInput object
            
        Returns:
            Password field security analysis results
        """
        # Initialize security checks
        checks = {
            'has_autocomplete_off': form_input.autocomplete == 'off',
            'has_pattern': form_input.pattern is not None,
            'has_minlength': form_input.minlength is not None,
            'minlength_value': form_input.minlength,
            'has_maxlength': form_input.maxlength is not None,
            'maxlength_value': form_input.maxlength,
            'recommendations': []
        }
        
        # Generate recommendations based on findings
        if not checks['has_autocomplete_off']:
            checks['recommendations'].append('Add autocomplete="off" to prevent password saving')
        
        if not checks['has_pattern']:
            checks['recommendations'].append('Add pattern attribute for password complexity')
        
        # Check minimum length requirements
        if not checks['has_minlength'] or (checks['minlength_value'] and checks['minlength_value'] < 8):
            checks['recommendations'].append('Set minlength="8" or higher')
        
        return checks
    
    def _analyze_hidden_field(self, form_input: FormInput) -> Dict[str, Any]:
        """
        Analyze hidden field security
        
        Args:
            form_input: Hidden FormInput object
            
        Returns:
            Hidden field security analysis results
        """
        # Initialize security checks
        check = {
            'is_csrf_token': False,
            'value_exposed': False,
            'sensitive_data': False,
            'recommendations': []
        }
        
        # Check if this is a CSRF token
        if form_input.name:
            check['is_csrf_token'] = form_input.name.lower() in [name.lower() for name in self.csrf_token_names]
        
        # Check if hidden field might contain sensitive data
        sensitive_patterns = [
            ('session', 'SESSION_ID_IN_HIDDEN_FIELD'),
            ('token', 'TOKEN_IN_HIDDEN_FIELD'),
            ('id', 'ID_IN_HIDDEN_FIELD'),
            ('key', 'KEY_IN_HIDDEN_FIELD'),
        ]
        
        for pattern, description in sensitive_patterns:
            if form_input.name and pattern in form_input.name.lower():
                check['sensitive_data'] = True
                check['recommendations'].append(f'Consider removing {form_input.name} from client-side')
                break
        
        # Check if value is exposed (non-empty)
        if form_input.value and len(form_input.value) > 0:
            check['value_exposed'] = True
        
        return check
    
    def _analyze_form_level_security(self, form_element, form_method: str, 
                                   form_action: str) -> List[Dict[str, Any]]:
        """
        Analyze form-level security issues
        
        Args:
            form_element: BeautifulSoup form element
            form_method: Form HTTP method
            form_action: Form action URL
            
        Returns:
            List of form-level vulnerabilities found
        """
        vulnerabilities = []
        
        # 1. Check for insecure action URLs (HTTP instead of HTTPS)
        if form_action.startswith('http://'):
            vulnerabilities.append({
                'type': 'INSECURE_FORM_ACTION',
                'severity': 'HIGH',
                'description': f'Form submits to HTTP instead of HTTPS: {form_action}',
                'location': 'Form action attribute',
                'recommendation': 'Change to HTTPS or use relative URL'
            })
        
        # 2. Check for GET method with sensitive data
        if form_method == 'GET':
            # Search for sensitive fields in the form
            sensitive_fields = form_element.find_all(['input', 'textarea', 'select'])
            has_sensitive = False
            
            for field in sensitive_fields:
                field_name = field.get('name', '').lower()
                field_type = field.get('type', '').lower()
                
                # Check if field contains sensitive data
                if 'password' in field_name or field_type == 'password':
                    has_sensitive = True
                    break
            
            if has_sensitive:
                vulnerabilities.append({
                    'type': 'SENSITIVE_DATA_VIA_GET',
                    'severity': 'CRITICAL',
                    'description': 'Form with sensitive data uses GET method',
                    'location': 'Form method attribute',
                    'recommendation': 'Change method to POST for sensitive data'
                })
        
        # 3. Check for missing or weak enctype on POST forms
        enctype = form_element.get('enctype', '')
        if form_method == 'POST' and not enctype:
            vulnerabilities.append({
                'type': 'MISSING_ENCTYPE',
                'severity': 'LOW',
                'description': 'POST form missing enctype attribute',
                'location': 'Form enctype attribute',
                'recommendation': 'Add enctype="application/x-www-form-urlencoded" or "multipart/form-data"'
            })
        
        # 4. Check for forms without proper identification
        if not form_element.get('id') and not form_element.get('name'):
            vulnerabilities.append({
                'type': 'UNIDENTIFIED_FORM',
                'severity': 'LOW',
                'description': 'Form missing id and name attributes',
                'location': 'Form attributes',
                'recommendation': 'Add id or name attribute for better tracking'
            })
        
        return vulnerabilities
    
    def _check_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Check security headers (would be from HTTP response)
        
        Args:
            headers: HTTP headers dictionary
            
        Returns:
            Security headers analysis results
        """
        analysis = {}
        
        # Check each security header
        for header in self.security_headers:
            if header in headers:
                # Header is present, check if it's securely configured
                analysis[header] = {
                    'present': True,
                    'value': headers[header],
                    'secure': self._is_security_header_secure(header, headers[header])
                }
            else:
                # Header is missing
                analysis[header] = {
                    'present': False,
                    'value': None,
                    'secure': False,
                    'recommendation': f'Add {header} security header'
                }
        
        return analysis
    
    def _is_security_header_secure(self, header: str, value: str) -> bool:
        """
        Check if security header is properly configured
        
        Args:
            header: Security header name
            value: Header value
            
        Returns:
            True if header is securely configured, False otherwise
        """
        if not value:
            return False
            
        if header == 'Content-Security-Policy':
            # Check for unsafe directives in CSP
            unsafe_directives = ["'unsafe-inline'", "'unsafe-eval'", "*"]
            return not any(directive in value for directive in unsafe_directives)
        
        elif header == 'X-Frame-Options':
            # Check for proper X-Frame-Options values
            return value.upper() in ['DENY', 'SAMEORIGIN']
        
        elif header == 'X-Content-Type-Options':
            # Check for nosniff directive
            return value.lower() == 'nosniff'
        
        elif header == 'X-XSS-Protection':
            # Check for XSS protection with blocking mode
            return '1; mode=block' in value
        
        elif header == 'Referrer-Policy':
            # Check for secure referrer policy values
            secure_values = ['no-referrer', 'same-origin', 'strict-origin']
            return any(secure_value in value for secure_value in secure_values)
        
        return True  # Default to True for other headers
    
    def _calculate_security_score(self, vulnerabilities: List[Dict[str, Any]], 
                                missing_validations: List[Dict[str, Any]]) -> float:
        """
        Calculate overall form security score
        
        Args:
            vulnerabilities: List of detected vulnerabilities
            missing_validations: List of missing validations
            
        Returns:
            Security score between 0.0 (worst) and 1.0 (best)
        """
        # Severity weights for different vulnerability levels
        vuln_weights = {
            'CRITICAL': 0.8,
            'HIGH': 0.6,
            'MEDIUM': 0.3,
            'LOW': 0.1,
        }
        
        # Weights for missing validations (less severe than actual vulnerabilities)
        validation_weights = {
            'CRITICAL': 0.4,
            'HIGH': 0.3,
            'MEDIUM': 0.2,
            'LOW': 0.1,
        }
        
        # Calculate penalty from actual vulnerabilities
        vuln_penalty = 0.0
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            weight = vuln_weights.get(severity, 0.1)
            vuln_penalty += weight
        
        # Calculate penalty from missing validations
        validation_penalty = 0.0
        for missing in missing_validations:
            severity = missing.get('severity', 'LOW')
            weight = validation_weights.get(severity, 0.1)
            validation_penalty += weight
        
        # Combine penalties with validation penalty weighted lower
        total_penalty = vuln_penalty + (validation_penalty * 0.5)
        
        # Normalize penalty based on total number of items
        total_items = len(vulnerabilities) + len(missing_validations)
        normalized_penalty = min(total_penalty / (1 + total_items * 0.2), 1.0)
        
        # Security score is inverse of penalty
        security_score = 1.0 - normalized_penalty
        
        # Ensure score is within 0.0 to 1.0 range
        return max(0.0, min(1.0, security_score))
    
    def _input_to_dict(self, form_input: FormInput) -> Dict[str, Any]:
        """
        Convert FormInput to dictionary for serialization
        
        Args:
            form_input: FormInput object
            
        Returns:
            Dictionary representation of FormInput
        """
        return {
            'name': form_input.name,
            'type': form_input.input_type,
            'required': form_input.required,
            'pattern': form_input.pattern,
            'maxlength': form_input.maxlength,
            'minlength': form_input.minlength,
            'placeholder': form_input.placeholder,
            'value': form_input.value,
            'autocomplete': form_input.autocomplete,
            'attributes': form_input.attributes
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get validator statistics
        
        Returns:
            Dictionary of current validator statistics
        """
        return self.stats.copy()