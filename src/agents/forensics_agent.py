"""
Digital Forensics Agent
Purpose: Collects, preserves, and analyzes digital evidence from security incidents
Techniques: Log analysis, memory forensics, disk forensics, network forensics, timeline analysis
"""

# Import Python's standard library modules for various functionalities
import hashlib          # For cryptographic hashing (MD5, SHA256, etc.)
import base64          # For encoding/decoding binary data
import json            # For parsing JSON format evidence
from typing import Dict, List, Any, Optional, Tuple  # Type hints for better code documentation
from datetime import datetime, timedelta  # For handling dates and times
import time            # For timing operations and generating timestamps
import re              # Regular expressions for parsing log files
from collections import defaultdict  # Dictionary with default values
import csv             # For parsing CSV files
import io              # For handling in-memory streams (StringIO)

# Import base agent - assuming it's in the same directory or proper path
try:
    from .base_agent import SecurityAgent, AgentCapability  # Import from same directory
except ImportError:
    # Fallback for testing or different import structure
    from base_agent import SecurityAgent, AgentCapability  # Import from current directory


class DigitalForensicsAgent(SecurityAgent):  # Inherits from base SecurityAgent class
    """
    Digital Forensics Agent
    
    This agent specializes in:
    1. Evidence collection and preservation
    2. Log analysis and correlation
    3. Memory forensics
    4. Disk image analysis
    5. Network traffic analysis
    6. Timeline reconstruction
    7. Artifact analysis
    8. Chain of custody tracking
    
    Techniques used:
    - Forensic imaging and hashing
    - Log parsing and normalization
    - Timeline analysis
    - File system analysis
    - Registry analysis (Windows)
    - Plist analysis (macOS)
    - JSON/XML parsing
    - Database forensics
    """
    
    def __init__(self, agent_id: str = "forensics_agent_001"):  # Constructor with default ID
        """
        Initialize the Digital Forensics Agent
        
        Args:
            agent_id: Unique identifier for this agent instance
        """
        # Initialize parent class with basic agent parameters
        super().__init__(  # Call parent class constructor
            agent_id=agent_id,  # Pass agent ID to parent
            name="Digital Forensics Agent",  # Human-readable name
            state_dim=768  # State dimension for agent's internal representation
        )
        
        # Add forensics capability to agent's capabilities list
        self.capabilities.append(AgentCapability.FORENSICS)  # Append FORENSICS enum
        
        # Evidence storage: dictionary to store processed evidence with evidence_id as key
        self.evidence_store = {}  # Empty dictionary to hold evidence objects
        
        # Counter for generating unique evidence IDs (starts at 0)
        self.evidence_counter = 0  # Incremented each time new evidence is processed
        
        # Chain of custody tracking: dictionary to store custody history for each evidence
        self.chain_of_custody = {}  # Maps evidence_id -> list of custody events
        
        # Initialize various parsers for different evidence types
        self.log_parsers = self._initialize_log_parsers()       # Log file parsers
        self.file_parsers = self._initialize_file_parsers()     # File format parsers
        self.artifact_parsers = self._initialize_artifact_parsers()  # Forensic artifact parsers
        
        # Timeline reconstruction storage (not currently used, but defined for future)
        self.timelines = {}  # Could store multiple timelines by case ID
        
        # Detection thresholds for various forensic analysis criteria
        self.thresholds = {
            'evidence_confidence': 0.7,      # Minimum confidence score (0.0-1.0) for evidence correlation
            'timeline_accuracy': 0.8,        # Minimum accuracy required for timeline reconstruction
            'artifact_relevance': 0.6,       # Minimum relevance score for artifacts to be considered
            'min_evidence_count': 3,         # Minimum number of evidence pieces for meaningful analysis
            'max_evidence_age_days': 30      # Maximum age (in days) of evidence to consider relevant
        }
        
        # List of supported evidence types that this agent can process
        self.supported_evidence = [
            'log_file', 'memory_dump', 'disk_image', 'network_pcap',
            'registry_hive', 'plist_file', 'json_file', 'xml_file',
            'database_file', 'browser_history', 'email_archive',
            'application_log', 'system_log', 'security_log'
        ]
        
        # Metrics tracking for agent performance and analysis statistics
        self.metrics = {
            'evidence_collected': 0,          # Total evidence pieces collected
            'evidence_analyzed': 0,           # Total evidence pieces analyzed
            'timelines_created': 0,           # Number of timelines created
            'artifacts_found': 0,             # Number of forensic artifacts found
            'incidents_reconstructed': 0,     # Number of incidents reconstructed
            'avg_analysis_time': 0.0          # Average analysis time (exponential moving average)
        }
        
        # Cryptographic hash algorithms supported for evidence integrity verification
        self.hash_algorithms = ['md5', 'sha1', 'sha256', 'sha512']  # Ordered by speed to security
    
    def _initialize_log_parsers(self) -> Dict[str, Any]:  # Private method (starts with _)
        """
        Initialize log file parsers for different log formats
        
        Returns:
            Dictionary containing regex patterns and field mappings for each log type
        """
        return {
            'syslog': {  # Standard syslog format
                'pattern': r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\[?(\d+)?\]?:\s+(.*)$',
                'fields': ['timestamp', 'hostname', 'process', 'pid', 'message']  # Field names
            },
            'apache': {  # Apache web server log format
                'pattern': r'^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"$',
                'fields': ['ip', 'ident', 'user', 'timestamp', 'request', 'status', 'size', 'referer', 'user_agent']
            },
            'nginx': {  # Nginx web server log format
                'pattern': r'^(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"\s+"([^"]*)"$',
                'fields': ['ip', 'remote_user', 'timestamp', 'request', 'status', 'body_bytes_sent', 'http_referer', 'http_user_agent', 'http_x_forwarded_for']
            },
            'windows_event': {  # Windows Event Log format
                'pattern': r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$',
                'fields': ['timestamp', 'event_id', 'level', 'task', 'opcode', 'keywords', 'source', 'message']
            }
        }
    
    def _initialize_file_parsers(self) -> Dict[str, Any]:
        """
        Initialize file format parsers for structured data files
        
        Returns:
            Dictionary mapping file formats to parsing functions
        """
        return {
            'json': lambda x: json.loads(x) if x else {},  # Parse JSON, return empty dict if None
            'xml': lambda x: self._parse_xml(x),  # Call internal XML parser
            'csv': lambda x: list(csv.DictReader(io.StringIO(x))) if x else [],  # Parse CSV to list of dicts
            'yaml': lambda x: self._parse_yaml(x),  # Call internal YAML parser
            'ini': lambda x: self._parse_ini(x)  # Call internal INI parser
        }
    
    def _initialize_artifact_parsers(self) -> Dict[str, Any]:
        """
        Initialize artifact parsers for common forensic artifacts
        
        Returns:
            Dictionary mapping artifact types to parsing functions
        """
        return {
            'browser_history': self._parse_browser_history,  # Function for browser history
            'registry': self._parse_registry,  # Function for Windows Registry
            'plist': self._parse_plist,  # Function for macOS property lists
            'prefetch': self._parse_prefetch,  # Function for Windows Prefetch files
            'shellbags': self._parse_shellbags,  # Function for Windows Shellbags
            'jumplists': self._parse_jumplists,  # Function for Windows Jump Lists
            'recycle_bin': self._parse_recycle_bin  # Function for Recycle Bin artifacts
        }
    
    def _parse_xml(self, xml_content: str) -> Dict:  # Takes XML string, returns dictionary
        """
        Parse XML content (simplified placeholder)
        
        Args:
            xml_content: XML string to parse
            
        Returns:
            Dictionary with parsed XML content or placeholder
        """
        # In production, this would use xml.etree.ElementTree or lxml
        # For now, return placeholder with limited content
        if not xml_content:  # Check if content is empty or None
            return {'content': '', 'note': 'Empty XML content'}  # Return empty result
        return {'content': xml_content[:1000], 'note': 'XML parsing placeholder - use proper XML parser in production'}  # Return first 1000 chars
    
    def _parse_yaml(self, yaml_content: str) -> Dict:
        """
        Parse YAML content (simplified placeholder)
        
        Args:
            yaml_content: YAML string to parse
            
        Returns:
            Dictionary with parsed YAML content or placeholder
        """
        # In production, this would use PyYAML library
        # For now, return placeholder with limited content
        if not yaml_content:  # Check for empty content
            return {'content': '', 'note': 'Empty YAML content'}
        return {'content': yaml_content[:1000], 'note': 'YAML parsing placeholder - use PyYAML in production'}  # Return first 1000 chars
    
    def _parse_ini(self, ini_content: str) -> Dict:
        """
        Parse INI configuration file content
        
        Args:
            ini_content: INI format string to parse
            
        Returns:
            Dictionary with parsed INI sections and key-value pairs
        """
        result = {}  # Initialize empty dictionary for result
        current_section = None  # Track current section being parsed
        
        # Handle empty content
        if not ini_content:  # If content is empty or None
            return result  # Return empty dictionary
        
        for line in ini_content.split('\n'):  # Split content by newlines
            line = line.strip()  # Remove leading/trailing whitespace
            
            # Skip empty lines and comments
            if not line or line.startswith(';') or line.startswith('#'):  # If line empty or comment
                continue  # Skip to next line
            
            # Section header (e.g., [section_name])
            if line.startswith('[') and line.endswith(']'):  # If line is section header
                current_section = line[1:-1]  # Extract section name (remove brackets)
                result[current_section] = {}  # Create empty dict for this section
            # Key-value pair (e.g., key=value)
            elif '=' in line and current_section is not None:  # If line has = and we're in a section
                key_value = line.split('=', 1)  # Split on first = only
                key = key_value[0].strip()  # Remove whitespace from key
                value = key_value[1].strip()  # Remove whitespace from value
                result[current_section][key] = value  # Store in current section
            # Orphaned key-value (add to default section)
            elif '=' in line:  # If line has = but no section defined
                if 'DEFAULT' not in result:  # Check if DEFAULT section exists
                    result['DEFAULT'] = {}  # Create DEFAULT section
                key_value = line.split('=', 1)  # Split on first =
                key = key_value[0].strip()  # Clean key
                value = key_value[1].strip()  # Clean value
                result['DEFAULT'][key] = value  # Store in DEFAULT section
        
        return result  # Return parsed INI structure
    
    def _parse_browser_history(self, content: bytes) -> List[Dict]:  # Takes bytes, returns list of dicts
        """
        Parse browser history artifacts (placeholder)
        
        Args:
            content: Binary content of browser history
            
        Returns:
            List of browser history entries
        """
        # In production, parse actual browser history databases (Chrome, Firefox, etc.)
        # For demonstration, return mock data
        if not content:  # Check if content is empty
            return []  # Return empty list
        
        return [  # Return list with one mock entry
            {
                'url': 'https://example.com',  # Example URL
                'timestamp': datetime.now().isoformat(),  # Current time in ISO format
                'visit_count': 1,  # Number of visits
                'title': 'Example Domain'  # Page title
            }
        ]
    
    def _parse_registry(self, content: bytes) -> Dict[str, Any]:  # Takes bytes, returns dict
        """
        Parse Windows Registry artifacts (placeholder)
        
        Args:
            content: Binary content of registry hive
            
        Returns:
            Dictionary with registry parsing results
        """
        # In production, use python-registry or similar library
        # For demonstration, return placeholder data
        return {
            'hive_type': 'unknown',  # Type of registry hive
            'keys_found': 0,  # Number of registry keys found
            'values_found': 0,  # Number of registry values found
            'note': 'Registry parsing placeholder - use python-registry in production'  # Informational note
        }
    
    def _parse_plist(self, content: bytes) -> Dict:
        """
        Parse macOS plist files (placeholder)
        
        Args:
            content: Binary content of plist file
            
        Returns:
            Dictionary with plist content
        """
        # In production, use plistlib module
        # For demonstration, return placeholder
        return {'content': 'Plist parsing placeholder - use plistlib in production'}  # Simple placeholder
    
    def _parse_prefetch(self, content: bytes) -> List[Dict]:
        """
        Parse Windows Prefetch files (placeholder)
        
        Args:
            content: Binary content of prefetch file
            
        Returns:
            List of prefetch entries
        """
        # In production, parse actual prefetch file format
        return [  # Return mock data
            {
                'filename': 'unknown.pf',  # Prefetch filename
                'last_run': datetime.now().isoformat(),  # Last execution time
                'run_count': 1  # Number of times executed
            }
        ]
    
    def _parse_shellbags(self, content: bytes) -> List[Dict]:
        """
        Parse Windows Shellbags artifacts (placeholder)
        
        Args:
            content: Binary content of shellbags
        
        Returns:
            List of shellbag entries
        """
        # In production, parse actual shellbags format
        return [  # Return mock data
            {
                'path': 'C:\\Windows\\System32',  # Directory path
                'accessed': datetime.now().isoformat(),  # Last access time
                'type': 'directory'  # Type of entry
            }
        ]
    
    def _parse_jumplists(self, content: bytes) -> List[Dict]:
        """
        Parse Windows Jump Lists (placeholder)
        
        Args:
            content: Binary content of jumplist
            
        Returns:
            List of jumplist entries
        """
        # In production, parse actual jumplist format
        return [  # Return mock data
            {
                'application': 'notepad.exe',  # Application name
                'target': 'C:\\Windows\\notepad.exe',  # Executable path
                'accessed': datetime.now().isoformat()  # Last access time
            }
        ]
    
    def _parse_recycle_bin(self, content: bytes) -> List[Dict]:
        """
        Parse Windows Recycle Bin artifacts (placeholder)
        
        Args:
            content: Binary content of recycle bin metadata
            
        Returns:
            List of recycle bin entries
        """
        # In production, parse actual recycle bin format
        return [  # Return mock data
            {
                'original_path': 'C:\\Users\\test\\document.txt',  # Original file path
                'deleted_time': datetime.now().isoformat(),  # Deletion timestamp
                'size': 1024  # File size in bytes
            }
        ]
    
    def analyze(self, security_data: Dict[str, Any]) -> Dict[str, Any]:  # Main public method
        """
        Main analysis method - analyze digital evidence for forensic investigation
        
        Process flow:
        1. Collect and preserve evidence
        2. Extract and normalize data
        3. Analyze artifacts
        4. Correlate evidence
        5. Reconstruct timeline
        6. Generate findings
        
        Args:
            security_data: Dictionary containing security data and evidence
            
        Returns:
            Dictionary with forensic analysis results
        """
        start_time = time.time()  # Record start time for performance measurement
        
        try:  # Try block for error handling
            # Extract evidence from security data
            evidence_list = self._extract_evidence(security_data)  # Call evidence extraction
            
            # Return empty response if no evidence found
            if not evidence_list:  # Check if evidence_list is empty
                return {  # Return minimal response
                    'agent_id': self.agent_id,  # Agent identifier
                    'agent_name': self.name,  # Agent name
                    'findings': [],  # Empty findings list
                    'timeline': [],  # Empty timeline
                    'recommendations': [],  # Empty recommendations
                    'analysis_timestamp': datetime.now().isoformat(),  # Current timestamp
                    'reasoning_state': self.get_reasoning_state(),  # Get agent's reasoning state
                    'decision': {  # Decision metrics
                        'incident_confidence': 0.1,  # Low confidence (no evidence)
                        'evidence_weight': 0.1,  # Low evidence weight
                        'timeline_confidence': 0.1,  # Low timeline confidence
                        'evidence': []  # Empty evidence list
                    }
                }
            
            # Process each piece of evidence
            processed_evidence = []  # List for processed evidence
            artifacts_found = []  # List for found artifacts
            
            for evidence in evidence_list:  # Loop through each raw evidence
                # Process individual evidence piece
                processed = self._process_evidence(evidence)  # Process evidence
                processed_evidence.append(processed)  # Add to processed list
                
                # Extract forensic artifacts from processed evidence
                artifacts = self._extract_artifacts(processed)  # Extract artifacts
                artifacts_found.extend(artifacts)  # Add to artifacts list
            
            # Correlate multiple pieces of evidence
            correlations = self._correlate_evidence(processed_evidence)  # Find correlations
            
            # Reconstruct timeline from evidence and artifacts
            timeline = self._reconstruct_timeline(processed_evidence, artifacts_found)  # Build timeline
            
            # Generate forensic findings
            findings = self._generate_findings(processed_evidence, artifacts_found, correlations, timeline)  # Create findings
            
            # Calculate processing time and update metrics
            processing_time = time.time() - start_time  # Calculate elapsed time
            self._update_metrics(len(evidence_list), len(artifacts_found), processing_time)  # Update metrics
            
            # Generate comprehensive response
            response = {  # Build response dictionary
                'agent_id': self.agent_id,  # Agent identifier
                'agent_name': self.name,  # Agent name
                'analysis_timestamp': datetime.now().isoformat(),  # Analysis completion time
                'processing_time': processing_time,  # Time taken for analysis
                'evidence_processed': len(processed_evidence),  # Number of evidence processed
                'artifacts_found': len(artifacts_found),  # Number of artifacts found
                'timeline_events': len(timeline),  # Number of timeline events
                'findings': findings,  # List of findings
                'timeline_summary': self._summarize_timeline(timeline),  # Timeline summary
                'evidence_chain': self._generate_evidence_chain(processed_evidence),  # Evidence relationships
                'recommendations': self._generate_recommendations(findings),  # Action recommendations
                'forensic_report': self._generate_forensic_report(  # Complete report
                    processed_evidence, findings, timeline
                ),
                'reasoning_state': self.get_reasoning_state(),  # Agent's reasoning state
                'decision': {  # Analysis decision metrics
                    'incident_confidence': self._calculate_incident_confidence(findings),  # Confidence in incident
                    'evidence_weight': self._calculate_evidence_weight(processed_evidence),  # Evidence strength
                    'timeline_confidence': self._calculate_timeline_confidence(timeline),  # Timeline reliability
                    'evidence': findings[:3] if findings else []  # Top 3 findings as evidence
                }
            }
            
            # Update agent confidence based on findings
            if findings:  # If findings exist
                certainty = min(0.9, len(findings) * 0.1)  # Calculate certainty (max 0.9)
                self.update_confidence({'certainty': certainty})  # Update agent confidence
            
            return response  # Return complete response
            
        except Exception as e:  # Catch any exception
            # Log error and return error response
            print(f"{self.name}: Forensic analysis error: {e}")  # Print error message
            return self._error_response(str(e))  # Return error response
    
    def _extract_evidence(self, security_data: Dict) -> List[Dict]:
        """
        Extract evidence from security data dictionary
        
        Evidence can be:
        - Log files
        - Memory dumps
        - Network captures
        - Disk images
        - Application data
        
        Args:
            security_data: Dictionary containing security data
            
        Returns:
            List of evidence dictionaries
        """
        evidence_list = []  # Initialize empty evidence list
        
        # Check for direct evidence in 'evidence' key
        if 'evidence' in security_data:  # If evidence key exists
            evidence_data = security_data['evidence']  # Get evidence data
            if isinstance(evidence_data, list):  # If it's a list
                evidence_list.extend(evidence_data)  # Add all list items
            else:  # If it's a single item
                evidence_list.append(evidence_data)  # Add the single item
        
        # Extract from other sources based on key names
        for key, value in security_data.items():  # Loop through all key-value pairs
            if key.endswith('_log') or key.endswith('_dump') or key.endswith('_capture'):  # Check key suffix
                evidence_list.append({  # Create evidence dictionary
                    'type': key.replace('_', ' '),  # Convert key to type (e.g., "web_log")
                    'content': value,  # Evidence content
                    'source': key,  # Source identifier
                    'timestamp': security_data.get('timestamp', datetime.now().isoformat())  # Use provided or current timestamp
                })
        
        # Filter valid evidence
        valid_evidence = []  # List for valid evidence
        for evidence in evidence_list:  # Loop through all evidence
            if self._is_valid_evidence(evidence):  # Check if evidence is valid
                valid_evidence.append(evidence)  # Add to valid list
        
        return valid_evidence  # Return filtered evidence
    
    def _is_valid_evidence(self, evidence: Dict) -> bool:  # Returns True/False
        """
        Validate evidence has required information
        
        Args:
            evidence: Evidence dictionary to validate
            
        Returns:
            True if evidence is valid, False otherwise
        """
        # Check for content
        if 'content' not in evidence:  # If no content key
            return False  # Invalid evidence
        
        # Check if content is not empty
        content = evidence['content']  # Get content
        if content is None or (isinstance(content, (str, bytes)) and len(content) == 0):  # If content is None or empty
            return False  # Invalid evidence
        
        # Check evidence type
        evidence_type = evidence.get('type', '').lower()  # Get type, default to empty string
        
        # Check if evidence type is in supported list
        supported = any(supported_type in evidence_type for supported_type in self.supported_evidence)  # Check if any supported type matches
        
        # If type not supported, try to determine it from content
        if not supported and evidence_type not in ['unknown', '']:  # If not supported and not unknown/empty
            evidence['type'] = self._determine_evidence_type(evidence['content'])  # Determine type from content
        
        return True  # Evidence is valid
    
    def _determine_evidence_type(self, content: Any) -> str:  # Takes any type, returns string
        """
        Determine evidence type from content analysis
        
        Args:
            content: Evidence content to analyze
            
        Returns:
            String representing evidence type
        """
        if content is None:  # If content is None
            return 'unknown'  # Return unknown type
        
        if isinstance(content, str):  # If content is string
            content_str = content.lower()  # Convert to lowercase for comparison
            
            # Check for log patterns
            for parser_name in self.log_parsers.keys():  # Loop through known log parsers
                if parser_name in content_str[:1000]:  # Check if parser name in first 1000 chars
                    return 'log_file'  # Return log_file type
            
            # Check for JSON
            if content_str.strip().startswith('{') or content_str.strip().startswith('['):  # Check for JSON start
                return 'json_file'  # Return json_file type
            
            # Check for XML
            if content_str.strip().startswith('<?xml') or (content_str.strip().startswith('<') and '>' in content_str):  # Check for XML
                return 'xml_file'  # Return xml_file type
        
        elif isinstance(content, bytes):  # If content is bytes
            # Check for binary formats using magic numbers
            if len(content) >= 4 and content[:4] == b'\x7fELF':  # ELF executable magic
                return 'executable'  # Return executable type
            elif len(content) >= 2 and content[:2] == b'MZ':  # Windows executable magic
                return 'windows_executable'  # Return windows_executable type
            elif len(content) >= 8 and content[:8] == b'\x89PNG\r\n\x1a\n':  # PNG image magic
                return 'image'  # Return image type
        
        return 'unknown'  # Default to unknown type
    
    def _process_evidence(self, evidence: Dict) -> Dict:  # Process single evidence
        """
        Process single piece of evidence
        
        Steps:
        1. Generate hash for integrity
        2. Extract metadata
        3. Parse content
        4. Normalize data
        
        Args:
            evidence: Raw evidence dictionary
            
        Returns:
            Processed evidence dictionary
        """
        # Generate unique evidence ID
        evidence_id = f"evd_{self.evidence_counter:06d}"  # Format as evd_000001
        self.evidence_counter += 1  # Increment counter for next evidence
        
        # Get content from evidence
        content = evidence['content']  # Extract content
        
        # Generate cryptographic hashes for integrity verification
        hashes = self._generate_hashes(content)  # Generate multiple hash values
        
        # Extract metadata from evidence
        metadata = self._extract_metadata(evidence, content)  # Extract metadata
        
        # Parse content based on evidence type
        evidence_type = evidence.get('type', 'unknown')  # Get evidence type
        parsed_content = self._parse_content(content, evidence_type)  # Parse content
        
        # Create processed evidence dictionary
        processed_evidence = {  # Build processed evidence structure
            'id': evidence_id,  # Unique evidence ID
            'type': evidence_type,  # Evidence type
            'source': evidence.get('source', 'unknown'),  # Source identifier
            'timestamp': evidence.get('timestamp', datetime.now().isoformat()),  # Evidence timestamp
            'hashes': hashes,  # Cryptographic hashes
            'metadata': metadata,  # Extracted metadata
            'parsed_content': parsed_content,  # Parsed content data
            'original_size': len(str(content)) if isinstance(content, (str, bytes)) else len(str(content)),  # Size in characters/bytes
            'collection_timestamp': datetime.now().isoformat(),  # When evidence was collected
            'collector': self.agent_id  # Who collected the evidence
        }
        
        # Store in evidence store
        self.evidence_store[evidence_id] = processed_evidence  # Add to evidence store
        
        # Update chain of custody
        self._update_chain_of_custody(evidence_id, 'collected')  # Record collection in chain
        
        # Update metrics
        self.metrics['evidence_collected'] += 1  # Increment evidence collected counter
        
        return processed_evidence  # Return processed evidence
    
    def _generate_hashes(self, content: Any) -> Dict[str, str]:  # Generate hash dictionary
        """
        Generate cryptographic hashes for evidence integrity
        
        Args:
            content: Evidence content to hash
            
        Returns:
            Dictionary of hash algorithm names to hash values
        """
        hashes = {}  # Initialize empty hash dictionary
        
        # Convert content to bytes for hashing
        if isinstance(content, str):  # If content is string
            content_bytes = content.encode('utf-8', errors='ignore')  # Convert to UTF-8 bytes
        elif isinstance(content, bytes):  # If content is already bytes
            content_bytes = content  # Use as-is
        else:  # If content is other type (int, float, dict, etc.)
            # Convert any other type to string then bytes
            content_bytes = str(content).encode('utf-8', errors='ignore')  # Convert to string then bytes
        
        # Generate hashes using all supported algorithms
        for algo in self.hash_algorithms:  # Loop through each algorithm
            try:  # Try to generate hash
                hash_func = hashlib.new(algo)  # Create hash function for algorithm
                hash_func.update(content_bytes)  # Update hash with content bytes
                hashes[algo] = hash_func.hexdigest()  # Get hexadecimal digest
            except Exception:  # If algorithm not supported
                # Skip unsupported algorithm
                continue  # Continue to next algorithm
        
        return hashes  # Return dictionary of hashes
    
    def _extract_metadata(self, evidence: Dict, content: Any) -> Dict[str, Any]:
        """
        Extract metadata from evidence
        
        Args:
            evidence: Evidence dictionary
            content: Evidence content
            
        Returns:
            Dictionary of metadata
        """
        metadata = {  # Initialize metadata dictionary
            'evidence_type': evidence.get('type', 'unknown'),  # Evidence type
            'source': evidence.get('source', 'unknown'),  # Evidence source
            'timestamp': evidence.get('timestamp', datetime.now().isoformat()),  # Evidence timestamp
            'content_type': type(content).__name__  # Python type name (str, bytes, etc.)
        }
        
        # Extract additional metadata based on evidence type
        evidence_type = evidence.get('type', '').lower()  # Get lowercase type
        
        if 'log' in evidence_type:  # If evidence is log file
            metadata['log_type'] = self._determine_log_type(content)  # Determine log format
            if isinstance(content, str):  # If content is string
                metadata['line_count'] = len(content.split('\n'))  # Count lines
            else:  # If not string
                metadata['line_count'] = 1  # Default to 1
        
        elif 'memory' in evidence_type:  # If evidence is memory dump
            metadata['memory_size'] = len(content) if isinstance(content, bytes) else 0  # Size in bytes
        
        elif 'network' in evidence_type or 'pcap' in evidence_type:  # If evidence is network capture
            metadata['packet_count'] = self._estimate_packet_count(content)  # Estimate packets
        
        return metadata  # Return metadata
    
    def _determine_log_type(self, content: Any) -> str:
        """
        Determine log file type from content analysis
        
        Args:
            content: Log content to analyze
            
        Returns:
            String representing log type
        """
        if not isinstance(content, str):  # If content is not string
            return 'unknown'  # Return unknown
        
        sample = content[:1000].lower()  # Get first 1000 chars in lowercase
        
        # Try to match against known log patterns
        for log_type, parser in self.log_parsers.items():  # Loop through parsers
            try:  # Try regex match
                if re.search(parser['pattern'], sample, re.MULTILINE):  # Search for pattern
                    return log_type  # Return matched log type
            except re.error:  # If regex pattern error
                continue  # Skip this parser
        
        # Check for common patterns heuristically
        if 'apache' in sample or 'httpd' in sample:  # Check for Apache keywords
            return 'apache'  # Return apache type
        elif 'nginx' in sample:  # Check for Nginx keywords
            return 'nginx'  # Return nginx type
        elif 'event' in sample and 'windows' in sample:  # Check for Windows Event keywords
            return 'windows_event'  # Return windows_event type
        
        return 'generic'  # Default to generic log type
    
    def _estimate_packet_count(self, content: Any) -> int:
        """
        Estimate packet count in network capture
        
        Args:
            content: Network capture content
            
        Returns:
            Estimated packet count
        """
        if isinstance(content, bytes):  # If content is bytes (binary PCAP)
            # Rough estimate: assume average packet size of 1500 bytes
            return max(1, len(content) // 1500)  # Return at least 1
        elif isinstance(content, str):  # If content is string (text PCAP)
            # For text-based PCAP representations
            return max(1, len(content) // 100)  # Rough estimate
        return 0  # Default to 0
    
    def _parse_content(self, content: Any, evidence_type: str) -> Dict[str, Any]:
        """
        Parse evidence content based on type
        
        Args:
            content: Evidence content to parse
            evidence_type: Type of evidence
            
        Returns:
            Dictionary with parsing results
        """
        result = {  # Initialize result dictionary
            'raw_preview': str(content)[:500] if content else '',  # First 500 chars as string
            'parsed_successfully': False,  # Parsing success flag
            'parsed_data': None,  # Placeholder for parsed data
            'parse_error': None  # Placeholder for error message
        }
        
        try:  # Try to parse content
            evidence_type_lower = evidence_type.lower()  # Convert to lowercase
            
            # Parse log files
            if 'log' in evidence_type_lower:  # If evidence type contains 'log'
                parsed = self._parse_log_content(content, evidence_type_lower)  # Parse as log
                result['parsed_data'] = parsed  # Store parsed data
                result['parsed_successfully'] = True  # Set success flag
            
            # Parse structured files (JSON, XML, CSV, YAML, INI)
            elif any(fmt in evidence_type_lower for fmt in ['json', 'xml', 'csv', 'yaml', 'ini']):  # Check for structured formats
                for fmt, parser in self.file_parsers.items():  # Loop through file parsers
                    if fmt in evidence_type_lower:  # If format matches evidence type
                        parsed = parser(content)  # Parse content
                        result['parsed_data'] = parsed  # Store parsed data
                        result['parsed_successfully'] = True  # Set success flag
                        break  # Stop searching
            
            # Parse forensic artifacts
            elif any(artifact in evidence_type_lower for artifact in self.artifact_parsers.keys()):  # Check for artifact types
                for artifact, parser in self.artifact_parsers.items():  # Loop through artifact parsers
                    if artifact in evidence_type_lower:  # If artifact matches evidence type
                        # Convert to bytes if needed
                        if isinstance(content, bytes):  # If already bytes
                            content_bytes = content  # Use as-is
                        else:  # If not bytes
                            content_bytes = str(content).encode('utf-8', errors='ignore')  # Convert to bytes
                        parsed = parser(content_bytes)  # Parse as artifact
                        result['parsed_data'] = parsed  # Store parsed data
                        result['parsed_successfully'] = True  # Set success flag
                        break  # Stop searching
            
            # For unknown types, just store preview
            else:  # If type not recognized
                result['parsed_data'] = {'preview': str(content)[:1000]}  # Store preview
                result['parsed_successfully'] = True  # Set success flag
        
        except Exception as e:  # Catch parsing errors
            result['parse_error'] = str(e)  # Store error message
        
        return result  # Return parsing result
    
    def _parse_log_content(self, content: Any, log_type: str) -> List[Dict]:
        """
        Parse log file content using appropriate parser
        
        Args:
            content: Log content to parse
            log_type: Type of log
            
        Returns:
            List of parsed log entries
        """
        if not isinstance(content, str):  # If content not string
            return []  # Return empty list
        
        lines = content.split('\n')  # Split content into lines
        parsed_lines = []  # Initialize list for parsed lines
        
        # Determine appropriate parser configuration
        parser_config = None  # Initialize parser config
        for parser_name, config in self.log_parsers.items():  # Loop through parsers
            if parser_name in log_type:  # If parser name in log type
                parser_config = config  # Set parser config
                break  # Stop searching
        
        # Auto-detect parser if not found by name
        if not parser_config:  # If no parser found by name
            for parser_name, config in self.log_parsers.items():  # Loop through parsers
                try:  # Try to match first line
                    if lines and re.search(config['pattern'], lines[0]):  # Check first line
                        parser_config = config  # Set parser config
                        break  # Stop searching
                except re.error:  # If regex error
                    continue  # Continue to next parser
        
        # If no parser found, use generic parsing
        if not parser_config:  # If still no parser
            for line in lines[:100]:  # Loop through first 100 lines
                line = line.strip()  # Remove whitespace
                if line:  # If line not empty
                    parsed_lines.append({  # Add generic entry
                        'raw': line[:200],  # First 200 chars
                        'timestamp': self._extract_timestamp(line),  # Extract timestamp
                        'message': line  # Full line as message
                    })
            return parsed_lines  # Return generic parsed lines
        
        # Use specific parser with regex pattern
        try:  # Try to parse with specific parser
            pattern = re.compile(parser_config['pattern'])  # Compile regex pattern
            fields = parser_config['fields']  # Get field names
            
            for line in lines[:1000]:  # Loop through first 1000 lines
                line = line.strip()  # Remove whitespace
                if not line:  # If line empty
                    continue  # Skip to next line
                    
                match = pattern.match(line)  # Try to match pattern
                if match:  # If pattern matches
                    parsed_line = {}  # Initialize parsed line dict
                    for i, field in enumerate(fields):  # Loop through fields
                        if i < len(match.groups()):  # If field exists in match
                            parsed_line[field] = match.group(i+1)  # Get matched group
                        else:  # If field doesn't exist
                            parsed_line[field] = None  # Set to None
                    
                    # Extract timestamp if not already parsed
                    if 'timestamp' not in parsed_line or not parsed_line['timestamp']:  # If no timestamp
                        parsed_line['timestamp'] = self._extract_timestamp(line)  # Extract timestamp
                    
                    parsed_line['raw'] = line[:200]  # Store raw line snippet
                    parsed_lines.append(parsed_line)  # Add to parsed lines
        except re.error:  # If regex compilation fails
            # Fall back to generic parsing if regex fails
            for line in lines[:100]:  # Loop through first 100 lines
                if line.strip():  # If line not empty
                    parsed_lines.append({  # Add generic entry
                        'raw': line[:200],  # First 200 chars
                        'timestamp': self._extract_timestamp(line),  # Extract timestamp
                        'message': line  # Full line
                    })
        
        return parsed_lines  # Return parsed lines
    
    def _extract_timestamp(self, text: str) -> Optional[str]:  # Returns string or None
        """
        Extract timestamp from text using common patterns
        
        Args:
            text: Text to search for timestamp
            
        Returns:
            Extracted timestamp string or None if not found
        """
        if not text:  # If text is empty
            return None  # Return None
        
        # Common timestamp patterns
        patterns = [
            r'(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)',  # ISO 8601 with timezone
            r'(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})',  # MM/DD/YYYY HH:MM:SS
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',    # Mon DD HH:MM:SS
            r'(\d{2}:\d{2}:\d{2})'                       # HH:MM:SS
        ]
        
        for pattern in patterns:  # Loop through patterns
            try:  # Try to search pattern
                match = re.search(pattern, text)  # Search for pattern in text
                if match:  # If found
                    return match.group(1)  # Return matched timestamp
            except re.error:  # If regex error
                continue  # Continue to next pattern
        
        return None  # Return None if no timestamp found
    
    def _update_chain_of_custody(self, evidence_id: str, action: str):  # No return value
        """
        Update chain of custody for evidence
        
        Args:
            evidence_id: ID of the evidence
            action: Action performed on evidence
        """
        if evidence_id not in self.chain_of_custody:  # If first entry for this evidence
            self.chain_of_custody[evidence_id] = []  # Initialize empty list
        
        self.chain_of_custody[evidence_id].append({  # Add new custody entry
            'timestamp': datetime.now().isoformat(),  # Current time
            'action': action,  # Action performed (collected, analyzed, etc.)
            'agent': self.agent_id,  # Who performed action
            'note': f'{action.capitalize()} by {self.name}'  # Human-readable note
        })
    
    def _extract_artifacts(self, evidence: Dict) -> List[Dict]:
        """
        Extract forensic artifacts from evidence
        
        Args:
            evidence: Processed evidence dictionary
            
        Returns:
            List of extracted artifacts
        """
        artifacts = []  # Initialize empty artifacts list
        
        # Extract artifacts based on evidence type
        evidence_type = evidence['type'].lower()  # Get lowercase type
        parsed_content = evidence['parsed_content']['parsed_data']  # Get parsed data
        
        if not parsed_content or not evidence['parsed_content']['parsed_successfully']:  # If parsing failed
            return artifacts  # Return empty list
        
        # Look for suspicious patterns in logs
        if 'log' in evidence_type and isinstance(parsed_content, list):  # If log file with list data
            for entry in parsed_content[:100]:  # Loop through first 100 entries
                artifact = self._extract_artifacts_from_log(entry)  # Extract artifacts from log entry
                if artifact:  # If artifact found
                    artifact['source_evidence'] = evidence['id']  # Add evidence reference
                    artifacts.append(artifact)  # Add to artifacts list
        
        # Look for suspicious files or registry entries
        elif any(artifact_type in evidence_type for artifact_type in self.artifact_parsers.keys()):  # If artifact type
            artifact = {  # Create artifact dictionary
                'type': evidence_type,  # Artifact type
                'content': parsed_content,  # Parsed content
                'source_evidence': evidence['id'],  # Source evidence ID
                'timestamp': evidence['timestamp'],  # Evidence timestamp
                'confidence': 0.7  # Default confidence
            }
            artifacts.append(artifact)  # Add to artifacts list
        
        # Update metrics
        self.metrics['artifacts_found'] += len(artifacts)  # Update artifact count
        
        return artifacts  # Return artifacts
    
    def _extract_artifacts_from_log(self, log_entry: Dict) -> Optional[Dict]:  # Returns dict or None
        """
        Extract forensic artifacts from log entry
        
        Args:
            log_entry: Parsed log entry dictionary
            
        Returns:
            Artifact dictionary if suspicious pattern found, None otherwise
        """
        message = str(log_entry.get('message', '')).lower()  # Get message in lowercase
        
        # Suspicious patterns to look for with corresponding artifact types and confidence scores
        suspicious_patterns = [
            (r'(failed\s+password|authentication\s+failure)', 'failed_auth', 0.8),
            (r'(sudo|su)\s+.*failed', 'privilege_escalation_attempt', 0.7),
            (r'(firewall\s+denied|blocked)', 'firewall_block', 0.6),
            (r'(malware|virus|trojan|ransomware)', 'malware_detection', 0.9),
            (r'(sql\s+injection|xss|cross-site)', 'web_attack', 0.8),
            (r'(port\s+scan|nmap|scanning)', 'port_scan', 0.7),
            (r'(brute\s+force|password\s+spray)', 'brute_force', 0.8),
            (r'(data\s+exfiltration|data\s+theft)', 'data_theft', 0.9),
            (r'(unauthorized\s+access|access\s+violation)', 'unauthorized_access', 0.8),
            (r'(privilege\s+escalation|root\s+access)', 'privilege_escalation', 0.9)
        ]
        
        for pattern, artifact_type, confidence in suspicious_patterns:  # Loop through patterns
            try:  # Try regex search
                if re.search(pattern, message, re.IGNORECASE):  # Search case-insensitive
                    return {  # Return artifact dictionary
                        'type': artifact_type,  # Artifact type
                        'source': 'log_analysis',  # Source of detection
                        'message': log_entry.get('message', '')[:200],  # Truncated message
                        'timestamp': log_entry.get('timestamp', ''),  # Log timestamp
                        'confidence': confidence,  # Detection confidence
                        'pattern_matched': pattern  # Pattern that matched
                    }
            except re.error:  # If regex error
                continue  # Continue to next pattern
        
        return None  # Return None if no suspicious patterns
    
    def _correlate_evidence(self, evidence_list: List[Dict]) -> List[Dict]:
        """
        Correlate multiple pieces of evidence
        
        Args:
            evidence_list: List of processed evidence dictionaries
            
        Returns:
            List of correlation findings
        """
        correlations = []  # Initialize correlations list
        
        if len(evidence_list) < 2:  # Need at least 2 pieces for correlation
            return correlations  # Return empty list
        
        # Look for correlations between evidence pairs
        for i in range(len(evidence_list)):  # Outer loop
            for j in range(i+1, len(evidence_list)):  # Inner loop (pairs)
                ev1 = evidence_list[i]  # First evidence
                ev2 = evidence_list[j]  # Second evidence
                
                # Check temporal correlation (time proximity)
                time_corr = self._check_temporal_correlation(ev1, ev2)  # Check time correlation
                if time_corr['correlated']:  # If temporally correlated
                    correlations.append({  # Add correlation
                        'evidence_ids': [ev1['id'], ev2['id']],  # Evidence IDs
                        'correlation_type': 'temporal',  # Type of correlation
                        'confidence': time_corr['confidence'],  # Correlation confidence
                        'time_gap': time_corr['time_gap'],  # Time difference
                        'description': time_corr['description']  # Human description
                    })
                
                # Check content similarity
                content_corr = self._check_content_correlation(ev1, ev2)  # Check content correlation
                if content_corr['correlated']:  # If content correlated
                    correlations.append({  # Add correlation
                        'evidence_ids': [ev1['id'], ev2['id']],  # Evidence IDs
                        'correlation_type': 'content',  # Type of correlation
                        'confidence': content_corr['confidence'],  # Correlation confidence
                        'similarity_score': content_corr['similarity'],  # Similarity score
                        'description': content_corr['description']  # Human description
                    })
                
                # Check source correlation
                source_corr = self._check_source_correlation(ev1, ev2)  # Check source correlation
                if source_corr['correlated']:  # If source correlated
                    correlations.append({  # Add correlation
                        'evidence_ids': [ev1['id'], ev2['id']],  # Evidence IDs
                        'correlation_type': 'source',  # Type of correlation
                        'confidence': source_corr['confidence'],  # Correlation confidence
                        'common_source': source_corr['common_source'],  # Common source
                        'description': source_corr['description']  # Human description
                    })
        
        return correlations  # Return all correlations
    
    def _check_temporal_correlation(self, ev1: Dict, ev2: Dict) -> Dict[str, Any]:
        """
        Check if two pieces of evidence are temporally correlated
        
        Args:
            ev1: First evidence dictionary
            ev2: Second evidence dictionary
            
        Returns:
            Dictionary with temporal correlation results
        """
        try:  # Try to parse timestamps
            # Parse timestamps, handling different formats
            t1_str = ev1['timestamp'].replace('Z', '+00:00')  # Convert Z to timezone
            t2_str = ev2['timestamp'].replace('Z', '+00:00')  # Convert Z to timezone
            
            # Handle different timestamp formats
            for fmt in ['%Y-%m-%dT%H:%M:%S.%f%z', '%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%d %H:%M:%S']:  # Try formats
                try:  # Try to parse with format
                    t1 = datetime.strptime(t1_str, fmt)  # Parse first timestamp
                    t2 = datetime.strptime(t2_str, fmt)  # Parse second timestamp
                    
                    time_gap = abs((t1 - t2).total_seconds())  # Calculate absolute time difference
                    
                    # Events within 5 minutes are considered correlated
                    if time_gap < 300:  # 300 seconds = 5 minutes
                        confidence = 1.0 - (time_gap / 300)  # Calculate confidence (closer = higher)
                        return {  # Return correlation result
                            'correlated': True,  # Correlation exists
                            'confidence': confidence,  # Confidence score
                            'time_gap': time_gap,  # Time difference
                            'description': f'Events within {time_gap:.1f} seconds'  # Description
                        }
                    break  # Break if parsed successfully (even if not correlated)
                except ValueError:  # If format doesn't match
                    continue  # Try next format
        except Exception:  # Catch any exception
            pass  # Ignore errors
        
        return {  # Return no correlation
            'correlated': False,  # No correlation
            'confidence': 0.0,  # Zero confidence
            'time_gap': None,  # No time gap
            'description': 'Not temporally correlated'  # Description
        }
    
    def _check_content_correlation(self, ev1: Dict, ev2: Dict) -> Dict[str, Any]:
        """
        Check if two pieces of evidence have similar content
        
        Args:
            ev1: First evidence dictionary
            ev2: Second evidence dictionary
            
        Returns:
            Dictionary with content correlation results
        """
        # Extract text from evidence
        text1 = str(ev1['parsed_content'].get('parsed_data', '')).lower()  # Convert to lowercase
        text2 = str(ev2['parsed_content'].get('parsed_data', '')).lower()  # Convert to lowercase
        
        if not text1 or not text2:  # If either text is empty
            return {  # Return no correlation
                'correlated': False,  # No correlation
                'confidence': 0.0,  # Zero confidence
                'similarity': 0.0,  # Zero similarity
                'description': 'No content to compare'  # Description
            }
        
        # Simple similarity check using word overlap
        words1 = set(re.findall(r'\w+', text1))  # Extract words from text1
        words2 = set(re.findall(r'\w+', text2))  # Extract words from text2
        
        if not words1 or not words2:  # If no words extracted
            return {  # Return no correlation
                'correlated': False,  # No correlation
                'confidence': 0.0,  # Zero confidence
                'similarity': 0.0,  # Zero similarity
                'description': 'No words to compare'  # Description
            }
        
        # Calculate Jaccard similarity (intersection over union)
        common_words = words1.intersection(words2)  # Find common words
        similarity = len(common_words) / max(len(words1), len(words2))  # Calculate similarity
        
        # 30% word overlap threshold for correlation
        if similarity > 0.3:  # If similarity above threshold
            return {  # Return correlation
                'correlated': True,  # Correlation exists
                'confidence': min(1.0, similarity * 2),  # Confidence (capped at 1.0)
                'similarity': similarity,  # Similarity score
                'description': f'{len(common_words)} common words ({similarity:.1%} similarity)'  # Description
            }
        
        return {  # Return no correlation
            'correlated': False,  # No correlation
            'confidence': 0.0,  # Zero confidence
            'similarity': similarity,  # Similarity score
            'description': 'Low content similarity'  # Description
        }
    
    def _check_source_correlation(self, ev1: Dict, ev2: Dict) -> Dict[str, Any]:
        """
        Check if two pieces of evidence come from related sources
        
        Args:
            ev1: First evidence dictionary
            ev2: Second evidence dictionary
            
        Returns:
            Dictionary with source correlation results
        """
        source1 = ev1.get('source', '').lower()  # Get source 1
        source2 = ev2.get('source', '').lower()  # Get source 2
        
        # Check if sources are identical
        if source1 == source2 and source1:  # If sources match and not empty
            return {  # Return correlation
                'correlated': True,  # Correlation exists
                'confidence': 0.9,  # High confidence
                'common_source': source1,  # Common source
                'description': f'Same source: {source1}'  # Description
            }
        
        # Check for related sources (e.g., same system, same application)
        common_terms = ['system', 'application', 'service', 'server', 'host', 'log']  # Common terms
        for term in common_terms:  # Loop through terms
            if term in source1 and term in source2:  # If both sources contain term
                return {  # Return correlation
                    'correlated': True,  # Correlation exists
                    'confidence': 0.6,  # Medium confidence
                    'common_source': term,  # Common term
                    'description': f'Related sources: both contain "{term}"'  # Description
                }
        
        return {  # Return no correlation
            'correlated': False,  # No correlation
            'confidence': 0.0,  # Zero confidence
            'common_source': None,  # No common source
            'description': 'Different sources'  # Description
        }
    
    def _reconstruct_timeline(self, evidence_list: List[Dict], artifacts: List[Dict]) -> List[Dict]:
        """
        Reconstruct timeline from evidence and artifacts
        
        Args:
            evidence_list: List of processed evidence
            artifacts: List of extracted artifacts
            
        Returns:
            List of timeline events sorted chronologically
        """
        timeline_events = []  # Initialize timeline events list
        
        # Add evidence collection events
        for evidence in evidence_list:  # Loop through evidence
            timeline_events.append({  # Add collection event
                'timestamp': evidence['collection_timestamp'],  # Collection time
                'type': 'evidence_collection',  # Event type
                'source': 'forensic_agent',  # Event source
                'description': f'Collected evidence: {evidence["id"]} ({evidence["type"]})',  # Description
                'evidence_id': evidence['id'],  # Evidence ID
                'confidence': 1.0  # Full confidence
            })
        
        # Add artifact events
        for artifact in artifacts:  # Loop through artifacts
            timeline_events.append({  # Add artifact event
                'timestamp': artifact.get('timestamp', datetime.now().isoformat()),  # Artifact time
                'type': artifact['type'],  # Artifact type
                'source': artifact.get('source', 'unknown'),  # Source
                'description': f'Found artifact: {artifact["type"]}',  # Description
                'artifact': artifact,  # Full artifact data
                'confidence': artifact.get('confidence', 0.5)  # Artifact confidence
            })
        
        # Add evidence events (from parsed content)
        for evidence in evidence_list:  # Loop through evidence
            if evidence['parsed_content']['parsed_successfully']:  # If parsing successful
                parsed_data = evidence['parsed_content']['parsed_data']  # Get parsed data
                
                if isinstance(parsed_data, list):  # If parsed data is list (log entries)
                    for entry in parsed_data[:50]:  # Loop through first 50 entries
                        if isinstance(entry, dict) and 'timestamp' in entry:  # If entry has timestamp
                            timeline_events.append({  # Add log event
                                'timestamp': entry['timestamp'],  # Log timestamp
                                'type': 'log_entry',  # Event type
                                'source': evidence['type'],  # Evidence type as source
                                'description': entry.get('message', 'Log entry')[:100],  # Truncated message
                                'evidence_id': evidence['id'],  # Evidence ID
                                'confidence': 0.7  # Medium confidence
                            })
        
        # Sort by timestamp
        try:  # Try to sort
            timeline_events.sort(key=lambda x: x['timestamp'])  # Sort by timestamp
        except Exception:  # If sorting fails
            # If sorting fails, keep original order
            pass  # Ignore error
        
        # Update metrics
        self.metrics['timelines_created'] += 1  # Increment timeline counter
        
        return timeline_events  # Return timeline
    
    def _generate_findings(self, evidence_list: List[Dict], artifacts: List[Dict], 
                         correlations: List[Dict], timeline: List[Dict]) -> List[Dict]:
        """
        Generate forensic findings from analysis results
        
        Args:
            evidence_list: List of processed evidence
            artifacts: List of extracted artifacts
            correlations: List of evidence correlations
            timeline: List of timeline events
            
        Returns:
            List of forensic findings
        """
        findings = []  # Initialize findings list
        
        # 1. Artifact-based findings
        for artifact in artifacts:  # Loop through artifacts
            if artifact.get('confidence', 0) > self.thresholds['artifact_relevance']:  # If above threshold
                findings.append({  # Add finding
                    'type': 'artifact_discovery',  # Finding type
                    'severity': self._artifact_severity(artifact['type']),  # Calculate severity
                    'confidence': artifact['confidence'],  # Artifact confidence
                    'description': f'Found {artifact["type"]} artifact',  # Description
                    'artifact': artifact,  # Full artifact data
                    'recommendation': self._artifact_recommendation(artifact['type'])  # Recommendation
                })
        
        # 2. Correlation-based findings
        for correlation in correlations:  # Loop through correlations
            if correlation['confidence'] > self.thresholds['evidence_confidence']:  # If above threshold
                findings.append({  # Add finding
                    'type': 'evidence_correlation',  # Finding type
                    'severity': 'medium',  # Fixed medium severity
                    'confidence': correlation['confidence'],  # Correlation confidence
                    'description': f'{correlation["correlation_type"]} correlation found',  # Description
                    'correlation': correlation,  # Full correlation data
                    'recommendation': 'Investigate correlated evidence further'  # Recommendation
                })
        
        # 3. Timeline-based findings
        if len(timeline) >= self.thresholds['min_evidence_count']:  # If enough timeline events
            timeline_analysis = self._analyze_timeline(timeline)  # Analyze timeline
            if timeline_analysis['suspicious']:  # If timeline suspicious
                findings.append({  # Add finding
                    'type': 'timeline_anomaly',  # Finding type
                    'severity': 'high',  # High severity
                    'confidence': timeline_analysis['confidence'],  # Analysis confidence
                    'description': timeline_analysis['description'],  # Description
                    'timeline_summary': timeline_analysis['summary'],  # Timeline summary
                    'recommendation': 'Conduct detailed timeline analysis'  # Recommendation
                })
        
        # 4. Evidence integrity findings
        for evidence in evidence_list:  # Loop through evidence
            integrity_check = self._check_evidence_integrity(evidence)  # Check integrity
            if not integrity_check['intact']:  # If integrity compromised
                findings.append({  # Add finding
                    'type': 'evidence_integrity',  # Finding type
                    'severity': 'critical',  # Critical severity
                    'confidence': 0.9,  # High confidence
                    'description': integrity_check['issue'],  # Integrity issue
                    'evidence_id': evidence['id'],  # Evidence ID
                    'recommendation': 'Preserve original evidence and verify chain of custody'  # Recommendation
                })
        
        # Update metrics
        self.metrics['incidents_reconstructed'] += len(findings)  # Update incident counter
        
        return findings  # Return findings
    
    def _artifact_severity(self, artifact_type: str) -> str:  # Returns severity string
        """
        Determine severity level for artifact type
        
        Args:
            artifact_type: Type of artifact
            
        Returns:
            Severity string ('critical', 'high', 'medium', 'low')
        """
        high_severity = ['malware_detection', 'data_theft', 'privilege_escalation', 
                        'unauthorized_access', 'web_attack']  # High severity artifacts
        medium_severity = ['failed_auth', 'brute_force', 'port_scan', 
                          'firewall_block', 'privilege_escalation_attempt']  # Medium severity artifacts
        
        if artifact_type in high_severity:  # If artifact in high list
            return 'high'  # Return high
        elif artifact_type in medium_severity:  # If artifact in medium list
            return 'medium'  # Return medium
        else:  # If not in either list
            return 'low'  # Return low
    
    def _artifact_recommendation(self, artifact_type: str) -> str:
        """
        Generate recommendation for artifact type
        
        Args:
            artifact_type: Type of artifact
            
        Returns:
            Recommendation string
        """
        recommendations = {  # Dictionary of recommendations by artifact type
            'malware_detection': 'Scan system for malware and isolate if found',
            'data_theft': 'Check for data exfiltration and review access logs',
            'privilege_escalation': 'Review user privileges and audit logs',
            'unauthorized_access': 'Investigate access patterns and strengthen authentication',
            'web_attack': 'Review web server logs and implement WAF rules',
            'failed_auth': 'Check for brute force attacks and implement account lockout',
            'brute_force': 'Implement rate limiting and monitor authentication attempts',
            'port_scan': 'Review firewall logs and block scanning IPs',
            'firewall_block': 'Monitor firewall for patterns and adjust rules as needed'
        }
        
        return recommendations.get(artifact_type, 'Investigate further')  # Return recommendation or default
    
    def _analyze_timeline(self, timeline: List[Dict]) -> Dict[str, Any]:
        """
        Analyze timeline for suspicious patterns
        
        Args:
            timeline: List of timeline events
            
        Returns:
            Dictionary with timeline analysis results
        """
        if len(timeline) < 3:  # Need at least 3 events for analysis
            return {'suspicious': False, 'confidence': 0.0, 'description': 'Insufficient data'}  # Return insufficient
        
        # Check for rapid sequence of events
        rapid_events = 0  # Initialize rapid event counter
        for i in range(1, len(timeline)):  # Loop through adjacent events
            try:  # Try to calculate time gap
                t1_str = timeline[i-1]['timestamp'].replace('Z', '+00:00')  # Convert first timestamp
                t2_str = timeline[i]['timestamp'].replace('Z', '+00:00')  # Convert second timestamp
                
                # Try multiple timestamp formats
                for fmt in ['%Y-%m-%dT%H:%M:%S.%f%z', '%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%d %H:%M:%S']:  # Try formats
                    try:  # Try to parse
                        t1 = datetime.strptime(t1_str, fmt)  # Parse first timestamp
                        t2 = datetime.strptime(t2_str, fmt)  # Parse second timestamp
                        time_gap = (t2 - t1).total_seconds()  # Calculate time gap
                        
                        if time_gap < 10:  # Less than 10 seconds between events
                            rapid_events += 1  # Count as rapid event
                        break  # Break after successful parse
                    except ValueError:  # If format doesn't match
                        continue  # Try next format
            except Exception:  # Catch any exception
                continue  # Continue to next pair
        
        rapid_ratio = rapid_events / max(1, len(timeline) - 1)  # Calculate ratio of rapid events
        
        if rapid_ratio > 0.3:  # More than 30% rapid events
            return {  # Return suspicious
                'suspicious': True,  # Timeline is suspicious
                'confidence': min(1.0, rapid_ratio),  # Confidence based on ratio
                'description': f'Rapid event sequence detected ({rapid_events} rapid events)',  # Description
                'summary': {'rapid_events': rapid_events, 'total_events': len(timeline), 'ratio': rapid_ratio}  # Summary
            }
        
        # Check for suspicious event types
        suspicious_types = ['malware_detection', 'data_theft', 'privilege_escalation']  # Suspicious types
        suspicious_count = sum(1 for event in timeline if event.get('type') in suspicious_types)  # Count suspicious
        
        if suspicious_count > 0:  # If any suspicious events
            suspicious_ratio = suspicious_count / len(timeline)  # Calculate ratio
            return {  # Return suspicious
                'suspicious': True,  # Timeline is suspicious
                'confidence': min(1.0, suspicious_ratio * 2),  # Confidence (weighted)
                'description': f'Suspicious event types detected ({suspicious_count} events)',  # Description
                'summary': {'suspicious_events': suspicious_count, 'total_events': len(timeline)}  # Summary
            }
        
        return {  # Return not suspicious
            'suspicious': False,  # Timeline not suspicious
            'confidence': 0.1,  # Low confidence
            'description': 'No significant anomalies detected',  # Description
            'summary': {'total_events': len(timeline)}  # Summary
        }
    
    def _check_evidence_integrity(self, evidence: Dict) -> Dict[str, Any]:
        """
        Check evidence integrity (simplified)
        
        Args:
            evidence: Evidence dictionary to check
            
        Returns:
            Dictionary with integrity check results
        """
        # In production, verify hashes and chain of custody
        if 'hashes' not in evidence or not evidence['hashes']:  # If no hashes
            return {  # Return integrity issue
                'intact': False,  # Integrity compromised
                'issue': 'No integrity hashes found',  # Issue description
                'recommendation': 'Generate cryptographic hashes for evidence'  # Recommendation
            }
        
        # Check if hashes are valid (non-empty strings)
        for hash_name, hash_value in evidence['hashes'].items():  # Loop through hashes
            if not hash_value or not isinstance(hash_value, str) or len(hash_value) < 32:  # If hash invalid
                return {  # Return integrity issue
                    'intact': False,  # Integrity compromised
                    'issue': f'Invalid hash for {hash_name}',  # Issue description
                    'recommendation': 'Regenerate cryptographic hashes for evidence'  # Recommendation
                }
        
        return {  # Return integrity intact
            'intact': True,  # Integrity intact
            'issue': None,  # No issues
            'recommendation': 'Evidence integrity appears intact'  # Recommendation
        }
    
    def _summarize_timeline(self, timeline: List[Dict]) -> Dict[str, Any]:
        """
        Create summary of timeline
        
        Args:
            timeline: List of timeline events
            
        Returns:
            Dictionary with timeline summary
        """
        if not timeline:  # If timeline empty
            return {'event_count': 0, 'time_span': '0 seconds', 'event_types': []}  # Return empty summary
        
        # Calculate time span
        try:  # Try to calculate time span
            first_str = timeline[0]['timestamp'].replace('Z', '+00:00')  # Convert first timestamp
            last_str = timeline[-1]['timestamp'].replace('Z', '+00:00')  # Convert last timestamp
            
            # Try multiple timestamp formats
            for fmt in ['%Y-%m-%dT%H:%M:%S.%f%z', '%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%d %H:%M:%S']:  # Try formats
                try:  # Try to parse
                    first = datetime.strptime(first_str, fmt)  # Parse first
                    last = datetime.strptime(last_str, fmt)  # Parse last
                    time_span = last - first  # Calculate time difference
                    time_span_str = str(time_span)  # Convert to string
                    break  # Break after success
                except ValueError:  # If format doesn't match
                    continue  # Try next format
            else:  # If no format matched
                time_span_str = 'unknown'  # Set to unknown
        except Exception:  # Catch any exception
            time_span_str = 'unknown'  # Set to unknown
        
        # Count event types
        event_types = {}  # Initialize event type counter
        for event in timeline:  # Loop through events
            event_type = event.get('type', 'unknown')  # Get event type
            event_types[event_type] = event_types.get(event_type, 0) + 1  # Increment counter
        
        return {  # Return summary
            'event_count': len(timeline),  # Total events
            'time_span': time_span_str,  # Time span string
            'event_types': [{'type': k, 'count': v} for k, v in event_types.items()],  # Type counts
            'first_event': timeline[0]['timestamp'] if timeline else None,  # First event timestamp
            'last_event': timeline[-1]['timestamp'] if timeline else None  # Last event timestamp
        }
    
    def _generate_evidence_chain(self, evidence_list: List[Dict]) -> List[Dict]:
        """
        Generate evidence chain showing relationships
        
        Args:
            evidence_list: List of processed evidence
            
        Returns:
            List of evidence chain entries
        """
        chain = []  # Initialize evidence chain
        
        for evidence in evidence_list:  # Loop through evidence
            # Truncate hash values for readability
            truncated_hashes = {}  # Initialize truncated hashes
            for algo, hash_value in evidence['hashes'].items():  # Loop through hashes
                if hash_value and len(hash_value) > 16:  # If hash long enough to truncate
                    truncated_hashes[algo] = hash_value[:16] + '...'  # Truncate to 16 chars
                else:  # If hash short or empty
                    truncated_hashes[algo] = hash_value  # Keep as-is
            
            chain.append({  # Add to chain
                'id': evidence['id'],  # Evidence ID
                'type': evidence['type'],  # Evidence type
                'timestamp': evidence['timestamp'],  # Evidence timestamp
                'source': evidence['source'],  # Evidence source
                'hashes': truncated_hashes,  # Truncated hashes
                'size': evidence['original_size']  # Evidence size
            })
        
        return chain  # Return evidence chain
    
    def _generate_recommendations(self, findings: List[Dict]) -> List[str]:
        """
        Generate recommendations based on findings
        
        Args:
            findings: List of forensic findings
            
        Returns:
            List of recommendation strings
        """
        recommendations = []  # Initialize recommendations list
        
        # Add recommendations from findings
        for finding in findings:  # Loop through findings
            if 'recommendation' in finding:  # If finding has recommendation
                recommendations.append(finding['recommendation'])  # Add recommendation
        
        # Add general forensic recommendations if there are findings
        if findings:  # If any findings
            recommendations.extend([  # Add general recommendations
                'Preserve all original evidence in secure storage',
                'Maintain chain of custody documentation',
                'Create forensic copies for analysis',
                'Document all analysis steps and findings'
            ])
        
        # Remove duplicates
        unique_recommendations = []  # Initialize unique list
        seen = set()  # Initialize set for tracking duplicates
        for rec in recommendations:  # Loop through recommendations
            if rec not in seen:  # If not seen before
                seen.add(rec)  # Add to seen set
                unique_recommendations.append(rec)  # Add to unique list
        
        # Return top 5 recommendations
        return unique_recommendations[:5]  # Return first 5 unique recommendations
    
    def _generate_forensic_report(self, evidence_list: List[Dict], findings: List[Dict], 
                                timeline: List[Dict]) -> Dict[str, Any]:
        """
        Generate comprehensive forensic report
        
        Args:
            evidence_list: List of processed evidence
            findings: List of forensic findings
            timeline: List of timeline events
            
        Returns:
            Dictionary with complete forensic report
        """
        report = {  # Initialize report dictionary
            'report_id': f"forensic_report_{int(time.time())}",  # Unique report ID with timestamp
            'generated_at': datetime.now().isoformat(),  # Report generation time
            'generated_by': self.agent_id,  # Agent ID
            'executive_summary': self._generate_executive_summary(findings, timeline),  # Executive summary
            'evidence_summary': {  # Evidence summary section
                'total_evidence': len(evidence_list),  # Evidence count
                'evidence_types': list(set(ev['type'] for ev in evidence_list)),  # Unique evidence types
                'total_size_bytes': sum(ev['original_size'] for ev in evidence_list)  # Total size
            },
            'findings_summary': {  # Findings summary section
                'total_findings': len(findings),  # Findings count
                'by_severity': {  # Findings by severity
                    'critical': len([f for f in findings if f.get('severity') == 'critical']),  # Critical count
                    'high': len([f for f in findings if f.get('severity') == 'high']),  # High count
                    'medium': len([f for f in findings if f.get('severity') == 'medium']),  # Medium count
                    'low': len([f for f in findings if f.get('severity') == 'low'])  # Low count
                }
            },
            'timeline_summary': self._summarize_timeline(timeline),  # Timeline summary
            'detailed_findings': findings[:10],  # Top 10 findings
            'recommendations': self._generate_recommendations(findings),  # Recommendations
            'chain_of_custody': self._get_chain_of_custody_summary(evidence_list)  # Chain of custody
        }
        
        return report  # Return complete report
    
    def _generate_executive_summary(self, findings: List[Dict], timeline: List[Dict]) -> str:
        """
        Generate executive summary for forensic report
        
        Args:
            findings: List of forensic findings
            timeline: List of timeline events
            
        Returns:
            Executive summary string
        """
        if not findings:  # If no findings
            return "No significant findings detected in the analyzed evidence."  # Return no findings message
        
        critical_findings = [f for f in findings if f.get('severity') == 'critical']  # Get critical findings
        high_findings = [f for f in findings if f.get('severity') == 'high']  # Get high findings
        
        summary = f"Forensic analysis of {len(timeline)} timeline events revealed "  # Start summary
        
        if critical_findings:  # If critical findings
            summary += f"{len(critical_findings)} critical finding(s) indicating potential security incidents. "  # Add critical
        elif high_findings:  # If high findings
            summary += f"{len(high_findings)} high-severity finding(s) requiring investigation. "  # Add high
        else:  # If only medium/low findings
            summary += f"{len(findings)} finding(s) of varying severity. "  # Add general count
        
        summary += "Detailed findings and recommendations are provided in this report."  # Closing sentence
        
        return summary  # Return summary string
    
    def _get_chain_of_custody_summary(self, evidence_list: List[Dict]) -> Dict[str, Any]:
        """
        Get chain of custody summary for evidence
        
        Args:
            evidence_list: List of evidence dictionaries
            
        Returns:
            Dictionary with chain of custody summary
        """
        custody_summary = {}  # Initialize custody summary
        
        for evidence in evidence_list:  # Loop through evidence
            evidence_id = evidence['id']  # Get evidence ID
            if evidence_id in self.chain_of_custody and self.chain_of_custody[evidence_id]:  # If custody entries exist
                custody_entries = self.chain_of_custody[evidence_id]  # Get custody entries
                custody_summary[evidence_id] = {  # Add to summary
                    'total_entries': len(custody_entries),  # Number of entries
                    'first_entry': custody_entries[0]['timestamp'] if custody_entries else None,  # First entry time
                    'last_entry': custody_entries[-1]['timestamp'] if custody_entries else None,  # Last entry time
                    'current_custodian': custody_entries[-1]['agent'] if custody_entries else None  # Current custodian
                }
        
        return custody_summary  # Return custody summary
    
    def _calculate_incident_confidence(self, findings: List[Dict]) -> float:
        """
        Calculate confidence that an incident occurred
        
        Args:
            findings: List of forensic findings
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        if not findings:  # If no findings
            return 0.1  # Return low confidence
        
        # Weight findings by severity
        severity_weights = {'critical': 1.0, 'high': 0.8, 'medium': 0.5, 'low': 0.2}  # Severity weights
        
        total_weight = 0.0  # Initialize total weight
        for finding in findings:  # Loop through findings
            severity = finding.get('severity', 'low')  # Get severity, default low
            confidence = finding.get('confidence', 0.5)  # Get confidence, default 0.5
            weight = severity_weights.get(severity, 0.2)  # Get weight for severity
            total_weight += weight * confidence  # Add weighted confidence
        
        # Normalize to 0.0-1.0 range
        max_possible = len(findings) * 1.0  # Maximum possible weight (all critical with 1.0 confidence)
        return min(1.0, total_weight / max_possible if max_possible > 0 else 0)  # Return normalized confidence
    
    def _calculate_evidence_weight(self, evidence_list: List[Dict]) -> float:
        """
        Calculate weight/strength of evidence
        
        Args:
            evidence_list: List of processed evidence
            
        Returns:
            Evidence weight score between 0.0 and 1.0
        """
        if not evidence_list:  # If no evidence
            return 0.1  # Return low weight
        
        # Consider multiple factors for evidence weight
        total_score = 0.0  # Initialize total score
        
        for evidence in evidence_list:  # Loop through evidence
            # Factor 1: Evidence type relevance
            type_score = 0.5  # Default type score
            if 'log' in evidence['type']:  # If log evidence
                type_score = 0.7  # Higher score for logs
            elif 'memory' in evidence['type'] or 'disk' in evidence['type']:  # If memory/disk evidence
                type_score = 0.9  # Highest score for memory/disk
            
            # Factor 2: Parsing success
            parse_score = 1.0 if evidence['parsed_content']['parsed_successfully'] else 0.3  # Score based on parsing
            
            # Factor 3: Size (larger evidence may be more complete)
            size_score = min(1.0, evidence['original_size'] / 1000000)  # Normalize by 1MB (capped at 1.0)
            
            # Combined score for this evidence
            evidence_score = (type_score * 0.4 + parse_score * 0.4 + size_score * 0.2)  # Weighted average
            total_score += evidence_score  # Add to total
        
        # Average score across all evidence
        return total_score / len(evidence_list)  # Return average score
    
    def _calculate_timeline_confidence(self, timeline: List[Dict]) -> float:
        """
        Calculate confidence in timeline reconstruction
        
        Args:
            timeline: List of timeline events
            
        Returns:
            Timeline confidence score between 0.0 and 1.0
        """
        if not timeline:  # If no timeline
            return 0.1  # Return low confidence
        
        # More events = higher confidence
        event_factor = min(1.0, len(timeline) / 50.0)  # Normalize by 50 events (capped at 1.0)
        
        # Event type diversity
        event_types = set(e.get('type', 'unknown') for e in timeline)  # Get unique event types
        diversity_factor = min(1.0, len(event_types) / 10.0)  # Normalize by 10 types (capped at 1.0)
        
        # Time span (longer span with events = more complete)
        try:  # Try to calculate time span
            first_str = timeline[0]['timestamp'].replace('Z', '+00:00')  # Convert first timestamp
            last_str = timeline[-1]['timestamp'].replace('Z', '+00:00')  # Convert last timestamp
            
            # Try multiple timestamp formats
            for fmt in ['%Y-%m-%dT%H:%M:%S.%f%z', '%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%d %H:%M:%S']:  # Try formats
                try:  # Try to parse
                    first = datetime.strptime(first_str, fmt)  # Parse first
                    last = datetime.strptime(last_str, fmt)  # Parse last
                    time_span = (last - first).total_seconds()  # Calculate time span in seconds
                    span_factor = min(1.0, time_span / 3600)  # Normalize by 1 hour (capped at 1.0)
                    break  # Break after success
                except ValueError:  # If format doesn't match
                    continue  # Try next format
            else:  # If no format matched
                span_factor = 0.3  # Default factor
        except Exception:  # Catch any exception
            span_factor = 0.3  # Default factor
        
        # Combined confidence using weighted factors
        return (event_factor * 0.4 + diversity_factor * 0.3 + span_factor * 0.3)  # Weighted average
    
    def _update_metrics(self, evidence_count: int, artifact_count: int, processing_time: float):
        """
        Update agent metrics
        
        Args:
            evidence_count: Number of evidence pieces processed
            artifact_count: Number of artifacts found
            processing_time: Time taken for analysis in seconds
        """
        self.metrics['evidence_analyzed'] += evidence_count  # Update evidence analyzed count
        self.metrics['artifacts_found'] += artifact_count  # Update artifacts found count
        
        # Update average analysis time using exponential moving average
        alpha = 0.1  # Smoothing factor (10% weight to new value)
        old_avg = self.metrics['avg_analysis_time']  # Get old average
        self.metrics['avg_analysis_time'] = (  # Calculate new average
            alpha * processing_time +  # New value weighted by alpha
            (1 - alpha) * old_avg  # Old average weighted by (1-alpha)
        )
    
    def _error_response(self, error_message: str) -> Dict[str, Any]:
        """
        Generate error response
        
        Args:
            error_message: Error description
            
        Returns:
            Dictionary with error response structure
        """
        return {  # Return error response
            'agent_id': self.agent_id,  # Agent ID
            'agent_name': self.name,  # Agent name
            'error': error_message,  # Error message
            'findings': [],  # Empty findings
            'timeline': [],  # Empty timeline
            'recommendations': [],  # Empty recommendations
            'reasoning_state': self.get_reasoning_state(),  # Agent reasoning state
            'decision': {  # Decision metrics
                'incident_confidence': 0.5,  # Medium confidence
                'evidence_weight': 0.1,  # Low evidence weight
                'timeline_confidence': 0.1,  # Low timeline confidence
                'evidence': [{'type': 'AGENT_ERROR', 'description': error_message}]  # Error as evidence
            }
        }
    
    def get_evidence_report(self, evidence_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed report for specific evidence
        
        Args:
            evidence_id: ID of the evidence to retrieve
            
        Returns:
            Detailed evidence report or None if not found
        """
        if evidence_id not in self.evidence_store:  # If evidence not found
            return None  # Return None
        
        evidence = self.evidence_store[evidence_id]  # Get evidence from store
        
        report = {  # Build evidence report
            'evidence_id': evidence_id,  # Evidence ID
            'type': evidence['type'],  # Evidence type
            'source': evidence['source'],  # Evidence source
            'timestamp': evidence['timestamp'],  # Evidence timestamp
            'collection_timestamp': evidence['collection_timestamp'],  # Collection time
            'collector': evidence['collector'],  # Collector ID
            'hashes': evidence['hashes'],  # Cryptographic hashes
            'metadata': evidence['metadata'],  # Metadata
            'size_bytes': evidence['original_size'],  # Evidence size
            'parsing_status': {  # Parsing status
                'successful': evidence['parsed_content']['parsed_successfully'],  # Success flag
                'error': evidence['parsed_content'].get('parse_error')  # Error message if any
            },
            'parsed_content_preview': str(evidence['parsed_content']['parsed_data'])[:500],  # Parsed content preview
            'chain_of_custody': self.chain_of_custody.get(evidence_id, []),  # Chain of custody entries
            'artifacts_found': self._get_artifacts_for_evidence(evidence_id),  # Artifacts from this evidence
            'related_evidence': self._get_related_evidence(evidence_id)  # Related evidence
        }
        
        return report  # Return evidence report
    
    def _get_artifacts_for_evidence(self, evidence_id: str) -> List[Dict]:
        """
        Get artifacts found in specific evidence
        
        Args:
            evidence_id: ID of the evidence
            
        Returns:
            List of artifacts found in the evidence
        """
        # In production, this would query an artifact database
        # For demonstration, return empty list
        return []  # Return empty list
    
    def _get_related_evidence(self, evidence_id: str) -> List[Dict]:
        """
        Get evidence related to specific evidence
        
        Args:
            evidence_id: ID of the target evidence
            
        Returns:
            List of related evidence entries
        """
        related = []  # Initialize related evidence list
        
        # Look for evidence with same source or similar timestamp
        target_evidence = self.evidence_store.get(evidence_id)  # Get target evidence
        if not target_evidence:  # If target not found
            return related  # Return empty list
        
        for ev_id, evidence in self.evidence_store.items():  # Loop through all evidence
            if ev_id == evidence_id:  # Skip target evidence
                continue  # Skip to next
            
            # Check source similarity
            if evidence['source'] == target_evidence['source']:  # If same source
                related.append({  # Add as related
                    'evidence_id': ev_id,  # Related evidence ID
                    'type': evidence['type'],  # Related evidence type
                    'timestamp': evidence['timestamp'],  # Related evidence timestamp
                    'relation': 'same_source'  # Relation type
                })
        
        return related  # Return related evidence
    
    def get_agent_status(self) -> Dict[str, Any]:
        """
        Get comprehensive agent status
        
        Returns:
            Dictionary with agent status information
        """
        # Get all evidence timestamps
        evidence_timestamps = []  # Initialize timestamp list
        for ev in self.evidence_store.values():  # Loop through evidence
            if 'timestamp' in ev:  # If evidence has timestamp
                evidence_timestamps.append(ev['timestamp'])  # Add to list
        
        return {  # Return agent status
            'agent_id': self.agent_id,  # Agent ID
            'name': self.name,  # Agent name
            'status': 'ACTIVE',  # Agent status
            'confidence': self.confidence,  # Agent confidence
            'metrics': self.metrics,  # Performance metrics
            'evidence_store': {  # Evidence store summary
                'total_evidence': len(self.evidence_store),  # Evidence count
                'evidence_types': list(set(ev['type'] for ev in self.evidence_store.values())),  # Unique types
                'oldest_evidence': min(evidence_timestamps) if evidence_timestamps else None,  # Oldest timestamp
                'newest_evidence': max(evidence_timestamps) if evidence_timestamps else None  # Newest timestamp
            },
            'capabilities': {  # Agent capabilities
                'supported_evidence_types': self.supported_evidence,  # Supported evidence types
                'log_parsers': list(self.log_parsers.keys()),  # Available log parsers
                'file_parsers': list(self.file_parsers.keys()),  # Available file parsers
                'artifact_parsers': list(self.artifact_parsers.keys()),  # Available artifact parsers
                'hash_algorithms': self.hash_algorithms  # Supported hash algorithms
            },
            'config': {  # Agent configuration
                'thresholds': self.thresholds,  # Analysis thresholds
                'max_evidence_age_days': self.thresholds['max_evidence_age_days'],  # Max evidence age
                'min_evidence_count': self.thresholds['min_evidence_count']  # Min evidence count
            }
        }