# src/agents/forensics_agent.py
"""
Digital Forensics Agent
Purpose: Collects, preserves, and analyzes digital evidence from security incidents
Techniques: Log analysis, memory forensics, disk forensics, network forensics, timeline analysis
"""

import hashlib
import base64
import json
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
import time
import re
from collections import defaultdict
import csv
import io

from .base_agent import SecurityAgent, AgentCapability

class DigitalForensicsAgent(SecurityAgent):
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
    
    def __init__(self, agent_id: str = "forensics_agent_001"):
        super().__init__(
            agent_id=agent_id,
            name="Digital Forensics Agent",
            state_dim=768
        )
        
        # Add forensics capability
        self.capabilities.append(AgentCapability.FORENSICS)
        
        # Evidence storage
        self.evidence_store = {}
        self.evidence_counter = 0
        
        # Chain of custody tracking
        self.chain_of_custody = {}
        
        # Forensic tools and parsers
        self.log_parsers = self._initialize_log_parsers()
        self.file_parsers = self._initialize_file_parsers()
        self.artifact_parsers = self._initialize_artifact_parsers()
        
        # Timeline reconstruction
        self.timelines = {}
        
        # Detection thresholds
        self.thresholds = {
            'evidence_confidence': 0.7,
            'timeline_accuracy': 0.8,
            'artifact_relevance': 0.6,
            'min_evidence_count': 3,
            'max_evidence_age_days': 30
        }
        
        # Supported evidence types
        self.supported_evidence = [
            'log_file', 'memory_dump', 'disk_image', 'network_pcap',
            'registry_hive', 'plist_file', 'json_file', 'xml_file',
            'database_file', 'browser_history', 'email_archive',
            'application_log', 'system_log', 'security_log'
        ]
        
        # Metrics
        self.metrics = {
            'evidence_collected': 0,
            'evidence_analyzed': 0,
            'timelines_created': 0,
            'artifacts_found': 0,
            'incidents_reconstructed': 0,
            'avg_analysis_time': 0.0
        }
        
        # Forensic hashing algorithms
        self.hash_algorithms = ['md5', 'sha1', 'sha256', 'sha512']
    
    def _initialize_log_parsers(self) -> Dict[str, Any]:
        """
        Initialize log file parsers for different log formats
        """
        return {
            'syslog': {
                'pattern': r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\[?(\d+)?\]?:\s+(.*)$',
                'fields': ['timestamp', 'hostname', 'process', 'pid', 'message']
            },
            'apache': {
                'pattern': r'^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"$',
                'fields': ['ip', 'ident', 'user', 'timestamp', 'request', 'status', 'size', 'referer', 'user_agent']
            },
            'nginx': {
                'pattern': r'^(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"\s+"([^"]*)"$',
                'fields': ['ip', 'remote_user', 'timestamp', 'request', 'status', 'body_bytes_sent', 'http_referer', 'http_user_agent', 'http_x_forwarded_for']
            },
            'windows_event': {
                'pattern': r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$',
                'fields': ['timestamp', 'event_id', 'level', 'task', 'opcode', 'keywords', 'source', 'message']
            }
        }
    
    def _initialize_file_parsers(self) -> Dict[str, Any]:
        """
        Initialize file format parsers
        """
        return {
            'json': lambda x: json.loads(x),
            'xml': lambda x: self._parse_xml(x),
            'csv': lambda x: list(csv.DictReader(io.StringIO(x))),
            'yaml': lambda x: self._parse_yaml(x),
            'ini': lambda x: self._parse_ini(x)
        }
    
    def _initialize_artifact_parsers(self) -> Dict[str, Any]:
        """
        Initialize artifact parsers for common forensic artifacts
        """
        return {
            'browser_history': self._parse_browser_history,
            'registry': self._parse_registry,
            'plist': self._parse_plist,
            'prefetch': self._parse_prefetch,
            'shellbags': self._parse_shellbags,
            'jumplists': self._parse_jumplists,
            'recycle_bin': self._parse_recycle_bin
        }
    
    def _parse_xml(self, xml_content: str) -> Dict:
        """
        Parse XML content (simplified)
        """
        # In production, use xml.etree.ElementTree or lxml
        return {'content': xml_content[:1000], 'note': 'XML parsing placeholder'}
    
    def _parse_yaml(self, yaml_content: str) -> Dict:
        """
        Parse YAML content (simplified)
        """
        # In production, use PyYAML
        return {'content': yaml_content[:1000], 'note': 'YAML parsing placeholder'}
    
    def _parse_ini(self, ini_content: str) -> Dict:
        """
        Parse INI content
        """
        result = {}
        current_section = None
        
        for line in ini_content.split('\n'):
            line = line.strip()
            
            if line.startswith('[') and line.endswith(']'):
                current_section = line[1:-1]
                result[current_section] = {}
            elif '=' in line and current_section:
                key, value = line.split('=', 1)
                result[current_section][key.strip()] = value.strip()
        
        return result
    
    def _parse_browser_history(self, content: bytes) -> List[Dict]:
        """
        Parse browser history artifacts
        """
        # In production, parse actual browser history databases
        # For now, return mock data
        return [
            {
                'url': 'https://example.com',
                'timestamp': datetime.now().isoformat(),
                'visit_count': 1,
                'title': 'Example Domain'
            }
        ]
    
    def _parse_registry(self, content: bytes) -> Dict[str, Any]:
        """
        Parse Windows Registry artifacts
        """
        # In production, use python-registry or similar
        return {
            'hive_type': 'unknown',
            'keys_found': 0,
            'values_found': 0,
            'note': 'Registry parsing placeholder'
        }
    
    def _parse_plist(self, content: bytes) -> Dict:
        """
        Parse macOS plist files
        """
        # In production, use plistlib
        return {'content': 'Plist parsing placeholder'}
    
    def _parse_prefetch(self, content: bytes) -> List[Dict]:
        """
        Parse Windows Prefetch files
        """
        return [
            {
                'filename': 'unknown.pf',
                'last_run': datetime.now().isoformat(),
                'run_count': 1
            }
        ]
    
    def _parse_shellbags(self, content: bytes) -> List[Dict]:
        """
        Parse Windows Shellbags artifacts
        """
        return [
            {
                'path': 'C:\\Windows\\System32',
                'accessed': datetime.now().isoformat(),
                'type': 'directory'
            }
        ]
    
    def _parse_jumplists(self, content: bytes) -> List[Dict]:
        """
        Parse Windows Jump Lists
        """
        return [
            {
                'application': 'notepad.exe',
                'target': 'C:\\Windows\\notepad.exe',
                'accessed': datetime.now().isoformat()
            }
        ]
    
    def _parse_recycle_bin(self, content: bytes) -> List[Dict]:
        """
        Parse Windows Recycle Bin artifacts
        """
        return [
            {
                'original_path': 'C:\\Users\\test\\document.txt',
                'deleted_time': datetime.now().isoformat(),
                'size': 1024
            }
        ]
    
    def analyze(self, security_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze digital evidence for forensic investigation
        
        Process flow:
        1. Collect and preserve evidence
        2. Extract and normalize data
        3. Analyze artifacts
        4. Correlate evidence
        5. Reconstruct timeline
        6. Generate findings
        """
        start_time = time.time()
        
        try:
            # Extract evidence from security data
            evidence_list = self._extract_evidence(security_data)
            
            if not evidence_list:
                return {
                    'agent_id': self.agent_id,
                    'agent_name': self.name,
                    'findings': [],
                    'timeline': [],
                    'recommendations': []
                }
            
            # Process each piece of evidence
            processed_evidence = []
            artifacts_found = []
            
            for evidence in evidence_list:
                # Process evidence
                processed = self._process_evidence(evidence)
                processed_evidence.append(processed)
                
                # Extract artifacts
                artifacts = self._extract_artifacts(processed)
                artifacts_found.extend(artifacts)
            
            # Correlate evidence
            correlations = self._correlate_evidence(processed_evidence)
            
            # Reconstruct timeline
            timeline = self._reconstruct_timeline(processed_evidence, artifacts_found)
            
            # Generate forensic findings
            findings = self._generate_findings(processed_evidence, artifacts_found, correlations, timeline)
            
            # Calculate processing time
            processing_time = time.time() - start_time
            self._update_metrics(len(evidence_list), len(artifacts_found), processing_time)
            
            # Generate response
            response = {
                'agent_id': self.agent_id,
                'agent_name': self.name,
                'analysis_timestamp': datetime.now().isoformat(),
                'processing_time': processing_time,
                'evidence_processed': len(processed_evidence),
                'artifacts_found': len(artifacts_found),
                'timeline_events': len(timeline),
                'findings': findings,
                'timeline_summary': self._summarize_timeline(timeline),
                'evidence_chain': self._generate_evidence_chain(processed_evidence),
                'recommendations': self._generate_recommendations(findings),
                'forensic_report': self._generate_forensic_report(
                    processed_evidence, findings, timeline
                ),
                'reasoning_state': self.get_reasoning_state(),
                'decision': {
                    'incident_confidence': self._calculate_incident_confidence(findings),
                    'evidence_weight': self._calculate_evidence_weight(processed_evidence),
                    'timeline_confidence': self._calculate_timeline_confidence(timeline),
                    'evidence': findings[:3] if findings else []
                }
            }
            
            # Update agent confidence
            if findings:
                certainty = min(0.9, len(findings) * 0.1)
                self.update_confidence({'certainty': certainty})
            
            return response
            
        except Exception as e:
            print(f"❌ {self.name}: Forensic analysis error: {e}")
            return self._error_response(str(e))
    
    def _extract_evidence(self, security_data: Dict) -> List[Dict]:
        """
        Extract evidence from security data
        
        Evidence can be:
        - Log files
        - Memory dumps
        - Network captures
        - Disk images
        - Application data
        """
        evidence_list = []
        
        # Check for direct evidence
        if 'evidence' in security_data:
            if isinstance(security_data['evidence'], list):
                evidence_list.extend(security_data['evidence'])
            else:
                evidence_list.append(security_data['evidence'])
        
        # Extract from other sources
        for key, value in security_data.items():
            if key.endswith('_log') or key.endswith('_dump') or key.endswith('_capture'):
                evidence_list.append({
                    'type': key.replace('_', ' '),
                    'content': value,
                    'source': key,
                    'timestamp': security_data.get('timestamp', datetime.now().isoformat())
                })
        
        # Filter valid evidence
        valid_evidence = []
        for evidence in evidence_list:
            if self._is_valid_evidence(evidence):
                valid_evidence.append(evidence)
        
        return valid_evidence
    
    def _is_valid_evidence(self, evidence: Dict) -> bool:
        """
        Validate evidence has required information
        """
        # Check for content
        if 'content' not in evidence:
            return False
        
        # Check evidence type
        evidence_type = evidence.get('type', '').lower()
        supported = any(supported_type in evidence_type for supported_type in self.supported_evidence)
        
        if not supported and evidence_type not in ['unknown', '']:
            # Try to determine type from content
            evidence['type'] = self._determine_evidence_type(evidence['content'])
        
        return True
    
    def _determine_evidence_type(self, content: Any) -> str:
        """
        Determine evidence type from content
        """
        if isinstance(content, str):
            content_str = content.lower()
            
            # Check for log patterns
            if any(parser_name in content_str[:1000] for parser_name in self.log_parsers.keys()):
                return 'log_file'
            
            # Check for JSON
            if content_str.strip().startswith('{') or content_str.strip().startswith('['):
                return 'json_file'
            
            # Check for XML
            if content_str.strip().startswith('<?xml') or content_str.strip().startswith('<'):
                return 'xml_file'
        
        elif isinstance(content, bytes):
            # Check for binary formats
            if content[:4] == b'\x7fELF':
                return 'executable'
            elif content[:2] == b'MZ':
                return 'windows_executable'
            elif content[:8] == b'\x89PNG\r\n\x1a\n':
                return 'image'
        
        return 'unknown'
    
    def _process_evidence(self, evidence: Dict) -> Dict:
        """
        Process single piece of evidence
        
        Steps:
        1. Generate hash for integrity
        2. Extract metadata
        3. Parse content
        4. Normalize data
        """
        # Generate evidence ID
        evidence_id = f"evd_{self.evidence_counter:06d}"
        self.evidence_counter += 1
        
        # Get content
        content = evidence['content']
        
        # Generate hashes for integrity
        hashes = self._generate_hashes(content)
        
        # Extract metadata
        metadata = self._extract_metadata(evidence, content)
        
        # Parse content based on type
        parsed_content = self._parse_content(content, evidence.get('type', 'unknown'))
        
        # Store in evidence store
        processed_evidence = {
            'id': evidence_id,
            'type': evidence.get('type', 'unknown'),
            'source': evidence.get('source', 'unknown'),
            'timestamp': evidence.get('timestamp', datetime.now().isoformat()),
            'hashes': hashes,
            'metadata': metadata,
            'parsed_content': parsed_content,
            'original_size': len(str(content)) if isinstance(content, (str, bytes)) else 0,
            'collection_timestamp': datetime.now().isoformat(),
            'collector': self.agent_id
        }
        
        # Add to evidence store
        self.evidence_store[evidence_id] = processed_evidence
        
        # Update chain of custody
        self._update_chain_of_custody(evidence_id, 'collected')
        
        # Update metrics
        self.metrics['evidence_collected'] += 1
        
        return processed_evidence
    
    def _generate_hashes(self, content: Any) -> Dict[str, str]:
        """
        Generate cryptographic hashes for evidence integrity
        """
        hashes = {}
        
        # Convert to bytes for hashing
        if isinstance(content, str):
            content_bytes = content.encode('utf-8', errors='ignore')
        elif isinstance(content, bytes):
            content_bytes = content
        else:
            content_bytes = str(content).encode('utf-8', errors='ignore')
        
        # Generate hashes
        for algo in self.hash_algorithms:
            hash_func = hashlib.new(algo)
            hash_func.update(content_bytes)
            hashes[algo] = hash_func.hexdigest()
        
        return hashes
    
    def _extract_metadata(self, evidence: Dict, content: Any) -> Dict[str, Any]:
        """
        Extract metadata from evidence
        """
        metadata = {
            'evidence_type': evidence.get('type', 'unknown'),
            'source': evidence.get('source', 'unknown'),
            'timestamp': evidence.get('timestamp', datetime.now().isoformat()),
            'content_type': type(content).__name__
        }
        
        # Extract additional metadata based on type
        evidence_type = evidence.get('type', '').lower()
        
        if 'log' in evidence_type:
            metadata['log_type'] = self._determine_log_type(content)
            metadata['line_count'] = len(str(content).split('\n')) if isinstance(content, str) else 1
        
        elif 'memory' in evidence_type:
            metadata['memory_size'] = len(content) if isinstance(content, bytes) else 0
        
        elif 'network' in evidence_type or 'pcap' in evidence_type:
            metadata['packet_count'] = self._estimate_packet_count(content)
        
        return metadata
    
    def _determine_log_type(self, content: Any) -> str:
        """
        Determine log file type from content
        """
        if not isinstance(content, str):
            return 'unknown'
        
        sample = content[:1000].lower()
        
        for log_type, parser in self.log_parsers.items():
            if re.search(parser['pattern'], sample, re.MULTILINE):
                return log_type
        
        # Check for common patterns
        if 'apache' in sample or 'httpd' in sample:
            return 'apache'
        elif 'nginx' in sample:
            return 'nginx'
        elif 'event' in sample and 'windows' in sample:
            return 'windows_event'
        
        return 'generic'
    
    def _estimate_packet_count(self, content: Any) -> int:
        """
        Estimate packet count in network capture
        """
        if isinstance(content, bytes):
            # Very rough estimate: assume average packet size of 1500 bytes
            return max(1, len(content) // 1500)
        return 0
    
    def _parse_content(self, content: Any, evidence_type: str) -> Dict[str, Any]:
        """
        Parse evidence content based on type
        """
        result = {
            'raw_preview': str(content)[:500] if content else '',
            'parsed_successfully': False,
            'parsed_data': None,
            'parse_error': None
        }
        
        try:
            evidence_type_lower = evidence_type.lower()
            
            # Parse log files
            if 'log' in evidence_type_lower:
                parsed = self._parse_log_content(content, evidence_type_lower)
                result['parsed_data'] = parsed
                result['parsed_successfully'] = True
            
            # Parse structured files
            elif any(fmt in evidence_type_lower for fmt in ['json', 'xml', 'csv', 'yaml', 'ini']):
                for fmt, parser in self.file_parsers.items():
                    if fmt in evidence_type_lower:
                        parsed = parser(content)
                        result['parsed_data'] = parsed
                        result['parsed_successfully'] = True
                        break
            
            # Parse forensic artifacts
            elif any(artifact in evidence_type_lower for artifact in self.artifact_parsers.keys()):
                for artifact, parser in self.artifact_parsers.items():
                    if artifact in evidence_type_lower:
                        parsed = parser(content if isinstance(content, bytes) else content.encode())
                        result['parsed_data'] = parsed
                        result['parsed_successfully'] = True
                        break
            
            # For unknown types, just store preview
            else:
                result['parsed_data'] = {'preview': str(content)[:1000]}
                result['parsed_successfully'] = True
        
        except Exception as e:
            result['parse_error'] = str(e)
        
        return result
    
    def _parse_log_content(self, content: Any, log_type: str) -> List[Dict]:
        """
        Parse log file content
        """
        if not isinstance(content, str):
            return []
        
        lines = content.split('\n')
        parsed_lines = []
        
        # Determine parser
        parser_config = None
        for parser_name, config in self.log_parsers.items():
            if parser_name in log_type:
                parser_config = config
                break
        
        if not parser_config:
            # Try to auto-detect
            for parser_name, config in self.log_parsers.items():
                if re.search(config['pattern'], lines[0] if lines else ''):
                    parser_config = config
                    break
        
        if not parser_config:
            # Generic parsing
            for line in lines[:100]:  # Limit to 100 lines
                if line.strip():
                    parsed_lines.append({
                        'raw': line[:200],
                        'timestamp': self._extract_timestamp(line),
                        'message': line
                    })
            return parsed_lines
        
        # Use specific parser
        pattern = re.compile(parser_config['pattern'])
        fields = parser_config['fields']
        
        for line in lines[:1000]:  # Limit to 1000 lines
            match = pattern.match(line)
            if match:
                parsed_line = {}
                for i, field in enumerate(fields):
                    if i < len(match.groups()):
                        parsed_line[field] = match.group(i+1)
                    else:
                        parsed_line[field] = None
                
                # Extract timestamp if not already parsed
                if 'timestamp' not in parsed_line or not parsed_line['timestamp']:
                    parsed_line['timestamp'] = self._extract_timestamp(line)
                
                parsed_line['raw'] = line[:200]
                parsed_lines.append(parsed_line)
        
        return parsed_lines
    
    def _extract_timestamp(self, text: str) -> Optional[str]:
        """
        Extract timestamp from text using common patterns
        """
        # Common timestamp patterns
        patterns = [
            r'(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)',
            r'(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})',
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',
            r'(\d{2}:\d{2}:\d{2})'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return match.group(1)
        
        return None
    
    def _update_chain_of_custody(self, evidence_id: str, action: str):
        """
        Update chain of custody for evidence
        """
        if evidence_id not in self.chain_of_custody:
            self.chain_of_custody[evidence_id] = []
        
        self.chain_of_custody[evidence_id].append({
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'agent': self.agent_id,
            'note': f'{action.capitalize()} by {self.name}'
        })
    
    def _extract_artifacts(self, evidence: Dict) -> List[Dict]:
        """
        Extract forensic artifacts from evidence
        """
        artifacts = []
        
        # Extract artifacts based on evidence type
        evidence_type = evidence['type'].lower()
        parsed_content = evidence['parsed_content']['parsed_data']
        
        if not parsed_content or not evidence['parsed_content']['parsed_successfully']:
            return artifacts
        
        # Look for suspicious patterns in logs
        if 'log' in evidence_type and isinstance(parsed_content, list):
            for entry in parsed_content[:100]:  # Limit to 100 entries
                artifact = self._extract_artifacts_from_log(entry)
                if artifact:
                    artifact['source_evidence'] = evidence['id']
                    artifacts.append(artifact)
        
        # Look for suspicious files or registry entries
        elif any(artifact_type in evidence_type for artifact_type in self.artifact_parsers.keys()):
            artifact = {
                'type': evidence_type,
                'content': parsed_content,
                'source_evidence': evidence['id'],
                'timestamp': evidence['timestamp'],
                'confidence': 0.7
            }
            artifacts.append(artifact)
        
        # Update metrics
        self.metrics['artifacts_found'] += len(artifacts)
        
        return artifacts
    
    def _extract_artifacts_from_log(self, log_entry: Dict) -> Optional[Dict]:
        """
        Extract forensic artifacts from log entry
        """
        message = str(log_entry.get('message', '')).lower()
        
        # Suspicious patterns to look for
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
        
        for pattern, artifact_type, confidence in suspicious_patterns:
            if re.search(pattern, message):
                return {
                    'type': artifact_type,
                    'source': 'log_analysis',
                    'message': log_entry.get('message', '')[:200],
                    'timestamp': log_entry.get('timestamp', ''),
                    'confidence': confidence,
                    'pattern_matched': pattern
                }
        
        return None
    
    def _correlate_evidence(self, evidence_list: List[Dict]) -> List[Dict]:
        """
        Correlate multiple pieces of evidence
        """
        correlations = []
        
        if len(evidence_list) < 2:
            return correlations
        
        # Look for temporal correlations
        for i in range(len(evidence_list)):
            for j in range(i+1, len(evidence_list)):
                ev1 = evidence_list[i]
                ev2 = evidence_list[j]
                
                # Check time proximity
                time_corr = self._check_temporal_correlation(ev1, ev2)
                if time_corr['correlated']:
                    correlations.append({
                        'evidence_ids': [ev1['id'], ev2['id']],
                        'correlation_type': 'temporal',
                        'confidence': time_corr['confidence'],
                        'time_gap': time_corr['time_gap'],
                        'description': time_corr['description']
                    })
                
                # Check content similarity
                content_corr = self._check_content_correlation(ev1, ev2)
                if content_corr['correlated']:
                    correlations.append({
                        'evidence_ids': [ev1['id'], ev2['id']],
                        'correlation_type': 'content',
                        'confidence': content_corr['confidence'],
                        'similarity_score': content_corr['similarity'],
                        'description': content_corr['description']
                    })
                
                # Check source correlation
                source_corr = self._check_source_correlation(ev1, ev2)
                if source_corr['correlated']:
                    correlations.append({
                        'evidence_ids': [ev1['id'], ev2['id']],
                        'correlation_type': 'source',
                        'confidence': source_corr['confidence'],
                        'common_source': source_corr['common_source'],
                        'description': source_corr['description']
                    })
        
        return correlations
    
    def _check_temporal_correlation(self, ev1: Dict, ev2: Dict) -> Dict[str, Any]:
        """
        Check if two pieces of evidence are temporally correlated
        """
        try:
            t1 = datetime.fromisoformat(ev1['timestamp'].replace('Z', '+00:00'))
            t2 = datetime.fromisoformat(ev2['timestamp'].replace('Z', '+00:00'))
            
            time_gap = abs((t1 - t2).total_seconds())
            
            # Events within 5 minutes are correlated
            if time_gap < 300:
                confidence = 1.0 - (time_gap / 300)
                return {
                    'correlated': True,
                    'confidence': confidence,
                    'time_gap': time_gap,
                    'description': f'Events within {time_gap:.1f} seconds'
                }
        except:
            pass
        
        return {
            'correlated': False,
            'confidence': 0.0,
            'time_gap': None,
            'description': 'Not temporally correlated'
        }
    
    def _check_content_correlation(self, ev1: Dict, ev2: Dict) -> Dict[str, Any]:
        """
        Check if two pieces of evidence have similar content
        """
        # Extract text from evidence
        text1 = str(ev1['parsed_content'].get('parsed_data', '')).lower()
        text2 = str(ev2['parsed_content'].get('parsed_data', '')).lower()
        
        if not text1 or not text2:
            return {
                'correlated': False,
                'confidence': 0.0,
                'similarity': 0.0,
                'description': 'No content to compare'
            }
        
        # Simple similarity check (word overlap)
        words1 = set(re.findall(r'\w+', text1))
        words2 = set(re.findall(r'\w+', text2))
        
        if not words1 or not words2:
            return {
                'correlated': False,
                'confidence': 0.0,
                'similarity': 0.0,
                'description': 'No words to compare'
            }
        
        common_words = words1.intersection(words2)
        similarity = len(common_words) / max(len(words1), len(words2))
        
        if similarity > 0.3:  # 30% word overlap
            return {
                'correlated': True,
                'confidence': min(1.0, similarity * 2),
                'similarity': similarity,
                'description': f'{len(common_words)} common words ({similarity:.1%} similarity)'
            }
        
        return {
            'correlated': False,
            'confidence': 0.0,
            'similarity': similarity,
            'description': 'Low content similarity'
        }
    
    def _check_source_correlation(self, ev1: Dict, ev2: Dict) -> Dict[str, Any]:
        """
        Check if two pieces of evidence come from related sources
        """
        source1 = ev1.get('source', '').lower()
        source2 = ev2.get('source', '').lower()
        
        # Check if sources are the same or related
        if source1 == source2:
            return {
                'correlated': True,
                'confidence': 0.9,
                'common_source': source1,
                'description': f'Same source: {source1}'
            }
        
        # Check for related sources (e.g., same system, same application)
        common_terms = ['system', 'application', 'service', 'server', 'host']
        for term in common_terms:
            if term in source1 and term in source2:
                return {
                    'correlated': True,
                    'confidence': 0.6,
                    'common_source': term,
                    'description': f'Related sources: both contain "{term}"'
                }
        
        return {
            'correlated': False,
            'confidence': 0.0,
            'common_source': None,
            'description': 'Different sources'
        }
    
    def _reconstruct_timeline(self, evidence_list: List[Dict], artifacts: List[Dict]) -> List[Dict]:
        """
        Reconstruct timeline from evidence and artifacts
        """
        timeline_events = []
        
        # Add evidence collection events
        for evidence in evidence_list:
            timeline_events.append({
                'timestamp': evidence['collection_timestamp'],
                'type': 'evidence_collection',
                'source': 'forensic_agent',
                'description': f'Collected evidence: {evidence["id"]} ({evidence["type"]})',
                'evidence_id': evidence['id'],
                'confidence': 1.0
            })
        
        # Add artifact events
        for artifact in artifacts:
            timeline_events.append({
                'timestamp': artifact.get('timestamp', datetime.now().isoformat()),
                'type': artifact['type'],
                'source': artifact.get('source', 'unknown'),
                'description': f'Found artifact: {artifact["type"]}',
                'artifact': artifact,
                'confidence': artifact.get('confidence', 0.5)
            })
        
        # Add evidence events (from parsed content)
        for evidence in evidence_list:
            if evidence['parsed_content']['parsed_successfully']:
                parsed_data = evidence['parsed_content']['parsed_data']
                
                if isinstance(parsed_data, list):
                    for entry in parsed_data[:50]:  # Limit to 50 entries
                        if isinstance(entry, dict) and 'timestamp' in entry:
                            timeline_events.append({
                                'timestamp': entry['timestamp'],
                                'type': 'log_entry',
                                'source': evidence['type'],
                                'description': entry.get('message', 'Log entry')[:100],
                                'evidence_id': evidence['id'],
                                'confidence': 0.7
                            })
        
        # Sort by timestamp
        timeline_events.sort(key=lambda x: x['timestamp'])
        
        # Update metrics
        self.metrics['timelines_created'] += 1
        
        return timeline_events
    
    def _generate_findings(self, evidence_list: List[Dict], artifacts: List[Dict], 
                         correlations: List[Dict], timeline: List[Dict]) -> List[Dict]:
        """
        Generate forensic findings from analysis
        """
        findings = []
        
        # 1. Artifact-based findings
        for artifact in artifacts:
            if artifact.get('confidence', 0) > self.thresholds['artifact_relevance']:
                findings.append({
                    'type': 'artifact_discovery',
                    'severity': self._artifact_severity(artifact['type']),
                    'confidence': artifact['confidence'],
                    'description': f'Found {artifact["type"]} artifact',
                    'artifact': artifact,
                    'recommendation': self._artifact_recommendation(artifact['type'])
                })
        
        # 2. Correlation-based findings
        for correlation in correlations:
            if correlation['confidence'] > self.thresholds['evidence_confidence']:
                findings.append({
                    'type': 'evidence_correlation',
                    'severity': 'medium',
                    'confidence': correlation['confidence'],
                    'description': f'{correlation["correlation_type"]} correlation found',
                    'correlation': correlation,
                    'recommendation': 'Investigate correlated evidence further'
                })
        
        # 3. Timeline-based findings
        if len(timeline) >= self.thresholds['min_evidence_count']:
            timeline_analysis = self._analyze_timeline(timeline)
            if timeline_analysis['suspicious']:
                findings.append({
                    'type': 'timeline_anomaly',
                    'severity': 'high',
                    'confidence': timeline_analysis['confidence'],
                    'description': timeline_analysis['description'],
                    'timeline_summary': timeline_analysis['summary'],
                    'recommendation': 'Conduct detailed timeline analysis'
                })
        
        # 4. Evidence integrity findings
        for evidence in evidence_list:
            integrity_check = self._check_evidence_integrity(evidence)
            if not integrity_check['intact']:
                findings.append({
                    'type': 'evidence_integrity',
                    'severity': 'critical',
                    'confidence': 0.9,
                    'description': integrity_check['issue'],
                    'evidence_id': evidence['id'],
                    'recommendation': 'Preserve original evidence and verify chain of custody'
                })
        
        # Update metrics
        self.metrics['incidents_reconstructed'] += len(findings)
        
        return findings
    
    def _artifact_severity(self, artifact_type: str) -> str:
        """
        Determine severity level for artifact type
        """
        high_severity = ['malware_detection', 'data_theft', 'privilege_escalation', 
                        'unauthorized_access', 'web_attack']
        medium_severity = ['failed_auth', 'brute_force', 'port_scan', 
                          'firewall_block', 'privilege_escalation_attempt']
        
        if artifact_type in high_severity:
            return 'high'
        elif artifact_type in medium_severity:
            return 'medium'
        else:
            return 'low'
    
    def _artifact_recommendation(self, artifact_type: str) -> str:
        """
        Generate recommendation for artifact type
        """
        recommendations = {
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
        
        return recommendations.get(artifact_type, 'Investigate further')
    
    def _analyze_timeline(self, timeline: List[Dict]) -> Dict[str, Any]:
        """
        Analyze timeline for suspicious patterns
        """
        if len(timeline) < 3:
            return {'suspicious': False, 'confidence': 0.0, 'description': 'Insufficient data'}
        
        # Check for rapid sequence of events
        rapid_events = 0
        for i in range(1, len(timeline)):
            try:
                t1 = datetime.fromisoformat(timeline[i-1]['timestamp'].replace('Z', '+00:00'))
                t2 = datetime.fromisoformat(timeline[i]['timestamp'].replace('Z', '+00:00'))
                time_gap = (t2 - t1).total_seconds()
                
                if time_gap < 10:  # Less than 10 seconds between events
                    rapid_events += 1
            except:
                continue
        
        rapid_ratio = rapid_events / max(1, len(timeline) - 1)
        
        if rapid_ratio > 0.3:  # More than 30% rapid events
            return {
                'suspicious': True,
                'confidence': min(1.0, rapid_ratio),
                'description': f'Rapid event sequence detected ({rapid_events} rapid events)',
                'summary': {'rapid_events': rapid_events, 'total_events': len(timeline), 'ratio': rapid_ratio}
            }
        
        # Check for suspicious event types
        suspicious_types = ['malware_detection', 'data_theft', 'privilege_escalation']
        suspicious_count = sum(1 for event in timeline if event.get('type') in suspicious_types)
        
        if suspicious_count > 0:
            suspicious_ratio = suspicious_count / len(timeline)
            return {
                'suspicious': True,
                'confidence': min(1.0, suspicious_ratio * 2),
                'description': f'Suspicious event types detected ({suspicious_count} events)',
                'summary': {'suspicious_events': suspicious_count, 'total_events': len(timeline)}
            }
        
        return {
            'suspicious': False,
            'confidence': 0.1,
            'description': 'No significant anomalies detected',
            'summary': {'total_events': len(timeline)}
        }
    
    def _check_evidence_integrity(self, evidence: Dict) -> Dict[str, Any]:
        """
        Check evidence integrity (simplified)
        """
        # In production, verify hashes and chain of custody
        if 'hashes' not in evidence or not evidence['hashes']:
            return {
                'intact': False,
                'issue': 'No integrity hashes found',
                'recommendation': 'Generate cryptographic hashes for evidence'
            }
        
        return {
            'intact': True,
            'issue': None,
            'recommendation': 'Evidence integrity appears intact'
        }
    
    def _summarize_timeline(self, timeline: List[Dict]) -> Dict[str, Any]:
        """
        Create summary of timeline
        """
        if not timeline:
            return {'event_count': 0, 'time_span': '0 seconds', 'event_types': []}
        
        # Calculate time span
        try:
            first = datetime.fromisoformat(timeline[0]['timestamp'].replace('Z', '+00:00'))
            last = datetime.fromisoformat(timeline[-1]['timestamp'].replace('Z', '+00:00'))
            time_span = last - first
            time_span_str = str(time_span)
        except:
            time_span_str = 'unknown'
        
        # Count event types
        event_types = {}
        for event in timeline:
            event_type = event.get('type', 'unknown')
            event_types[event_type] = event_types.get(event_type, 0) + 1
        
        return {
            'event_count': len(timeline),
            'time_span': time_span_str,
            'event_types': [{'type': k, 'count': v} for k, v in event_types.items()],
            'first_event': timeline[0]['timestamp'] if timeline else None,
            'last_event': timeline[-1]['timestamp'] if timeline else None
        }
    
    def _generate_evidence_chain(self, evidence_list: List[Dict]) -> List[Dict]:
        """
        Generate evidence chain showing relationships
        """
        chain = []
        
        for evidence in evidence_list:
            chain.append({
                'id': evidence['id'],
                'type': evidence['type'],
                'timestamp': evidence['timestamp'],
                'source': evidence['source'],
                'hashes': {k: v[:16] + '...' for k, v in evidence['hashes'].items()},
                'size': evidence['original_size']
            })
        
        return chain
    
    def _generate_recommendations(self, findings: List[Dict]) -> List[str]:
        """
        Generate recommendations based on findings
        """
        recommendations = []
        
        # Add recommendations from findings
        for finding in findings:
            if 'recommendation' in finding:
                recommendations.append(finding['recommendation'])
        
        # Add general forensic recommendations
        if findings:
            recommendations.extend([
                'Preserve all original evidence in secure storage',
                'Maintain chain of custody documentation',
                'Create forensic copies for analysis',
                'Document all analysis steps and findings'
            ])
        
        # Remove duplicates
        unique_recommendations = []
        seen = set()
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        return unique_recommendations[:5]  # Top 5 recommendations
    
    def _generate_forensic_report(self, evidence_list: List[Dict], findings: List[Dict], 
                                timeline: List[Dict]) -> Dict[str, Any]:
        """
        Generate comprehensive forensic report
        """
        report = {
            'report_id': f"forensic_report_{int(time.time())}",
            'generated_at': datetime.now().isoformat(),
            'generated_by': self.agent_id,
            'executive_summary': self._generate_executive_summary(findings, timeline),
            'evidence_summary': {
                'total_evidence': len(evidence_list),
                'evidence_types': list(set(ev['type'] for ev in evidence_list)),
                'total_size_bytes': sum(ev['original_size'] for ev in evidence_list)
            },
            'findings_summary': {
                'total_findings': len(findings),
                'by_severity': {
                    'critical': len([f for f in findings if f.get('severity') == 'critical']),
                    'high': len([f for f in findings if f.get('severity') == 'high']),
                    'medium': len([f for f in findings if f.get('severity') == 'medium']),
                    'low': len([f for f in findings if f.get('severity') == 'low'])
                }
            },
            'timeline_summary': self._summarize_timeline(timeline),
            'detailed_findings': findings[:10],  # Top 10 findings
            'recommendations': self._generate_recommendations(findings),
            'chain_of_custody': self._get_chain_of_custody_summary(evidence_list)
        }
        
        return report
    
    def _generate_executive_summary(self, findings: List[Dict], timeline: List[Dict]) -> str:
        """
        Generate executive summary for forensic report
        """
        if not findings:
            return "No significant findings detected in the analyzed evidence."
        
        critical_findings = [f for f in findings if f.get('severity') == 'critical']
        high_findings = [f for f in findings if f.get('severity') == 'high']
        
        summary = f"Forensic analysis of {len(timeline)} timeline events revealed "
        
        if critical_findings:
            summary += f"{len(critical_findings)} critical finding(s) indicating potential security incidents. "
        elif high_findings:
            summary += f"{len(high_findings)} high-severity finding(s) requiring investigation. "
        else:
            summary += f"{len(findings)} finding(s) of varying severity. "
        
        summary += "Detailed findings and recommendations are provided in this report."
        
        return summary
    
    def _get_chain_of_custody_summary(self, evidence_list: List[Dict]) -> Dict[str, Any]:
        """
        Get chain of custody summary for evidence
        """
        custody_summary = {}
        
        for evidence in evidence_list:
            evidence_id = evidence['id']
            if evidence_id in self.chain_of_custody:
                custody_summary[evidence_id] = {
                    'total_entries': len(self.chain_of_custody[evidence_id]),
                    'first_entry': self.chain_of_custody[evidence_id][0]['timestamp'] if self.chain_of_custody[evidence_id] else None,
                    'last_entry': self.chain_of_custody[evidence_id][-1]['timestamp'] if self.chain_of_custody[evidence_id] else None,
                    'current_custodian': self.chain_of_custody[evidence_id][-1]['agent'] if self.chain_of_custody[evidence_id] else None
                }
        
        return custody_summary
    
    def _calculate_incident_confidence(self, findings: List[Dict]) -> float:
        """
        Calculate confidence that an incident occurred
        """
        if not findings:
            return 0.1
        
        # Weight findings by severity
        severity_weights = {'critical': 1.0, 'high': 0.8, 'medium': 0.5, 'low': 0.2}
        
        total_weight = 0.0
        for finding in findings:
            severity = finding.get('severity', 'low')
            confidence = finding.get('confidence', 0.5)
            weight = severity_weights.get(severity, 0.2)
            total_weight += weight * confidence
        
        # Normalize
        max_possible = len(findings) * 1.0  # If all were critical with 1.0 confidence
        return min(1.0, total_weight / max_possible if max_possible > 0 else 0)
    
    def _calculate_evidence_weight(self, evidence_list: List[Dict]) -> float:
        """
        Calculate weight/strength of evidence
        """
        if not evidence_list:
            return 0.1
        
        # Consider multiple factors
        total_score = 0.0
        
        for evidence in evidence_list:
            # Factor 1: Evidence type relevance
            type_score = 0.5
            if 'log' in evidence['type']:
                type_score = 0.7
            elif 'memory' in evidence['type'] or 'disk' in evidence['type']:
                type_score = 0.9
            
            # Factor 2: Parsing success
            parse_score = 1.0 if evidence['parsed_content']['parsed_successfully'] else 0.3
            
            # Factor 3: Size (larger evidence may be more complete)
            size_score = min(1.0, evidence['original_size'] / 1000000)  # Normalize by 1MB
            
            # Combined score for this evidence
            evidence_score = (type_score * 0.4 + parse_score * 0.4 + size_score * 0.2)
            total_score += evidence_score
        
        # Average score
        return total_score / len(evidence_list)
    
    def _calculate_timeline_confidence(self, timeline: List[Dict]) -> float:
        """
        Calculate confidence in timeline reconstruction
        """
        if not timeline:
            return 0.1
        
        # More events = higher confidence
        event_factor = min(1.0, len(timeline) / 50.0)
        
        # Event type diversity
        event_types = set(e.get('type', 'unknown') for e in timeline)
        diversity_factor = min(1.0, len(event_types) / 10.0)
        
        # Time span (longer span with events = more complete)
        try:
            first = datetime.fromisoformat(timeline[0]['timestamp'].replace('Z', '+00:00'))
            last = datetime.fromisoformat(timeline[-1]['timestamp'].replace('Z', '+00:00'))
            time_span = (last - first).total_seconds()
            span_factor = min(1.0, time_span / 3600)  # Normalize by 1 hour
        except:
            span_factor = 0.3
        
        # Combined confidence
        return (event_factor * 0.4 + diversity_factor * 0.3 + span_factor * 0.3)
    
    def _update_metrics(self, evidence_count: int, artifact_count: int, processing_time: float):
        """
        Update agent metrics
        """
        self.metrics['evidence_analyzed'] += evidence_count
        self.metrics['artifacts_found'] += artifact_count
        
        # Update average analysis time (exponential moving average)
        alpha = 0.1
        self.metrics['avg_analysis_time'] = (
            alpha * processing_time + 
            (1 - alpha) * self.metrics['avg_analysis_time']
        )
    
    def _error_response(self, error_message: str) -> Dict[str, Any]:
        """
        Generate error response
        """
        return {
            'agent_id': self.agent_id,
            'agent_name': self.name,
            'error': error_message,
            'findings': [],
            'timeline': [],
            'recommendations': [],
            'reasoning_state': self.get_reasoning_state(),
            'decision': {
                'incident_confidence': 0.5,
                'evidence_weight': 0.1,
                'timeline_confidence': 0.1,
                'evidence': [{'type': 'AGENT_ERROR', 'description': error_message}]
            }
        }
    
    def get_evidence_report(self, evidence_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed report for specific evidence
        """
        if evidence_id not in self.evidence_store:
            return None
        
        evidence = self.evidence_store[evidence_id]
        
        report = {
            'evidence_id': evidence_id,
            'type': evidence['type'],
            'source': evidence['source'],
            'timestamp': evidence['timestamp'],
            'collection_timestamp': evidence['collection_timestamp'],
            'collector': evidence['collector'],
            'hashes': evidence['hashes'],
            'metadata': evidence['metadata'],
            'size_bytes': evidence['original_size'],
            'parsing_status': {
                'successful': evidence['parsed_content']['parsed_successfully'],
                'error': evidence['parsed_content'].get('parse_error')
            },
            'parsed_content_preview': str(evidence['parsed_content']['parsed_data'])[:500],
            'chain_of_custody': self.chain_of_custody.get(evidence_id, []),
            'artifacts_found': self._get_artifacts_for_evidence(evidence_id),
            'related_evidence': self._get_related_evidence(evidence_id)
        }
        
        return report
    
    def _get_artifacts_for_evidence(self, evidence_id: str) -> List[Dict]:
        """
        Get artifacts found in specific evidence
        """
        # This would query artifact database in production
        # For now, return empty list
        return []
    
    def _get_related_evidence(self, evidence_id: str) -> List[Dict]:
        """
        Get evidence related to specific evidence
        """
        related = []
        
        # Look for evidence with same source or similar timestamp
        target_evidence = self.evidence_store.get(evidence_id)
        if not target_evidence:
            return related
        
        for ev_id, evidence in self.evidence_store.items():
            if ev_id == evidence_id:
                continue
            
            # Check source similarity
            if evidence['source'] == target_evidence['source']:
                related.append({
                    'evidence_id': ev_id,
                    'type': evidence['type'],
                    'timestamp': evidence['timestamp'],
                    'relation': 'same_source'
                })
        
        return related
    
    def get_agent_status(self) -> Dict[str, Any]:
        """
        Get comprehensive agent status
        """
        return {
            'agent_id': self.agent_id,
            'name': self.name,
            'status': 'ACTIVE',
            'confidence': self.confidence,
            'metrics': self.metrics,
            'evidence_store': {
                'total_evidence': len(self.evidence_store),
                'evidence_types': list(set(ev['type'] for ev in self.evidence_store.values())),
                'oldest_evidence': min((ev['timestamp'] for ev in self.evidence_store.values()), default=None),
                'newest_evidence': max((ev['timestamp'] for ev in self.evidence_store.values()), default=None)
            },
            'capabilities': {
                'supported_evidence_types': self.supported_evidence,
                'log_parsers': list(self.log_parsers.keys()),
                'file_parsers': list(self.file_parsers.keys()),
                'artifact_parsers': list(self.artifact_parsers.keys()),
                'hash_algorithms': self.hash_algorithms
            },
            'config': {
                'thresholds': self.thresholds,
                'max_evidence_age_days': self.thresholds['max_evidence_age_days'],
                'min_evidence_count': self.thresholds['min_evidence_count']
            }
        }