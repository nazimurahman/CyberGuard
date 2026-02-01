# src/agents/incident_response_agent.py
"""
Incident Response Agent
Specialized agent for automated incident response, containment, and recovery
Implements NIST SP 800-61 incident response lifecycle
"""

import torch
import asyncio
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from enum import Enum
import json
from dataclasses import dataclass, asdict
from ..core.mhc_architecture import ManifoldConstrainedHyperConnections

# Import random module which was missing but used in the code
import random

# Enum for incident severity levels (NIST classification)
class IncidentSeverity(Enum):
    """NIST incident severity classification"""
    INFORMATIONAL = 0  # No impact, just information
    LOW = 1           # Minor impact, easily contained
    MODERATE = 2      # Some impact, requires response
    HIGH = 3          # Significant impact, urgent response
    CRITICAL = 4      # Severe impact, emergency response

# Enum for incident status
class IncidentStatus(Enum):
    """Incident lifecycle status"""
    DETECTED = "detected"          # Incident detected, awaiting triage
    TRIAGED = "triaged"            # Incident analyzed and prioritized
    CONTAINED = "contained"        # Threat contained, stopped spreading
    ERADICATED = "eradicated"      # Threat removed from systems
    RECOVERED = "recovered"        # Systems restored to normal
    CLOSED = "closed"              # Incident resolved and documented
    ESCALATED = "escalated"        # Escalated to human analysts

# Data class for structured incident data
@dataclass
class SecurityIncident:
    """Structured incident data following NIST guidelines"""
    incident_id: str               # Unique incident identifier
    timestamp: datetime           # When incident was detected
    severity: IncidentSeverity    # Incident severity level
    status: IncidentStatus        # Current incident status
    description: str              # Human-readable description
    affected_assets: List[str]    # List of affected systems/assets
    attack_vectors: List[str]     # Methods used in attack
    indicators: Dict[str, Any]    # IOCs and evidence
    source_ip: Optional[str]      # Source of attack (if known)
    target_url: Optional[str]     # Target URL/endpoint
    estimated_impact: str         # Business impact assessment
    response_actions: List[str]   # Actions taken
    required_escalation: bool = False  # Needs human intervention
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)  # Convert dataclass to dictionary
        data['severity'] = self.severity.value  # Convert enum to value
        data['status'] = self.status.value      # Convert enum to value
        data['timestamp'] = self.timestamp.isoformat()  # Convert datetime to ISO string
        return data

class IncidentResponseAgent:
    """
    Incident Response Agent
    Automated incident response following NIST SP 800-61 framework
    Handles detection, analysis, containment, eradication, and recovery
    """
    
    def __init__(self, agent_id: str = "incident_response_001"):
        """
        Initialize Incident Response Agent
        
        Args:
            agent_id: Unique identifier for this agent instance
        """
        self.agent_id = agent_id
        self.name = "Incident Response Agent"
        
        # Initialize mHC for coordination with other agents
        self.mhc = ManifoldConstrainedHyperConnections(
            n_agents=1,  # Will be updated by orchestrator
            state_dim=512
        )
        
        # Incident database (in production, use persistent storage)
        self.incidents: Dict[str, SecurityIncident] = {}
        self.incident_counter = 0
        
        # Response playbooks (NIST-based)
        self.response_playbooks = self._load_response_playbooks()
        
        # Containment strategies by threat type
        self.containment_strategies = {
            'XSS': ['block_source_ip', 'sanitize_inputs', 'update_waf_rules'],
            'SQL_INJECTION': ['block_source_ip', 'parameterize_queries', 'update_ids_rules'],
            'CSRF': ['invalidate_sessions', 'require_csrf_tokens', 'block_requests'],
            'DDOS': ['enable_rate_limiting', 'block_bot_ips', 'scale_resources'],
            'MALWARE': ['quarantine_file', 'block_c2_servers', 'scan_system'],
            'DATA_EXFILTRATION': ['block_outbound', 'revoke_credentials', 'encrypt_data'],
            'INSIDER_THREAT': ['suspend_account', 'review_logs', 'audit_access'],
            'PHISHING': ['block_url', 'notify_users', 'update_filters']
        }
        
        # Recovery procedures
        self.recovery_procedures = {
            'SERVER_COMPROMISE': ['restore_backup', 'patch_vulnerabilities', 'rotate_keys'],
            'DATA_BREACH': ['contain_leak', 'notify_affected', 'enhance_security'],
            'RANSOMWARE': ['isolate_network', 'restore_backups', 'decrypt_if_possible'],
            'ACCOUNT_TAKEOVER': ['reset_password', 'review_access', 'enable_mfa']
        }
        
        # Confidence and performance tracking
        self.confidence = 0.7  # Initial confidence level
        self.resolved_incidents = 0
        self.escalated_incidents = 0
        self.false_positives = 0
        
        # Response time metrics
        self.response_times = []
        self.average_response_time = 0.0
        
        # Learning from past incidents
        self.incident_patterns = {}
    
    def _load_response_playbooks(self) -> Dict[str, Dict[str, Any]]:
        """
        Load NIST-based incident response playbooks
        
        Returns:
            Dictionary of playbooks keyed by threat type
        """
        return {
            'XSS': {
                'name': 'Cross-Site Scripting Response',
                'steps': [
                    '1. Identify and block attack source',
                    '2. Sanitize affected inputs',
                    '3. Update WAF/CSP rules',
                    '4. Scan for persisted payloads',
                    '5. Notify affected users if data compromised'
                ],
                'severity_threshold': IncidentSeverity.HIGH,
                'containment_time': '15 minutes',
                'recovery_time': '1 hour'
            },
            'SQL_INJECTION': {
                'name': 'SQL Injection Response',
                'steps': [
                    '1. Block malicious IP addresses',
                    '2. Review database logs for data access',
                    '3. Implement parameterized queries',
                    '4. Rotate database credentials',
                    '5. Check for data exfiltration'
                ],
                'severity_threshold': IncidentSeverity.CRITICAL,
                'containment_time': '10 minutes',
                'recovery_time': '2 hours'
            },
            'DDOS': {
                'name': 'Distributed Denial of Service Response',
                'steps': [
                    '1. Activate DDoS mitigation service',
                    '2. Block attacking IP ranges',
                    '3. Scale up resources temporarily',
                    '4. Analyze attack patterns',
                    '5. Implement rate limiting'
                ],
                'severity_threshold': IncidentSeverity.HIGH,
                'containment_time': '5 minutes',
                'recovery_time': '30 minutes'
            },
            'DATA_BREACH': {
                'name': 'Data Breach Response',
                'steps': [
                    '1. Contain the breach',
                    '2. Assess data sensitivity',
                    '3. Notify legal/compliance teams',
                    '4. Contact affected parties if required',
                    '5. Implement enhanced security measures'
                ],
                'severity_threshold': IncidentSeverity.CRITICAL,
                'containment_time': 'Immediate',
                'recovery_time': 'Days to weeks'
            }
        }
    
    def analyze(self, security_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze security data for incidents and initiate response
        
        Args:
            security_data: Dictionary containing security event data including:
                - threat_type: Type of threat detected
                - threat_level: Severity score (0.0 to 1.0)
                - evidence: List of evidence items
                - source_ip: Attacker IP address
                - target_url: Affected URL/endpoint
                - timestamp: When threat was detected
                
        Returns:
            Dictionary with incident analysis and response actions
        """
        import time
        start_time = time.time()  # Start timing response
        
        # Extract threat information
        threat_type = security_data.get('threat_type', 'UNKNOWN')
        threat_level = security_data.get('threat_level', 0.0)
        evidence = security_data.get('evidence', [])
        source_ip = security_data.get('source_ip', 'UNKNOWN')
        target_url = security_data.get('target_url', 'UNKNOWN')
        
        # Step 1: Classify incident severity (NIST guidelines)
        severity = self._classify_severity(threat_type, threat_level, evidence)
        
        # Step 2: Create incident record
        incident_id = self._generate_incident_id()
        incident = SecurityIncident(
            incident_id=incident_id,
            timestamp=datetime.now(),
            severity=severity,
            status=IncidentStatus.DETECTED,
            description=f"{threat_type} attack detected from {source_ip}",
            affected_assets=[target_url] if target_url != 'UNKNOWN' else [],
            attack_vectors=[threat_type],
            indicators={
                'source_ip': source_ip,
                'threat_level': threat_level,
                'evidence_count': len(evidence),
                'initial_evidence': evidence[:3]  # First 3 pieces of evidence
            },
            source_ip=source_ip if source_ip != 'UNKNOWN' else None,
            target_url=target_url if target_url != 'UNKNOWN' else None,
            estimated_impact=self._estimate_impact(severity, threat_type),
            response_actions=[],  # Empty list, will be populated
            required_escalation=False  # Default, will be evaluated
        )
        
        # Store incident in memory
        self.incidents[incident_id] = incident
        
        # Step 3: Execute incident response lifecycle
        response_result = self._execute_response_lifecycle(incident, security_data)
        
        # Step 4: Update incident status based on response
        incident.status = response_result['new_status']
        incident.response_actions = response_result['actions_taken']
        incident.required_escalation = response_result['requires_escalation']
        
        # Step 5: Update metrics
        response_time = time.time() - start_time
        self.response_times.append(response_time)
        # Calculate average response time
        self.average_response_time = sum(self.response_times) / len(self.response_times)
        
        # Track resolution/escalation statistics
        if incident.status == IncidentStatus.CLOSED:
            self.resolved_incidents += 1
        elif incident.status == IncidentStatus.ESCALATED:
            self.escalated_incidents += 1
        
        # Step 6: Update confidence based on response effectiveness
        self._update_confidence(response_result)
        
        # Step 7: Generate comprehensive response report
        response_report = self._generate_response_report(incident, response_result)
        
        # Return comprehensive analysis result
        return {
            'agent_id': self.agent_id,
            'agent_name': self.name,
            'incident_id': incident_id,
            'incident': incident.to_dict(),
            'response_actions': incident.response_actions,
            'requires_human_review': incident.required_escalation,
            'severity': severity.value,
            'status': incident.status.value,
            'response_time_seconds': response_time,
            'playbook_used': response_result.get('playbook', 'custom'),
            'containment_effectiveness': response_result.get('containment_score', 0.0),
            'recommended_next_steps': response_result.get('next_steps', []),
            'confidence': self.confidence,
            'reasoning_state': self._get_reasoning_state(),
            'decision': {
                'threat_level': threat_level,
                'confidence': self.confidence,
                'evidence': response_report['summary']
            }
        }
    
    def _classify_severity(self, threat_type: str, 
                          threat_level: float, 
                          evidence: List[Dict]) -> IncidentSeverity:
        """
        Classify incident severity using NIST guidelines
        
        Args:
            threat_type: Type of threat (XSS, SQLi, etc.)
            threat_level: Numeric threat level (0.0 to 1.0)
            evidence: List of evidence items
            
        Returns:
            IncidentSeverity enum value
        """
        # Base severity on threat level
        if threat_level >= 0.9:
            base_severity = IncidentSeverity.CRITICAL
        elif threat_level >= 0.7:
            base_severity = IncidentSeverity.HIGH
        elif threat_level >= 0.5:
            base_severity = IncidentSeverity.MODERATE
        elif threat_level >= 0.3:
            base_severity = IncidentSeverity.LOW
        else:
            base_severity = IncidentSeverity.INFORMATIONAL
        
        # Adjust based on threat type
        critical_threats = ['SQL_INJECTION', 'RCE', 'DATA_BREACH', 'RANSOMWARE']
        high_threats = ['XSS', 'CSRF', 'SSRF', 'AUTH_BYPASS']
        
        if threat_type in critical_threats:
            # Escalate severity for critical threats
            if base_severity.value < IncidentSeverity.CRITICAL.value:
                # Increase severity by one level, cap at CRITICAL
                return IncidentSeverity(min(base_severity.value + 1, IncidentSeverity.CRITICAL.value))
        
        elif threat_type in high_threats:
            # Escalate severity for high threats
            if base_severity.value < IncidentSeverity.HIGH.value:
                # Increase severity by one level, cap at HIGH
                return IncidentSeverity(min(base_severity.value + 1, IncidentSeverity.HIGH.value))
        
        # Adjust based on evidence volume and credibility
        credible_evidence = sum(1 for e in evidence if e.get('certainty', 0) > 0.7)
        if credible_evidence >= 3:
            # Multiple credible evidence points increase severity
            return IncidentSeverity(min(base_severity.value + 1, IncidentSeverity.CRITICAL.value))
        
        return base_severity
    
    def _generate_incident_id(self) -> str:
        """Generate unique incident identifier"""
        self.incident_counter += 1  # Increment counter
        timestamp = datetime.now().strftime("%Y%m%d")  # Current date as YYYYMMDD
        return f"INC-{timestamp}-{self.incident_counter:06d}"  # Format with leading zeros
    
    def _estimate_impact(self, severity: IncidentSeverity, 
                        threat_type: str) -> str:
        """
        Estimate business impact of incident
        
        Args:
            severity: Incident severity level
            threat_type: Type of threat
            
        Returns:
            Human-readable impact estimation
        """
        # Templates for impact descriptions by severity
        impact_templates = {
            IncidentSeverity.CRITICAL: [
                "Critical business disruption, data loss possible",
                "System compromise affecting core operations",
                "Significant financial or reputational damage likely"
            ],
            IncidentSeverity.HIGH: [
                "Major service disruption, potential data exposure",
                "Multiple systems affected, recovery needed",
                "Substantial operational impact"
            ],
            IncidentSeverity.MODERATE: [
                "Limited service disruption, contained impact",
                "Single system affected, quick recovery expected",
                "Minimal business impact"
            ],
            IncidentSeverity.LOW: [
                "Minor disruption, no data loss",
                "Isolated issue, easy containment",
                "Negligible business impact"
            ],
            IncidentSeverity.INFORMATIONAL: [
                "Security observation, no immediate impact",
                "Potential vulnerability identified",
                "Proactive security monitoring alert"
            ]
        }
        
        # Select random template for given severity
        templates = impact_templates.get(severity, ["Impact assessment pending"])
        impact = random.choice(templates)  # Randomly select one template
        
        # Add threat-specific context
        if threat_type == 'DATA_BREACH':
            impact += ". Sensitive data potentially exposed."
        elif threat_type == 'RANSOMWARE':
            impact += ". Systems encrypted, recovery needed."
        elif threat_type == 'DDOS':
            impact += ". Service availability impacted."
        
        return impact
    
    def _execute_response_lifecycle(self, incident: SecurityIncident,
                                  security_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute NIST incident response lifecycle
        
        Steps:
        1. Preparation
        2. Detection & Analysis
        3. Containment, Eradication & Recovery
        4. Post-Incident Activity
        
        Args:
            incident: SecurityIncident object
            security_data: Original security data
            
        Returns:
            Dictionary with response results
        """
        threat_type = security_data.get('threat_type', 'UNKNOWN')
        
        # Get appropriate playbook
        playbook = self.response_playbooks.get(threat_type)
        if not playbook:
            # Create dynamic playbook for unknown threat types
            playbook = self._create_dynamic_playbook(threat_type, incident.severity)
        
        # Step 1: Initial containment (immediate action)
        containment_result = self._execute_containment(incident, playbook)
        
        # Step 2: Determine if escalation needed
        requires_escalation = self._requires_human_escalation(incident, containment_result)
        
        # Step 3: Execute eradication if contained
        eradication_result = {}
        if containment_result['success']:
            eradication_result = self._execute_eradication(incident, playbook)
        
        # Step 4: Execute recovery
        recovery_result = {}
        if eradication_result.get('success', False):
            recovery_result = self._execute_recovery(incident, playbook)
        
        # Step 5: Determine new status
        new_status = self._determine_new_status(
            incident.status,
            containment_result,
            eradication_result,
            recovery_result,
            requires_escalation
        )
        
        # Step 6: Compile actions taken
        actions_taken = []
        actions_taken.extend(containment_result.get('actions', []))
        actions_taken.extend(eradication_result.get('actions', []))
        actions_taken.extend(recovery_result.get('actions', []))
        
        # Step 7: Calculate containment effectiveness
        containment_score = self._calculate_containment_score(
            containment_result,
            eradication_result,
            recovery_result
        )
        
        # Return comprehensive lifecycle results
        return {
            'new_status': new_status,
            'requires_escalation': requires_escalation,
            'actions_taken': actions_taken,
            'containment_success': containment_result['success'],
            'eradication_success': eradication_result.get('success', False),
            'recovery_success': recovery_result.get('success', False),
            'containment_score': containment_score,
            'playbook': playbook.get('name', 'custom'),
            'next_steps': self._determine_next_steps(new_status, requires_escalation)
        }
    
    def _execute_containment(self, incident: SecurityIncident,
                           playbook: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute containment phase of incident response
        
        Args:
            incident: SecurityIncident object
            playbook: Response playbook
            
        Returns:
            Dictionary with containment results
        """
        threat_type = incident.attack_vectors[0] if incident.attack_vectors else 'UNKNOWN'
        actions = []
        
        # Get containment strategies for this threat type
        strategies = self.containment_strategies.get(threat_type, [])
        
        # Execute strategies
        for strategy in strategies:
            if strategy == 'block_source_ip' and incident.source_ip:
                action = f"Blocked source IP {incident.source_ip}"
                actions.append(action)
                # In production, this would call firewall API
                
            elif strategy == 'sanitize_inputs':
                action = "Sanitized input validation rules"
                actions.append(action)
                
            elif strategy == 'update_waf_rules':
                action = "Updated WAF rules for threat type"
                actions.append(action)
                
            elif strategy == 'parameterize_queries':
                action = "Enabled parameterized query enforcement"
                actions.append(action)
                
            elif strategy == 'enable_rate_limiting':
                action = "Enabled rate limiting on affected endpoints"
                actions.append(action)
                
            elif strategy == 'quarantine_file':
                action = "Quarantined suspicious files"
                actions.append(action)
        
        # Add playbook-specific actions (first 2 steps)
        if 'steps' in playbook:
            playbook_actions = [f"Playbook: {step}" for step in playbook.get('steps', [])[:2]]
            actions.extend(playbook_actions)
        
        # Determine containment success
        # Success if actions were taken and incident is not critical (which requires escalation)
        success = len(actions) > 0 and incident.severity != IncidentSeverity.CRITICAL
        
        return {
            'success': success,
            'actions': actions,
            'strategies_applied': strategies[:3],  # First 3 strategies
            'containment_time': playbook.get('containment_time', 'Unknown')
        }
    
    def _requires_human_escalation(self, incident: SecurityIncident,
                                 containment_result: Dict[str, Any]) -> bool:
        """
        Determine if incident requires human escalation
        
        Args:
            incident: SecurityIncident object
            containment_result: Results from containment phase
            
        Returns:
            True if human escalation required
        """
        # Always escalate critical incidents
        if incident.severity == IncidentSeverity.CRITICAL:
            return True
        
        # Escalate if containment failed
        if not containment_result['success']:
            return True
        
        # Escalate for certain threat types regardless of severity
        critical_threats = ['DATA_BREACH', 'RANSOMWARE', 'INSIDER_THREAT']
        if any(threat in critical_threats for threat in incident.attack_vectors):
            return True
        
        # Escalate if multiple systems affected
        if len(incident.affected_assets) > 3:
            return True
        
        # Escalate if source is internal
        if incident.source_ip and self._is_internal_ip(incident.source_ip):
            return True
        
        return False
    
    def _is_internal_ip(self, ip_address: str) -> bool:
        """
        Check if IP address is internal/private
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if internal IP
        """
        # Common private IP address ranges
        internal_prefixes = ['10.', '192.168.', '172.16.', '172.17.', 
                           '172.18.', '172.19.', '172.20.', '172.21.',
                           '172.22.', '172.23.', '172.24.', '172.25.',
                           '172.26.', '172.27.', '172.28.', '172.29.',
                           '172.30.', '172.31.', '127.', '::1']
        
        # Check if IP starts with any internal prefix
        return any(ip_address.startswith(prefix) for prefix in internal_prefixes)
    
    def _execute_eradication(self, incident: SecurityIncident,
                           playbook: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute eradication phase (remove threat completely)
        
        Args:
            incident: SecurityIncident object
            playbook: Response playbook
            
        Returns:
            Dictionary with eradication results
        """
        actions = []
        
        # Common eradication actions
        eradication_actions = [
            "Removed malicious files and artifacts",
            "Patched exploited vulnerabilities",
            "Rotated compromised credentials",
            "Cleared malicious cache entries",
            "Updated security configurations"
        ]
        
        # Select appropriate eradication actions based on severity
        if incident.severity.value >= IncidentSeverity.HIGH.value:
            actions = eradication_actions[:3]  # Take first 3 actions for high severity
        else:
            actions = eradication_actions[:2]  # Take first 2 actions for lower severity
        
        # Add playbook-specific eradication steps if available
        if 'eradication_steps' in playbook:
            actions.extend([f"Playbook eradication: {step}" 
                          for step in playbook.get('eradication_steps', [])])
        
        return {
            'success': len(actions) > 0,  # Success if actions were taken
            'actions': actions,
            'eradication_complete': True
        }
    
    def _execute_recovery(self, incident: SecurityIncident,
                        playbook: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute recovery phase (restore normal operations)
        
        Args:
            incident: SecurityIncident object
            playbook: Response playbook
            
        Returns:
            Dictionary with recovery results
        """
        actions = []
        
        # Get recovery procedures based on incident type
        recovery_key = self._determine_recovery_procedure(incident)
        procedures = self.recovery_procedures.get(recovery_key, [])
        
        # Execute recovery procedures (limit to 2)
        for procedure in procedures[:2]:
            actions.append(f"Recovery: {procedure}")
            
            # Simulate procedure execution
            if 'restore' in procedure.lower():
                actions.append("System restore initiated")
            elif 'rotate' in procedure.lower():
                actions.append("Credentials rotated")
            elif 'scan' in procedure.lower():
                actions.append("Security scan completed")
        
        # Verify recovery with additional checks
        verification_actions = [
            "Verified system integrity",
            "Confirmed no residual threats",
            "Validated security controls",
            "Tested system functionality"
        ]
        
        # Add first 2 verification actions
        actions.extend(verification_actions[:2])
        
        return {
            'success': len(actions) > 0,  # Success if actions were taken
            'actions': actions,
            'recovery_time': playbook.get('recovery_time', 'Unknown'),
            'systems_restored': len(incident.affected_assets)
        }
    
    def _determine_recovery_procedure(self, incident: SecurityIncident) -> str:
        """Determine appropriate recovery procedure based on incident type"""
        if 'DATA_BREACH' in incident.attack_vectors:
            return 'DATA_BREACH'
        elif 'RANSOMWARE' in incident.attack_vectors:
            return 'RANSOMWARE'
        elif len(incident.affected_assets) > 1:
            return 'SERVER_COMPROMISE'
        else:
            return 'ACCOUNT_TAKEOVER'
    
    def _determine_new_status(self, current_status: IncidentStatus,
                            containment_result: Dict[str, Any],
                            eradication_result: Dict[str, Any],
                            recovery_result: Dict[str, Any],
                            requires_escalation: bool) -> IncidentStatus:
        """
        Determine new incident status based on response results
        
        Args:
            current_status: Current incident status
            containment_result: Results from containment phase
            eradication_result: Results from eradication phase
            recovery_result: Results from recovery phase
            requires_escalation: Whether human escalation is needed
            
        Returns:
            New IncidentStatus
        """
        # First check for escalation
        if requires_escalation:
            return IncidentStatus.ESCALATED
        
        # Check containment failure
        if not containment_result['success']:
            return IncidentStatus.DETECTED  # Still in detection phase
        
        # Check progression through lifecycle
        if containment_result['success'] and not eradication_result:
            return IncidentStatus.CONTAINED
        
        if eradication_result.get('success', False) and not recovery_result:
            return IncidentStatus.ERADICATED
        
        if recovery_result.get('success', False):
            return IncidentStatus.RECOVERED
        
        # Default: move to next stage in predefined flow
        status_flow = {
            IncidentStatus.DETECTED: IncidentStatus.TRIAGED,
            IncidentStatus.TRIAGED: IncidentStatus.CONTAINED,
            IncidentStatus.CONTAINED: IncidentStatus.ERADICATED,
            IncidentStatus.ERADICATED: IncidentStatus.RECOVERED,
            IncidentStatus.RECOVERED: IncidentStatus.CLOSED,
        }
        
        # Get next status or keep current if not in flow
        return status_flow.get(current_status, current_status)
    
    def _calculate_containment_score(self, containment_result: Dict[str, Any],
                                   eradication_result: Dict[str, Any],
                                   recovery_result: Dict[str, Any]) -> float:
        """Calculate effectiveness score of containment efforts"""
        score = 0.0
        
        # Base score for successful containment
        if containment_result['success']:
            score += 0.4
            
            # Bonus for immediate containment
            if 'Immediate' in containment_result.get('containment_time', ''):
                score += 0.1
        
        # Score for eradication
        if eradication_result.get('success', False):
            score += 0.3
            
            # Bonus for complete eradication
            if eradication_result.get('eradication_complete', False):
                score += 0.1
        
        # Score for recovery
        if recovery_result.get('success', False):
            score += 0.2
            
            # Bonus for restoring multiple systems
            if recovery_result.get('systems_restored', 0) > 0:
                score += 0.1
        
        # Cap score at 1.0
        return min(score, 1.0)
    
    def _determine_next_steps(self, status: IncidentStatus,
                            requires_escalation: bool) -> List[str]:
        """Determine next steps based on current status"""
        # If escalation needed, specific steps for analyst handoff
        if requires_escalation:
            return [
                "Await human analyst review",
                "Prepare incident briefing",
                "Gather additional evidence"
            ]
        
        # Define next steps for each status
        next_steps_map = {
            IncidentStatus.DETECTED: [
                "Analyze attack vector",
                "Gather additional IOCs",
                "Assess impact scope"
            ],
            IncidentStatus.TRIAGED: [
                "Initiate containment procedures",
                "Notify relevant teams",
                "Document incident details"
            ],
            IncidentStatus.CONTAINED: [
                "Begin eradication procedures",
                "Scan for residual threats",
                "Update security controls"
            ],
            IncidentStatus.ERADICATED: [
                "Initiate recovery procedures",
                "Validate system integrity",
                "Test security improvements"
            ],
            IncidentStatus.RECOVERED: [
                "Conduct post-incident review",
                "Update incident response playbooks",
                "Close incident with documentation"
            ],
            IncidentStatus.CLOSED: [
                "Archive incident records",
                "Update threat intelligence",
                "Conduct lessons learned session"
            ],
            IncidentStatus.ESCALATED: [
                "Assist human analysts",
                "Provide automated analysis",
                "Monitor for similar incidents"
            ]
        }
        
        # Get next steps or default monitoring
        return next_steps_map.get(status, ["Continue monitoring"])
    
    def _create_dynamic_playbook(self, threat_type: str,
                               severity: IncidentSeverity) -> Dict[str, Any]:
        """Create dynamic playbook for unknown threat types"""
        return {
            'name': f'Dynamic Playbook for {threat_type}',
            'steps': [
                f'1. Analyze {threat_type} attack pattern',
                '2. Implement generic containment',
                '3. Monitor for attack evolution',
                '4. Update threat intelligence'
            ],
            'severity_threshold': severity,
            'containment_time': '30 minutes',
            'recovery_time': 'TBD based on impact'
        }
    
    def _update_confidence(self, response_result: Dict[str, Any]):
        """Update agent confidence based on response effectiveness"""
        containment_score = response_result.get('containment_score', 0.0)
        
        # Adjust confidence based on containment score
        if containment_score >= 0.8:
            # Excellent response, increase confidence by 10%
            self.confidence = min(1.0, self.confidence * 1.1)
        elif containment_score >= 0.6:
            # Good response, slight increase (5%)
            self.confidence = min(1.0, self.confidence * 1.05)
        elif containment_score >= 0.4:
            # Adequate response, maintain (slight decay 1%)
            self.confidence = self.confidence * 0.99
        else:
            # Poor response, decrease confidence by 10%
            self.confidence = max(0.1, self.confidence * 0.9)
    
    def _generate_response_report(self, incident: SecurityIncident,
                                response_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive incident response report"""
        return {
            'summary': [
                f"Incident {incident.incident_id} - {incident.description}",
                f"Severity: {incident.severity.name}",
                f"Status: {incident.status.value}",
                f"Containment Score: {response_result.get('containment_score', 0.0):.2f}",
                f"Response Time: {response_result.get('response_time', 'N/A')}",
                f"Actions Taken: {len(incident.response_actions)}",
                f"Escalation Required: {incident.required_escalation}"
            ],
            'timeline': [
                f"{incident.timestamp.isoformat()}: Incident detected",
                f"{datetime.now().isoformat()}: Current status - {incident.status.value}"
            ],
            'evidence': incident.indicators,
            'recommendations': response_result.get('next_steps', [])
        }
    
    def _get_reasoning_state(self) -> torch.Tensor:
        """Get current reasoning state for mHC coordination"""
        # Convert recent incident patterns to state vector
        if not self.incidents:
            return torch.zeros(512)  # Return zero tensor if no incidents
        
        # Use features from last 5 incidents
        recent_incidents = list(self.incidents.values())[-5:]
        
        # Extract features from each incident
        features = []
        for incident in recent_incidents:
            features.extend([
                incident.severity.value / 4.0,  # Normalized severity (0-1)
                1.0 if incident.required_escalation else 0.0,  # Escalation flag
                len(incident.affected_assets) / 10.0,  # Normalized asset count
                len(incident.response_actions) / 10.0  # Normalized actions count
            ])
        
        # Pad or truncate to 512 dimensions
        if len(features) < 512:
            features.extend([0.0] * (512 - len(features)))  # Pad with zeros
        else:
            features = features[:512]  # Truncate to 512
        
        # Convert to PyTorch tensor
        return torch.tensor(features, dtype=torch.float32)
    
    def get_agent_status(self) -> Dict[str, Any]:
        """Get current agent status and metrics"""
        # Count active incidents (not closed)
        active_incidents = len([i for i in self.incidents.values() 
                               if i.status != IncidentStatus.CLOSED])
        
        return {
            'agent_id': self.agent_id,
            'agent_name': self.name,
            'confidence': self.confidence,
            'active_incidents': active_incidents,
            'total_incidents': len(self.incidents),
            'resolved_incidents': self.resolved_incidents,
            'escalated_incidents': self.escalated_incidents,
            'false_positives': self.false_positives,
            'average_response_time': self.average_response_time,
            'playbooks_available': len(self.response_playbooks),
            'containment_strategies': len(self.containment_strategies)
        }