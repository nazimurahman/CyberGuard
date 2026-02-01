"""
Inference Result Data Model for CyberGuard

Defines the structured data model for inference results from security analysis.
This ensures consistent data format across the entire inference pipeline.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Union
from datetime import datetime
import json
from enum import Enum


class ThreatSeverity(Enum):
    """Enumeration of threat severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ThreatType(Enum):
    """Enumeration of threat types"""
    XSS = "XSS"
    SQL_INJECTION = "SQL_INJECTION"
    CSRF = "CSRF"
    SSRF = "SSRF"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    XXE = "XXE"
    DESERIALIZATION = "DESERIALIZATION"
    IDOR = "IDOR"
    BROKEN_AUTH = "BROKEN_AUTH"
    MALWARE = "MALWARE"
    BOT_ATTACK = "BOT_ATTACK"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    API_ABUSE = "API_ABUSE"
    UNKNOWN = "UNKNOWN"


@dataclass
class SecurityEvidence:
    """
    Data class representing a piece of security evidence.
    Each evidence item supports the inference conclusion.
    """
    
    evidence_id: str  # Unique identifier for the evidence
    evidence_type: str  # Type/category of evidence
    description: str  # Human-readable description of evidence
    severity: ThreatSeverity = ThreatSeverity.MEDIUM  # Severity level of evidence
    confidence: float = 0.5  # Confidence score (0.0 to 1.0)
    location: str = ""  # Where the evidence was found
    timestamp: datetime = field(default_factory=datetime.now)  # When evidence was collected
    raw_data: Optional[Dict[str, Any]] = None  # Original raw data
    source_agent: str = ""  # Which agent found this evidence
    tags: List[str] = field(default_factory=list)  # Categorization tags
    metadata: Dict[str, Any] = field(default_factory=dict)  # Additional metadata
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert evidence to dictionary for serialization"""
        return {
            'evidence_id': self.evidence_id,
            'evidence_type': self.evidence_type,
            'description': self.description,
            'severity': self.severity.value,
            'confidence': self.confidence,
            'location': self.location,
            'timestamp': self.timestamp.isoformat(),
            'source_agent': self.source_agent,
            'tags': self.tags,
            'metadata': self.metadata,
            'raw_data': self.raw_data
        }
    
    def validate(self) -> bool:
        """Validate evidence data"""
        if not self.evidence_id:
            raise ValueError("evidence_id is required")
        if not self.evidence_type:
            raise ValueError("evidence_type is required")
        if not self.description:
            raise ValueError("description is required")
        if not 0 <= self.confidence <= 1:
            raise ValueError("confidence must be between 0 and 1")
        return True


@dataclass
class SecurityRecommendation:
    """
    Data class representing a structured security recommendation.
    """
    
    recommendation_id: str  # Unique identifier for recommendation
    title: str  # Short title of recommendation
    description: str  # Detailed description
    priority: str = "MEDIUM"  # Implementation priority
    category: str = "general"  # Category/type of recommendation
    action_items: List[str] = field(default_factory=list)  # Specific actions to take
    references: List[str] = field(default_factory=list)  # Reference URLs/docs
    estimated_effort: str = "MEDIUM"  # Estimated implementation effort
    risk_reduction: float = 0.5  # How much risk this reduces (0-1)
    implementation_cost: Optional[str] = None  # Cost to implement
    time_to_fix: Optional[str] = None  # Estimated time to fix
    metadata: Dict[str, Any] = field(default_factory=dict)  # Additional metadata
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert recommendation to dictionary for serialization"""
        return {
            'recommendation_id': self.recommendation_id,
            'title': self.title,
            'description': self.description,
            'priority': self.priority,
            'category': self.category,
            'action_items': self.action_items,
            'references': self.references,
            'estimated_effort': self.estimated_effort,
            'risk_reduction': self.risk_reduction,
            'implementation_cost': self.implementation_cost,
            'time_to_fix': self.time_to_fix,
            'metadata': self.metadata
        }
    
    def validate(self) -> bool:
        """Validate recommendation data"""
        if not self.recommendation_id:
            raise ValueError("recommendation_id is required")
        if not self.title:
            raise ValueError("title is required")
        if not self.description:
            raise ValueError("description is required")
        if self.priority not in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            raise ValueError("priority must be one of: CRITICAL, HIGH, MEDIUM, LOW")
        if not 0 <= self.risk_reduction <= 1:
            raise ValueError("risk_reduction must be between 0 and 1")
        return True


@dataclass
class AgentContribution:
    """Data class representing an agent's contribution to the inference"""
    
    agent_id: str  # Unique agent identifier
    agent_name: str  # Human-readable agent name
    confidence: float = 0.5  # Agent's confidence in its analysis
    reasoning_state: Optional[Any] = None  # Agent's internal reasoning state
    evidence_count: int = 0  # Number of evidence items contributed
    analysis_time_ms: float = 0.0  # Time taken for analysis in milliseconds
    metadata: Dict[str, Any] = field(default_factory=dict)  # Additional metadata
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert agent contribution to dictionary"""
        result = {
            'agent_id': self.agent_id,
            'agent_name': self.agent_name,
            'confidence': self.confidence,
            'evidence_count': self.evidence_count,
            'analysis_time_ms': self.analysis_time_ms,
            'metadata': self.metadata
        }
        if self.reasoning_state is not None:
            # Only include reasoning_state if it exists
            result['reasoning_state'] = self.reasoning_state
        return result


@dataclass
class InferenceResult:
    """
    Main data class representing the complete inference result from security analysis.
    This is the core data structure that flows through the inference pipeline.
    """
    
    # Core inference data
    inference_id: str  # Unique identifier for this inference
    timestamp: datetime = field(default_factory=datetime.now)  # When inference occurred
    model_version: str = "1.0.0"  # Version of model used
    
    # Threat assessment
    threat_level: float = 0.0  # Overall threat score (0.0 to 1.0)
    confidence: float = 0.5    # Confidence in assessment (0.0 to 1.0)
    threat_type: Union[str, ThreatType] = ThreatType.UNKNOWN  # Type of threat
    severity: Union[str, ThreatSeverity] = ThreatSeverity.INFO  # Severity level
    
    # Evidence and supporting data
    evidence: List[Union[SecurityEvidence, Dict[str, Any]]] = field(default_factory=list)
    recommendations: List[Union[SecurityRecommendation, Dict[str, Any]]] = field(default_factory=list)
    
    # Source information
    target_url: str = ""  # URL or target being analyzed
    scan_id: str = ""  # Associated scan identifier
    analysis_mode: str = "standard"  # Analysis mode used
    
    # Agent coordination
    agent_contributions: List[AgentContribution] = field(default_factory=list)
    coordination_state: Optional[Any] = None  # State of multi-agent coordination
    
    # Performance metrics
    processing_time_ms: float = 0.0  # Total processing time in ms
    token_count: int = 0  # Number of tokens processed
    model_latency_ms: float = 0.0  # Model inference latency in ms
    
    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization processing - convert string enums to enum types"""
        # Convert string threat_type to ThreatType enum
        if isinstance(self.threat_type, str):
            try:
                self.threat_type = ThreatType[self.threat_type]
            except KeyError:
                self.threat_type = ThreatType.UNKNOWN
        
        # Convert string severity to ThreatSeverity enum
        if isinstance(self.severity, str):
            try:
                self.severity = ThreatSeverity[self.severity]
            except KeyError:
                self.severity = ThreatSeverity.INFO
    
    def validate(self) -> bool:
        """
        Validate the inference result for correctness and completeness.
        
        Returns:
            bool: True if validation passes
        
        Raises:
            ValueError: If validation fails with specific error messages
        """
        # Validate required fields
        if not self.inference_id:
            raise ValueError("inference_id is required")
        
        # Validate threat level
        if not isinstance(self.threat_level, (int, float)):
            raise ValueError("threat_level must be numeric")
        if not 0 <= self.threat_level <= 1:
            raise ValueError("threat_level must be between 0 and 1")
        
        # Validate confidence
        if not isinstance(self.confidence, (int, float)):
            raise ValueError("confidence must be numeric")
        if not 0 <= self.confidence <= 1:
            raise ValueError("confidence must be between 0 and 1")
        
        # Validate threat type
        if not self.threat_type:
            raise ValueError("threat_type is required")
        
        # Validate severity
        if not self.severity:
            raise ValueError("severity is required")
        
        # Validate evidence
        for i, evidence in enumerate(self.evidence):
            if isinstance(evidence, SecurityEvidence):
                evidence.validate()
            elif isinstance(evidence, dict):
                # Basic validation for dict evidence
                if not evidence.get('description'):
                    raise ValueError(f"Evidence at index {i} missing description")
        
        # Validate recommendations
        for i, rec in enumerate(self.recommendations):
            if isinstance(rec, SecurityRecommendation):
                rec.validate()
            elif isinstance(rec, dict):
                # Basic validation for dict recommendations
                if not rec.get('title'):
                    raise ValueError(f"Recommendation at index {i} missing title")
        
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert inference result to dictionary for serialization.
        
        Returns:
            Dict[str, Any]: Dictionary representation of the inference result
        """
        # Serialize evidence
        evidence_list = []
        for evidence in self.evidence:
            if isinstance(evidence, SecurityEvidence):
                evidence_list.append(evidence.to_dict())
            else:
                evidence_list.append(evidence)
        
        # Serialize recommendations
        recommendations_list = []
        for rec in self.recommendations:
            if isinstance(rec, SecurityRecommendation):
                recommendations_list.append(rec.to_dict())
            else:
                recommendations_list.append(rec)
        
        # Serialize agent contributions
        agent_contributions_list = [ac.to_dict() for ac in self.agent_contributions]
        
        # Build result dictionary
        result_dict = {
            'inference_id': self.inference_id,
            'timestamp': self.timestamp.isoformat(),
            'model_version': self.model_version,
            'threat_level': self.threat_level,
            'confidence': self.confidence,
            'threat_type': self.threat_type.value if isinstance(self.threat_type, ThreatType) else str(self.threat_type),
            'severity': self.severity.value if isinstance(self.severity, ThreatSeverity) else str(self.severity),
            'evidence': evidence_list,
            'recommendations': recommendations_list,
            'target_url': self.target_url,
            'scan_id': self.scan_id,
            'analysis_mode': self.analysis_mode,
            'agent_contributions': agent_contributions_list,
            'processing_time_ms': self.processing_time_ms,
            'token_count': self.token_count,
            'model_latency_ms': self.model_latency_ms,
            'metadata': self.metadata
        }
        
        # Add coordination_state if present
        if self.coordination_state is not None:
            result_dict['coordination_state'] = self.coordination_state
        
        return result_dict
    
    def to_json(self, pretty: bool = True) -> str:
        """
        Convert inference result to JSON string.
        
        Args:
            pretty: Whether to format JSON with indentation
        
        Returns:
            str: JSON string representation
        """
        result_dict = self.to_dict()
        if pretty:
            return json.dumps(result_dict, indent=2, ensure_ascii=False)
        else:
            return json.dumps(result_dict, separators=(',', ':'), ensure_ascii=False)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'InferenceResult':
        """
        Create InferenceResult instance from dictionary.
        
        Args:
            data: Dictionary containing inference result data
        
        Returns:
            InferenceResult: New instance created from dictionary
        
        Raises:
            ValueError: If required fields are missing or invalid
        """
        # Convert evidence dictionaries to SecurityEvidence objects
        evidence_objects = []
        for ev_data in data.get('evidence', []):
            if isinstance(ev_data, dict):
                # Parse timestamp
                timestamp_str = ev_data.get('timestamp')
                if timestamp_str:
                    try:
                        timestamp = datetime.fromisoformat(timestamp_str)
                    except ValueError:
                        timestamp = datetime.now()
                else:
                    timestamp = datetime.now()
                
                # Parse severity
                severity_str = ev_data.get('severity', 'MEDIUM')
                try:
                    severity = ThreatSeverity(severity_str)
                except ValueError:
                    severity = ThreatSeverity.MEDIUM
                
                # Create SecurityEvidence object
                evidence_objects.append(SecurityEvidence(
                    evidence_id=ev_data.get('evidence_id', ''),
                    evidence_type=ev_data.get('evidence_type', ''),
                    description=ev_data.get('description', ''),
                    severity=severity,
                    confidence=ev_data.get('confidence', 0.5),
                    location=ev_data.get('location', ''),
                    timestamp=timestamp,
                    source_agent=ev_data.get('source_agent', ''),
                    tags=ev_data.get('tags', []),
                    metadata=ev_data.get('metadata', {}),
                    raw_data=ev_data.get('raw_data')
                ))
            else:
                evidence_objects.append(ev_data)
        
        # Convert recommendation dictionaries to SecurityRecommendation objects
        recommendation_objects = []
        for rec_data in data.get('recommendations', []):
            if isinstance(rec_data, dict):
                recommendation_objects.append(SecurityRecommendation(
                    recommendation_id=rec_data.get('recommendation_id', ''),
                    title=rec_data.get('title', ''),
                    description=rec_data.get('description', ''),
                    priority=rec_data.get('priority', 'MEDIUM'),
                    category=rec_data.get('category', 'general'),
                    action_items=rec_data.get('action_items', []),
                    references=rec_data.get('references', []),
                    estimated_effort=rec_data.get('estimated_effort', 'MEDIUM'),
                    risk_reduction=rec_data.get('risk_reduction', 0.5),
                    implementation_cost=rec_data.get('implementation_cost'),
                    time_to_fix=rec_data.get('time_to_fix'),
                    metadata=rec_data.get('metadata', {})
                ))
            else:
                recommendation_objects.append(rec_data)
        
        # Convert agent contribution dictionaries
        agent_contributions = []
        for ac_data in data.get('agent_contributions', []):
            if isinstance(ac_data, dict):
                agent_contributions.append(AgentContribution(
                    agent_id=ac_data.get('agent_id', ''),
                    agent_name=ac_data.get('agent_name', ''),
                    confidence=ac_data.get('confidence', 0.5),
                    reasoning_state=ac_data.get('reasoning_state'),
                    evidence_count=ac_data.get('evidence_count', 0),
                    analysis_time_ms=ac_data.get('analysis_time_ms', 0.0),
                    metadata=ac_data.get('metadata', {})
                ))
            else:
                agent_contributions.append(ac_data)
        
        # Parse main timestamp
        timestamp = data.get('timestamp')
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)
        elif timestamp is None:
            timestamp = datetime.now()
        
        # Parse threat_type and severity
        threat_type = data.get('threat_type', ThreatType.UNKNOWN)
        severity = data.get('severity', ThreatSeverity.INFO)
        
        # Create instance
        return cls(
            inference_id=data.get('inference_id', ''),
            timestamp=timestamp,
            model_version=data.get('model_version', '1.0.0'),
            threat_level=data.get('threat_level', 0.0),
            confidence=data.get('confidence', 0.5),
            threat_type=threat_type,
            severity=severity,
            evidence=evidence_objects,
            recommendations=recommendation_objects,
            target_url=data.get('target_url', ''),
            scan_id=data.get('scan_id', ''),
            analysis_mode=data.get('analysis_mode', 'standard'),
            agent_contributions=agent_contributions,
            coordination_state=data.get('coordination_state'),
            processing_time_ms=data.get('processing_time_ms', 0.0),
            token_count=data.get('token_count', 0),
            model_latency_ms=data.get('model_latency_ms', 0.0),
            metadata=data.get('metadata', {})
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> 'InferenceResult':
        """
        Create InferenceResult instance from JSON string.
        
        Args:
            json_str: JSON string containing inference result data
        
        Returns:
            InferenceResult: New instance created from JSON
        """
        data = json.loads(json_str)
        return cls.from_dict(data)
    
    def add_evidence(self, evidence: Union[SecurityEvidence, Dict[str, Any]]) -> None:
        """Add evidence to the inference result"""
        if isinstance(evidence, dict):
            # Convert dict to SecurityEvidence if it has required fields
            if 'description' in evidence:
                # Generate evidence_id if not provided
                evidence_id = evidence.get('evidence_id', f'ev_{len(self.evidence)}_{datetime.now().timestamp()}')
                
                # Parse severity
                severity_str = evidence.get('severity', 'MEDIUM')
                try:
                    severity = ThreatSeverity(severity_str)
                except ValueError:
                    severity = ThreatSeverity.MEDIUM
                
                evidence_obj = SecurityEvidence(
                    evidence_id=evidence_id,
                    evidence_type=evidence.get('evidence_type', 'custom'),
                    description=evidence['description'],
                    severity=severity,
                    confidence=evidence.get('confidence', 0.5),
                    location=evidence.get('location', ''),
                    source_agent=evidence.get('source_agent', ''),
                    tags=evidence.get('tags', []),
                    metadata=evidence.get('metadata', {}),
                    raw_data=evidence
                )
                self.evidence.append(evidence_obj)
            else:
                self.evidence.append(evidence)
        else:
            self.evidence.append(evidence)
    
    def add_recommendation(self, recommendation: Union[SecurityRecommendation, Dict[str, Any]]) -> None:
        """Add recommendation to the inference result"""
        if isinstance(recommendation, dict):
            # Convert dict to SecurityRecommendation if it has required fields
            if 'title' in recommendation:
                # Generate recommendation_id if not provided
                rec_id = recommendation.get('recommendation_id', f'rec_{len(self.recommendations)}_{datetime.now().timestamp()}')
                
                rec_obj = SecurityRecommendation(
                    recommendation_id=rec_id,
                    title=recommendation['title'],
                    description=recommendation.get('description', ''),
                    priority=recommendation.get('priority', 'MEDIUM'),
                    category=recommendation.get('category', 'general'),
                    action_items=recommendation.get('action_items', []),
                    references=recommendation.get('references', []),
                    estimated_effort=recommendation.get('estimated_effort', 'MEDIUM'),
                    risk_reduction=recommendation.get('risk_reduction', 0.5),
                    implementation_cost=recommendation.get('implementation_cost'),
                    time_to_fix=recommendation.get('time_to_fix'),
                    metadata=recommendation.get('metadata', {})
                )
                self.recommendations.append(rec_obj)
            else:
                self.recommendations.append(recommendation)
        else:
            self.recommendations.append(recommendation)
    
    def add_agent_contribution(self, agent_id: str, agent_name: str, 
                              confidence: float = 0.5, evidence_count: int = 0,
                              analysis_time_ms: float = 0.0) -> AgentContribution:
        """Add agent contribution to the inference result"""
        contribution = AgentContribution(
            agent_id=agent_id,
            agent_name=agent_name,
            confidence=confidence,
            evidence_count=evidence_count,
            analysis_time_ms=analysis_time_ms
        )
        self.agent_contributions.append(contribution)
        return contribution
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the inference result"""
        return {
            'inference_id': self.inference_id,
            'timestamp': self.timestamp.isoformat(),
            'threat_level': self.threat_level,
            'confidence': self.confidence,
            'threat_type': self.threat_type.value if isinstance(self.threat_type, ThreatType) else str(self.threat_type),
            'severity': self.severity.value if isinstance(self.severity, ThreatSeverity) else str(self.severity),
            'evidence_count': len(self.evidence),
            'recommendation_count': len(self.recommendations),
            'agent_count': len(self.agent_contributions),
            'target_url': self.target_url
        }
    
    def is_critical(self) -> bool:
        """Check if the inference result represents a critical threat"""
        return (self.severity == ThreatSeverity.CRITICAL or 
                (self.threat_level >= 0.8 and self.confidence >= 0.7))
    
    def requires_immediate_action(self) -> bool:
        """Check if the inference result requires immediate action"""
        return (self.severity in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH] or
                self.threat_level >= 0.7)
    
    def get_top_recommendations(self, limit: int = 5) -> List[Union[SecurityRecommendation, Dict[str, Any]]]:
        """Get top priority recommendations"""
        # Sort by priority (critical, high, medium, low)
        priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        
        def get_priority(rec):
            if isinstance(rec, SecurityRecommendation):
                return priority_order.get(rec.priority, 3)
            elif isinstance(rec, dict):
                return priority_order.get(rec.get('priority', 'MEDIUM'), 3)
            return 3
        
        sorted_recs = sorted(self.recommendations, key=get_priority)
        return sorted_recs[:limit]
    
    def get_evidence_by_severity(self, severity: Union[str, ThreatSeverity]) -> List[Union[SecurityEvidence, Dict[str, Any]]]:
        """Get evidence filtered by severity"""
        if isinstance(severity, str):
            try:
                severity = ThreatSeverity(severity)
            except ValueError:
                # If invalid severity string, return empty list
                return []
        
        filtered = []
        for evidence in self.evidence:
            if isinstance(evidence, SecurityEvidence):
                if evidence.severity == severity:
                    filtered.append(evidence)
            elif isinstance(evidence, dict):
                # Try to get severity value from dict
                ev_severity = evidence.get('severity')
                if ev_severity == severity.value:
                    filtered.append(evidence)
        
        return filtered


# Factory function for creating inference results
def create_inference_result(
    inference_id: str,
    threat_level: float,
    confidence: float,
    threat_type: Union[str, ThreatType],
    severity: Union[str, ThreatSeverity],
    target_url: str = "",
    **kwargs
) -> InferenceResult:
    """
    Factory function to create InferenceResult with common defaults.
    
    Args:
        inference_id: Unique identifier for the inference
        threat_level: Numeric threat level (0-1)
        confidence: Confidence score (0-1)
        threat_type: Type of threat detected
        severity: Severity of the threat
        target_url: URL or target of the analysis
        **kwargs: Additional keyword arguments for InferenceResult
    
    Returns:
        InferenceResult: New inference result instance
    """
    return InferenceResult(
        inference_id=inference_id,
        threat_level=threat_level,
        confidence=confidence,
        threat_type=threat_type,
        severity=severity,
        target_url=target_url,
        **kwargs
    )