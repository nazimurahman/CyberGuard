"""
Base Agent Implementation
=======================

This module defines the abstract base class for all security agents in the CyberGuard system.
It provides common functionality, mHC integration, and the foundation for specialized agents.

Key Features:
------------
1. Abstract analysis method that all agents must implement
2. Confidence tracking and updating mechanism
3. Memory management with bounded storage
4. mHC (Manifold-Constrained Hyper-Connections) integration
5. Reasoning state generation for coordination
6. Threat escalation logic

Design Principles:
-----------------
- Single Responsibility: Each agent focuses on one domain
- Open/Closed: Extensible through inheritance
- Interface Segregation: Clean abstract interfaces
- Dependency Inversion: Depend on abstractions, not concretions
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Tuple
import torch
import torch.nn as nn
import time
import numpy as np
from dataclasses import dataclass
from enum import Enum


class ThreatSeverity(Enum):
    """Enumeration for threat severity levels"""
    INFORMATIONAL = 0  # No immediate threat, just information
    LOW = 1           # Minor security issue
    MEDIUM = 2        # Moderate security risk
    HIGH = 3          # Serious security vulnerability
    CRITICAL = 4      # Immediate threat requiring action


class AgentState(Enum):
    """Enumeration for agent operational states"""
    IDLE = "idle"            # Ready to process new tasks
    ANALYZING = "analyzing"  # Currently processing analysis
    TRAINING = "training"    # Undergoing training/learning
    ERROR = "error"          # Encountered an error
    SHUTDOWN = "shutdown"    # Agent has been shut down


@dataclass
class SecurityFinding:
    """Data class for standardized security findings across all agents"""
    # Basic identification
    finding_id: str                     # Unique identifier for this finding
    agent_id: str                       # Which agent created this finding
    timestamp: float                    # When the finding was created
    
    # Content
    title: str                          # Short descriptive title
    description: str                    # Detailed description of the finding
    severity: ThreatSeverity            # How severe is this finding
    confidence: float                   # Agent's confidence (0.0 to 1.0)
    
    # Technical details
    threat_type: str                    # Type of threat (XSS, SQLi, etc.)
    location: str                       # Where was it found (URL, header, etc.)
    evidence: str                       # Evidence or pattern that triggered detection
    context: Dict[str, Any]             # Additional context data
    
    # Metadata
    recommendation: str                 # Recommended action to take
    references: List[str]               # Reference URLs or CVE IDs
    requires_human_review: bool = False # Whether human review is needed


class SecurityAgent(ABC):
    """
    Abstract base class for all CyberGuard security agents.
    
    This class provides the foundation for specialized agents with:
    - Common analysis interface
    - Confidence management
    - Memory and state management
    - mHC integration for multi-agent coordination
    
    Every specialized agent MUST inherit from this class and implement
    the abstract `analyze` method.
    """
    
    def __init__(self, 
                 agent_id: str, 
                 name: str, 
                 description: str,
                 state_dim: int = 512,
                 memory_size: int = 1000):
        """
        Initialize a new security agent.
        
        Args:
            agent_id (str): Unique identifier for this agent (e.g., "threat_detection_001")
            name (str): Human-readable name for the agent
            description (str): What this agent specializes in
            state_dim (int): Dimension of the reasoning state vector for mHC
            memory_size (int): Maximum number of memories to store (FIFO buffer)
            
        Explanation:
        -----------
        Each agent needs a unique ID for tracking, a descriptive name for humans,
        and a state dimension that matches the mHC system's requirements.
        The memory is bounded to prevent unlimited growth and ensure stability.
        """
        
        # Core identification
        self.agent_id = agent_id          # Unique identifier (immutable)
        self.name = name                  # Human-readable name
        self.description = description    # What the agent does
        self.version = "1.0.0"            # Agent version for compatibility
        
        # State management
        self.state = AgentState.IDLE      # Current operational state
        self.state_dim = state_dim        # Dimension for mHC coordination
        self.reasoning_state = torch.zeros(state_dim)  # Current reasoning vector
        
        # Performance tracking
        self.confidence = 0.5             # Initial confidence (0.0 to 1.0)
        self.uncertainty_threshold = 0.3  # Below this, agent is uncertain
        self.analysis_count = 0           # Total analyses performed
        self.successful_analyses = 0      # Analyses with confidence > threshold
        
        # Memory system (FIFO bounded buffer)
        self.memory_size = memory_size
        self.memory = []                  # Stores past analysis results
        self.memory_indices = {}          # Quick lookup by finding ID
        
        # mHC integration
        # Note: The full mHC object is managed by the orchestrator
        # This agent only maintains its local reasoning state
        self.mhc_weights = None           # Will be set by orchestrator
        
        # Statistics and metrics
        self.metrics = {
            'total_analyses': 0,
            'avg_confidence': 0.0,
            'avg_processing_time': 0.0,
            'threats_detected': 0,
            'false_positives': 0,
            'false_negatives': 0
        }
        
        # Initialize agent-specific knowledge
        self._initialize_agent()
        
        print(f"✅ Initialized agent: {self.name} ({self.agent_id})")
    
    def _initialize_agent(self) -> None:
        """
        Initialize agent-specific knowledge and resources.
        
        This method is called during initialization and should be overridden
        by subclasses to load threat patterns, models, or other resources.
        
        Explanation:
        -----------
        Each agent has specialized knowledge (patterns, rules, models).
        This method provides a hook for subclasses to initialize their
        specific resources without cluttering the main constructor.
        """
        # Base implementation does nothing
        # Subclasses should override this to load their specific resources
        pass
    
    @abstractmethod
    def analyze(self, security_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze security data and return findings.
        
        This is the core method that every agent MUST implement.
        It takes security data (HTTP request, traffic log, etc.) and returns
        structured findings about potential threats or vulnerabilities.
        
        Args:
            security_data (Dict[str, Any]): Security data to analyze. Typically includes:
                - url: The URL being accessed
                - headers: HTTP headers
                - body: Request body
                - method: HTTP method
                - source_ip: Client IP address
                - timestamp: When the request occurred
                - Additional agent-specific data
                
        Returns:
            Dict[str, Any]: Analysis results including:
                - agent_id: Identifier of the analyzing agent
                - agent_name: Human-readable agent name
                - findings: List of SecurityFinding objects
                - threat_level: Overall threat score (0.0 to 1.0)
                - certainty: Agent's confidence in analysis (0.0 to 1.0)
                - reasoning_state: Current reasoning vector for mHC
                - processing_time: How long analysis took
                - recommendations: Suggested actions
                
        Explanation:
        -----------
        This method is where each agent applies its specialized expertise.
        The input format is standardized, but each agent can focus on
        different aspects of the data. For example:
        - Threat detection agent looks for attack patterns
        - Traffic anomaly agent looks for statistical anomalies
        - Compliance agent checks for regulatory violations
        
        The output MUST include a reasoning_state vector that represents
        the agent's internal reasoning process. This is crucial for mHC
        coordination between agents.
        """
        pass
    
    def update_confidence(self, analysis_result: Dict[str, Any]) -> float:
        """
        Update agent's confidence based on analysis quality.
        
        Confidence is a measure of how reliable the agent's analysis is.
        It evolves based on the agent's performance and certainty in findings.
        
        Args:
            analysis_result (Dict[str, Any]): Result from the analyze method
            
        Returns:
            float: Updated confidence value (0.0 to 1.0)
            
        Explanation:
        -----------
        Confidence management is crucial for multi-agent systems:
        1. High confidence → Agent's opinion carries more weight
        2. Low confidence → Agent's opinion carries less weight
        3. Confidence evolves based on:
           - Certainty of current analysis
           - Historical performance
           - Consistency with other agents
        
        The update uses an exponential moving average to smooth changes
        and prevent rapid fluctuations that could destabilize coordination.
        """
        
        # Extract certainty from analysis result
        # Default to 0.5 if not provided (neutral confidence)
        certainty = analysis_result.get('certainty', 0.5)
        
        # Update metrics
        self.analysis_count += 1
        self.metrics['total_analyses'] = self.analysis_count
        
        # Update success count if analysis was confident
        if certainty > self.uncertainty_threshold:
            self.successful_analyses += 1
        
        # Calculate success rate
        success_rate = self.successful_analyses / max(1, self.analysis_count)
        
        # Update confidence using exponential moving average
        # Formula: new_confidence = alpha * current_confidence + (1-alpha) * new_evidence
        alpha = 0.9  # How much to weigh historical performance (smoothing factor)
        
        # Combine certainty of current analysis with historical success rate
        current_evidence = (certainty + success_rate) / 2.0
        
        # Apply exponential moving average
        self.confidence = alpha * self.confidence + (1 - alpha) * current_evidence
        
        # Ensure confidence stays within bounds
        self.confidence = max(0.1, min(0.99, self.confidence))
        
        # Update average confidence metric
        self.metrics['avg_confidence'] = (
            (self.metrics['avg_confidence'] * (self.analysis_count - 1) + certainty) 
            / self.analysis_count
        )
        
        return self.confidence
    
    def add_to_memory(self, finding: SecurityFinding) -> None:
        """
        Add a finding to the agent's memory.
        
        Memory allows agents to:
        1. Learn from past analyses
        2. Detect recurring patterns
        3. Provide context for new analyses
        4. Generate better reasoning states
        
        Args:
            finding (SecurityFinding): The finding to remember
            
        Explanation:
        -----------
        The memory system is a FIFO (First-In-First-Out) buffer with
        bounded size. This prevents memory from growing indefinitely
        and ensures the system remains responsive.
        
        Each memory entry includes the finding and a vector representation
        that can be used for similarity search and pattern detection.
        """
        
        # Create memory entry
        memory_entry = {
            'finding': finding,
            'timestamp': time.time(),
            'vector': self._finding_to_vector(finding)
        }
        
        # Add to memory (FIFO)
        self.memory.append(memory_entry)
        
        # Index for quick lookup
        self.memory_indices[finding.finding_id] = len(self.memory) - 1
        
        # Trim memory if exceeds maximum size
        if len(self.memory) > self.memory_size:
            # Remove oldest entry
            removed = self.memory.pop(0)
            # Clean up index
            if removed['finding'].finding_id in self.memory_indices:
                del self.memory_indices[removed['finding'].finding_id]
            
            # Update remaining indices
            self.memory_indices = {
                entry['finding'].finding_id: idx 
                for idx, entry in enumerate(self.memory)
            }
    
    def _finding_to_vector(self, finding: SecurityFinding) -> torch.Tensor:
        """
        Convert a finding to a vector representation.
        
        This is used for:
        1. Memory similarity search
        2. Clustering related findings
        3. Generating reasoning states
        4. Pattern detection across time
        
        Args:
            finding (SecurityFinding): The finding to convert
            
        Returns:
            torch.Tensor: Vector representation of the finding
            
        Explanation:
        -----------
        The vector representation encodes key aspects of the finding:
        - Severity level
        - Threat type (encoded as one-hot)
        - Confidence score
        - Temporal features
        - Contextual features
        
        This allows for mathematical operations on findings (similarity,
        clustering, etc.) which is essential for advanced threat detection.
        """
        
        # Start with severity as base (normalized 0-1)
        severity_vector = torch.tensor([finding.severity.value / 4.0])
        
        # Encode threat type (simple hash-based encoding for now)
        # In production, this would use learned embeddings
        threat_hash = hash(finding.threat_type) % 1000
        threat_vector = torch.zeros(10)
        threat_vector[threat_hash % 10] = 1.0
        
        # Confidence
        confidence_vector = torch.tensor([finding.confidence])
        
        # Combine into final vector
        vector = torch.cat([
            severity_vector,
            threat_vector,
            confidence_vector,
            torch.randn(self.state_dim - 12)  # Random features for remaining dimensions
        ])
        
        # Normalize to unit length for cosine similarity
        vector = vector / (torch.norm(vector) + 1e-8)
        
        return vector
    
    def get_reasoning_state(self) -> torch.Tensor:
        """
        Get current reasoning state for mHC coordination.
        
        The reasoning state represents the agent's current "thinking"
        about the security situation. It's used by the mHC system to
        coordinate between agents without sharing raw findings.
        
        Returns:
            torch.Tensor: Current reasoning state vector
            
        Explanation:
        -----------
        The reasoning state is a compressed representation of:
        1. Recent findings and their patterns
        2. Agent's confidence level
        3. Current threat assessment
        4. Historical context
        
        This state is what gets mixed with other agents' states in the
        mHC framework. By operating on these abstract states rather than
        raw findings, mHC prevents information overload and maintains
        stable coordination.
        """
        
        # If we have recent memories, use them to inform the state
        if self.memory:
            # Get recent memories (last 10)
            recent_memories = self.memory[-10:]
            
            # Extract vectors
            memory_vectors = [entry['vector'] for entry in recent_memories]
            
            # Average the vectors (simple aggregation)
            if memory_vectors:
                aggregated = torch.stack(memory_vectors).mean(dim=0)
                
                # Blend with current state (exponential moving average)
                alpha = 0.7  # How much to weigh new information
                self.reasoning_state = (
                    alpha * self.reasoning_state + 
                    (1 - alpha) * aggregated
                )
        
        # Ensure state has correct dimension
        if len(self.reasoning_state) != self.state_dim:
            self.reasoning_state = torch.zeros(self.state_dim)
        
        # Normalize state (important for mHC stability)
        norm = torch.norm(self.reasoning_state)
        if norm > 0:
            self.reasoning_state = self.reasoning_state / norm
        
        return self.reasoning_state.clone()  # Return copy to prevent modification
    
    def should_escalate(self, threat_level: float, confidence: float) -> bool:
        """
        Determine if a finding should be escalated for immediate action.
        
        Escalation criteria:
        1. High threat level with high confidence → Immediate escalation
        2. High threat level with medium confidence → Review needed
        3. Any critical finding → Always escalate
        
        Args:
            threat_level (float): Threat severity (0.0 to 1.0)
            confidence (float): Agent's confidence (0.0 to 1.0)
            
        Returns:
            bool: True if finding should be escalated
            
        Explanation:
        -----------
        Not all findings require immediate action. This method implements
        a risk-based triage system:
        - Critical + High confidence → Block immediately
        - High + Medium confidence → Challenge (CAPTCHA, 2FA)
        - Medium → Monitor and log
        - Low → Informational only
        
        This prevents alert fatigue and focuses attention on real threats.
        """
        
        # Critical threat always escalates
        if threat_level > 0.9:
            return True
        
        # High threat with reasonable confidence
        if threat_level > 0.7 and confidence > 0.6:
            return True
        
        # Medium threat with high confidence (potential false positive)
        if threat_level > 0.5 and confidence > 0.8:
            return True
        
        return False
    
    def get_similar_findings(self, 
                           query: SecurityFinding, 
                           threshold: float = 0.7) -> List[SecurityFinding]:
        """
        Find similar past findings using vector similarity.
        
        This enables pattern detection and reduces false positives by
        identifying recurring attack patterns or similar benign traffic.
        
        Args:
            query (SecurityFinding): Finding to compare against
            threshold (float): Similarity threshold (0.0 to 1.0)
            
        Returns:
            List[SecurityFinding]: Similar past findings
            
        Explanation:
        -----------
        Uses cosine similarity between vector representations to find
        similar findings. This is useful for:
        1. Detecting attack campaigns (similar patterns over time)
        2. Identifying false positive patterns
        3. Providing context for current analysis
        4. Learning from past mistakes/successes
        """
        
        if not self.memory:
            return []
        
        # Convert query to vector
        query_vector = self._finding_to_vector(query)
        
        # Calculate similarities
        similarities = []
        for entry in self.memory[-100:]:  # Check last 100 memories
            similarity = torch.dot(query_vector, entry['vector']).item()
            if similarity >= threshold:
                similarities.append((similarity, entry['finding']))
        
        # Sort by similarity (highest first)
        similarities.sort(key=lambda x: x[0], reverse=True)
        
        # Return just the findings
        return [finding for _, finding in similarities[:5]]  # Top 5 matches
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get current agent status and metrics.
        
        Returns:
            Dict[str, Any]: Agent status including metrics, state, and configuration
            
        Explanation:
        -----------
        This provides a comprehensive view of the agent's health and
        performance. It's used by the orchestrator for load balancing,
        by the dashboard for monitoring, and for debugging.
        """
        
        return {
            # Identification
            'agent_id': self.agent_id,
            'name': self.name,
            'description': self.description,
            'version': self.version,
            
            # Current state
            'state': self.state.value,
            'confidence': self.confidence,
            'reasoning_state_norm': torch.norm(self.reasoning_state).item(),
            
            # Performance metrics
            'metrics': self.metrics.copy(),
            'analysis_count': self.analysis_count,
            'successful_analyses': self.successful_analyses,
            'success_rate': self.successful_analyses / max(1, self.analysis_count),
            
            # Memory usage
            'memory_usage': len(self.memory),
            'memory_capacity': self.memory_size,
            'memory_percentage': (len(self.memory) / self.memory_size) * 100,
            
            # Configuration
            'state_dim': self.state_dim,
            'uncertainty_threshold': self.uncertainty_threshold,
            
            # Timestamps
            'created_at': getattr(self, 'created_at', time.time()),
            'last_analysis': getattr(self, 'last_analysis_time', None)
        }
    
    def reset(self) -> None:
        """
        Reset agent to initial state (except learned knowledge).
        
        This is useful for:
        1. Testing and debugging
        2. Recovering from error states
        3. Clearing transient state while preserving learned patterns
        
        Explanation:
        -----------
        Resets metrics, confidence, and reasoning state but preserves:
        - Learned threat patterns
        - Memory of past findings
        - Configuration parameters
        
        This allows the agent to "start fresh" while retaining its
        accumulated knowledge about threat patterns.
        """
        
        # Reset state
        self.state = AgentState.IDLE
        self.reasoning_state = torch.zeros(self.state_dim)
        
        # Reset performance metrics (but keep memory)
        self.confidence = 0.5
        self.analysis_count = 0
        self.successful_analyses = 0
        
        # Reset metrics
        self.metrics = {
            'total_analyses': 0,
            'avg_confidence': 0.0,
            'avg_processing_time': 0.0,
            'threats_detected': 0,
            'false_positives': 0,
            'false_negatives': 0
        }
        
        print(f"🔄 Reset agent: {self.name}")
    
    def shutdown(self) -> None:
        """
        Gracefully shutdown the agent.
        
        This ensures:
        1. Any pending analyses are completed
        2. Memory is persisted if needed
        3. Resources are cleaned up
        4. State is saved for restart
        
        Explanation:
        -----------
        Proper shutdown is important for:
        - Data integrity (don't lose important findings)
        - Resource cleanup (close files, network connections)
        - State persistence (save for next startup)
        - Clean restarts (without corruption)
        """
        
        self.state = AgentState.SHUTDOWN
        
        # Save state if needed (in production, this would persist to disk)
        print(f"🛑 Shutting down agent: {self.name}")
        
        # Clean up resources
        # In a real implementation, this would:
        # 1. Close database connections
        # 2. Save memory to disk
        # 3. Close file handles
        # 4. Release GPU memory if using CUDA
        
        print(f"✅ Agent {self.name} shutdown complete")