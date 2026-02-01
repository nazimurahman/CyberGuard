"""
Base Agent Implementation for CyberGuard Security System
=======================================================

This module defines the abstract base class for all security agents in the CyberGuard system.
It provides common functionality, mHC (Manifold-Constrained Hyper-Connections) integration, 
and the foundation for specialized security agents.

Key Features:
------------
1. Abstract analysis method that all agents must implement
2. Confidence tracking and updating mechanism based on performance
3. Memory management with bounded storage (FIFO buffer)
4. mHC integration for multi-agent coordination and communication
5. Reasoning state generation for representing agent's current understanding
6. Threat escalation logic for determining when to take immediate action

Design Principles (SOLID applied to agent architecture):
-----------------
- Single Responsibility: Each agent focuses on one specific security domain
- Open/Closed: Extensible through inheritance without modifying base class
- Interface Segregation: Clean abstract interfaces for each agent type
- Dependency Inversion: Depend on abstractions (SecurityAgent), not concrete implementations
"""

# Import abstract base class functionality for defining interfaces
from abc import ABC, abstractmethod
# Import comprehensive type hints for better code documentation and IDE support
from typing import Dict, List, Any, Optional, Tuple, Union
# Import time module for timestamping and performance tracking
import time
# Import numpy for numerical operations and fallback when PyTorch is unavailable
import numpy as np
# Import dataclass decorator for creating structured data containers
from dataclasses import dataclass, field
# Import Enum for type-safe constant definitions
from enum import Enum
# Import hashlib for consistent hash generation (better than built-in hash)
import hashlib
# Import warnings module for displaying non-critical alerts
import warnings

# Check for PyTorch availability with graceful fallback mechanism
# PyTorch is preferred for tensor operations and neural network functionality
try:
    # Attempt to import PyTorch libraries
    import torch  # Main PyTorch tensor library
    import torch.nn as nn  # Neural network module from PyTorch
    # Set flag indicating PyTorch is successfully imported
    TORCH_AVAILABLE = True
except ImportError:
    # PyTorch is not available - create dummy implementations to prevent crashes
    # Create a dummy tensor class that mimics PyTorch tensor interface
    class DummyTensor:
        # Initialize a placeholder tensor object
        def __init__(self, *args, **kwargs):
            # Store empty data placeholder
            self.data = []
        # Return zero norm for dummy tensor
        def norm(self):
            return 0.0
        # Return zero length for dummy tensor
        def __len__(self):
            return 0
        # Return self as clone (no actual cloning needed for dummy)
        def clone(self):
            return self
    
    # Create a dummy torch module that mimics PyTorch functionality
    class DummyTorch:
        # Set Tensor class to our dummy implementation
        Tensor = DummyTensor
        # Create dummy tensor method
        def tensor(self, data):
            return DummyTensor()
        # Create dummy zeros method
        def zeros(self, size):
            return DummyTensor()
        # Create dummy randn method for random normal distribution
        def randn(self, size):
            return DummyTensor()
        # Create dummy concatenation method
        def cat(self, tensors):
            return DummyTensor()
        # Create dummy stack method
        def stack(self, tensors):
            return DummyTensor()
        # Create dummy dot product method returning zero
        def dot(self, a, b):
            return 0.0
    
    # Replace actual torch module with our dummy implementation
    torch = DummyTorch()
    # Create empty neural network module placeholder
    nn = type('nn', (), {})()
    # Set flag indicating PyTorch is not available
    TORCH_AVAILABLE = False
    # Display warning to inform users about limited functionality
    warnings.warn("PyTorch not available. Running in limited mode.")


class ThreatSeverity(Enum):
    """
    Enumeration class defining standardized threat severity levels.
    Using Enum ensures type safety and prevents invalid severity values.
    Each level has both a numerical value and semantic meaning.
    """
    # Information-only findings, no immediate action required
    INFORMATIONAL = 0
    # Minor security issues that should be noted but don't require immediate action
    LOW = 1
    # Moderate security risks that should be addressed soon
    MEDIUM = 2
    # Serious security vulnerabilities requiring prompt attention
    HIGH = 3
    # Immediate threats that require blocking or emergency response
    CRITICAL = 4


class AgentState(Enum):
    """
    Enumeration class defining possible operational states of a security agent.
    This helps in monitoring agent health and managing agent lifecycle.
    """
    # Agent is ready and waiting for new analysis tasks
    IDLE = "idle"
    # Agent is currently processing security data
    ANALYZING = "analyzing"
    # Agent is updating its internal models or patterns
    TRAINING = "training"
    # Agent has encountered an error and may need intervention
    ERROR = "error"
    # Agent has been permanently stopped
    SHUTDOWN = "shutdown"


@dataclass
class SecurityFinding:
    """
    Data class representing a standardized security finding.
    Using @dataclass automatically generates __init__, __repr__, and comparison methods.
    This ensures all agents produce findings in a consistent format.
    """
    # Basic identification fields for tracking and reference
    # Unique identifier for this specific finding (UUID format recommended)
    finding_id: str
    # Which agent created this finding (references the agent's ID)
    agent_id: str
    # Unix timestamp when the finding was created (float for precision)
    timestamp: float
    
    # Content fields describing the finding
    # Short, human-readable title summarizing the finding
    title: str
    # Detailed description of what was found and why it's significant
    description: str
    # How severe this finding is (from ThreatSeverity enum)
    severity: ThreatSeverity
    # How confident the agent is in this finding (0.0 to 1.0)
    confidence: float
    
    # Technical details for security analysts and automated systems
    # Category of threat (e.g., "XSS", "SQLi", "BruteForce")
    threat_type: str
    # Where the threat was detected (e.g., "/login.php", "User-Agent header")
    location: str
    # Specific evidence that triggered the detection
    evidence: str
    # Additional structured data relevant to this finding
    context: Dict[str, Any]
    
    # Metadata for response and reference
    # Recommended action to address this finding
    recommendation: str
    # External references like CVE IDs, documentation URLs
    references: List[str]
    # Flag indicating if human review is recommended
    requires_human_review: bool = False


class SecurityAgent(ABC):
    """
    Abstract base class defining the interface and common functionality
    for all CyberGuard security agents. This implements the Template Method
    pattern where subclasses provide specific analysis implementations.
    
    Key Responsibilities:
    1. Define standard interface for all security agents
    2. Manage agent state and lifecycle
    3. Track confidence and performance metrics
    4. Provide memory system for learning from past findings
    5. Generate reasoning states for multi-agent coordination
    6. Implement threat escalation logic
    """
    
    def __init__(self, 
                 agent_id: str, 
                 name: str, 
                 description: str,
                 state_dim: int = 512,
                 memory_size: int = 1000):
        """
        Constructor for initializing a new security agent instance.
        
        Parameters:
        agent_id: Unique string identifier for this agent instance
        name: Human-readable display name for the agent
        description: Brief explanation of what this agent specializes in
        state_dim: Dimensionality of the reasoning state vector (default 512)
        memory_size: Maximum number of findings to retain in memory (default 1000)
        """
        
        # Core identification attributes - immutable agent properties
        self.agent_id = agent_id  # Unique identifier for agent tracking
        self.name = name  # Display name for logs and UI
        self.description = description  # Agent's specialization description
        self.version = "1.0.0"  # Version for compatibility tracking
        
        # State management attributes - track agent operational status
        self.state = AgentState.IDLE  # Start in idle state
        self.state_dim = state_dim  # Dimension for mHC coordination vectors
        
        # Initialize reasoning state vector based on available libraries
        if TORCH_AVAILABLE:
            # Use PyTorch tensor for efficient vector operations if available
            self.reasoning_state = torch.zeros(state_dim)
        else:
            # Fallback to numpy array when PyTorch is not installed
            self.reasoning_state = np.zeros(state_dim)
        
        # Performance tracking attributes - measure agent effectiveness
        self.confidence = 0.5  # Initial neutral confidence (0.0 to 1.0)
        self.uncertainty_threshold = 0.3  # Confidence below this is considered uncertain
        self.analysis_count = 0  # Counter for total analyses performed
        self.successful_analyses = 0  # Counter for analyses with confidence above threshold
        
        # Memory system attributes - bounded storage for past findings
        # Ensure minimum memory size of 10 to maintain basic functionality
        self.memory_size = max(10, memory_size)
        # Type-annotated list for storing memory entries as dictionaries
        self.memory: List[Dict[str, Any]] = []
        # Type-annotated dictionary for quick finding lookup by ID
        self.memory_indices: Dict[str, int] = {}
        
        # mHC (Manifold-Constrained Hyper-Connections) integration
        # Weights for multi-agent coordination (set by orchestrator)
        self.mhc_weights = None
        
        # Statistics and metrics dictionary for performance monitoring
        self.metrics = {
            'total_analyses': 0,  # Total number of analyses performed
            'avg_confidence': 0.0,  # Average confidence across all analyses
            'avg_processing_time': 0.0,  # Average time taken per analysis
            'threats_detected': 0,  # Count of actual threats detected
            'false_positives': 0,  # Count of incorrect threat detections
            'false_negatives': 0  # Count of missed threats
        }
        
        # Timing attributes for monitoring and debugging
        self.created_at = time.time()  # Record when agent was created
        self.last_analysis_time = None  # Track when last analysis occurred
        
        # Initialize agent-specific knowledge (patterns, models, rules)
        self._initialize_agent()
        
        # Print confirmation message with agent details
        print(f"Initialized agent: {self.name} ({self.agent_id})")
    
    def _initialize_agent(self) -> None:
        """
        Protected method for agent-specific initialization.
        This is a hook method that subclasses can override to load their
        specific resources like threat patterns, machine learning models,
        or rule databases.
        
        The base implementation does nothing, expecting subclasses to
        provide their own initialization logic if needed.
        """
        # Base implementation is intentionally empty
        # Subclasses should override to initialize their specific resources
        # Example: Load threat signature database, initialize ML model, etc.
        pass
    
    @abstractmethod
    def analyze(self, security_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Abstract method defining the core analysis interface.
        Every concrete security agent MUST implement this method.
        
        Parameters:
        security_data: Dictionary containing security-related data to analyze.
                       Typical structure includes:
                       - 'url': Request URL
                       - 'headers': HTTP headers dictionary
                       - 'body': Request body content
                       - 'method': HTTP method (GET, POST, etc.)
                       - 'source_ip': Client IP address
                       - 'timestamp': Request timestamp
                       - Agent-specific additional fields
        
        Returns:
        Dictionary containing analysis results with structure:
        - 'agent_id': Identifier of analyzing agent
        - 'agent_name': Human-readable agent name
        - 'findings': List of SecurityFinding objects
        - 'threat_level': Overall threat score (0.0 to 1.0)
        - 'certainty': Agent's confidence in analysis (0.0 to 1.0)
        - 'reasoning_state': Current reasoning vector for mHC
        - 'processing_time': Analysis duration in seconds
        - 'recommendations': List of suggested actions
        
        This method represents the agent's specialized expertise and is
        called by the orchestrator for each security event.
        """
        # Abstract method - no implementation in base class
        # Forces subclasses to provide their own analysis logic
        pass
    
    def update_confidence(self, analysis_result: Dict[str, Any]) -> float:
        """
        Updates the agent's self-confidence based on analysis performance.
        Confidence is a measure of how reliable the agent's judgments are.
        
        Confidence evolves using an exponential moving average that balances:
        1. Current analysis certainty
        2. Historical success rate
        3. Smoothing to prevent rapid fluctuations
        
        Parameters:
        analysis_result: Dictionary returned by the analyze() method
        
        Returns:
        Updated confidence value between 0.0 and 1.0
        """
        
        # Extract certainty value from analysis result
        # Default to 0.5 (neutral) if certainty is not provided
        certainty = analysis_result.get('certainty', 0.5)
        
        # Validate certainty is within valid range [0.0, 1.0]
        certainty = max(0.0, min(1.0, certainty))
        
        # Update analysis counters and metrics
        self.analysis_count += 1
        self.metrics['total_analyses'] = self.analysis_count
        
        # Count as successful if certainty exceeds uncertainty threshold
        if certainty > self.uncertainty_threshold:
            self.successful_analyses += 1
        
        # Calculate success rate with safe division (avoid divide-by-zero)
        # If no analyses yet, assume 50% success rate
        success_rate = (self.successful_analyses / self.analysis_count 
                       if self.analysis_count > 0 else 0.5)
        
        # Exponential Moving Average (EMA) parameters
        alpha = 0.9  # Smoothing factor - higher alpha gives more weight to history
        
        # Combine current certainty with historical success rate
        current_evidence = (certainty + success_rate) / 2.0
        
        # Apply exponential moving average formula:
        # new_confidence = alpha * old_confidence + (1-alpha) * new_evidence
        self.confidence = alpha * self.confidence + (1 - alpha) * current_evidence
        
        # Ensure confidence stays within reasonable bounds
        # Minimum 0.1 prevents complete loss of confidence
        # Maximum 0.99 prevents overconfidence
        self.confidence = max(0.1, min(0.99, self.confidence))
        
        # Update average confidence metric
        if self.analysis_count == 1:
            # First analysis: average is just the certainty
            self.metrics['avg_confidence'] = certainty
        else:
            # Update running average: (old_avg * (n-1) + new_value) / n
            self.metrics['avg_confidence'] = (
                (self.metrics['avg_confidence'] * (self.analysis_count - 1) + certainty) 
                / self.analysis_count
            )
        
        # Return updated confidence value
        return self.confidence
    
    def add_to_memory(self, finding: SecurityFinding) -> None:
        """
        Stores a security finding in the agent's memory system.
        Memory uses FIFO (First-In-First-Out) eviction policy when full.
        
        Memory enables:
        1. Learning from past analyses
        2. Pattern detection across multiple findings
        3. Context preservation for future analyses
        4. Reduction of false positives through pattern recognition
        
        Parameters:
        finding: SecurityFinding object to store in memory
        """
        
        # Check if this finding already exists in memory (by finding_id)
        if finding.finding_id in self.memory_indices:
            # Update existing entry instead of creating duplicate
            idx = self.memory_indices[finding.finding_id]
            self.memory[idx]['finding'] = finding  # Update finding data
            self.memory[idx]['timestamp'] = time.time()  # Update timestamp
            return  # Exit early since we updated existing entry
        
        # Create new memory entry with three components:
        memory_entry = {
            'finding': finding,  # The original finding object
            'timestamp': time.time(),  # When this entry was stored
            'vector': self._finding_to_vector(finding)  # Vector representation for similarity
        }
        
        # Add new entry to the end of memory list (FIFO queue)
        self.memory.append(memory_entry)
        
        # Create index entry for quick lookup by finding_id
        self.memory_indices[finding.finding_id] = len(self.memory) - 1
        
        # Check if memory exceeds maximum capacity
        if len(self.memory) > self.memory_size:
            # Remove oldest entry (from beginning of list)
            removed = self.memory.pop(0)
            
            # Clean up index for removed entry
            if removed['finding'].finding_id in self.memory_indices:
                del self.memory_indices[removed['finding'].finding_id]
            
            # Rebuild indices for remaining entries
            # More efficient than incremental updates when many removals occur
            self.memory_indices = {
                entry['finding'].finding_id: idx 
                for idx, entry in enumerate(self.memory)
            }
    
    def _finding_to_vector(self, finding: SecurityFinding) -> Union[torch.Tensor, np.ndarray]:
        """
        Converts a SecurityFinding object to a numerical vector representation.
        This enables mathematical operations on findings (similarity, clustering).
        
        Vector encoding includes:
        1. Severity level (normalized)
        2. Threat type (one-hot encoded via hash)
        3. Confidence score
        4. Random features for remaining dimensions
        
        Parameters:
        finding: SecurityFinding object to convert
        
        Returns:
        Vector representation as either torch.Tensor or numpy.ndarray
        """
        
        # Generate consistent hash from threat type string
        # Using hashlib instead of built-in hash() for consistency across sessions
        # Take first 8 hex characters (4 bytes) of MD5 hash and convert to integer
        threat_hash = int(hashlib.md5(finding.threat_type.encode()).hexdigest()[:8], 16)
        
        # Check if PyTorch is available for tensor operations
        if TORCH_AVAILABLE:
            # Calculate normalized severity value (0.0 to 1.0)
            severity_value = finding.severity.value / 4.0
            # Create 1D tensor for severity
            severity_vector = torch.tensor([severity_value], dtype=torch.float32)
            
            # Create one-hot encoded vector for threat type
            # 10-dimensional vector with 1 at position determined by hash
            threat_vector = torch.zeros(10, dtype=torch.float32)
            threat_vector[threat_hash % 10] = 1.0
            
            # Create tensor for confidence value
            confidence_vector = torch.tensor([finding.confidence], dtype=torch.float32)
            
            # Calculate how many dimensions remain after essential features
            # Essential features: 1(severity) + 10(threat) + 1(confidence) = 12
            remaining_dims = self.state_dim - 12
            
            # Check if we have enough dimensions for all features
            if remaining_dims > 0:
                # Add random normal features to fill remaining dimensions
                random_features = torch.randn(remaining_dims, dtype=torch.float32)
                # Concatenate all feature vectors
                vector = torch.cat([
                    severity_vector,
                    threat_vector,
                    confidence_vector,
                    random_features
                ])
            else:
                # If state_dim is too small, use only essential features
                vector = torch.cat([
                    severity_vector,
                    threat_vector,
                    confidence_vector
                ])
            
            # Normalize vector to unit length for cosine similarity calculations
            norm = torch.norm(vector)  # Calculate Euclidean norm (L2 norm)
            if norm > 0:
                # Divide by norm to get unit vector (magnitude = 1)
                vector = vector / (norm + 1e-8)  # Add small epsilon to avoid division by zero
            
            return vector
        else:
            # Fallback implementation using numpy when PyTorch is unavailable
            severity_value = finding.severity.value / 4.0
            threat_vector = np.zeros(10)
            threat_vector[threat_hash % 10] = 1.0
            
            # Create list of basic features
            features = [severity_value, finding.confidence]
            remaining_dims = self.state_dim - 12
            
            if remaining_dims > 0:
                # Generate random normal values for remaining dimensions
                random_features = np.random.randn(remaining_dims)
                # Concatenate all arrays
                vector = np.concatenate([features, threat_vector, random_features])
            else:
                vector = np.concatenate([features, threat_vector])
            
            # Normalize the numpy array
            norm = np.linalg.norm(vector)  # Calculate L2 norm
            if norm > 0:
                vector = vector / (norm + 1e-8)
            
            return vector
    
    def get_reasoning_state(self) -> Union[torch.Tensor, np.ndarray]:
        """
        Generates and returns the agent's current reasoning state vector.
        The reasoning state represents the agent's current "understanding"
        of the security situation in a compact numerical form.
        
        Reasoning states are used by the mHC system for:
        1. Multi-agent coordination without sharing raw data
        2. Consensus formation between agents
        3. Anomaly detection in agent behavior
        4. Load balancing and routing decisions
        
        Returns:
        Current reasoning state vector as torch.Tensor or numpy.ndarray
        """
        
        # Check if agent has any memories to inform reasoning state
        if self.memory:
            # Get most recent memories (up to last 10 entries)
            recent_memories = self.memory[-10:]
            
            # Extract vector representations from memory entries
            memory_vectors = [entry['vector'] for entry in recent_memories]
            
            # Check if we have any vectors to process
            if memory_vectors:
                # Determine if we're using PyTorch or numpy based on first vector
                if TORCH_AVAILABLE and isinstance(memory_vectors[0], torch.Tensor):
                    # PyTorch implementation for tensor operations
                    # Stack vectors into a 2D tensor and compute mean across vectors
                    aggregated = torch.stack(memory_vectors).mean(dim=0)
                    
                    # Blend aggregated memory with current state using EMA
                    alpha = 0.7  # Weight for current state (30% weight for new info)
                    self.reasoning_state = (
                        alpha * self.reasoning_state + 
                        (1 - alpha) * aggregated
                    )
                else:
                    # Numpy implementation for array operations
                    aggregated = np.stack(memory_vectors).mean(axis=0)
                    alpha = 0.7
                    self.reasoning_state = (
                        alpha * self.reasoning_state + 
                        (1 - alpha) * aggregated
                    )
        
        # Safety check: ensure reasoning state has correct dimension
        if len(self.reasoning_state) != self.state_dim:
            # Reinitialize with correct dimension if mismatch occurs
            if TORCH_AVAILABLE and isinstance(self.reasoning_state, torch.Tensor):
                self.reasoning_state = torch.zeros(self.state_dim)
            else:
                self.reasoning_state = np.zeros(self.state_dim)
        
        # Normalize state vector to unit length for mHC stability
        if TORCH_AVAILABLE and isinstance(self.reasoning_state, torch.Tensor):
            norm = torch.norm(self.reasoning_state)
            if norm > 0:
                self.reasoning_state = self.reasoning_state / norm
            # Return a copy to prevent external modification of internal state
            return self.reasoning_state.clone()
        else:
            norm = np.linalg.norm(self.reasoning_state)
            if norm > 0:
                self.reasoning_state = self.reasoning_state / norm
            return self.reasoning_state.copy()
    
    def should_escalate(self, threat_level: float, confidence: float) -> bool:
        """
        Decision logic for determining when to escalate a finding.
        Escalation means taking immediate action (block, challenge, alert).
        
        Decision criteria based on risk assessment:
        1. Critical threats always escalate regardless of confidence
        2. High threats escalate with reasonable confidence
        3. Medium threats escalate only with high confidence (reduce false positives)
        4. Low threats typically don't escalate
        
        Parameters:
        threat_level: Normalized threat severity (0.0 to 1.0)
        confidence: Agent's confidence in the assessment (0.0 to 1.0)
        
        Returns:
        Boolean indicating whether to escalate (True) or not (False)
        """
        
        # Validate inputs to ensure they're within expected range
        threat_level = max(0.0, min(1.0, threat_level))
        confidence = max(0.0, min(1.0, confidence))
        
        # Rule 1: Critical threats (threat_level > 0.9) always escalate
        # This ensures immediate response to potentially damaging attacks
        if threat_level > 0.9:
            return True
        
        # Rule 2: High threats (threat_level > 0.7) with reasonable confidence (> 0.6)
        # Balances sensitivity and specificity for serious threats
        if threat_level > 0.7 and confidence > 0.6:
            return True
        
        # Rule 3: Medium threats (threat_level > 0.5) only with high confidence (> 0.8)
        # Reduces false positives for moderate threats
        if threat_level > 0.5 and confidence > 0.8:
            return True
        
        # Default: Don't escalate
        # Low threats (threat_level <= 0.5) typically don't require immediate action
        return False
    
    def get_similar_findings(self, 
                           query: SecurityFinding, 
                           threshold: float = 0.7) -> List[SecurityFinding]:
        """
        Performs similarity search across past findings using vector similarity.
        Uses cosine similarity between vector representations.
        
        Applications:
        1. Detect recurring attack patterns
        2. Identify false positive patterns
        3. Provide context for current analysis
        4. Support incremental learning
        
        Parameters:
        query: SecurityFinding to compare against past findings
        threshold: Minimum similarity score (0.0 to 1.0) for matches
        
        Returns:
        List of similar SecurityFinding objects (maximum 5, sorted by similarity)
        """
        
        # Early return if memory is empty
        if not self.memory:
            return []
        
        # Convert query finding to vector representation
        query_vector = self._finding_to_vector(query)
        
        # Initialize list to store similarity scores and findings
        similarities = []
        
        # Determine which memories to check
        # Limit to last 100 memories for performance, or all if fewer than 100
        check_memories = self.memory[-100:] if len(self.memory) > 100 else self.memory
        
        # Calculate similarity for each memory entry
        for entry in check_memories:
            memory_vector = entry['vector']
            
            # Calculate cosine similarity (dot product for normalized vectors)
            if TORCH_AVAILABLE and isinstance(query_vector, torch.Tensor):
                # PyTorch implementation
                similarity = torch.dot(query_vector, memory_vector).item()
            else:
                # Numpy implementation
                similarity = np.dot(query_vector, memory_vector)
            
            # Add to results if similarity meets threshold
            if similarity >= threshold:
                similarities.append((similarity, entry['finding']))
        
        # Sort results by similarity score in descending order
        similarities.sort(key=lambda x: x[0], reverse=True)
        
        # Return top 5 most similar findings (or fewer if not enough matches)
        # Extract just the finding objects from the (similarity, finding) tuples
        return [finding for _, finding in similarities[:5]]
    
    def get_status(self) -> Dict[str, Any]:
        """
        Generates comprehensive status report for agent monitoring.
        
        Used by:
        1. Orchestrator for load balancing and health checks
        2. Dashboard for real-time monitoring
        3. Debugging and performance analysis
        4. Logging and audit trails
        
        Returns:
        Dictionary containing all agent status information
        """
        
        # Calculate norm of reasoning state (indicates "activity level")
        if TORCH_AVAILABLE and isinstance(self.reasoning_state, torch.Tensor):
            reasoning_norm = torch.norm(self.reasoning_state).item()
        else:
            reasoning_norm = np.linalg.norm(self.reasoning_state)
        
        # Calculate success rate with safe division
        success_rate = (self.successful_analyses / self.analysis_count 
                       if self.analysis_count > 0 else 0.0)
        
        # Build comprehensive status dictionary
        return {
            # Identification section - basic agent info
            'agent_id': self.agent_id,
            'name': self.name,
            'description': self.description,
            'version': self.version,
            
            # Current operational state
            'state': self.state.value,  # String value of AgentState enum
            'confidence': float(self.confidence),  # Convert to float for JSON
            'reasoning_state_norm': float(reasoning_norm),  # Magnitude of reasoning
            
            # Performance metrics
            'metrics': self.metrics.copy(),  # Copy to prevent modification
            'analysis_count': self.analysis_count,
            'successful_analyses': self.successful_analyses,
            'success_rate': float(success_rate),  # Success percentage
            
            # Memory system status
            'memory_usage': len(self.memory),  # Current number of stored memories
            'memory_capacity': self.memory_size,  # Maximum memory capacity
            'memory_percentage': (len(self.memory) / self.memory_size) * 100 
                                if self.memory_size > 0 else 0.0,  # Usage percentage
            
            # Configuration parameters
            'state_dim': self.state_dim,  # Dimension of reasoning vectors
            'uncertainty_threshold': self.uncertainty_threshold,  # Confidence threshold
            
            # Timing information
            'created_at': self.created_at,  # When agent was initialized
            'last_analysis': self.last_analysis_time,  # Last analysis timestamp
            
            # System compatibility info
            'torch_available': TORCH_AVAILABLE  # Whether PyTorch is being used
        }
    
    def reset(self) -> None:
        """
        Resets agent's operational state while preserving learned knowledge.
        
        Useful for:
        1. Testing and debugging
        2. Recovering from error states
        3. Clearing temporary state between test scenarios
        4. Periodic maintenance
        
        Note: Memory (learned patterns) is NOT cleared by reset()
        """
        
        # Reset operational state to IDLE
        self.state = AgentState.IDLE
        
        # Reset reasoning state to zero vector
        if TORCH_AVAILABLE:
            self.reasoning_state = torch.zeros(self.state_dim)
        else:
            self.reasoning_state = np.zeros(self.state_dim)
        
        # Reset performance tracking (but preserve memory)
        self.confidence = 0.5  # Return to neutral confidence
        self.analysis_count = 0  # Reset analysis counter
        self.successful_analyses = 0  # Reset success counter
        
        # Reset metrics dictionary to initial values
        self.metrics = {
            'total_analyses': 0,
            'avg_confidence': 0.0,
            'avg_processing_time': 0.0,
            'threats_detected': 0,
            'false_positives': 0,
            'false_negatives': 0
        }
        
        # Reset timing information
        self.last_analysis_time = None
        
        # Log reset action
        print(f"Reset agent: {self.name}")
    
    def shutdown(self) -> None:
        """
        Gracefully shuts down the agent, performing cleanup operations.
        
        Should be called to:
        1. Release allocated resources
        2. Save state to persistent storage
        3. Close network connections
        4. Prepare for process termination
        
        In production, this would include saving memory to disk,
        closing database connections, and other cleanup tasks.
        """
        
        # Set state to SHUTDOWN to prevent new analyses
        self.state = AgentState.SHUTDOWN
        
        # Log shutdown initiation
        print(f"Shutting down agent: {self.name}")
        
        # In a production implementation, this section would:
        # 1. Serialize memory to disk for persistence
        # 2. Close any open file handles or database connections
        # 3. Release GPU memory if using CUDA
        # 4. Send final status reports to monitoring systems
        
        # Example cleanup logging (production would have actual persistence)
        print(f"   - Memory entries: {len(self.memory)}")
        print(f"   - Total analyses: {self.analysis_count}")
        print(f"   - Final confidence: {self.confidence:.3f}")
        
        # Final shutdown confirmation
        print(f"Agent {self.name} shutdown complete")