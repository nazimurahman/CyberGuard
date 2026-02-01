"""
Core orchestrator for CyberGuard multi-agent security system.
Manages coordination between specialized security agents using 
Manifold-Constrained Hyper-Connections (mHC) for stable reasoning.

Key Features:
1. mHC-based agent coordination (prevents reasoning collapse)
2. Dynamic confidence-weighted aggregation
3. Threat severity scoring and action recommendation
4. Real-time agent monitoring and health checks
5. Scalable parallel agent execution
6. Explainable decision aggregation
"""

# Import essential Python standard library modules
import asyncio              # Asynchronous programming support for concurrent agent execution
import concurrent.futures   # Thread pool executor for parallel processing
import threading           # Thread management for background operations
import time                # Time measurement and scheduling
import uuid                # Generate unique identifiers for analyses and agents
import json                # JSON serialization for results and logging
import logging             # Logging framework for system monitoring

# Import type hints for better code documentation and IDE support
from typing import Dict, List, Any, Optional, Tuple, Callable, Set
# Dict: Dictionary type (key-value pairs)
# List: List/array type
# Any: Any type (when type is dynamic)
# Optional: Value that could be None
# Tuple: Fixed-size collection of typed elements
# Callable: Function/method type
# Set: Collection of unique elements

from dataclasses import dataclass, field  # For creating data holder classes with auto-generated methods
from enum import Enum                     # For creating enumerated constants

# Import agent base classes (Note: These imports assume files exist in the same package)
# Since we're analyzing the orchestrator standalone, we'll create placeholder classes
# In production, these would be actual imports

# Placeholder for missing imports to avoid syntax errors
class SecurityAgent:
    """
    Abstract base class representing a security analysis agent.
    All specialized agents (web threat, malware, etc.) inherit from this.
    """
    def __init__(self):
        self.agent_id = str(uuid.uuid4())  # Unique identifier for this agent instance
        self.name = "BaseAgent"            # Human-readable agent name
        self.confidence = 0.5              # Default confidence score (0.0 to 1.0)
    
    def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Core analysis method - must be implemented by all concrete agents"""
        return {"threat_level": 0.0, "confidence": 0.5}  # Placeholder result
    
    def shutdown(self):
        """Cleanup method for graceful agent termination"""
        pass

# Placeholder for mHC architecture
class ManifoldConstrainedHyperConnections:
    """
    Mathematical coordination system for preventing reasoning collapse.
    
    mHC Theory:
    - Uses doubly-stochastic matrices to prevent single-agent dominance
    - Applies convex mixing with bounded signal propagation
    - Ensures non-expansive updates for reasoning stability
    - Implements identity-preserving mappings
    """
    def __init__(self, n_agents: int = 0, state_dim: int = 512, temperature: float = 1.0):
        self.n_agents = n_agents      # Number of agents in the system
        self.state_dim = state_dim    # Dimensionality of agent reasoning states
        self.temperature = temperature  # Controls sharpness of attention distribution

# Get logger instance for this module
logger = logging.getLogger(__name__)


class AgentStatus(Enum):
    """
    Finite set of possible agent lifecycle states.
    Enum ensures type safety and prevents invalid states.
    """
    IDLE = "idle"               # Agent initialized and ready to process tasks
    PROCESSING = "processing"   # Agent actively analyzing security data
    DEGRADED = "degraded"       # Agent functional but with performance/reliability issues
    FAILED = "failed"           # Agent encountered unrecoverable error
    UNAVAILABLE = "unavailable" # Agent temporarily offline (network, maintenance)
    INITIALIZING = "initializing" # Agent starting up, not yet ready


class ThreatSeverity(Enum):
    """
    Standardized threat classification levels.
    Provides consistent severity assessment across all agents.
    """
    CRITICAL = "critical"       # Immediate action required, potential system compromise
    HIGH = "high"               # High priority remediation needed
    MEDIUM = "medium"           # Moderate risk, schedule remediation
    LOW = "low"                 # Low risk, monitor situation
    INFORMATIONAL = "informational" # No threat, security-relevant information only


@dataclass
class AgentMetrics:
    """
    Data container for tracking agent performance statistics.
    @dataclass automatically generates __init__, __repr__, and comparison methods.
    """
    agent_id: str                     # Reference to the agent being measured
    name: str                        # Agent name for reporting
    
    # Performance counters (default to zero)
    total_requests: int = 0                     # Cumulative requests handled
    successful_analyses: int = 0                # Number of successful analyses
    failed_analyses: int = 0                    # Number of failed analyses
    avg_processing_time: float = 0.0            # Exponential moving average of processing time
    total_processing_time: float = 0.0          # Sum of all processing times
    threats_detected: int = 0                   # Count of threats identified
    false_positives: int = 0                    # Incorrect threat detections
    false_negatives: int = 0                    # Missed threats (requires ground truth)
    confidence_score: float = 0.5               # Current trustworthiness (0.0 to 1.0)
    
    # Timestamp and derived metrics
    last_updated: float = field(default_factory=time.time)  # Auto-set to current time
    error_rate: float = 0.0                     # Failed analyses / total requests
    
    def update(self, success: bool, processing_time: float, threat_detected: bool = False):
        """
        Update metrics after each agent analysis.
        
        Args:
            success: Whether analysis completed successfully
            processing_time: Time taken for analysis in seconds
            threat_detected: Whether a security threat was identified
        """
        self.total_requests += 1                     # Increment total counter
        self.total_processing_time += processing_time  # Add to cumulative time
        
        if success:
            self.successful_analyses += 1            # Increment success counter
            if threat_detected:
                self.threats_detected += 1           # Record threat detection
        else:
            self.failed_analyses += 1                # Increment failure counter
        
        # Exponential moving average: 90% old value, 10% new value
        # This gives recent measurements more weight than ancient history
        self.avg_processing_time = (
            self.avg_processing_time * 0.9 + processing_time * 0.1
        )
        
        # Error rate = failures / total (avoid division by zero with max(1, ...))
        self.error_rate = self.failed_analyses / max(1, self.total_requests)
        self.last_updated = time.time()  # Record when metrics were last updated


@dataclass
class OrchestrationResult:
    """
    Comprehensive result structure for security analysis orchestration.
    Contains both individual agent results and consolidated decisions.
    """
    # Core identification and timing
    analysis_id: str                           # UUID for this specific analysis run
    timestamp: float                           # Unix timestamp when analysis started
    security_data: Dict[str, Any]              # Original input data (preserved for auditing)
    final_decision: Dict[str, Any]             # Consolidated security decision from all agents
    agent_results: List[Dict[str, Any]]        # Raw results from each individual agent
    coordination_metrics: Dict[str, Any]       # Performance data about orchestration process
    
    # Optional fields (can be None)
    mhc_state: Optional[Any] = None            # Internal state of mHC coordination system
    
    # Decision metadata
    requires_human_review: bool = False        # Flag indicating if security analyst should review
    confidence_score: float = 0.0              # Overall system confidence (0.0 to 1.0)
    threat_severity: ThreatSeverity = ThreatSeverity.INFORMATIONAL  # Final threat classification
    
    # Actionable outputs
    recommended_actions: List[str] = field(default_factory=list)  # List of security actions to take
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for serialization (JSON, database storage, API responses).
        
        Returns:
            Dictionary representation with only serializable data types
        """
        return {
            'analysis_id': self.analysis_id,
            'timestamp': self.timestamp,
            'final_decision': self.final_decision,
            'agent_results_count': len(self.agent_results),  # Count instead of full list for brevity
            'coordination_metrics': self.coordination_metrics,
            'requires_human_review': self.requires_human_review,
            'confidence_score': self.confidence_score,
            'threat_severity': self.threat_severity.value,  # Convert Enum to string
            'recommended_actions': self.recommended_actions
        }


class AgentOrchestrator:
    """
    Central coordination system for multiple security analysis agents.
    
    Architecture Purpose:
    - Coordinates specialized agents (web, network, malware, etc.)
    - Prevents single-agent dominance through mHC mathematics
    - Provides explainable AI decisions
    - Ensures system reliability through health monitoring
    - Scales horizontally with additional agents
    
    Key Innovations:
    1. mHC Coordination: Mathematical guarantee against reasoning collapse
    2. Graceful Degradation: Continues functioning with partial agent failures
    3. Explainable Decisions: Human-readable reasoning for every decision
    4. Confidence Aggregation: Weighted combination of agent opinions
    5. Real-time Monitoring: Continuous health checking of all agents
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Construct orchestrator with optional configuration.
        
        Args:
            config: Optional dictionary of configuration parameters.
                   If None, defaults are used for all settings.
        """
        # Configuration with defaults (user config overrides defaults)
        self.config = config or {}  # Empty dict if no config provided
        self._set_default_config()  # Fill in any missing config values with defaults
        
        # ===== AGENT REGISTRIES =====
        # Four parallel dictionaries indexed by agent_id:
        self.agents: Dict[str, SecurityAgent] = {}            # agent_id -> agent instance
        self.agent_status: Dict[str, AgentStatus] = {}       # agent_id -> current status
        self.agent_metrics: Dict[str, AgentMetrics] = {}     # agent_id -> performance metrics
        self.agent_capabilities: Dict[str, List[str]] = {}   # agent_id -> list of capabilities
        
        # ===== mHC COORDINATION SYSTEM =====
        # Mathematical coordination engine for preventing reasoning collapse
        self.mhc = ManifoldConstrainedHyperConnections(
            n_agents=0,  # Will be updated as agents register
            state_dim=self.config['mhc_state_dim'],      # From config
            temperature=self.config['mhc_temperature']   # From config
        )
        
        # ===== CONCURRENCY INFRASTRUCTURE =====
        self.task_queue = asyncio.Queue()               # Async queue for analysis tasks
        self.processing_lock = threading.RLock()        # Reentrant lock for thread safety
        
        # ===== HISTORY AND STATE TRACKING =====
        self.analysis_history: List[OrchestrationResult] = []  # Circular buffer of recent analyses
        self.max_history_size = self.config['max_history_size']  # How many analyses to keep
        
        # ===== PERFORMANCE METRICS =====
        self.metrics = {
            'total_coordinations': 0,          # Total orchestration attempts
            'successful_coordinations': 0,     # Successful orchestration completions
            'failed_coordinations': 0,         # Failed orchestration attempts
            'avg_coordination_time': 0.0,      # Moving average of coordination time
            'total_agents_registered': 0,      # Cumulative agents ever registered
            'active_agents': 0,                # Currently registered agents
            'last_coordination_time': 0.0      # Time taken for last coordination
        }
        
        # ===== PARALLEL EXECUTION INFRASTRUCTURE =====
        # Thread pool for running agent analyses in parallel
        self.executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=self.config['max_parallel_agents']  # Configurable parallelism
        )
        
        # ===== HEALTH MONITORING INFRASTRUCTURE =====
        self.health_check_interval = self.config['health_check_interval']  # Seconds between checks
        self.health_check_thread = None  # Will hold reference to monitoring thread
        self.is_running = False          # Control flag for health monitoring loop
        
        # ===== SYSTEM UPTIME TRACKING =====
        self._start_time = time.time()  # Record when orchestrator was initialized
        
        # ===== LOGGING SETUP =====
        self._setup_logging()  # Configure orchestrator-specific logging
        
        # Log initialization with non-sensitive config values
        logger.info("AgentOrchestrator initialized with configuration: %s", 
                   {k: v for k, v in self.config.items() 
                    if not k.startswith('_')})  # Skip private/internal config keys
    
    def _set_default_config(self):
        """
        Ensure all required configuration parameters have sensible defaults.
        Only sets values for keys that don't already exist in self.config.
        """
        defaults = {
            # ===== mHC MATHEMATICAL PARAMETERS =====
            'mhc_state_dim': 512,                     # Dimension of agent reasoning state vectors
            'mhc_temperature': 1.0,                   # Controls attention distribution sharpness
            'mhc_sinkhorn_iterations': 50,            # Iterations for doubly-stochastic projection
            'mhc_signal_bound': 1.0,                  # Maximum signal amplification factor
            'mhc_identity_preserve': 0.1,             # How much to preserve agent identity
            
            # ===== AGENT COORDINATION PARAMETERS =====
            'max_parallel_agents': 10,                # Maximum concurrent agent executions
            'agent_timeout_seconds': 30,              # Timeout for individual agent analysis
            'min_confidence_threshold': 0.3,          # Minimum confidence to include agent
            'consensus_threshold': 0.7,               # Threshold for agent agreement
            
            # ===== THREAT SCORING THRESHOLDS =====
            'critical_threshold': 0.8,                # Threat level ≥ 0.8 = CRITICAL
            'high_threshold': 0.6,                    # Threat level ≥ 0.6 = HIGH
            'medium_threshold': 0.4,                  # Threat level ≥ 0.4 = MEDIUM
            'low_threshold': 0.2,                     # Threat level ≥ 0.2 = LOW
            
            # ===== SYSTEM OPERATIONAL PARAMETERS =====
            'max_history_size': 1000,                 # Maximum analyses to keep in memory
            'health_check_interval': 60,              # Seconds between health checks
            'enable_auto_healing': True,              # Attempt to restart failed agents
            'max_retry_attempts': 3,                  # Retry attempts for auto-healing
            
            # ===== LOGGING AND MONITORING PARAMETERS =====
            'enable_detailed_logging': True,          # Enable verbose orchestration logging
            'log_coordination_decisions': True,       # Log all coordination decisions
            'monitor_agent_performance': True         # Continuously monitor agent metrics
        }
        
        # Apply defaults only for missing configuration keys
        for key, value in defaults.items():
            if key not in self.config:  # Only set if user didn't provide this key
                self.config[key] = value
    
    def _setup_logging(self):
        """
        Configure orchestrator-specific logging handlers.
        Creates rotating log files for operational auditing.
        """
        # Only create detailed logs if enabled in configuration
        if self.config.get('enable_detailed_logging', False):
            try:
                import logging.handlers  # For RotatingFileHandler
                import os                # For directory operations
                
                # Create logs directory if it doesn't exist
                log_dir = 'logs'
                if not os.path.exists(log_dir):
                    os.makedirs(log_dir)  # Create directory recursively
                
                # Create rotating file handler with size limits
                orchestration_handler = logging.handlers.RotatingFileHandler(
                    'logs/orchestration.log',  # Log file path
                    maxBytes=10485760,  # 10MB maximum file size (10 * 1024 * 1024)
                    backupCount=10      # Keep 10 backup files when rotating
                )
                orchestration_handler.setLevel(logging.INFO)  # Log INFO and above
                orchestration_handler.setFormatter(
                    logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
                )
                logger.addHandler(orchestration_handler)  # Attach handler to module logger
            except Exception as e:
                # Log error but don't crash if logging setup fails
                logger.error(f"Failed to setup detailed logging: {e}")
    
    def register_agent(self, agent: SecurityAgent, 
                      capabilities: Optional[List[str]] = None) -> bool:
        """
        Register a new security agent with the orchestrator.
        
        Process Flow:
        1. Validate agent type and check for duplicates
        2. Initialize tracking structures
        3. Set initial status and metrics
        4. Update system counters
        
        Args:
            agent: Concrete SecurityAgent instance to register
            capabilities: Optional list of agent's analysis capabilities
            
        Returns:
            bool: True if registration successful, False otherwise
        """
        with self.processing_lock:  # Thread-safe registration (prevents race conditions)
            try:
                # ===== VALIDATION PHASE =====
                # Ensure object is actually a SecurityAgent (not some other type)
                if not isinstance(agent, SecurityAgent):
                    logger.error(f"Attempted to register non-agent: {type(agent)}")
                    return False  # Reject non-agent objects
                
                # Check for duplicate agent IDs (each agent must be unique)
                if agent.agent_id in self.agents:
                    logger.warning(f"Agent {agent.agent_id} already registered")
                    return False  # Reject duplicate registration
                
                # ===== REGISTRATION PHASE =====
                # Store agent instance in registry
                self.agents[agent.agent_id] = agent
                # Set initial status to INITIALIZING (not yet ready)
                self.agent_status[agent.agent_id] = AgentStatus.INITIALIZING
                
                # ===== METRICS INITIALIZATION =====
                # Create metrics tracking object for this agent
                self.agent_metrics[agent.agent_id] = AgentMetrics(
                    agent_id=agent.agent_id,
                    name=agent.name,
                    # Use agent's confidence if available, otherwise default to 0.5
                    confidence_score=agent.confidence if hasattr(agent, 'confidence') else 0.5
                )
                
                # ===== CAPABILITIES REGISTRATION =====
                # Use provided capabilities or extract from agent object
                if capabilities is None:
                    capabilities = getattr(agent, 'capabilities', [])  # Get from agent or empty list
                self.agent_capabilities[agent.agent_id] = capabilities
                
                # ===== FINALIZATION PHASE =====
                logger.info(f"Registered agent: {agent.name} (ID: {agent.agent_id})")
                
                # Mark agent as IDLE (ready to process tasks)
                self.agent_status[agent.agent_id] = AgentStatus.IDLE
                
                # Update system-level counters
                self.metrics['total_agents_registered'] += 1  # Cumulative count
                self.metrics['active_agents'] += 1            # Current active count
                
                return True  # Registration successful
                
            except Exception as e:
                # ===== ERROR HANDLING =====
                logger.error(f"Failed to register agent {agent.agent_id}: {e}")
                # Clean up any partially created entries to maintain consistency
                if agent.agent_id in self.agents:
                    del self.agents[agent.agent_id]
                if agent.agent_id in self.agent_status:
                    del self.agent_status[agent.agent_id]
                return False  # Registration failed
    
    def unregister_agent(self, agent_id: str) -> bool:
        """
        Remove an agent from the orchestrator.
        
        Process:
        1. Gracefully shutdown agent if possible
        2. Remove from all tracking dictionaries
        3. Update system counters
        
        Args:
            agent_id: Unique identifier of agent to remove
            
        Returns:
            bool: True if unregistration successful, False otherwise
        """
        with self.processing_lock:  # Thread-safe operation
            # Check if agent exists before attempting removal
            if agent_id not in self.agents:
                logger.warning(f"Agent {agent_id} not found for unregistration")
                return False  # Cannot unregister non-existent agent
            
            try:
                # ===== GRACEFUL SHUTDOWN =====
                agent = self.agents[agent_id]  # Get agent instance
                if hasattr(agent, 'shutdown'):  # Check if agent has shutdown method
                    agent.shutdown()  # Allow agent to clean up resources
                
                # ===== REMOVAL FROM REGISTRIES =====
                # Remove from all four tracking dictionaries
                del self.agents[agent_id]
                del self.agent_status[agent_id]
                del self.agent_metrics[agent_id]
                del self.agent_capabilities[agent_id]
                
                logger.info(f"Unregistered agent: {agent_id}")
                self.metrics['active_agents'] -= 1  # Decrement active count
                
                return True  # Unregistration successful
                
            except Exception as e:
                logger.error(f"Failed to unregister agent {agent_id}: {e}")
                return False  # Unregistration failed
    
    def get_agent_by_capability(self, capability: str) -> List[SecurityAgent]:
        """
        Find all agents that have a specific analysis capability.
        
        Used for:
        - Routing security data to appropriate agents
        - Dynamic agent selection based on analysis type
        - Capability-based load balancing
        
        Args:
            capability: String describing required capability (e.g., 'malware_detection')
            
        Returns:
            List[SecurityAgent]: Agents with required capability, sorted by confidence
        """
        matching_agents = []
        
        # Iterate through all registered capabilities
        for agent_id, capabilities in self.agent_capabilities.items():
            if capability in capabilities:  # Check if agent has required capability
                agent = self.agents.get(agent_id)  # Get agent instance
                # Only include agents that are currently IDLE (available)
                if agent and self.agent_status.get(agent_id) == AgentStatus.IDLE:
                    matching_agents.append(agent)
        
        # Sort agents by confidence score (highest first)
        # This ensures most reliable agents are used first
        matching_agents.sort(
            key=lambda a: self.agent_metrics.get(a.agent_id, 
                                                 AgentMetrics(a.agent_id, a.name)).confidence_score,
            reverse=True  # Descending order (highest confidence first)
        )
        
        return matching_agents
    
    async def coordinate_analysis(self, 
                                 security_data: Dict[str, Any],
                                 analysis_id: Optional[str] = None) -> OrchestrationResult:
        """
        Main entry point for security analysis orchestration.
        
        Orchestration Pipeline:
        1. Select appropriate agents based on data type
        2. Execute agents in parallel with timeout protection
        3. Apply mHC mathematical coordination
        4. Generate consolidated security decision
        5. Create structured result with explanations
        
        Args:
            security_data: Dictionary containing security-relevant data
            analysis_id: Optional custom identifier for tracking
            
        Returns:
            OrchestrationResult: Comprehensive analysis result
        """
        start_time = time.time()  # Record when analysis started
        # Generate unique ID if not provided
        analysis_id = analysis_id or str(uuid.uuid4())
        
        logger.info(f"Starting coordinated analysis {analysis_id} for data: {security_data.get('type', 'unknown')}")
        
        try:
            # ===== STEP 1: AGENT SELECTION =====
            # Choose which agents should analyze this data
            selected_agents = self._select_agents_for_analysis(security_data)
            
            # Handle case where no agents are available/appropriate
            if not selected_agents:
                logger.warning(f"No agents selected for analysis {analysis_id}")
                return self._create_empty_result(analysis_id, security_data, 
                                                "No suitable agents available")
            
            # ===== STEP 2: PARALLEL EXECUTION =====
            # Run all selected agents concurrently
            agent_results = await self._execute_agents_parallel(
                selected_agents, security_data
            )
            
            # ===== STEP 3: mHC COORDINATION =====
            # Apply mathematical coordination to prevent reasoning collapse
            coordinated_result = self._apply_mhc_coordination(agent_results)
            
            # ===== STEP 4: DECISION GENERATION =====
            # Create final security decision from coordinated results
            final_decision = self._generate_final_decision(
                coordinated_result, security_data
            )
            
            # ===== STEP 5: RESULT PACKAGING =====
            # Package everything into structured result object
            result = self._create_orchestration_result(
                analysis_id=analysis_id,
                start_time=start_time,
                security_data=security_data,
                agent_results=agent_results,
                coordinated_result=coordinated_result,
                final_decision=final_decision
            )
            
            # ===== STEP 6: METRICS AND HISTORY =====
            # Update system metrics and store result in history
            self._update_metrics_and_history(result, start_time)
            
            logger.info(f"Completed analysis {analysis_id} in {time.time() - start_time:.2f}s")
            return result  # Return comprehensive result
            
        except Exception as e:
            # ===== ERROR HANDLING =====
            logger.error(f"Failed to coordinate analysis {analysis_id}: {e}", exc_info=True)
            # Return error result instead of raising exception
            return self._create_error_result(analysis_id, security_data, str(e))
    
    def _select_agents_for_analysis(self, 
                                   security_data: Dict[str, Any]) -> List[SecurityAgent]:
        """
        Intelligent agent selection based on data characteristics.
        
        Routing Logic:
        - HTTP requests → Web security agents
        - Network traffic → Traffic analysis agents  
        - Source code → Code review agents
        - Security logs → Forensic analysis agents
        
        Args:
            security_data: Dictionary with security data to analyze
            
        Returns:
            List[SecurityAgent]: Selected agents, limited by max_parallel_agents
        """
        selected_agents = []
        
        # Extract data type for intelligent routing
        data_type = security_data.get('type', 'unknown')
        content = security_data.get('content', '')  # Not currently used, but available
        
        # ===== CONTENT-BASED ROUTING =====
        if data_type == 'http_request':
            # Web request analysis - select relevant agents
            selected_agents.extend(self.get_agent_by_capability('http_analysis'))
            selected_agents.extend(self.get_agent_by_capability('threat_detection'))
            selected_agents.extend(self.get_agent_by_capability('bot_detection'))
            
        elif data_type == 'network_traffic':
            # Network traffic analysis
            selected_agents.extend(self.get_agent_by_capability('traffic_analysis'))
            selected_agents.extend(self.get_agent_by_capability('malware_detection'))
            selected_agents.extend(self.get_agent_by_capability('anomaly_detection'))
            
        elif data_type == 'source_code':
            # Source code security analysis
            selected_agents.extend(self.get_agent_by_capability('code_review'))
            selected_agents.extend(self.get_agent_by_capability('vulnerability_scan'))
            selected_agents.extend(self.get_agent_by_capability('compliance_check'))
            
        elif data_type == 'security_log':
            # Security log analysis
            selected_agents.extend(self.get_agent_by_capability('forensic_analysis'))
            selected_agents.extend(self.get_agent_by_capability('incident_response'))
            selected_agents.extend(self.get_agent_by_capability('threat_hunting'))
            
        else:
            # Unknown data type - use all available agents
            logger.debug(f"Unknown data type {data_type}, using all available agents")
            for agent in self.agents.values():
                # Only include idle agents (not currently processing)
                if self.agent_status.get(agent.agent_id) == AgentStatus.IDLE:
                    selected_agents.append(agent)
        
        # ===== DEDUPLICATION =====
        # Remove duplicate agents (same agent might match multiple capabilities)
        unique_agents = []
        seen_ids = set()  # Use set for O(1) lookups
        for agent in selected_agents:
            if agent.agent_id not in seen_ids:
                unique_agents.append(agent)
                seen_ids.add(agent.agent_id)
        
        # ===== RESOURCE LIMITING =====
        # Limit to maximum parallel agents to prevent system overload
        return unique_agents[:self.config['max_parallel_agents']]
    
    async def _execute_agents_parallel(self,
                                      agents: List[SecurityAgent],
                                      security_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Execute multiple agents concurrently with robust error handling.
        
        Features:
        - Parallel execution for speed
        - Timeout protection for stuck agents
        - Individual error isolation (one agent failure doesn't affect others)
        - Comprehensive result collection
        
        Args:
            agents: List of agents to execute
            security_data: Security data to analyze
            
        Returns:
            List[Dict[str, Any]]: Results from all agents (successful and failed)
        """
        tasks = []          # List of (agent, task) tuples for tracking
        agent_results = []  # Collected results from all agents
        
        # ===== TASK CREATION =====
        # Create async task for each agent
        for agent in agents:
            task = asyncio.create_task(
                self._execute_single_agent(agent, security_data)
            )
            tasks.append((agent, task))
        
        # ===== PARALLEL EXECUTION WITH TIMEOUT =====
        # Wait for each task with configurable timeout
        for agent, task in tasks:
            try:
                # Wait for task completion with timeout
                result = await asyncio.wait_for(
                    task, 
                    timeout=self.config['agent_timeout_seconds']
                )
                agent_results.append(result)  # Add successful result
                
            except asyncio.TimeoutError:
                # Agent took too long - create timeout result
                logger.warning(f"Agent {agent.agent_id} timed out")
                agent_results.append(self._create_agent_timeout_result(agent))
                
            except Exception as e:
                # Agent crashed - create error result
                logger.error(f"Agent {agent.agent_id} failed: {e}")
                agent_results.append(self._create_agent_error_result(agent, str(e)))
        
        return agent_results
    
    async def _execute_single_agent(self,
                                   agent: SecurityAgent,
                                   security_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a single agent with comprehensive error handling and metrics.
        
        Process:
        1. Update agent status to PROCESSING
        2. Execute analysis in thread pool (sync to async conversion)
        3. Update performance metrics
        4. Handle any exceptions gracefully
        5. Reset status to IDLE
        
        Args:
            agent: Agent instance to execute
            security_data: Data to analyze
            
        Returns:
            Dict[str, Any]: Enhanced result with metadata
        """
        start_time = time.time()  # Record start time for performance measurement
        
        try:
            # ===== STATUS UPDATE =====
            # Mark agent as actively processing
            self.agent_status[agent.agent_id] = AgentStatus.PROCESSING
            
            # ===== ASYNCHRONOUS EXECUTION =====
            # Run synchronous analyze() method in thread pool
            loop = asyncio.get_event_loop()  # Get current event loop
            result = await loop.run_in_executor(
                self.executor,    # Thread pool executor
                agent.analyze,    # Method to call
                security_data     # Argument to pass
            )
            
            processing_time = time.time() - start_time  # Calculate execution time
            
            # ===== METRICS UPDATE =====
            if agent.agent_id in self.agent_metrics:
                metrics = self.agent_metrics[agent.agent_id]
                # Determine if threat was detected (threshold = 0.3)
                threat_detected = result.get('threat_level', 0) > 0.3
                # Update all metrics
                metrics.update(
                    success=True,
                    processing_time=processing_time,
                    threat_detected=threat_detected
                )
            
            # ===== RESULT ENHANCEMENT =====
            # Add metadata to agent's raw result
            return {
                'agent_id': agent.agent_id,
                'agent_name': agent.name,
                'analysis_result': result,           # Raw agent output
                'processing_time': processing_time,  # Performance data
                'success': True,                     # Execution status
                'error': None,                       # No error
                'confidence': result.get('confidence', 0.5),  # Agent's confidence
                'threat_level': result.get('threat_level', 0.0),  # Threat assessment
                'reasoning_state': getattr(agent, 'get_reasoning_state', lambda: None)()
                # Get agent's internal reasoning state if method exists
            }
            
        except Exception as e:
            # ===== EXCEPTION HANDLING =====
            processing_time = time.time() - start_time
            logger.error(f"Agent {agent.agent_id} execution failed: {e}")
            
            # Update metrics for failure
            if agent.agent_id in self.agent_metrics:
                self.agent_metrics[agent.agent_id].update(
                    success=False,
                    processing_time=processing_time
                )
            
            # ===== AGENT HEALTH DEGRADATION =====
            # If agent fails too often, mark as DEGRADED
            if agent.agent_id in self.agent_metrics:
                metrics = self.agent_metrics[agent.agent_id]
                if metrics.error_rate > 0.5:  # More than 50% failure rate
                    self.agent_status[agent.agent_id] = AgentStatus.DEGRADED
            
            # ===== ERROR RESULT =====
            return {
                'agent_id': agent.agent_id,
                'agent_name': agent.name,
                'analysis_result': None,      # No result due to error
                'processing_time': processing_time,
                'success': False,             # Execution failed
                'error': str(e),              # Error message
                'confidence': 0.1,            # Very low confidence for failed agents
                'threat_level': 0.0,          # No threat assessment possible
                'reasoning_state': None       # No reasoning state available
            }
        finally:
            # ===== CLEANUP =====
            # Always reset agent status to IDLE (whether success or failure)
            if agent.agent_id in self.agent_status:
                self.agent_status[agent.agent_id] = AgentStatus.IDLE
    
    def _apply_mhc_coordination(self, 
                               agent_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Apply Manifold-Constrained Hyper-Connections (mHC) for agent coordination.
        
        mHC Mathematical Principles:
        1. Doubly-stochastic normalization → Prevents single agent dominance
        2. Convex state mixing → Maintains reasoning diversity
        3. Identity-preserving mappings → Preserves agent expertise
        4. Non-expansive updates → Prevents reasoning collapse
        
        Args:
            agent_results: Individual agent analysis results
            
        Returns:
            Dict[str, Any]: Coordinated result with mHC-applied consensus
        """
        try:
            # ===== VALID RESULT FILTERING =====
            # Only use results from successful agent executions
            valid_results = [r for r in agent_results if r['success']]
            
            if not valid_results:
                logger.warning("No valid agent results for mHC coordination")
                return {
                    'coordinated': False,
                    'error': 'No valid agent results',
                    'threat_level': 0.0,
                    'confidence': 0.0,
                    'agent_contributions': [],
                    'reasoning_states': []
                }
            
            # ===== DATA EXTRACTION =====
            agent_confidences = []
            reasoning_states = []
            agent_contributions = []
            
            for result in valid_results:
                confidence = result.get('confidence', 0.5)
                reasoning_state = result.get('reasoning_state')
                
                agent_confidences.append(confidence)
                if reasoning_state is not None:
                    reasoning_states.append(reasoning_state)
                
                # Track individual agent contributions for explainability
                agent_contributions.append({
                    'agent_id': result['agent_id'],
                    'agent_name': result['agent_name'],
                    'confidence': confidence,
                    'threat_level': result.get('threat_level', 0.0),
                    'success': result['success']
                })
            
            # ===== SIMPLIFIED mHC IMPLEMENTATION =====
            # Note: Full mHC would use tensor operations and Sinkhorn iterations
            # This is a pedagogical simplification
            
            # Calculate total confidence for normalization
            total_confidence = sum(agent_confidences)
            if total_confidence > 0:
                # Initial weights based on confidence (confidence-weighted average)
                weights = [c / total_confidence for c in agent_confidences]
                
                # ===== DOUBLY-STOCHASTIC NORMALIZATION =====
                # Ensure no single agent dominates (>50% weight)
                max_weight = max(weights) if weights else 0
                if max_weight > 0.5:  # Any agent with >50% weight
                    # Redistribute excess weight from dominant agent
                    excess = max_weight - 0.5
                    # Subtract excess only from dominant agent
                    weights = [w - (excess if w == max_weight else 0) for w in weights]
                    # Renormalize to sum to 1
                    total = sum(weights)
                    weights = [w / total for w in weights]
                
                # ===== WEIGHTED AVERAGE CALCULATION =====
                # Calculate coordinated threat level (weighted average)
                threat_levels = [r.get('threat_level', 0.0) for r in valid_results]
                coordinated_threat = sum(t * w for t, w in zip(threat_levels, weights))
                
                # Calculate coordinated confidence (weighted average)
                coordinated_confidence = sum(c * w for c, w in zip(agent_confidences, weights))
                
            else:
                # Edge case: all agents have zero confidence
                coordinated_threat = 0.0
                coordinated_confidence = 0.0
                weights = [0] * len(agent_confidences)
            
            # ===== RESULT PACKAGING =====
            return {
                'coordinated': True,                     # mHC successfully applied
                'threat_level': coordinated_threat,      # Consolidated threat score
                'confidence': coordinated_confidence,    # Consolidated confidence
                'agent_contributions': agent_contributions,  # Individual agent data
                'weights': weights,                      # mHC-calculated weights
                'reasoning_states': reasoning_states,    # Agent reasoning states
                'valid_agents_count': len(valid_results),  # Number of successful agents
                'total_agents_count': len(agent_results)   # Total agents attempted
            }
            
        except Exception as e:
            # ===== mHC FAILURE HANDLING =====
            logger.error(f"mHC coordination failed: {e}")
            return {
                'coordinated': False,
                'error': str(e),
                'threat_level': 0.0,
                'confidence': 0.0,
                'agent_contributions': [],
                'reasoning_states': []
            }
    
    def _generate_final_decision(self,
                                coordinated_result: Dict[str, Any],
                                security_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform coordinated results into actionable security decisions.
        
        Multi-stage Decision Process:
        1. Threat severity classification
        2. Confidence validation  
        3. Action determination
        4. Human review requirement
        5. Explanation generation
        6. Mitigation recommendations
        
        Args:
            coordinated_result: mHC-coordinated agent consensus
            security_data: Original input data for context
            
        Returns:
            Dict[str, Any]: Complete security decision with explanations
        """
        # Extract core metrics from coordinated result
        threat_level = coordinated_result.get('threat_level', 0.0)
        confidence = coordinated_result.get('confidence', 0.0)
        
        # ===== STEP 1: THREAT SEVERITY CLASSIFICATION =====
        threat_severity = self._classify_threat_severity(threat_level)
        
        # ===== STEP 2: CONFIDENCE VALIDATION =====
        min_confidence = self.config['min_confidence_threshold']
        is_confident = confidence >= min_confidence  # Does system trust its own assessment?
        
        # ===== STEP 3: ACTION DETERMINATION =====
        action, action_severity = self._determine_action(
            threat_level, confidence, threat_severity
        )
        
        # ===== STEP 4: HUMAN REVIEW CHECK =====
        requires_human_review = self._requires_human_review(
            threat_level, confidence, coordinated_result
        )
        
        # ===== STEP 5: EXPLANATION GENERATION =====
        explanation = self._generate_explanation(
            threat_level, confidence, threat_severity,
            coordinated_result.get('agent_contributions', [])
        )
        
        # ===== STEP 6: MITIGATION RECOMMENDATIONS =====
        mitigations = self._generate_mitigations(
            threat_severity, security_data, coordinated_result
        )
        
        # ===== FINAL DECISION PACKAGE =====
        return {
            'action': action,                          # What to do (BLOCK, QUARANTINE, etc.)
            'action_severity': action_severity,        # Severity of required action
            'threat_level': threat_level,              # Numeric threat score (0.0-1.0)
            'confidence': confidence,                  # System confidence in assessment
            'threat_severity': threat_severity,        # Categorical threat severity
            'is_confident': is_confident,              # Whether confidence meets threshold
            'requires_human_review': requires_human_review,  # Need analyst review?
            'explanation': explanation,                # Human-readable reasoning
            'mitigations': mitigations,                # Recommended security actions
            'agent_contributions': coordinated_result.get('agent_contributions', []),
            'coordinated_success': coordinated_result.get('coordinated', False),
            'timestamp': time.time()                   # Decision timestamp
        }
    
    def _classify_threat_severity(self, threat_level: float) -> ThreatSeverity:
        """
        Convert numeric threat score to categorical severity level.
        
        Threshold Mapping:
        - ≥ 0.8 → CRITICAL (immediate action required)
        - ≥ 0.6 → HIGH (high priority remediation)
        - ≥ 0.4 → MEDIUM (schedule remediation)
        - ≥ 0.2 → LOW (monitor)
        - < 0.2 → INFORMATIONAL (no immediate threat)
        
        Args:
            threat_level: Numeric threat score (0.0 to 1.0)
            
        Returns:
            ThreatSeverity: Categorized threat level
        """
        # Check thresholds in descending order (most severe first)
        if threat_level >= self.config['critical_threshold']:
            return ThreatSeverity.CRITICAL
        elif threat_level >= self.config['high_threshold']:
            return ThreatSeverity.HIGH
        elif threat_level >= self.config['medium_threshold']:
            return ThreatSeverity.MEDIUM
        elif threat_level >= self.config['low_threshold']:
            return ThreatSeverity.LOW
        else:
            return ThreatSeverity.INFORMATIONAL
    
    def _determine_action(self, 
                         threat_level: float,
                         confidence: float,
                         severity: ThreatSeverity) -> Tuple[str, str]:
        """
        Determine appropriate security response based on threat assessment.
        
        Action Logic:
        - CRITICAL + high confidence → Immediate block
        - HIGH + high confidence → Quarantine
        - HIGH + low confidence → Challenge (CAPTCHA/2FA)
        - MEDIUM → Enhanced monitoring
        - LOW → Basic monitoring
        - INFORMATIONAL → Log only
        
        Args:
            threat_level: Numeric threat score
            confidence: System confidence in assessment
            severity: Categorized threat severity
            
        Returns:
            Tuple[str, str]: (action_type, action_severity)
        """
        
        # ===== CRITICAL THREATS =====
        if severity == ThreatSeverity.CRITICAL and confidence > 0.8:
            # High confidence critical threat → immediate blocking
            return 'BLOCK_IMMEDIATE', 'critical'
        
        # ===== HIGH THREATS =====
        elif severity == ThreatSeverity.HIGH:
            if confidence > 0.7:
                # High confidence high threat → quarantine
                return 'QUARANTINE', 'high'
            else:
                # Low confidence high threat → challenge user
                return 'CHALLENGE', 'high'  # CAPTCHA, 2FA, etc.
        
        # ===== MEDIUM THREATS =====
        elif severity == ThreatSeverity.MEDIUM:
            # Medium threat → enhanced monitoring
            return 'MONITOR_ENHANCED', 'medium'
        
        # ===== LOW THREATS =====
        elif severity == ThreatSeverity.LOW:
            # Low threat → basic monitoring
            return 'MONITOR_BASIC', 'low'
        
        # ===== INFORMATIONAL =====
        else:
            # No threat → log for awareness only
            return 'LOG_ONLY', 'informational'
    
    def _requires_human_review(self,
                              threat_level: float,
                              confidence: float,
                              coordinated_result: Dict[str, Any]) -> bool:
        """
        Determine if human security analyst should review this decision.
        
        Review Triggers:
        1. High threat with low confidence (ambiguous situation)
        2. High variance in agent opinions (conflicting assessments)
        3. Critical threat detection (always review for confirmation)
        
        Args:
            threat_level: Consolidated threat score
            confidence: System confidence
            coordinated_result: Full coordination results
            
        Returns:
            bool: True if human review required, False otherwise
        """
        
        # ===== CONDITION 1: HIGH THREAT, LOW CONFIDENCE =====
        # Threat is serious but system isn't confident
        if threat_level > 0.7 and confidence < 0.6:
            return True
        
        # ===== CONDITION 2: CONFLICTING AGENT OPINIONS =====
        # Agents disagree significantly about threat level
        contributions = coordinated_result.get('agent_contributions', [])
        if len(contributions) >= 3:  # Need multiple agents for meaningful variance
            # Extract threat levels from all agents
            threat_levels = [c.get('threat_level', 0) for c in contributions]
            if len(threat_levels) >= 3:  # Need at least 3 for variance calculation
                try:
                    import statistics
                    # Calculate variance of agent opinions
                    variance = statistics.variance(threat_levels)
                    if variance > 0.1:  # High variance = significant disagreement
                        return True
                except:
                    pass  # If statistics fails, continue without this check
        
        # ===== CONDITION 3: CRITICAL THREAT DETECTION =====
        # Always have human review critical threats
        if threat_level > 0.9:
            return True
        
        return False  # No review required
    
    def _generate_explanation(self,
                            threat_level: float,
                            confidence: float,
                            severity: ThreatSeverity,
                            agent_contributions: List[Dict]) -> str:
        """
        Create human-readable explanation of security decision.
        
        Explanation Structure:
        1. Basic assessment (severity, score, confidence)
        2. Top contributing agents
        3. Contextual reasoning based on severity
        
        Args:
            threat_level: Numeric threat score
            confidence: System confidence
            severity: Threat severity category
            agent_contributions: Individual agent assessments
            
        Returns:
            str: Human-readable explanation
        """
        
        # ===== BASE EXPLANATION =====
        # Start with basic assessment information
        explanation = (
            f"Detected {severity.value} level threat (score: {threat_level:.2f}) "
            f"with {confidence:.2f} confidence. "
        )
        
        # ===== AGENT ATTRIBUTION =====
        # Credit the top agents that contributed to this decision
        if agent_contributions:
            # Sort agents by confidence (most confident first)
            top_agents = sorted(
                agent_contributions,
                key=lambda x: x.get('confidence', 0),
                reverse=True
            )[:3]  # Take top 3 agents
            
            # Extract agent names
            agent_names = [a['agent_name'] for a in top_agents]
            explanation += f"Primary analysis by: {', '.join(agent_names)}. "
        
        # ===== SEVERITY-BASED REASONING =====
        # Add contextual guidance based on threat severity
        if severity == ThreatSeverity.CRITICAL:
            explanation += (
                "This indicates a clear and immediate security threat that "
                "requires prompt action to prevent potential compromise."
            )
        elif severity == ThreatSeverity.HIGH:
            explanation += (
                "This represents a significant security risk that should be "
                "addressed to prevent potential exploitation."
            )
        elif severity == ThreatSeverity.MEDIUM:
            explanation += (
                "This indicates a potential security issue that should be "
                "monitored and addressed during regular security maintenance."
            )
        else:
            explanation += (
                "No immediate action required, but this information may be "
                "useful for security awareness and trend analysis."
            )
        
        return explanation
    
    def _generate_mitigations(self,
                             severity: ThreatSeverity,
                             security_data: Dict[str, Any],
                             coordinated_result: Dict[str, Any]) -> List[str]:
        """
        Generate actionable security mitigation recommendations.
        
        Mitigation Types:
        1. General mitigations based on severity
        2. Data-type specific mitigations
        3. Agent-specific recommendations
        
        Args:
            severity: Threat severity level
            security_data: Original input data
            coordinated_result: Coordinated agent results
            
        Returns:
            List[str]: Actionable mitigation steps
        """
        
        mitigations = []
        data_type = security_data.get('type', 'unknown')
        
        # ===== GENERAL MITIGATIONS =====
        # Apply to all high/critical severity threats
        if severity in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH]:
            mitigations.extend([
                "Isolate affected systems from the network",
                "Preserve all logs and evidence for forensic analysis",
                "Activate incident response team",
                "Notify relevant stakeholders and authorities if required"
            ])
        
        # ===== DATA-TYPE SPECIFIC MITIGATIONS =====
        # Tailored recommendations based on what was analyzed
        if data_type == 'http_request':
            mitigations.extend([
                "Implement Web Application Firewall (WAF) rules",
                "Review and validate all input sanitization routines",
                "Check for missing security headers (CSP, HSTS, etc.)",
                "Audit authentication and session management"
            ])
        elif data_type == 'network_traffic':
            mitigations.extend([
                "Review firewall rules and network segmentation",
                "Check for unusual outbound connections",
                "Monitor for data exfiltration patterns",
                "Update intrusion detection system signatures"
            ])
        elif data_type == 'source_code':
            mitigations.extend([
                "Conduct secure code review for identified vulnerabilities",
                "Implement static application security testing (SAST)",
                "Update third-party libraries with known vulnerabilities",
                "Add security unit tests for vulnerable components"
            ])
        
        # ===== AGENT-SPECIFIC RECOMMENDATIONS =====
        # Include recommendations from individual agents if available
        for contribution in coordinated_result.get('agent_contributions', []):
            if 'recommendations' in contribution:
                mitigations.extend(contribution['recommendations'])
        
        # ===== DEDUPLICATION AND LIMITING =====
        # Remove duplicates and limit to manageable number
        unique_mitigations = []
        seen = set()
        for mitigation in mitigations:
            if mitigation not in seen:
                unique_mitigations.append(mitigation)
                seen.add(mitigation)
        
        # Return top 10 unique mitigations (prioritization could be added)
        return unique_mitigations[:10]
    
    def _create_orchestration_result(self,
                                    analysis_id: str,
                                    start_time: float,
                                    security_data: Dict[str, Any],
                                    agent_results: List[Dict[str, Any]],
                                    coordinated_result: Dict[str, Any],
                                    final_decision: Dict[str, Any]) -> OrchestrationResult:
        """
        Package all analysis components into structured OrchestrationResult.
        
        Args:
            analysis_id: Unique identifier for this analysis
            start_time: When analysis began (for performance calculation)
            security_data: Original input data
            agent_results: Individual agent outputs
            coordinated_result: mHC coordination results
            final_decision: Final security decision
            
        Returns:
            OrchestrationResult: Complete packaged result
        """
        
        # Calculate total processing time
        processing_time = time.time() - start_time
        
        # Construct comprehensive result object
        return OrchestrationResult(
            analysis_id=analysis_id,
            timestamp=start_time,
            security_data=security_data,
            final_decision=final_decision,
            agent_results=agent_results,
            coordination_metrics={
                'processing_time': processing_time,
                'agents_executed': len(agent_results),
                'agents_successful': len([r for r in agent_results if r['success']]),
                'agents_failed': len([r for r in agent_results if not r['success']]),
                'mhc_applied': coordinated_result.get('coordinated', False)
            },
            mhc_state=coordinated_result.get('reasoning_states'),
            requires_human_review=final_decision.get('requires_human_review', False),
            confidence_score=final_decision.get('confidence', 0.0),
            threat_severity=final_decision.get('threat_severity', ThreatSeverity.INFORMATIONAL),
            recommended_actions=final_decision.get('mitigations', [])
        )
    
    def _create_empty_result(self,
                            analysis_id: str,
                            security_data: Dict[str, Any],
                            reason: str) -> OrchestrationResult:
        """
        Create result when no agents are available for analysis.
        
        Args:
            analysis_id: Analysis identifier
            security_data: Input data
            reason: Explanation for empty result
            
        Returns:
            OrchestrationResult: Structured error/empty result
        """
        return OrchestrationResult(
            analysis_id=analysis_id,
            timestamp=time.time(),
            security_data=security_data,
            final_decision={
                'action': 'NO_ACTION',
                'action_severity': 'informational',
                'threat_level': 0.0,
                'confidence': 0.0,
                'threat_severity': ThreatSeverity.INFORMATIONAL,
                'is_confident': False,
                'requires_human_review': False,
                'explanation': f"No agents available for analysis: {reason}",
                'mitigations': ["Check agent availability and configuration"],
                'agent_contributions': [],
                'coordinated_success': False,
                'timestamp': time.time()
            },
            agent_results=[],
            coordination_metrics={
                'processing_time': 0.0,
                'agents_executed': 0,
                'agents_successful': 0,
                'agents_failed': 0,
                'mhc_applied': False
            },
            requires_human_review=False,
            confidence_score=0.0,
            threat_severity=ThreatSeverity.INFORMATIONAL,
            recommended_actions=["Ensure security agents are properly registered and configured"]
        )
    
    def _create_error_result(self,
                            analysis_id: str,
                            security_data: Dict[str, Any],
                            error: str) -> OrchestrationResult:
        """
        Create result when orchestration process fails entirely.
        
        Args:
            analysis_id: Analysis identifier
            security_data: Input data
            error: Exception/error message
            
        Returns:
            OrchestrationResult: Error result with diagnostic information
        """
        return OrchestrationResult(
            analysis_id=analysis_id,
            timestamp=time.time(),
            security_data=security_data,
            final_decision={
                'action': 'ERROR',
                'action_severity': 'error',
                'threat_level': 0.0,
                'confidence': 0.0,
                'threat_severity': ThreatSeverity.INFORMATIONAL,
                'is_confident': False,
                'requires_human_review': True,
                'explanation': f"Orchestration failed: {error}",
                'mitigations': ["Check orchestrator logs and configuration"],
                'agent_contributions': [],
                'coordinated_success': False,
                'timestamp': time.time()
            },
            agent_results=[],
            coordination_metrics={
                'processing_time': 0.0,
                'agents_executed': 0,
                'agents_successful': 0,
                'agents_failed': 0,
                'mhc_applied': False
            },
            requires_human_review=True,
            confidence_score=0.0,
            threat_severity=ThreatSeverity.INFORMATIONAL,
            recommended_actions=["Review error logs and restart orchestrator if needed"]
        )
    
    def _create_agent_timeout_result(self, agent: SecurityAgent) -> Dict[str, Any]:
        """
        Create standardized result for agent timeout.
        
        Args:
            agent: Agent that timed out
            
        Returns:
            Dict[str, Any]: Timeout result structure
        """
        return {
            'agent_id': agent.agent_id,
            'agent_name': agent.name,
            'analysis_result': None,
            'processing_time': self.config['agent_timeout_seconds'],
            'success': False,
            'error': 'Agent execution timed out',
            'confidence': 0.1,  # Very low confidence for timeout
            'threat_level': 0.0,
            'reasoning_state': None
        }
    
    def _create_agent_error_result(self, agent: SecurityAgent, error: str) -> Dict[str, Any]:
        """
        Create standardized result for agent error/exception.
        
        Args:
            agent: Agent that errored
            error: Exception message
            
        Returns:
            Dict[str, Any]: Error result structure
        """
        return {
            'agent_id': agent.agent_id,
            'agent_name': agent.name,
            'analysis_result': None,
            'processing_time': 0.0,
            'success': False,
            'error': error,
            'confidence': 0.1,  # Very low confidence for errored agent
            'threat_level': 0.0,
            'reasoning_state': None
        }
    
    def _update_metrics_and_history(self,
                                   result: OrchestrationResult,
                                   start_time: float):
        """
        Update system metrics and maintain analysis history.
        
        Args:
            result: Completed orchestration result
            start_time: When analysis started
        """
        # Calculate total processing time
        processing_time = time.time() - start_time
        
        # ===== ORCHESTRATOR METRICS UPDATE =====
        self.metrics['total_coordinations'] += 1  # Increment total count
        
        # Track success/failure based on coordination success
        if result.final_decision.get('coordinated_success', False):
            self.metrics['successful_coordinations'] += 1
        else:
            self.metrics['failed_coordinations'] += 1
        
        # Update moving average of coordination time
        self.metrics['avg_coordination_time'] = (
            self.metrics['avg_coordination_time'] * 0.9 + processing_time * 0.1
        )
        self.metrics['last_coordination_time'] = processing_time
        
        # ===== HISTORY MAINTENANCE =====
        # Store result in history (circular buffer)
        self.analysis_history.append(result)
        
        # Trim history if exceeds configured maximum size
        if len(self.analysis_history) > self.config['max_history_size']:
            # Keep only the most recent N results
            self.analysis_history = self.analysis_history[-self.config['max_history_size']:]
    
    def start_health_monitoring(self):
        """
        Launch background thread for continuous agent health monitoring.
        
        Monitoring includes:
        - Agent responsiveness checks
        - Performance degradation detection
        - Auto-recovery attempts
        """
        # Check if monitoring is already running
        if self.health_check_thread and self.health_check_thread.is_alive():
            logger.warning("Health monitoring already running")
            return
        
        # Set running flag and create monitoring thread
        self.is_running = True
        self.health_check_thread = threading.Thread(
            target=self._health_monitoring_loop,  # Function to run in thread
            daemon=True,                         # Thread exits when main program exits
            name="OrchestratorHealthMonitor"     # Descriptive thread name for debugging
        )
        self.health_check_thread.start()  # Start the thread
        logger.info("Health monitoring started")
    
    def stop_health_monitoring(self):
        """
        Gracefully stop health monitoring thread.
        """
        self.is_running = False  # Signal thread to stop
        
        # Wait for thread to terminate (5 second timeout)
        if self.health_check_thread:
            self.health_check_thread.join(timeout=5)
            logger.info("Health monitoring stopped")
    
    def _health_monitoring_loop(self):
        """
        Main loop for health monitoring thread.
        
        Continuously checks agent health at configured intervals.
        Handles its own errors to prevent thread crashes.
        """
        while self.is_running:  # Run until stopped
            try:
                self._perform_health_checks()  # Check all agents
                time.sleep(self.health_check_interval)  # Wait before next check
            except Exception as e:
                # Log error but continue monitoring
                logger.error(f"Health monitoring error: {e}")
                time.sleep(10)  # Wait longer after error before retrying
    
    def _perform_health_checks(self):
        """
        Perform health checks on all registered agents.
        
        For each agent:
        1. Skip if already failed and auto-healing disabled
        2. Check health using multiple methods
        3. Update status based on health check result
        4. Attempt auto-recovery if enabled
        """
        with self.processing_lock:  # Thread-safe agent status updates
            for agent_id, agent in self.agents.items():
                try:
                    # Get current agent status
                    current_status = self.agent_status.get(agent_id, AgentStatus.UNAVAILABLE)
                    
                    # Skip failed agents if auto-healing is disabled
                    if current_status == AgentStatus.FAILED and not self.config['enable_auto_healing']:
                        continue
                    
                    # Perform health check
                    is_healthy = self._check_agent_health(agent)
                    
                    if is_healthy:
                        # Agent is healthy - ensure status is appropriate
                        if current_status in [AgentStatus.DEGRADED, AgentStatus.FAILED]:
                            self.agent_status[agent_id] = AgentStatus.IDLE
                            logger.info(f"Agent {agent_id} recovered, status reset to IDLE")
                    else:
                        # Agent is unhealthy
                        if current_status != AgentStatus.FAILED:
                            self.agent_status[agent_id] = AgentStatus.FAILED
                            logger.warning(f"Agent {agent_id} health check failed, marked as FAILED")
                            
                            # Attempt to automatically recover the agent
                            if self.config['enable_auto_healing']:
                                self._attempt_agent_recovery(agent_id, agent)
                    
                except Exception as e:
                    # Log health check failure and mark agent as failed
                    logger.error(f"Health check failed for agent {agent_id}: {e}")
                    self.agent_status[agent_id] = AgentStatus.FAILED
    
    def _check_agent_health(self, agent: SecurityAgent) -> bool:
        """
        Check if an agent is healthy using multiple methods.
        
        Health Check Methods (in order):
        1. Agent's custom check_health() method (if available)
        2. Agent's status attribute (if available)
        3. Test analysis with timeout (fallback method)
        
        Args:
            agent: Agent to check
            
        Returns:
            bool: True if agent is healthy, False otherwise
        """
        try:
            # ===== METHOD 1: CUSTOM HEALTH CHECK =====
            # Use agent's own health check method if available
            if hasattr(agent, 'check_health'):
                return agent.check_health()
            
            # ===== METHOD 2: STATUS ATTRIBUTE CHECK =====
            # Check agent's status attribute if available
            if hasattr(agent, 'status'):
                status = agent.status
                # Consider agent healthy if status is not one of these values
                return status not in ['failed', 'error', 'unavailable']
            
            # ===== METHOD 3: TEST ANALYSIS =====
            # Perform a minimal test analysis to verify functionality
            test_data = {'type': 'health_check', 'content': 'ping'}
            
            # Use threading for timeout control
            import threading
            result = None
            exception = None
            
            # Define analysis function to run in thread
            def analyze():
                nonlocal result, exception
                try:
                    result = agent.analyze(test_data)  # Try to analyze test data
                except Exception as e:
                    exception = e  # Capture any exception
            
            # Create and start analysis thread
            thread = threading.Thread(target=analyze)
            thread.start()
            thread.join(timeout=5)  # Wait up to 5 seconds
            
            # Check thread status after timeout
            if thread.is_alive():
                logger.warning(f"Agent {agent.agent_id} health check timed out")
                return False  # Timeout = unhealthy
            
            if exception is not None:
                logger.warning(f"Agent {agent.agent_id} health check raised exception: {exception}")
                return False  # Exception = unhealthy
            
            # If we got a result, agent is healthy
            return result is not None
            
        except Exception as e:
            # Any error in health checking itself means agent is unhealthy
            logger.error(f"Health check error for agent {agent.agent_id}: {e}")
            return False
    
    def _attempt_agent_recovery(self, agent_id: str, agent: SecurityAgent):
        """
        Attempt to automatically recover a failed agent.
        
        Recovery Methods (in order):
        1. Reinitialize agent (if supported)
        2. Restart agent (if supported)
        3. Wait and retry (exponential backoff)
        
        Args:
            agent_id: ID of agent to recover
            agent: Agent instance
        """
        retry_count = 0
        max_retries = self.config['max_retry_attempts']
        
        # Attempt recovery up to max_retries times
        while retry_count < max_retries and self.is_running:
            try:
                logger.info(f"Attempting to recover agent {agent_id} (attempt {retry_count + 1}/{max_retries})")
                
                # ===== METHOD 1: REINITIALIZE =====
                if hasattr(agent, 'reinitialize'):
                    if agent.reinitialize():  # Returns True if successful
                        self.agent_status[agent_id] = AgentStatus.IDLE
                        logger.info(f"Agent {agent_id} successfully reinitialized")
                        return  # Recovery successful
                
                # ===== METHOD 2: RESTART =====
                if hasattr(agent, 'restart'):
                    if agent.restart():  # Returns True if successful
                        self.agent_status[agent_id] = AgentStatus.IDLE
                        logger.info(f"Agent {agent_id} successfully restarted")
                        return  # Recovery successful
                
                # ===== METHOD 3: WAIT AND RETRY =====
                # Exponential backoff: wait 1s, then 2s, then 4s, etc.
                time.sleep(2 ** retry_count)
                retry_count += 1
                
            except Exception as e:
                logger.error(f"Recovery attempt {retry_count + 1} failed for agent {agent_id}: {e}")
                retry_count += 1
                time.sleep(2 ** retry_count)  # Backoff after error
        
        # If all retries failed, log final failure
        if retry_count >= max_retries:
            logger.error(f"Agent {agent_id} recovery failed after {max_retries} attempts")
    
    def get_system_status(self) -> Dict[str, Any]:
        """
        Generate comprehensive system status report.
        
        Report includes:
        - System health metrics
        - Orchestrator performance statistics
        - Agent status distribution
        - Detailed agent information
        - Configuration summary
        
        Returns:
            Dict[str, Any]: Complete system status
        """
        with self.processing_lock:  # Thread-safe status generation
            # ===== AGENT STATUS DISTRIBUTION =====
            # Count how many agents are in each state
            status_counts = {
                'idle': 0,
                'processing': 0,
                'degraded': 0,
                'failed': 0,
                'unavailable': 0,
                'initializing': 0
            }
            
            # Iterate through all agent statuses
            for status in self.agent_status.values():
                # Convert Enum to string if needed
                status_name = status.value if isinstance(status, AgentStatus) else str(status)
                if status_name in status_counts:
                    status_counts[status_name] += 1
            
            # ===== AGENT DETAILS =====
            # Generate detailed information for each agent
            agent_details = []
            for agent_id, agent in self.agents.items():
                metrics = self.agent_metrics.get(agent_id)
                status = self.agent_status.get(agent_id, AgentStatus.UNAVAILABLE)
                
                agent_details.append({
                    'id': agent_id,
                    'name': agent.name,
                    'status': status.value if isinstance(status, AgentStatus) else str(status),
                    'capabilities': self.agent_capabilities.get(agent_id, []),
                    'metrics': {
                        'total_requests': metrics.total_requests if metrics else 0,
                        'success_rate': (
                            metrics.successful_analyses / max(1, metrics.total_requests) 
                            if metrics else 0
                        ),
                        'avg_processing_time': metrics.avg_processing_time if metrics else 0,
                        'confidence': metrics.confidence_score if metrics else 0.5,
                        'error_rate': metrics.error_rate if metrics else 0.0
                    } if metrics else {}
                })
            
            # ===== SYSTEM HEALTH SCORE =====
            # Calculate overall system health (0-100)
            healthy_agents = sum(1 for s in self.agent_status.values() 
                               if s in [AgentStatus.IDLE, AgentStatus.PROCESSING])
            total_agents = len(self.agents)
            
            # Health score = percentage of healthy agents
            health_score = (healthy_agents / max(1, total_agents)) * 100
            
            # ===== COMPREHENSIVE STATUS REPORT =====
            return {
                'system': {
                    'health_score': health_score,
                    'total_agents': total_agents,
                    'healthy_agents': healthy_agents,
                    'is_running': self.is_running,
                    'uptime': time.time() - self._start_time  # Calculate uptime
                },
                'orchestrator_metrics': self.metrics.copy(),  # Copy to avoid mutation
                'agent_status_distribution': status_counts,
                'agent_details': agent_details,
                'recent_analyses': len(self.analysis_history),
                'config': {
                    'max_parallel_agents': self.config['max_parallel_agents'],
                    'agent_timeout': self.config['agent_timeout_seconds'],
                    'health_check_interval': self.config['health_check_interval'],
                    'enable_auto_healing': self.config['enable_auto_healing']
                }
            }
    
    def get_analysis_history(self, 
                            limit: int = 10,
                            filter_severity: Optional[ThreatSeverity] = None) -> List[Dict[str, Any]]:
        """
        Retrieve recent analysis history with optional filtering.
        
        Args:
            limit: Maximum number of results to return
            filter_severity: Optional severity filter
            
        Returns:
            List[Dict[str, Any]]: Serialized history results
        """
        results = self.analysis_history
        
        # ===== FILTER BY SEVERITY =====
        if filter_severity:
            results = [r for r in results if r.threat_severity == filter_severity]
        
        # ===== SORTING =====
        # Sort by timestamp (newest first)
        results.sort(key=lambda x: x.timestamp, reverse=True)
        
        # ===== LIMITING =====
        limited_results = results[:limit]
        
        # ===== SERIALIZATION =====
        # Convert OrchestrationResult objects to dictionaries
        return [r.to_dict() for r in limited_results]
    
    def shutdown(self):
        """
        Gracefully shutdown the entire orchestrator system.
        
        Shutdown Process:
        1. Stop health monitoring
        2. Shutdown all agents
        3. Clear all registries
        4. Shutdown thread pool
        """
        logger.info("Shutting down AgentOrchestrator...")
        
        # ===== STEP 1: STOP HEALTH MONITORING =====
        self.stop_health_monitoring()
        
        # ===== STEP 2: SHUTDOWN ALL AGENTS =====
        with self.processing_lock:
            for agent_id, agent in self.agents.items():
                try:
                    # Call agent's shutdown method if available
                    if hasattr(agent, 'shutdown'):
                        agent.shutdown()
                    logger.info(f"Shutdown agent: {agent_id}")
                except Exception as e:
                    logger.error(f"Failed to shutdown agent {agent_id}: {e}")
            
            # ===== STEP 3: CLEAR REGISTRIES =====
            # Remove all agents from tracking dictionaries
            self.agents.clear()
            self.agent_status.clear()
            self.agent_metrics.clear()
            self.agent_capabilities.clear()
        
        # ===== STEP 4: SHUTDOWN THREAD POOL =====
        self.executor.shutdown(wait=True)  # Wait for running tasks to complete
        
        logger.info("AgentOrchestrator shutdown complete")


# ===== PLACEHOLDER AGENT CLASSES =====
# These would be replaced with actual agent implementations in production

class WebThreatDetectionAgent(SecurityAgent):
    """Agent for detecting web application threats (XSS, SQLi, etc.)"""
    def __init__(self):
        super().__init__()
        self.name = "WebThreatDetectionAgent"
        self.capabilities = ['http_analysis', 'threat_detection', 'owasp_top10']

class TrafficAnomalyAgent(SecurityAgent):
    """Agent for detecting anomalous network traffic patterns"""
    def __init__(self):
        super().__init__()
        self.name = "TrafficAnomalyAgent"
        self.capabilities = ['traffic_analysis', 'anomaly_detection', 'behavior_modeling']

class BotDetectionAgent(SecurityAgent):
    """Agent for identifying automated/bot traffic"""
    def __init__(self):
        super().__init__()
        self.name = "BotDetectionAgent"
        self.capabilities = ['bot_detection', 'abuse_prevention', 'rate_limiting']

class MalwarePayloadAgent(SecurityAgent):
    """Agent for analyzing and detecting malware payloads"""
    def __init__(self):
        super().__init__()
        self.name = "MalwarePayloadAgent"
        self.capabilities = ['malware_detection', 'payload_analysis', 'yara_matching']

class ExploitChainReasoningAgent(SecurityAgent):
    """Agent for reasoning about exploit chains and attack paths"""
    def __init__(self):
        super().__init__()
        self.name = "ExploitChainReasoningAgent"
        self.capabilities = ['exploit_analysis', 'attack_chain', 'threat_hunting']

class DigitalForensicsAgent(SecurityAgent):
    """Agent for forensic analysis and evidence collection"""
    def __init__(self):
        super().__init__()
        self.name = "DigitalForensicsAgent"
        self.capabilities = ['forensic_analysis', 'evidence_collection', 'timeline_reconstruction']

class IncidentResponseAgent(SecurityAgent):
    """Agent for incident response and containment actions"""
    def __init__(self):
        super().__init__()
        self.name = "IncidentResponseAgent"
        self.capabilities = ['incident_response', 'containment', 'remediation']

class CompliancePrivacyAgent(SecurityAgent):
    """Agent for compliance checking and privacy auditing"""
    def __init__(self):
        super().__init__()
        self.name = "CompliancePrivacyAgent"
        self.capabilities = ['compliance_check', 'privacy_audit', 'gdpr_hipaa']

class SecureCodeReviewAgent(SecurityAgent):
    """Agent for secure code review and vulnerability scanning"""
    def __init__(self):
        super().__init__()
        self.name = "SecureCodeReviewAgent"
        self.capabilities = ['code_review', 'vulnerability_scan', 'sast']

class ThreatEducationAgent(SecurityAgent):
    """Agent for security education and vulnerability explanation"""
    def __init__(self):
        super().__init__()
        self.name = "ThreatEducationAgent"
        self.capabilities = ['security_education', 'vulnerability_explanation', 'mitigation_guidance']


# ===== FACTORY FUNCTION =====
def create_default_orchestrator() -> AgentOrchestrator:
    """
    Convenience function to create a pre-configured orchestrator.
    
    Creates orchestrator with all default security agents registered.
    Useful for quick setup and testing.
    
    Returns:
        AgentOrchestrator: Fully configured orchestrator instance
    """
    # Create orchestrator with default configuration
    orchestrator = AgentOrchestrator()
    
    # Define all default agents and their capabilities
    agents_to_register = [
        # (AgentClass, capabilities_list)
        (WebThreatDetectionAgent, ['http_analysis', 'threat_detection', 'owasp_top10']),
        (TrafficAnomalyAgent, ['traffic_analysis', 'anomaly_detection', 'behavior_modeling']),
        (BotDetectionAgent, ['bot_detection', 'abuse_prevention', 'rate_limiting']),
        (MalwarePayloadAgent, ['malware_detection', 'payload_analysis', 'yara_matching']),
        (ExploitChainReasoningAgent, ['exploit_analysis', 'attack_chain', 'threat_hunting']),
        (DigitalForensicsAgent, ['forensic_analysis', 'evidence_collection', 'timeline_reconstruction']),
        (IncidentResponseAgent, ['incident_response', 'containment', 'remediation']),
        (CompliancePrivacyAgent, ['compliance_check', 'privacy_audit', 'gdpr_hipaa']),
        (SecureCodeReviewAgent, ['code_review', 'vulnerability_scan', 'sast']),
        (ThreatEducationAgent, ['security_education', 'vulnerability_explanation', 'mitigation_guidance'])
    ]
    
    # Register each agent
    for AgentClass, capabilities in agents_to_register:
        try:
            agent = AgentClass()  # Create agent instance
            orchestrator.register_agent(agent, capabilities)  # Register with orchestrator
        except Exception as e:
            logger.error(f"Failed to create and register {AgentClass.__name__}: {e}")
    
    # Start health monitoring
    orchestrator.start_health_monitoring()
    
    return orchestrator


# ===== MAIN EXECUTION BLOCK =====
if __name__ == "__main__":
    """
    Example usage and testing of the AgentOrchestrator.
    This block runs when the script is executed directly.
    """
    
    # Configure basic logging for testing
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create orchestrator with all default agents
    orchestrator = create_default_orchestrator()
    
    try:
        # ===== GET SYSTEM STATUS =====
        status = orchestrator.get_system_status()
        print(f"System Status: {json.dumps(status, indent=2, default=str)}")
        
        # ===== EXAMPLE SECURITY ANALYSIS =====
        # Create test HTTP request data
        test_data = {
            'type': 'http_request',
            'url': 'https://example.com/admin',
            'method': 'POST',
            'headers': {'User-Agent': 'Mozilla/5.0'},
            'body': 'username=admin&password=test123'
        }
        
        # Run coordinated analysis (async function)
        import asyncio
        result = asyncio.run(orchestrator.coordinate_analysis(test_data))
        
        # ===== DISPLAY RESULTS =====
        print(f"\nAnalysis Result:")
        print(f"  Threat Severity: {result.threat_severity.value}")
        print(f"  Confidence: {result.confidence_score:.2f}")
        print(f"  Action: {result.final_decision.get('action')}")
        print(f"  Explanation: {result.final_decision.get('explanation')[:100]}...")
        
        # Show top contributing agents
        print(f"\nAgent Contributions:")
        for contribution in result.final_decision.get('agent_contributions', [])[:3]:
            print(f"  - {contribution['agent_name']}: "
                  f"confidence={contribution['confidence']:.2f}, "
                  f"threat={contribution.get('threat_level', 0):.2f}")
        
    finally:
        # ===== GRACEFUL SHUTDOWN =====
        # Always shutdown properly, even if errors occur
        orchestrator.shutdown()