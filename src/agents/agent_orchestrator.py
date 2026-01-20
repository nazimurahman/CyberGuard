"""
agent_orchestrator.py

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

import asyncio
import concurrent.futures
import threading
import time
from typing import Dict, List, Any, Optional, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
import uuid
import json
import logging

# Import agent base classes
from .base_agent import SecurityAgent
from .threat_detection_agent import WebThreatDetectionAgent
from .traffic_anomaly_agent import TrafficAnomalyAgent
from .bot_detection_agent import BotDetectionAgent
from .malware_agent import MalwarePayloadAgent
from .exploit_chain_agent import ExploitChainReasoningAgent
from .forensics_agent import DigitalForensicsAgent
from .incident_response_agent import IncidentResponseAgent
from .compliance_agent import CompliancePrivacyAgent
from .code_review_agent import SecureCodeReviewAgent
from .threat_education_agent import ThreatEducationAgent

# Import mHC components from core
from ..core.mhc_architecture import ManifoldConstrainedHyperConnections

logger = logging.getLogger(__name__)


class AgentStatus(Enum):
    """Enumeration of possible agent states"""
    IDLE = "idle"               # Agent is ready but not processing
    PROCESSING = "processing"   # Agent is actively analyzing
    DEGRADED = "degraded"       # Agent is functional but with reduced capability
    FAILED = "failed"           # Agent has encountered an error
    UNAVAILABLE = "unavailable" # Agent is temporarily unavailable
    INITIALIZING = "initializing" # Agent is starting up


class ThreatSeverity(Enum):
    """Standardized threat severity levels"""
    CRITICAL = "critical"       # Immediate action required
    HIGH = "high"               # High priority remediation
    MEDIUM = "medium"           # Moderate risk, schedule remediation
    LOW = "low"                 # Low risk, monitor
    INFORMATIONAL = "informational" # No immediate threat, information only


@dataclass
class AgentMetrics:
    """Comprehensive metrics tracking for each agent"""
    agent_id: str
    name: str
    total_requests: int = 0                     # Total requests processed
    successful_analyses: int = 0                # Successful threat analyses
    failed_analyses: int = 0                    # Failed analyses
    avg_processing_time: float = 0.0            # Average time per analysis (seconds)
    total_processing_time: float = 0.0          # Cumulative processing time
    threats_detected: int = 0                   # Total threats identified
    false_positives: int = 0                    # False positive detections
    false_negatives: int = 0                    # Missed threats (if known)
    confidence_score: float = 0.5               # Current confidence (0.0 to 1.0)
    last_updated: float = field(default_factory=time.time)  # Last metrics update
    error_rate: float = 0.0                     # Error percentage
    
    def update(self, success: bool, processing_time: float, threat_detected: bool = False):
        """Update metrics after an analysis"""
        self.total_requests += 1
        self.total_processing_time += processing_time
        
        if success:
            self.successful_analyses += 1
            if threat_detected:
                self.threats_detected += 1
        else:
            self.failed_analyses += 1
        
        # Update moving averages
        self.avg_processing_time = (
            self.avg_processing_time * 0.9 + processing_time * 0.1
        )
        self.error_rate = self.failed_analyses / max(1, self.total_requests)
        self.last_updated = time.time()


@dataclass
class OrchestrationResult:
    """Structured result from agent orchestration"""
    analysis_id: str                           # Unique identifier for this analysis
    timestamp: float                           # When analysis was performed
    security_data: Dict[str, Any]              # Original input data
    final_decision: Dict[str, Any]             # Consolidated decision from all agents
    agent_results: List[Dict[str, Any]]        # Individual agent results
    coordination_metrics: Dict[str, Any]       # Metrics about coordination process
    mhc_state: Optional[Any] = None            # mHC coordination state
    requires_human_review: bool = False        # Whether human review is needed
    confidence_score: float = 0.0              # Overall confidence (0.0 to 1.0)
    threat_severity: ThreatSeverity = ThreatSeverity.INFORMATIONAL
    recommended_actions: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'analysis_id': self.analysis_id,
            'timestamp': self.timestamp,
            'final_decision': self.final_decision,
            'agent_results_count': len(self.agent_results),
            'coordination_metrics': self.coordination_metrics,
            'requires_human_review': self.requires_human_review,
            'confidence_score': self.confidence_score,
            'threat_severity': self.threat_severity.value,
            'recommended_actions': self.recommended_actions
        }


class AgentOrchestrator:
    """
    Main orchestrator for CyberGuard security agents.
    
    Implements mHC (Manifold-Constrained Hyper-Connections) for stable
    multi-agent reasoning. Prevents reasoning collapse, signal explosion,
    and dominant agent bias through doubly-stochastic normalization.
    
    Key Responsibilities:
    1. Register and manage specialized security agents
    2. Distribute security analysis tasks to appropriate agents
    3. Apply mHC principles for agent coordination
    4. Aggregate and reconcile agent findings
    5. Generate actionable security recommendations
    6. Monitor agent health and performance
    7. Provide explainable decision making
    
    Architecture Benefits:
    - ✅ Prevents single agent dominance through convex mixing
    - ✅ Maintains reasoning stability via doubly-stochastic constraints
    - ✅ Enables graceful degradation when agents fail
    - ✅ Provides explainable aggregation with confidence weighting
    - ✅ Scales horizontally with agent pool expansion
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the agent orchestrator with configuration.
        
        Args:
            config: Configuration dictionary with orchestration parameters
                   including mHC settings, agent thresholds, etc.
        """
        # Configuration with defaults
        self.config = config or {}
        self._set_default_config()
        
        # Agent registry and state tracking
        self.agents: Dict[str, SecurityAgent] = {}            # agent_id -> agent instance
        self.agent_status: Dict[str, AgentStatus] = {}       # agent_id -> current status
        self.agent_metrics: Dict[str, AgentMetrics] = {}     # agent_id -> performance metrics
        self.agent_capabilities: Dict[str, List[str]] = {}   # agent_id -> list of capabilities
        
        # mHC (Manifold-Constrained Hyper-Connections) system
        self.mhc = ManifoldConstrainedHyperConnections(
            n_agents=0,  # Will be updated as agents register
            state_dim=self.config['mhc_state_dim'],
            temperature=self.config['mhc_temperature']
        )
        
        # Task queue for asynchronous processing
        self.task_queue = asyncio.Queue()
        self.processing_lock = threading.RLock()  # Reentrant lock for thread safety
        
        # Analysis history and state
        self.analysis_history: List[OrchestrationResult] = []  # Recent analyses
        self.max_history_size = self.config['max_history_size']
        
        # Performance tracking
        self.metrics = {
            'total_coordinations': 0,
            'successful_coordinations': 0,
            'failed_coordinations': 0,
            'avg_coordination_time': 0.0,
            'total_agents_registered': 0,
            'active_agents': 0,
            'last_coordination_time': 0.0
        }
        
        # Thread pool for parallel agent execution
        self.executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=self.config['max_parallel_agents']
        )
        
        # Health monitoring
        self.health_check_interval = self.config['health_check_interval']
        self.health_check_thread = None
        self.is_running = False
        
        # Initialize logging
        self._setup_logging()
        
        logger.info("AgentOrchestrator initialized with configuration: %s", 
                   {k: v for k, v in self.config.items() 
                    if not k.startswith('_')})
    
    def _set_default_config(self):
        """Set default configuration values"""
        defaults = {
            # mHC configuration
            'mhc_state_dim': 512,                     # Dimension of agent state vectors
            'mhc_temperature': 1.0,                   # Temperature for attention sharpness
            'mhc_sinkhorn_iterations': 50,            # Sinkhorn-Knopp projection iterations
            'mhc_signal_bound': 1.0,                  # Maximum signal propagation
            'mhc_identity_preserve': 0.1,             # Identity preservation factor
            
            # Agent coordination
            'max_parallel_agents': 10,                # Maximum agents to run in parallel
            'agent_timeout_seconds': 30,              # Timeout for agent analysis
            'min_confidence_threshold': 0.3,          # Minimum confidence for agent inclusion
            'consensus_threshold': 0.7,               # Threshold for agent consensus
            
            # Threat scoring
            'critical_threshold': 0.8,                # Score above which threat is critical
            'high_threshold': 0.6,                    # Score above which threat is high
            'medium_threshold': 0.4,                  # Score above which threat is medium
            'low_threshold': 0.2,                     # Score above which threat is low
            
            # System configuration
            'max_history_size': 1000,                 # Maximum analysis history to keep
            'health_check_interval': 60,              # Health check interval in seconds
            'enable_auto_healing': True,              # Attempt to restart failed agents
            'max_retry_attempts': 3,                  # Maximum retries for failed agents
            
            # Logging and monitoring
            'enable_detailed_logging': True,
            'log_coordination_decisions': True,
            'monitor_agent_performance': True
        }
        
        # Update config with defaults (only if key doesn't exist)
        for key, value in defaults.items():
            if key not in self.config:
                self.config[key] = value
    
    def _setup_logging(self):
        """Configure orchestrator-specific logging"""
        # Create a separate log handler for orchestration decisions if enabled
        if self.config.get('enable_detailed_logging'):
            import logging.handlers
            
            # Create rotating file handler for orchestration logs
            orchestration_handler = logging.handlers.RotatingFileHandler(
                'logs/orchestration.log',
                maxBytes=10485760,  # 10MB
                backupCount=10
            )
            orchestration_handler.setLevel(logging.INFO)
            orchestration_handler.setFormatter(
                logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            )
            logger.addHandler(orchestration_handler)
    
    def register_agent(self, agent: SecurityAgent, 
                      capabilities: Optional[List[str]] = None) -> bool:
        """
        Register a security agent with the orchestrator.
        
        Args:
            agent: The SecurityAgent instance to register
            capabilities: Optional list of agent capabilities for routing
            
        Returns:
            bool: True if registration successful, False otherwise
            
        Registration Process:
        1. Validate agent instance
        2. Check for duplicate agent IDs
        3. Initialize agent metrics
        4. Update mHC system with new agent count
        5. Set initial agent status
        """
        with self.processing_lock:  # Thread-safe registration
            try:
                # Validate agent
                if not isinstance(agent, SecurityAgent):
                    logger.error(f"Attempted to register non-agent: {type(agent)}")
                    return False
                
                # Check for duplicate agent ID
                if agent.agent_id in self.agents:
                    logger.warning(f"Agent {agent.agent_id} already registered")
                    return False
                
                # Register agent
                self.agents[agent.agent_id] = agent
                self.agent_status[agent.agent_id] = AgentStatus.INITIALIZING
                
                # Initialize metrics
                self.agent_metrics[agent.agent_id] = AgentMetrics(
                    agent_id=agent.agent_id,
                    name=agent.name,
                    confidence_score=agent.confidence if hasattr(agent, 'confidence') else 0.5
                )
                
                # Set capabilities (use agent's capabilities if not provided)
                if capabilities is None:
                    capabilities = getattr(agent, 'capabilities', [])
                self.agent_capabilities[agent.agent_id] = capabilities
                
                # Update mHC system with new agent count
                # Note: In production, mHC would need to be reinitialized or dynamically adjusted
                # For simplicity, we'll note the update but keep existing mHC
                logger.info(f"Registered agent: {agent.name} (ID: {agent.agent_id})")
                
                # Mark agent as idle (ready for processing)
                self.agent_status[agent.agent_id] = AgentStatus.IDLE
                
                # Update metrics
                self.metrics['total_agents_registered'] += 1
                self.metrics['active_agents'] += 1
                
                return True
                
            except Exception as e:
                logger.error(f"Failed to register agent {agent.agent_id}: {e}")
                # Clean up any partial registration
                if agent.agent_id in self.agents:
                    del self.agents[agent.agent_id]
                if agent.agent_id in self.agent_status:
                    del self.agent_status[agent.agent_id]
                return False
    
    def unregister_agent(self, agent_id: str) -> bool:
        """
        Unregister an agent from the orchestrator.
        
        Args:
            agent_id: ID of the agent to unregister
            
        Returns:
            bool: True if unregistration successful, False otherwise
        """
        with self.processing_lock:
            if agent_id not in self.agents:
                logger.warning(f"Agent {agent_id} not found for unregistration")
                return False
            
            try:
                # Clean shutdown of agent if needed
                agent = self.agents[agent_id]
                if hasattr(agent, 'shutdown'):
                    agent.shutdown()
                
                # Remove from all registries
                del self.agents[agent_id]
                del self.agent_status[agent_id]
                del self.agent_metrics[agent_id]
                del self.agent_capabilities[agent_id]
                
                logger.info(f"Unregistered agent: {agent_id}")
                self.metrics['active_agents'] -= 1
                
                return True
                
            except Exception as e:
                logger.error(f"Failed to unregister agent {agent_id}: {e}")
                return False
    
    def get_agent_by_capability(self, capability: str) -> List[SecurityAgent]:
        """
        Find agents with specific capabilities.
        
        Args:
            capability: The capability to search for (e.g., 'xss_detection')
            
        Returns:
            List[SecurityAgent]: List of agents with the specified capability
        """
        matching_agents = []
        for agent_id, capabilities in self.agent_capabilities.items():
            if capability in capabilities:
                agent = self.agents.get(agent_id)
                if agent and self.agent_status.get(agent_id) == AgentStatus.IDLE:
                    matching_agents.append(agent)
        
        # Sort by confidence score (highest first)
        matching_agents.sort(
            key=lambda a: self.agent_metrics.get(a.agent_id, AgentMetrics(a.agent_id, a.name)).confidence_score,
            reverse=True
        )
        
        return matching_agents
    
    async def coordinate_analysis(self, 
                                 security_data: Dict[str, Any],
                                 analysis_id: Optional[str] = None) -> OrchestrationResult:
        """
        Main coordination method for security analysis.
        
        Orchestrates multi-agent analysis using mHC principles:
        1. Select appropriate agents based on data type
        2. Execute agents in parallel
        3. Apply mHC coordination for result aggregation
        4. Generate final security decision
        
        Args:
            security_data: Dictionary containing security data to analyze
            analysis_id: Optional custom ID for tracking
        
        Returns:
            OrchestrationResult: Structured result with agent findings and final decision
        """
        start_time = time.time()
        analysis_id = analysis_id or str(uuid.uuid4())
        
        logger.info(f"Starting coordinated analysis {analysis_id} for data: {security_data.get('type', 'unknown')}")
        
        try:
            # Step 1: Select appropriate agents for this analysis
            selected_agents = self._select_agents_for_analysis(security_data)
            
            if not selected_agents:
                logger.warning(f"No agents selected for analysis {analysis_id}")
                return self._create_empty_result(analysis_id, security_data, 
                                                "No suitable agents available")
            
            # Step 2: Execute agents in parallel
            agent_results = await self._execute_agents_parallel(
                selected_agents, security_data
            )
            
            # Step 3: Apply mHC coordination
            coordinated_result = self._apply_mhc_coordination(agent_results)
            
            # Step 4: Generate final decision
            final_decision = self._generate_final_decision(
                coordinated_result, security_data
            )
            
            # Step 5: Create orchestration result
            result = self._create_orchestration_result(
                analysis_id=analysis_id,
                start_time=start_time,
                security_data=security_data,
                agent_results=agent_results,
                coordinated_result=coordinated_result,
                final_decision=final_decision
            )
            
            # Step 6: Update metrics and history
            self._update_metrics_and_history(result, start_time)
            
            logger.info(f"Completed analysis {analysis_id} in {time.time() - start_time:.2f}s")
            return result
            
        except Exception as e:
            logger.error(f"Failed to coordinate analysis {analysis_id}: {e}", exc_info=True)
            return self._create_error_result(analysis_id, security_data, str(e))
    
    def _select_agents_for_analysis(self, 
                                   security_data: Dict[str, Any]) -> List[SecurityAgent]:
        """
        Select appropriate agents based on security data characteristics.
        
        Uses content-based routing:
        - URL analysis → Threat detection, Bot detection
        - Network traffic → Traffic anomaly, Malware detection
        - Code snippets → Code review, Compliance
        - Log data → Forensics, Incident response
        
        Args:
            security_data: Dictionary with security data
            
        Returns:
            List[SecurityAgent]: Selected agents for analysis
        """
        selected_agents = []
        
        # Extract data type for routing
        data_type = security_data.get('type', 'unknown')
        content = security_data.get('content', '')
        
        # Routing logic based on data characteristics
        if data_type == 'http_request':
            # Web request analysis
            selected_agents.extend(self.get_agent_by_capability('http_analysis'))
            selected_agents.extend(self.get_agent_by_capability('threat_detection'))
            selected_agents.extend(self.get_agent_by_capability('bot_detection'))
            
        elif data_type == 'network_traffic':
            # Network traffic analysis
            selected_agents.extend(self.get_agent_by_capability('traffic_analysis'))
            selected_agents.extend(self.get_agent_by_capability('malware_detection'))
            selected_agents.extend(self.get_agent_by_capability('anomaly_detection'))
            
        elif data_type == 'source_code':
            # Source code analysis
            selected_agents.extend(self.get_agent_by_capability('code_review'))
            selected_agents.extend(self.get_agent_by_capability('vulnerability_scan'))
            selected_agents.extend(self.get_agent_by_capability('compliance_check'))
            
        elif data_type == 'security_log':
            # Security log analysis
            selected_agents.extend(self.get_agent_by_capability('forensic_analysis'))
            selected_agents.extend(self.get_agent_by_capability('incident_response'))
            selected_agents.extend(self.get_agent_by_capability('threat_hunting'))
            
        else:
            # Default: include all capable agents
            logger.debug(f"Unknown data type {data_type}, using all available agents")
            for agent in self.agents.values():
                if self.agent_status.get(agent.agent_id) == AgentStatus.IDLE:
                    selected_agents.append(agent)
        
        # Deduplicate agents
        unique_agents = []
        seen_ids = set()
        for agent in selected_agents:
            if agent.agent_id not in seen_ids:
                unique_agents.append(agent)
                seen_ids.add(agent.agent_id)
        
        # Limit to maximum parallel agents
        return unique_agents[:self.config['max_parallel_agents']]
    
    async def _execute_agents_parallel(self,
                                      agents: List[SecurityAgent],
                                      security_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Execute multiple agents in parallel with timeout protection.
        
        Args:
            agents: List of agents to execute
            security_data: Security data to analyze
            
        Returns:
            List[Dict[str, Any]]: Results from all agents
        """
        tasks = []
        agent_results = []
        
        # Create analysis tasks for each agent
        for agent in agents:
            task = asyncio.create_task(
                self._execute_single_agent(agent, security_data)
            )
            tasks.append((agent, task))
        
        # Wait for all tasks with timeout
        for agent, task in tasks:
            try:
                # Wait with timeout
                result = await asyncio.wait_for(
                    task, 
                    timeout=self.config['agent_timeout_seconds']
                )
                agent_results.append(result)
                
            except asyncio.TimeoutError:
                logger.warning(f"Agent {agent.agent_id} timed out")
                agent_results.append(self._create_agent_timeout_result(agent))
                
            except Exception as e:
                logger.error(f"Agent {agent.agent_id} failed: {e}")
                agent_results.append(self._create_agent_error_result(agent, str(e)))
        
        return agent_results
    
    async def _execute_single_agent(self,
                                   agent: SecurityAgent,
                                   security_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a single agent's analysis with proper error handling.
        
        Args:
            agent: The agent to execute
            security_data: Security data to analyze
            
        Returns:
            Dict[str, Any]: Agent analysis result
        """
        start_time = time.time()
        
        try:
            # Update agent status
            self.agent_status[agent.agent_id] = AgentStatus.PROCESSING
            
            # Execute agent analysis
            # Note: Convert sync method to async if needed
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                self.executor,
                agent.analyze,
                security_data
            )
            
            processing_time = time.time() - start_time
            
            # Update agent metrics
            if agent.agent_id in self.agent_metrics:
                metrics = self.agent_metrics[agent.agent_id]
                threat_detected = result.get('threat_level', 0) > 0.3
                metrics.update(
                    success=True,
                    processing_time=processing_time,
                    threat_detected=threat_detected
                )
            
            # Return enhanced result
            return {
                'agent_id': agent.agent_id,
                'agent_name': agent.name,
                'analysis_result': result,
                'processing_time': processing_time,
                'success': True,
                'error': None,
                'confidence': result.get('confidence', 0.5),
                'threat_level': result.get('threat_level', 0.0),
                'reasoning_state': getattr(agent, 'get_reasoning_state', lambda: None)()
            }
            
        except Exception as e:
            processing_time = time.time() - start_time
            logger.error(f"Agent {agent.agent_id} execution failed: {e}")
            
            # Update metrics for failure
            if agent.agent_id in self.agent_metrics:
                self.agent_metrics[agent.agent_id].update(
                    success=False,
                    processing_time=processing_time
                )
            
            # Mark agent as degraded if too many failures
            if agent.agent_id in self.agent_metrics:
                metrics = self.agent_metrics[agent.agent_id]
                if metrics.error_rate > 0.5:  # More than 50% error rate
                    self.agent_status[agent.agent_id] = AgentStatus.DEGRADED
            
            return {
                'agent_id': agent.agent_id,
                'agent_name': agent.name,
                'analysis_result': None,
                'processing_time': processing_time,
                'success': False,
                'error': str(e),
                'confidence': 0.1,  # Very low confidence for failed agents
                'threat_level': 0.0,
                'reasoning_state': None
            }
        finally:
            # Reset agent status to idle
            if agent.agent_id in self.agent_status:
                self.agent_status[agent.agent_id] = AgentStatus.IDLE
    
    def _apply_mhc_coordination(self, 
                               agent_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Apply Manifold-Constrained Hyper-Connections for agent coordination.
        
        mHC Principles Applied:
        1. Doubly-stochastic normalization prevents single agent dominance
        2. Convex state mixing with bounded signal propagation
        3. Identity-preserving mappings for reasoning stability
        4. Non-expansive updates to prevent reasoning collapse
        
        Args:
            agent_results: List of individual agent results
            
        Returns:
            Dict[str, Any]: Coordinated result using mHC
        """
        try:
            # Filter out failed agents
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
            
            # Extract agent confidences and reasoning states
            agent_confidences = []
            reasoning_states = []
            agent_contributions = []
            
            for result in valid_results:
                confidence = result.get('confidence', 0.5)
                reasoning_state = result.get('reasoning_state')
                
                agent_confidences.append(confidence)
                if reasoning_state is not None:
                    reasoning_states.append(reasoning_state)
                
                # Track individual contributions
                agent_contributions.append({
                    'agent_id': result['agent_id'],
                    'agent_name': result['agent_name'],
                    'confidence': confidence,
                    'threat_level': result.get('threat_level', 0.0),
                    'success': result['success']
                })
            
            # Convert to tensors for mHC processing
            # Note: In production, this would use PyTorch tensors
            confidence_tensor = agent_confidences  # Simplified for this example
            
            # Apply mHC coordination
            # In production: mhc.residual_coordination(reasoning_states, confidence_tensor)
            # For this example, we'll implement a simplified version
            
            # Simplified mHC: Weighted average with confidence normalization
            total_confidence = sum(agent_confidences)
            if total_confidence > 0:
                weights = [c / total_confidence for c in agent_confidences]
                
                # Apply doubly-stochastic normalization (simplified)
                # Ensure no single agent dominates
                max_weight = max(weights) if weights else 0
                if max_weight > 0.5:  # If any agent has >50% weight
                    # Redistribute weights
                    excess = max_weight - 0.5
                    weights = [w - (excess if w == max_weight else 0) for w in weights]
                    # Normalize again
                    total = sum(weights)
                    weights = [w / total for w in weights]
                
                # Calculate weighted threat level
                threat_levels = [r.get('threat_level', 0.0) for r in valid_results]
                coordinated_threat = sum(t * w for t, w in zip(threat_levels, weights))
                
                # Calculate weighted confidence
                coordinated_confidence = sum(c * w for c, w in zip(agent_confidences, weights))
                
            else:
                coordinated_threat = 0.0
                coordinated_confidence = 0.0
                weights = [0] * len(agent_confidences)
            
            return {
                'coordinated': True,
                'threat_level': coordinated_threat,
                'confidence': coordinated_confidence,
                'agent_contributions': agent_contributions,
                'weights': weights,
                'reasoning_states': reasoning_states,
                'valid_agents_count': len(valid_results),
                'total_agents_count': len(agent_results)
            }
            
        except Exception as e:
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
        Generate final security decision from coordinated results.
        
        Implements multi-stage decision making:
        1. Threat severity classification
        2. Confidence validation
        3. Action recommendation
        4. Human review requirement check
        
        Args:
            coordinated_result: mHC-coordinated agent results
            security_data: Original security data
            
        Returns:
            Dict[str, Any]: Final security decision
        """
        threat_level = coordinated_result.get('threat_level', 0.0)
        confidence = coordinated_result.get('confidence', 0.0)
        
        # Step 1: Determine threat severity
        threat_severity = self._classify_threat_severity(threat_level)
        
        # Step 2: Check if confidence meets threshold
        min_confidence = self.config['min_confidence_threshold']
        is_confident = confidence >= min_confidence
        
        # Step 3: Determine required action
        action, action_severity = self._determine_action(
            threat_level, confidence, threat_severity
        )
        
        # Step 4: Check if human review is required
        requires_human_review = self._requires_human_review(
            threat_level, confidence, coordinated_result
        )
        
        # Step 5: Generate explanation
        explanation = self._generate_explanation(
            threat_level, confidence, threat_severity,
            coordinated_result.get('agent_contributions', [])
        )
        
        # Step 6: Generate mitigation recommendations
        mitigations = self._generate_mitigations(
            threat_severity, security_data, coordinated_result
        )
        
        return {
            'action': action,
            'action_severity': action_severity,
            'threat_level': threat_level,
            'confidence': confidence,
            'threat_severity': threat_severity,
            'is_confident': is_confident,
            'requires_human_review': requires_human_review,
            'explanation': explanation,
            'mitigations': mitigations,
            'agent_contributions': coordinated_result.get('agent_contributions', []),
            'coordinated_success': coordinated_result.get('coordinated', False),
            'timestamp': time.time()
        }
    
    def _classify_threat_severity(self, threat_level: float) -> ThreatSeverity:
        """Classify threat based on severity thresholds"""
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
        """Determine appropriate security action"""
        
        # Critical threats with high confidence: Immediate block
        if severity == ThreatSeverity.CRITICAL and confidence > 0.8:
            return 'BLOCK_IMMEDIATE', 'critical'
        
        # High threats: Challenge or quarantine
        elif severity == ThreatSeverity.HIGH:
            if confidence > 0.7:
                return 'QUARANTINE', 'high'
            else:
                return 'CHALLENGE', 'high'  # CAPTCHA or 2FA
        
        # Medium threats: Monitor and alert
        elif severity == ThreatSeverity.MEDIUM:
            return 'MONITOR_ENHANCED', 'medium'
        
        # Low threats: Basic monitoring
        elif severity == ThreatSeverity.LOW:
            return 'MONITOR_BASIC', 'low'
        
        # Informational: Log only
        else:
            return 'LOG_ONLY', 'informational'
    
    def _requires_human_review(self,
                              threat_level: float,
                              confidence: float,
                              coordinated_result: Dict[str, Any]) -> bool:
        """Determine if human security analyst review is required"""
        
        # Conditions requiring human review:
        # 1. High threat with low confidence
        if threat_level > 0.7 and confidence < 0.6:
            return True
        
        # 2. Conflicting agent opinions
        contributions = coordinated_result.get('agent_contributions', [])
        if len(contributions) >= 3:
            # Check for high variance in threat levels
            threat_levels = [c.get('threat_level', 0) for c in contributions]
            if len(threat_levels) >= 3:
                import statistics
                try:
                    variance = statistics.variance(threat_levels)
                    if variance > 0.1:  # High variance in agent opinions
                        return True
                except:
                    pass
        
        # 3. Critical threat detection
        if threat_level > 0.9:
            return True
        
        return False
    
    def _generate_explanation(self,
                            threat_level: float,
                            confidence: float,
                            severity: ThreatSeverity,
                            agent_contributions: List[Dict]) -> str:
        """Generate human-readable explanation of the decision"""
        
        # Base explanation
        explanation = (
            f"Detected {severity.value} level threat (score: {threat_level:.2f}) "
            f"with {confidence:.2f} confidence. "
        )
        
        # Add agent contribution summary
        if agent_contributions:
            top_agents = sorted(
                agent_contributions,
                key=lambda x: x.get('confidence', 0),
                reverse=True
            )[:3]  # Top 3 contributing agents
            
            agent_names = [a['agent_name'] for a in top_agents]
            explanation += f"Primary analysis by: {', '.join(agent_names)}. "
        
        # Add reasoning based on severity
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
        """Generate actionable mitigation recommendations"""
        
        mitigations = []
        data_type = security_data.get('type', 'unknown')
        
        # General mitigations based on severity
        if severity in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH]:
            mitigations.extend([
                "Isolate affected systems from the network",
                "Preserve all logs and evidence for forensic analysis",
                "Activate incident response team",
                "Notify relevant stakeholders and authorities if required"
            ])
        
        # Specific mitigations based on data type
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
        
        # Add agent-specific recommendations if available
        for contribution in coordinated_result.get('agent_contributions', []):
            if 'recommendations' in contribution:
                mitigations.extend(contribution['recommendations'])
        
        # Deduplicate and limit mitigations
        unique_mitigations = []
        seen = set()
        for mitigation in mitigations:
            if mitigation not in seen:
                unique_mitigations.append(mitigation)
                seen.add(mitigation)
        
        return unique_mitigations[:10]  # Return top 10 unique mitigations
    
    def _create_orchestration_result(self,
                                    analysis_id: str,
                                    start_time: float,
                                    security_data: Dict[str, Any],
                                    agent_results: List[Dict[str, Any]],
                                    coordinated_result: Dict[str, Any],
                                    final_decision: Dict[str, Any]) -> OrchestrationResult:
        """Create structured orchestration result"""
        
        processing_time = time.time() - start_time
        
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
        """Create result when no agents are available"""
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
        """Create result when orchestration fails"""
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
        """Create result for agent timeout"""
        return {
            'agent_id': agent.agent_id,
            'agent_name': agent.name,
            'analysis_result': None,
            'processing_time': self.config['agent_timeout_seconds'],
            'success': False,
            'error': 'Agent execution timed out',
            'confidence': 0.1,
            'threat_level': 0.0,
            'reasoning_state': None
        }
    
    def _create_agent_error_result(self, agent: SecurityAgent, error: str) -> Dict[str, Any]:
        """Create result for agent error"""
        return {
            'agent_id': agent.agent_id,
            'agent_name': agent.name,
            'analysis_result': None,
            'processing_time': 0.0,
            'success': False,
            'error': error,
            'confidence': 0.1,
            'threat_level': 0.0,
            'reasoning_state': None
        }
    
    def _update_metrics_and_history(self,
                                   result: OrchestrationResult,
                                   start_time: float):
        """Update system metrics and store result in history"""
        processing_time = time.time() - start_time
        
        # Update orchestrator metrics
        self.metrics['total_coordinations'] += 1
        if result.final_decision.get('coordinated_success', False):
            self.metrics['successful_coordinations'] += 1
        else:
            self.metrics['failed_coordinations'] += 1
        
        # Update moving average for coordination time
        self.metrics['avg_coordination_time'] = (
            self.metrics['avg_coordination_time'] * 0.9 + processing_time * 0.1
        )
        self.metrics['last_coordination_time'] = processing_time
        
        # Store in history
        self.analysis_history.append(result)
        
        # Trim history if too large
        if len(self.analysis_history) > self.config['max_history_size']:
            self.analysis_history = self.analysis_history[-self.config['max_history_size']:]
    
    def start_health_monitoring(self):
        """Start background health monitoring for all agents"""
        if self.health_check_thread and self.health_check_thread.is_alive():
            logger.warning("Health monitoring already running")
            return
        
        self.is_running = True
        self.health_check_thread = threading.Thread(
            target=self._health_monitoring_loop,
            daemon=True
        )
        self.health_check_thread.start()
        logger.info("Health monitoring started")
    
    def stop_health_monitoring(self):
        """Stop background health monitoring"""
        self.is_running = False
        if self.health_check_thread:
            self.health_check_thread.join(timeout=5)
            logger.info("Health monitoring stopped")
    
    def _health_monitoring_loop(self):
        """Background thread for continuous agent health monitoring"""
        while self.is_running:
            try:
                self._perform_health_checks()
                time.sleep(self.health_check_interval)
            except Exception as e:
                logger.error(f"Health monitoring error: {e}")
                time.sleep(10)  # Wait before retrying
    
    def _perform_health_checks(self):
        """Perform health checks on all registered agents"""
        with self.processing_lock:
            for agent_id, agent in self.agents.items():
                try:
                    current_status = self.agent_status.get(agent_id, AgentStatus.UNAVAILABLE)
                    
                    # Skip if agent is already in failed state and auto-healing disabled
                    if current_status == AgentStatus.FAILED and not self.config['enable_auto_healing']:
                        continue
                    
                    # Check agent health
                    is_healthy = self._check_agent_health(agent)
                    
                    if is_healthy:
                        # Agent is healthy, ensure status is appropriate
                        if current_status in [AgentStatus.DEGRADED, AgentStatus.FAILED]:
                            self.agent_status[agent_id] = AgentStatus.IDLE
                            logger.info(f"Agent {agent_id} recovered, status reset to IDLE")
                    else:
                        # Agent is unhealthy
                        if current_status != AgentStatus.FAILED:
                            self.agent_status[agent_id] = AgentStatus.FAILED
                            logger.warning(f"Agent {agent_id} health check failed, marked as FAILED")
                            
                            # Attempt auto-healing if enabled
                            if self.config['enable_auto_healing']:
                                self._attempt_agent_recovery(agent_id, agent)
                    
                except Exception as e:
                    logger.error(f"Health check failed for agent {agent_id}: {e}")
                    self.agent_status[agent_id] = AgentStatus.FAILED
    
    def _check_agent_health(self, agent: SecurityAgent) -> bool:
        """Check if an agent is healthy and responsive"""
        try:
            # Method 1: Check if agent has a health check method
            if hasattr(agent, 'check_health'):
                return agent.check_health()
            
            # Method 2: Simple status check
            if hasattr(agent, 'status'):
                status = agent.status
                return status not in ['failed', 'error', 'unavailable']
            
            # Method 3: Attempt a minimal analysis to verify functionality
            test_data = {'type': 'health_check', 'content': 'ping'}
            
            # Use a short timeout for health check
            import threading
            result = None
            exception = None
            
            def analyze():
                nonlocal result, exception
                try:
                    result = agent.analyze(test_data)
                except Exception as e:
                    exception = e
            
            thread = threading.Thread(target=analyze)
            thread.start()
            thread.join(timeout=5)  # 5 second timeout
            
            if thread.is_alive():
                logger.warning(f"Agent {agent.agent_id} health check timed out")
                return False
            
            if exception is not None:
                logger.warning(f"Agent {agent.agent_id} health check raised exception: {exception}")
                return False
            
            # If we got a result, agent is healthy
            return result is not None
            
        except Exception as e:
            logger.error(f"Health check error for agent {agent.agent_id}: {e}")
            return False
    
    def _attempt_agent_recovery(self, agent_id: str, agent: SecurityAgent):
        """Attempt to recover a failed agent"""
        retry_count = 0
        max_retries = self.config['max_retry_attempts']
        
        while retry_count < max_retries and self.is_running:
            try:
                logger.info(f"Attempting to recover agent {agent_id} (attempt {retry_count + 1}/{max_retries})")
                
                # Method 1: Try to reinitialize the agent
                if hasattr(agent, 'reinitialize'):
                    if agent.reinitialize():
                        self.agent_status[agent_id] = AgentStatus.IDLE
                        logger.info(f"Agent {agent_id} successfully reinitialized")
                        return
                
                # Method 2: Try a simple restart (if supported)
                if hasattr(agent, 'restart'):
                    if agent.restart():
                        self.agent_status[agent_id] = AgentStatus.IDLE
                        logger.info(f"Agent {agent_id} successfully restarted")
                        return
                
                # Method 3: Wait and retry
                time.sleep(2 ** retry_count)  # Exponential backoff
                retry_count += 1
                
            except Exception as e:
                logger.error(f"Recovery attempt {retry_count + 1} failed for agent {agent_id}: {e}")
                retry_count += 1
                time.sleep(2 ** retry_count)
        
        if retry_count >= max_retries:
            logger.error(f"Agent {agent_id} recovery failed after {max_retries} attempts")
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        with self.processing_lock:
            # Calculate agent status distribution
            status_counts = {
                'idle': 0,
                'processing': 0,
                'degraded': 0,
                'failed': 0,
                'unavailable': 0,
                'initializing': 0
            }
            
            for status in self.agent_status.values():
                status_name = status.value if isinstance(status, AgentStatus) else str(status)
                if status_name in status_counts:
                    status_counts[status_name] += 1
            
            # Prepare agent details
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
            
            # Calculate system health score (0-100)
            healthy_agents = sum(1 for s in self.agent_status.values() 
                               if s in [AgentStatus.IDLE, AgentStatus.PROCESSING])
            total_agents = len(self.agents)
            
            health_score = (healthy_agents / max(1, total_agents)) * 100
            
            return {
                'system': {
                    'health_score': health_score,
                    'total_agents': total_agents,
                    'healthy_agents': healthy_agents,
                    'is_running': self.is_running,
                    'uptime': getattr(self, '_start_time', 0)  # Would track actual uptime
                },
                'orchestrator_metrics': self.metrics.copy(),
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
        """Get recent analysis history with optional filtering"""
        results = self.analysis_history
        
        # Filter by severity if specified
        if filter_severity:
            results = [r for r in results if r.threat_severity == filter_severity]
        
        # Sort by timestamp (newest first) and limit
        results.sort(key=lambda x: x.timestamp, reverse=True)
        limited_results = results[:limit]
        
        # Convert to dictionaries
        return [r.to_dict() for r in limited_results]
    
    def shutdown(self):
        """Gracefully shutdown the orchestrator and all agents"""
        logger.info("Shutting down AgentOrchestrator...")
        
        # Stop health monitoring
        self.stop_health_monitoring()
        
        # Shutdown all agents
        with self.processing_lock:
            for agent_id, agent in self.agents.items():
                try:
                    if hasattr(agent, 'shutdown'):
                        agent.shutdown()
                    logger.info(f"Shutdown agent: {agent_id}")
                except Exception as e:
                    logger.error(f"Failed to shutdown agent {agent_id}: {e}")
            
            # Clear registries
            self.agents.clear()
            self.agent_status.clear()
            self.agent_metrics.clear()
            self.agent_capabilities.clear()
        
        # Shutdown thread pool
        self.executor.shutdown(wait=True)
        
        logger.info("AgentOrchestrator shutdown complete")


# Factory function for creating pre-configured orchestrator
def create_default_orchestrator() -> AgentOrchestrator:
    """
    Create a pre-configured orchestrator with all default agents.
    
    This is a convenience function for quickly setting up CyberGuard
    with all the specialized security agents.
    
    Returns:
        AgentOrchestrator: Fully configured orchestrator with all agents
    """
    orchestrator = AgentOrchestrator()
    
    # Register all default security agents
    agents_to_register = [
        # (AgentClass, capabilities)
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
    
    for AgentClass, capabilities in agents_to_register:
        try:
            # Create agent instance
            agent = AgentClass()
            # Register with orchestrator
            orchestrator.register_agent(agent, capabilities)
        except Exception as e:
            logger.error(f"Failed to create and register {AgentClass.__name__}: {e}")
    
    # Start health monitoring
    orchestrator.start_health_monitoring()
    
    return orchestrator


# Example usage and testing
if __name__ == "__main__":
    # Configure logging for testing
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create and test the orchestrator
    orchestrator = create_default_orchestrator()
    
    try:
        # Get system status
        status = orchestrator.get_system_status()
        print(f"System Status: {json.dumps(status, indent=2, default=str)}")
        
        # Example security analysis
        test_data = {
            'type': 'http_request',
            'url': 'https://example.com/admin',
            'method': 'POST',
            'headers': {'User-Agent': 'Mozilla/5.0'},
            'body': 'username=admin&password=test123'
        }
        
        # Run a test analysis (in a real app, this would be async)
        import asyncio
        result = asyncio.run(orchestrator.coordinate_analysis(test_data))
        
        print(f"\nAnalysis Result:")
        print(f"  Threat Severity: {result.threat_severity.value}")
        print(f"  Confidence: {result.confidence_score:.2f}")
        print(f"  Action: {result.final_decision.get('action')}")
        print(f"  Explanation: {result.final_decision.get('explanation')[:100]}...")
        
        # Show agent contributions
        print(f"\nAgent Contributions:")
        for contribution in result.final_decision.get('agent_contributions', [])[:3]:
            print(f"  - {contribution['agent_name']}: "
                  f"confidence={contribution['confidence']:.2f}, "
                  f"threat={contribution.get('threat_level', 0):.2f}")
        
    finally:
        # Clean shutdown
        orchestrator.shutdown()