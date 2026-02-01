"""
Agent Training Module for Cybersecurity Agents
Purpose: Train specialized security agents using reinforcement learning and imitation learning

This module implements:
1. Multi-agent reinforcement learning for coordinated threat detection
2. Imitation learning from expert security analysts
3. Curriculum learning for progressive difficulty
4. Transfer learning between agent types
5. Self-play for adversarial training
6. Meta-learning for rapid adaptation
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from torch.distributions import Categorical, Normal
import numpy as np
from typing import Dict, List, Tuple, Optional, Any, Callable
import time
import logging
from pathlib import Path
from collections import deque, defaultdict
import random
from dataclasses import dataclass
from enum import Enum
import pickle
import json
from torch.utils.data import DataLoader  # Added missing import


class TrainingMode(Enum):
    """Training modes for security agents"""
    REINFORCEMENT_LEARNING = "rl"  # Learn through rewards
    IMITATION_LEARNING = "il"  # Learn from expert demonstrations
    CURRICULUM_LEARNING = "cl"  # Progressive difficulty
    TRANSFER_LEARNING = "tl"  # Transfer knowledge between agents
    META_LEARNING = "ml"  # Learn to learn quickly
    SELF_PLAY = "sp"  # Learn by playing against self


class AgentType(Enum):
    """Types of security agents"""
    THREAT_DETECTION = "threat_detection"
    TRAFFIC_ANOMALY = "traffic_anomaly"
    BOT_DETECTION = "bot_detection"
    MALWARE_ANALYSIS = "malware_analysis"
    EXPLOIT_CHAIN = "exploit_chain"
    INCIDENT_RESPONSE = "incident_response"


@dataclass
class AgentTrainingConfig:
    """
    Configuration for agent training
    
    Each parameter carefully tuned for security agent training
    """
    # Agent configuration
    agent_type: AgentType = AgentType.THREAT_DETECTION
    state_dim: int = 512  # Dimension of state representation
    action_dim: int = 10  # Number of possible actions (threat classifications)
    
    # Training mode
    training_mode: TrainingMode = TrainingMode.REINFORCEMENT_LEARNING
    
    # Reinforcement learning parameters
    gamma: float = 0.99  # Discount factor for future rewards
    lambda_: float = 0.95  # GAE (Generalized Advantage Estimation) parameter
    clip_epsilon: float = 0.2  # PPO clipping parameter
    entropy_coef: float = 0.01  # Entropy regularization coefficient
    value_coef: float = 0.5  # Value loss coefficient
    
    # Training hyperparameters
    learning_rate: float = 3e-4
    batch_size: int = 64
    num_epochs: int = 1000
    steps_per_epoch: int = 4000
    mini_batch_size: int = 64
    
    # Memory and experience replay
    replay_buffer_size: int = 100000
    priority_replay: bool = True  # Prioritized experience replay
    priority_alpha: float = 0.6  # Priority exponent
    priority_beta: float = 0.4  # Importance sampling exponent
    
    # Exploration strategy
    exploration_strategy: str = "epsilon_greedy"  # epsilon_greedy, softmax, ucb
    epsilon_start: float = 1.0  # Initial exploration rate
    epsilon_end: float = 0.01  # Final exploration rate
    epsilon_decay: float = 0.995  # Exploration rate decay
    
    # Curriculum learning
    curriculum_enabled: bool = True
    curriculum_levels: int = 10
    level_up_threshold: float = 0.8  # Success rate needed to advance
    
    # Transfer learning
    transfer_source: Optional[str] = None  # Source agent for transfer
    transfer_freeze_layers: bool = True  # Freeze early layers during transfer
    
    # Meta-learning
    meta_batch_size: int = 16  # Number of tasks per meta-update
    meta_lr: float = 1e-3  # Meta-learning rate
    inner_lr: float = 0.1  # Inner loop learning rate
    adaptation_steps: int = 5  # Steps for fast adaptation
    
    # Self-play
    self_play_enabled: bool = False
    opponent_pool_size: int = 10  # Size of opponent pool
    self_play_update_freq: int = 100  # Update opponent pool frequency
    
    # Checkpointing
    save_frequency: int = 100  # Save checkpoint every N episodes
    checkpoint_dir: str = "./checkpoints/agents"
    
    # Evaluation
    eval_frequency: int = 10  # Evaluate every N episodes
    eval_episodes: int = 20  # Number of episodes for evaluation


class ExperienceReplayBuffer:
    """
    Experience replay buffer for storing agent experiences
    
    Supports:
    - Standard experience replay
    - Prioritized experience replay
    - N-step returns
    - Multi-agent experiences
    """
    
    def __init__(self, buffer_size: int, state_dim: int, 
                 priority_replay: bool = True):
        """
        Initialize experience replay buffer
        
        Args:
            buffer_size: Maximum number of experiences to store
            state_dim: Dimension of state representation
            priority_replay: Whether to use prioritized experience replay
        """
        self.buffer_size = buffer_size
        self.state_dim = state_dim
        self.priority_replay = priority_replay
        
        # Initialize buffers with proper numpy data types
        self.states = np.zeros((buffer_size, state_dim), dtype=np.float32)
        self.actions = np.zeros(buffer_size, dtype=np.int32)
        self.rewards = np.zeros(buffer_size, dtype=np.float32)
        self.next_states = np.zeros((buffer_size, state_dim), dtype=np.float32)
        self.dones = np.zeros(buffer_size, dtype=np.bool_)  # Changed from np.bool to np.bool_
        
        # For prioritized replay
        if priority_replay:
            self.priorities = np.zeros(buffer_size, dtype=np.float32)
            self.max_priority = 1.0  # Initial priority for new experiences
        
        self.position = 0  # Current position in circular buffer
        self.size = 0  # Current number of stored experiences
        
    def add(self, state: np.ndarray, action: int, reward: float,
            next_state: np.ndarray, done: bool):
        """
        Add experience to buffer
        
        Args:
            state: Current state
            action: Action taken
            reward: Reward received
            next_state: Next state
            done: Whether episode ended
        """
        idx = self.position
        
        # Store experience at current position
        self.states[idx] = state
        self.actions[idx] = action
        self.rewards[idx] = reward
        self.next_states[idx] = next_state
        self.dones[idx] = done
        
        # Initialize priority for new experience if using prioritized replay
        if self.priority_replay:
            self.priorities[idx] = self.max_priority
        
        # Update buffer position (circular buffer)
        self.position = (self.position + 1) % self.buffer_size
        self.size = min(self.size + 1, self.buffer_size)  # Increment size, capped at buffer_size
    
    def sample(self, batch_size: int, beta: float = 0.4) -> Dict[str, np.ndarray]:
        """
        Sample batch of experiences from buffer
        
        Args:
            batch_size: Number of experiences to sample
            beta: Importance sampling exponent for prioritized replay
            
        Returns:
            Dictionary containing sampled experiences
        """
        # Check if buffer has enough samples
        if self.size < batch_size:
            raise ValueError(f"Buffer size {self.size} < batch size {batch_size}")
        
        if self.priority_replay:
            # Sample with probability proportional to priority (alpha=0.6)
            priorities = self.priorities[:self.size]
            probs = priorities ** 0.6  # alpha=0.6
            probs = probs / probs.sum()  # Normalize to probabilities
            
            # Sample indices based on probabilities
            indices = np.random.choice(self.size, batch_size, p=probs)
            
            # Compute importance sampling weights for bias correction
            weights = (self.size * probs[indices]) ** (-beta)
            weights = weights / weights.max()  # Normalize weights to max=1
        else:
            # Uniform sampling - random indices from buffer
            indices = np.random.choice(self.size, batch_size, replace=False)
            weights = np.ones(batch_size, dtype=np.float32)  # All weights equal
        
        # Extract experiences at sampled indices
        batch = {
            'states': self.states[indices],
            'actions': self.actions[indices],
            'rewards': self.rewards[indices],
            'next_states': self.next_states[indices],
            'dones': self.dones[indices],
            'indices': indices if self.priority_replay else None,  # Only return indices for priority updates
            'weights': weights if self.priority_replay else None  # Only return weights for priority replay
        }
        
        return batch
    
    def update_priorities(self, indices: np.ndarray, priorities: np.ndarray):
        """
        Update priorities for sampled experiences
        
        Args:
            indices: Indices of experiences to update
            priorities: New priorities
        """
        if not self.priority_replay:
            return  # Nothing to update if not using prioritized replay
        
        # Update priorities at given indices
        self.priorities[indices] = priorities
        
        # Update maximum priority for new experiences
        self.max_priority = max(self.max_priority, priorities.max())
    
    def save(self, filepath: str):
        """
        Save buffer to disk
        
        Args:
            filepath: Path to save buffer
        """
        # Prepare buffer data for serialization
        buffer_data = {
            'states': self.states[:self.size],
            'actions': self.actions[:self.size],
            'rewards': self.rewards[:self.size],
            'next_states': self.next_states[:self.size],
            'dones': self.dones[:self.size],
            'position': self.position,
            'size': self.size
        }
        
        # Add priority data if using prioritized replay
        if self.priority_replay:
            buffer_data['priorities'] = self.priorities[:self.size]
            buffer_data['max_priority'] = self.max_priority
        
        # Serialize data using pickle
        with open(filepath, 'wb') as f:
            pickle.dump(buffer_data, f)
    
    def load(self, filepath: str):
        """
        Load buffer from disk
        
        Args:
            filepath: Path to load buffer from
        """
        # Deserialize data from pickle file
        with open(filepath, 'rb') as f:
            buffer_data = pickle.load(f)
        
        # Get size of loaded data
        data_size = buffer_data['states'].shape[0]
        
        # Load data into buffer arrays
        self.states[:data_size] = buffer_data['states']
        self.actions[:data_size] = buffer_data['actions']
        self.rewards[:data_size] = buffer_data['rewards']
        self.next_states[:data_size] = buffer_data['next_states']
        self.dones[:data_size] = buffer_data['dones']
        
        # Restore buffer state
        self.position = buffer_data['position']
        self.size = buffer_data['size']
        
        # Load priority data if available
        if self.priority_replay and 'priorities' in buffer_data:
            self.priorities[:data_size] = buffer_data['priorities']
            self.max_priority = buffer_data.get('max_priority', 1.0)


class SecurityAgentPolicy(nn.Module):
    """
    Policy network for security agent
    
    Implements actor-critic architecture for reinforcement learning
    Can be used for various security agent types
    """
    
    def __init__(self, state_dim: int, action_dim: int, hidden_dim: int = 256):
        """
        Initialize policy network
        
        Args:
            state_dim: Dimension of state input
            action_dim: Dimension of action output
            hidden_dim: Dimension of hidden layers
        """
        super().__init__()
        
        # Shared feature extractor - processes state into features
        self.feature_extractor = nn.Sequential(
            nn.Linear(state_dim, hidden_dim),  # Linear transformation
            nn.LayerNorm(hidden_dim),  # Layer normalization for stability
            nn.GELU(),  # Gaussian Error Linear Unit activation
            nn.Linear(hidden_dim, hidden_dim),  # Second linear layer
            nn.LayerNorm(hidden_dim),  # Another layer normalization
            nn.GELU()  # Final activation
        )
        
        # Actor network (policy) - outputs action probabilities
        self.actor = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),  # Hidden layer
            nn.GELU(),  # Activation function
            nn.Linear(hidden_dim, action_dim)  # Output layer for actions
        )
        
        # Critic network (value function) - estimates state value
        self.critic = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),  # Hidden layer
            nn.GELU(),  # Activation function
            nn.Linear(hidden_dim, 1)  # Single output for state value
        )
        
        # Initialize weights using orthogonal initialization
        self.apply(self._init_weights)
    
    def _init_weights(self, module):
        """Initialize network weights using orthogonal initialization"""
        if isinstance(module, nn.Linear):  # Only initialize Linear layers
            nn.init.orthogonal_(module.weight, gain=np.sqrt(2))  # Orthogonal init
            nn.init.constant_(module.bias, 0.0)  # Zero bias initialization
    
    def forward(self, state: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Forward pass through policy network
        
        Args:
            state: Input state tensor [batch_size, state_dim]
            
        Returns:
            Tuple of (action_logits, state_value)
        """
        # Extract features from state
        features = self.feature_extractor(state)
        
        # Get action logits (unnormalized probabilities) from actor
        action_logits = self.actor(features)
        
        # Get state value estimate from critic
        state_value = self.critic(features)
        
        return action_logits, state_value
    
    def get_action(self, state: torch.Tensor, 
                   deterministic: bool = False) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Sample action from policy
        
        Args:
            state: Input state tensor [batch_size, state_dim]
            deterministic: Whether to use deterministic policy
            
        Returns:
            Tuple of (action, log_prob, entropy, state_value)
        """
        # Get action logits and value from forward pass
        action_logits, state_value = self.forward(state)
        
        # Create categorical distribution over actions using logits
        action_dist = Categorical(logits=action_logits)
        
        if deterministic:
            # Use mode of distribution (most probable action)
            action = torch.argmax(action_logits, dim=-1)
            log_prob = action_dist.log_prob(action)  # Log probability of chosen action
        else:
            # Sample action from distribution (exploration)
            action = action_dist.sample()
            log_prob = action_dist.log_prob(action)  # Log probability of sampled action
        
        # Compute entropy of distribution (measure of uncertainty)
        entropy = action_dist.entropy()
        
        return action, log_prob, entropy, state_value
    
    def evaluate_actions(self, states: torch.Tensor, 
                        actions: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Evaluate actions under current policy
        
        Args:
            states: Batch of states [batch_size, state_dim]
            actions: Batch of actions [batch_size]
            
        Returns:
            Tuple of (log_probs, entropy, values)
        """
        # Get action logits and state values from forward pass
        action_logits, values = self.forward(states)
        
        # Create categorical distribution over actions
        action_dist = Categorical(logits=action_logits)
        
        # Compute log probabilities of given actions
        log_probs = action_dist.log_prob(actions)
        
        # Compute entropy of distribution
        entropy = action_dist.entropy()
        
        return log_probs, entropy, values


class CurriculumManager:
    """
    Manages curriculum learning for progressive difficulty
    
    Gradually increases task difficulty as agent improves
    """
    
    def __init__(self, num_levels: int = 10, 
                 level_up_threshold: float = 0.8):
        """
        Initialize curriculum manager
        
        Args:
            num_levels: Number of difficulty levels
            level_up_threshold: Success rate needed to advance
        """
        self.num_levels = num_levels
        self.level_up_threshold = level_up_threshold
        
        # Current level and performance tracking
        self.current_level = 0  # Start at level 0 (easiest)
        self.level_performance = defaultdict(list)  # Track performance per level
        
        # Create configurations for each difficulty level
        self.level_configs = self._create_level_configs()
    
    def _create_level_configs(self) -> List[Dict[str, Any]]:
        """
        Create configurations for each difficulty level
        
        Returns:
            List of level configurations
        """
        configs = []  # List to store configurations for each level
        
        for level in range(self.num_levels):
            # Base difficulty increases linearly with level (0 to 1)
            difficulty = level / max(1, (self.num_levels - 1))  # Avoid division by zero
            
            # Create configuration for this level
            config = {
                'level': level,
                'difficulty': difficulty,
                
                # Threat detection parameters - increase with difficulty
                'threat_complexity': 0.1 + 0.9 * difficulty,  # 0.1 to 1.0
                'obfuscation_level': 0.0 + 0.8 * difficulty,   # 0.0 to 0.8
                'noise_level': 0.0 + 0.5 * difficulty,         # 0.0 to 0.5
                
                # Traffic anomaly parameters
                'anomaly_rate': 0.05 + 0.25 * difficulty,      # 5% to 30%
                'attack_sophistication': 0.1 + 0.9 * difficulty,
                
                # Bot detection parameters
                'bot_evasion_techniques': int(1 + 4 * difficulty),  # 1 to 5 techniques
                'request_rate': 1.0 + 4.0 * difficulty,        # 1x to 5x normal rate
                
                # Malware analysis parameters
                'packing_level': 0.0 + 0.7 * difficulty,       # 0% to 70% packed
                'polymorphic_variants': int(1 + 4 * difficulty),  # 1 to 5 variants
                
                # Reward scaling - adjust rewards based on difficulty
                'reward_scale': 0.5 + 0.5 * difficulty,        # 0.5x to 1.0x
                'penalty_multiplier': 1.0 + 2.0 * difficulty,  # 1x to 3x
            }
            
            configs.append(config)  # Add config to list
        
        return configs
    
    def update_performance(self, success: bool):
        """
        Update performance for current level
        
        Args:
            success: Whether agent succeeded in current task
        """
        # Append success/failure to current level's performance history
        self.level_performance[self.current_level].append(success)
        
        # Keep only recent performances (last 100 episodes) to prevent memory growth
        if len(self.level_performance[self.current_level]) > 100:
            self.level_performance[self.current_level] = \
                self.level_performance[self.current_level][-100:]
    
    def check_level_up(self) -> bool:
        """
        Check if agent should level up
        
        Returns:
            True if agent should advance to next level
        """
        # Check if already at maximum level
        if self.current_level >= self.num_levels - 1:
            return False  # Already at max level
        
        # Get performance history for current level
        performances = self.level_performance[self.current_level]
        
        # Need minimum samples to make level-up decision
        if len(performances) < 20:
            return False  # Not enough data
        
        # Compute success rate over recent 50 episodes
        recent_performances = performances[-50:] if len(performances) >= 50 else performances
        success_rate = np.mean(recent_performances)
        
        # Check if success rate exceeds threshold
        if success_rate >= self.level_up_threshold:
            # Level up: increment current level
            self.current_level += 1
            # Initialize empty performance list for new level
            self.level_performance[self.current_level] = []
            return True
        
        return False  # Not ready to level up
    
    def check_level_down(self) -> bool:
        """
        Check if agent should level down (for struggling)
        
        Returns:
            True if agent should go back a level
        """
        # Check if already at minimum level
        if self.current_level <= 0:
            return False  # Already at minimum level
        
        # Get performance history for current level
        performances = self.level_performance[self.current_level]
        
        # Need sufficient samples to make level-down decision
        if len(performances) < 50:
            return False  # Not enough data
        
        # Compute overall success rate at current level
        success_rate = np.mean(performances)
        
        # If agent is struggling badly (less than 30% success), go back a level
        if success_rate < 0.3:
            self.current_level -= 1  # Level down
            return True
        
        return False  # Keep at current level
    
    def get_current_config(self) -> Dict[str, Any]:
        """
        Get configuration for current level
        
        Returns:
            Current level configuration
        """
        # Return configuration for current difficulty level
        return self.level_configs[self.current_level]
    
    def get_progress(self) -> Dict[str, Any]:
        """
        Get curriculum progress information
        
        Returns:
            Progress information
        """
        # Calculate level progress based on previous level's performance
        if self.current_level == 0:
            level_progress = 0.0  # Starting level has no previous performance
        else:
            # Get performance from previous level
            performances = self.level_performance[self.current_level - 1]
            if len(performances) > 0:
                # Compute average success rate over recent 20 episodes
                recent_performances = performances[-20:] if len(performances) >= 20 else performances
                level_progress = np.mean(recent_performances)
            else:
                level_progress = 0.0  # No performance data
        
        # Return progress information
        return {
            'current_level': self.current_level,
            'max_level': self.num_levels - 1,
            'level_progress': level_progress,
            'config': self.get_current_config()
        }


class AgentTrainer:
    """
    Trainer for cybersecurity agents
    
    Supports multiple training modes:
    - Reinforcement learning
    - Imitation learning
    - Curriculum learning
    - Transfer learning
    - Meta-learning
    - Self-play
    """
    
    def __init__(self, agent_policy: SecurityAgentPolicy, 
                 config: AgentTrainingConfig):
        """
        Initialize agent trainer
        
        Args:
            agent_policy: Policy network to train
            config: Training configuration
        """
        self.agent_policy = agent_policy
        self.config = config
        
        # Setup device (GPU if available, otherwise CPU)
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.agent_policy.to(self.device)  # Move model to device
        
        # Setup optimizer (Adam optimizer for parameter updates)
        self.optimizer = optim.Adam(
            self.agent_policy.parameters(),  # Parameters to optimize
            lr=config.learning_rate  # Learning rate from config
        )
        
        # Setup experience replay buffer
        self.replay_buffer = ExperienceReplayBuffer(
            buffer_size=config.replay_buffer_size,  # Max buffer size
            state_dim=config.state_dim,  # State dimension
            priority_replay=config.priority_replay  # Whether to use prioritized replay
        )
        
        # Setup curriculum manager if curriculum learning is enabled
        if config.curriculum_enabled:
            self.curriculum = CurriculumManager(
                num_levels=config.curriculum_levels,  # Number of difficulty levels
                level_up_threshold=config.level_up_threshold  # Threshold to advance
            )
        else:
            self.curriculum = None  # No curriculum learning
        
        # Exploration strategy initialization
        self.epsilon = config.epsilon_start  # Initial exploration rate
        self.exploration_decay = config.epsilon_decay  # Decay rate for exploration
        
        # Training state tracking
        self.episode = 0  # Current episode number
        self.total_steps = 0  # Total training steps taken
        self.best_reward = -float('inf')  # Best reward achieved so far
        
        # Metrics tracking dictionary
        self.metrics = {
            'episode_rewards': [],  # List of episode rewards
            'episode_lengths': [],  # List of episode lengths
            'exploration_rate': [],  # List of exploration rates
            'value_loss': [],  # List of value losses
            'policy_loss': [],  # List of policy losses
            'entropy': []  # List of entropy values
        }
        
        # For self-play: opponent pool initialization
        if config.self_play_enabled:
            self.opponent_pool = []  # List to store opponent models
            self.opponent_pool_size = config.opponent_pool_size  # Max pool size
        
        # Setup logging
        self.logger = self._setup_logger()
        
        # Log initialization information
        self.logger.info(f"Agent Trainer initialized for {config.agent_type}")
        self.logger.info(f"Training mode: {config.training_mode}")
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logging configuration"""
        # Create logger instance
        logger = logging.getLogger("AgentTrainer")
        logger.setLevel(logging.INFO)  # Set logging level to INFO
        
        # Create logs directory if it doesn't exist
        log_dir = Path("logs/agents")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # File handler for logging to file
        file_handler = logging.FileHandler(
            log_dir / f"agent_training_{time.strftime('%Y%m%d_%H%M%S')}.log"
        )
        file_handler.setLevel(logging.INFO)
        
        # Console handler for logging to console
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatter for log messages
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers to logger
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def compute_gae(self, rewards: np.ndarray, values: np.ndarray,
                   next_values: np.ndarray, dones: np.ndarray) -> np.ndarray:
        """
        Compute Generalized Advantage Estimation (GAE)
        
        Args:
            rewards: Array of rewards
            values: Array of value estimates
            next_values: Array of next state value estimates
            dones: Array of done flags
            
        Returns:
            Array of advantages
        """
        advantages = np.zeros_like(rewards)  # Initialize advantages array
        last_advantage = 0  # Initialize last advantage for recursion
        
        # Compute advantages in reverse temporal order (from last step to first)
        for t in reversed(range(len(rewards))):
            # Check if episode ended at this step
            if dones[t]:
                # TD error for terminal state
                delta = rewards[t] - values[t]
                last_advantage = delta  # Reset advantage for next episode
            else:
                # TD error for non-terminal state
                delta = rewards[t] + self.config.gamma * next_values[t] - values[t]
                # GAE recursion: current delta + discounted future advantage
                last_advantage = delta + self.config.gamma * self.config.lambda_ * last_advantage
            
            # Store computed advantage
            advantages[t] = last_advantage
        
        return advantages
    
    def collect_experience(self, env, num_steps: int) -> Dict[str, Any]:
        """
        Collect experience by interacting with environment
        
        Args:
            env: Training environment
            num_steps: Number of steps to collect
            
        Returns:
            Dictionary with collected experience
        """
        # Initialize lists to store experience
        states = []
        actions = []
        rewards = []
        next_states = []
        dones = []
        values = []
        log_probs = []
        
        # Reset environment to initial state
        state = env.reset()
        
        # Collect experience for specified number of steps
        for step in range(num_steps):
            # Convert state to tensor and add batch dimension
            state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)
            
            # Get action from policy (with exploration)
            with torch.no_grad():  # No gradient computation during collection
                if random.random() < self.epsilon and self.config.training_mode == TrainingMode.REINFORCEMENT_LEARNING:
                    # Exploration: choose random action (epsilon-greedy)
                    action = torch.randint(0, self.config.action_dim, (1,)).item()
                    log_prob = torch.log(torch.tensor(1.0 / self.config.action_dim))
                    # Estimate value for random action
                    value = self.agent_policy.critic(
                        self.agent_policy.feature_extractor(state_tensor)
                    ).item()
                    entropy = torch.log(torch.tensor(self.config.action_dim))
                else:
                    # Exploitation: get action from policy network
                    action_tensor, log_prob_tensor, entropy_tensor, value_tensor = \
                        self.agent_policy.get_action(state_tensor)
                    
                    action = action_tensor.item()
                    log_prob = log_prob_tensor.item()
                    value = value_tensor.item()
            
            # Take action in environment, get next state, reward, done flag
            next_state, reward, done, _ = env.step(action)
            
            # Store experience components
            states.append(state)
            actions.append(action)
            rewards.append(reward)
            next_states.append(next_state)
            dones.append(done)
            values.append(value)
            log_probs.append(log_prob)
            
            # Update state for next step
            state = next_state if not done else env.reset()
            
            # Update exploration rate (decay epsilon)
            self.epsilon = max(self.config.epsilon_end, 
                             self.epsilon * self.exploration_decay)
            
            # Increment total steps counter
            self.total_steps += 1
        
        # Convert lists to numpy arrays for efficiency
        states = np.array(states)
        actions = np.array(actions)
        rewards = np.array(rewards)
        next_states = np.array(next_states)
        dones = np.array(dones)
        values = np.array(values)
        log_probs = np.array(log_probs)
        
        # Return collected experience as dictionary
        return {
            'states': states,
            'actions': actions,
            'rewards': rewards,
            'next_states': next_states,
            'dones': dones,
            'values': values,
            'log_probs': log_probs
        }
    
    def train_reinforcement_learning(self, env, num_episodes: int):
        """
        Train agent using reinforcement learning (PPO)
        
        Args:
            env: Training environment
            num_episodes: Number of episodes to train
        """
        self.logger.info(f"Starting RL training for {num_episodes} episodes")
        
        for episode in range(num_episodes):
            self.episode = episode + 1  # Update episode counter
            episode_start_time = time.time()  # Start timing episode
            
            # Collect experience by interacting with environment
            experience = self.collect_experience(env, self.config.steps_per_epoch)
            
            # Compute advantages and returns for PPO
            with torch.no_grad():  # No gradients needed for advantage computation
                # Get value estimates for next states
                next_states_tensor = torch.FloatTensor(experience['next_states']).to(self.device)
                next_values = self.agent_policy.critic(
                    self.agent_policy.feature_extractor(next_states_tensor)
                ).squeeze(-1).cpu().numpy()  # Remove extra dimension and convert to numpy
            
            # Compute GAE advantages using collected experience
            advantages = self.compute_gae(
                experience['rewards'],  # Rewards
                experience['values'],  # Current value estimates
                next_values,  # Next state value estimates
                experience['dones']  # Done flags
            )
            
            # Normalize advantages for training stability
            advantages = (advantages - advantages.mean()) / (advantages.std() + 1e-8)
            
            # Compute returns (advantages + values)
            returns = advantages + experience['values']
            
            # Convert numpy arrays to PyTorch tensors
            states_tensor = torch.FloatTensor(experience['states']).to(self.device)
            actions_tensor = torch.LongTensor(experience['actions']).to(self.device)
            old_log_probs_tensor = torch.FloatTensor(experience['log_probs']).to(self.device)
            advantages_tensor = torch.FloatTensor(advantages).to(self.device)
            returns_tensor = torch.FloatTensor(returns).to(self.device)
            
            # PPO training epochs (multiple passes over collected data)
            for epoch in range(self.config.num_epochs):
                # Shuffle indices for mini-batch training
                indices = np.random.permutation(len(states_tensor))
                
                # Process data in mini-batches
                for start in range(0, len(indices), self.config.mini_batch_size):
                    end = start + self.config.mini_batch_size
                    batch_indices = indices[start:end]
                    
                    # Get batch data using shuffled indices
                    batch_states = states_tensor[batch_indices]
                    batch_actions = actions_tensor[batch_indices]
                    batch_old_log_probs = old_log_probs_tensor[batch_indices]
                    batch_advantages = advantages_tensor[batch_indices]
                    batch_returns = returns_tensor[batch_indices]
                    
                    # Evaluate actions under current policy
                    batch_log_probs, batch_entropy, batch_values = \
                        self.agent_policy.evaluate_actions(batch_states, batch_actions)
                    
                    # Compute policy loss using PPO clipping objective
                    ratio = torch.exp(batch_log_probs - batch_old_log_probs)  # Importance ratio
                    surr1 = ratio * batch_advantages  # Unclipped objective
                    surr2 = torch.clamp(ratio, 1 - self.config.clip_epsilon, 
                                       1 + self.config.clip_epsilon) * batch_advantages  # Clipped objective
                    policy_loss = -torch.min(surr1, surr2).mean()  # Minimize negative advantage
                    
                    # Compute value loss (mean squared error)
                    value_loss = F.mse_loss(batch_values.squeeze(-1), batch_returns)
                    
                    # Compute entropy loss (maximize entropy for exploration)
                    entropy_loss = -batch_entropy.mean()
                    
                    # Compute total loss with coefficients
                    total_loss = (policy_loss 
                                 + self.config.value_coef * value_loss
                                 + self.config.entropy_coef * entropy_loss)
                    
                    # Optimization step
                    self.optimizer.zero_grad()  # Clear previous gradients
                    total_loss.backward()  # Backpropagate gradients
                    
                    # Gradient clipping for stability
                    torch.nn.utils.clip_grad_norm_(
                        self.agent_policy.parameters(),
                        max_norm=0.5  # Maximum gradient norm
                    )
                    
                    self.optimizer.step()  # Update model parameters
            
            # Update metrics after episode
            episode_reward = np.sum(experience['rewards'])  # Total reward for episode
            episode_length = len(experience['rewards'])  # Length of episode
            
            # Store metrics for analysis
            self.metrics['episode_rewards'].append(episode_reward)
            self.metrics['episode_lengths'].append(episode_length)
            self.metrics['exploration_rate'].append(self.epsilon)
            self.metrics['value_loss'].append(value_loss.item() if 'value_loss' in locals() else 0)
            self.metrics['policy_loss'].append(policy_loss.item() if 'policy_loss' in locals() else 0)
            self.metrics['entropy'].append(entropy_loss.item() if 'entropy_loss' in locals() else 0)
            
            # Log episode summary
            episode_time = time.time() - episode_start_time
            self._log_episode_summary(episode, episode_reward, episode_length, 
                                     episode_time)
            
            # Save checkpoint periodically
            if self.episode % self.config.save_frequency == 0:
                self.save_checkpoint(f"episode_{self.episode}")
            
            # Evaluate agent periodically
            if self.episode % self.config.eval_frequency == 0:
                eval_metrics = self.evaluate(env, self.config.eval_episodes)
                self._log_evaluation_metrics(eval_metrics)
            
            # Curriculum learning update (if enabled)
            if self.curriculum:
                # Determine if episode was successful (simplified heuristic)
                recent_rewards = self.metrics['episode_rewards'][-10:] if len(self.metrics['episode_rewards']) >= 10 else self.metrics['episode_rewards']
                success = episode_reward > np.mean(recent_rewards)
                self.curriculum.update_performance(success)
                
                # Check for level changes
                if self.curriculum.check_level_up():
                    self.logger.info(f"Agent leveled up to level {self.curriculum.current_level}")
                    # Update environment difficulty if env has set_difficulty method
                    if hasattr(env, 'set_difficulty'):
                        env.set_difficulty(self.curriculum.get_current_config())
                
                if self.curriculum.check_level_down():
                    self.logger.info(f"Agent leveled down to level {self.curriculum.current_level}")
                    # Update environment difficulty if env has set_difficulty method
                    if hasattr(env, 'set_difficulty'):
                        env.set_difficulty(self.curriculum.get_current_config())
    
    def train_imitation_learning(self, expert_demonstrations: List[Dict]):
        """
        Train agent using imitation learning from expert demonstrations
        
        Args:
            expert_demonstrations: List of expert demonstration trajectories
        """
        self.logger.info(f"Starting IL training with {len(expert_demonstrations)} demonstrations")
        
        # Convert demonstrations to training data
        states = []
        actions = []
        
        for demo in expert_demonstrations:
            states.extend(demo['states'])  # Extract states
            actions.extend(demo['actions'])  # Extract actions
        
        # Convert to PyTorch tensors
        states_tensor = torch.FloatTensor(states).to(self.device)
        actions_tensor = torch.LongTensor(actions).to(self.device)
        
        # Create dataset and dataloader for batch processing
        dataset = torch.utils.data.TensorDataset(states_tensor, actions_tensor)
        dataloader = DataLoader(dataset, batch_size=self.config.batch_size, shuffle=True)
        
        # Training loop for imitation learning
        num_epochs = self.config.num_epochs
        
        for epoch in range(num_epochs):
            epoch_loss = 0  # Accumulate loss for epoch
            num_batches = 0  # Count batches
            
            for batch_states, batch_actions in dataloader:
                # Forward pass: get action logits from policy
                action_logits, _ = self.agent_policy(batch_states)
                
                # Compute loss (cross-entropy between policy and expert actions)
                loss = F.cross_entropy(action_logits, batch_actions)
                
                # Optimization step
                self.optimizer.zero_grad()  # Clear gradients
                loss.backward()  # Compute gradients
                self.optimizer.step()  # Update parameters
                
                epoch_loss += loss.item()  # Accumulate loss
                num_batches += 1  # Increment batch counter
            
            # Log epoch summary
            avg_loss = epoch_loss / num_batches if num_batches > 0 else 0
            self.logger.info(f"Epoch {epoch + 1}/{num_epochs} | Loss: {avg_loss:.4f}")
            
            # Save checkpoint periodically
            if (epoch + 1) % 10 == 0:
                self.save_checkpoint(f"il_epoch_{epoch + 1}")
    
    def train_meta_learning(self, tasks: List[Callable], num_iterations: int):
        """
        Train agent using meta-learning (MAML)
        
        Args:
            tasks: List of task functions
            num_iterations: Number of meta-learning iterations
        """
        self.logger.info(f"Starting meta-learning with {len(tasks)} tasks")
        
        # Store initial parameters for reference
        initial_params = [p.clone().detach() for p in self.agent_policy.parameters()]
        
        # Meta-learning iterations
        for iteration in range(num_iterations):
            iteration_loss = 0  # Accumulate loss for iteration
            
            # Sample meta-batch of tasks
            task_batch = random.sample(tasks, min(self.config.meta_batch_size, len(tasks)))
            
            for task in task_batch:
                # Clone model for task-specific adaptation
                task_model = self._clone_model(self.agent_policy)
                task_optimizer = optim.SGD(task_model.parameters(), 
                                          lr=self.config.inner_lr)  # Inner loop optimizer
                
                # Fast adaptation on task (inner loop)
                for adaptation_step in range(self.config.adaptation_steps):
                    # Sample data from task
                    task_data = task.sample_batch()  # Task should implement sample_batch method
                    states = torch.FloatTensor(task_data['states']).to(self.device)
                    actions = torch.LongTensor(task_data['actions']).to(self.device)
                    
                    # Compute loss on task data
                    action_logits, _ = task_model(states)
                    loss = F.cross_entropy(action_logits, actions)
                    
                    # Adaptation step (inner loop update)
                    task_optimizer.zero_grad()
                    loss.backward()
                    task_optimizer.step()
                
                # Compute loss on adapted model (outer loop loss)
                eval_data = task.sample_batch()  # New batch for evaluation
                eval_states = torch.FloatTensor(eval_data['states']).to(self.device)
                eval_actions = torch.LongTensor(eval_data['actions']).to(self.device)
                
                eval_logits, _ = task_model(eval_states)
                eval_loss = F.cross_entropy(eval_logits, eval_actions)
                
                iteration_loss += eval_loss.item()  # Accumulate meta-loss
                
                # Compute gradients for meta-update
                self.optimizer.zero_grad()  # Clear meta-optimizer gradients
                eval_loss.backward()  # Backpropagate through adaptation steps
            
            # Meta-update (outer loop update)
            self.optimizer.step()
            
            # Log iteration summary
            avg_loss = iteration_loss / len(task_batch) if task_batch else 0
            self.logger.info(f"Iteration {iteration + 1}/{num_iterations} | "
                           f"Meta-loss: {avg_loss:.4f}")
    
    def _clone_model(self, model: nn.Module) -> nn.Module:
        """Clone model for meta-learning"""
        # Create new instance of same model class
        clone = type(model)(self.config.state_dim, self.config.action_dim).to(self.device)
        # Copy weights from original model
        clone.load_state_dict(model.state_dict())
        return clone
    
    def train_self_play(self, env, num_episodes: int):
        """
        Train agent using self-play
        
        Args:
            env: Training environment with opponent support
            num_episodes: Number of episodes to train
        """
        self.logger.info(f"Starting self-play training for {num_episodes} episodes")
        
        # Initialize opponent pool with current agent
        self.opponent_pool.append(self._clone_model(self.agent_policy))
        
        # Self-play training loop
        for episode in range(num_episodes):
            self.episode = episode + 1
            
            # Select opponent from pool (if pool not empty)
            if len(self.opponent_pool) > 0:
                opponent = random.choice(self.opponent_pool)
                # Set opponent in environment (env must implement set_opponent)
                if hasattr(env, 'set_opponent'):
                    env.set_opponent(opponent)
            
            # Collect experience by playing against opponent
            experience = self.collect_experience(env, self.config.steps_per_epoch)
            
            # Update agent using standard RL update
            self._update_from_experience(experience)
            
            # Update opponent pool periodically
            if self.episode % self.config.self_play_update_freq == 0:
                self._update_opponent_pool()
            
            # Log episode summary
            episode_reward = np.sum(experience['rewards'])
            self.logger.info(f"Episode {self.episode} | Reward: {episode_reward:.2f}")
    
    def _update_opponent_pool(self):
        """Update opponent pool with current agent"""
        # Clone current agent for opponent pool
        opponent = self._clone_model(self.agent_policy)
        
        # Add cloned agent to opponent pool
        self.opponent_pool.append(opponent)
        
        # Limit pool size by removing oldest opponent
        if len(self.opponent_pool) > self.opponent_pool_size:
            self.opponent_pool.pop(0)  # Remove first (oldest) opponent
    
    def _update_from_experience(self, experience: Dict[str, Any]):
        """Update agent from collected experience"""
        # Convert experience to tensors
        states = torch.FloatTensor(experience['states']).to(self.device)
        actions = torch.LongTensor(experience['actions']).to(self.device)
        rewards = torch.FloatTensor(experience['rewards']).to(self.device)
        
        # Compute losses
        action_logits, values = self.agent_policy(states)  # Forward pass
        action_loss = F.cross_entropy(action_logits, actions)  # Action prediction loss
        value_loss = F.mse_loss(values.squeeze(-1), rewards)  # Value estimation loss
        
        # Total loss with balancing coefficient
        total_loss = action_loss + 0.5 * value_loss
        
        # Optimization step
        self.optimizer.zero_grad()  # Clear gradients
        total_loss.backward()  # Compute gradients
        self.optimizer.step()  # Update parameters
    
    def evaluate(self, env, num_episodes: int) -> Dict[str, float]:
        """
        Evaluate agent performance
        
        Args:
            env: Evaluation environment
            num_episodes: Number of episodes for evaluation
            
        Returns:
            Dictionary with evaluation metrics
        """
        self.agent_policy.eval()  # Set model to evaluation mode
        
        episode_rewards = []  # Store rewards per episode
        episode_lengths = []  # Store lengths per episode
        
        with torch.no_grad():  # No gradient computation during evaluation
            for episode in range(num_episodes):
                state = env.reset()  # Reset environment
                done = False
                episode_reward = 0
                episode_length = 0
                
                # Run episode until termination
                while not done:
                    # Convert state to tensor
                    state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)
                    
                    # Get action from policy (deterministic for evaluation)
                    action, _, _, _ = self.agent_policy.get_action(
                        state_tensor, deterministic=True  # No exploration during evaluation
                    )
                    
                    # Take action in environment
                    next_state, reward, done, info = env.step(action.item())
                    
                    # Accumulate episode statistics
                    episode_reward += reward
                    episode_length += 1
                    state = next_state  # Update state
                
                # Store episode results
                episode_rewards.append(episode_reward)
                episode_lengths.append(episode_length)
        
        self.agent_policy.train()  # Set model back to training mode
        
        # Compute evaluation metrics
        metrics = {
            'mean_reward': np.mean(episode_rewards) if episode_rewards else 0,
            'std_reward': np.std(episode_rewards) if episode_rewards else 0,
            'min_reward': np.min(episode_rewards) if episode_rewards else 0,
            'max_reward': np.max(episode_rewards) if episode_rewards else 0,
            'mean_length': np.mean(episode_lengths) if episode_lengths else 0,
            'success_rate': np.mean([r > 0 for r in episode_rewards]) if episode_rewards else 0  # Positive reward = success
        }
        
        return metrics
    
    def _log_episode_summary(self, episode: int, reward: float, 
                           length: int, time_taken: float):
        """
        Log episode training summary
        
        Args:
            episode: Episode number
            reward: Total episode reward
            length: Episode length
            time_taken: Time taken for episode
        """
        # Format log message with episode information
        log_msg = (f"Episode {episode:4d} | "
                   f"Reward: {reward:8.2f} | "
                   f"Length: {length:4d} | "
                   f"Time: {time_taken:5.2f}s | "
                   f"Exploration: {self.epsilon:.3f}")
        
        self.logger.info(log_msg)
    
    def _log_evaluation_metrics(self, metrics: Dict[str, float]):
        """
        Log evaluation metrics
        
        Args:
            metrics: Evaluation metrics
        """
        # Format evaluation results log message
        log_msg = (f"Evaluation | "
                   f"Mean Reward: {metrics['mean_reward']:.2f} | "
                   f"Success Rate: {metrics['success_rate']:.2%} | "
                   f"Episode Length: {metrics['mean_length']:.1f}")
        
        self.logger.info(log_msg)
    
    def save_checkpoint(self, name: str):
        """
        Save training checkpoint
        
        Args:
            name: Checkpoint name
        """
        # Create checkpoint directory if it doesn't exist
        checkpoint_dir = Path(self.config.checkpoint_dir)
        checkpoint_dir.mkdir(parents=True, exist_ok=True)
        
        # Prepare checkpoint data
        checkpoint = {
            'episode': self.episode,
            'total_steps': self.total_steps,
            'agent_state_dict': self.agent_policy.state_dict(),  # Model parameters
            'optimizer_state_dict': self.optimizer.state_dict(),  # Optimizer state
            'epsilon': self.epsilon,  # Current exploration rate
            'best_reward': self.best_reward,  # Best reward achieved
            'metrics': self.metrics,  # Training metrics
            'config': self.config.__dict__,  # Training configuration
        }
        
        # Add curriculum state if curriculum learning is enabled
        if self.curriculum:
            checkpoint['curriculum_state'] = {
                'current_level': self.curriculum.current_level,
                'level_performance': dict(self.curriculum.level_performance)  # Convert defaultdict to dict
            }
        
        # Save replay buffer if it has sufficient data
        if self.replay_buffer.size > 1000:
            replay_buffer_path = checkpoint_dir / f"{name}_replay_buffer.pkl"
            self.replay_buffer.save(str(replay_buffer_path))
        
        # Save checkpoint file
        checkpoint_path = checkpoint_dir / f"{name}.pt"
        torch.save(checkpoint, checkpoint_path)  # Save using PyTorch
        
        self.logger.info(f"Checkpoint saved: {checkpoint_path}")
    
    def load_checkpoint(self, checkpoint_path: str):
        """
        Load training checkpoint
        
        Args:
            checkpoint_path: Path to checkpoint file
        """
        # Load checkpoint file
        checkpoint = torch.load(checkpoint_path, map_location=self.device)
        
        # Load model and optimizer state
        self.agent_policy.load_state_dict(checkpoint['agent_state_dict'])
        self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
        
        # Load training state
        self.episode = checkpoint['episode']
        self.total_steps = checkpoint['total_steps']
        self.epsilon = checkpoint['epsilon']
        self.best_reward = checkpoint['best_reward']
        self.metrics = checkpoint['metrics']
        
        # Load curriculum state if available and curriculum is enabled
        if 'curriculum_state' in checkpoint and self.curriculum:
            self.curriculum.current_level = checkpoint['curriculum_state']['current_level']
            # Convert dict back to defaultdict
            self.curriculum.level_performance = defaultdict(
                list, checkpoint['curriculum_state']['level_performance']
            )
        
        self.logger.info(f"Checkpoint loaded from {checkpoint_path}")
        self.logger.info(f"Resuming from episode {self.episode}")
    
    def export_agent(self, export_path: str, format: str = "onnx"):
        """
        Export trained agent for deployment
        
        Args:
            export_path: Path to save exported agent
            format: Export format
        """
        self.agent_policy.eval()  # Set to evaluation mode for export
        
        if format == "onnx":
            # Create dummy input for tracing
            dummy_input = torch.randn(1, self.config.state_dim, device=self.device)
            
            # Export to ONNX format
            torch.onnx.export(
                self.agent_policy,  # Model to export
                dummy_input,  # Example input
                export_path,  # Output file path
                export_params=True,  # Include model parameters
                opset_version=14,  # ONNX opset version
                do_constant_folding=True,  # Optimize constants
                input_names=['state'],  # Input tensor name
                output_names=['action_logits', 'value'],  # Output tensor names
                dynamic_axes={  # Support dynamic batch size
                    'state': {0: 'batch_size'},
                    'action_logits': {0: 'batch_size'},
                    'value': {0: 'batch_size'}
                }
            )
        
        elif format == "torchscript":
            # Create dummy input for tracing
            dummy_input = torch.randn(1, self.config.state_dim, device=self.device)
            # Trace model to TorchScript
            traced_agent = torch.jit.trace(self.agent_policy, dummy_input)
            # Save traced model
            traced_agent.save(export_path)
        
        else:
            raise ValueError(f"Unknown export format: {format}")
        
        self.logger.info(f"Agent exported to {export_path} in {format} format")