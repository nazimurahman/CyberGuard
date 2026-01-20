# src/inference/__init__.py
"""
Inference Module for CyberGuard Web Security AI System

This module handles:
1. Main inference engine orchestration
2. Threat-specific inference logic
3. Response parsing and formatting
4. Integration with agent system and mHC coordination

Exports:
- InferenceEngine: Main inference orchestrator
- ThreatInference: Specialized threat inference
- ResponseParser: Response formatting utilities
- InferenceResult: Data class for inference results
"""

from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field
import numpy as np
import torch
from datetime import datetime

# Import local modules using relative imports
from .inference_engine import InferenceEngine
from .threat_inference import ThreatInference
from .response_parser import ResponseParser, SecurityRecommendation

# Define data classes for structured inference results
@dataclass
class InferenceResult:
    """
    Structured result container for inference outputs.
    Provides type safety and clear data organization for all inference results.
    
    Attributes:
        threat_level (float): Overall threat score from 0.0 to 1.0
        confidence (float): Model confidence in the prediction (0.0 to 1.0)
        threat_type (str): Primary threat category (XSS, SQLi, CSRF, etc.)
        severity (str): Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        evidence (List[Dict]): Supporting evidence for the decision
        recommendations (List[SecurityRecommendation]): Security recommendations
        metadata (Dict[str, Any]): Additional inference metadata
        timestamp (datetime): When inference was performed
        model_version (str): Version of model used
    """
    threat_level: float = 0.0
    confidence: float = 0.0
    threat_type: str = "UNKNOWN"
    severity: str = "INFO"
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[SecurityRecommendation] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    model_version: str = "cyberguard-v1.0"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert InferenceResult to dictionary for JSON serialization"""
        return {
            'threat_level': self.threat_level,
            'confidence': self.confidence,
            'threat_type': self.threat_type,
            'severity': self.severity,
            'evidence': self.evidence,
            'recommendations': [rec.to_dict() for rec in self.recommendations],
            'metadata': self.metadata,
            'timestamp': self.timestamp.isoformat(),
            'model_version': self.model_version
        }
    
    def validate(self) -> bool:
        """Validate the inference result for consistency and completeness"""
        # Check threat level bounds
        if not 0.0 <= self.threat_level <= 1.0:
            raise ValueError(f"Threat level {self.threat_level} out of bounds [0.0, 1.0]")
        
        # Check confidence bounds
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Confidence {self.confidence} out of bounds [0.0, 1.0]")
        
        # Validate severity is one of allowed values
        allowed_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        if self.severity not in allowed_severities:
            raise ValueError(f"Invalid severity: {self.severity}. Must be one of {allowed_severities}")
        
        # Validate evidence structure
        for ev in self.evidence:
            if not isinstance(ev, dict):
                raise ValueError("Evidence items must be dictionaries")
            if 'type' not in ev or 'description' not in ev:
                raise ValueError("Evidence must have 'type' and 'description' fields")
        
        return True

@dataclass
class InferenceRequest:
    """
    Structured request for inference operations.
    Encapsulates all data needed for security inference.
    
    Attributes:
        request_data (Dict[str, Any]): Raw request data (URL, headers, body, etc.)
        context (Dict[str, Any]): Additional context (user info, session data, etc.)
        inference_mode (str): Mode of inference (realtime, batch, deep_scan)
        priority (int): Request priority (1=highest, 5=lowest)
        timeout (float): Maximum inference time in seconds
        require_explanation (bool): Whether to generate detailed explanations
    """
    request_data: Dict[str, Any]
    context: Dict[str, Any] = field(default_factory=dict)
    inference_mode: str = "realtime"
    priority: int = 3
    timeout: float = 5.0
    require_explanation: bool = True

# Define module-level constants
DEFAULT_INFERENCE_TIMEOUT = 5.0  # seconds
MAX_EVIDENCE_ITEMS = 10
THREAT_THRESHOLDS = {
    'CRITICAL': 0.9,
    'HIGH': 0.7,
    'MEDIUM': 0.5,
    'LOW': 0.3,
    'INFO': 0.1
}

# Version tracking
__version__ = "1.0.0"
__author__ = "CyberGuard Security Team"
__description__ = "Advanced Inference Module for Web Security AI System"

# Export public API
__all__ = [
    'InferenceEngine',
    'ThreatInference',
    'ResponseParser',
    'InferenceResult',
    'InferenceRequest',
    'SecurityRecommendation',
    'run_inference',
    'validate_inference_input'
]

# Public utility functions
def run_inference(request: InferenceRequest, engine: Optional[InferenceEngine] = None) -> InferenceResult:
    """
    Convenience function to run inference with default or provided engine.
    
    Args:
        request: Inference request with data and parameters
        engine: Optional inference engine (creates default if None)
    
    Returns:
        InferenceResult with threat analysis
    
    Example:
        >>> request = InferenceRequest({"url": "https://example.com"})
        >>> result = run_inference(request)
        >>> print(f"Threat level: {result.threat_level}")
    """
    if engine is None:
        # Create default engine with reasonable defaults
        from .inference_engine import InferenceEngine
        engine = InferenceEngine()
    
    return engine.infer(request)

def validate_inference_input(data: Dict[str, Any]) -> bool:
    """
    Validate inference input data for required fields and structure.
    
    Args:
        data: Input data dictionary to validate
    
    Returns:
        bool: True if valid, False otherwise
    
    Raises:
        ValueError: If validation fails with specific error
    """
    # Check if data is a dictionary
    if not isinstance(data, dict):
        raise ValueError("Input data must be a dictionary")
    
    # Check for required fields based on inference type
    if 'url' in data:
        # URL-based inference
        import re
        url_pattern = re.compile(
            r'^(https?://)?'  # http:// or https://
            r'([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}'  # domain
            r'(:\d+)?'  # optional port
            r'(/.*)?$'  # optional path
        )
        if not url_pattern.match(data['url']):
            raise ValueError(f"Invalid URL format: {data['url']}")
    
    elif 'headers' in data or 'body' in data:
        # HTTP request inference
        if 'method' not in data:
            data['method'] = 'GET'  # Default method
        
        valid_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
        if data['method'] not in valid_methods:
            raise ValueError(f"Invalid HTTP method: {data['method']}")
    
    else:
        raise ValueError("Input must contain 'url' or 'headers/body' for inference")
    
    return True

# Module initialization hook
def _initialize_module() -> None:
    """
    Initialize module when imported.
    Sets up logging, verifies dependencies, and prepares global state.
    """
    import logging
    import sys
    
    # Configure module logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    
    # Add console handler if no handlers exist
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        logger.addHandler(handler)
    
    # Log module initialization
    logger.info(f"Initializing CyberGuard Inference Module v{__version__}")
    
    # Check for required dependencies
    try:
        import torch
        logger.info(f"PyTorch version: {torch.__version__}")
    except ImportError:
        logger.error("PyTorch not found. Some features may be unavailable.")
    
    try:
        import numpy as np
        logger.info(f"NumPy version: {np.__version__}")
    except ImportError:
        logger.error("NumPy not found. Required for tensor operations.")
    
    # Initialize thread pool for async operations
    import concurrent.futures
    global _THREAD_POOL
    _THREAD_POOL = concurrent.futures.ThreadPoolExecutor(
        max_workers=4,
        thread_name_prefix="cyberguard_inference"
    )
    
    logger.info("Inference module initialized successfully")

# Global thread pool for async operations
_THREAD_POOL = None

# Run initialization when module is imported
_initialize_module()