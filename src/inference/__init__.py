"""
Inference Module for CyberGuard.

This module handles:
1. Inference engine for security analysis
2. Threat inference processing
3. Response parsing and formatting
4. Result data models
"""

# Importing all necessary components from the inference package modules
# These imports make the package's public API accessible when importing the package

# Import the InferenceEngine class from the inference_engine module
from .inference_engine import InferenceEngine

# Import the ThreatInference class from the threat_inference module  
from .threat_inference import ThreatInference

# Import the ResponseParser class and parse_result function from the response_parser module
from .response_parser import ResponseParser, parse_result

# Import all data model classes and functions from the inference_result module
from .inference_result import (
    InferenceResult,            # Main result container class
    SecurityEvidence,          # Evidence data structure
    SecurityRecommendation,    # Recommendation data structure  
    AgentContribution,         # Agent contribution tracking
    ThreatSeverity,            # Enum/class for threat severity levels
    ThreatType,                # Enum/class for threat type categorization
    create_inference_result    # Factory function for creating InferenceResult instances
)

# Define the public API of the inference package
# This controls what gets exported when using "from inference import *"
# All listed names will be available for import from the package level
__all__ = [
    'InferenceEngine',          # Expose the main inference engine class
    'ThreatInference',          # Expose threat inference processing class
    'ResponseParser',           # Expose response parsing class
    'parse_result',             # Expose the standalone parse result function
    'InferenceResult',          # Expose the main result data class
    'SecurityEvidence',         # Expose evidence data structure
    'SecurityRecommendation',   # Expose recommendation data structure
    'AgentContribution',        # Expose agent contribution tracker
    'ThreatSeverity',           # Expose threat severity enum/class
    'ThreatType',               # Expose threat type enum/class
    'create_inference_result'   # Expose the factory function
]

# Note: There are no syntax errors in the original code. The structure is correct:
# 1. Module docstring at the top
# 2. Relative imports (using .) from sibling modules
# 3. Proper use of parentheses for multi-line import
# 4. Properly defined __all__ list for explicit exports
# 5. All imports match the exports in __all__

# This file serves as the public interface to the inference package.
# When users import from this package (e.g., `from src.inference import InferenceEngine`),
# they access the components defined in __all__ through these imports.