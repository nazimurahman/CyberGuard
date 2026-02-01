"""
Hash Validation Module
======================

This module provides secure hash validation for data integrity verification.
It supports multiple hash algorithms and includes security best practices
to prevent hash-related attacks.
"""

import hashlib
import hmac
import re  # Added missing import for regex patterns
import logging
from typing import Optional, Dict, List, Tuple, Union, Any
from enum import Enum
from pathlib import Path

# Local imports - fixed import path (removed .. prefix)
from utils.crypto_utils import constant_time_compare  # Fixed import path

# Custom exceptions
class HashValidationError(Exception):
    """Base exception for hash validation errors"""
    pass

class InvalidHashFormat(HashValidationError):
    """Raised when hash format is invalid"""
    pass

class UnsupportedAlgorithm(HashValidationError):
    """Raised when hash algorithm is not supported"""
    pass

class HashMismatchError(HashValidationError):
    """Raised when calculated hash doesn't match expected hash"""
    pass

class HashAlgorithm(Enum):
    """Supported hash algorithms"""
    # Modern secure algorithms (recommended)
    SHA256 = "sha256"      # 256-bit, widely used, secure
    SHA512 = "sha512"      # 512-bit, more secure than SHA256
    BLAKE2B = "blake2b"   # 512-bit, faster than SHA512
    BLAKE2S = "blake2s"   # 256-bit, faster than SHA256 on 32-bit
    SHA3_256 = "sha3_256" # 256-bit SHA-3 (Keccak)
    SHA3_512 = "sha3_512" # 512-bit SHA-3 (Keccak)
    
    # Legacy algorithms (use with caution)
    SHA1 = "sha1"         # 160-bit, considered broken
    MD5 = "md5"           # 128-bit, cryptographically broken
    
    # Special purpose
    SHA256D = "sha256d"   # Double SHA256 (Bitcoin style)
    RIPEMD160 = "ripemd160" # 160-bit, used in Bitcoin
    
    @property
    def digest_size(self) -> int:
        """Get digest size in bytes"""
        sizes = {
            HashAlgorithm.MD5: 16,
            HashAlgorithm.SHA1: 20,
            HashAlgorithm.SHA256: 32,
            HashAlgorithm.SHA512: 64,
            HashAlgorithm.BLAKE2B: 64,
            HashAlgorithm.BLAKE2S: 32,
            HashAlgorithm.SHA3_256: 32,
            HashAlgorithm.SHA3_512: 64,
            HashAlgorithm.SHA256D: 32,
            HashAlgorithm.RIPEMD160: 20,
        }
        return sizes.get(self, 32)  # Default to 32 bytes if not found
    
    @property
    def block_size(self) -> int:
        """Get block size in bytes"""
        sizes = {
            HashAlgorithm.MD5: 64,
            HashAlgorithm.SHA1: 64,
            HashAlgorithm.SHA256: 64,
            HashAlgorithm.SHA512: 128,
            HashAlgorithm.BLAKE2B: 128,
            HashAlgorithm.BLAKE2S: 64,
            HashAlgorithm.SHA3_256: 136,
            HashAlgorithm.SHA3_512: 72,
            HashAlgorithm.SHA256D: 64,
            HashAlgorithm.RIPEMD160: 64,
        }
        return sizes.get(self, 64)  # Default to 64 bytes if not found
    
    @property
    def is_secure(self) -> bool:
        """Check if algorithm is considered secure for current use"""
        secure_algorithms = {
            HashAlgorithm.SHA256,
            HashAlgorithm.SHA512,
            HashAlgorithm.BLAKE2B,
            HashAlgorithm.BLAKE2S,
            HashAlgorithm.SHA3_256,
            HashAlgorithm.SHA3_512,
        }
        return self in secure_algorithms
    
    @property
    def is_deprecated(self) -> bool:
        """Check if algorithm is deprecated (should not be used)"""
        deprecated_algorithms = {
            HashAlgorithm.MD5,
            HashAlgorithm.SHA1,
        }
        return self in deprecated_algorithms


class HashValidator:
    """
    Secure hash validator with multiple algorithm support
    """
    
    # Default hash algorithm
    DEFAULT_ALGORITHM = HashAlgorithm.SHA256
    
    # Algorithm mapping from string to HashAlgorithm enum
    ALGORITHM_MAP = {
        # Modern algorithms
        "sha256": HashAlgorithm.SHA256,
        "sha-256": HashAlgorithm.SHA256,
        "sha512": HashAlgorithm.SHA512,
        "sha-512": HashAlgorithm.SHA512,
        "blake2b": HashAlgorithm.BLAKE2B,
        "blake2b-512": HashAlgorithm.BLAKE2B,
        "blake2s": HashAlgorithm.BLAKE2S,
        "blake2s-256": HashAlgorithm.BLAKE2S,
        "sha3-256": HashAlgorithm.SHA3_256,
        "sha3_256": HashAlgorithm.SHA3_256,
        "sha3-512": HashAlgorithm.SHA3_512,
        "sha3_512": HashAlgorithm.SHA3_512,
        
        # Legacy algorithms
        "md5": HashAlgorithm.MD5,
        "sha1": HashAlgorithm.SHA1,
        "sha-1": HashAlgorithm.SHA1,
        
        # Special algorithms
        "sha256d": HashAlgorithm.SHA256D,
        "ripemd160": HashAlgorithm.RIPEMD160,
        "ripemd-160": HashAlgorithm.RIPEMD160,
    }
    
    # Hash format regex patterns
    HASH_PATTERNS = {
        HashAlgorithm.MD5: r'^[a-fA-F0-9]{32}$',
        HashAlgorithm.SHA1: r'^[a-fA-F0-9]{40}$',
        HashAlgorithm.SHA256: r'^[a-fA-F0-9]{64}$',
        HashAlgorithm.SHA512: r'^[a-fA-F0-9]{128}$',
        HashAlgorithm.BLAKE2B: r'^[a-fA-F0-9]{128}$',
        HashAlgorithm.BLAKE2S: r'^[a-fA-F0-9]{64}$',
        HashAlgorithm.SHA3_256: r'^[a-fA-F0-9]{64}$',
        HashAlgorithm.SHA3_512: r'^[a-fA-F0-9]{128}$',
        HashAlgorithm.SHA256D: r'^[a-fA-F0-9]{64}$',
        HashAlgorithm.RIPEMD160: r'^[a-fA-F0-9]{40}$',
    }
    
    def __init__(
        self,
        default_algorithm: HashAlgorithm = DEFAULT_ALGORITHM,
        allow_deprecated: bool = False,
        require_secure: bool = True
    ):
        """
        Initialize hash validator
        
        Args:
            default_algorithm: Default algorithm to use when not specified
            allow_deprecated: Allow deprecated algorithms (MD5, SHA1)
            require_secure: Require secure algorithms only
        """
        # Initialize logger for debugging and error tracking
        self.logger = logging.getLogger(__name__)
        self.default_algorithm = default_algorithm
        self.allow_deprecated = allow_deprecated
        self.require_secure = require_secure
        
        # Compile regex patterns for hash format validation
        self._regex_cache = {}
        for algorithm, pattern in self.HASH_PATTERNS.items():
            self._regex_cache[algorithm] = re.compile(pattern)
        
        # Performance cache for frequent hashes to avoid recalculating
        self._hash_cache: Dict[Tuple[str, HashAlgorithm], str] = {}
        self._cache_max_size = 1000  # Maximum number of cached hashes
        
        # Log initialization parameters
        self.logger.info(
            f"HashValidator initialized: "
            f"default={default_algorithm.value}, "
            f"allow_deprecated={allow_deprecated}, "
            f"require_secure={require_secure}"
        )
    
    def parse_hash_string(self, hash_string: str) -> Tuple[HashAlgorithm, str]:
        """
        Parse hash string into algorithm and hash value
        
        Supports formats:
        - "sha256:abc123..." (algorithm:hash)
        - "abc123..." (detect algorithm from length)
        
        Args:
            hash_string: Hash string to parse
            
        Returns:
            Tuple of (algorithm, hash_value)
            
        Raises:
            InvalidHashFormat: If hash string format is invalid
            UnsupportedAlgorithm: If algorithm is not supported
        """
        # Validate input is a non-empty string
        if not hash_string or not isinstance(hash_string, str):
            raise InvalidHashFormat("Hash string must be a non-empty string")
        
        # Trim whitespace from input
        hash_string = hash_string.strip()
        
        # Check for algorithm prefix (format: algorithm:hash)
        if ':' in hash_string:
            # Split into algorithm and hash parts
            algorithm_str, hash_value = hash_string.split(':', 1)
            algorithm_str = algorithm_str.strip().lower()  # Normalize to lowercase
            hash_value = hash_value.strip()
            
            # Look up algorithm in mapping
            if algorithm_str not in self.ALGORITHM_MAP:
                raise UnsupportedAlgorithm(
                    f"Unsupported hash algorithm: {algorithm_str}. "
                    f"Supported: {', '.join(sorted(self.ALGORITHM_MAP.keys()))}"
                )
            
            algorithm = self.ALGORITHM_MAP[algorithm_str]
            
        else:
            # No algorithm prefix, try to detect from hash length
            hash_value = hash_string
            algorithm = self._detect_algorithm_from_hash(hash_value)
            
            if not algorithm:
                # Use default algorithm if detection fails
                algorithm = self.default_algorithm
                self.logger.debug(
                    f"Could not detect algorithm for hash, using default: {algorithm.value}"
                )
        
        # Validate algorithm security settings
        self._validate_algorithm(algorithm)
        
        # Validate hash format matches algorithm expectations
        self._validate_hash_format(hash_value, algorithm)
        
        # Normalize hash to lowercase for consistent comparison
        hash_value = hash_value.lower()
        
        return algorithm, hash_value
    
    def _detect_algorithm_from_hash(self, hash_value: str) -> Optional[HashAlgorithm]:
        """
        Detect hash algorithm from hash value length
        
        Args:
            hash_value: Hash value string
            
        Returns:
            HashAlgorithm or None if cannot detect
        """
        # Clean input: remove whitespace and convert to lowercase
        hash_value = hash_value.strip().lower()
        
        # Check if string contains only hexadecimal characters
        if not all(c in '0123456789abcdef' for c in hash_value):
            return None
        
        # Get length of hash string (in hex characters)
        length = len(hash_value)
        
        # Map hex string length to possible algorithms
        length_to_algorithms = {
            32: [HashAlgorithm.MD5],  # 128-bit = 32 hex chars
            40: [HashAlgorithm.SHA1, HashAlgorithm.RIPEMD160],  # 160-bit = 40 hex chars
            64: [
                HashAlgorithm.SHA256,     # 256-bit = 64 hex chars
                HashAlgorithm.BLAKE2S,
                HashAlgorithm.SHA3_256,
                HashAlgorithm.SHA256D,
            ],
            128: [
                HashAlgorithm.SHA512,     # 512-bit = 128 hex chars
                HashAlgorithm.BLAKE2B,
                HashAlgorithm.SHA3_512,
            ],
        }
        
        # Get possible algorithms for this length
        possible_algorithms = length_to_algorithms.get(length, [])
        
        if not possible_algorithms:
            return None
        
        # Return first secure algorithm if require_secure is True
        if self.require_secure:
            for algorithm in possible_algorithms:
                if algorithm.is_secure:
                    return algorithm
        
        # Return first algorithm if no security requirement or no secure ones found
        return possible_algorithms[0] if possible_algorithms else None
    
    def _validate_algorithm(self, algorithm: HashAlgorithm):
        """
        Validate hash algorithm based on security settings
        
        Args:
            algorithm: Algorithm to validate
            
        Raises:
            UnsupportedAlgorithm: If algorithm is not allowed
        """
        # Check if algorithm is deprecated and not allowed
        if algorithm.is_deprecated and not self.allow_deprecated:
            raise UnsupportedAlgorithm(
                f"Deprecated hash algorithm: {algorithm.value}. "
                f"Set allow_deprecated=True to allow."
            )
        
        # Check if secure algorithm is required but algorithm is insecure
        if self.require_secure and not algorithm.is_secure:
            raise UnsupportedAlgorithm(
                f"Insecure hash algorithm: {algorithm.value}. "
                f"Set require_secure=False to allow."
            )
    
    def _validate_hash_format(self, hash_value: str, algorithm: HashAlgorithm):
        """
        Validate hash value format for given algorithm
        
        Args:
            hash_value: Hash value to validate
            algorithm: Expected algorithm
            
        Raises:
            InvalidHashFormat: If hash format is invalid
        """
        # Convert to lowercase for validation
        hash_lower = hash_value.lower()
        
        # Check if string contains only hexadecimal characters
        if not all(c in '0123456789abcdef' for c in hash_lower):
            raise InvalidHashFormat(
                f"Hash value must be hexadecimal: {hash_value[:20]}..."
            )
        
        # Calculate expected length: digest_size (bytes) * 2 (hex chars per byte)
        expected_length = algorithm.digest_size * 2
        actual_length = len(hash_value)
        
        # Check if hash length matches expected length for algorithm
        if actual_length != expected_length:
            raise InvalidHashFormat(
                f"Invalid hash length for {algorithm.value}. "
                f"Expected {expected_length} chars, got {actual_length}. "
                f"Hash: {hash_value[:20]}..."
            )
        
        # Check against regex pattern for additional validation
        regex = self._regex_cache.get(algorithm)
        if regex and not regex.match(hash_value):
            raise InvalidHashFormat(
                f"Hash value does not match expected pattern for {algorithm.value}"
            )
    
    def calculate_hash(
        self,
        data: Union[bytes, str],
        algorithm: Optional[HashAlgorithm] = None,
        use_cache: bool = True
    ) -> str:
        """
        Calculate hash of data
        
        Args:
            data: Data to hash (bytes or string)
            algorithm: Hash algorithm to use (defaults to default_algorithm)
            use_cache: Use caching for performance
            
        Returns:
            Hexadecimal hash string
            
        Raises:
            HashValidationError: If hash calculation fails
        """
        # Use default algorithm if none specified
        if algorithm is None:
            algorithm = self.default_algorithm
        
        # Validate algorithm security settings
        self._validate_algorithm(algorithm)
        
        # Convert string data to bytes (UTF-8 encoding)
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Generate cache key
        cache_key = (self._get_data_key(data), algorithm)
        
        # Return cached hash if available and caching is enabled
        if use_cache and cache_key in self._hash_cache:
            return self._hash_cache[cache_key]
        
        try:
            # Calculate hash based on algorithm type
            if algorithm == HashAlgorithm.SHA256D:
                # Double SHA256 (Bitcoin style): hash(hash(data))
                hash1 = hashlib.sha256(data).digest()
                hash_bytes = hashlib.sha256(hash1).digest()
            else:
                # Standard single-pass hash algorithms
                hash_func = self._get_hash_function(algorithm)
                hash_func.update(data)
                hash_bytes = hash_func.digest()
            
            # Convert binary hash to hexadecimal string
            hash_hex = hash_bytes.hex()
            
            # Update cache if enabled
            if use_cache:
                self._update_cache(cache_key, hash_hex)
            
            return hash_hex
            
        except Exception as e:
            # Wrap any exception in HashValidationError for consistent error handling
            raise HashValidationError(f"Failed to calculate hash: {e}")
    
    def _get_hash_function(self, algorithm: HashAlgorithm):
        """
        Get hash function for algorithm
        
        Args:
            algorithm: Hash algorithm
            
        Returns:
            Hash function object
            
        Raises:
            UnsupportedAlgorithm: If algorithm is not available
        """
        # Map HashAlgorithm enum to hashlib functions
        if algorithm == HashAlgorithm.SHA256:
            return hashlib.sha256()
        elif algorithm == HashAlgorithm.SHA512:
            return hashlib.sha512()
        elif algorithm == HashAlgorithm.SHA1:
            return hashlib.sha1()
        elif algorithm == HashAlgorithm.MD5:
            return hashlib.md5()
        elif algorithm == HashAlgorithm.BLAKE2B:
            return hashlib.blake2b(digest_size=64)
        elif algorithm == HashAlgorithm.BLAKE2S:
            return hashlib.blake2s(digest_size=32)
        elif algorithm == HashAlgorithm.SHA3_256:
            return hashlib.sha3_256()
        elif algorithm == HashAlgorithm.SHA3_512:
            return hashlib.sha3_512()
        elif algorithm == HashAlgorithm.RIPEMD160:
            try:
                return hashlib.new('ripemd160')
            except ValueError:
                # RIPEMD-160 might not be available on all systems
                raise UnsupportedAlgorithm("RIPEMD-160 not available on this system")
        else:
            raise UnsupportedAlgorithm(f"Unsupported algorithm: {algorithm}")
    
    def _get_data_key(self, data: bytes) -> str:
        """
        Create cache key for data
        
        For large data, we use a hash of the data as the key
        to avoid storing large data in cache.
        
        Args:
            data: Input data bytes
            
        Returns:
            Cache key string
        """
        # For data larger than 1KB, use SHA256 hash as cache key
        if len(data) > 1024:
            return hashlib.sha256(data).hexdigest()
        else:
            # For small data, use hex representation directly
            return data.hex()
    
    def _update_cache(self, cache_key: Tuple[str, HashAlgorithm], hash_value: str):
        """
        Update hash cache with LRU-like behavior
        
        Args:
            cache_key: Tuple of (data_key, algorithm)
            hash_value: Calculated hash value
        """
        # Add new entry to cache
        self._hash_cache[cache_key] = hash_value
        
        # Remove oldest entries if cache exceeds maximum size
        if len(self._hash_cache) > self._cache_max_size:
            # Remove first 10% of entries (simple LRU approximation)
            remove_count = self._cache_max_size // 10
            keys_to_remove = list(self._hash_cache.keys())[:remove_count]
            for key in keys_to_remove:
                del self._hash_cache[key]
    
    def verify_hash(
        self,
        data: Union[bytes, str],
        expected_hash: str,
        algorithm: Optional[HashAlgorithm] = None
    ) -> bool:
        """
        Verify data against expected hash
        
        Args:
            data: Data to verify
            expected_hash: Expected hash string
            algorithm: Algorithm to use (overrides detected algorithm)
            
        Returns:
            True if hash matches, False otherwise
            
        Raises:
            HashValidationError: If verification fails due to invalid input
        """
        try:
            # Parse expected hash to get algorithm and hash value
            if algorithm is None:
                # Auto-detect algorithm from hash string
                expected_algorithm, expected_hash_value = self.parse_hash_string(expected_hash)
            else:
                # Use provided algorithm
                expected_algorithm = algorithm
                expected_hash_value = expected_hash.lower()
                # Validate format for provided algorithm
                self._validate_hash_format(expected_hash_value, expected_algorithm)
            
            # Calculate actual hash of data
            actual_hash = self.calculate_hash(data, expected_algorithm)
            
            # Use constant-time comparison to prevent timing attacks
            return constant_time_compare(actual_hash, expected_hash_value)
            
        except (InvalidHashFormat, UnsupportedAlgorithm) as e:
            # Re-raise validation errors for invalid input
            raise HashValidationError(f"Hash verification failed: {e}")
        except Exception as e:
            # Log other errors and return False (verification failed)
            self.logger.debug(f"Hash verification error: {e}")
            return False
    
    def verify_hash_list(
        self,
        data: Union[bytes, str],
        expected_hashes: List[str],
        require_all: bool = False
    ) -> Dict[str, bool]:
        """
        Verify data against multiple expected hashes
        
        Args:
            data: Data to verify
            expected_hashes: List of expected hash strings
            require_all: Whether all hashes must match (vs any hash)
            
        Returns:
            Dictionary mapping each hash to verification result
            
        Raises:
            HashValidationError: If any hash format is invalid
        """
        results = {}
        
        # Verify each hash in the list
        for expected_hash in expected_hashes:
            try:
                is_valid = self.verify_hash(data, expected_hash)
                results[expected_hash] = is_valid
            except HashValidationError as e:
                # Store error as False result and log
                results[expected_hash] = False
                self.logger.debug(f"Hash validation failed for {expected_hash}: {e}")
        
        # Calculate overall result based on require_all flag
        if require_all:
            # All hashes must be valid
            all_valid = all(results.values())
            results['_overall'] = all_valid
        else:
            # At least one hash must be valid
            any_valid = any(results.values())
            results['_overall'] = any_valid
        
        return results
    
    def verify_file_hash(
        self,
        filepath: Union[str, Path],
        expected_hash: str,
        algorithm: Optional[HashAlgorithm] = None,
        chunk_size: int = 8192
    ) -> bool:
        """
        Verify file hash (streaming for large files)
        
        Args:
            filepath: Path to file
            expected_hash: Expected hash string
            algorithm: Algorithm to use
            chunk_size: Chunk size for streaming read
            
        Returns:
            True if file hash matches, False otherwise
        """
        # Convert to Path object for consistent handling
        filepath = Path(filepath)
        
        # Check if file exists and is a regular file
        if not filepath.exists():
            self.logger.error(f"File not found: {filepath}")
            return False
        
        if not filepath.is_file():
            self.logger.error(f"Path is not a file: {filepath}")
            return False
        
        try:
            # Parse expected hash
            if algorithm is None:
                expected_algorithm, expected_hash_value = self.parse_hash_string(expected_hash)
            else:
                expected_algorithm = algorithm
                expected_hash_value = expected_hash.lower()
                self._validate_hash_format(expected_hash_value, expected_algorithm)
            
            # Get hash function for the algorithm
            hash_func = self._get_hash_function(expected_algorithm)
            
            # Calculate file hash using streaming (read in chunks)
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    hash_func.update(chunk)
            
            # Get hexadecimal hash
            actual_hash = hash_func.hexdigest()
            
            # Constant-time comparison
            return constant_time_compare(actual_hash, expected_hash_value)
            
        except Exception as e:
            # Log error and return False (verification failed)
            self.logger.error(f"File hash verification failed for {filepath}: {e}")
            return False
    
    def calculate_file_hash(
        self,
        filepath: Union[str, Path],
        algorithm: Optional[HashAlgorithm] = None,
        chunk_size: int = 8192
    ) -> Optional[str]:
        """
        Calculate hash of file (streaming for large files)
        
        Args:
            filepath: Path to file
            algorithm: Algorithm to use
            chunk_size: Chunk size for streaming read
            
        Returns:
            Hexadecimal hash string or None if failed
        """
        # Convert to Path object
        filepath = Path(filepath)
        
        # Validate file exists and is a regular file
        if not filepath.exists() or not filepath.is_file():
            self.logger.error(f"Invalid file: {filepath}")
            return None
        
        # Use default algorithm if none specified
        if algorithm is None:
            algorithm = self.default_algorithm
        
        try:
            # Get hash function for the algorithm
            hash_func = self._get_hash_function(algorithm)
            
            # Calculate hash using streaming (read in chunks)
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    hash_func.update(chunk)
            
            # Return hexadecimal hash
            return hash_func.hexdigest()
            
        except Exception as e:
            # Log error and return None (calculation failed)
            self.logger.error(f"Failed to calculate file hash for {filepath}: {e}")
            return None
    
    def hmac_verify(
        self,
        data: Union[bytes, str],
        key: Union[bytes, str],
        expected_hmac: str,
        algorithm: HashAlgorithm = HashAlgorithm.SHA256
    ) -> bool:
        """
        Verify HMAC (Hash-based Message Authentication Code)
        
        Args:
            data: Data to verify
            key: HMAC key
            expected_hmac: Expected HMAC string
            algorithm: Hash algorithm to use
            
        Returns:
            True if HMAC matches, False otherwise
        """
        try:
            # Convert inputs to bytes if they are strings
            if isinstance(data, str):
                data = data.encode('utf-8')
            if isinstance(key, str):
                key = key.encode('utf-8')
            
            # Parse expected HMAC string
            expected_algorithm, expected_hmac_value = self.parse_hash_string(expected_hmac)
            
            # Use provided algorithm or detected algorithm
            if algorithm is None:
                algorithm = expected_algorithm
            
            # Get hash function for HMAC calculation
            hash_func = self._get_hash_function(algorithm)
            
            # Calculate HMAC using hmac module
            hmac_calculator = hmac.new(key, data, hash_func)
            actual_hmac = hmac_calculator.hexdigest()
            
            # Constant-time comparison
            return constant_time_compare(actual_hmac, expected_hmac_value)
            
        except Exception as e:
            # Log error and return False (verification failed)
            self.logger.debug(f"HMAC verification failed: {e}")
            return False
    
    def get_algorithm_info(self, algorithm: HashAlgorithm) -> Dict[str, Any]:
        """
        Get information about a hash algorithm
        
        Args:
            algorithm: Algorithm to get info for
            
        Returns:
            Dictionary with algorithm information
        """
        return {
            'name': algorithm.value,          # Algorithm name
            'digest_size': algorithm.digest_size,  # Output size in bytes
            'block_size': algorithm.block_size,    # Internal block size
            'is_secure': algorithm.is_secure,      # Security status
            'is_deprecated': algorithm.is_deprecated,  # Deprecation status
            'description': self._get_algorithm_description(algorithm),  # Description
        }
    
    def _get_algorithm_description(self, algorithm: HashAlgorithm) -> str:
        """Get description of hash algorithm"""
        descriptions = {
            HashAlgorithm.SHA256: "SHA-256, 256-bit, widely used and secure",
            HashAlgorithm.SHA512: "SHA-512, 512-bit, more secure than SHA-256",
            HashAlgorithm.BLAKE2B: "BLAKE2b, 512-bit, faster than SHA-512",
            HashAlgorithm.BLAKE2S: "BLAKE2s, 256-bit, optimized for 32-bit systems",
            HashAlgorithm.SHA3_256: "SHA3-256, 256-bit, SHA-3 standard",
            HashAlgorithm.SHA3_512: "SHA3-512, 512-bit, SHA-3 standard",
            HashAlgorithm.MD5: "MD5, 128-bit, cryptographically broken",
            HashAlgorithm.SHA1: "SHA-1, 160-bit, considered broken",
            HashAlgorithm.SHA256D: "Double SHA-256, 256-bit, used in Bitcoin",
            HashAlgorithm.RIPEMD160: "RIPEMD-160, 160-bit, used in Bitcoin",
        }
        return descriptions.get(algorithm, "Unknown algorithm")
    
    def get_supported_algorithms(self) -> List[Dict[str, Any]]:
        """
        Get list of supported hash algorithms with info
        
        Returns:
            List of algorithm information dictionaries
        """
        algorithms = []
        
        # Iterate through all HashAlgorithm enum values
        for algorithm in HashAlgorithm:
            try:
                # Check if algorithm is available on this system
                self._get_hash_function(algorithm)
                
                # Add algorithm info to list
                algorithms.append(self.get_algorithm_info(algorithm))
            except (UnsupportedAlgorithm, ValueError):
                # Algorithm not available on this system, skip it
                continue
        
        return algorithms
    
    def clear_cache(self):
        """Clear hash cache"""
        self._hash_cache.clear()
        self.logger.debug("Hash cache cleared")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get hash cache statistics
        
        Returns:
            Dictionary with cache statistics
        """
        return {
            'size': len(self._hash_cache),  # Current cache size
            'max_size': self._cache_max_size,  # Maximum cache size
            'hit_rate': 0.0,  # Placeholder for hit rate (would need tracking)
            'algorithm_distribution': self._get_cache_distribution(),  # Cache distribution
        }
    
    def _get_cache_distribution(self) -> Dict[str, int]:
        """Get distribution of cached hashes by algorithm"""
        distribution = {}
        
        # Count cached entries by algorithm
        for (_, algorithm), _ in self._hash_cache.items():
            alg_name = algorithm.value
            distribution[alg_name] = distribution.get(alg_name, 0) + 1
        
        return distribution


# Convenience functions for easy usage without creating HashValidator instances

def verify_data_hash(
    data: Union[bytes, str],
    expected_hash: str,
    algorithm: Optional[HashAlgorithm] = None
) -> bool:
    """
    Convenience function to verify data hash
    
    Args:
        data: Data to verify
        expected_hash: Expected hash string
        algorithm: Algorithm to use
        
    Returns:
        True if hash matches, False otherwise
    """
    validator = HashValidator()  # Create default validator
    return validator.verify_hash(data, expected_hash, algorithm)


def calculate_data_hash(
    data: Union[bytes, str],
    algorithm: HashAlgorithm = HashAlgorithm.SHA256
) -> str:
    """
    Convenience function to calculate data hash
    
    Args:
        data: Data to hash
        algorithm: Algorithm to use
        
    Returns:
        Hexadecimal hash string
    """
    validator = HashValidator()  # Create default validator
    return validator.calculate_hash(data, algorithm)


def verify_file_hash_simple(
    filepath: Union[str, Path],
    expected_hash: str
) -> bool:
    """
    Convenience function to verify file hash
    
    Args:
        filepath: Path to file
        expected_hash: Expected hash string
        
    Returns:
        True if file hash matches, False otherwise
    """
    validator = HashValidator()  # Create default validator
    return validator.verify_file_hash(filepath, expected_hash)


def get_secure_hash_algorithms() -> List[Dict[str, Any]]:
    """
    Get list of secure hash algorithms
    
    Returns:
        List of secure algorithm information
    """
    # Create validator with secure-only setting
    validator = HashValidator(require_secure=True)
    
    # Filter to only secure algorithms
    secure_algorithms = []
    for algorithm_info in validator.get_supported_algorithms():
        if algorithm_info['is_secure']:
            secure_algorithms.append(algorithm_info)
    
    return secure_algorithms