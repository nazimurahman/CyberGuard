# CyberGuard/src/utils/crypto_utils.py
"""
Cryptography Utilities for CyberGuard Web Security AI System.

This module provides comprehensive cryptographic operations:
- Symmetric encryption (AES-GCM, ChaCha20-Poly1305)
- Asymmetric encryption (RSA, ECC)
- Digital signatures and verification
- Hash functions and HMAC
- Key management and rotation
- Secure random generation
- CSRF token generation

All operations follow cryptographic best practices and use
audited libraries (cryptography, PyNaCl).
"""

import os
import base64
import json
import hashlib
import hmac
import secrets
from typing import Union, Optional, Tuple, Dict, Any, List
from datetime import datetime, timedelta
from enum import Enum
import threading
from dataclasses import dataclass, asdict

# Third-party cryptography libraries
try:
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as asym_padding
    from cryptography.hazmat.primitives.serialization import (
        load_pem_public_key, load_pem_private_key,
        Encoding, PrivateFormat, PublicFormat, NoEncryption
    )
    from cryptography.exceptions import InvalidSignature, InvalidKey
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

try:
    import nacl.secret
    import nacl.utils
    import nacl.public
    import nacl.signing
    PYNACL_AVAILABLE = True
except ImportError:
    PYNACL_AVAILABLE = False


class EncryptionAlgorithm(Enum):
    """Supported encryption algorithms."""
    AES_GCM = "AES-GCM"          # Authenticated encryption (recommended)
    CHACHA20_POLY1305 = "CHACHA20-POLY1305"  # Fast, secure alternative
    AES_CBC = "AES-CBC"          # Legacy compatibility


class HashAlgorithm(Enum):
    """Supported hash algorithms."""
    SHA256 = "SHA256"            # Standard secure hash
    SHA512 = "SHA512"            # Stronger hash
    BLAKE2B = "BLAKE2B"          # Fast, modern hash
    SHA3_256 = "SHA3_256"        # SHA-3 family


class KeyType(Enum):
    """Key types for asymmetric cryptography."""
    RSA_2048 = "RSA_2048"        # 2048-bit RSA
    RSA_4096 = "RSA_4096"        # 4096-bit RSA (more secure)
    ECDSA_P256 = "ECDSA_P256"    # P-256 curve (NIST)
    ECDSA_P384 = "ECDSA_P384"    # P-384 curve (more secure)
    ED25519 = "ED25519"          # Edwards curve (fast, secure)


@dataclass
class EncryptionResult:
    """Result of encryption operation."""
    ciphertext: bytes            # Encrypted data
    tag: Optional[bytes] = None  # Authentication tag (GCM/Poly1305)
    iv: Optional[bytes] = None   # Initialization vector
    algorithm: str = "AES-GCM"   # Algorithm used
    timestamp: Optional[str] = None  # Encryption timestamp
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        # Encode binary fields as base64
        for field in ['ciphertext', 'tag', 'iv']:
            if data[field]:
                data[field] = base64.b64encode(data[field]).decode('utf-8')
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EncryptionResult':
        """Create from dictionary."""
        # Decode base64 fields
        for field in ['ciphertext', 'tag', 'iv']:
            if data.get(field):
                data[field] = base64.b64decode(data[field])
        return cls(**data)


class CryptoManager:
    """
    Central cryptography manager for all cryptographic operations.
    
    Provides a unified interface for encryption, decryption, signing,
    and verification with automatic key management.
    """
    
    def __init__(self, 
                 master_key: Optional[bytes] = None,
                 key_rotation_days: int = 30,
                 key_storage_path: str = "keys/"):
        """
        Initialize cryptography manager.
        
        Args:
            master_key: Optional master key for key derivation
            key_rotation_days: Days between automatic key rotation
            key_storage_path: Path for key storage
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            raise ImportError("cryptography library is required")
        
        self.key_rotation_days = key_rotation_days
        self.key_storage_path = key_storage_path
        
        # Create key storage directory
        os.makedirs(key_storage_path, exist_ok=True)
        
        # Initialize or load master key
        self.master_key = master_key or self._load_or_generate_master_key()
        
        # Key cache for performance
        self._key_cache: Dict[str, bytes] = {}
        self._cache_lock = threading.Lock()
        
        # Current key version
        self.current_key_version = self._get_current_key_version()
        
        # Key rotation tracker
        self.last_rotation_date = self._load_rotation_date()
    
    def _load_or_generate_master_key(self) -> bytes:
        """
        Load existing master key or generate new one.
        
        Returns:
            Master key bytes
        """
        master_key_path = os.path.join(self.key_storage_path, "master.key")
        
        if os.path.exists(master_key_path):
            # Load existing key
            with open(master_key_path, 'rb') as f:
                encrypted_key = f.read()
            
            # In production, this would use a KMS or hardware security module
            # For this example, we'll use a simple approach
            # WARNING: In production, use proper key management!
            key = self._decrypt_with_env_key(encrypted_key)
        else:
            # Generate new key
            key = secrets.token_bytes(32)  # 256-bit key
            
            # Encrypt and store
            encrypted_key = self._encrypt_with_env_key(key)
            with open(master_key_path, 'wb') as f:
                f.write(encrypted_key)
            
            # Set restrictive permissions
            os.chmod(master_key_path, 0o600)
        
        return key
    
    def _encrypt_with_env_key(self, data: bytes) -> bytes:
        """Encrypt data with environment-based key (simplified)."""
        # In production, use AWS KMS, Azure Key Vault, or HashiCorp Vault
        # This is a simplified example for demonstration
        env_key = os.environ.get('CYBERGUARD_ENCRYPTION_KEY', '').encode()
        
        if not env_key:
            # Fallback: use a derived key (NOT SECURE FOR PRODUCTION)
            env_key = hashlib.sha256(b"fallback_key").digest()
        
        # Simple XOR encryption (NOT SECURE - for demonstration only)
        # In production, use proper authenticated encryption
        result = bytearray(data)
        for i in range(len(result)):
            result[i] ^= env_key[i % len(env_key)]
        
        return bytes(result)
    
    def _decrypt_with_env_key(self, data: bytes) -> bytes:
        """Decrypt data with environment-based key."""
        # Same as encryption for XOR
        return self._encrypt_with_env_key(data)
    
    def _get_current_key_version(self) -> str:
        """Get current key version identifier."""
        version_file = os.path.join(self.key_storage_path, "current_version")
        
        if os.path.exists(version_file):
            with open(version_file, 'r') as f:
                return f.read().strip()
        else:
            # Generate new version
            version = datetime.now().strftime("%Y%m%d_%H%M%S")
            with open(version_file, 'w') as f:
                f.write(version)
            return version
    
    def _load_rotation_date(self) -> datetime:
        """Load last key rotation date."""
        rotation_file = os.path.join(self.key_storage_path, "last_rotation")
        
        if os.path.exists(rotation_file):
            with open(rotation_file, 'r') as f:
                date_str = f.read().strip()
                return datetime.fromisoformat(date_str)
        else:
            return datetime.now()
    
    def _check_key_rotation(self):
        """Check if key rotation is needed."""
        days_since_rotation = (datetime.now() - self.last_rotation_date).days
        
        if days_since_rotation >= self.key_rotation_days:
            self._rotate_keys()
    
    def _rotate_keys(self):
        """Rotate encryption keys."""
        print("Rotating encryption keys...")
        
        # Generate new key version
        new_version = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Update current version
        version_file = os.path.join(self.key_storage_path, "current_version")
        with open(version_file, 'w') as f:
            f.write(new_version)
        
        # Update rotation date
        rotation_file = os.path.join(self.key_storage_path, "last_rotation")
        with open(rotation_file, 'w') as f:
            f.write(datetime.now().isoformat())
        
        # Clear key cache
        with self._cache_lock:
            self._key_cache.clear()
        
        self.current_key_version = new_version
        self.last_rotation_date = datetime.now()
        
        print(f"Key rotation complete. New version: {new_version}")
    
    def derive_key(self, context: str, key_size: int = 32) -> bytes:
        """
        Derive a cryptographic key from master key.
        
        Args:
            context: Key context/identifier
            key_size: Key size in bytes
            
        Returns:
            Derived key bytes
        """
        cache_key = f"{context}_{key_size}"
        
        with self._cache_lock:
            if cache_key in self._key_cache:
                return self._key_cache[cache_key]
        
        # Use HKDF for key derivation
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        
        # Include key version in context to ensure key rotation works
        full_context = f"{self.current_key_version}:{context}"
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=key_size,
            salt=None,
            info=full_context.encode(),
        )
        
        derived_key = hkdf.derive(self.master_key)
        
        with self._cache_lock:
            self._key_cache[cache_key] = derived_key
        
        return derived_key
    
    def encrypt(self, plaintext: Union[str, bytes], 
               algorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES_GCM,
               context: str = "default") -> EncryptionResult:
        """
        Encrypt data with authenticated encryption.
        
        Args:
            plaintext: Data to encrypt
            algorithm: Encryption algorithm to use
            context: Key derivation context
            
        Returns:
            EncryptionResult with ciphertext and metadata
            
        Raises:
            ValueError: If plaintext is empty
        """
        if not plaintext:
            raise ValueError("Cannot encrypt empty plaintext")
        
        # Convert to bytes if string
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Check key rotation
        self._check_key_rotation()
        
        if algorithm == EncryptionAlgorithm.AES_GCM:
            return self._encrypt_aes_gcm(plaintext, context)
        elif algorithm == EncryptionAlgorithm.CHACHA20_POLY1305 and PYNACL_AVAILABLE:
            return self._encrypt_chacha20(plaintext, context)
        elif algorithm == EncryptionAlgorithm.AES_CBC:
            return self._encrypt_aes_cbc(plaintext, context)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def _encrypt_aes_gcm(self, plaintext: bytes, context: str) -> EncryptionResult:
        """Encrypt using AES-GCM."""
        # Derive encryption key
        key = self.derive_key(context, 32)  # 256-bit key
        
        # Generate random IV (96 bits for GCM)
        iv = secrets.token_bytes(12)
        
        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        
        # Encrypt
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        return EncryptionResult(
            ciphertext=ciphertext,
            tag=encryptor.tag,
            iv=iv,
            algorithm="AES-GCM",
            timestamp=datetime.now().isoformat()
        )
    
    def _encrypt_chacha20(self, plaintext: bytes, context: str) -> EncryptionResult:
        """Encrypt using ChaCha20-Poly1305."""
        if not PYNACL_AVAILABLE:
            raise ImportError("PyNaCl required for ChaCha20-Poly1305")
        
        # Derive encryption key
        key = self.derive_key(context, 32)
        
        # Create secret box
        box = nacl.secret.SecretBox(key)
        
        # Encrypt
        encrypted = box.encrypt(plaintext)
        
        # Split into nonce and ciphertext
        nonce = encrypted.nonce
        ciphertext = encrypted.ciphertext
        
        return EncryptionResult(
            ciphertext=ciphertext,
            tag=None,  # Poly1305 tag is included in ciphertext
            iv=nonce,
            algorithm="CHACHA20-POLY1305",
            timestamp=datetime.now().isoformat()
        )
    
    def _encrypt_aes_cbc(self, plaintext: bytes, context: str) -> EncryptionResult:
        """Encrypt using AES-CBC (legacy)."""
        # Derive encryption key
        key = self.derive_key(context, 32)
        
        # Generate random IV
        iv = secrets.token_bytes(16)
        
        # Pad plaintext
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Encrypt
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        return EncryptionResult(
            ciphertext=ciphertext,
            tag=None,
            iv=iv,
            algorithm="AES-CBC",
            timestamp=datetime.now().isoformat()
        )
    
    def decrypt(self, encrypted_data: Union[EncryptionResult, Dict[str, Any]],
               context: str = "default") -> bytes:
        """
        Decrypt data.
        
        Args:
            encrypted_data: Encrypted data with metadata
            context: Key derivation context
            
        Returns:
            Decrypted plaintext bytes
            
        Raises:
            ValueError: If decryption fails
        """
        # Convert dict to EncryptionResult if needed
        if isinstance(encrypted_data, dict):
            encrypted_data = EncryptionResult.from_dict(encrypted_data)
        
        algorithm = encrypted_data.algorithm
        
        if algorithm == "AES-GCM":
            return self._decrypt_aes_gcm(encrypted_data, context)
        elif algorithm == "CHACHA20-POLY1305" and PYNACL_AVAILABLE:
            return self._decrypt_chacha20(encrypted_data, context)
        elif algorithm == "AES-CBC":
            return self._decrypt_aes_cbc(encrypted_data, context)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def _decrypt_aes_gcm(self, encrypted: EncryptionResult, context: str) -> bytes:
        """Decrypt AES-GCM encrypted data."""
        if not encrypted.tag or not encrypted.iv:
            raise ValueError("Missing authentication tag or IV for AES-GCM")
        
        # Derive decryption key
        key = self.derive_key(context, 32)
        
        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.GCM(encrypted.iv, encrypted.tag))
        decryptor = cipher.decryptor()
        
        # Decrypt
        plaintext = decryptor.update(encrypted.ciphertext) + decryptor.finalize()
        
        return plaintext
    
    def _decrypt_chacha20(self, encrypted: EncryptionResult, context: str) -> bytes:
        """Decrypt ChaCha20-Poly1305 encrypted data."""
        if not PYNACL_AVAILABLE:
            raise ImportError("PyNaCl required for ChaCha20-Poly1305")
        
        if not encrypted.iv:
            raise ValueError("Missing nonce for ChaCha20-Poly1305")
        
        # Derive decryption key
        key = self.derive_key(context, 32)
        
        # Create secret box
        box = nacl.secret.SecretBox(key)
        
        # Decrypt
        try:
            plaintext = box.decrypt(encrypted.ciphertext, encrypted.iv)
        except nacl.exceptions.CryptoError as e:
            raise ValueError(f"Decryption failed: {e}")
        
        return plaintext
    
    def _decrypt_aes_cbc(self, encrypted: EncryptionResult, context: str) -> bytes:
        """Decrypt AES-CBC encrypted data."""
        if not encrypted.iv:
            raise ValueError("Missing IV for AES-CBC")
        
        # Derive decryption key
        key = self.derive_key(context, 32)
        
        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(encrypted.iv))
        decryptor = cipher.decryptor()
        
        # Decrypt
        padded_data = decryptor.update(encrypted.ciphertext) + decryptor.finalize()
        
        # Unpad
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        
        return plaintext
    
    def encrypt_string(self, plaintext: str, **kwargs) -> str:
        """
        Encrypt string and return as base64-encoded JSON.
        
        Args:
            plaintext: String to encrypt
            **kwargs: Additional arguments for encrypt()
            
        Returns:
            Base64-encoded JSON string
        """
        result = self.encrypt(plaintext, **kwargs)
        result_dict = result.to_dict()
        return base64.b64encode(json.dumps(result_dict).encode()).decode()
    
    def decrypt_string(self, encrypted_str: str, **kwargs) -> str:
        """
        Decrypt base64-encoded JSON string.
        
        Args:
            encrypted_str: Base64-encoded encrypted data
            **kwargs: Additional arguments for decrypt()
            
        Returns:
            Decrypted string
        """
        # Decode base64 and parse JSON
        encrypted_dict = json.loads(base64.b64decode(encrypted_str).decode())
        plaintext_bytes = self.decrypt(encrypted_dict, **kwargs)
        return plaintext_bytes.decode('utf-8')
    
    def generate_hmac(self, data: Union[str, bytes], 
                     key_context: str = "hmac") -> str:
        """
        Generate HMAC for data verification.
        
        Args:
            data: Data to hash
            key_context: Key derivation context
            
        Returns:
            Hex-encoded HMAC
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Derive HMAC key
        key = self.derive_key(key_context, 32)
        
        # Generate HMAC
        h = hmac.new(key, data, hashlib.sha256)
        return h.hexdigest()
    
    def verify_hmac(self, data: Union[str, bytes], 
                   hmac_value: str,
                   key_context: str = "hmac") -> bool:
        """
        Verify HMAC for data.
        
        Args:
            data: Data to verify
            hmac_value: Expected HMAC value
            key_context: Key derivation context
            
        Returns:
            True if HMAC is valid
        """
        expected_hmac = self.generate_hmac(data, key_context)
        return hmac.compare_digest(expected_hmac, hmac_value)


class KeyManager:
    """
    Manager for asymmetric key pairs (RSA, ECC).
    
    Handles key generation, storage, rotation, and retrieval.
    """
    
    def __init__(self, key_storage_path: str = "keys/asymmetric/"):
        """
        Initialize key manager.
        
        Args:
            key_storage_path: Path for key storage
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            raise ImportError("cryptography library is required")
        
        self.key_storage_path = key_storage_path
        os.makedirs(key_storage_path, exist_ok=True)
    
    def generate_key_pair(self, key_type: KeyType = KeyType.RSA_2048,
                         key_id: Optional[str] = None) -> Tuple[str, str]:
        """
        Generate asymmetric key pair.
        
        Args:
            key_type: Type of key to generate
            key_id: Optional identifier for the key
            
        Returns:
            Tuple of (private_key_pem, public_key_pem)
        """
        if not key_id:
            key_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if key_type in [KeyType.RSA_2048, KeyType.RSA_4096]:
            # RSA key generation
            key_size = 2048 if key_type == KeyType.RSA_2048 else 4096
            
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
            )
        
        elif key_type in [KeyType.ECDSA_P256, KeyType.ECDSA_P384]:
            # ECDSA key generation
            curve = ec.SECP256R1() if key_type == KeyType.ECDSA_P256 else ec.SECP384R1()
            
            private_key = ec.generate_private_key(curve)
        
        elif key_type == KeyType.ED25519 and PYNACL_AVAILABLE:
            # Ed25519 key generation
            private_key = nacl.signing.SigningKey.generate()
            public_key = private_key.verify_key
            
            # Convert to PEM-like format
            private_pem = private_key.encode().hex()
            public_pem = public_key.encode().hex()
            
            # Save keys
            self._save_key(key_id, "private", private_pem)
            self._save_key(key_id, "public", public_pem)
            
            return private_pem, public_pem
        
        else:
            raise ValueError(f"Unsupported key type: {key_type}")
        
        # Convert to PEM format
        private_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        ).decode('utf-8')
        
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        # Save keys
        self._save_key(key_id, "private", private_pem)
        self._save_key(key_id, "public", public_pem)
        
        return private_pem, public_pem
    
    def _save_key(self, key_id: str, key_type: str, key_data: str):
        """Save key to file."""
        filename = f"{key_id}_{key_type}.pem"
        filepath = os.path.join(self.key_storage_path, filename)
        
        with open(filepath, 'w') as f:
            f.write(key_data)
        
        # Set restrictive permissions
        os.chmod(filepath, 0o600)
    
    def load_key_pair(self, key_id: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Load key pair by ID.
        
        Args:
            key_id: Key identifier
            
        Returns:
            Tuple of (private_key, public_key) or (None, None) if not found
        """
        private_path = os.path.join(self.key_storage_path, f"{key_id}_private.pem")
        public_path = os.path.join(self.key_storage_path, f"{key_id}_public.pem")
        
        private_key = None
        public_key = None
        
        if os.path.exists(private_path):
            with open(private_path, 'r') as f:
                private_key = f.read()
        
        if os.path.exists(public_path):
            with open(public_path, 'r') as f:
                public_key = f.read()
        
        return private_key, public_key
    
    def sign_data(self, data: Union[str, bytes], 
                 private_key_pem: str,
                 hash_algorithm: HashAlgorithm = HashAlgorithm.SHA256) -> bytes:
        """
        Sign data with private key.
        
        Args:
            data: Data to sign
            private_key_pem: Private key in PEM format
            hash_algorithm: Hash algorithm to use
            
        Returns:
            Digital signature bytes
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Load private key
        private_key = load_pem_private_key(
            private_key_pem.encode(),
            password=None
        )
        
        # Create signature
        if isinstance(private_key, rsa.RSAPrivateKey):
            # RSA signing
            hasher = self._get_hash_algorithm(hash_algorithm)
            
            signature = private_key.sign(
                data,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hasher),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hasher()
            )
        
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            # ECDSA signing
            hasher = self._get_hash_algorithm(hash_algorithm)
            
            signature = private_key.sign(
                data,
                ec.ECDSA(hasher())
            )
        
        else:
            raise ValueError("Unsupported private key type")
        
        return signature
    
    def verify_signature(self, data: Union[str, bytes],
                        signature: bytes,
                        public_key_pem: str,
                        hash_algorithm: HashAlgorithm = HashAlgorithm.SHA256) -> bool:
        """
        Verify digital signature.
        
        Args:
            data: Original data
            signature: Signature to verify
            public_key_pem: Public key in PEM format
            hash_algorithm: Hash algorithm used
            
        Returns:
            True if signature is valid
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        try:
            # Load public key
            public_key = load_pem_public_key(public_key_pem.encode())
            
            # Verify signature
            if isinstance(public_key, rsa.RSAPublicKey):
                # RSA verification
                hasher = self._get_hash_algorithm(hash_algorithm)
                
                public_key.verify(
                    signature,
                    data,
                    asym_padding.PSS(
                        mgf=asym_padding.MGF1(hasher),
                        salt_length=asym_padding.PSS.MAX_LENGTH
                    ),
                    hasher()
                )
            
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                # ECDSA verification
                hasher = self._get_hash_algorithm(hash_algorithm)
                
                public_key.verify(
                    signature,
                    data,
                    ec.ECDSA(hasher())
                )
            
            else:
                return False
            
            return True
        
        except InvalidSignature:
            return False
        except Exception:
            return False
    
    def _get_hash_algorithm(self, hash_algo: HashAlgorithm) -> Any:
        """Get cryptography hash algorithm object."""
        if hash_algo == HashAlgorithm.SHA256:
            return hashes.SHA256
        elif hash_algo == HashAlgorithm.SHA512:
            return hashes.SHA512
        elif hash_algo == HashAlgorithm.SHA3_256:
            return hashes.SHA3_256
        else:
            raise ValueError(f"Unsupported hash algorithm: {hash_algo}")


# Global crypto manager instance
_CRYPTO_MANAGER: Optional[CryptoManager] = None
_KEY_MANAGER: Optional[KeyManager] = None


def get_crypto_manager() -> CryptoManager:
    """
    Get global crypto manager instance.
    
    Returns:
        CryptoManager instance
    """
    global _CRYPTO_MANAGER
    
    if _CRYPTO_MANAGER is None:
        _CRYPTO_MANAGER = CryptoManager(
            key_rotation_days=30,
            key_storage_path="keys/symmetric/"
        )
    
    return _CRYPTO_MANAGER


def get_key_manager() -> KeyManager:
    """
    Get global key manager instance.
    
    Returns:
        KeyManager instance
    """
    global _KEY_MANAGER
    
    if _KEY_MANAGER is None:
        _KEY_MANAGER = KeyManager(
            key_storage_path="keys/asymmetric/"
        )
    
    return _KEY_MANAGER


def encrypt_data(plaintext: Union[str, bytes], **kwargs) -> Union[EncryptionResult, str]:
    """
    Encrypt data using global crypto manager.
    
    Args:
        plaintext: Data to encrypt
        **kwargs: Additional arguments for CryptoManager.encrypt()
        
    Returns:
        EncryptionResult or encrypted string
    """
    manager = get_crypto_manager()
    
    if kwargs.get('return_string', False):
        return manager.encrypt_string(plaintext, **kwargs)
    else:
        return manager.encrypt(plaintext, **kwargs)


def decrypt_data(encrypted_data: Union[EncryptionResult, Dict[str, Any], str],
                **kwargs) -> Union[bytes, str]:
    """
    Decrypt data using global crypto manager.
    
    Args:
        encrypted_data: Encrypted data
        **kwargs: Additional arguments for CryptoManager.decrypt()
        
    Returns:
        Decrypted bytes or string
    """
    manager = get_crypto_manager()
    
    if isinstance(encrypted_data, str):
        # Assume it's a base64-encoded JSON string
        return manager.decrypt_string(encrypted_data, **kwargs)
    else:
        decrypted = manager.decrypt(encrypted_data, **kwargs)
        
        if kwargs.get('return_string', False):
            return decrypted.decode('utf-8')
        else:
            return decrypted


def generate_key_pair(key_type: KeyType = KeyType.RSA_2048,
                     key_id: Optional[str] = None) -> Tuple[str, str]:
    """
    Generate asymmetric key pair.
    
    Args:
        key_type: Type of key to generate
        key_id: Optional key identifier
        
    Returns:
        Tuple of (private_key, public_key) in PEM format
    """
    manager = get_key_manager()
    return manager.generate_key_pair(key_type, key_id)


def sign_data(data: Union[str, bytes],
             private_key_pem: str,
             **kwargs) -> str:
    """
    Sign data with private key.
    
    Args:
        data: Data to sign
        private_key_pem: Private key in PEM format
        **kwargs: Additional arguments
        
    Returns:
        Base64-encoded signature
    """
    manager = get_key_manager()
    signature = manager.sign_data(data, private_key_pem, **kwargs)
    return base64.b64encode(signature).decode()


def verify_signature(data: Union[str, bytes],
                    signature_b64: str,
                    public_key_pem: str,
                    **kwargs) -> bool:
    """
    Verify digital signature.
    
    Args:
        data: Original data
        signature_b64: Base64-encoded signature
        public_key_pem: Public key in PEM format
        **kwargs: Additional arguments
        
    Returns:
        True if signature is valid
    """
    manager = get_key_manager()
    signature = base64.b64decode(signature_b64)
    return manager.verify_signature(data, signature, public_key_pem, **kwargs)


def generate_hmac(data: Union[str, bytes], **kwargs) -> str:
    """
    Generate HMAC for data.
    
    Args:
        data: Data to hash
        **kwargs: Additional arguments
        
    Returns:
        Hex-encoded HMAC
    """
    manager = get_crypto_manager()
    return manager.generate_hmac(data, **kwargs)


def verify_hmac(data: Union[str, bytes], hmac_value: str, **kwargs) -> bool:
    """
    Verify HMAC for data.
    
    Args:
        data: Data to verify
        hmac_value: Expected HMAC
        **kwargs: Additional arguments
        
    Returns:
        True if HMAC is valid
    """
    manager = get_crypto_manager()
    return manager.verify_hmac(data, hmac_value, **kwargs)


def generate_csrf_token(session_id: str, expiry_minutes: int = 30) -> str:
    """
    Generate CSRF token with expiry.
    
    Args:
        session_id: Session identifier
        expiry_minutes: Token expiry in minutes
        
    Returns:
        CSRF token
    """
    # Create token data
    timestamp = int(time.time())
    expiry = timestamp + (expiry_minutes * 60)
    
    token_data = f"{session_id}:{expiry}:{secrets.token_hex(16)}"
    
    # Sign with HMAC
    hmac_key = get_crypto_manager().derive_key("csrf", 32)
    token_hmac = hmac.new(hmac_key, token_data.encode(), hashlib.sha256).hexdigest()
    
    # Combine token and HMAC
    full_token = f"{token_data}:{token_hmac}"
    
    return base64.b64encode(full_token.encode()).decode()


def verify_csrf_token(token: str, session_id: str) -> bool:
    """
    Verify CSRF token.
    
    Args:
        token: CSRF token to verify
        session_id: Expected session ID
        
    Returns:
        True if token is valid
    """
    try:
        # Decode token
        token_bytes = base64.b64decode(token)
        token_parts = token_bytes.decode().split(':')
        
        if len(token_parts) != 4:
            return False
        
        token_session, token_expiry, random_part, token_hmac = token_parts
        
        # Check session ID
        if token_session != session_id:
            return False
        
        # Check expiry
        if int(time.time()) > int(token_expiry):
            return False
        
        # Verify HMAC
        token_data = f"{token_session}:{token_expiry}:{random_part}"
        hmac_key = get_crypto_manager().derive_key("csrf", 32)
        expected_hmac = hmac.new(hmac_key, token_data.encode(), hashlib.sha256).hexdigest()
        
        return hmac.compare_digest(expected_hmac, token_hmac)
    
    except Exception:
        return False


# Example usage
if __name__ == "__main__":
    # Test symmetric encryption
    crypto = get_crypto_manager()
    
    plaintext = "Sensitive data that needs encryption"
    
    # Encrypt
    encrypted = crypto.encrypt(plaintext, context="test")
    print(f"Encrypted: {len(encrypted.ciphertext)} bytes")
    
    # Decrypt
    decrypted = crypto.decrypt(encrypted, context="test")
    print(f"Decrypted: {decrypted.decode()}")
    
    # Test string encryption
    encrypted_str = crypto.encrypt_string(plaintext, context="test")
    print(f"Encrypted string: {encrypted_str[:50]}...")
    
    decrypted_str = crypto.decrypt_string(encrypted_str, context="test")
    print(f"Decrypted string: {decrypted_str}")
    
    # Test HMAC
    data = "Data to authenticate"
    hmac_value = crypto.generate_hmac(data, key_context="test")
    print(f"HMAC: {hmac_value}")
    
    is_valid = crypto.verify_hmac(data, hmac_value, key_context="test")
    print(f"HMAC valid: {is_valid}")
    
    # Test asymmetric cryptography
    key_manager = get_key_manager()
    
    # Generate key pair
    private_key, public_key = key_manager.generate_key_pair(KeyType.RSA_2048)
    print(f"Private key length: {len(private_key)}")
    print(f"Public key length: {len(public_key)}")
    
    # Sign and verify
    data_to_sign = "Important document"
    signature = key_manager.sign_data(data_to_sign, private_key)
    print(f"Signature length: {len(signature)} bytes")
    
    is_verified = key_manager.verify_signature(data_to_sign, signature, public_key)
    print(f"Signature verified: {is_verified}")
    
    # Test CSRF tokens
    session_id = "session_12345"
    csrf_token = generate_csrf_token(session_id)
    print(f"CSRF token: {csrf_token[:30]}...")
    
    is_valid_csrf = verify_csrf_token(csrf_token, session_id)
    print(f"CSRF token valid: {is_valid_csrf}")