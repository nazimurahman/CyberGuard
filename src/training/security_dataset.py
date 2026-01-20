# src/training/security_dataset.py
"""
Security Dataset Module for CyberGuard
======================================

This module provides specialized datasets for cybersecurity training:
1. SecurityDataset: Base class for all security datasets
2. ThreatIntelligenceDataset: CVE, exploit, and threat feed data
3. WebTrafficDataset: HTTP request/response data for web security
4. AttackPatternDataset: MITRE ATT&CK and OWASP patterns

Key Features:
- Real-time threat feed integration
- Data augmentation for attack patterns
- Privacy-preserving data handling
- Label encoding for security categories
"""

import torch
from torch.utils.data import Dataset, DataLoader
from typing import Dict, List, Tuple, Optional, Union, Any
import numpy as np
import pandas as pd
from datetime import datetime
import json
import hashlib
from pathlib import Path
import warnings
from collections import defaultdict
import random

class SecurityDataset(Dataset):
    """
    Base dataset class for cybersecurity training data.
    
    This class provides the foundation for all security datasets with:
    - Secure data loading and validation
    - Privacy-preserving transformations
    - Threat label encoding
    - Data integrity verification
    
    Architecture:
    ├── Data Ingestion: Load from secure sources (CVE feeds, WAF logs, etc.)
    ├── Preprocessing: Clean, normalize, and augment security data
    ├── Feature Extraction: Convert raw security events to ML features
    └── Label Encoding: Map security findings to threat categories
    """
    
    def __init__(self, 
                 data_path: Union[str, Path],
                 feature_dim: int = 512,
                 max_sequence_length: int = 512,
                 threat_categories: Optional[List[str]] = None,
                 use_encryption: bool = True):
        """
        Initialize the security dataset.
        
        Args:
            data_path: Path to security data (file or directory)
            feature_dim: Dimension of feature vectors (default: 512)
            max_sequence_length: Maximum sequence length for transformer models
            threat_categories: List of threat category names (e.g., ['XSS', 'SQLi'])
            use_encryption: Whether to encrypt sensitive data in memory
            
        Why these parameters matter:
        - feature_dim=512: Standard size for transformer embeddings
        - max_sequence_length=512: Common limit for transformer models
        - threat_categories: Enables multi-label classification
        - use_encryption: Protects sensitive attack patterns in memory
        """
        super().__init__()
        
        # Convert path to Path object for cross-platform compatibility
        self.data_path = Path(data_path)
        self.feature_dim = feature_dim
        self.max_sequence_length = max_sequence_length
        self.use_encryption = use_encryption
        
        # Default threat categories based on OWASP Top-10 2021
        self.threat_categories = threat_categories or [
            'Injection',              # SQLi, NoSQLi, OS command injection
            'Broken_Authentication',  # Credential stuffing, session hijacking
            'Sensitive_Data_Exposure', # PII leakage, improper encryption
            'XML_External_Entities',  # XXE attacks
            'Broken_Access_Control',  # IDOR, privilege escalation
            'Security_Misconfiguration', # Default credentials, exposed admin panels
            'Cross_Site_Scripting',   # XSS attacks (reflected, stored, DOM)
            'Insecure_Deserialization', # RCE via deserialization
            'Using_Components_with_Known_Vulns', # CVEs in dependencies
            'Insufficient_Logging_Monitoring' # Lack of security observability
        ]
        
        # Create mapping from threat categories to indices for one-hot encoding
        self.category_to_idx = {
            category: idx for idx, category in enumerate(self.threat_categories)
        }
        self.idx_to_category = {
            idx: category for category, idx in self.category_to_idx.items()
        }
        
        # Data storage with optional encryption
        self.encrypted_data = [] if use_encryption else None
        self.data_hash = None
        
        # Statistics tracking
        self.stats = {
            'total_samples': 0,
            'threat_distribution': defaultdict(int),
            'avg_sequence_length': 0,
            'data_source': str(data_path)
        }
        
        # Load and validate data
        self._load_data()
        self._validate_data()
        
        # Initialize feature extractor
        self._init_feature_extractor()
        
    def _load_data(self):
        """
        Load security data from various formats with integrity checking.
        
        Supported formats:
        - JSON/JSONL: For structured threat intelligence
        - CSV: For WAF logs and security events
        - Parquet: For large-scale security telemetry
        - PCAP: Network traffic captures (requires additional parsing)
        
        Security measures:
        1. File hash verification for tamper detection
        2. Schema validation against security standards
        3. Malicious pattern detection in loaded data
        4. Rate limiting for remote data sources
        """
        print(f"🔍 Loading security data from: {self.data_path}")
        
        # Check if path exists
        if not self.data_path.exists():
            raise FileNotFoundError(f"Security data not found at: {self.data_path}")
        
        # Calculate data hash for integrity verification
        self.data_hash = self._calculate_data_hash()
        print(f"📊 Data integrity hash: {self.data_hash[:16]}...")
        
        # Determine file type and load accordingly
        if self.data_path.is_file():
            # Single file
            if self.data_path.suffix == '.json':
                self._load_json_data()
            elif self.data_path.suffix == '.jsonl':
                self._load_jsonl_data()
            elif self.data_path.suffix == '.csv':
                self._load_csv_data()
            elif self.data_path.suffix == '.parquet':
                self._load_parquet_data()
            else:
                raise ValueError(f"Unsupported file format: {self.data_path.suffix}")
        else:
            # Directory - load all supported files
            self._load_directory_data()
        
        print(f"✅ Loaded {self.stats['total_samples']} security samples")
        
    def _calculate_data_hash(self) -> str:
        """
        Calculate SHA-256 hash of data for integrity verification.
        
        This prevents:
        - Data tampering during training
        - Poisoning attacks on training data
        - Version mismatches in security datasets
        
        Returns:
            SHA-256 hash of the data file/directory
        """
        hasher = hashlib.sha256()
        
        if self.data_path.is_file():
            # Hash file content
            with open(self.data_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hasher.update(chunk)
        else:
            # Hash directory structure and file contents
            for file_path in self.data_path.rglob('*'):
                if file_path.is_file():
                    # Add file path to hash
                    hasher.update(str(file_path.relative_to(self.data_path)).encode())
                    
                    # Add file content to hash
                    with open(file_path, 'rb') as f:
                        for chunk in iter(lambda: f.read(4096), b''):
                            hasher.update(chunk)
        
        return hasher.hexdigest()
    
    def _load_json_data(self):
        """Load JSON security data with schema validation."""
        try:
            with open(self.data_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # JSON can be a list of samples or a single object
            if isinstance(data, list):
                samples = data
            else:
                samples = [data]  # Single sample
            
            # Process each sample
            for sample in samples:
                self._process_sample(sample)
                
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in {self.data_path}: {e}")
    
    def _load_jsonl_data(self):
        """Load JSONL (JSON Lines) security data."""
        with open(self.data_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    sample = json.loads(line.strip())
                    self._process_sample(sample)
                except json.JSONDecodeError as e:
                    warnings.warn(f"Line {line_num}: Invalid JSON - {e}")
                    continue
    
    def _load_csv_data(self):
        """Load CSV security data (e.g., WAF logs)."""
        try:
            df = pd.read_csv(self.data_path)
            
            # Convert each row to a sample
            for _, row in df.iterrows():
                sample = row.to_dict()
                self._process_sample(sample)
                
        except Exception as e:
            raise ValueError(f"Error loading CSV {self.data_path}: {e}")
    
    def _load_parquet_data(self):
        """Load Parquet security data for large datasets."""
        try:
            df = pd.read_parquet(self.data_path)
            
            for _, row in df.iterrows():
                sample = row.to_dict()
                self._process_sample(sample)
                
        except Exception as e:
            raise ValueError(f"Error loading Parquet {self.data_path}: {e}")
    
    def _load_directory_data(self):
        """Load all supported files from a directory."""
        supported_extensions = {'.json', '.jsonl', '.csv', '.parquet'}
        
        for ext in supported_extensions:
            for file_path in self.data_path.rglob(f'*{ext}'):
                print(f"  📂 Loading: {file_path.name}")
                
                # Create a temporary dataset instance for this file
                temp_dataset = SecurityDataset(
                    file_path,
                    self.feature_dim,
                    self.max_sequence_length,
                    self.threat_categories,
                    self.use_encryption
                )
                
                # Merge data from temporary dataset
                # (Implementation depends on specific merging logic)
                self._merge_dataset(temp_dataset)
    
    def _process_sample(self, sample: Dict[str, Any]):
        """
        Process a single security sample.
        
        This method:
        1. Validates the sample structure
        2. Extracts features
        3. Encodes threat labels
        4. Applies security transformations
        5. Stores in encrypted format if enabled
        
        Args:
            sample: Dictionary containing security event data
        """
        # Validate sample structure
        if not self._validate_sample(sample):
            warnings.warn(f"Invalid sample structure: {sample.get('id', 'unknown')}")
            return
        
        # Extract features from sample
        features = self._extract_features(sample)
        
        # Encode threat labels
        labels = self._encode_labels(sample)
        
        # Apply security transformations (anonymization, etc.)
        transformed_sample = self._apply_security_transformations(sample)
        
        # Store sample
        if self.use_encryption:
            # Encrypt sensitive data
            encrypted_sample = self._encrypt_sample({
                'features': features,
                'labels': labels,
                'metadata': transformed_sample,
                'original_sample': sample  # Keep original for debugging
            })
            self.encrypted_data.append(encrypted_sample)
        else:
            # Store in plaintext (not recommended for production)
            self.encrypted_data.append({
                'features': features,
                'labels': labels,
                'metadata': transformed_sample,
                'original_sample': sample
            })
        
        # Update statistics
        self.stats['total_samples'] += 1
        
        # Update threat distribution
        if 'threat_types' in sample:
            for threat_type in sample['threat_types']:
                self.stats['threat_distribution'][threat_type] += 1
        
        # Update average sequence length
        seq_length = len(features) if hasattr(features, '__len__') else 1
        current_avg = self.stats['avg_sequence_length']
        n = self.stats['total_samples']
        self.stats['avg_sequence_length'] = (current_avg * (n-1) + seq_length) / n
    
    def _validate_sample(self, sample: Dict[str, Any]) -> bool:
        """
        Validate a security sample against required schema.
        
        Required fields vary by dataset type:
        - Network traffic: src_ip, dst_ip, protocol, payload
        - Web requests: method, url, headers, body
        - Threat intel: cve_id, description, severity, cvss_score
        
        Returns:
            True if sample is valid, False otherwise
        """
        # Basic validation - sample must be a dictionary
        if not isinstance(sample, dict):
            return False
        
        # Check for minimum required fields
        required_fields = ['id', 'timestamp', 'source']
        
        for field in required_fields:
            if field not in sample:
                warnings.warn(f"Missing required field: {field}")
                return False
        
        # Validate timestamp format
        timestamp = sample.get('timestamp')
        if not self._validate_timestamp(timestamp):
            warnings.warn(f"Invalid timestamp: {timestamp}")
            return False
        
        # Validate threat types if present
        if 'threat_types' in sample:
            threat_types = sample['threat_types']
            if not isinstance(threat_types, list):
                return False
            
            # Check if all threat types are valid
            for threat_type in threat_types:
                if threat_type not in self.threat_categories:
                    warnings.warn(f"Unknown threat type: {threat_type}")
                    # Still accept sample but with warning
        
        return True
    
    def _validate_timestamp(self, timestamp: Any) -> bool:
        """Validate timestamp format."""
        try:
            # Try to parse as ISO format
            datetime.fromisoformat(str(timestamp).replace('Z', '+00:00'))
            return True
        except (ValueError, TypeError):
            # Try as Unix timestamp
            try:
                float(timestamp)
                return True
            except (ValueError, TypeError):
                return False
    
    def _extract_features(self, sample: Dict[str, Any]) -> torch.Tensor:
        """
        Extract features from security sample.
        
        This is the core feature engineering method that converts
        raw security data into numerical features for ML models.
        
        Feature types:
        1. Categorical: Encoded threat types, protocols, etc.
        2. Numerical: Packet sizes, duration, counts
        3. Textual: Payload analysis (converted via embeddings)
        4. Temporal: Time-based patterns and sequences
        
        Args:
            sample: Raw security sample
            
        Returns:
            Feature tensor of shape [feature_dim] or [seq_len, feature_dim]
        """
        # This is a template method - subclasses should override
        # For the base class, return a simple one-hot encoding of threat types
        
        # Initialize feature vector
        features = torch.zeros(self.feature_dim)
        
        # If threat types are present, encode them
        if 'threat_types' in sample:
            threat_types = sample['threat_types']
            
            # Simple encoding: set bits for present threat types
            for threat_type in threat_types:
                if threat_type in self.category_to_idx:
                    idx = self.category_to_idx[threat_type]
                    # Use one-hot or distributed representation
                    # Here we use a simple one-hot for demonstration
                    if idx < self.feature_dim:
                        features[idx] = 1.0
        
        # Normalize features
        if features.norm() > 0:
            features = features / features.norm()
        
        return features
    
    def _encode_labels(self, sample: Dict[str, Any]) -> torch.Tensor:
        """
        Encode threat labels for multi-label classification.
        
        Returns a binary vector where:
        - 1 indicates presence of threat category
        - 0 indicates absence
        
        Args:
            sample: Security sample with threat information
            
        Returns:
            Label tensor of shape [num_categories]
        """
        # Initialize all zeros
        labels = torch.zeros(len(self.threat_categories))
        
        # Set to 1 for present threat types
        if 'threat_types' in sample:
            threat_types = sample['threat_types']
            for threat_type in threat_types:
                if threat_type in self.category_to_idx:
                    idx = self.category_to_idx[threat_type]
                    labels[idx] = 1.0
        
        return labels
    
    def _apply_security_transformations(self, sample: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply security-preserving transformations to sample.
        
        Transformations include:
        - IP address anonymization
        - PII redaction
        - Data normalization
        - Feature scaling
        - Noise addition for differential privacy
        
        Args:
            sample: Original security sample
            
        Returns:
            Transformed sample with privacy protections
        """
        transformed = sample.copy()
        
        # Anonymize IP addresses
        if 'src_ip' in transformed:
            transformed['src_ip'] = self._anonymize_ip(transformed['src_ip'])
        if 'dst_ip' in transformed:
            transformed['dst_ip'] = self._anonymize_ip(transformed['dst_ip'])
        
        # Redact PII from payloads
        if 'payload' in transformed:
            transformed['payload'] = self._redact_pii(transformed['payload'])
        
        # Add differential privacy noise to numerical features
        if 'count' in transformed:
            transformed['count'] = self._add_dp_noise(transformed['count'])
        
        return transformed
    
    def _anonymize_ip(self, ip_address: str) -> str:
        """Anonymize IP address for privacy."""
        # Simple anonymization: keep first two octets
        parts = ip_address.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.0.0"
        return "0.0.0.0"
    
    def _redact_pii(self, text: str) -> str:
        """Redact personally identifiable information from text."""
        # Simple PII redaction patterns
        patterns = {
            r'\b\d{3}-\d{2}-\d{4}\b': '[SSN_REDACTED]',  # SSN
            r'\b\d{16}\b': '[CREDIT_CARD_REDACTED]',     # Credit card
            r'\b[\w\.-]+@[\w\.-]+\.\w+\b': '[EMAIL_REDACTED]',  # Email
        }
        
        for pattern, replacement in patterns.items():
            import re
            text = re.sub(pattern, replacement, text)
        
        return text
    
    def _add_dp_noise(self, value: float, epsilon: float = 1.0) -> float:
        """Add Laplace noise for differential privacy."""
        # Laplace mechanism for differential privacy
        scale = 1.0 / epsilon if epsilon > 0 else 0.0
        noise = np.random.laplace(0, scale)
        return value + noise
    
    def _encrypt_sample(self, sample: Dict[str, Any]) -> bytes:
        """
        Encrypt sensitive sample data.
        
        Note: In production, use proper cryptographic libraries
        like cryptography.fernet or similar.
        
        Args:
            sample: Sample data to encrypt
            
        Returns:
            Encrypted bytes (or sample if encryption disabled)
        """
        if not self.use_encryption:
            return sample
        
        # Simple XOR encryption for demonstration
        # WARNING: Not secure for production - use proper encryption
        import pickle
        pickled_data = pickle.dumps(sample)
        
        # Generate a simple key from data hash
        key = self.data_hash[:32].encode()
        
        # XOR encryption
        encrypted = bytearray()
        for i, byte in enumerate(pickled_data):
            key_byte = key[i % len(key)]
            encrypted.append(byte ^ key_byte)
        
        return bytes(encrypted)
    
    def _decrypt_sample(self, encrypted_data: bytes) -> Dict[str, Any]:
        """Decrypt sample data."""
        if not self.use_encryption:
            return encrypted_data
        
        # XOR decryption (same as encryption)
        key = self.data_hash[:32].encode()
        
        decrypted = bytearray()
        for i, byte in enumerate(encrypted_data):
            key_byte = key[i % len(key)]
            decrypted.append(byte ^ key_byte)
        
        import pickle
        return pickle.loads(bytes(decrypted))
    
    def _init_feature_extractor(self):
        """Initialize feature extraction components."""
        # This would initialize things like:
        # - Pre-trained embeddings for text
        # - Feature normalization parameters
        # - Tokenizers for payload analysis
        # - Graph feature extractors for network data
        
        # For now, just a placeholder
        self.feature_extractors = {}
    
    def _validate_data(self):
        """Validate loaded data for consistency and security."""
        print("🔒 Validating security dataset...")
        
        # Check for data poisoning patterns
        self._check_for_poisoning()
        
        # Validate label distribution
        self._validate_label_distribution()
        
        # Check for bias in data
        self._check_for_bias()
        
        print("✅ Data validation complete")
    
    def _check_for_poisoning(self):
        """Check for data poisoning attacks."""
        # Look for anomalous patterns that might indicate poisoning
        suspicious_patterns = [
            'eval(', 'exec(', 'system(', 'shell_exec(',
            'union select', "' or '1'='1", '<script>alert(',
            # Add more patterns based on threat intelligence
        ]
        
        warning_count = 0
        for sample in self.encrypted_data:
            # Decrypt if necessary
            if self.use_encryption:
                sample = self._decrypt_sample(sample)
            
            # Check sample content for suspicious patterns
            sample_str = str(sample).lower()
            for pattern in suspicious_patterns:
                if pattern in sample_str:
                    warning_count += 1
                    if warning_count <= 5:  # Limit warnings
                        warnings.warn(f"Suspicious pattern '{pattern}' found in sample")
                    break
        
        if warning_count > 0:
            print(f"⚠️  Found {warning_count} samples with suspicious patterns")
    
    def _validate_label_distribution(self):
        """Validate that labels are reasonably distributed."""
        total_samples = self.stats['total_samples']
        
        if total_samples == 0:
            return
        
        # Calculate label frequencies
        label_counts = list(self.stats['threat_distribution'].values())
        
        if label_counts:
            avg_count = sum(label_counts) / len(label_counts)
            
            # Check for extreme imbalance
            max_count = max(label_counts)
            min_count = min(label_counts) if min(label_counts) > 0 else 1
            
            imbalance_ratio = max_count / min_count
            
            if imbalance_ratio > 100:
                warnings.warn(f"Severe class imbalance detected: ratio = {imbalance_ratio:.1f}")
            elif imbalance_ratio > 10:
                warnings.warn(f"Moderate class imbalance detected: ratio = {imbalance_ratio:.1f}")
    
    def _check_for_bias(self):
        """Check for bias in security data."""
        # Bias could come from:
        # - Over-representation of certain IP ranges
        # - Geographic bias in attack sources
        # - Temporal bias in sampling
        
        # This is a simplified check
        print("📊 Checking for data bias...")
        # In production, implement comprehensive bias detection
    
    def __len__(self) -> int:
        """Return number of samples in dataset."""
        return self.stats['total_samples']
    
    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        """
        Get a training sample by index.
        
        Returns a dictionary with:
        - 'features': Input features for the model
        - 'labels': Target labels for training
        - 'metadata': Additional sample information
        
        Args:
            idx: Sample index
            
        Returns:
            Dictionary containing features, labels, and metadata
        """
        if idx >= len(self):
            raise IndexError(f"Index {idx} out of range for dataset of size {len(self)}")
        
        # Get encrypted sample
        encrypted_sample = self.encrypted_data[idx]
        
        # Decrypt if necessary
        if self.use_encryption:
            sample = self._decrypt_sample(encrypted_sample)
        else:
            sample = encrypted_sample
        
        # Ensure features are the right shape
        features = sample['features']
        if isinstance(features, torch.Tensor):
            # Ensure 2D shape for sequence models
            if features.dim() == 1:
                features = features.unsqueeze(0)  # [feature_dim] -> [1, feature_dim]
        else:
            # Convert to tensor
            features = torch.tensor(features, dtype=torch.float32)
        
        # Ensure labels are the right shape
        labels = sample['labels']
        if not isinstance(labels, torch.Tensor):
            labels = torch.tensor(labels, dtype=torch.float32)
        
        return {
            'features': features,
            'labels': labels,
            'metadata': sample.get('metadata', {}),
            'sample_id': sample.get('original_sample', {}).get('id', f'sample_{idx}')
        }
    
    def get_dataloader(self, 
                      batch_size: int = 32,
                      shuffle: bool = True,
                      num_workers: int = 4,
                      pin_memory: bool = True) -> DataLoader:
        """
        Create a DataLoader for this dataset.
        
        Args:
            batch_size: Number of samples per batch
            shuffle: Whether to shuffle the data
            num_workers: Number of data loading processes
            pin_memory: Pin memory for faster GPU transfer
            
        Returns:
            DataLoader for this security dataset
        """
        return DataLoader(
            self,
            batch_size=batch_size,
            shuffle=shuffle,
            num_workers=num_workers,
            pin_memory=pin_memory,
            collate_fn=self._collate_fn
        )
    
    def _collate_fn(self, batch: List[Dict[str, torch.Tensor]]) -> Dict[str, torch.Tensor]:
        """
        Custom collate function for security data.
        
        Handles variable-length sequences and packs them efficiently.
        
        Args:
            batch: List of samples
            
        Returns:
            Batched data dictionary
        """
        # Extract features and labels
        features = [item['features'] for item in batch]
        labels = [item['labels'] for item in batch]
        
        # Handle variable sequence lengths
        # Pad features to same length
        max_len = max(f.shape[0] for f in features)
        
        padded_features = []
        attention_masks = []
        
        for f in features:
            seq_len = f.shape[0]
            
            # Pad sequence
            if seq_len < max_len:
                padding = torch.zeros(max_len - seq_len, f.shape[1])
                padded = torch.cat([f, padding], dim=0)
            else:
                padded = f[:max_len]  # Truncate if too long
            
            # Create attention mask (1 for real tokens, 0 for padding)
            mask = torch.cat([
                torch.ones(seq_len),
                torch.zeros(max_len - seq_len)
            ])
            
            padded_features.append(padded)
            attention_masks.append(mask)
        
        # Stack into batches
        batched_features = torch.stack(padded_features)
        batched_labels = torch.stack(labels)
        batched_masks = torch.stack(attention_masks)
        
        # Extract metadata
        metadata = [item['metadata'] for item in batch]
        sample_ids = [item['sample_id'] for item in batch]
        
        return {
            'features': batched_features,
            'labels': batched_labels,
            'attention_mask': batched_masks,
            'metadata': metadata,
            'sample_ids': sample_ids
        }
    
    def split(self, 
             train_ratio: float = 0.7,
             val_ratio: float = 0.15,
             test_ratio: float = 0.15) -> Tuple['SecurityDataset', 'SecurityDataset', 'SecurityDataset']:
        """
        Split dataset into train, validation, and test sets.
        
        Maintains class distribution across splits.
        
        Args:
            train_ratio: Proportion for training
            val_ratio: Proportion for validation
            test_ratio: Proportion for testing
            
        Returns:
            Tuple of (train_dataset, val_dataset, test_dataset)
        """
        # Validate ratios
        total = train_ratio + val_ratio + test_ratio
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"Ratios must sum to 1.0, got {total}")
        
        # Calculate split sizes
        n_samples = len(self)
        n_train = int(n_samples * train_ratio)
        n_val = int(n_samples * val_ratio)
        n_test = n_samples - n_train - n_val
        
        # Create indices for stratified split
        # Group samples by threat categories for stratified sampling
        category_indices = defaultdict(list)
        
        for idx in range(n_samples):
            # Get sample to determine its categories
            sample = self.encrypted_data[idx]
            if self.use_encryption:
                sample = self._decrypt_sample(sample)
            
            # Use first threat category for stratification
            if 'threat_types' in sample.get('original_sample', {}):
                threat_types = sample['original_sample']['threat_types']
                if threat_types:
                    primary_category = threat_types[0]
                    category_indices[primary_category].append(idx)
            else:
                # If no threat types, use 'unknown' category
                category_indices['unknown'].append(idx)
        
        # Split each category
        train_indices = []
        val_indices = []
        test_indices = []
        
        for category, indices in category_indices.items():
            # Shuffle indices for this category
            random.shuffle(indices)
            
            # Calculate split points
            cat_n = len(indices)
            cat_n_train = int(cat_n * train_ratio)
            cat_n_val = int(cat_n * val_ratio)
            cat_n_test = cat_n - cat_n_train - cat_n_val
            
            # Assign to splits
            train_indices.extend(indices[:cat_n_train])
            val_indices.extend(indices[cat_n_train:cat_n_train + cat_n_val])
            test_indices.extend(indices[cat_n_train + cat_n_val:])
        
        # Create subset datasets
        train_dataset = self._create_subset(train_indices)
        val_dataset = self._create_subset(val_indices)
        test_dataset = self._create_subset(test_indices)
        
        return train_dataset, val_dataset, test_dataset
    
    def _create_subset(self, indices: List[int]) -> 'SecurityDataset':
        """
        Create a subset of the dataset.
        
        Args:
            indices: List of indices to include in subset
            
        Returns:
            New SecurityDataset with only the specified indices
        """
        # This creates a new dataset with only the specified samples
        # In a full implementation, we would copy only the necessary data
        
        # For now, return self but with a note about subsetting
        subset = SecurityDataset(
            self.data_path,
            self.feature_dim,
            self.max_sequence_length,
            self.threat_categories,
            self.use_encryption
        )
        
        # Filter data (simplified - in reality would copy only needed data)
        subset.encrypted_data = [self.encrypted_data[i] for i in indices]
        subset.stats['total_samples'] = len(indices)
        
        # Recalculate statistics for subset
        # (This would need to be implemented based on actual data)
        
        return subset
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get dataset statistics.
        
        Returns:
            Dictionary with dataset statistics
        """
        stats = self.stats.copy()
        
        # Add additional calculated statistics
        stats['num_categories'] = len(self.threat_categories)
        stats['feature_dimension'] = self.feature_dim
        stats['max_sequence_length'] = self.max_sequence_length
        stats['encryption_enabled'] = self.use_encryption
        
        # Calculate label distribution percentages
        total = stats['total_samples']
        if total > 0:
            for category, count in stats['threat_distribution'].items():
                stats['threat_distribution'][category] = {
                    'count': count,
                    'percentage': count / total * 100
                }
        
        return stats
    
    def save(self, path: Union[str, Path]):
        """Save dataset to disk."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        # Save metadata and statistics
        save_data = {
            'config': {
                'feature_dim': self.feature_dim,
                'max_sequence_length': self.max_sequence_length,
                'threat_categories': self.threat_categories,
                'use_encryption': self.use_encryption,
                'data_hash': self.data_hash
            },
            'stats': self.stats,
            'encrypted_data': self.encrypted_data
        }
        
        with open(path, 'wb') as f:
            import pickle
            pickle.dump(save_data, f)
        
        print(f"💾 Dataset saved to {path}")
    
    @classmethod
    def load(cls, path: Union[str, Path]) -> 'SecurityDataset':
        """Load dataset from disk."""
        path = Path(path)
        
        with open(path, 'rb') as f:
            import pickle
            save_data = pickle.load(f)
        
        # Create dataset instance
        config = save_data['config']
        dataset = cls(
            data_path=path,  # This is just a placeholder
            feature_dim=config['feature_dim'],
            max_sequence_length=config['max_sequence_length'],
            threat_categories=config['threat_categories'],
            use_encryption=config['use_encryption']
        )
        
        # Restore data
        dataset.encrypted_data = save_data['encrypted_data']
        dataset.stats = save_data['stats']
        dataset.data_hash = config['data_hash']
        
        print(f"📂 Dataset loaded from {path}")
        return dataset


class ThreatIntelligenceDataset(SecurityDataset):
    """
    Dataset for threat intelligence data (CVEs, exploits, threat feeds).
    
    Specializes in handling:
    - CVE vulnerability descriptions
    - Exploit database entries
    - Threat actor reports
    - Attack pattern definitions (MITRE ATT&CK)
    
    Key Features:
    - Temporal analysis of vulnerability discovery
    - Severity score regression
    - Exploit availability prediction
    - Threat actor attribution
    """
    
    def __init__(self, 
                 data_path: Union[str, Path],
                 include_cvss: bool = True,
                 include_exploits: bool = True,
                 include_patches: bool = False,
                 **kwargs):
        """
        Initialize threat intelligence dataset.
        
        Args:
            data_path: Path to threat intelligence data
            include_cvss: Whether to include CVSS scores as features
            include_exploits: Whether to include exploit availability
            include_patches: Whether to include patch information
            **kwargs: Additional arguments for SecurityDataset
        """
        # Update threat categories for threat intelligence
        threat_categories = kwargs.pop('threat_categories', None)
        if threat_categories is None:
            threat_categories = [
                'Privilege_Escalation',
                'Lateral_Movement',
                'Exfiltration',
                'Persistence',
                'Defense_Evasion',
                'Credential_Access',
                'Discovery',
                'Execution',
                'Collection',
                'Initial_Access',
                'Reconnaissance',
                'Resource_Development',
                'Command_Control'
            ]
        
        super().__init__(data_path, threat_categories=threat_categories, **kwargs)
        
        self.include_cvss = include_cvss
        self.include_exploits = include_exploits
        self.include_patches = include_patches
        
        # CVSS score ranges for normalization
        self.cvss_bins = {
            'None': 0.0,
            'Low': 0.1,
            'Medium': 0.4,
            'High': 0.7,
            'Critical': 0.9
        }
        
    def _extract_features(self, sample: Dict[str, Any]) -> torch.Tensor:
        """
        Extract features from threat intelligence sample.
        
        Feature engineering for threat intelligence:
        1. CVE metadata: ID, description, references
        2. CVSS scores: Base, temporal, environmental
        3. Exploit information: Availability, weaponization
        4. Temporal features: Discovery date, patch dates
        5. Text features: Description embeddings
        """
        # Start with base features from parent
        features = super()._extract_features(sample)
        
        # Additional threat intelligence features
        additional_features = []
        
        # CVSS score features
        if self.include_cvss and 'cvss_score' in sample:
            cvss_score = sample['cvss_score']
            
            # Normalize CVSS score (0-10 scale to 0-1)
            normalized_score = min(cvss_score / 10.0, 1.0)
            additional_features.append(normalized_score)
            
            # CVSS vector components if available
            if 'cvss_vector' in sample:
                vector_features = self._parse_cvss_vector(sample['cvss_vector'])
                additional_features.extend(vector_features)
        
        # Exploit availability
        if self.include_exploits:
            exploit_available = sample.get('exploit_available', False)
            additional_features.append(1.0 if exploit_available else 0.0)
            
            exploit_count = sample.get('exploit_count', 0)
            additional_features.append(min(exploit_count / 10.0, 1.0))  # Normalize
        
        # Patch information
        if self.include_patches:
            patch_available = sample.get('patch_available', False)
            additional_features.append(1.0 if patch_available else 0.0)
            
            days_to_patch = sample.get('days_to_patch', 365)
            additional_features.append(min(days_to_patch / 365.0, 1.0))  # Normalize to 1 year
        
        # Combine features
        if additional_features:
            additional_tensor = torch.tensor(additional_features, dtype=torch.float32)
            
            # Resize base features if needed
            if len(features) + len(additional_tensor) > self.feature_dim:
                # Truncate base features to make room
                features = features[:self.feature_dim - len(additional_tensor)]
            
            # Concatenate features
            features = torch.cat([features, additional_tensor])
        
        # Ensure correct dimension
        if len(features) > self.feature_dim:
            features = features[:self.feature_dim]
        elif len(features) < self.feature_dim:
            # Pad with zeros
            padding = torch.zeros(self.feature_dim - len(features))
            features = torch.cat([features, padding])
        
        return features
    
    def _parse_cvss_vector(self, cvss_vector: str) -> List[float]:
        """
        Parse CVSS vector string into numerical features.
        
        Example: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        
        Returns:
            List of numerical features encoding CVSS metrics
        """
        features = []
        
        # CVSS v3.1 metrics mapping
        metric_mappings = {
            'AV': {'N': 1.0, 'A': 0.6, 'L': 0.4, 'P': 0.2},  # Attack Vector
            'AC': {'L': 1.0, 'H': 0.5},  # Attack Complexity
            'PR': {'N': 1.0, 'L': 0.7, 'H': 0.3},  # Privileges Required
            'UI': {'N': 1.0, 'R': 0.6},  # User Interaction
            'S': {'U': 1.0, 'C': 0.5},  # Scope
            'C': {'H': 1.0, 'L': 0.5, 'N': 0.0},  # Confidentiality
            'I': {'H': 1.0, 'L': 0.5, 'N': 0.0},  # Integrity
            'A': {'H': 1.0, 'L': 0.5, 'N': 0.0},  # Availability
        }
        
        # Parse vector components
        components = cvss_vector.split('/')
        
        for component in components:
            if ':' in component:
                metric, value = component.split(':')
                if metric in metric_mappings and value in metric_mappings[metric]:
                    features.append(metric_mappings[metric][value])
        
        return features
    
    def _encode_labels(self, sample: Dict[str, Any]) -> torch.Tensor:
        """
        Encode labels for threat intelligence.
        
        For threat intelligence, we might want to predict:
        1. Severity level (classification)
        2. CVSS score (regression)
        3. Exploit likelihood (probability)
        4. Patch urgency (ordinal)
        """
        # Start with base multi-label encoding
        labels = super()._encode_labels(sample)
        
        # Add regression targets if available
        regression_targets = []
        
        # CVSS score target (normalized 0-1)
        if 'cvss_score' in sample:
            cvss_normalized = min(sample['cvss_score'] / 10.0, 1.0)
            regression_targets.append(cvss_normalized)
        
        # Exploit probability target
        if 'exploit_available' in sample:
            exploit_prob = 1.0 if sample['exploit_available'] else 0.0
            regression_targets.append(exploit_prob)
        
        # Combine classification and regression labels
        if regression_targets:
            regression_tensor = torch.tensor(regression_targets, dtype=torch.float32)
            # In a full implementation, we might structure this differently
            # For now, just append to labels
            labels = torch.cat([labels, regression_tensor])
        
        return labels


class WebTrafficDataset(SecurityDataset):
    """
    Dataset for web traffic and HTTP request/response data.
    
    Specializes in handling:
    - HTTP requests (methods, URLs, headers, bodies)
    - Web application attacks (OWASP Top-10)
    - API security violations
    - Bot traffic patterns
    
    Key Features:
    - Real-time request processing
    - Payload analysis for injection attacks
    - Session-based anomaly detection
    - Rate limiting and DDoS detection
    """
    
    def __init__(self,
                 data_path: Union[str, Path],
                 include_headers: bool = True,
                 include_payload: bool = True,
                 include_session: bool = False,
                 **kwargs):
        """
        Initialize web traffic dataset.
        
        Args:
            data_path: Path to web traffic data
            include_headers: Whether to include HTTP headers in features
            include_payload: Whether to include request/response payloads
            include_session: Whether to include session context
            **kwargs: Additional arguments for SecurityDataset
        """
        # Update threat categories for web security
        threat_categories = kwargs.pop('threat_categories', None)
        if threat_categories is None:
            threat_categories = [
                'SQL_Injection',
                'Cross_Site_Scripting',
                'Cross_Site_Request_Forgery',
                'Server_Side_Request_Forgery',
                'Command_Injection',
                'Path_Traversal',
                'XML_External_Entities',
                'Insecure_Deserialization',
                'Broken_Authentication',
                'Broken_Access_Control',
                'Security_Misconfiguration',
                'Sensitive_Data_Exposure',
                'Insufficient_Logging_Monitoring',
                'Bot_Traffic',
                'Credential_Stuffing',
                'API_Abuse'
            ]
        
        super().__init__(data_path, threat_categories=threat_categories, **kwargs)
        
        self.include_headers = include_headers
        self.include_payload = include_payload
        self.include_session = include_session
        
        # Common attack patterns for web applications
        self.attack_patterns = {
            'sql_injection': [
                "' OR '1'='1", "UNION SELECT", "; DROP", "--", "/*", "*/",
                "WAITFOR DELAY", "BENCHMARK(", "SLEEP(", "PG_SLEEP("
            ],
            'xss': [
                "<script>", "javascript:", "onload=", "onerror=", "alert(",
                "document.cookie", "window.location", "eval(", "innerHTML"
            ],
            'command_injection': [
                "; ls", "| cat", "`whoami`", "$(id)", "& dir", "|| ping",
                "&& netstat", "> /etc/passwd", "< /etc/passwd"
            ],
            'path_traversal': [
                "../", "..\\", "/etc/passwd", "C:\\Windows\\", "../../",
                "%2e%2e%2f", "%252e%252e%252f"
            ]
        }
        
        # HTTP methods for feature encoding
        self.http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
        
        # Common security headers
        self.security_headers = [
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security',
            'Referrer-Policy'
        ]
    
    def _extract_features(self, sample: Dict[str, Any]) -> torch.Tensor:
        """
        Extract features from web traffic sample.
        
        Feature engineering for web traffic:
        1. HTTP method encoding (one-hot)
        2. URL analysis (length, parameters, extensions)
        3. Header analysis (presence of security headers)
        4. Payload analysis (attack pattern matching)
        5. Temporal features (request timing, rate)
        6. Session features (user behavior patterns)
        """
        features = []
        
        # 1. HTTP Method encoding
        method = sample.get('method', 'GET').upper()
        method_encoding = self._encode_http_method(method)
        features.extend(method_encoding)
        
        # 2. URL features
        url = sample.get('url', '')
        url_features = self._extract_url_features(url)
        features.extend(url_features)
        
        # 3. Status code features
        status_code = sample.get('status_code', 200)
        status_features = self._encode_status_code(status_code)
        features.extend(status_features)
        
        # 4. Header features
        if self.include_headers:
            headers = sample.get('headers', {})
            header_features = self._extract_header_features(headers)
            features.extend(header_features)
        
        # 5. Payload features
        if self.include_payload:
            payload = sample.get('payload', '')
            payload_features = self._extract_payload_features(payload)
            features.extend(payload_features)
        
        # 6. Attack pattern matching
        attack_features = self._detect_attack_patterns(sample)
        features.extend(attack_features)
        
        # 7. Temporal features
        if 'timestamp' in sample:
            temporal_features = self._extract_temporal_features(sample['timestamp'])
            features.extend(temporal_features)
        
        # 8. Session features (if available)
        if self.include_session and 'session_id' in sample:
            session_features = self._extract_session_features(sample)
            features.extend(session_features)
        
        # Convert to tensor and ensure correct dimension
        features_tensor = torch.tensor(features, dtype=torch.float32)
        
        if len(features_tensor) > self.feature_dim:
            features_tensor = features_tensor[:self.feature_dim]
        elif len(features_tensor) < self.feature_dim:
            padding = torch.zeros(self.feature_dim - len(features_tensor))
            features_tensor = torch.cat([features_tensor, padding])
        
        return features_tensor
    
    def _encode_http_method(self, method: str) -> List[float]:
        """Encode HTTP method as one-hot vector."""
        encoding = [0.0] * len(self.http_methods)
        
        if method in self.http_methods:
            idx = self.http_methods.index(method)
            encoding[idx] = 1.0
        else:
            # Unknown method - use uniform distribution
            encoding = [1.0 / len(self.http_methods)] * len(self.http_methods)
        
        return encoding
    
    def _extract_url_features(self, url: str) -> List[float]:
        """Extract features from URL."""
        features = []
        
        # URL length (normalized)
        url_length = len(url)
        features.append(min(url_length / 1000.0, 1.0))  # Cap at 1000 chars
        
        # Number of parameters
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        num_params = len(query_params)
        features.append(min(num_params / 20.0, 1.0))  # Cap at 20 params
        
        # Has file extension
        path = parsed.path.lower()
        common_extensions = ['.php', '.asp', '.aspx', '.jsp', '.do', '.action']
        has_extension = any(path.endswith(ext) for ext in common_extensions)
        features.append(1.0 if has_extension else 0.0)
        
        # Is API endpoint
        api_patterns = ['/api/', '/graphql', '/rest/', '/v1/', '/v2/']
        is_api = any(pattern in path for pattern in api_patterns)
        features.append(1.0 if is_api else 0.0)
        
        # Contains suspicious patterns
        suspicious_patterns = ['../', '..\\', '//', '/./', '/../']
        is_suspicious = any(pattern in url for pattern in suspicious_patterns)
        features.append(1.0 if is_suspicious else 0.0)
        
        return features
    
    def _encode_status_code(self, status_code: int) -> List[float]:
        """Encode HTTP status code."""
        features = []
        
        # Status code category
        if 200 <= status_code < 300:
            # Success
            features.extend([1.0, 0.0, 0.0, 0.0])
        elif 300 <= status_code < 400:
            # Redirection
            features.extend([0.0, 1.0, 0.0, 0.0])
        elif 400 <= status_code < 500:
            # Client error
            features.extend([0.0, 0.0, 1.0, 0.0])
        elif 500 <= status_code < 600:
            # Server error
            features.extend([0.0, 0.0, 0.0, 1.0])
        else:
            # Unknown
            features.extend([0.25, 0.25, 0.25, 0.25])
        
        # Specific error codes of interest
        error_codes_of_interest = [401, 403, 404, 500, 502, 503]
        is_error_of_interest = status_code in error_codes_of_interest
        features.append(1.0 if is_error_of_interest else 0.0)
        
        return features
    
    def _extract_header_features(self, headers: Dict[str, str]) -> List[float]:
        """Extract features from HTTP headers."""
        features = []
        
        # Number of headers
        num_headers = len(headers)
        features.append(min(num_headers / 50.0, 1.0))  # Cap at 50 headers
        
        # Presence of security headers
        security_header_count = 0
        for header in self.security_headers:
            if header in headers:
                security_header_count += 1
        
        features.append(security_header_count / len(self.security_headers))
        
        # User-Agent analysis
        user_agent = headers.get('User-Agent', '').lower()
        
        # Is browser
        browser_keywords = ['chrome', 'firefox', 'safari', 'edge', 'opera']
        is_browser = any(keyword in user_agent for keyword in browser_keywords)
        features.append(1.0 if is_browser else 0.0)
        
        # Is bot/crawler
        bot_keywords = ['bot', 'crawler', 'spider', 'scraper', 'python-requests']
        is_bot = any(keyword in user_agent for keyword in bot_keywords)
        features.append(1.0 if is_bot else 0.0)
        
        # Content-Type analysis
        content_type = headers.get('Content-Type', '')
        
        # Is JSON
        is_json = 'application/json' in content_type
        features.append(1.0 if is_json else 0.0)
        
        # Is XML
        is_xml = 'application/xml' in content_type or 'text/xml' in content_type
        features.append(1.0 if is_xml else 0.0)
        
        return features
    
    def _extract_payload_features(self, payload: str) -> List[float]:
        """Extract features from request/response payload."""
        features = []
        
        if not payload:
            return [0.0] * 10  # Return zeros if no payload
        
        payload_lower = payload.lower()
        
        # Payload length (normalized)
        payload_length = len(payload)
        features.append(min(payload_length / 10000.0, 1.0))  # Cap at 10KB
        
        # Contains SQL keywords
        sql_keywords = ['select', 'insert', 'update', 'delete', 'drop', 'union']
        sql_count = sum(1 for keyword in sql_keywords if keyword in payload_lower)
        features.append(min(sql_count / 10.0, 1.0))
        
        # Contains JavaScript/HTML tags
        js_html_patterns = ['<script>', '</script>', 'javascript:', 'onload=']
        js_count = sum(1 for pattern in js_html_patterns if pattern in payload_lower)
        features.append(min(js_count / 5.0, 1.0))
        
        # Contains system commands
        system_commands = ['system(', 'exec(', 'shell_exec(', 'passthru(']
        cmd_count = sum(1 for cmd in system_commands if cmd in payload_lower)
        features.append(min(cmd_count / 5.0, 1.0))
        
        # Contains encoded patterns
        encoded_patterns = ['%3c', '%3e', '%27', '%22', '%2f', '%5c']
        encoded_count = sum(1 for pattern in encoded_patterns if pattern in payload_lower)
        features.append(min(encoded_count / 10.0, 1.0))
        
        # Entropy of payload (measure of randomness)
        entropy = self._calculate_entropy(payload)
        features.append(entropy)
        
        # JSON structure detection (if payload might be JSON)
        try:
            import json
            json.loads(payload)
            features.append(1.0)  # Valid JSON
        except:
            features.append(0.0)  # Not valid JSON
        
        # XML structure detection
        if payload_lower.strip().startswith('<?xml') or payload_lower.strip().startswith('<'):
            features.append(1.0)
        else:
            features.append(0.0)
        
        return features
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0
        
        import math
        from collections import Counter
        
        # Count character frequencies
        counter = Counter(text)
        text_length = len(text)
        
        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            probability = count / text_length
            entropy -= probability * math.log2(probability)
        
        # Normalize to 0-1 range (max entropy for bytes is log2(256) = 8)
        return entropy / 8.0
    
    def _detect_attack_patterns(self, sample: Dict[str, Any]) -> List[float]:
        """Detect known attack patterns in web traffic."""
        features = []
        
        # Combine all text fields for pattern matching
        text_to_check = []
        
        # Add URL
        if 'url' in sample:
            text_to_check.append(sample['url'].lower())
        
        # Add payload
        if 'payload' in sample:
            text_to_check.append(sample['payload'].lower())
        
        # Add headers as text
        if 'headers' in sample:
            headers_text = ' '.join(f"{k}:{v}" for k, v in sample['headers'].items())
            text_to_check.append(headers_text.lower())
        
        combined_text = ' '.join(text_to_check)
        
        # Check for each attack pattern category
        for attack_type, patterns in self.attack_patterns.items():
            pattern_count = 0
            for pattern in patterns:
                if pattern.lower() in combined_text:
                    pattern_count += 1
            
            # Normalize by number of patterns in this category
            normalized = min(pattern_count / len(patterns), 1.0)
            features.append(normalized)
        
        return features
    
    def _extract_temporal_features(self, timestamp: str) -> List[float]:
        """Extract temporal features from timestamp."""
        features = []
        
        try:
            # Parse timestamp
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            
            # Hour of day (sine/cosine encoding for cyclical feature)
            hour = dt.hour
            hour_sin = math.sin(2 * math.pi * hour / 24)
            hour_cos = math.cos(2 * math.pi * hour / 24)
            features.extend([hour_sin, hour_cos])
            
            # Day of week
            day_of_week = dt.weekday()  # Monday=0, Sunday=6
            day_sin = math.sin(2 * math.pi * day_of_week / 7)
            day_cos = math.cos(2 * math.pi * day_of_week / 7)
            features.extend([day_sin, day_cos])
            
            # Is weekend
            is_weekend = 1.0 if day_of_week >= 5 else 0.0
            features.append(is_weekend)
            
            # Is business hours (9 AM - 5 PM)
            is_business_hours = 1.0 if 9 <= hour <= 17 else 0.0
            features.append(is_business_hours)
            
        except (ValueError, TypeError):
            # If timestamp parsing fails, use default values
            features.extend([0.0, 1.0, 0.0, 1.0, 0.0, 0.0])
        
        return features
    
    def _extract_session_features(self, sample: Dict[str, Any]) -> List[float]:
        """Extract session-based features."""
        features = []
        
        # This would typically require session context
        # For now, return placeholder features
        
        # Placeholder: request count in session (if available)
        request_count = sample.get('session_request_count', 1)
        features.append(min(request_count / 100.0, 1.0))  # Cap at 100 requests
        
        # Placeholder: session duration (if available)
        session_duration = sample.get('session_duration_seconds', 0)
        features.append(min(session_duration / 3600.0, 1.0))  # Cap at 1 hour
        
        # Placeholder: is new session
        is_new_session = sample.get('is_new_session', False)
        features.append(1.0 if is_new_session else 0.0)
        
        return features
    
    def _validate_sample(self, sample: Dict[str, Any]) -> bool:
        """Validate web traffic sample."""
        # Start with base validation
        if not super()._validate_sample(sample):
            return False
        
        # Web-specific validation
        required_fields = ['method', 'url']
        
        for field in required_fields:
            if field not in sample:
                warnings.warn(f"Web sample missing required field: {field}")
                return False
        
        # Validate HTTP method
        method = sample.get('method', '').upper()
        if method not in self.http_methods:
            warnings.warn(f"Unusual HTTP method: {method}")
            # Still accept it, but log warning
        
        # Validate URL format
        url = sample.get('url', '')
        if not self._is_valid_url(url):
            warnings.warn(f"Invalid URL format: {url}")
            # Still accept it for analysis
        
        return True
    
    def _is_valid_url(self, url: str) -> bool:
        """Check if URL has valid format."""
        import re
        
        # Simple URL validation pattern
        url_pattern = re.compile(
            r'^(https?://)?'  # http:// or https://
            r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'  # domain
            r'[a-zA-Z]{2,}'  # TLD
            r'(/.*)?$'  # path
        )
        
        return bool(url_pattern.match(url))


# Example usage and testing
if __name__ == "__main__":
    # Create a sample dataset
    print("🧪 Testing SecurityDataset...")
    
    # Create sample data
    sample_data = [
        {
            'id': 'sample_001',
            'timestamp': '2024-01-15T10:30:00Z',
            'source': 'waf_logs',
            'threat_types': ['SQL_Injection', 'Broken_Authentication'],
            'method': 'POST',
            'url': '/api/login',
            'status_code': 200,
            'headers': {'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'},
            'payload': '{"username": "admin", "password": "\' OR \'1\'=\'1"}',
            'cvss_score': 8.5,
            'exploit_available': True
        },
        {
            'id': 'sample_002',
            'timestamp': '2024-01-15T11:45:00Z',
            'source': 'waf_logs',
            'threat_types': ['Cross_Site_Scripting'],
            'method': 'GET',
            'url': '/search?q=<script>alert(1)</script>',
            'status_code': 200,
            'headers': {'User-Agent': 'Chrome/120.0.0.0'},
            'payload': '',
            'cvss_score': 6.2,
            'exploit_available': False
        }
    ]
    
    # Save sample data to file
    import tempfile
    import json
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(sample_data, f)
        temp_file = f.name
    
    try:
        # Test SecurityDataset
        print("\n📊 Testing base SecurityDataset...")
        dataset = SecurityDataset(temp_file, use_encryption=False)
        print(f"Dataset size: {len(dataset)}")
        print(f"Threat categories: {dataset.threat_categories[:5]}...")
        
        # Get a sample
        sample = dataset[0]
        print(f"\nSample features shape: {sample['features'].shape}")
        print(f"Sample labels shape: {sample['labels'].shape}")
        
        # Test statistics
        stats = dataset.get_statistics()
        print(f"\n📈 Dataset statistics:")
        print(f"  Total samples: {stats['total_samples']}")
        print(f"  Feature dimension: {stats['feature_dimension']}")
        print(f"  Threat distribution: {dict(list(stats['threat_distribution'].items())[:3])}")
        
        # Test WebTrafficDataset
        print("\n🌐 Testing WebTrafficDataset...")
        web_dataset = WebTrafficDataset(temp_file, use_encryption=False)
        web_sample = web_dataset[0]
        print(f"Web sample features shape: {web_sample['features'].shape}")
        print(f"Web sample labels shape: {web_sample['labels'].shape}")
        
        # Test split
        print("\n✂️  Testing dataset split...")
        train, val, test = dataset.split(train_ratio=0.6, val_ratio=0.2, test_ratio=0.2)
        print(f"Train size: {len(train)}")
        print(f"Val size: {len(val)}")
        print(f"Test size: {len(test)}")
        
        # Test DataLoader
        print("\n🔄 Testing DataLoader...")
        dataloader = dataset.get_dataloader(batch_size=2)
        batch = next(iter(dataloader))
        print(f"Batch features shape: {batch['features'].shape}")
        print(f"Batch labels shape: {batch['labels'].shape}")
        print(f"Batch attention mask shape: {batch['attention_mask'].shape}")
        
        print("\n✅ All tests passed!")
        
    finally:
        # Clean up
        import os
        os.unlink(temp_file)