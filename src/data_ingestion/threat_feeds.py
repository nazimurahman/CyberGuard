"""
Threat Intelligence Feed Manager
===============================

This module manages multiple threat intelligence feeds including:
- Malware hash databases
- IP reputation feeds
- Domain blacklists
- Phishing URLs
- Exploit databases
- Security advisories

Features:
---------
1. Multi-feed management and aggregation
2. Feed validation and deduplication
3. Real-time feed updates
4. Feed prioritization and scoring
5. Historical data tracking
6. Feed health monitoring
7. Custom feed integration

Security Controls:
-----------------
- Feed source authentication
- Data integrity verification
- Rate limiting per feed
- Quarantine for suspicious data
- Audit logging for all operations

Usage Examples:
---------------
# Initialize feed manager
manager = ThreatFeedManager()

# Add a feed
manager.add_feed(
    name="MalwareHashRegistry",
    url="https://example.com/malware-hashes.csv",
    feed_type=FeedType.MALWARE_HASH,
    update_interval=3600
)

# Update all feeds
results = manager.update_all_feeds()

# Query threat intelligence
threats = manager.query(
    indicator="malware.exe",
    indicator_type=IndicatorType.FILE_HASH
)
"""

import asyncio
import aiohttp
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, field, asdict
import logging
from pathlib import Path
import json
import csv

# Local imports
from .secure_loader import SecureDataLoader, DataValidationError
from .hash_validator import HashValidator, HashAlgorithm
from .quarantine_pipeline import QuarantineManager
from ..utils.logging_utils import audit_log

# Custom exceptions
class ThreatFeedError(Exception):
    """Base exception for threat feed errors"""
    pass

class FeedConfigurationError(ThreatFeedError):
    """Raised when feed configuration is invalid"""
    pass

class FeedUpdateError(ThreatFeedError):
    """Raised when feed update fails"""
    pass

class IndicatorNotFound(ThreatFeedError):
    """Raised when indicator is not found in feeds"""
    pass

# Enums
class FeedType(Enum):
    """Types of threat intelligence feeds"""
    MALWARE_HASH = "malware_hash"          # MD5, SHA1, SHA256 hashes
    IP_REPUTATION = "ip_reputation"        # Malicious IP addresses
    DOMAIN_BLACKLIST = "domain_blacklist"  # Malicious domains
    PHISHING_URL = "phishing_url"          # Phishing URLs
    EXPLOIT_DB = "exploit_db"              # Exploit information
    SECURITY_ADVISORY = "security_advisory" # Security advisories
    VULNERABILITY = "vulnerability"        # Vulnerability information
    CUSTOM = "custom"                      # Custom/private feeds

class IndicatorType(Enum):
    """Types of threat indicators"""
    FILE_HASH = "file_hash"        # MD5, SHA1, SHA256
    IP_ADDRESS = "ip_address"      # IPv4/IPv6 addresses
    DOMAIN = "domain"              # Domain names
    URL = "url"                    # Full URLs
    EMAIL = "email"                # Email addresses
    CVE = "cve"                    # CVE identifiers
    USER_AGENT = "user_agent"      # Malicious user agents
    ASN = "asn"                    # Autonomous System Numbers
    CERTIFICATE = "certificate"    # SSL/TLS certificates
    CUSTOM = "custom"              # Custom indicators

class FeedFormat(Enum):
    """Supported feed formats"""
    CSV = "csv"
    JSON = "json"
    TXT = "txt"           # One indicator per line
    STIX = "stix"         # STIX format
    MISP = "misp"         # MISP format
    CUSTOM = "custom"

class ThreatSeverity(Enum):
    """Threat severity levels"""
    INFO = "info"         # Informational
    LOW = "low"           # Low risk
    MEDIUM = "medium"     # Medium risk
    HIGH = "high"         # High risk
    CRITICAL = "critical" # Critical risk

@dataclass
class ThreatIndicator:
    """
    Threat intelligence indicator
    
    Represents a single piece of threat intelligence
    with metadata, context, and scoring.
    """
    # Core identification
    indicator: str                    # The indicator value (hash, IP, domain, etc.)
    indicator_type: IndicatorType     # Type of indicator
    
    # Threat information
    threat_type: str                  # Type of threat (malware, phishing, etc.)
    severity: ThreatSeverity          # Threat severity
    confidence: float                 # Confidence score (0.0 to 1.0)
    
    # Metadata
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    
    # Context and references
    description: Optional[str] = None
    references: List[str] = field(default_factory=list)
    tags: Set[str] = field(default_factory=set)
    
    # Source information
    source: str = "unknown"
    source_reliability: float = 0.5  # Source reliability (0.0 to 1.0)
    
    # Technical details (type-specific)
    details: Dict[str, Any] = field(default_factory=dict)
    
    # Scoring and prioritization
    score: float = 0.0               # Calculated threat score
    false_positive: bool = False     # Marked as false positive
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        result = asdict(self)
        
        # Convert enums to strings
        result['indicator_type'] = self.indicator_type.value
        result['severity'] = self.severity.value
        result['threat_type'] = self.threat_type
        
        # Convert dates
        if self.first_seen:
            result['first_seen'] = self.first_seen.isoformat()
        if self.last_seen:
            result['last_seen'] = self.last_seen.isoformat()
        if self.expires_at:
            result['expires_at'] = self.expires_at.isoformat()
        
        # Convert set to list
        result['tags'] = list(self.tags)
        
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ThreatIndicator':
        """Create ThreatIndicator from dictionary"""
        # Convert string enums back to Enum objects
        data['indicator_type'] = IndicatorType(data['indicator_type'])
        data['severity'] = ThreatSeverity(data['severity'])
        
        # Convert dates
        if data.get('first_seen'):
            data['first_seen'] = datetime.fromisoformat(data['first_seen'])
        if data.get('last_seen'):
            data['last_seen'] = datetime.fromisoformat(data['last_seen'])
        if data.get('expires_at'):
            data['expires_at'] = datetime.fromisoformat(data['expires_at'])
        
        # Convert list to set
        if 'tags' in data:
            data['tags'] = set(data['tags'])
        
        return cls(**data)
    
    @property
    def is_active(self) -> bool:
        """Check if indicator is still active (not expired)"""
        if self.expires_at:
            return datetime.now() < self.expires_at
        return True
    
    @property
    def is_fresh(self) -> bool:
        """Check if indicator is fresh (seen recently)"""
        if self.last_seen:
            # Consider fresh if seen in last 30 days
            return (datetime.now() - self.last_seen) < timedelta(days=30)
        return True
    
    def calculate_score(self) -> float:
        """Calculate threat score based on various factors"""
        score = 0.0
        
        # Base score from severity
        severity_scores = {
            ThreatSeverity.INFO: 0.1,
            ThreatSeverity.LOW: 0.3,
            ThreatSeverity.MEDIUM: 0.6,
            ThreatSeverity.HIGH: 0.8,
            ThreatSeverity.CRITICAL: 1.0,
        }
        score += severity_scores.get(self.severity, 0.5)
        
        # Confidence multiplier
        score *= self.confidence
        
        # Source reliability multiplier
        score *= self.source_reliability
        
        # Freshness bonus (recent indicators are more relevant)
        if self.is_fresh:
            score *= 1.2  # 20% bonus for fresh indicators
        
        # Multiple references bonus
        if len(self.references) > 1:
            score *= 1.1  # 10% bonus for multiple references
        
        # Cap at 1.0
        return min(1.0, score)
    
    def update_seen(self):
        """Update last_seen timestamp"""
        now = datetime.now()
        self.last_seen = now
        
        # Set first_seen if not set
        if not self.first_seen:
            self.first_seen = now
    
    def add_tag(self, tag: str):
        """Add a tag to the indicator"""
        self.tags.add(tag.lower())
    
    def has_tag(self, tag: str) -> bool:
        """Check if indicator has a specific tag"""
        return tag.lower() in self.tags

@dataclass
class ThreatFeed:
    """
    Threat intelligence feed configuration
    
    Represents a single threat intelligence feed
    with configuration, metadata, and state.
    """
    # Basic configuration
    name: str
    url: str
    feed_type: FeedType
    format: FeedFormat = FeedFormat.CSV
    
    # Update configuration
    update_interval: int = 3600  # Seconds between updates
    enabled: bool = True
    priority: int = 5  # 1 (highest) to 10 (lowest)
    
    # Authentication (if required)
    auth_type: Optional[str] = None  # "basic", "api_key", "oauth"
    auth_config: Dict[str, str] = field(default_factory=dict)
    
    # Parsing configuration
    parser_config: Dict[str, Any] = field(default_factory=dict)
    
    # Validation
    expected_hash: Optional[str] = None  # Expected hash of feed data
    min_update_size: int = 100  # Minimum expected indicators per update
    
    # State tracking
    last_update: Optional[datetime] = None
    last_successful_update: Optional[datetime] = None
    update_count: int = 0
    error_count: int = 0
    indicators_count: int = 0
    
    # Performance metrics
    avg_update_time: float = 0.0
    success_rate: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        result = asdict(self)
        
        # Convert enums to strings
        result['feed_type'] = self.feed_type.value
        result['format'] = self.format.value
        
        # Convert dates
        if self.last_update:
            result['last_update'] = self.last_update.isoformat()
        if self.last_successful_update:
            result['last_successful_update'] = self.last_successful_update.isoformat()
        
        return result
    
    @property
    def is_due_for_update(self) -> bool:
        """Check if feed is due for update"""
        if not self.last_update:
            return True
        
        time_since_update = datetime.now() - self.last_update
        return time_since_update.total_seconds() >= self.update_interval
    
    @property
    def health_status(self) -> str:
        """Get feed health status"""
        if self.error_count > 10:
            return "unhealthy"
        elif self.success_rate < 0.5:
            return "degraded"
        elif not self.enabled:
            return "disabled"
        else:
            return "healthy"
    
    def record_update(self, success: bool, indicators_count: int, duration: float):
        """Record update statistics"""
        now = datetime.now()
        self.last_update = now
        
        if success:
            self.last_successful_update = now
            self.indicators_count = indicators_count
            self.update_count += 1
            
            # Update average update time (moving average)
            if self.avg_update_time == 0:
                self.avg_update_time = duration
            else:
                self.avg_update_time = (self.avg_update_time * 0.9) + (duration * 0.1)
        else:
            self.error_count += 1
        
        # Update success rate
        total_updates = self.update_count + self.error_count
        if total_updates > 0:
            self.success_rate = self.update_count / total_updates

class FeedParser:
    """
    Parser for different threat feed formats
    
    Supports multiple formats and can be extended
    with custom parsers for specific feeds.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.hash_validator = HashValidator()
        
        # Register parsers for different formats
        self.parsers = {
            FeedFormat.CSV: self._parse_csv,
            FeedFormat.JSON: self._parse_json,
            FeedFormat.TXT: self._parse_txt,
            FeedFormat.STIX: self._parse_stix,
            FeedFormat.MISP: self._parse_misp,
        }
    
    def parse(
        self,
        data: bytes,
        feed: ThreatFeed
    ) -> List[ThreatIndicator]:
        """
        Parse feed data based on feed format
        
        Args:
            data: Raw feed data
            feed: Feed configuration
            
        Returns:
            List of parsed threat indicators
            
        Raises:
            FeedUpdateError: If parsing fails
        """
        try:
            parser_func = self.parsers.get(feed.format)
            if not parser_func:
                raise FeedConfigurationError(
                    f"No parser available for format: {feed.format}"
                )
            
            indicators = parser_func(data, feed)
            
            # Apply feed-specific transformations
            indicators = self._apply_feed_transformations(indicators, feed)
            
            # Validate parsed indicators
            indicators = [i for i in indicators if self._validate_indicator(i)]
            
            self.logger.info(
                f"Parsed {len(indicators)} indicators from feed {feed.name}"
            )
            
            return indicators
            
        except Exception as e:
            raise FeedUpdateError(f"Failed to parse feed {feed.name}: {e}")
    
    def _parse_csv(self, data: bytes, feed: ThreatFeed) -> List[ThreatIndicator]:
        """Parse CSV format feed"""
        indicators = []
        
        try:
            csv_text = data.decode('utf-8')
            reader = csv.DictReader(csv_text.splitlines())
            
            # Get column mappings from parser config
            column_map = feed.parser_config.get('column_map', {})
            
            for row in reader:
                try:
                    indicator = self._parse_csv_row(row, column_map, feed)
                    if indicator:
                        indicators.append(indicator)
                except Exception as e:
                    self.logger.debug(f"Failed to parse CSV row: {e}")
                    continue
            
        except Exception as e:
            raise FeedUpdateError(f"CSV parsing failed: {e}")
        
        return indicators
    
    def _parse_csv_row(
        self,
        row: Dict[str, str],
        column_map: Dict[str, str],
        feed: ThreatFeed
    ) -> Optional[ThreatIndicator]:
        """Parse single CSV row"""
        # Map columns using configuration
        indicator_value = row.get(column_map.get('indicator', 'indicator'))
        if not indicator_value:
            return None
        
        # Determine indicator type
        indicator_type = self._detect_indicator_type(indicator_value, feed.feed_type)
        
        # Parse timestamps
        first_seen = None
        last_seen = None
        
        if 'first_seen' in column_map:
            first_seen_str = row.get(column_map['first_seen'])
            if first_seen_str:
                first_seen = self._parse_timestamp(first_seen_str)
        
        if 'last_seen' in column_map:
            last_seen_str = row.get(column_map['last_seen'])
            if last_seen_str:
                last_seen = self._parse_timestamp(last_seen_str)
        
        # Parse severity
        severity_str = row.get(column_map.get('severity', 'severity'), 'medium')
        severity = self._parse_severity(severity_str)
        
        # Parse confidence
        confidence_str = row.get(column_map.get('confidence', 'confidence'), '0.5')
        try:
            confidence = float(confidence_str)
        except ValueError:
            confidence = 0.5
        
        # Create indicator
        indicator = ThreatIndicator(
            indicator=indicator_value.strip(),
            indicator_type=indicator_type,
            threat_type=self._feed_type_to_threat_type(feed.feed_type),
            severity=severity,
            confidence=confidence,
            first_seen=first_seen,
            last_seen=last_seen,
            description=row.get(column_map.get('description', 'description')),
            source=feed.name,
            source_reliability=feed.priority / 10.0,  # Convert priority to reliability
        )
        
        # Add tags
        tags_str = row.get(column_map.get('tags', 'tags'))
        if tags_str:
            for tag in tags_str.split(','):
                indicator.add_tag(tag.strip())
        
        # Add references
        references_str = row.get(column_map.get('references', 'references'))
        if references_str:
            for ref in references_str.split(','):
                indicator.references.append(ref.strip())
        
        # Calculate score
        indicator.score = indicator.calculate_score()
        
        return indicator
    
    def _parse_json(self, data: bytes, feed: ThreatFeed) -> List[ThreatIndicator]:
        """Parse JSON format feed"""
        try:
            json_data = json.loads(data.decode('utf-8'))
            indicators = []
            
            # Check for common JSON structures
            if isinstance(json_data, list):
                # List of indicators
                for item in json_data:
                    indicator = self._parse_json_item(item, feed)
                    if indicator:
                        indicators.append(indicator)
            elif isinstance(json_data, dict):
                # Single indicator or structured feed
                if 'indicators' in json_data:
                    # Feed with indicators array
                    for item in json_data['indicators']:
                        indicator = self._parse_json_item(item, feed)
                        if indicator:
                            indicators.append(indicator)
                else:
                    # Single indicator
                    indicator = self._parse_json_item(json_data, feed)
                    if indicator:
                        indicators.append(indicator)
            
            return indicators
            
        except json.JSONDecodeError as e:
            raise FeedUpdateError(f"Invalid JSON in feed {feed.name}: {e}")
    
    def _parse_json_item(
        self,
        item: Dict[str, Any],
        feed: ThreatFeed
    ) -> Optional[ThreatIndicator]:
        """Parse single JSON item"""
        try:
            # Extract indicator value
            indicator_value = item.get('indicator')
            if not indicator_value:
                return None
            
            # Determine indicator type
            indicator_type_str = item.get('type')
            if indicator_type_str:
                try:
                    indicator_type = IndicatorType(indicator_type_str)
                except ValueError:
                    indicator_type = self._detect_indicator_type(indicator_value, feed.feed_type)
            else:
                indicator_type = self._detect_indicator_type(indicator_value, feed.feed_type)
            
            # Parse timestamps
            first_seen = self._parse_timestamp(item.get('first_seen'))
            last_seen = self._parse_timestamp(item.get('last_seen'))
            
            # Parse severity
            severity_str = item.get('severity', 'medium')
            severity = self._parse_severity(severity_str)
            
            # Parse confidence
            confidence = item.get('confidence', 0.5)
            if isinstance(confidence, str):
                try:
                    confidence = float(confidence)
                except ValueError:
                    confidence = 0.5
            
            # Create indicator
            indicator = ThreatIndicator(
                indicator=str(indicator_value),
                indicator_type=indicator_type,
                threat_type=self._feed_type_to_threat_type(feed.feed_type),
                severity=severity,
                confidence=confidence,
                first_seen=first_seen,
                last_seen=last_seen,
                description=item.get('description'),
                source=feed.name,
                source_reliability=feed.priority / 10.0,
                details=item.get('details', {})
            )
            
            # Add tags
            tags = item.get('tags', [])
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(',')]
            
            for tag in tags:
                indicator.add_tag(str(tag))
            
            # Add references
            references = item.get('references', [])
            if isinstance(references, str):
                references = [r.strip() for r in references.split(',')]
            
            indicator.references.extend(references)
            
            # Calculate score
            indicator.score = indicator.calculate_score()
            
            return indicator
            
        except Exception as e:
            self.logger.debug(f"Failed to parse JSON item: {e}")
            return None
    
    def _parse_txt(self, data: bytes, feed: ThreatFeed) -> List[ThreatIndicator]:
        """Parse TXT format (one indicator per line)"""
        indicators = []
        
        try:
            text = data.decode('utf-8')
            
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Simple TXT format: indicator only
                indicator_value = line.split()[0]  # Take first word
                
                indicator = ThreatIndicator(
                    indicator=indicator_value,
                    indicator_type=self._detect_indicator_type(indicator_value, feed.feed_type),
                    threat_type=self._feed_type_to_threat_type(feed.feed_type),
                    severity=ThreatSeverity.MEDIUM,  # Default for TXT
                    confidence=0.5,  # Default confidence
                    source=feed.name,
                    source_reliability=feed.priority / 10.0,
                )
                
                indicator.score = indicator.calculate_score()
                indicators.append(indicator)
            
        except Exception as e:
            raise FeedUpdateError(f"TXT parsing failed: {e}")
        
        return indicators
    
    def _parse_stix(self, data: bytes, feed: ThreatFeed) -> List[ThreatIndicator]:
        """Parse STIX format (simplified implementation)"""
        # Note: Full STIX parsing would require a STIX library
        # This is a simplified implementation
        
        try:
            stix_data = json.loads(data.decode('utf-8'))
            indicators = []
            
            # Check STIX version
            if stix_data.get('type') == 'bundle':
                objects = stix_data.get('objects', [])
            else:
                objects = [stix_data]
            
            for obj in objects:
                indicator = self._parse_stix_object(obj, feed)
                if indicator:
                    indicators.append(indicator)
            
            return indicators
            
        except Exception as e:
            raise FeedUpdateError(f"STIX parsing failed: {e}")
    
    def _parse_stix_object(
        self,
        obj: Dict[str, Any],
        feed: ThreatFeed
    ) -> Optional[ThreatIndicator]:
        """Parse single STIX object"""
        try:
            # Only process indicator objects
            if obj.get('type') != 'indicator':
                return None
            
            pattern = obj.get('pattern', '')
            
            # Extract indicator from pattern (simplified)
            indicator_value = None
            
            if 'file:hashes' in pattern:
                # File hash indicator
                import re
                match = re.search(r"file:hashes\..*='([^']+)'", pattern)
                if match:
                    indicator_value = match.group(1)
                    indicator_type = IndicatorType.FILE_HASH
            elif 'ipv4-addr:value' in pattern:
                # IP address indicator
                import re
                match = re.search(r"ipv4-addr:value='([^']+)'", pattern)
                if match:
                    indicator_value = match.group(1)
                    indicator_type = IndicatorType.IP_ADDRESS
            elif 'domain-name:value' in pattern:
                # Domain indicator
                import re
                match = re.search(r"domain-name:value='([^']+)'", pattern)
                if match:
                    indicator_value = match.group(1)
                    indicator_type = IndicatorType.DOMAIN
            elif 'url:value' in pattern:
                # URL indicator
                import re
                match = re.search(r"url:value='([^']+)'", pattern)
                if match:
                    indicator_value = match.group(1)
                    indicator_type = IndicatorType.URL
            
            if not indicator_value:
                return None
            
            # Parse timestamps
            created = self._parse_timestamp(obj.get('created'))
            modified = self._parse_timestamp(obj.get('modified'))
            
            # Parse labels (as tags)
            tags = set()
            for label in obj.get('labels', []):
                tags.add(label.lower())
            
            # Create indicator
            indicator = ThreatIndicator(
                indicator=indicator_value,
                indicator_type=indicator_type,
                threat_type=self._feed_type_to_threat_type(feed.feed_type),
                severity=ThreatSeverity.MEDIUM,  # Default
                confidence=obj.get('confidence', 0.5),
                first_seen=created,
                last_seen=modified,
                description=obj.get('description'),
                source=feed.name,
                source_reliability=feed.priority / 10.0,
                tags=tags,
                details={'stix_id': obj.get('id')}
            )
            
            indicator.score = indicator.calculate_score()
            
            return indicator
            
        except Exception as e:
            self.logger.debug(f"Failed to parse STIX object: {e}")
            return None
    
    def _parse_misp(self, data: bytes, feed: ThreatFeed) -> List[ThreatIndicator]:
        """Parse MISP format (simplified implementation)"""
        try:
            misp_data = json.loads(data.decode('utf-8'))
            indicators = []
            
            # MISP event structure
            if 'Event' in misp_data:
                event = misp_data['Event']
                attributes = event.get('Attribute', [])
                
                for attr in attributes:
                    indicator = self._parse_misp_attribute(attr, feed, event)
                    if indicator:
                        indicators.append(indicator)
            
            return indicators
            
        except Exception as e:
            raise FeedUpdateError(f"MISP parsing failed: {e}")
    
    def _parse_misp_attribute(
        self,
        attr: Dict[str, Any],
        feed: ThreatFeed,
        event: Dict[str, Any]
    ) -> Optional[ThreatIndicator]:
        """Parse MISP attribute"""
        try:
            indicator_value = attr.get('value')
            if not indicator_value:
                return None
            
            # Map MISP types to our indicator types
            type_mapping = {
                'md5': IndicatorType.FILE_HASH,
                'sha1': IndicatorType.FILE_HASH,
                'sha256': IndicatorType.FILE_HASH,
                'ip-src': IndicatorType.IP_ADDRESS,
                'ip-dst': IndicatorType.IP_ADDRESS,
                'domain': IndicatorType.DOMAIN,
                'hostname': IndicatorType.DOMAIN,
                'url': IndicatorType.URL,
                'email-src': IndicatorType.EMAIL,
                'email-dst': IndicatorType.EMAIL,
            }
            
            misp_type = attr.get('type', '')
            indicator_type = type_mapping.get(misp_type)
            
            if not indicator_type:
                # Try to detect from value
                indicator_type = self._detect_indicator_type(indicator_value, feed.feed_type)
            
            # Parse timestamps
            timestamp = self._parse_timestamp(attr.get('timestamp'))
            
            # Parse tags
            tags = set()
            for tag_obj in attr.get('Tag', []):
                tag_name = tag_obj.get('name', '')
                if tag_name:
                    tags.add(tag_name.lower())
            
            # Get event info
            event_info = event.get('info', 'MISP Event')
            event_id = event.get('id', '')
            
            # Create indicator
            indicator = ThreatIndicator(
                indicator=indicator_value,
                indicator_type=indicator_type,
                threat_type=self._feed_type_to_threat_type(feed.feed_type),
                severity=ThreatSeverity.MEDIUM,  # Default
                confidence=attr.get('confidence', 0.5),
                first_seen=timestamp,
                last_seen=timestamp,
                description=f"{event_info}: {attr.get('comment', '')}",
                source=feed.name,
                source_reliability=feed.priority / 10.0,
                tags=tags,
                details={
                    'misp_event_id': event_id,
                    'misp_type': misp_type,
                    'misp_category': attr.get('category', ''),
                }
            )
            
            indicator.score = indicator.calculate_score()
            
            return indicator
            
        except Exception as e:
            self.logger.debug(f"Failed to parse MISP attribute: {e}")
            return None
    
    def _apply_feed_transformations(
        self,
        indicators: List[ThreatIndicator],
        feed: ThreatFeed
    ) -> List[ThreatIndicator]:
        """Apply feed-specific transformations to indicators"""
        transformed = []
        
        for indicator in indicators:
            # Update indicator based on feed configuration
            indicator.source = feed.name
            
            # Apply any feed-specific tags
            feed_tags = feed.parser_config.get('tags', [])
            for tag in feed_tags:
                indicator.add_tag(tag)
            
            # Set expiration if configured
            if 'ttl_days' in feed.parser_config:
                ttl_days = feed.parser_config['ttl_days']
                if indicator.last_seen:
                    indicator.expires_at = indicator.last_seen + timedelta(days=ttl_days)
                else:
                    indicator.expires_at = datetime.now() + timedelta(days=ttl_days)
            
            transformed.append(indicator)
        
        return transformed
    
    def _validate_indicator(self, indicator: ThreatIndicator) -> bool:
        """Validate parsed indicator"""
        # Check required fields
        if not indicator.indicator or not indicator.indicator_type:
            return False
        
        # Validate indicator value based on type
        if indicator.indicator_type == IndicatorType.FILE_HASH:
            # Check if it looks like a hash
            hash_length = len(indicator.indicator)
            if hash_length not in [32, 40, 64]:  # MD5, SHA1, SHA256
                return False
            if not all(c in '0123456789abcdefABCDEF' for c in indicator.indicator):
                return False
        
        elif indicator.indicator_type == IndicatorType.IP_ADDRESS:
            # Basic IP validation
            import ipaddress
            try:
                ipaddress.ip_address(indicator.indicator)
            except ValueError:
                return False
        
        elif indicator.indicator_type == IndicatorType.DOMAIN:
            # Basic domain validation
            if len(indicator.indicator) > 253:
                return False
            if '..' in indicator.indicator:
                return False
        
        elif indicator.indicator_type == IndicatorType.URL:
            # Basic URL validation
            if not indicator.indicator.startswith(('http://', 'https://')):
                return False
        
        # Confidence must be between 0 and 1
        if not 0 <= indicator.confidence <= 1:
            return False
        
        # Source reliability must be between 0 and 1
        if not 0 <= indicator.source_reliability <= 1:
            return False
        
        return True
    
    @staticmethod
    def _detect_indicator_type(
        value: str,
        feed_type: FeedType
    ) -> IndicatorType:
        """Detect indicator type from value and feed type"""
        value_lower = value.lower()
        
        # Based on feed type
        if feed_type == FeedType.MALWARE_HASH:
            # Check hash length
            if len(value) == 32 and all(c in '0123456789abcdef' for c in value_lower):
                return IndicatorType.FILE_HASH
            elif len(value) == 40 and all(c in '0123456789abcdef' for c in value_lower):
                return IndicatorType.FILE_HASH
            elif len(value) == 64 and all(c in '0123456789abcdef' for c in value_lower):
                return IndicatorType.FILE_HASH
        
        elif feed_type == FeedType.IP_REPUTATION:
            import ipaddress
            try:
                ipaddress.ip_address(value)
                return IndicatorType.IP_ADDRESS
            except ValueError:
                pass
        
        elif feed_type == FeedType.DOMAIN_BLACKLIST:
            if '.' in value and ' ' not in value:
                return IndicatorType.DOMAIN
        
        elif feed_type == FeedType.PHISHING_URL:
            if value.startswith(('http://', 'https://')):
                return IndicatorType.URL
        
        # Fallback: Try to detect from value pattern
        import re
        
        # IP address pattern
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, value):
            return IndicatorType.IP_ADDRESS
        
        # Hash patterns
        hash_patterns = {
            32: r'^[a-fA-F0-9]{32}$',  # MD5
            40: r'^[a-fA-F0-9]{40}$',  # SHA1
            64: r'^[a-fA-F0-9]{64}$',  # SHA256
        }
        
        for length, pattern in hash_patterns.items():
            if len(value) == length and re.match(pattern, value):
                return IndicatorType.FILE_HASH
        
        # URL pattern
        url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        if re.match(url_pattern, value, re.IGNORECASE):
            return IndicatorType.URL
        
        # Domain pattern (simplified)
        domain_pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(domain_pattern, value):
            return IndicatorType.DOMAIN
        
        # Default to CUSTOM if can't detect
        return IndicatorType.CUSTOM
    
    @staticmethod
    def _parse_timestamp(timestamp: Any) -> Optional[datetime]:
        """Parse timestamp from various formats"""
        if not timestamp:
            return None
        
        try:
            # Try ISO format
            if isinstance(timestamp, str):
                # Remove timezone info for simplicity
                timestamp = timestamp.replace('Z', '+00:00')
                return datetime.fromisoformat(timestamp)
            
            # Try Unix timestamp
            elif isinstance(timestamp, (int, float)):
                return datetime.fromtimestamp(timestamp)
            
            # Already datetime
            elif isinstance(timestamp, datetime):
                return timestamp
            
        except (ValueError, TypeError):
            pass
        
        return None
    
    @staticmethod
    def _parse_severity(severity_str: str) -> ThreatSeverity:
        """Parse severity string to ThreatSeverity enum"""
        severity_str = severity_str.lower()
        
        if severity_str in ['critical', 'crit', '4']:
            return ThreatSeverity.CRITICAL
        elif severity_str in ['high', '3']:
            return ThreatSeverity.HIGH
        elif severity_str in ['medium', 'med', '2']:
            return ThreatSeverity.MEDIUM
        elif severity_str in ['low', '1']:
            return ThreatSeverity.LOW
        else:
            return ThreatSeverity.INFO
    
    @staticmethod
    def _feed_type_to_threat_type(feed_type: FeedType) -> str:
        """Convert feed type to threat type string"""
        mapping = {
            FeedType.MALWARE_HASH: "malware",
            FeedType.IP_REPUTATION: "malicious_ip",
            FeedType.DOMAIN_BLACKLIST: "malicious_domain",
            FeedType.PHISHING_URL: "phishing",
            FeedType.EXPLOIT_DB: "exploit",
            FeedType.SECURITY_ADVISORY: "advisory",
            FeedType.VULNERABILITY: "vulnerability",
            FeedType.CUSTOM: "custom",
        }
        return mapping.get(feed_type, "unknown")

class ThreatFeedManager:
    """
    Manager for multiple threat intelligence feeds
    
    Handles feed registration, updates, querying, and management
    with support for async operations and persistence.
    """
    
    def __init__(
        self,
        storage_dir: Optional[str] = None,
        enable_persistence: bool = True,
        max_indicators: int = 1000000
    ):
        """
        Initialize threat feed manager
        
        Args:
            storage_dir: Directory for persistent storage
            enable_persistence: Whether to save indicators to disk
            max_indicators: Maximum number of indicators to keep in memory
        """
        self.logger = logging.getLogger(__name__)
        self.loader = SecureDataLoader(
            user_agent="CyberGuard-ThreatFeeds/1.0",
            timeout_seconds=30,
            max_retries=3,
        )
        self.parser = FeedParser()
        self.quarantine = QuarantineManager()
        
        # Setup storage
        if storage_dir:
            self.storage_dir = Path(storage_dir)
        else:
            self.storage_dir = Path("./cache/threat_feeds")
        
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        # Security: Set restrictive permissions
        try:
            self.storage_dir.chmod(0o700)
        except Exception as e:
            self.logger.warning(f"Failed to set storage directory permissions: {e}")
        
        self.enable_persistence = enable_persistence
        self.max_indicators = max_indicators
        
        # Feed registry
        self.feeds: Dict[str, ThreatFeed] = {}
        
        # Indicator storage
        self.indicators: Dict[str, ThreatIndicator] = {}  # indicator -> object
        self.indices: Dict[str, Dict[str, Set[str]]] = {
            'by_type': {},      # indicator_type -> set(indicator)
            'by_source': {},    # source -> set(indicator)
            'by_tag': {},       # tag -> set(indicator)
            'by_severity': {},  # severity -> set(indicator)
        }
        
        # Statistics
        self.stats = {
            'total_indicators': 0,
            'active_indicators': 0,
            'feeds_loaded': 0,
            'last_update': None,
            'queries_served': 0,
        }
        
        # Load persisted data if enabled
        if enable_persistence:
            self._load_persisted_data()
        
        # Register built-in feeds
        self._register_builtin_feeds()
        
        audit_log(
            action="threat_feed_manager_init",
            resource="ThreatFeedManager",
            status="success",
            details={
                "storage_dir": str(self.storage_dir),
                "enable_persistence": enable_persistence,
                "max_indicators": max_indicators,
            }
        )
    
    def _register_builtin_feeds(self):
        """Register built-in threat intelligence feeds"""
        builtin_feeds = [
            ThreatFeed(
                name="EmergingThreats",
                url="https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                feed_type=FeedType.IP_REPUTATION,
                format=FeedFormat.TXT,
                update_interval=3600,
                priority=3,
            ),
            ThreatFeed(
                name="AbuseIPDB",
                url="https://www.abuseipdb.com/feed",
                feed_type=FeedType.IP_REPUTATION,
                format=FeedFormat.CSV,
                update_interval=7200,
                priority=2,
            ),
            ThreatFeed(
                name="PhishTank",
                url="https://data.phishtank.com/data/online-valid.csv",
                feed_type=FeedType.PHISHING_URL,
                format=FeedFormat.CSV,
                update_interval=3600,
                priority=2,
            ),
        ]
        
        for feed in builtin_feeds:
            self.add_feed(feed)
    
    def add_feed(self, feed: ThreatFeed):
        """
        Add a threat feed to the manager
        
        Args:
            feed: ThreatFeed configuration
            
        Raises:
            FeedConfigurationError: If feed configuration is invalid
        """
        # Validate feed
        if not feed.name or not feed.url:
            raise FeedConfigurationError("Feed must have name and URL")
        
        if feed.name in self.feeds:
            self.logger.warning(f"Feed {feed.name} already exists, replacing")
        
        # Add to registry
        self.feeds[feed.name] = feed
        
        self.logger.info(f"Added feed: {feed.name} ({feed.feed_type.value})")
        
        audit_log(
            action="feed_added",
            resource=feed.name,
            status="success",
            details={
                "url": feed.url,
                "type": feed.feed_type.value,
                "format": feed.format.value,
                "update_interval": feed.update_interval,
            }
        )
    
    def remove_feed(self, feed_name: str):
        """
        Remove a threat feed
        
        Args:
            feed_name: Name of feed to remove
        """
        if feed_name in self.feeds:
            del self.feeds[feed_name]
            self.logger.info(f"Removed feed: {feed_name}")
            
            audit_log(
                action="feed_removed",
                resource=feed_name,
                status="success",
                details={}
            )
    
    def update_feed(self, feed_name: str, force: bool = False) -> Dict[str, Any]:
        """
        Update a single threat feed
        
        Args:
            feed_name: Name of feed to update
            force: Force update even if not due
            
        Returns:
            Dictionary with update results
            
        Raises:
            FeedUpdateError: If update fails
        """
        if feed_name not in self.feeds:
            raise FeedConfigurationError(f"Feed not found: {feed_name}")
        
        feed = self.feeds[feed_name]
        
        # Check if update is needed
        if not force and not feed.is_due_for_update:
            return {
                'status': 'skipped',
                'reason': 'not_due',
                'feed': feed_name,
                'indicators_added': 0,
            }
        
        self.logger.info(f"Updating feed: {feed_name}")
        
        start_time = datetime.now()
        
        try:
            # Download feed data
            data = self.loader.load_url(
                feed.url,
                expected_content_type=self._get_expected_content_type(feed.format),
                max_size_mb=50,
            )
            
            # Verify hash if configured
            if feed.expected_hash:
                if not self.parser.hash_validator.verify_hash(data, feed.expected_hash):
                    raise DataValidationError(
                        f"Hash verification failed for feed {feed_name}"
                    )
            
            # Parse indicators
            indicators = self.parser.parse(data, feed)
            
            # Check minimum indicators
            if len(indicators) < feed.min_update_size:
                self.logger.warning(
                    f"Feed {feed_name} returned only {len(indicators)} indicators "
                    f"(minimum: {feed.min_update_size})"
                )
            
            # Add indicators
            added_count = self._add_indicators(indicators)
            
            # Update feed statistics
            duration = (datetime.now() - start_time).total_seconds()
            feed.record_update(True, added_count, duration)
            
            # Persist if enabled
            if self.enable_persistence:
                self._persist_indicators()
            
            result = {
                'status': 'success',
                'feed': feed_name,
                'indicators_parsed': len(indicators),
                'indicators_added': added_count,
                'duration_seconds': duration,
                'timestamp': datetime.now().isoformat(),
            }
            
            self.logger.info(
                f"Feed {feed_name} updated: {added_count} indicators added "
                f"({duration:.2f}s)"
            )
            
            audit_log(
                action="feed_update",
                resource=feed_name,
                status="success",
                details=result
            )
            
            return result
            
        except Exception as e:
            # Update feed error statistics
            duration = (datetime.now() - start_time).total_seconds()
            feed.record_update(False, 0, duration)
            
            error_msg = f"Failed to update feed {feed_name}: {e}"
            self.logger.error(error_msg)
            
            audit_log(
                action="feed_update",
                resource=feed_name,
                status="failure",
                details={
                    'feed': feed_name,
                    'error': str(e),
                    'duration_seconds': duration,
                }
            )
            
            raise FeedUpdateError(error_msg)
    
    async def update_feed_async(self, feed_name: str, force: bool = False) -> Dict[str, Any]:
        """
        Asynchronously update a single threat feed
        
        Args:
            feed_name: Name of feed to update
            force: Force update even if not due
            
        Returns:
            Dictionary with update results
        """
        # Run sync update in thread pool for compatibility
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self.update_feed, feed_name, force
        )
    
    def update_all_feeds(self, force: bool = False) -> Dict[str, Any]:
        """
        Update all registered feeds
        
        Args:
            force: Force update even if not due
            
        Returns:
            Dictionary with update results for all feeds
        """
        self.logger.info(f"Updating all feeds (force: {force})")
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'total_feeds': len(self.feeds),
            'updated': 0,
            'failed': 0,
            'skipped': 0,
            'total_indicators_added': 0,
            'feeds': {},
        }
        
        for feed_name in self.feeds:
            try:
                feed_result = self.update_feed(feed_name, force)
                results['feeds'][feed_name] = feed_result
                
                if feed_result['status'] == 'success':
                    results['updated'] += 1
                    results['total_indicators_added'] += feed_result['indicators_added']
                elif feed_result['status'] == 'skipped':
                    results['skipped'] += 1
                else:
                    results['failed'] += 1
                    
            except Exception as e:
                results['feeds'][feed_name] = {
                    'status': 'error',
                    'error': str(e),
                }
                results['failed'] += 1
        
        # Update global statistics
        self.stats['last_update'] = datetime.now()
        self.stats['feeds_loaded'] = results['updated']
        
        self.logger.info(
            f"Feed update completed: {results['updated']} updated, "
            f"{results['failed']} failed, {results['skipped']} skipped, "
            f"{results['total_indicators_added']} indicators added"
        )
        
        audit_log(
            action="all_feeds_update",
            resource="ThreatFeedManager",
            status="success" if results['failed'] == 0 else "partial",
            details=results
        )
        
        return results
    
    async def update_all_feeds_async(self, force: bool = False) -> Dict[str, Any]:
        """
        Asynchronously update all registered feeds
        
        Args:
            force: Force update even if not due
            
        Returns:
            Dictionary with update results
        """
        self.logger.info(f"Async updating all feeds (force: {force})")
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'total_feeds': len(self.feeds),
            'updated': 0,
            'failed': 0,
            'skipped': 0,
            'total_indicators_added': 0,
            'feeds': {},
        }
        
        # Create tasks for all feeds
        tasks = []
        for feed_name in self.feeds:
            task = self.update_feed_async(feed_name, force)
            tasks.append((feed_name, task))
        
        # Wait for all tasks
        for feed_name, task in tasks:
            try:
                feed_result = await task
                results['feeds'][feed_name] = feed_result
                
                if feed_result['status'] == 'success':
                    results['updated'] += 1
                    results['total_indicators_added'] += feed_result['indicators_added']
                elif feed_result['status'] == 'skipped':
                    results['skipped'] += 1
                else:
                    results['failed'] += 1
                    
            except Exception as e:
                results['feeds'][feed_name] = {
                    'status': 'error',
                    'error': str(e),
                }
                results['failed'] += 1
        
        # Update global statistics
        self.stats['last_update'] = datetime.now()
        self.stats['feeds_loaded'] = results['updated']
        
        self.logger.info(
            f"Async feed update completed: {results['updated']} updated, "
            f"{results['failed']} failed, {results['skipped']} skipped, "
            f"{results['total_indicators_added']} indicators added"
        )
        
        return results
    
    def _add_indicators(self, indicators: List[ThreatIndicator]) -> int:
        """
        Add indicators to storage and update indices
        
        Args:
            indicators: List of indicators to add
            
        Returns:
            Number of indicators actually added (excluding duplicates)
        """
        added_count = 0
        
        for indicator in indicators:
            # Skip if already exists (by indicator value)
            if indicator.indicator in self.indicators:
                # Update existing indicator
                existing = self.indicators[indicator.indicator]
                
                # Update timestamps
                if indicator.last_seen:
                    if not existing.last_seen or indicator.last_seen > existing.last_seen:
                        existing.last_seen = indicator.last_seen
                
                # Update score if new one is higher
                if indicator.score > existing.score:
                    existing.score = indicator.score
                    existing.severity = indicator.severity
                    existing.confidence = indicator.confidence
                
                # Merge tags
                existing.tags.update(indicator.tags)
                
                # Merge references
                for ref in indicator.references:
                    if ref not in existing.references:
                        existing.references.append(ref)
                
                continue
            
            # Check if we're at capacity
            if len(self.indicators) >= self.max_indicators:
                # Remove oldest indicators (by last_seen)
                self._cleanup_old_indicators(1000)  # Remove 1000 oldest
            
            # Add to storage
            self.indicators[indicator.indicator] = indicator
            added_count += 1
            
            # Update indices
            self._update_indices(indicator)
        
        # Update statistics
        self.stats['total_indicators'] = len(self.indicators)
        self.stats['active_indicators'] = sum(
            1 for i in self.indicators.values() if i.is_active
        )
        
        return added_count
    
    def _update_indices(self, indicator: ThreatIndicator):
        """Update search indices for an indicator"""
        # Index by type
        type_key = indicator.indicator_type.value
        if type_key not in self.indices['by_type']:
            self.indices['by_type'][type_key] = set()
        self.indices['by_type'][type_key].add(indicator.indicator)
        
        # Index by source
        source_key = indicator.source
        if source_key not in self.indices['by_source']:
            self.indices['by_source'][source_key] = set()
        self.indices['by_source'][source_key].add(indicator.indicator)
        
        # Index by severity
        severity_key = indicator.severity.value
        if severity_key not in self.indices['by_severity']:
            self.indices['by_severity'][severity_key] = set()
        self.indices['by_severity'][severity_key].add(indicator.indicator)
        
        # Index by tags
        for tag in indicator.tags:
            if tag not in self.indices['by_tag']:
                self.indices['by_tag'][tag] = set()
            self.indices['by_tag'][tag].add(indicator.indicator)
    
    def _cleanup_old_indicators(self, count: int = 1000):
        """Remove oldest indicators to free up space"""
        # Sort indicators by last_seen (oldest first)
        sorted_indicators = sorted(
            self.indicators.items(),
            key=lambda x: x[1].last_seen or datetime.min
        )
        
        # Remove oldest ones
        for i in range(min(count, len(sorted_indicators))):
            indicator_key, indicator = sorted_indicators[i]
            
            # Remove from main storage
            del self.indicators[indicator_key]
            
            # Remove from indices
            self._remove_from_indices(indicator)
        
        self.logger.info(f"Cleaned up {count} oldest indicators")
    
    def _remove_from_indices(self, indicator: ThreatIndicator):
        """Remove indicator from all indices"""
        # Remove from type index
        type_key = indicator.indicator_type.value
        if type_key in self.indices['by_type']:
            self.indices['by_type'][type_key].discard(indicator.indicator)
            if not self.indices['by_type'][type_key]:
                del self.indices['by_type'][type_key]
        
        # Remove from source index
        source_key = indicator.source
        if source_key in self.indices['by_source']:
            self.indices['by_source'][source_key].discard(indicator.indicator)
            if not self.indices['by_source'][source_key]:
                del self.indices['by_source'][source_key]
        
        # Remove from severity index
        severity_key = indicator.severity.value
        if severity_key in self.indices['by_severity']:
            self.indices['by_severity'][severity_key].discard(indicator.indicator)
            if not self.indices['by_severity'][severity_key]:
                del self.indices['by_severity'][severity_key]
        
        # Remove from tag indices
        for tag in indicator.tags:
            if tag in self.indices['by_tag']:
                self.indices['by_tag'][tag].discard(indicator.indicator)
                if not self.indices['by_tag'][tag]:
                    del self.indices['by_tag'][tag]
    
    def query(
        self,
        indicator: Optional[str] = None,
        indicator_type: Optional[IndicatorType] = None,
        source: Optional[str] = None,
        tag: Optional[str] = None,
        severity: Optional[ThreatSeverity] = None,
        min_confidence: float = 0.0,
        min_score: float = 0.0,
        active_only: bool = True,
        limit: int = 100
    ) -> List[ThreatIndicator]:
        """
        Query threat indicators
        
        Args:
            indicator: Specific indicator value to look for
            indicator_type: Type of indicator
            source: Feed source name
            tag: Tag to filter by
            severity: Minimum severity
            min_confidence: Minimum confidence score
            min_score: Minimum threat score
            active_only: Only return active (non-expired) indicators
            limit: Maximum number of results
            
        Returns:
            List of matching threat indicators
        """
        self.stats['queries_served'] += 1
        
        # Start with all indicators
        if indicator:
            # Direct lookup
            if indicator in self.indicators:
                result = [self.indicators[indicator]]
            else:
                result = []
        else:
            # Build result set from indices
            candidate_sets = []
            
            if indicator_type:
                type_key = indicator_type.value
                if type_key in self.indices['by_type']:
                    candidate_sets.append(self.indices['by_type'][type_key])
            
            if source:
                if source in self.indices['by_source']:
                    candidate_sets.append(self.indices['by_source'][source])
            
            if tag:
                tag_lower = tag.lower()
                if tag_lower in self.indices['by_tag']:
                    candidate_sets.append(self.indices['by_tag'][tag_lower])
            
            if severity:
                severity_key = severity.value
                # Include all severities >= requested severity
                severity_order = {
                    ThreatSeverity.CRITICAL.value: 5,
                    ThreatSeverity.HIGH.value: 4,
                    ThreatSeverity.MEDIUM.value: 3,
                    ThreatSeverity.LOW.value: 2,
                    ThreatSeverity.INFO.value: 1,
                }
                
                requested_level = severity_order.get(severity_key, 0)
                for sev_key, sev_set in self.indices['by_severity'].items():
                    sev_level = severity_order.get(sev_key, 0)
                    if sev_level >= requested_level:
                        candidate_sets.append(sev_set)
            
            # Intersect candidate sets
            if candidate_sets:
                # Start with first set
                candidate_indicators = set(candidate_sets[0])
                
                # Intersect with remaining sets
                for candidate_set in candidate_sets[1:]:
                    candidate_indicators.intersection_update(candidate_set)
            else:
                # No filters, start with all indicators
                candidate_indicators = set(self.indicators.keys())
        
        # Filter and sort results
        results = []
        for indicator_key in candidate_indicators:
            indicator_obj = self.indicators.get(indicator_key)
            if not indicator_obj:
                continue
            
            # Apply filters
            if active_only and not indicator_obj.is_active:
                continue
            
            if indicator_obj.confidence < min_confidence:
                continue
            
            if indicator_obj.score < min_score:
                continue
            
            results.append(indicator_obj)
        
        # Sort by score (highest first) and limit
        results.sort(key=lambda x: x.score, reverse=True)
        results = results[:limit]
        
        # Update last_seen for returned indicators
        for indicator_obj in results:
            indicator_obj.update_seen()
        
        return results
    
    def check_indicator(self, indicator: str) -> Optional[ThreatIndicator]:
        """
        Check if an indicator is in threat database
        
        Args:
            indicator: Indicator value to check
            
        Returns:
            ThreatIndicator if found, None otherwise
        """
        if indicator in self.indicators:
            indicator_obj = self.indicators[indicator]
            
            # Update last_seen
            indicator_obj.update_seen()
            
            # Check if expired
            if not indicator_obj.is_active:
                return None
            
            return indicator_obj
        
        return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get threat feed manager statistics"""
        # Calculate feed statistics
        feed_stats = {}
        for feed_name, feed in self.feeds.items():
            feed_stats[feed_name] = {
                'health': feed.health_status,
                'enabled': feed.enabled,
                'last_update': feed.last_update.isoformat() if feed.last_update else None,
                'indicators_count': feed.indicators_count,
                'success_rate': feed.success_rate,
                'avg_update_time': feed.avg_update_time,
            }
        
        # Calculate indicator statistics
        type_counts = {}
        severity_counts = {}
        source_counts = {}
        
        for indicator in self.indicators.values():
            # Type counts
            type_key = indicator.indicator_type.value
            type_counts[type_key] = type_counts.get(type_key, 0) + 1
            
            # Severity counts
            severity_key = indicator.severity.value
            severity_counts[severity_key] = severity_counts.get(severity_key, 0) + 1
            
            # Source counts
            source_key = indicator.source
            source_counts[source_key] = source_counts.get(source_key, 0) + 1
        
        # Calculate tag statistics
        tag_counts = {}
        for tag, indicator_set in self.indices['by_tag'].items():
            tag_counts[tag] = len(indicator_set)
        
        # Top tags
        top_tags = sorted(
            tag_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        return {
            'indicators': {
                'total': self.stats['total_indicators'],
                'active': self.stats['active_indicators'],
                'by_type': type_counts,
                'by_severity': severity_counts,
                'by_source': source_counts,
            },
            'feeds': {
                'total': len(self.feeds),
                'enabled': sum(1 for f in self.feeds.values() if f.enabled),
                'details': feed_stats,
            },
            'performance': {
                'queries_served': self.stats['queries_served'],
                'last_update': self.stats['last_update'].isoformat() if self.stats['last_update'] else None,
                'feeds_loaded': self.stats['feeds_loaded'],
            },
            'tags': {
                'total_tags': len(tag_counts),
                'top_tags': top_tags,
            },
        }
    
    def _persist_indicators(self):
        """Persist indicators to disk"""
        if not self.enable_persistence:
            return
        
        try:
            # Prepare data for persistence
            data = {
                'metadata': {
                    'version': '1.0',
                    'export_date': datetime.now().isoformat(),
                    'total_indicators': len(self.indicators),
                },
                'indicators': [indicator.to_dict() for indicator in self.indicators.values()],
            }
            
            # Write to file
            persist_file = self.storage_dir / 'indicators.json'
            
            with open(persist_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            
            # Set restrictive permissions
            persist_file.chmod(0o600)
            
            self.logger.debug(f"Persisted {len(self.indicators)} indicators to disk")
            
        except Exception as e:
            self.logger.error(f"Failed to persist indicators: {e}")
    
    def _load_persisted_data(self):
        """Load persisted indicators from disk"""
        persist_file = self.storage_dir / 'indicators.json'
        
        if not persist_file.exists():
            self.logger.info("No persisted indicators found")
            return
        
        try:
            with open(persist_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Parse indicators
            indicators = []
            for indicator_dict in data.get('indicators', []):
                try:
                    indicator = ThreatIndicator.from_dict(indicator_dict)
                    indicators.append(indicator)
                except Exception as e:
                    self.logger.warning(f"Failed to parse persisted indicator: {e}")
                    continue
            
            # Add indicators
            added = self._add_indicators(indicators)
            
            self.logger.info(f"Loaded {added} indicators from persistence")
            
        except Exception as e:
            self.logger.error(f"Failed to load persisted indicators: {e}")
    
    @staticmethod
    def _get_expected_content_type(feed_format: FeedFormat) -> str:
        """Get expected content type for feed format"""
        mapping = {
            FeedFormat.CSV: 'text/csv',
            FeedFormat.JSON: 'application/json',
            FeedFormat.TXT: 'text/plain',
            FeedFormat.STIX: 'application/json',
            FeedFormat.MISP: 'application/json',
            FeedFormat.CUSTOM: 'application/octet-stream',
        }
        return mapping.get(feed_format, 'application/octet-stream')
    
    def export_indicators(
        self,
        output_file: str,
        format: FeedFormat = FeedFormat.JSON
    ) -> str:
        """
        Export indicators to file
        
        Args:
            output_file: Path to output file
            format: Export format
            
        Returns:
            Path to exported file
        """
        output_path = Path(output_file)
        
        if format == FeedFormat.JSON:
            # Export as JSON
            data = {
                'metadata': {
                    'export_date': datetime.now().isoformat(),
                    'total_indicators': len(self.indicators),
                    'format': 'cyberguard_threat_indicators',
                },
                'indicators': [indicator.to_dict() for indicator in self.indicators.values()],
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        
        elif format == FeedFormat.CSV:
            # Export as CSV
            import csv
            
            # Define CSV columns
            fieldnames = [
                'indicator',
                'type',
                'threat_type',
                'severity',
                'confidence',
                'score',
                'source',
                'first_seen',
                'last_seen',
                'description',
                'tags',
                'references',
            ]
            
            with open(output_path, 'w', encoding='utf-8', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                
                for indicator in self.indicators.values():
                    row = {
                        'indicator': indicator.indicator,
                        'type': indicator.indicator_type.value,
                        'threat_type': indicator.threat_type,
                        'severity': indicator.severity.value,
                        'confidence': indicator.confidence,
                        'score': indicator.score,
                        'source': indicator.source,
                        'first_seen': indicator.first_seen.isoformat() if indicator.first_seen else '',
                        'last_seen': indicator.last_seen.isoformat() if indicator.last_seen else '',
                        'description': indicator.description or '',
                        'tags': ','.join(indicator.tags),
                        'references': ','.join(indicator.references),
                    }
                    writer.writerow(row)
        
        elif format == FeedFormat.TXT:
            # Export as TXT (one indicator per line)
            with open(output_path, 'w', encoding='utf-8') as f:
                for indicator in self.indicators.values():
                    f.write(f"{indicator.indicator}\n")
        
        else:
            raise ValueError(f"Unsupported export format: {format}")
        
        # Set restrictive permissions
        output_path.chmod(0o600)
        
        self.logger.info(f"Exported {len(self.indicators)} indicators to {output_path}")
        
        return str(output_path)

# Convenience functions
def create_feed_manager(
    storage_dir: Optional[str] = None,
    auto_update: bool = True
) -> ThreatFeedManager:
    """
    Create and initialize threat feed manager
    
    Args:
        storage_dir: Storage directory for persistence
        auto_update: Whether to update feeds on creation
        
    Returns:
        Initialized ThreatFeedManager
    """
    manager = ThreatFeedManager(storage_dir=storage_dir)
    
    if auto_update:
        # Update feeds in background
        import threading
        
        def update_background():
            try:
                manager.update_all_feeds()
            except Exception as e:
                logging.getLogger(__name__).error(f"Background feed update failed: {e}")
        
        thread = threading.Thread(target=update_background, daemon=True)
        thread.start()
    
    return manager

def check_threat_indicator(
    indicator: str,
    manager: Optional[ThreatFeedManager] = None
) -> Optional[ThreatIndicator]:
    """
    Check if an indicator is in threat database
    
    Args:
        indicator: Indicator value to check
        manager: Existing ThreatFeedManager instance
        
    Returns:
        ThreatIndicator if found, None otherwise
    """
    if manager is None:
        manager = create_feed_manager(auto_update=False)
    
    return manager.check_indicator(indicator)