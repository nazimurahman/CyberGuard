"""
CVE (Common Vulnerabilities and Exposures) Ingestion Module
==========================================================

This module provides specialized ingestion and processing for CVE data
from multiple sources including:
- MITRE CVE database
- NVD (National Vulnerability Database)
- Vendor-specific security advisories
- Third-party vulnerability feeds

Features:
---------
1. Multi-source CVE data ingestion
2. CVE data parsing and normalization
3. Severity scoring (CVSS v2/v3)
4. Affected software/product mapping
5. Temporal data tracking (published, modified dates)
6. Reference and link management
7. Data deduplication and merging

Security Considerations:
-----------------------
- All CVE data is validated before processing
- Source authenticity is verified
- Data integrity is checked via hashes
- Rate limiting on API calls
- Cache management for performance

Usage Examples:
---------------
# Basic CVE ingestion
ingestor = CVEIngestor()
cves = ingestor.load_cves_from_mitre()

# Process specific CVE
cve_data = ingestor.get_cve("CVE-2021-44228")

# Search for CVEs
results = ingestor.search_cves(
    product="Apache Log4j",
    min_cvss_score=7.0
)

# Update CVE database
ingestor.update_database()
"""

import json
import csv
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from datetime import datetime, date
from dataclasses import dataclass, field, asdict
from enum import Enum
import logging
from pathlib import Path

# Local imports
from .secure_loader import SecureDataLoader, DataValidationError
from .hash_validator import HashValidator
from ..utils.logging_utils import audit_log

# Custom exceptions for CVE processing
class CVEProcessingError(Exception):
    """Base exception for CVE processing errors"""
    pass

class CVEParseError(CVEProcessingError):
    """Raised when CVE data cannot be parsed"""
    pass

class CVESourceError(CVEProcessingError):
    """Raised when CVE source is unavailable or invalid"""
    pass

class CVEDuplicateError(CVEProcessingError):
    """Raised when duplicate CVE is detected"""
    pass

# Enums for CVE data
class CVSSVersion(Enum):
    """CVSS version enumeration"""
    V2 = "2.0"
    V3 = "3.0"
    V31 = "3.1"

class CVSSSeverity(Enum):
    """CVSS severity levels"""
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class CVEStatus(Enum):
    """CVE status enumeration"""
    ENTRY = "ENTRY"          # Initial entry
    CANDIDATE = "CANDIDATE"  # Candidate for inclusion
    REJECTED = "REJECTED"    # Rejected CVE
    DISPUTED = "DISPUTED"    # Disputed CVE
    MODIFIED = "MODIFIED"    # Modified CVE

@dataclass
class CVSSMetrics:
    """
    CVSS (Common Vulnerability Scoring System) metrics
    
    This class represents CVSS v2, v3, or v3.1 metrics
    with all base, temporal, and environmental scores.
    """
    version: CVSSVersion
    vector_string: str
    
    # Base scores
    base_score: float
    base_severity: CVSSSeverity
    
    # Vector components (availability depends on version)
    attack_vector: Optional[str] = None  # NETWORK, ADJACENT, LOCAL, PHYSICAL
    attack_complexity: Optional[str] = None  # LOW, HIGH
    privileges_required: Optional[str] = None  # NONE, LOW, HIGH
    user_interaction: Optional[str] = None  # NONE, REQUIRED
    scope: Optional[str] = None  # UNCHANGED, CHANGED
    confidentiality_impact: Optional[str] = None  # NONE, LOW, HIGH
    integrity_impact: Optional[str] = None  # NONE, LOW, HIGH
    availability_impact: Optional[str] = None  # NONE, LOW, HIGH
    
    # Temporal metrics (optional)
    exploit_code_maturity: Optional[str] = None  # UNPROVEN, POC, FUNCTIONAL, HIGH, NOT_DEFINED
    remediation_level: Optional[str] = None  # OFFICIAL, TEMPORARY, WORKAROUND, UNAVAILABLE, NOT_DEFINED
    report_confidence: Optional[str] = None  # UNKNOWN, REASONABLE, CONFIRMED, NOT_DEFINED
    
    # Environmental metrics (optional)
    confidentiality_requirement: Optional[str] = None  # LOW, MEDIUM, HIGH, NOT_DEFINED
    integrity_requirement: Optional[str] = None  # LOW, MEDIUM, HIGH, NOT_DEFINED
    availability_requirement: Optional[str] = None  # LOW, MEDIUM, HIGH, NOT_DEFINED
    modified_attack_vector: Optional[str] = None
    modified_attack_complexity: Optional[str] = None
    modified_privileges_required: Optional[str] = None
    modified_user_interaction: Optional[str] = None
    modified_scope: Optional[str] = None
    modified_confidentiality_impact: Optional[str] = None
    modified_integrity_impact: Optional[str] = None
    modified_availability_impact: Optional[str] = None
    
    # Calculated scores
    temporal_score: Optional[float] = None
    environmental_score: Optional[float] = None
    overall_score: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        result = asdict(self)
        result['version'] = self.version.value
        result['base_severity'] = self.base_severity.value
        return result
    
    @classmethod
    def from_vector_string(cls, vector_string: str) -> 'CVSSMetrics':
        """
        Parse CVSS metrics from vector string
        
        Args:
            vector_string: CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
            
        Returns:
            CVSSMetrics object
        """
        # Parse vector string
        if not vector_string.startswith("CVSS:"):
            raise CVEParseError(f"Invalid CVSS vector string: {vector_string}")
        
        # Extract version
        version_str = vector_string.split('/')[0].split(':')[1]
        
        if version_str.startswith('3.1'):
            version = CVSSVersion.V31
        elif version_str.startswith('3.0'):
            version = CVSSVersion.V3
        elif version_str.startswith('2'):
            version = CVSSVersion.V2
        else:
            raise CVEParseError(f"Unsupported CVSS version: {version_str}")
        
        # Parse metrics from vector string
        metrics = {}
        for component in vector_string.split('/')[1:]:
            if ':' in component:
                key, value = component.split(':', 1)
                metrics[key] = value
        
        # Calculate base score (simplified - in production would use proper CVSS calculator)
        base_score = cls._calculate_base_score(version, metrics)
        base_severity = cls._score_to_severity(base_score, version)
        
        return cls(
            version=version,
            vector_string=vector_string,
            base_score=base_score,
            base_severity=base_severity,
            **{k.lower(): v for k, v in metrics.items()}
        )
    
    @staticmethod
    def _calculate_base_score(version: CVSSVersion, metrics: Dict[str, str]) -> float:
        """Calculate base score from metrics (simplified implementation)"""
        # Note: This is a simplified calculation. In production,
        # you would use the official CVSS v2/v3/v3.1 calculator.
        
        if version == CVSSVersion.V2:
            # Simplified CVSS v2 calculation
            # In reality, CVSS v2 has complex formulas
            return 5.0  # Placeholder
        else:
            # CVSS v3/v3.1 simplified calculation
            score = 0.0
            
            # Attack Vector
            av_scores = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
            if metrics.get('AV') in av_scores:
                score += av_scores[metrics['AV']]
            
            # Attack Complexity
            ac_scores = {'L': 0.77, 'H': 0.44}
            if metrics.get('AC') in ac_scores:
                score += ac_scores[metrics['AC']]
            
            # Normalize to 0-10 scale (simplified)
            return min(10.0, score * 3)
    
    @staticmethod
    def _score_to_severity(score: float, version: CVSSVersion) -> CVSSSeverity:
        """Convert score to severity level"""
        if version == CVSSVersion.V2:
            # CVSS v2 severity ranges
            if score == 0.0:
                return CVSSSeverity.NONE
            elif score < 4.0:
                return CVSSSeverity.LOW
            elif score < 7.0:
                return CVSSSeverity.MEDIUM
            else:
                return CVSSSeverity.HIGH  # CVSS v2 doesn't have CRITICAL
        else:
            # CVSS v3/v3.1 severity ranges
            if score == 0.0:
                return CVSSSeverity.NONE
            elif score < 4.0:
                return CVSSSeverity.LOW
            elif score < 7.0:
                return CVSSSeverity.MEDIUM
            elif score < 9.0:
                return CVSSSeverity.HIGH
            else:
                return CVSSSeverity.CRITICAL

@dataclass
class AffectedProduct:
    """Information about affected software/product"""
    vendor: str
    product: str
    version: Optional[str] = None
    version_end_excluding: Optional[str] = None
    version_end_including: Optional[str] = None
    version_start_excluding: Optional[str] = None
    version_start_including: Optional[str] = None
    platform: Optional[str] = None
    update: Optional[str] = None
    edition: Optional[str] = None
    language: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)

@dataclass
class CVEReference:
    """Reference link for CVE"""
    url: str
    name: str
    refsource: Optional[str] = None  # Reference source
    tags: List[str] = field(default_factory=list)  # e.g., "Patch", "Exploit", "Vendor Advisory"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)

@dataclass
class CVE:
    """
    CVE (Common Vulnerabilities and Exposures) data class
    
    This class represents a complete CVE record with all metadata,
    severity scores, affected products, and references.
    """
    # Basic identification
    cve_id: str  # Format: CVE-YYYY-NNNNN
    status: CVEStatus
    description: str
    
    # Dates
    published_date: Optional[datetime] = None
    last_modified_date: Optional[datetime] = None
    
    # CVSS metrics
    cvss_metrics: Optional[CVSSMetrics] = None
    cvss_v2: Optional[CVSSMetrics] = None
    cvss_v3: Optional[CVSSMetrics] = None
    cvss_v31: Optional[CVSSMetrics] = None
    
    # Affected products
    affected_products: List[AffectedProduct] = field(default_factory=list)
    
    # References
    references: List[CVEReference] = field(default_factory=list)
    
    # Additional metadata
    cwe_ids: List[str] = field(default_factory=list)  # Common Weakness Enumeration
    assigner: Optional[str] = None  # Organization that assigned the CVE
    problem_types: List[str] = field(default_factory=list)
    
    # Internal tracking
    source: str = "unknown"
    ingested_at: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert CVE to dictionary for serialization"""
        result = asdict(self)
        
        # Convert enums to strings
        result['status'] = self.status.value
        
        # Convert dates to ISO format
        if self.published_date:
            result['published_date'] = self.published_date.isoformat()
        if self.last_modified_date:
            result['last_modified_date'] = self.last_modified_date.isoformat()
        result['ingested_at'] = self.ingested_at.isoformat()
        result['last_updated'] = self.last_updated.isoformat()
        
        # Convert nested objects
        if self.cvss_metrics:
            result['cvss_metrics'] = self.cvss_metrics.to_dict()
        if self.cvss_v2:
            result['cvss_v2'] = self.cvss_v2.to_dict()
        if self.cvss_v3:
            result['cvss_v3'] = self.cvss_v3.to_dict()
        if self.cvss_v31:
            result['cvss_v31'] = self.cvss_v31.to_dict()
        
        result['affected_products'] = [p.to_dict() for p in self.affected_products]
        result['references'] = [r.to_dict() for r in self.references]
        
        return result
    
    @property
    def year(self) -> int:
        """Extract year from CVE ID"""
        try:
            return int(self.cve_id.split('-')[1])
        except (IndexError, ValueError):
            return 0
    
    @property
    def sequence_number(self) -> int:
        """Extract sequence number from CVE ID"""
        try:
            return int(self.cve_id.split('-')[2])
        except (IndexError, ValueError):
            return 0
    
    @property
    def severity(self) -> CVSSSeverity:
        """Get the highest severity from available CVSS metrics"""
        severities = []
        
        if self.cvss_v31 and self.cvss_v31.base_severity:
            severities.append(self.cvss_v31.base_severity)
        if self.cvss_v3 and self.cvss_v3.base_severity:
            severities.append(self.cvss_v3.base_severity)
        if self.cvss_v2 and self.cvss_v2.base_severity:
            severities.append(self.cvss_v2.base_severity)
        if self.cvss_metrics and self.cvss_metrics.base_severity:
            severities.append(self.cvss_metrics.base_severity)
        
        if not severities:
            return CVSSSeverity.NONE
        
        # Order: CRITICAL > HIGH > MEDIUM > LOW > NONE
        severity_order = {
            CVSSSeverity.CRITICAL: 5,
            CVSSSeverity.HIGH: 4,
            CVSSSeverity.MEDIUM: 3,
            CVSSSeverity.LOW: 2,
            CVSSSeverity.NONE: 1
        }
        
        return max(severities, key=lambda s: severity_order.get(s, 0))
    
    @property
    def max_score(self) -> float:
        """Get the maximum CVSS score from available metrics"""
        scores = []
        
        if self.cvss_v31:
            scores.append(self.cvss_v31.base_score)
        if self.cvss_v3:
            scores.append(self.cvss_v3.base_score)
        if self.cvss_v2:
            scores.append(self.cvss_v2.base_score)
        if self.cvss_metrics:
            scores.append(self.cvss_metrics.base_score)
        
        return max(scores) if scores else 0.0
    
    def is_critical(self) -> bool:
        """Check if CVE is critical (CVSS >= 9.0)"""
        return self.max_score >= 9.0
    
    def is_high_severity(self) -> bool:
        """Check if CVE is high severity (CVSS >= 7.0)"""
        return self.max_score >= 7.0
    
    def affects_product(self, vendor: str, product: str) -> bool:
        """Check if CVE affects a specific product"""
        vendor_lower = vendor.lower()
        product_lower = product.lower()
        
        for affected in self.affected_products:
            if (affected.vendor.lower() == vendor_lower and 
                affected.product.lower() == product_lower):
                return True
        return False

class CVEParser:
    """
    Parser for CVE data in various formats
    
    Supports:
    - JSON (NVD format)
    - CSV (MITRE format)
    - XML (legacy formats)
    - Custom vendor formats
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.hash_validator = HashValidator()
    
    def parse_nvd_json(self, json_data: Union[str, dict]) -> List[CVE]:
        """
        Parse NVD (National Vulnerability Database) JSON format
        
        Args:
            json_data: JSON string or dictionary
            
        Returns:
            List of CVE objects
        """
        try:
            if isinstance(json_data, str):
                data = json.loads(json_data)
            else:
                data = json_data
            
            cves = []
            
            # NVD JSON structure
            vulnerabilities = data.get('vulnerabilities', [])
            
            for vuln in vulnerabilities:
                try:
                    cve = self._parse_nvd_vulnerability(vuln)
                    if cve:
                        cves.append(cve)
                except Exception as e:
                    self.logger.warning(f"Failed to parse vulnerability: {e}")
                    continue
            
            self.logger.info(f"Parsed {len(cves)} CVEs from NVD JSON")
            return cves
            
        except (json.JSONDecodeError, KeyError) as e:
            raise CVEParseError(f"Failed to parse NVD JSON: {e}")
    
    def _parse_nvd_vulnerability(self, vuln_data: dict) -> Optional[CVE]:
        """Parse individual vulnerability from NVD JSON"""
        cve_data = vuln_data.get('cve', {})
        
        # Extract CVE ID
        cve_id = cve_data.get('id', '')
        if not cve_id.startswith('CVE-'):
            return None
        
        # Parse dates
        published_date = None
        last_modified_date = None
        
        published_str = cve_data.get('published')
        if published_str:
            try:
                published_date = datetime.fromisoformat(published_str.replace('Z', '+00:00'))
            except ValueError:
                pass
        
        last_modified_str = cve_data.get('lastModified')
        if last_modified_str:
            try:
                last_modified_date = datetime.fromisoformat(last_modified_str.replace('Z', '+00:00'))
            except ValueError:
                pass
        
        # Parse descriptions
        descriptions = cve_data.get('descriptions', [])
        description = ''
        for desc in descriptions:
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break
        
        if not description:
            # Fall back to any description
            for desc in descriptions:
                description = desc.get('value', '')
                if description:
                    break
        
        # Parse metrics (CVSS)
        metrics_data = cve_data.get('metrics', {})
        cvss_v2 = None
        cvss_v3 = None
        cvss_v31 = None
        
        # CVSS v2
        if 'cvssMetricV2' in metrics_data:
            for metric in metrics_data['cvssMetricV2']:
                cvss_data = metric.get('cvssData', {})
                if 'vectorString' in cvss_data:
                    try:
                        cvss_v2 = CVSSMetrics.from_vector_string(cvss_data['vectorString'])
                    except Exception as e:
                        self.logger.debug(f"Failed to parse CVSS v2 for {cve_id}: {e}")
        
        # CVSS v3/v3.1
        for metric_key in ['cvssMetricV30', 'cvssMetricV31']:
            if metric_key in metrics_data:
                for metric in metrics_data[metric_key]:
                    cvss_data = metric.get('cvssData', {})
                    if 'vectorString' in cvss_data:
                        try:
                            if metric_key == 'cvssMetricV30':
                                cvss_v3 = CVSSMetrics.from_vector_string(cvss_data['vectorString'])
                            else:
                                cvss_v31 = CVSSMetrics.from_vector_string(cvss_data['vectorString'])
                        except Exception as e:
                            self.logger.debug(f"Failed to parse {metric_key} for {cve_id}: {e}")
        
        # Parse affected products
        configurations = cve_data.get('configurations', [])
        affected_products = self._parse_affected_products(configurations)
        
        # Parse references
        references_data = cve_data.get('references', [])
        references = []
        for ref in references_data:
            url = ref.get('url', '')
            if url:
                references.append(CVEReference(
                    url=url,
                    name=ref.get('name', ''),
                    refsource=ref.get('source', None),
                    tags=ref.get('tags', [])
                ))
        
        # Parse CWE IDs
        cwe_ids = []
        problem_types = cve_data.get('problemtype', {}).get('problemtype_data', [])
        for problem_type in problem_types:
            for description in problem_type.get('description', []):
                cwe_id = description.get('value', '')
                if cwe_id.startswith('CWE-'):
                    cwe_ids.append(cwe_id)
        
        # Determine CVE status
        status = CVEStatus.ENTRY
        vuln_status = cve_data.get('vulnStatus', '').upper()
        if vuln_status in [s.value for s in CVEStatus]:
            status = CVEStatus(vuln_status)
        
        # Create CVE object
        cve = CVE(
            cve_id=cve_id,
            status=status,
            description=description,
            published_date=published_date,
            last_modified_date=last_modified_date,
            cvss_v2=cvss_v2,
            cvss_v3=cvss_v3,
            cvss_v31=cvss_v31,
            affected_products=affected_products,
            references=references,
            cwe_ids=cwe_ids,
            assigner=cve_data.get('sourceIdentifier', None),
            source='nvd',
            ingested_at=datetime.now()
        )
        
        # Set cvss_metrics to the highest version available
        if cvss_v31:
            cve.cvss_metrics = cvss_v31
        elif cvss_v3:
            cve.cvss_metrics = cvss_v3
        elif cvss_v2:
            cve.cvss_metrics = cvss_v2
        
        return cve
    
    def _parse_affected_products(self, configurations: List[dict]) -> List[AffectedProduct]:
        """Parse affected products from NVD configurations"""
        affected_products = []
        
        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                # Parse CPE matches
                cpe_matches = node.get('cpeMatch', [])
                for cpe_match in cpe_matches:
                    criteria = cpe_match.get('criteria', '')
                    
                    # Parse CPE string
                    # Format: cpe:2.3:a:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
                    if criteria.startswith('cpe:2.3:'):
                        parts = criteria.split(':')
                        if len(parts) >= 6:
                            affected = AffectedProduct(
                                vendor=parts[3] if len(parts) > 3 else '',
                                product=parts[4] if len(parts) > 4 else '',
                                version=parts[5] if len(parts) > 5 and parts[5] != '*' else None,
                                update=parts[6] if len(parts) > 6 and parts[6] != '*' else None,
                                edition=parts[7] if len(parts) > 7 and parts[7] != '*' else None,
                                language=parts[8] if len(parts) > 8 and parts[8] != '*' else None,
                                version_start_excluding=cpe_match.get('versionStartExcluding'),
                                version_start_including=cpe_match.get('versionStartIncluding'),
                                version_end_excluding=cpe_match.get('versionEndExcluding'),
                                version_end_including=cpe_match.get('versionEndIncluding')
                            )
                            affected_products.append(affected)
        
        return affected_products
    
    def parse_mitre_csv(self, csv_data: str) -> List[CVE]:
        """
        Parse MITRE CVE CSV format
        
        Args:
            csv_data: CSV string
            
        Returns:
            List of CVE objects
        """
        try:
            cves = []
            reader = csv.DictReader(csv_data.splitlines())
            
            for row in reader:
                try:
                    cve = self._parse_mitre_csv_row(row)
                    if cve:
                        cves.append(cve)
                except Exception as e:
                    self.logger.warning(f"Failed to parse CSV row: {e}")
                    continue
            
            self.logger.info(f"Parsed {len(cves)} CVEs from MITRE CSV")
            return cves
            
        except Exception as e:
            raise CVEParseError(f"Failed to parse MITRE CSV: {e}")
    
    def _parse_mitre_csv_row(self, row: Dict[str, str]) -> Optional[CVE]:
        """Parse individual row from MITRE CSV"""
        cve_id = row.get('Name', '')
        if not cve_id.startswith('CVE-'):
            return None
        
        # Parse dates
        published_date = None
        last_modified_date = None
        
        published_str = row.get('Published')
        if published_str:
            try:
                published_date = datetime.strptime(published_str, '%Y-%m-%d')
            except ValueError:
                pass
        
        modified_str = row.get('Modified')
        if modified_str:
            try:
                last_modified_date = datetime.strptime(modified_str, '%Y-%m-%d')
            except ValueError:
                pass
        
        # Description
        description = row.get('Description', '')
        
        # CVSS metrics (MITRE CSV has limited CVSS info)
        cvss_metrics = None
        cvss_score = row.get('CVSS')
        if cvss_score:
            try:
                score = float(cvss_score)
                # Create simplified CVSS metrics
                cvss_metrics = CVSSMetrics(
                    version=CVSSVersion.V2,  # MITRE CSV typically has v2
                    vector_string="",
                    base_score=score,
                    base_severity=self._score_to_severity_v2(score)
                )
            except ValueError:
                pass
        
        # Affected products (simplified parsing)
        affected_products = []
        vendors = row.get('Vendors', '')
        products = row.get('Products', '')
        
        if vendors and products:
            # Simple parsing - in production would need more sophisticated parsing
            affected = AffectedProduct(
                vendor=vendors.split(',')[0].strip(),
                product=products.split(',')[0].strip()
            )
            affected_products.append(affected)
        
        # References
        references = []
        references_str = row.get('References', '')
        if references_str:
            for ref in references_str.split('|'):
                ref = ref.strip()
                if ref.startswith('http'):
                    references.append(CVEReference(
                        url=ref,
                        name=f"Reference for {cve_id}"
                    ))
        
        # Create CVE
        return CVE(
            cve_id=cve_id,
            status=CVEStatus.ENTRY,  # MITRE CSV doesn't have status
            description=description,
            published_date=published_date,
            last_modified_date=last_modified_date,
            cvss_metrics=cvss_metrics,
            affected_products=affected_products,
            references=references,
            source='mitre_csv',
            ingested_at=datetime.now()
        )
    
    @staticmethod
    def _score_to_severity_v2(score: float) -> CVSSSeverity:
        """Convert CVSS v2 score to severity"""
        if score == 0.0:
            return CVSSSeverity.NONE
        elif score < 4.0:
            return CVSSSeverity.LOW
        elif score < 7.0:
            return CVSSSeverity.MEDIUM
        else:
            return CVSSSeverity.HIGH

class CVEIngestor:
    """
    Main CVE ingestion and management class
    
    This class coordinates CVE data loading from multiple sources,
    parsing, validation, and storage.
    """
    
    # CVE data sources
    CVE_SOURCES = {
        'nvd': {
            'url': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            'format': 'json',
            'description': 'NVD CVE JSON API',
            'update_frequency': 'daily',
        },
        'mitre': {
            'url': 'https://cve.mitre.org/data/downloads/allitems.csv',
            'format': 'csv',
            'description': 'MITRE CVE CSV',
            'update_frequency': 'daily',
        },
        'mitre_recent': {
            'url': 'https://cve.mitre.org/data/downloads/allitems.csv',
            'format': 'csv',
            'description': 'Recent CVEs from MITRE',
            'update_frequency': 'hourly',
        }
    }
    
    def __init__(
        self,
        cache_dir: Optional[str] = None,
        enable_cache: bool = True,
        update_interval_hours: int = 24
    ):
        """
        Initialize CVE ingestor
        
        Args:
            cache_dir: Directory for caching CVE data
            enable_cache: Whether to enable caching
            update_interval_hours: Hours between updates
        """
        self.logger = logging.getLogger(__name__)
        self.parser = CVEParser()
        self.loader = SecureDataLoader(
            user_agent="CyberGuard-CVE-Ingestor/1.0",
            timeout_seconds=60,
            max_retries=5,
            max_size_mb=500,  # CVE feeds can be large
        )
        
        # Setup cache directory
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = Path("./cache/cve_data")
        
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Security: Set restrictive permissions on cache directory
        try:
            self.cache_dir.chmod(0o700)  # Owner read/write/execute only
        except Exception as e:
            self.logger.warning(f"Failed to set cache directory permissions: {e}")
        
        self.enable_cache = enable_cache
        self.update_interval = update_interval_hours
        
        # In-memory CVE cache
        self._cve_cache: Dict[str, CVE] = {}
        self._cve_index: Dict[str, List[str]] = {
            'by_vendor': {},
            'by_product': {},
            'by_cvss': {},
            'by_year': {},
        }
        
        # Statistics
        self.stats = {
            'total_cves': 0,
            'last_update': None,
            'sources_loaded': set(),
            'update_errors': 0,
        }
        
        audit_log(
            action="cve_ingestor_init",
            resource="CVEIngestor",
            status="success",
            details={
                "cache_dir": str(self.cache_dir),
                "enable_cache": enable_cache,
                "update_interval_hours": update_interval_hours,
            }
        )
    
    def load_cves_from_source(
        self,
        source_name: str,
        force_refresh: bool = False
    ) -> List[CVE]:
        """
        Load CVEs from a specific source
        
        Args:
            source_name: Name of the source (see CVE_SOURCES)
            force_refresh: Force refresh even if cache is valid
            
        Returns:
            List of CVE objects
            
        Raises:
            CVESourceError: If source is unavailable or invalid
        """
        if source_name not in self.CVE_SOURCES:
            raise CVESourceError(f"Unknown CVE source: {source_name}")
        
        source_info = self.CVE_SOURCES[source_name]
        url = source_info['url']
        format_type = source_info['format']
        
        self.logger.info(f"Loading CVEs from {source_name}: {url}")
        
        # Check cache first
        cache_file = self.cache_dir / f"{source_name}.{format_type}"
        cache_valid = False
        
        if self.enable_cache and cache_file.exists() and not force_refresh:
            # Check if cache is still valid
            cache_age = datetime.now() - datetime.fromtimestamp(cache_file.stat().st_mtime)
            if cache_age.total_seconds() < (self.update_interval * 3600):
                cache_valid = True
        
        if cache_valid:
            # Load from cache
            self.logger.info(f"Loading CVEs from cache: {cache_file}")
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    if format_type == 'json':
                        data = json.load(f)
                        cves = self.parser.parse_nvd_json(data)
                    elif format_type == 'csv':
                        data = f.read()
                        cves = self.parser.parse_mitre_csv(data)
                    else:
                        raise CVESourceError(f"Unsupported format: {format_type}")
                
                self.logger.info(f"Loaded {len(cves)} CVEs from cache")
                return cves
                
            except Exception as e:
                self.logger.warning(f"Cache load failed, falling back to source: {e}")
                cache_valid = False
        
        # Load from source
        try:
            # Download data
            data = self.loader.load_url(
                url,
                expected_content_type=f"text/{format_type}" if format_type == 'csv' else "application/json",
                max_size_mb=1000,  # Large files for CVE feeds
                force_refresh=force_refresh,
            )
            
            # Parse data
            if format_type == 'json':
                json_data = json.loads(data.decode('utf-8'))
                cves = self.parser.parse_nvd_json(json_data)
            elif format_type == 'csv':
                csv_data = data.decode('utf-8')
                cves = self.parser.parse_mitre_csv(csv_data)
            else:
                raise CVESourceError(f"Unsupported format: {format_type}")
            
            self.logger.info(f"Loaded {len(cves)} CVEs from {source_name}")
            
            # Update cache
            if self.enable_cache:
                try:
                    with open(cache_file, 'w', encoding='utf-8') as f:
                        if format_type == 'json':
                            json.dump(json_data, f, indent=2)
                        else:
                            f.write(csv_data)
                    
                    # Set restrictive permissions on cache file
                    cache_file.chmod(0o600)  # Owner read/write only
                    
                    self.logger.info(f"Cached {len(cves)} CVEs to {cache_file}")
                except Exception as e:
                    self.logger.warning(f"Failed to cache CVEs: {e}")
            
            # Update statistics
            self.stats['sources_loaded'].add(source_name)
            self.stats['last_update'] = datetime.now()
            
            # Add to memory cache
            self._add_to_memory_cache(cves)
            
            audit_log(
                action="cve_source_load",
                resource=source_name,
                status="success",
                details={
                    "url": url,
                    "cves_loaded": len(cves),
                    "format": format_type,
                    "cache_updated": self.enable_cache,
                }
            )
            
            return cves
            
        except Exception as e:
            self.stats['update_errors'] += 1
            
            audit_log(
                action="cve_source_load",
                resource=source_name,
                status="failure",
                details={
                    "url": url,
                    "error": str(e),
                }
            )
            
            raise CVESourceError(f"Failed to load CVEs from {source_name}: {e}")
    
    def _add_to_memory_cache(self, cves: List[CVE]):
        """Add CVEs to in-memory cache and update indexes"""
        for cve in cves:
            # Add to main cache
            self._cve_cache[cve.cve_id] = cve
            
            # Update indexes
            # By vendor
            for product in cve.affected_products:
                vendor = product.vendor.lower()
                if vendor not in self._cve_index['by_vendor']:
                    self._cve_index['by_vendor'][vendor] = []
                if cve.cve_id not in self._cve_index['by_vendor'][vendor]:
                    self._cve_index['by_vendor'][vendor].append(cve.cve_id)
                
                # By product
                product_key = f"{vendor}:{product.product.lower()}"
                if product_key not in self._cve_index['by_product']:
                    self._cve_index['by_product'][product_key] = []
                if cve.cve_id not in self._cve_index['by_product'][product_key]:
                    self._cve_index['by_product'][product_key].append(cve.cve_id)
            
            # By CVSS score range
            score_range = self._get_score_range(cve.max_score)
            if score_range not in self._cve_index['by_cvss']:
                self._cve_index['by_cvss'][score_range] = []
            if cve.cve_id not in self._cve_index['by_cvss'][score_range]:
                self._cve_index['by_cvss'][score_range].append(cve.cve_id)
            
            # By year
            year = str(cve.year)
            if year not in self._cve_index['by_year']:
                self._cve_index['by_year'][year] = []
            if cve.cve_id not in self._cve_index['by_year'][year]:
                self._cve_index['by_year'][year].append(cve.cve_id)
        
        self.stats['total_cves'] = len(self._cve_cache)
    
    @staticmethod
    def _get_score_range(score: float) -> str:
        """Convert score to range string"""
        if score == 0.0:
            return "0.0"
        elif score < 4.0:
            return "1.0-3.9"
        elif score < 7.0:
            return "4.0-6.9"
        elif score < 9.0:
            return "7.0-8.9"
        else:
            return "9.0-10.0"
    
    def update_database(self, force: bool = False) -> Dict[str, Any]:
        """
        Update CVE database from all sources
        
        Args:
            force: Force update even if not needed
            
        Returns:
            Dictionary with update results
        """
        results = {
            'timestamp': datetime.now().isoformat(),
            'sources': {},
            'total_cves_loaded': 0,
            'errors': 0,
        }
        
        self.logger.info("Starting CVE database update")
        
        for source_name in self.CVE_SOURCES:
            try:
                cves = self.load_cves_from_source(source_name, force_refresh=force)
                results['sources'][source_name] = {
                    'status': 'success',
                    'cves_loaded': len(cves),
                }
                results['total_cves_loaded'] += len(cves)
                
            except Exception as e:
                self.logger.error(f"Failed to update from {source_name}: {e}")
                results['sources'][source_name] = {
                    'status': 'error',
                    'error': str(e),
                    'cves_loaded': 0,
                }
                results['errors'] += 1
        
        # Update statistics
        self.stats['last_update'] = datetime.now()
        
        audit_log(
            action="cve_database_update",
            resource="CVEIngestor",
            status="success" if results['errors'] == 0 else "partial",
            details=results
        )
        
        return results
    
    def get_cve(self, cve_id: str) -> Optional[CVE]:
        """
        Get CVE by ID
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")
            
        Returns:
            CVE object or None if not found
        """
        # Normalize CVE ID
        cve_id = cve_id.upper()
        if not cve_id.startswith('CVE-'):
            cve_id = f"CVE-{cve_id}"
        
        return self._cve_cache.get(cve_id)
    
    def search_cves(
        self,
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        min_cvss_score: Optional[float] = None,
        max_cvss_score: Optional[float] = None,
        year: Optional[int] = None,
        severity: Optional[CVSSSeverity] = None,
        keyword: Optional[str] = None,
        limit: int = 100
    ) -> List[CVE]:
        """
        Search CVEs by various criteria
        
        Args:
            vendor: Vendor name to filter by
            product: Product name to filter by
            min_cvss_score: Minimum CVSS score
            max_cvss_score: Maximum CVSS score
            year: Year of CVE
            severity: Severity level
            keyword: Keyword to search in description
            limit: Maximum number of results
            
        Returns:
            List of matching CVE objects
        """
        # Start with all CVE IDs
        if vendor or product:
            # Use index for vendor/product search
            cve_ids = self._search_by_vendor_product(vendor, product)
        elif year:
            # Use year index
            year_str = str(year)
            cve_ids = self._cve_index['by_year'].get(year_str, [])
        else:
            # Start with all CVEs
            cve_ids = list(self._cve_cache.keys())
        
        # Apply filters
        results = []
        for cve_id in cve_ids[:limit * 10]:  # Check more than limit for filtering
            cve = self._cve_cache.get(cve_id)
            if not cve:
                continue
            
            # Apply filters
            if min_cvss_score is not None and cve.max_score < min_cvss_score:
                continue
            
            if max_cvss_score is not None and cve.max_score > max_cvss_score:
                continue
            
            if severity is not None and cve.severity != severity:
                continue
            
            if keyword:
                keyword_lower = keyword.lower()
                if (keyword_lower not in cve.description.lower() and
                    not any(keyword_lower in ref.url.lower() for ref in cve.references)):
                    continue
            
            results.append(cve)
            
            # Stop if we have enough results
            if len(results) >= limit:
                break
        
        return results
    
    def _search_by_vendor_product(
        self,
        vendor: Optional[str],
        product: Optional[str]
    ) -> List[str]:
        """Search CVE IDs by vendor and/or product"""
        if vendor and product:
            # Search by both vendor and product
            vendor_lower = vendor.lower()
            product_lower = product.lower()
            product_key = f"{vendor_lower}:{product_lower}"
            
            # Get CVEs for this specific product
            cve_ids = self._cve_index['by_product'].get(product_key, [])
            
            # Also get CVEs for vendor (broader search)
            vendor_cves = self._cve_index['by_vendor'].get(vendor_lower, [])
            
            # Combine and deduplicate
            all_cves = set(cve_ids) | set(vendor_cves)
            return list(all_cves)
        
        elif vendor:
            # Search by vendor only
            vendor_lower = vendor.lower()
            return self._cve_index['by_vendor'].get(vendor_lower, [])
        
        elif product:
            # Search by product (across all vendors)
            product_lower = product.lower()
            cve_ids = []
            
            for product_key in self._cve_index['by_product']:
                if product_key.endswith(f":{product_lower}"):
                    cve_ids.extend(self._cve_index['by_product'][product_key])
            
            return list(set(cve_ids))  # Deduplicate
        
        else:
            return list(self._cve_cache.keys())
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get CVE database statistics"""
        # Calculate severity distribution
        severity_counts = {s.value: 0 for s in CVSSSeverity}
        score_ranges = {
            "0.0": 0,
            "1.0-3.9": 0,
            "4.0-6.9": 0,
            "7.0-8.9": 0,
            "9.0-10.0": 0,
        }
        
        year_counts = {}
        
        for cve in self._cve_cache.values():
            # Severity
            severity_counts[cve.severity.value] += 1
            
            # Score range
            score_range = self._get_score_range(cve.max_score)
            score_ranges[score_range] += 1
            
            # Year
            year = str(cve.year)
            year_counts[year] = year_counts.get(year, 0) + 1
        
        # Vendor/product statistics
        vendor_counts = {}
        product_counts = {}
        
        for cve in self._cve_cache.values():
            for affected in cve.affected_products:
                vendor = affected.vendor
                product = f"{vendor}:{affected.product}"
                
                vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1
                product_counts[product] = product_counts.get(product, 0) + 1
        
        # Top vendors/products
        top_vendors = sorted(
            vendor_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        top_products = sorted(
            product_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        return {
            'total_cves': self.stats['total_cves'],
            'last_update': self.stats['last_update'].isoformat() if self.stats['last_update'] else None,
            'sources_loaded': list(self.stats['sources_loaded']),
            'severity_distribution': severity_counts,
            'score_distribution': score_ranges,
            'year_distribution': dict(sorted(year_counts.items())),
            'top_vendors': top_vendors,
            'top_products': top_products,
            'update_errors': self.stats['update_errors'],
        }
    
    def export_to_json(self, output_file: str) -> str:
        """
        Export CVE database to JSON file
        
        Args:
            output_file: Path to output JSON file
            
        Returns:
            Path to exported file
        """
        output_path = Path(output_file)
        
        # Prepare data for export
        export_data = {
            'metadata': {
                'export_date': datetime.now().isoformat(),
                'total_cves': self.stats['total_cves'],
                'version': '1.0',
            },
            'cves': [cve.to_dict() for cve in self._cve_cache.values()],
            'statistics': self.get_statistics(),
        }
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        # Set restrictive permissions
        output_path.chmod(0o600)
        
        self.logger.info(f"Exported {self.stats['total_cves']} CVEs to {output_path}")
        
        return str(output_path)
    
    def import_from_json(self, input_file: str) -> int:
        """
        Import CVE database from JSON file
        
        Args:
            input_file: Path to input JSON file
            
        Returns:
            Number of CVEs imported
        """
        input_path = Path(input_file)
        
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")
        
        # Read and parse JSON
        with open(input_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Parse CVEs
        cve_dicts = data.get('cves', [])
        cves = []
        
        for cve_dict in cve_dicts:
            try:
                # Convert dictionary back to CVE object
                cve = self._dict_to_cve(cve_dict)
                if cve:
                    cves.append(cve)
            except Exception as e:
                self.logger.warning(f"Failed to parse CVE from import: {e}")
                continue
        
        # Add to memory cache
        self._add_to_memory_cache(cves)
        
        self.logger.info(f"Imported {len(cves)} CVEs from {input_path}")
        
        return len(cves)
    
    def _dict_to_cve(self, cve_dict: Dict[str, Any]) -> Optional[CVE]:
        """Convert dictionary to CVE object"""
        try:
            # Parse dates
            published_date = None
            if cve_dict.get('published_date'):
                published_date = datetime.fromisoformat(cve_dict['published_date'])
            
            last_modified_date = None
            if cve_dict.get('last_modified_date'):
                last_modified_date = datetime.fromisoformat(cve_dict['last_modified_date'])
            
            ingested_at = datetime.fromisoformat(cve_dict.get('ingested_at', datetime.now().isoformat()))
            last_updated = datetime.fromisoformat(cve_dict.get('last_updated', datetime.now().isoformat()))
            
            # Parse CVSS metrics if present
            cvss_metrics = None
            if cve_dict.get('cvss_metrics'):
                cvss_dict = cve_dict['cvss_metrics']
                try:
                    cvss_metrics = CVSSMetrics.from_vector_string(cvss_dict['vector_string'])
                except:
                    pass
            
            # Parse affected products
            affected_products = []
            for product_dict in cve_dict.get('affected_products', []):
                affected = AffectedProduct(**product_dict)
                affected_products.append(affected)
            
            # Parse references
            references = []
            for ref_dict in cve_dict.get('references', []):
                reference = CVEReference(**ref_dict)
                references.append(reference)
            
            # Create CVE
            return CVE(
                cve_id=cve_dict['cve_id'],
                status=CVEStatus(cve_dict['status']),
                description=cve_dict['description'],
                published_date=published_date,
                last_modified_date=last_modified_date,
                cvss_metrics=cvss_metrics,
                affected_products=affected_products,
                references=references,
                cwe_ids=cve_dict.get('cwe_ids', []),
                assigner=cve_dict.get('assigner'),
                source=cve_dict.get('source', 'import'),
                ingested_at=ingested_at,
                last_updated=last_updated,
            )
            
        except Exception as e:
            self.logger.warning(f"Failed to convert dict to CVE: {e}")
            return None

# Convenience functions
def load_cve_database(
    cache_dir: Optional[str] = None,
    update: bool = True
) -> CVEIngestor:
    """
    Convenience function to load or create CVE database
    
    Args:
        cache_dir: Cache directory
        update: Whether to update from sources
        
    Returns:
        Initialized CVEIngestor instance
    """
    ingestor = CVEIngestor(cache_dir=cache_dir)
    
    if update:
        ingestor.update_database()
    
    return ingestor

def get_cve_by_id(cve_id: str, ingestor: Optional[CVEIngestor] = None) -> Optional[CVE]:
    """
    Get CVE by ID, creating ingestor if needed
    
    Args:
        cve_id: CVE identifier
        ingestor: Existing CVEIngestor instance (optional)
        
    Returns:
        CVE object or None
    """
    if ingestor is None:
        ingestor = load_cve_database(update=False)
    
    return ingestor.get_cve(cve_id)