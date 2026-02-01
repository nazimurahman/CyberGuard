"""
CyberGuard Web Security Scanner - Command Line Interface
This script provides a command-line interface for running security scans.
Purpose: Main entry point for the security scanner that coordinates scanning,
         analysis, and reporting functions through a user-friendly CLI.
"""

import os
import sys
import json
import time
import argparse
import threading
import concurrent.futures
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

# Add project root to Python path for module imports
# This ensures that modules in the src directory can be imported correctly
project_root = Path(__file__).parent.parent  # Go up one level from scripts directory
sys.path.insert(0, str(project_root))  # Add project root to Python's module search path

# Import scanner components - using try/except for better error handling
# These imports bring in the core scanning and analysis functionality
try:
    from src.web_security.scanner import WebSecurityScanner  # Main web scanner
    from src.agents.agent_orchestrator import AgentOrchestrator  # Coordinates AI agents
    from src.agents.threat_detection_agent import WebThreatDetectionAgent  # Threat detection AI
    from src.agents.traffic_anomaly_agent import TrafficAnomalyAgent  # Traffic analysis AI
    from src.agents.bot_detection_agent import BotDetectionAgent  # Bot detection AI
except ImportError as e:
    # Graceful error handling if dependencies aren't available
    print(f"Error importing modules: {e}")
    print("Please ensure all required modules are installed and available.")
    sys.exit(1)  # Exit with error code


class SecurityScanCLI:
    """
    Command Line Interface for CyberGuard Security Scanner
    Purpose: This class encapsulates all CLI functionality including:
             - Configuration management
             - Scanner initialization
             - URL scanning (single and batch)
             - Report generation
             - Progress tracking and statistics
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the security scanner CLI
        Purpose: Set up all necessary components, load configuration, and prepare for scanning
        
        Args:
            config_path: Optional path to configuration file for custom settings
        """
        # Initialize timing and tracking variables
        self.start_time = time.time()  # Record when scanning starts for duration calculation
        self.scan_results = []  # Store all scan results for reporting
        self.total_scans = 0  # Count of URLs to be scanned
        self.completed_scans = 0  # Count of successfully completed scans
        self.failed_scans = 0  # Count of failed scans for error reporting
        
        # Load configuration from file or use defaults
        # This determines scanner behavior (timeouts, threads, features enabled)
        self.config = self._load_configuration(config_path)
        
        # Initialize scanner components (web scanner and AI agents)
        self._initialize_scanner()
        
        # Initialize statistics dictionary to track scanning metrics
        self.statistics = {
            'total_urls': 0,  # Will be updated during scanning
            'vulnerabilities_found': 0,  # Total vulnerabilities across all scans
            'critical_vulnerabilities': 0,  # Only count critical severity vulnerabilities
            'scan_duration': 0,  # Total time spent scanning
            'avg_scan_time': 0  # Average time per scan
        }
        
        # Define supported output formats for reports
        self.output_formats = ['json', 'html', 'txt', 'pdf']
        
        # ANSI color codes for console output
        # Purpose: Provide colored output for better user experience and readability
        # \033[ is the escape sequence, 91m means red foreground, 0m resets formatting
        self.COLORS = {
            'RED': '\033[91m',      # For errors and critical issues
            'GREEN': '\033[92m',    # For success messages
            'YELLOW': '\033[93m',   # For warnings
            'BLUE': '\033[94m',     # For informational messages
            'MAGENTA': '\033[95m',  # For highlighting
            'CYAN': '\033[96m',     # For scan details
            'WHITE': '\033[97m',    # For normal text
            'RESET': '\033[0m',     # Reset to terminal default
            'BOLD': '\033[1m'       # For bold text (headers, important info)
        }
    
    def _load_configuration(self, config_path: Optional[str]) -> Dict[str, Any]:
        """
        Load configuration from file or use defaults
        Purpose: Read scanner settings from YAML/JSON config file or use sensible defaults
        
        Args:
            config_path: Path to configuration file (YAML/JSON format)
            
        Returns:
            Dictionary with configuration values for all scanner components
        """
        # Default configuration values that provide safe, reasonable defaults
        # These ensure the scanner works even without a config file
        default_config = {
            'scan': {
                'timeout': 30,      # Maximum time (seconds) to wait for a website response
                'max_depth': 2,     # How many levels deep to crawl from the initial URL
                'max_pages': 100,   # Maximum number of pages to scan per website
                'threads': 5,       # Number of concurrent scans for batch processing
                'user_agent': 'CyberGuard-Security-Scanner/1.0'  # Browser identity to use
            },
            'output': {
                'directory': 'reports',  # Where to save generated reports
                'format': 'json',        # Default report format
                'verbose': False,        # Whether to show detailed debugging info
                'save_raw': True         # Whether to keep raw scan data in reports
            },
            'security': {
                'check_headers': True,   # Check HTTP security headers (CSP, HSTS, etc.)
                'check_forms': True,     # Analyze HTML forms for vulnerabilities
                'check_scripts': True,   # Analyze JavaScript for security issues
                'check_endpoints': True, # Check API endpoints and hidden URLs
                'enable_crawling': True  # Enable website crawling to discover more pages
            }
        }
        
        # Load configuration from file if provided and exists
        if config_path and os.path.exists(config_path):
            try:
                import yaml  # Import here to avoid unnecessary dependency if not used
                with open(config_path, 'r') as f:
                    file_config = yaml.safe_load(f)  # Parse YAML configuration
                
                # Recursively merge file config with defaults
                # This allows partial config files that only override some settings
                self._merge_dicts(default_config, file_config)
                print(f"{self.COLORS['GREEN']}✓ Configuration loaded from {config_path}{self.COLORS['RESET']}")
                
            except Exception as e:
                # Graceful degradation if config file is invalid or unreadable
                print(f"{self.COLORS['YELLOW']}⚠ Warning: Failed to load config: {e}{self.COLORS['RESET']}")
                print(f"{self.COLORS['BLUE']}ℹ Using default configuration{self.COLORS['RESET']}")
        
        return default_config
    
    def _merge_dicts(self, base: Dict, overlay: Dict) -> None:
        """
        Recursively merge two dictionaries (overlay into base)
        Purpose: Combine default config with user config, with user values taking precedence
        
        Args:
            base: Base dictionary to merge into (modified in-place)
            overlay: Dictionary with overlay values to apply on top of base
        """
        for key, value in overlay.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                # Recursively merge nested dictionaries (for nested config sections)
                self._merge_dicts(base[key], value)
            else:
                # Replace or add the key-value pair from overlay
                base[key] = value
    
    def _initialize_scanner(self) -> None:
        """
        Initialize the web security scanner and AI agents
        Purpose: Create and configure all scanner components for use
        """
        print(f"{self.COLORS['BLUE']}Initializing CyberGuard Security Scanner...{self.COLORS['RESET']}")
        
        # Initialize web security scanner with configuration
        # This creates the core scanner that will examine websites
        self.scanner = WebSecurityScanner(self.config.get('scan', {}))
        
        # Initialize agent orchestrator for coordinating AI agents
        # The orchestrator manages communication between different AI agents
        self.orchestrator = AgentOrchestrator(state_dim=512)  # 512-dimensional state space
        
        # Register security agents
        print(f"{self.COLORS['BLUE']}Registering security agents...{self.COLORS['RESET']}")
        
        # Create instances of different security agents
        # Each agent specializes in a different aspect of security analysis
        agents = [
            WebThreatDetectionAgent("threat_detection_001"),  # Detects malware, exploits
            TrafficAnomalyAgent("traffic_anomaly_001"),       # Analyzes traffic patterns
            BotDetectionAgent("bot_detection_001")            # Identifies bot activity
        ]
        
        # Register each agent with the orchestrator
        # This enables the orchestrator to coordinate their analysis
        for agent in agents:
            self.orchestrator.register_agent(agent)
            print(f"  {self.COLORS['GREEN']}✓{self.COLORS['RESET']} {agent.name}")
        
        print(f"{self.COLORS['GREEN']}Scanner initialized with {len(agents)} agents{self.COLORS['RESET']}")
    
    def print_banner(self) -> None:
        """Print CyberGuard banner to console
        Purpose: Display a professional-looking banner at startup for branding and UX
        """
        banner = f"""
{self.COLORS['CYAN']}{self.COLORS['BOLD']}
╔══════════════════════════════════════════════════════════════╗
║           CYBERGUARD SECURITY SCANNER                        ║
║           Web Security AI System v1.0                        ║
╚══════════════════════════════════════════════════════════════╝
{self.COLORS['RESET']}
        """
        print(banner)
    
    def validate_url(self, url: str) -> bool:
        """
        Validate URL format using regular expression
        Purpose: Ensure URLs are properly formatted before attempting to scan them
        
        Args:
            url: URL string to validate (e.g., "https://example.com/path")
            
        Returns:
            True if URL format is valid, False otherwise
        """
        import re
        
        # Comprehensive URL pattern matching http/https URLs
        # Regular expression breakdown:
        # ^https?://                        - Starts with http:// or https://
        # (?:                               - Non-capturing group for domain/IP
        #   (?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+  - Domain name parts
        #   [A-Z]{2,6}\.?|                  - Top-level domain (2-6 chars)
        #   localhost|                      - Allow localhost for testing
        #   \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}  - IPv4 address
        # )
        # (?::\d+)?                         - Optional port number (:80, :443, etc.)
        # (?:/?|[/?]\S+)$                   - Optional path and query string
        url_pattern = re.compile(
            r'^https?://'  # Match http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # Domain names
            r'localhost|'  # Allow localhost
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IPv4 addresses
            r'(?::\d+)?'  # Optional port number
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)  # Path and query string
        
        return bool(url_pattern.match(url))
    
    def scan_single_url(self, url: str, scan_id: str = None) -> Dict[str, Any]:
        """
        Perform comprehensive security scan on a single URL
        Purpose: Main scanning function that coordinates scanning and AI analysis
        
        Args:
            url: URL to scan (must be http:// or https://)
            scan_id: Optional identifier for the scan (useful for batch processing)
            
        Returns:
            Dictionary containing complete scan results including:
            - Scan metadata (ID, timestamp, duration)
            - Raw scan data from web scanner
            - AI analysis results
            - Risk assessment and recommended actions
        """
        # Validate URL format before proceeding
        if not self.validate_url(url):
            return {
                'url': url,
                'error': 'Invalid URL format',
                'status': 'failed'
            }
        
        print(f"\n{self.COLORS['BLUE']} Scanning: {url}{self.COLORS['RESET']}")
        
        try:
            # Phase 1: Perform web security scan
            # This collects raw data about the website (headers, forms, scripts, etc.)
            scan_start = time.time()
            scan_data = self.scanner.scan_website(url)  # Core scanning operation
            scan_duration = time.time() - scan_start  # Measure how long scanning took
            
            # Phase 2: Analyze results with AI agents
            # The orchestrator distributes scan data to all registered AI agents
            analysis_start = time.time()
            analysis_results = self.orchestrator.coordinate_analysis({
                'url': url,
                'scan_data': scan_data,
                'timestamp': datetime.now().isoformat()
            })
            analysis_duration = time.time() - analysis_start  # Measure AI analysis time
            
            # Compile comprehensive results
            # Combine raw scan data with AI analysis into a single report
            result = {
                'scan_id': scan_id or f"scan_{int(time.time())}",  # Unique ID for this scan
                'url': url,  # The scanned URL
                'timestamp': datetime.now().isoformat(),  # When scan occurred
                'scan_duration': scan_duration,  # Time spent on web scanning
                'analysis_duration': analysis_duration,  # Time spent on AI analysis
                'total_duration': scan_duration + analysis_duration,  # Total time
                'scan_data': scan_data,  # Raw data from web scanner
                'analysis': analysis_results,  # AI analysis results
                'status': 'completed',  # Scan completion status
                'risk_score': analysis_results.get('final_decision', {}).get('threat_level', 0),  # 0-1 risk score
                'action': analysis_results.get('final_decision', {}).get('action', 'UNKNOWN')  # Recommended action
            }
            
            # Update statistics with this scan's results
            self._update_statistics(result)
            
            # Print summary to console for immediate user feedback
            self._print_scan_summary(result)
            
            return result
            
        except Exception as e:
            # Handle scan failures gracefully
            # This prevents one failed scan from crashing the entire process
            error_result = {
                'scan_id': scan_id or f"scan_{int(time.time())}",
                'url': url,
                'timestamp': datetime.now().isoformat(),
                'error': str(e),  # Capture error message for debugging
                'status': 'failed'
            }
            
            print(f"{self.COLORS['RED']}✗ Scan failed: {e}{self.COLORS['RESET']}")
            self.failed_scans += 1  # Track failure for statistics
            
            return error_result
    
    def scan_batch(self, urls: List[str], max_workers: int = 5) -> List[Dict[str, Any]]:
        """
        Perform concurrent security scans on multiple URLs
        Purpose: Efficiently scan many URLs in parallel using threading
        
        Args:
            urls: List of URLs to scan
            max_workers: Maximum number of concurrent scans (threads)
            
        Returns:
            List of scan results for all URLs (preserving order where possible)
        """
        # Initialize counters for progress tracking
        self.total_scans = len(urls)
        self.completed_scans = 0
        self.failed_scans = 0
        
        print(f"\n{self.COLORS['BLUE']}📋 Batch scan starting: {len(urls)} URLs{self.COLORS['RESET']}")
        print(f"{self.COLORS['BLUE']}🧵 Concurrent workers: {max_workers}{self.COLORS['RESET']}")
        
        # Start progress display in separate thread
        # This shows a progress bar while scans are running
        progress_thread = threading.Thread(target=self._show_progress)
        progress_thread.daemon = True  # Thread exits when main program exits
        progress_thread.start()
        
        # Perform concurrent scans using thread pool
        # ThreadPoolExecutor manages the thread pool and task distribution
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all scan tasks to executor
            # Each URL gets its own scan task submitted to the thread pool
            future_to_url = {
                executor.submit(self.scan_single_url, url, f"batch_scan_{i}"): url
                for i, url in enumerate(urls)
            }
            
            # Process completed scans as they finish
            # as_completed yields futures as they complete (not necessarily in order)
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]  # Get URL associated with this future
                try:
                    # Get result with timeout (scan timeout + 30 seconds buffer)
                    result = future.result(timeout=self.config['scan']['timeout'] + 30)
                    results.append(result)
                except concurrent.futures.TimeoutError:
                    # Handle timeout errors (scans taking too long)
                    error_result = {
                        'url': url,
                        'error': 'Scan timeout',
                        'status': 'failed'
                    }
                    results.append(error_result)
                    self.failed_scans += 1
                except Exception as e:
                    # Handle other exceptions (network errors, parsing errors, etc.)
                    error_result = {
                        'url': url,
                        'error': str(e),
                        'status': 'failed'
                    }
                    results.append(error_result)
                    self.failed_scans += 1
        
        return results
    
    def _show_progress(self) -> None:
        """
        Display progress bar for batch scans (runs in separate thread)
        Purpose: Provide visual feedback during long batch scans
        """
        while self.completed_scans < self.total_scans:
            completed = self.completed_scans
            total = self.total_scans
            
            if total > 0:
                # Calculate progress percentage
                percentage = (completed / total) * 100
                bar_length = 40  # Width of progress bar in characters
                filled_length = int(bar_length * completed // total)
                # Create bar with filled (█) and empty (░) segments
                bar = '█' * filled_length + '░' * (bar_length - filled_length)
                
                # Write progress bar to console (using \r to overwrite line)
                sys.stdout.write(
                    f'\r{self.COLORS["BLUE"]}Progress: [{bar}] {percentage:.1f}% '
                    f'({completed}/{total} URLs){self.COLORS["RESET"]}'
                )
                sys.stdout.flush()  # Ensure immediate display
            
            time.sleep(0.5)  # Update every 500ms (not too frequent to avoid flickering)
    
    def _update_statistics(self, scan_result: Dict[str, Any]) -> None:
        """
        Update global statistics with results from a single scan
        Purpose: Aggregate metrics across all scans for summary reporting
        
        Args:
            scan_result: Dictionary containing scan results
        """
        self.completed_scans += 1  # Increment completed scan counter
        
        # Only count vulnerabilities for successful scans
        if scan_result.get('status') == 'completed':
            scan_data = scan_result.get('scan_data', {})
            vulnerabilities = scan_data.get('vulnerabilities', [])
            
            # Count total vulnerabilities found in this scan
            self.statistics['vulnerabilities_found'] += len(vulnerabilities)
            
            # Count critical vulnerabilities specifically
            # Critical vulnerabilities require immediate attention
            critical = sum(1 for v in vulnerabilities 
                          if v.get('severity') == 'CRITICAL')
            self.statistics['critical_vulnerabilities'] += critical
            
            # Update timing statistics
            self.statistics['scan_duration'] += scan_result.get('total_duration', 0)
            if self.completed_scans > 0:
                # Calculate running average of scan times
                self.statistics['avg_scan_time'] = (
                    self.statistics['scan_duration'] / self.completed_scans
                )
    
    def _print_scan_summary(self, scan_result: Dict[str, Any]) -> None:
        """
        Print formatted summary of scan results to console
        Purpose: Provide immediate, readable feedback after each scan
        
        Args:
            scan_result: Dictionary containing scan results
        """
        # Extract key information from results
        url = scan_result.get('url', 'Unknown')
        status = scan_result.get('status', 'unknown')
        risk_score = scan_result.get('risk_score', 0)  # Risk score from 0 (safe) to 1 (critical)
        duration = scan_result.get('total_duration', 0)
        
        # Determine color and text based on risk score
        # Color coding helps users quickly identify problem areas
        if risk_score > 0.8:
            risk_color = self.COLORS['RED']
            risk_text = 'CRITICAL'  # Immediate action required
        elif risk_score > 0.6:
            risk_color = self.COLORS['YELLOW']
            risk_text = 'HIGH'  # High priority to fix
        elif risk_score > 0.4:
            risk_color = self.COLORS['CYAN']
            risk_text = 'MEDIUM'  # Should be addressed
        elif risk_score > 0.2:
            risk_color = self.COLORS['BLUE']
            risk_text = 'LOW'  # Low priority
        else:
            risk_color = self.COLORS['GREEN']
            risk_text = 'INFORMATIONAL'  # No immediate threat
        
        # Print formatted summary with consistent indentation
        print(f"\n{self.COLORS['WHITE']}{self.COLORS['BOLD']}Scan Summary:{self.COLORS['RESET']}")
        print(f"  URL: {url}")
        # Color-code status (green for success, red for failure)
        status_color = self.COLORS['GREEN'] if status == 'completed' else self.COLORS['RED']
        print(f"  Status: {status_color}{status}{self.COLORS['RESET']}")
        print(f"  Risk: {risk_color}{risk_text} ({risk_score:.2f}){self.COLORS['RESET']}")
        print(f"  Duration: {duration:.2f}s")
        
        # Show vulnerability count and top 3 vulnerabilities
        if scan_result.get('scan_data', {}).get('vulnerabilities'):
            vulns = scan_result['scan_data']['vulnerabilities']
            print(f"  Vulnerabilities: {len(vulns)} found")
            
            # Display top 3 vulnerabilities with severity colors
            # Showing only top 3 prevents information overload in console
            for i, vuln in enumerate(vulns[:3], 1):
                severity = vuln.get('severity', 'UNKNOWN')
                severity_color = {
                    'CRITICAL': self.COLORS['RED'],
                    'HIGH': self.COLORS['YELLOW'],
                    'MEDIUM': self.COLORS['CYAN'],
                    'LOW': self.COLORS['BLUE']
                }.get(severity, self.COLORS['WHITE'])
                
                print(f"    {i}. {severity_color}{severity}{self.COLORS['RESET']}: {vuln.get('type', 'Unknown')}")
    
    def generate_report(self, results: List[Dict[str, Any]], 
                       format: str = 'json',
                       output_dir: str = 'reports') -> str:
        """
        Generate scan report in specified format
        Purpose: Create professional reports from scan results for documentation and sharing
        
        Args:
            results: List of scan results to include in report
            format: Output format (json, html, txt, pdf) - each has different use cases
            output_dir: Directory to save reports
            
        Returns:
            Path to generated report file
        """
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate timestamp for unique filename
        # This prevents overwriting previous reports
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')  # Format: 20240122_143022
        filename = f"cyberguard_scan_report_{timestamp}"
        
        # Generate report based on requested format
        # Each format serves different purposes:
        # - JSON: Machine-readable, for integration with other tools
        # - HTML: Human-readable, good for sharing with non-technical stakeholders
        # - TXT: Simple, no formatting required
        # - PDF: Professional, printable format
        if format == 'json':
            report_path = self._generate_json_report(results, output_dir, filename)
        elif format == 'html':
            report_path = self._generate_html_report(results, output_dir, filename)
        elif format == 'txt':
            report_path = self._generate_text_report(results, output_dir, filename)
        elif format == 'pdf':
            report_path = self._generate_pdf_report(results, output_dir, filename)
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        return report_path
    
    def _generate_json_report(self, results: List[Dict[str, Any]], 
                            output_dir: str, filename: str) -> str:
        """
        Generate JSON report with all scan data
        Purpose: Create machine-readable output for integration with other security tools
        
        Args:
            results: List of scan results
            output_dir: Output directory
            filename: Base filename (without extension)
            
        Returns:
            Path to JSON report file
        """
        report_path = os.path.join(output_dir, f"{filename}.json")
        
        # Structure report data in a logical hierarchy
        report_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),  # ISO 8601 timestamp
                'cyberguard_version': '1.0.0',  # Scanner version for compatibility
                'total_scans': len(results),  # How many scans were attempted
                'successful_scans': sum(1 for r in results if r.get('status') == 'completed'),
                'failed_scans': sum(1 for r in results if r.get('status') == 'failed'),
                'scan_duration': time.time() - self.start_time  # Total time for all scans
            },
            'statistics': self.statistics,  # Aggregated statistics
            'results': results,  # Raw scan results (preserving all data)
            'summary': self._generate_summary_statistics(results)  # Derived insights
        }
        
        # Write JSON to file with pretty printing
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)  # default=str handles datetime objects
        
        print(f"{self.COLORS['GREEN']}✓ JSON report saved: {report_path}{self.COLORS['RESET']}")
        return report_path
    
    def _generate_html_report(self, results: List[Dict[str, Any]], 
                            output_dir: str, filename: str) -> str:
        """
        Generate HTML report with formatted output
        Purpose: Create visually appealing, interactive report for human consumption
        
        Args:
            results: List of scan results
            output_dir: Output directory
            filename: Base filename
            
        Returns:
            Path to HTML report file
        """
        report_path = os.path.join(output_dir, f"{filename}.html")
        
        # Generate HTML content with inline CSS for portability
        html_content = self._create_html_content(results)
        
        # Write HTML to file
        with open(report_path, 'w') as f:
            f.write(html_content)
        
        print(f"{self.COLORS['GREEN']}✓ HTML report saved: {report_path}{self.COLORS['RESET']}")
        return report_path
    
    def _create_html_content(self, results: List[Dict[str, Any]]) -> str:
        """
        Create HTML content for report
        Purpose: Build the complete HTML document with styling and data
        
        Args:
            results: List of scan results
            
        Returns:
            HTML content as string with embedded CSS and data
        """
        # Filter completed results (failed scans handled separately)
        completed_results = [r for r in results if r.get('status') == 'completed']
        
        # Calculate vulnerability statistics for the dashboard
        total_vulns = sum(len(r.get('scan_data', {}).get('vulnerabilities', [])) 
                         for r in completed_results)
        
        # Count critical vulnerabilities specifically (these need special attention)
        critical_vulns = sum(
            sum(1 for v in r.get('scan_data', {}).get('vulnerabilities', [])
                if v.get('severity') == 'CRITICAL')
            for r in completed_results
        )
        
        # Build HTML structure with inline CSS
        # Inline CSS ensures the report works even when emailed or moved
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberGuard Security Scan Report</title>
    <style>
        /* CSS reset and base styles */
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        
        /* Header styles */
        .header {{ text-align: center; margin-bottom: 40px; }}
        .header h1 {{ color: #2c3e50; margin-bottom: 10px; }}
        .header .subtitle {{ color: #7f8c8d; font-size: 18px; }}
        
        /* Statistics dashboard using CSS Grid */
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 40px; }}
        .stat-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #3498db; }}
        .stat-card.critical {{ border-left-color: #e74c3c; }}  /* Red for critical */
        .stat-card.high {{ border-left-color: #f39c12; }}     /* Orange for high */
        .stat-card.medium {{ border-left-color: #3498db; }}   /* Blue for medium */
        .stat-card.low {{ border-left-color: #2ecc71; }}      /* Green for low */
        .stat-value {{ font-size: 32px; font-weight: bold; margin: 10px 0; }}
        .stat-label {{ color: #7f8c8d; font-size: 14px; }}
        
        /* Scan results section */
        .scan-results {{ margin-top: 40px; }}
        .scan-item {{ background: #f8f9fa; margin-bottom: 20px; padding: 20px; border-radius: 8px; }}
        .scan-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }}
        .scan-url {{ font-weight: bold; color: #2c3e50; }}
        .scan-risk {{ padding: 5px 15px; border-radius: 20px; font-weight: bold; color: white; }}
        .risk-critical {{ background: #e74c3c; }}
        .risk-high {{ background: #f39c12; }}
        .risk-medium {{ background: #3498db; }}
        .risk-low {{ background: #2ecc71; }}
        
        /* Vulnerability items */
        .vulnerabilities {{ margin-top: 15px; }}
        .vuln-item {{ background: white; padding: 10px 15px; margin-bottom: 10px; border-radius: 5px; border-left: 4px solid #ddd; }}
        .vuln-critical {{ border-left-color: #e74c3c; }}
        .vuln-high {{ border-left-color: #f39c12; }}
        .vuln-medium {{ border-left-color: #3498db; }}
        .vuln-low {{ border-left-color: #2ecc71; }}
        
        /* Footer */
        .footer {{ margin-top: 40px; text-align: center; color: #7f8c8d; font-size: 14px; border-top: 1px solid #eee; padding-top: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1> CyberGuard Security Scan Report</h1>
            <div class="subtitle">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{len(results)}</div>
                <div class="stat-label">Total URLs Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{len(completed_results)}</div>
                <div class="stat-label">Successful Scans</div>
            </div>
            <div class="stat-card critical">
                <div class="stat-value">{critical_vulns}</div>
                <div class="stat-label">Critical Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{total_vulns}</div>
                <div class="stat-label">Total Vulnerabilities</div>
            </div>
        </div>
        
        <div class="scan-results">
            <h2>Scan Results</h2>
            {"".join(self._create_scan_item_html(r) for r in completed_results)}
        </div>
        
        <div class="footer">
            <p>Generated by CyberGuard Web Security AI System v1.0.0</p>
            <p>© {datetime.now().year} CyberGuard Security. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
        """
        
        return html
    
    def _create_scan_item_html(self, result: Dict[str, Any]) -> str:
        """
        Create HTML for a single scan result item
        Purpose: Generate consistent HTML for each scanned URL in the report
        
        Args:
            result: Single scan result dictionary
            
        Returns:
            HTML string for the scan item with risk indicators and vulnerability list
        """
        # Extract data from result for display
        url = result.get('url', 'Unknown')
        risk_score = result.get('risk_score', 0)  # Numerical risk score
        duration = result.get('total_duration', 0)  # How long the scan took
        vulnerabilities = result.get('scan_data', {}).get('vulnerabilities', [])
        
        # Determine risk level for styling
        # Same risk categorization as console output for consistency
        if risk_score > 0.8:
            risk_class = 'critical'
            risk_text = 'CRITICAL'
        elif risk_score > 0.6:
            risk_class = 'high'
            risk_text = 'HIGH'
        elif risk_score > 0.4:
            risk_class = 'medium'
            risk_text = 'MEDIUM'
        elif risk_score > 0.2:
            risk_class = 'low'
            risk_text = 'LOW'
        else:
            risk_class = 'low'
            risk_text = 'INFORMATIONAL'
        
        # Generate vulnerabilities HTML
        vulns_html = ""
        for vuln in vulnerabilities[:5]:  # Limit to first 5 vulnerabilities per URL
            severity = vuln.get('severity', 'UNKNOWN').lower()
            vulns_html += f"""
            <div class="vuln-item vuln-{severity}">
                <strong>{vuln.get('type', 'Unknown')}</strong> - {vuln.get('description', '')}
                <div style="font-size: 12px; color: #666; margin-top: 5px;">
                    Location: {vuln.get('location', 'Unknown')}
                </div>
            </div>
            """
        
        # Add message if more vulnerabilities exist beyond the first 5
        if len(vulnerabilities) > 5:
            vulns_html += f'<div style="text-align: center; color: #666; padding: 10px;">... and {len(vulnerabilities) - 5} more vulnerabilities</div>'
        
        # Return formatted HTML for this scan item
        return f"""
        <div class="scan-item">
            <div class="scan-header">
                <div class="scan-url">{url}</div>
                <div class="scan-risk risk-{risk_class}">{risk_text} ({risk_score:.2f})</div>
            </div>
            <div style="color: #666; font-size: 14px; margin-bottom: 15px;">
                Scan duration: {duration:.2f}s | Vulnerabilities: {len(vulnerabilities)}
            </div>
            <div class="vulnerabilities">
                {vulns_html if vulns_html else '<div style="color: #666; text-align: center;">No vulnerabilities found</div>'}
            </div>
        </div>
        """
    
    def _generate_text_report(self, results: List[Dict[str, Any]], 
                            output_dir: str, filename: str) -> str:
        """
        Generate plain text report
        Purpose: Create simple, no-formatting report for terminals or simple viewing
        
        Args:
            results: List of scan results
            output_dir: Output directory
            filename: Base filename
            
        Returns:
            Path to text report file
        """
        report_path = os.path.join(output_dir, f"{filename}.txt")
        
        # Create and write text content
        with open(report_path, 'w') as f:
            f.write(self._create_text_content(results))
        
        print(f"{self.COLORS['GREEN']}✓ Text report saved: {report_path}{self.COLORS['RESET']}")
        return report_path
    
    def _create_text_content(self, results: List[Dict[str, Any]]) -> str:
        """
        Create text content for report
        Purpose: Format scan results in plain text with ASCII art borders
        
        Args:
            results: List of scan results
            
        Returns:
            Text content as string with ASCII formatting
        """
        # Filter completed results
        completed_results = [r for r in results if r.get('status') == 'completed']
        
        # Build text report with ASCII formatting
        # = characters create visual sections in the report
        text = f"""
{'='*80}
CYBERGUARD SECURITY SCAN REPORT
{'='*80}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total URLs Scanned: {len(results)}
Successful Scans: {len(completed_results)}
Failed Scans: {len(results) - len(completed_results)}
Scan Duration: {time.time() - self.start_time:.2f} seconds

{'='*80}
SUMMARY STATISTICS
{'='*80}
Total Vulnerabilities Found: {self.statistics['vulnerabilities_found']}
Critical Vulnerabilities: {self.statistics['critical_vulnerabilities']}
Average Scan Time: {self.statistics['avg_scan_time']:.2f} seconds

{'='*80}
DETAILED RESULTS
{'='*80}
"""
        
        # Add detailed results for each URL
        for i, result in enumerate(completed_results, 1):
            url = result.get('url', 'Unknown')
            risk_score = result.get('risk_score', 0)
            vulnerabilities = result.get('scan_data', {}).get('vulnerabilities', [])
            
            text += f"\n{i}. {url}\n"
            text += f"   Risk Score: {risk_score:.2f}\n"
            text += f"   Vulnerabilities: {len(vulnerabilities)}\n"
            
            # List first 3 vulnerabilities with indentation
            for j, vuln in enumerate(vulnerabilities[:3], 1):
                text += f"   {j}. [{vuln.get('severity', 'UNKNOWN')}] {vuln.get('type', 'Unknown')}\n"
                text += f"      {vuln.get('description', '')}\n"
            
            # Indicate if more vulnerabilities exist beyond the first 3
            if len(vulnerabilities) > 3:
                text += f"   ... and {len(vulnerabilities) - 3} more\n"
            
            text += "-" * 80 + "\n"  # Separator between URLs
        
        # Add recommendations section
        # These are generic security recommendations based on common best practices
        text += f"""
{'='*80}
RECOMMENDATIONS
{'='*80}
1. Review critical and high severity vulnerabilities immediately
2. Implement security headers on all web applications
3. Regularly update threat intelligence feeds
4. Schedule recurring security scans
5. Monitor for new vulnerabilities in used frameworks

{'='*80}
END OF REPORT
{'='*80}
Generated by CyberGuard Web Security AI System v1.0.0
"""
        
        return text
    
    def _generate_pdf_report(self, results: List[Dict[str, Any]], 
                           output_dir: str, filename: str) -> str:
        """
        Generate PDF report (requires reportlab library)
        Purpose: Create professional, printable PDF reports
        
        Args:
            results: List of scan results
            output_dir: Output directory
            filename: Base filename
            
        Returns:
            Path to PDF report file (falls back to HTML if PDF generation fails)
        """
        try:
            # Import PDF generation libraries
            # ReportLab is a popular Python library for PDF generation
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter  # US Letter size paper
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch  # Measurement unit (1 inch = 72 points)
            
            report_path = os.path.join(output_dir, f"{filename}.pdf")
            
            # Create PDF document with margins
            # Margins ensure content doesn't get cut off when printing
            doc = SimpleDocTemplate(
                report_path,
                pagesize=letter,
                rightMargin=72,   # 1 inch right margin
                leftMargin=72,    # 1 inch left margin
                topMargin=72,     # 1 inch top margin
                bottomMargin=72   # 1 inch bottom margin
            )
            
            # Define styles for PDF
            styles = getSampleStyleSheet()  # Get default styles
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],  # Inherit from Heading1
                fontSize=24,      # Large font for title
                spaceAfter=30,    # Space after title paragraph
                textColor=colors.HexColor('#2c3e50')  # Dark blue color
            )
            
            # Build PDF content (story is ReportLab terminology for document content)
            story = []
            
            # Add title and generation timestamp
            story.append(Paragraph("CyberGuard Security Scan Report", title_style))
            story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
            story.append(Spacer(1, 20))  # Add vertical space (1 inch * 20/72 = ~0.28 inches)
            
            # Create summary table with key statistics
            completed = sum(1 for r in results if r.get('status') == 'completed')
            data = [
                ['Total URLs Scanned', str(len(results))],
                ['Successful Scans', str(completed)],
                ['Failed Scans', str(len(results) - completed)],
                ['Total Duration', f"{time.time() - self.start_time:.2f} seconds"],
                ['Vulnerabilities Found', str(self.statistics['vulnerabilities_found'])],
                ['Critical Vulnerabilities', str(self.statistics['critical_vulnerabilities'])]
            ]
            
            table = Table(data, colWidths=[3*inch, 2*inch])  # Column widths
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),  # Header row background
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),  # Header text color
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),  # Left align all cells
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),  # Bold header font
                ('FONTSIZE', (0, 0), (-1, 0), 14),  # Larger font for header
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),  # Padding below header
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),  # Data row background
                ('GRID', (0, 0), (-1, -1), 1, colors.black)  # Show grid lines
            ]))
            
            story.append(table)
            story.append(Spacer(1, 30))
            
            # Add results section with each URL and its risk score
            story.append(Paragraph("Scan Results", styles['Heading2']))
            
            # List results in numbered format
            for i, result in enumerate(results, 1):
                if result.get('status') == 'completed':
                    url = result.get('url', 'Unknown')
                    risk = result.get('risk_score', 0)
                    
                    story.append(Paragraph(f"{i}. {url}", styles['Normal']))
                    story.append(Paragraph(f"   Risk Score: {risk:.2f}", styles['Normal']))
                    story.append(Spacer(1, 10))  # Space between items
            
            # Generate PDF file
            doc.build(story)
            
            print(f"{self.COLORS['GREEN']}✓ PDF report saved: {report_path}{self.COLORS['RESET']}")
            return report_path
            
        except ImportError:
            # Handle missing reportlab dependency gracefully
            # Fall back to HTML report which doesn't require external dependencies
            print(f"{self.COLORS['YELLOW']}⚠ PDF generation requires reportlab. Install with: pip install reportlab{self.COLORS['RESET']}")
            print(f"{self.COLORS['BLUE']}ℹ Falling back to HTML report{self.COLORS['RESET']}")
            return self._generate_html_report(results, output_dir, filename)
    
    def _generate_summary_statistics(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate summary statistics from scan results
        Purpose: Create high-level insights from raw scan data
        
        Args:
            results: List of scan results
            
        Returns:
            Dictionary with summary statistics including risk distribution and top vulnerabilities
        """
        # Filter completed results (ignore failed scans for statistics)
        completed = [r for r in results if r.get('status') == 'completed']
        
        if not completed:
            return {}  # No statistics if no successful scans
        
        # Calculate risk score distribution
        # This shows how many URLs fall into each risk category
        risk_distribution = {
            'critical': 0,      # > 0.8 risk score
            'high': 0,          # > 0.6 risk score
            'medium': 0,        # > 0.4 risk score
            'low': 0,           # > 0.2 risk score
            'informational': 0  # <= 0.2 risk score
        }
        
        for result in completed:
            risk = result.get('risk_score', 0)
            if risk > 0.8:
                risk_distribution['critical'] += 1
            elif risk > 0.6:
                risk_distribution['high'] += 1
            elif risk > 0.4:
                risk_distribution['medium'] += 1
            elif risk > 0.2:
                risk_distribution['low'] += 1
            else:
                risk_distribution['informational'] += 1
        
        # Count vulnerability types across all scans
        # This identifies the most common security issues
        vulnerability_types = {}
        for result in completed:
            for vuln in result.get('scan_data', {}).get('vulnerabilities', []):
                vuln_type = vuln.get('type', 'Unknown')
                vulnerability_types[vuln_type] = vulnerability_types.get(vuln_type, 0) + 1
        
        # Get top 10 most common vulnerabilities
        # Sorting by frequency helps prioritize remediation efforts
        top_vulnerabilities = sorted(
            vulnerability_types.items(),
            key=lambda x: x[1],  # Sort by count (second element of tuple)
            reverse=True  # Highest count first
        )[:10]  # Limit to top 10
        
        return {
            'risk_distribution': risk_distribution,  # How URLs are distributed by risk
            'top_vulnerabilities': dict(top_vulnerabilities),  # Most common issue types
            'average_risk_score': sum(r.get('risk_score', 0) for r in completed) / len(completed),  # Overall risk
            'total_scan_duration': sum(r.get('total_duration', 0) for r in completed)  # Total scanning time
        }
    
    def print_statistics(self) -> None:
        """Print final scan statistics to console
        Purpose: Show summary of scanning operation after completion
        """
        duration = time.time() - self.start_time  # Total execution time
        
        # Print formatted statistics with visual separators
        print(f"\n{self.COLORS['CYAN']}{self.COLORS['BOLD']}📊 SCAN STATISTICS{' ' * 40}{self.COLORS['RESET']}")
        print(f"{self.COLORS['WHITE']}{'='*60}{self.COLORS['RESET']}")
        print(f"  Total URLs Scanned:    {self.total_scans}")
        print(f"  Successful Scans:      {self.completed_scans}")
        print(f"  Failed Scans:          {self.failed_scans}")
        print(f"  Total Duration:        {duration:.2f} seconds")
        print(f"  Vulnerabilities Found: {self.statistics['vulnerabilities_found']}")
        print(f"  Critical Vulnerabilities: {self.statistics['critical_vulnerabilities']}")
        print(f"  Average Scan Time:     {self.statistics['avg_scan_time']:.2f} seconds")
        print(f"{self.COLORS['WHITE']}{'='*60}{self.COLORS['RESET']}")


def main():
    """Main entry point for the security scan CLI
    Purpose: Parse command-line arguments and coordinate the entire scanning process
    """
    # Create argument parser with detailed help
    # RawDescriptionHelpFormatter preserves formatting of epilog
    parser = argparse.ArgumentParser(
        description='CyberGuard Web Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com                      # Scan single URL
  %(prog)s -i urls.txt -o report.json              # Batch scan from file, output JSON
  %(prog)s -i urls.txt -f html -t 10 -v            # HTML report, 10 threads, verbose
  %(prog)s --schedule "0 0 * * *" -i urls.txt      # Schedule daily scans
        
For more information, visit: https://cyberguard.example.com/docs
        """
    )
    
    # Input arguments group
    input_group = parser.add_argument_group('Input Options')
    input_group.add_argument(
        'url',
        nargs='?',  # Optional positional argument
        help='Single URL to scan'
    )
    input_group.add_argument(
        '-i', '--input-file',
        help='File containing URLs to scan (one per line)'
    )
    input_group.add_argument(
        '-c', '--config',
        help='Path to configuration file'
    )
    
    # Output arguments group
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '-o', '--output',
        help='Output file path for report'
    )
    output_group.add_argument(
        '-f', '--format',
        choices=['json', 'html', 'txt', 'pdf'],  # Limit to supported formats
        default='json',  # JSON is default as it's machine-readable
        help='Output format (default: json)'
    )
    output_group.add_argument(
        '-d', '--output-dir',
        default='reports',  # Default directory name
        help='Output directory for reports (default: reports)'
    )
    output_group.add_argument(
        '-v', '--verbose',
        action='store_true',  # Boolean flag (true when present)
        help='Enable verbose output'
    )
    
    # Scan arguments group
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument(
        '-t', '--threads',
        type=int,
        default=5,  # Reasonable default for concurrent scanning
        help='Number of concurrent scans (default: 5)'
    )
    scan_group.add_argument(
        '--timeout',
        type=int,
        default=30,  # 30 seconds is reasonable for most websites
        help='Scan timeout in seconds (default: 30)'
    )
    scan_group.add_argument(
        '--no-crawl',
        action='store_true',  # Store True when flag is present
        help='Disable page crawling'
    )
    scan_group.add_argument(
        '--schedule',
        help='Cron-like schedule for recurring scans'
    )
    
    # Feature arguments group
    feature_group = parser.add_argument_group('Feature Options')
    feature_group.add_argument(
        '--no-headers',
        action='store_true',
        help='Disable security header checks'
    )
    feature_group.add_argument(
        '--no-forms',
        action='store_true',
        help='Disable form analysis'
    )
    feature_group.add_argument(
        '--no-scripts',
        action='store_true',
        help='Disable JavaScript analysis'
    )
    
    # Parse command line arguments
    args = parser.parse_args()
    
    # Validate input - need either a URL or an input file
    if not args.url and not args.input_file:
        parser.print_help()
        print(f"\n{parser.epilog}")
        sys.exit(1)  # Exit with error code
    
    try:
        # Initialize scanner CLI with optional config file
        scanner = SecurityScanCLI(args.config)
        scanner.print_banner()  # Show welcome banner
        
        # Prepare URL list from command line arguments
        urls = []
        
        # Add single URL if provided as positional argument
        if args.url:
            urls.append(args.url)
        
        # Add URLs from file if provided
        if args.input_file:
            if os.path.exists(args.input_file):
                with open(args.input_file, 'r') as f:
                    # Read non-empty lines, strip whitespace
                    file_urls = [line.strip() for line in f if line.strip()]
                urls.extend(file_urls)
            else:
                print(f"{scanner.COLORS['RED']}Error: Input file not found: {args.input_file}{scanner.COLORS['RESET']}")
                sys.exit(1)
        
        # Remove duplicate URLs while preserving order
        # dict.fromkeys() removes duplicates because dict keys are unique
        urls = list(dict.fromkeys(urls))
        
        print(f"{scanner.COLORS['BLUE']} Preparing to scan {len(urls)} URLs...{scanner.COLORS['RESET']}")
        
        # Perform scan based on number of URLs
        if len(urls) == 1:
            # Single URL scan (simpler, no threading needed)
            results = [scanner.scan_single_url(urls[0])]
        else:
            # Batch scan with concurrent workers for efficiency
            results = scanner.scan_batch(urls, max_workers=args.threads)
        
        # Generate report if results exist
        if results:
            report_path = scanner.generate_report(
                results,
                format=args.format,
                output_dir=args.output_dir
            )
            
            # Copy to custom output location if specified with -o flag
            if args.output:
                import shutil
                shutil.copy(report_path, args.output)
                report_path = args.output  # Update report_path to custom location
            
            # Print final statistics for user review
            scanner.print_statistics()
            
            # Success message with emoji for visual appeal
            print(f"\n{scanner.COLORS['GREEN']}{scanner.COLORS['BOLD']} Scan completed successfully!{scanner.COLORS['RESET']}")
            print(f"{scanner.COLORS['BLUE']} Report saved: {report_path}{scanner.COLORS['RESET']}")
            
        else:
            # Handle case where no results were generated (shouldn't happen but safety)
            print(f"{scanner.COLORS['YELLOW']} No scan results generated{scanner.COLORS['RESET']}")
        
    except KeyboardInterrupt:
        # Handle user interrupt (Ctrl+C) gracefully
        print(f"\n{scanner.COLORS['YELLOW']} Scan interrupted by user{scanner.COLORS['RESET']}")
        sys.exit(130)  # Standard exit code for SIGINT (Ctrl+C)
    except Exception as e:
        # Handle unexpected errors
        print(f"{scanner.COLORS['RED']} Error: {e}{scanner.COLORS['RESET']}")
        if args.verbose:
            import traceback
            traceback.print_exc()  # Print full traceback in verbose mode
        sys.exit(1)  # Exit with error code


if __name__ == "__main__":
    # Entry point when script is run directly (not imported as module)
    main()