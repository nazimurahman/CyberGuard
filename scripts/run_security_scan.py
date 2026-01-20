#!/usr/bin/env python3
"""
scripts/run_security_scan.py

CyberGuard Web Security Scanner - Command Line Interface
=======================================================
This script provides a command-line interface for running
security scans using the CyberGuard AI system.

Features:
- Single URL scanning
- Batch scanning from file
- Scheduled scanning
- Report generation (HTML, JSON, PDF)
- Integration with threat intelligence
- Real-time progress tracking
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

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.web_security.scanner import WebSecurityScanner
from src.agents.agent_orchestrator import AgentOrchestrator
from src.agents.threat_detection_agent import WebThreatDetectionAgent
from src.agents.traffic_anomaly_agent import TrafficAnomalyAgent
from src.agents.bot_detection_agent import BotDetectionAgent

class SecurityScanCLI:
    """
    Command Line Interface for CyberGuard Security Scanner
    
    This class provides a comprehensive CLI for running web security scans,
    generating reports, and managing scan results.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the security scanner CLI
        
        Args:
            config_path: Path to configuration file (optional)
        """
        self.start_time = time.time()
        self.scan_results = []
        self.total_scans = 0
        self.completed_scans = 0
        self.failed_scans = 0
        
        # Load configuration
        self.config = self._load_configuration(config_path)
        
        # Initialize scanner components
        self._initialize_scanner()
        
        # Statistics
        self.statistics = {
            'total_urls': 0,
            'vulnerabilities_found': 0,
            'critical_vulnerabilities': 0,
            'scan_duration': 0,
            'avg_scan_time': 0
        }
        
        # Output formats
        self.output_formats = ['json', 'html', 'txt', 'pdf']
        
        # Color codes for console output
        self.COLORS = {
            'RED': '\033[91m',
            'GREEN': '\033[92m',
            'YELLOW': '\033[93m',
            'BLUE': '\033[94m',
            'MAGENTA': '\033[95m',
            'CYAN': '\033[96m',
            'WHITE': '\033[97m',
            'RESET': '\033[0m',
            'BOLD': '\033[1m'
        }
    
    def _load_configuration(self, config_path: Optional[str]) -> Dict[str, Any]:
        """
        Load configuration from file or use defaults
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            Dictionary with configuration values
        """
        default_config = {
            'scan': {
                'timeout': 30,
                'max_depth': 2,
                'max_pages': 100,
                'threads': 5,
                'user_agent': 'CyberGuard-Security-Scanner/1.0'
            },
            'output': {
                'directory': 'reports',
                'format': 'json',
                'verbose': False,
                'save_raw': True
            },
            'security': {
                'check_headers': True,
                'check_forms': True,
                'check_scripts': True,
                'check_endpoints': True,
                'enable_crawling': True
            }
        }
        
        # Load from file if provided
        if config_path and os.path.exists(config_path):
            try:
                import yaml
                with open(config_path, 'r') as f:
                    file_config = yaml.safe_load(f)
                
                # Merge with defaults
                self._merge_dicts(default_config, file_config)
                print(f"{self.COLORS['GREEN']}✓ Configuration loaded from {config_path}{self.COLORS['RESET']}")
                
            except Exception as e:
                print(f"{self.COLORS['YELLOW']}⚠ Warning: Failed to load config from {config_path}: {e}{self.COLORS['RESET']}")
                print(f"{self.COLORS['BLUE']}ℹ Using default configuration{self.COLORS['RESET']}")
        
        return default_config
    
    def _merge_dicts(self, base: Dict, overlay: Dict) -> None:
        """
        Recursively merge two dictionaries
        
        Args:
            base: Base dictionary to merge into
            overlay: Dictionary with overlay values
        """
        for key, value in overlay.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_dicts(base[key], value)
            else:
                base[key] = value
    
    def _initialize_scanner(self) -> None:
        """
        Initialize the web security scanner and agents
        """
        print(f"{self.COLORS['BLUE']}Initializing CyberGuard Security Scanner...{self.COLORS['RESET']}")
        
        # Initialize web security scanner
        self.scanner = WebSecurityScanner(self.config.get('scan', {}))
        
        # Initialize agent orchestrator
        self.orchestrator = AgentOrchestrator(state_dim=512)
        
        # Register security agents
        print(f"{self.COLORS['BLUE']}Registering security agents...{self.COLORS['RESET']}")
        
        agents = [
            WebThreatDetectionAgent("threat_detection_001"),
            TrafficAnomalyAgent("traffic_anomaly_001"),
            BotDetectionAgent("bot_detection_001")
        ]
        
        for agent in agents:
            self.orchestrator.register_agent(agent)
            print(f"  {self.COLORS['GREEN']}✓{self.COLORS['RESET']} {agent.name}")
        
        print(f"{self.COLORS['GREEN']}Scanner initialized with {len(agents)} agents{self.COLORS['RESET']}")
    
    def print_banner(self) -> None:
        """
        Print CyberGuard banner
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
        Validate URL format
        
        Args:
            url: URL to validate
            
        Returns:
            True if URL is valid, False otherwise
        """
        import re
        
        # Basic URL pattern
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
            r'localhost|'  # localhost
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP address
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
        return bool(url_pattern.match(url))
    
    def scan_single_url(self, url: str, scan_id: str = None) -> Dict[str, Any]:
        """
        Perform security scan on a single URL
        
        Args:
            url: URL to scan
            scan_id: Optional scan identifier
            
        Returns:
            Dictionary with scan results
        """
        if not self.validate_url(url):
            return {
                'url': url,
                'error': 'Invalid URL format',
                'status': 'failed'
            }
        
        print(f"\n{self.COLORS['BLUE']}🔍 Scanning: {url}{self.COLORS['RESET']}")
        
        try:
            # Perform web security scan
            scan_start = time.time()
            scan_data = self.scanner.scan_website(url)
            scan_duration = time.time() - scan_start
            
            # Analyze with AI agents
            analysis_start = time.time()
            analysis_results = self.orchestrator.coordinate_analysis({
                'url': url,
                'scan_data': scan_data,
                'timestamp': datetime.now().isoformat()
            })
            analysis_duration = time.time() - analysis_start
            
            # Compile results
            result = {
                'scan_id': scan_id or f"scan_{int(time.time())}",
                'url': url,
                'timestamp': datetime.now().isoformat(),
                'scan_duration': scan_duration,
                'analysis_duration': analysis_duration,
                'total_duration': scan_duration + analysis_duration,
                'scan_data': scan_data,
                'analysis': analysis_results,
                'status': 'completed',
                'risk_score': analysis_results.get('final_decision', {}).get('threat_level', 0),
                'action': analysis_results.get('final_decision', {}).get('action', 'UNKNOWN')
            }
            
            # Update statistics
            self._update_statistics(result)
            
            # Print summary
            self._print_scan_summary(result)
            
            return result
            
        except Exception as e:
            error_result = {
                'scan_id': scan_id or f"scan_{int(time.time())}",
                'url': url,
                'timestamp': datetime.now().isoformat(),
                'error': str(e),
                'status': 'failed'
            }
            
            print(f"{self.COLORS['RED']}✗ Scan failed: {e}{self.COLORS['RESET']}")
            self.failed_scans += 1
            
            return error_result
    
    def scan_batch(self, urls: List[str], max_workers: int = 5) -> List[Dict[str, Any]]:
        """
        Perform security scans on multiple URLs concurrently
        
        Args:
            urls: List of URLs to scan
            max_workers: Maximum number of concurrent scans
            
        Returns:
            List of scan results
        """
        self.total_scans = len(urls)
        self.completed_scans = 0
        self.failed_scans = 0
        
        print(f"\n{self.COLORS['BLUE']}📋 Batch scan starting: {len(urls)} URLs{self.COLORS['RESET']}")
        print(f"{self.COLORS['BLUE']}🧵 Concurrent workers: {max_workers}{self.COLORS['RESET']}")
        
        # Progress tracking
        progress_thread = threading.Thread(target=self._show_progress)
        progress_thread.daemon = True
        progress_thread.start()
        
        # Perform concurrent scans
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all scan tasks
            future_to_url = {
                executor.submit(self.scan_single_url, url, f"batch_scan_{i}"): url
                for i, url in enumerate(urls)
            }
            
            # Process completed scans
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result(timeout=self.config['scan']['timeout'] + 30)
                    results.append(result)
                except concurrent.futures.TimeoutError:
                    error_result = {
                        'url': url,
                        'error': 'Scan timeout',
                        'status': 'failed'
                    }
                    results.append(error_result)
                    self.failed_scans += 1
                except Exception as e:
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
        Show progress bar for batch scans
        """
        import time
        
        while self.completed_scans < self.total_scans:
            completed = self.completed_scans
            total = self.total_scans
            
            if total > 0:
                percentage = (completed / total) * 100
                bar_length = 40
                filled_length = int(bar_length * completed // total)
                bar = '█' * filled_length + '░' * (bar_length - filled_length)
                
                sys.stdout.write(
                    f'\r{self.COLORS["BLUE"]}Progress: [{bar}] {percentage:.1f}% '
                    f'({completed}/{total} URLs){self.COLORS["RESET"]}'
                )
                sys.stdout.flush()
            
            time.sleep(0.5)
    
    def _update_statistics(self, scan_result: Dict[str, Any]) -> None:
        """
        Update scan statistics
        
        Args:
            scan_result: Scan result to process
        """
        self.completed_scans += 1
        
        # Count vulnerabilities
        if scan_result.get('status') == 'completed':
            scan_data = scan_result.get('scan_data', {})
            vulnerabilities = scan_data.get('vulnerabilities', [])
            
            self.statistics['vulnerabilities_found'] += len(vulnerabilities)
            
            # Count critical vulnerabilities
            critical = sum(1 for v in vulnerabilities 
                          if v.get('severity') == 'CRITICAL')
            self.statistics['critical_vulnerabilities'] += critical
            
            # Update timing statistics
            self.statistics['scan_duration'] += scan_result.get('total_duration', 0)
            self.statistics['avg_scan_time'] = (
                self.statistics['scan_duration'] / self.completed_scans
            )
    
    def _print_scan_summary(self, scan_result: Dict[str, Any]) -> None:
        """
        Print summary of a scan result
        
        Args:
            scan_result: Scan result to summarize
        """
        url = scan_result.get('url', 'Unknown')
        status = scan_result.get('status', 'unknown')
        risk_score = scan_result.get('risk_score', 0)
        duration = scan_result.get('total_duration', 0)
        
        # Determine color based on risk
        if risk_score > 0.8:
            risk_color = self.COLORS['RED']
            risk_text = 'CRITICAL'
        elif risk_score > 0.6:
            risk_color = self.COLORS['YELLOW']
            risk_text = 'HIGH'
        elif risk_score > 0.4:
            risk_color = self.COLORS['CYAN']
            risk_text = 'MEDIUM'
        elif risk_score > 0.2:
            risk_color = self.COLORS['BLUE']
            risk_text = 'LOW'
        else:
            risk_color = self.COLORS['GREEN']
            risk_text = 'INFORMATIONAL'
        
        # Print summary
        print(f"\n{self.COLORS['WHITE']}{self.COLORS['BOLD']}Scan Summary:{self.COLORS['RESET']}")
        print(f"  URL: {url}")
        print(f"  Status: {self.COLORS['GREEN'] if status == 'completed' else self.COLORS['RED']}{status}{self.COLORS['RESET']}")
        print(f"  Risk: {risk_color}{risk_text} ({risk_score:.2f}){self.COLORS['RESET']}")
        print(f"  Duration: {duration:.2f}s")
        
        # Show vulnerabilities if any
        if scan_result.get('scan_data', {}).get('vulnerabilities'):
            vulns = scan_result['scan_data']['vulnerabilities']
            print(f"  Vulnerabilities: {len(vulns)} found")
            
            # Show top 3 vulnerabilities
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
        
        Args:
            results: List of scan results
            format: Output format (json, html, txt, pdf)
            output_dir: Directory to save reports
            
        Returns:
            Path to generated report file
        """
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"cyberguard_scan_report_{timestamp}"
        
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
        Generate JSON report
        
        Args:
            results: Scan results
            output_dir: Output directory
            filename: Base filename
            
        Returns:
            Path to JSON report
        """
        report_path = os.path.join(output_dir, f"{filename}.json")
        
        report_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'cyberguard_version': '1.0.0',
                'total_scans': len(results),
                'successful_scans': sum(1 for r in results if r.get('status') == 'completed'),
                'failed_scans': sum(1 for r in results if r.get('status') == 'failed'),
                'scan_duration': time.time() - self.start_time
            },
            'statistics': self.statistics,
            'results': results,
            'summary': self._generate_summary_statistics(results)
        }
        
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        print(f"{self.COLORS['GREEN']}✓ JSON report saved: {report_path}{self.COLORS['RESET']}")
        return report_path
    
    def _generate_html_report(self, results: List[Dict[str, Any]], 
                            output_dir: str, filename: str) -> str:
        """
        Generate HTML report
        
        Args:
            results: Scan results
            output_dir: Output directory
            filename: Base filename
            
        Returns:
            Path to HTML report
        """
        report_path = os.path.join(output_dir, f"{filename}.html")
        
        # Generate HTML content
        html_content = self._create_html_content(results)
        
        with open(report_path, 'w') as f:
            f.write(html_content)
        
        print(f"{self.COLORS['GREEN']}✓ HTML report saved: {report_path}{self.COLORS['RESET']}")
        return report_path
    
    def _create_html_content(self, results: List[Dict[str, Any]]) -> str:
        """
        Create HTML content for report
        
        Args:
            results: Scan results
            
        Returns:
            HTML content as string
        """
        completed_results = [r for r in results if r.get('status') == 'completed']
        
        # Calculate statistics
        total_vulns = sum(len(r.get('scan_data', {}).get('vulnerabilities', [])) 
                         for r in completed_results)
        
        critical_vulns = sum(
            sum(1 for v in r.get('scan_data', {}).get('vulnerabilities', [])
                if v.get('severity') == 'CRITICAL')
            for r in completed_results
        )
        
        # Create HTML
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberGuard Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 40px; }}
        .header h1 {{ color: #2c3e50; margin-bottom: 10px; }}
        .header .subtitle {{ color: #7f8c8d; font-size: 18px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 40px; }}
        .stat-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #3498db; }}
        .stat-card.critical {{ border-left-color: #e74c3c; }}
        .stat-card.high {{ border-left-color: #f39c12; }}
        .stat-card.medium {{ border-left-color: #3498db; }}
        .stat-card.low {{ border-left-color: #2ecc71; }}
        .stat-value {{ font-size: 32px; font-weight: bold; margin: 10px 0; }}
        .stat-label {{ color: #7f8c8d; font-size: 14px; }}
        .scan-results {{ margin-top: 40px; }}
        .scan-item {{ background: #f8f9fa; margin-bottom: 20px; padding: 20px; border-radius: 8px; }}
        .scan-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }}
        .scan-url {{ font-weight: bold; color: #2c3e50; }}
        .scan-risk {{ padding: 5px 15px; border-radius: 20px; font-weight: bold; color: white; }}
        .risk-critical {{ background: #e74c3c; }}
        .risk-high {{ background: #f39c12; }}
        .risk-medium {{ background: #3498db; }}
        .risk-low {{ background: #2ecc71; }}
        .vulnerabilities {{ margin-top: 15px; }}
        .vuln-item {{ background: white; padding: 10px 15px; margin-bottom: 10px; border-radius: 5px; border-left: 4px solid #ddd; }}
        .vuln-critical {{ border-left-color: #e74c3c; }}
        .vuln-high {{ border-left-color: #f39c12; }}
        .vuln-medium {{ border-left-color: #3498db; }}
        .vuln-low {{ border-left-color: #2ecc71; }}
        .footer {{ margin-top: 40px; text-align: center; color: #7f8c8d; font-size: 14px; border-top: 1px solid #eee; padding-top: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 CyberGuard Security Scan Report</h1>
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
        Create HTML for a single scan result
        
        Args:
            result: Scan result
            
        Returns:
            HTML string
        """
        url = result.get('url', 'Unknown')
        risk_score = result.get('risk_score', 0)
        duration = result.get('total_duration', 0)
        vulnerabilities = result.get('scan_data', {}).get('vulnerabilities', [])
        
        # Determine risk level
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
        
        # Create vulnerabilities HTML
        vulns_html = ""
        for vuln in vulnerabilities[:5]:  # Show max 5 vulnerabilities
            severity = vuln.get('severity', 'UNKNOWN').lower()
            vulns_html += f"""
            <div class="vuln-item vuln-{severity}">
                <strong>{vuln.get('type', 'Unknown')}</strong> - {vuln.get('description', '')}
                <div style="font-size: 12px; color: #666; margin-top: 5px;">
                    Location: {vuln.get('location', 'Unknown')}
                </div>
            </div>
            """
        
        if len(vulnerabilities) > 5:
            vulns_html += f'<div style="text-align: center; color: #666; padding: 10px;">... and {len(vulnerabilities) - 5} more vulnerabilities</div>'
        
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
        Generate text report
        
        Args:
            results: Scan results
            output_dir: Output directory
            filename: Base filename
            
        Returns:
            Path to text report
        """
        report_path = os.path.join(output_dir, f"{filename}.txt")
        
        with open(report_path, 'w') as f:
            f.write(self._create_text_content(results))
        
        print(f"{self.COLORS['GREEN']}✓ Text report saved: {report_path}{self.COLORS['RESET']}")
        return report_path
    
    def _create_text_content(self, results: List[Dict[str, Any]]) -> str:
        """
        Create text content for report
        
        Args:
            results: Scan results
            
        Returns:
            Text content as string
        """
        completed_results = [r for r in results if r.get('status') == 'completed']
        
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
        
        for i, result in enumerate(completed_results, 1):
            url = result.get('url', 'Unknown')
            risk_score = result.get('risk_score', 0)
            vulnerabilities = result.get('scan_data', {}).get('vulnerabilities', [])
            
            text += f"\n{i}. {url}\n"
            text += f"   Risk Score: {risk_score:.2f}\n"
            text += f"   Vulnerabilities: {len(vulnerabilities)}\n"
            
            for j, vuln in enumerate(vulnerabilities[:3], 1):
                text += f"   {j}. [{vuln.get('severity', 'UNKNOWN')}] {vuln.get('type', 'Unknown')}\n"
                text += f"      {vuln.get('description', '')}\n"
            
            if len(vulnerabilities) > 3:
                text += f"   ... and {len(vulnerabilities) - 3} more\n"
            
            text += "-" * 80 + "\n"
        
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
        Generate PDF report (requires reportlab)
        
        Args:
            results: Scan results
            output_dir: Output directory
            filename: Base filename
            
        Returns:
            Path to PDF report
        """
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            
            report_path = os.path.join(output_dir, f"{filename}.pdf")
            
            # Create PDF document
            doc = SimpleDocTemplate(
                report_path,
                pagesize=letter,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=72
            )
            
            # Get styles
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                spaceAfter=30,
                textColor=colors.HexColor('#2c3e50')
            )
            
            # Build story
            story = []
            
            # Title
            story.append(Paragraph("CyberGuard Security Scan Report", title_style))
            story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Summary table
            completed = sum(1 for r in results if r.get('status') == 'completed')
            data = [
                ['Total URLs Scanned', str(len(results))],
                ['Successful Scans', str(completed)],
                ['Failed Scans', str(len(results) - completed)],
                ['Total Duration', f"{time.time() - self.start_time:.2f} seconds"],
                ['Vulnerabilities Found', str(self.statistics['vulnerabilities_found'])],
                ['Critical Vulnerabilities', str(self.statistics['critical_vulnerabilities'])]
            ]
            
            table = Table(data, colWidths=[3*inch, 2*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(table)
            story.append(Spacer(1, 30))
            
            # Results
            story.append(Paragraph("Scan Results", styles['Heading2']))
            
            for i, result in enumerate(results, 1):
                if result.get('status') == 'completed':
                    url = result.get('url', 'Unknown')
                    risk = result.get('risk_score', 0)
                    
                    story.append(Paragraph(f"{i}. {url}", styles['Normal']))
                    story.append(Paragraph(f"   Risk Score: {risk:.2f}", styles['Normal']))
                    story.append(Spacer(1, 10))
            
            # Build PDF
            doc.build(story)
            
            print(f"{self.COLORS['GREEN']}✓ PDF report saved: {report_path}{self.COLORS['RESET']}")
            return report_path
            
        except ImportError:
            print(f"{self.COLORS['YELLOW']}⚠ PDF generation requires reportlab. Install with: pip install reportlab{self.COLORS['RESET']}")
            print(f"{self.COLORS['BLUE']}ℹ Falling back to HTML report{self.COLORS['RESET']}")
            return self._generate_html_report(results, output_dir, filename)
    
    def _generate_summary_statistics(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate summary statistics from scan results
        
        Args:
            results: List of scan results
            
        Returns:
            Dictionary with summary statistics
        """
        completed = [r for r in results if r.get('status') == 'completed']
        
        if not completed:
            return {}
        
        # Calculate risk distribution
        risk_distribution = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'informational': 0
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
        
        # Most common vulnerabilities
        vulnerability_types = {}
        for result in completed:
            for vuln in result.get('scan_data', {}).get('vulnerabilities', []):
                vuln_type = vuln.get('type', 'Unknown')
                vulnerability_types[vuln_type] = vulnerability_types.get(vuln_type, 0) + 1
        
        top_vulnerabilities = sorted(
            vulnerability_types.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        return {
            'risk_distribution': risk_distribution,
            'top_vulnerabilities': dict(top_vulnerabilities),
            'average_risk_score': sum(r.get('risk_score', 0) for r in completed) / len(completed),
            'total_scan_duration': sum(r.get('total_duration', 0) for r in completed)
        }
    
    def print_statistics(self) -> None:
        """
        Print final statistics
        """
        duration = time.time() - self.start_time
        
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
    """
    Main entry point for the security scan CLI
    """
    parser = argparse.ArgumentParser(
        description='CyberGuard Web Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com
  %(prog)s -i urls.txt -o report.json
  %(prog)s -i urls.txt -f html -t 10 -v
  %(prog)s --schedule "0 0 * * *" -i urls.txt
        
For more information, visit: https://cyberguard.example.com/docs
        """
    )
    
    # Input arguments
    input_group = parser.add_argument_group('Input Options')
    input_group.add_argument(
        'url',
        nargs='?',
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
    
    # Output arguments
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '-o', '--output',
        help='Output file path for report'
    )
    output_group.add_argument(
        '-f', '--format',
        choices=['json', 'html', 'txt', 'pdf'],
        default='json',
        help='Output format (default: json)'
    )
    output_group.add_argument(
        '-d', '--output-dir',
        default='reports',
        help='Output directory for reports (default: reports)'
    )
    output_group.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    # Scan arguments
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument(
        '-t', '--threads',
        type=int,
        default=5,
        help='Number of concurrent scans (default: 5)'
    )
    scan_group.add_argument(
        '--timeout',
        type=int,
        default=30,
        help='Scan timeout in seconds (default: 30)'
    )
    scan_group.add_argument(
        '--no-crawl',
        action='store_true',
        help='Disable page crawling'
    )
    scan_group.add_argument(
        '--schedule',
        help='Cron-like schedule for recurring scans'
    )
    
    # Feature arguments
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
    
    # Parse arguments
    args = parser.parse_args()
    
    # Check if any input is provided
    if not args.url and not args.input_file:
        parser.print_help()
        print(f"\n{parser.epilog}")
        sys.exit(1)
    
    try:
        # Initialize scanner
        scanner = SecurityScanCLI(args.config)
        scanner.print_banner()
        
        # Prepare URLs
        urls = []
        
        if args.url:
            urls.append(args.url)
        
        if args.input_file:
            if os.path.exists(args.input_file):
                with open(args.input_file, 'r') as f:
                    file_urls = [line.strip() for line in f if line.strip()]
                urls.extend(file_urls)
            else:
                print(f"{scanner.COLORS['RED']}Error: Input file not found: {args.input_file}{scanner.COLORS['RESET']}")
                sys.exit(1)
        
        # Remove duplicates
        urls = list(dict.fromkeys(urls))
        
        print(f"{scanner.COLORS['BLUE']}📋 Preparing to scan {len(urls)} URLs...{scanner.COLORS['RESET']}")
        
        # Perform scan
        if len(urls) == 1:
            # Single URL scan
            results = [scanner.scan_single_url(urls[0])]
        else:
            # Batch scan
            results = scanner.scan_batch(urls, max_workers=args.threads)
        
        # Generate report
        if results:
            report_path = scanner.generate_report(
                results,
                format=args.format,
                output_dir=args.output_dir
            )
            
            # Use custom output path if specified
            if args.output:
                import shutil
                shutil.copy(report_path, args.output)
                report_path = args.output
            
            # Print statistics
            scanner.print_statistics()
            
            print(f"\n{scanner.COLORS['GREEN']}{scanner.COLORS['BOLD']}✅ Scan completed successfully!{scanner.COLORS['RESET']}")
            print(f"{scanner.COLORS['BLUE']}📄 Report saved: {report_path}{scanner.COLORS['RESET']}")
            
        else:
            print(f"{scanner.COLORS['YELLOW']}⚠ No scan results generated{scanner.COLORS['RESET']}")
        
    except KeyboardInterrupt:
        print(f"\n{scanner.COLORS['YELLOW']}⚠ Scan interrupted by user{scanner.COLORS['RESET']}")
        sys.exit(130)
    except Exception as e:
        print(f"{scanner.COLORS['RED']}❌ Error: {e}{scanner.COLORS['RESET']}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()