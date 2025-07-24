"""
Port Scanner for PGDN DePIN Infrastructure Scanner

Respectful port scanning functionality integrated into the PGDN scanner framework.
Based on the port-scan-new.py script, adapted for modular architecture.
"""

import asyncio
import socket
import subprocess
import json
import ssl
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
import time
import re
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from urllib.parse import urlparse
import concurrent.futures
from datetime import datetime
import hashlib

from .base_scanner import BaseScanner
from ..core.logging import get_logger

# Disable urllib3 warnings for cleaner output
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = get_logger(__name__)


@dataclass
class PortScanResult:
    """Container for single port scan results"""
    target: str
    port: int
    timestamp: str
    is_open: bool
    confidence_score: float = 0.0
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    nmap_results: Optional[Dict] = None
    ssl_info: Optional[Dict] = None
    http_info: Optional[Dict] = None
    raw_data: Dict = None
    scan_log: List[str] = None

    def __post_init__(self):
        if self.raw_data is None:
            self.raw_data = {}
        if self.scan_log is None:
            self.scan_log = []


class PortScanner(BaseScanner):
    """
    Respectful port scanner that collects data efficiently
    without being aggressive or intrusive.
    
    Integrates the respectful port scanning functionality into the PGDN framework.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        
        # Configuration with defaults - respectful timeouts
        self.timeout = self.config.get('timeout', 10)
        self.connect_timeout = min(3, self.timeout // 3)  # Quick connection timeout
        self.read_timeout = min(5, self.timeout // 2)     # Quick read timeout
        self.nmap_timeout = min(15, self.timeout + 5)     # Brief nmap scan
        self.max_threads = self.config.get('max_threads', 10)
        
        # Setup HTTP session
        self.session = requests.Session()
        self.session.timeout = (self.connect_timeout, self.read_timeout)
        
        # Minimal retry strategy - just fail fast
        retry_strategy = Retry(
            total=0,  # No retries
            backoff_factor=0,
            status_forcelist=[]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Common service ports and their likely services
        self.common_services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 993: 'imaps',
            995: 'pop3s', 3306: 'mysql', 5432: 'postgresql', 6379: 'redis',
            27017: 'mongodb', 2375: 'docker', 2376: 'docker-tls', 
            8080: 'http-alt', 8443: 'https-alt', 9090: 'prometheus'
        }

    @property
    def scanner_type(self) -> str:
        """Return the type of scanner."""
        return "port_scan"

    def scan(self, target: str, hostname: str = None, ports: List[int] = None, **kwargs) -> Dict[str, Any]:
        """
        Perform port scan on target.
        
        Args:
            target: Target IP address or hostname
            hostname: Optional hostname (not used by port scanner)
            ports: List of ports to scan (passed from orchestrator)
            **kwargs: Additional scan parameters including:
                - port: Alternative way to specify ports as string (from CLI)
                - skip_nmap: Skip nmap scanning for faster results
                
        Returns:
            Scan results dictionary
        """
        # Parse ports from orchestrator parameter or kwargs
        if ports is None:
            ports = self._parse_ports(kwargs)
        elif isinstance(ports, str):
            # Handle string format from CLI
            try:
                ports = [int(p.strip()) for p in ports.split(',') if p.strip()]
            except ValueError as e:
                self.logger.error(f"Invalid port format: {e}")
                return {
                    'target': target,
                    'scanner_type': self.scanner_type,
                    'error': f'Invalid port format: {e}',
                    'timestamp': datetime.now().isoformat()
                }
        
        if not ports:
            self.logger.error("No ports specified for scanning")
            return {
                'target': target,
                'scanner_type': self.scanner_type,
                'error': 'No ports specified',
                'timestamp': datetime.now().isoformat()
            }
        
        if len(ports) > 5:
            self.logger.warning(f"Too many ports specified ({len(ports)}), limiting to first 5")
            ports = ports[:5]
        
        skip_nmap = kwargs.get('skip_nmap', False)
        
        self.logger.info(f"Starting port scan of {target} on ports: {ports}")
        
        # Run the async scan
        try:
            results = asyncio.run(self._scan_ports_async(target, ports, skip_nmap))
            return self._generate_scan_report(target, results, skip_nmap)
        except Exception as e:
            self.logger.error(f"Port scan failed: {e}")
            return {
                'target': target,
                'scanner_type': self.scanner_type,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

    def _parse_ports(self, kwargs: Dict[str, Any]) -> List[int]:
        """Parse ports from various input formats."""
        ports = []
        
        # Try 'ports' parameter first
        if 'ports' in kwargs:
            ports_input = kwargs['ports']
            if isinstance(ports_input, str):
                # Handle comma-separated string
                try:
                    ports = [int(p.strip()) for p in ports_input.split(',') if p.strip()]
                except ValueError as e:
                    self.logger.error(f"Invalid port format in --ports: {e}")
                    return []
            elif isinstance(ports_input, list):
                try:
                    ports = [int(p) for p in ports_input]
                except ValueError as e:
                    self.logger.error(f"Invalid port format in ports list: {e}")
                    return []
        
        # Try 'port' parameter as fallback
        elif 'port' in kwargs:
            port_input = kwargs['port']
            if isinstance(port_input, str):
                try:
                    ports = [int(p.strip()) for p in port_input.split(',') if p.strip()]
                except ValueError as e:
                    self.logger.error(f"Invalid port format in --port: {e}")
                    return []
            elif isinstance(port_input, (int, list)):
                ports = [port_input] if isinstance(port_input, int) else port_input
        
        # Validate port ranges
        valid_ports = []
        for port in ports:
            if 1 <= port <= 65535:
                valid_ports.append(port)
            else:
                self.logger.warning(f"Invalid port number: {port} (must be 1-65535)")
        
        return valid_ports

    async def _scan_ports_async(self, target: str, ports: List[int], skip_nmap: bool = False) -> List[PortScanResult]:
        """
        Main async entry point - scans ports respectfully
        """
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for port in ports:
                future = executor.submit(self._scan_single_port, target, port, skip_nmap)
                futures.append(future)
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    self.logger.error(f"Error scanning port: {e}")
        
        return results

    def _scan_single_port(self, target: str, port: int, skip_nmap: bool = False) -> PortScanResult:
        """
        Respectfully scan a single port using available techniques
        """
        timestamp = datetime.now().isoformat()
        result = PortScanResult(target=target, port=port, timestamp=timestamp, is_open=False)
        
        self.logger.debug(f"Starting comprehensive scan of {target}:{port}")
        result.scan_log.append(f"SCAN_START: {timestamp}")
        
        # 1. Basic connectivity check
        self.logger.debug(f"Testing port connectivity for {target}:{port}")
        if not self._check_port_open(target, port):
            self.logger.debug(f"Port {port} is closed or filtered on {target}")
            result.scan_log.append("CONNECTIVITY: Port closed/filtered")
            result.confidence_score = 100.0  # We're confident it's closed
            return result
        
        result.is_open = True
        self.logger.info(f"Port {port} is OPEN on {target} - beginning enumeration")
        result.scan_log.append("CONNECTIVITY: Port open - proceeding with enumeration")
        
        # 2. Banner grabbing
        self.logger.debug(f"Banner grabbing for {target}:{port}")
        try:
            result.banner = self._grab_banner(target, port)
            if result.banner:
                self.logger.debug(f"Banner captured for {target}:{port}: {len(result.banner)} bytes")
                result.scan_log.append(f"BANNER: Captured {len(result.banner)} bytes")
            else:
                self.logger.debug(f"No banner data received from {target}:{port}")
                result.scan_log.append("BANNER: No response to probes")
        except Exception as e:
            self.logger.error(f"Banner grab failed for {target}:{port}: {e}")
            result.scan_log.append(f"BANNER: Failed - {str(e)}")
        
        # 3. Nmap basic scan (optional)
        if not skip_nmap:
            self.logger.debug(f"Running nmap service detection for {target}:{port}")
            try:
                result.nmap_results = self._nmap_basic_scan(target, port)
                if result.nmap_results and not result.nmap_results.get('error'):
                    self.logger.debug(f"Nmap service detection completed for {target}:{port}")
                    result.scan_log.append("NMAP: Service detection completed")
                else:
                    self.logger.debug(f"Nmap service detection failed for {target}:{port}")
                    result.scan_log.append("NMAP: Failed or unavailable")
            except Exception as e:
                self.logger.debug(f"Nmap scan error for {target}:{port}: {e}")
                result.scan_log.append(f"NMAP: Error - {str(e)}")
        else:
            self.logger.debug(f"Skipping nmap scan for {target}:{port}")
            result.scan_log.append("NMAP: Skipped by user request")
        
        # 4. Service detection and version
        self.logger.debug(f"Service and version detection for {target}:{port}")
        try:
            result.service, result.version = self._detect_service_version(target, port, result.banner, result.nmap_results)
            if result.service:
                self.logger.debug(f"Service detected on {target}:{port}: {result.service}" + (f" v{result.version}" if result.version else ""))
                result.scan_log.append(f"SERVICE: {result.service}" + (f" v{result.version}" if result.version else ""))
            else:
                self.logger.debug(f"Service type unknown for {target}:{port}")
                result.scan_log.append("SERVICE: Unknown")
        except Exception as e:
            self.logger.error(f"Service detection error for {target}:{port}: {e}")
            result.scan_log.append(f"SERVICE: Detection failed - {str(e)}")
        
        # 5. SSL/TLS analysis (if applicable)
        if self._is_ssl_port(port) or self._appears_ssl(result.banner):
            self.logger.debug(f"Running SSL/TLS analysis for {target}:{port}")
            try:
                result.ssl_info = self._analyze_ssl(target, port)
                if result.ssl_info:
                    protocol = result.ssl_info.get('protocol_version', 'unknown')
                    self.logger.debug(f"SSL analysis completed for {target}:{port}: {protocol}")
                    result.scan_log.append(f"SSL: Analysis completed - {protocol}")
                else:
                    self.logger.debug(f"SSL analysis failed for {target}:{port}")
                    result.scan_log.append("SSL: Analysis failed")
            except Exception as e:
                self.logger.error(f"SSL analysis error for {target}:{port}: {e}")
                result.scan_log.append(f"SSL: Error - {str(e)}")
        else:
            self.logger.debug(f"Skipping SSL analysis for {target}:{port} - not an SSL port")
            result.scan_log.append("SSL: Skipped - not SSL port")
        
        # 6. HTTP analysis (if applicable)
        if self._is_http_port(port) or self._appears_http(result.service):
            self.logger.debug(f"Running HTTP analysis for {target}:{port}")
            try:
                result.http_info = self._analyze_http(target, port)
                if result.http_info:
                    methods = list(result.http_info.get('methods', {}).keys())
                    endpoints = len([k for k, v in result.http_info.get('endpoints', {}).items() if v.get('accessible')])
                    self.logger.debug(f"HTTP analysis completed for {target}:{port}: {len(methods)} methods, {endpoints} accessible endpoints")
                    result.scan_log.append(f"HTTP: {len(methods)} methods, {endpoints} accessible endpoints")
                else:
                    self.logger.debug(f"HTTP analysis failed for {target}:{port}")
                    result.scan_log.append("HTTP: Analysis failed")
            except Exception as e:
                self.logger.error(f"HTTP analysis error for {target}:{port}: {e}")
                result.scan_log.append(f"HTTP: Error - {str(e)}")
        else:
            self.logger.debug(f"Skipping HTTP analysis for {target}:{port} - not an HTTP service")
            result.scan_log.append("HTTP: Skipped - not HTTP service")
        
        # 7. Protocol-specific probing
        self.logger.debug(f"Running protocol-specific probing for {target}:{port}")
        try:
            self._protocol_specific_probe(target, port, result)
            probe_count = len([k for k in result.raw_data.keys() if not k.startswith('_')])
            if probe_count > 0:
                self.logger.debug(f"Protocol-specific probing completed for {target}:{port}: {probe_count} additional data points")
                result.scan_log.append(f"PROTOCOL_PROBE: {probe_count} data points collected")
            else:
                self.logger.debug(f"No protocol-specific probes applicable for {target}:{port}")
                result.scan_log.append("PROTOCOL_PROBE: No applicable probes")
        except Exception as e:
            self.logger.error(f"Protocol-specific probing error for {target}:{port}: {e}")
            result.scan_log.append(f"PROTOCOL_PROBE: Error - {str(e)}")
        
        # 8. Calculate confidence score
        result.confidence_score = self._calculate_confidence_score(result)
        self.logger.debug(f"Scan completed for {target}:{port} - Confidence Score: {result.confidence_score:.1f}/100")
        result.scan_log.append(f"SCAN_COMPLETE: Confidence {result.confidence_score:.1f}/100")
        
        return result

    def _check_port_open(self, target: str, port: int) -> bool:
        """Basic port connectivity check"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.connect_timeout)
                result = sock.connect_ex((target, port))
                return result == 0
        except Exception as e:
            self.logger.debug(f"Port check error: {e}")
            return False

    def _grab_banner(self, target: str, port: int) -> Optional[str]:
        """Basic banner grabbing - single probe only"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.read_timeout)
                sock.connect((target, port))
                
                # Single HTTP probe for web services, otherwise just listen
                if port in [80, 443, 8080, 8443]:
                    probe = b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n"
                    sock.send(probe)
                
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner if banner else None
                        
        except Exception as e:
            self.logger.debug(f"Banner grab error for {target}:{port}: {e}")
        
        return None

    def _nmap_basic_scan(self, target: str, port: int) -> Optional[Dict]:
        """Basic nmap service detection only"""
        try:
            cmd = [
                'nmap', '-sV',  # Just version detection
                '-p', str(port), target, 
                '--host-timeout', f'{self.nmap_timeout}s',
                '--max-retries', '1'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.nmap_timeout)
            
            if result.returncode == 0:
                output = result.stdout
                parsed = {
                    'raw_output': output,
                    'command': ' '.join(cmd)
                }
                
                # Extract key information
                if 'open' in output:
                    parsed['status'] = 'open'
                if 'version' in output.lower():
                    version_match = re.search(r'version ([^\s<]+)', output, re.IGNORECASE)
                    if version_match:
                        parsed['version'] = version_match.group(1)
                
                return parsed
                
        except subprocess.TimeoutExpired:
            self.logger.debug(f"Nmap scan timed out for {target}:{port} after {self.nmap_timeout}s")
            return {'error': 'timeout', 'timeout_duration': self.nmap_timeout}
        except FileNotFoundError:
            self.logger.debug("Nmap not found - skipping nmap scan")
            return {'error': 'nmap_not_found'}
        except Exception as e:
            self.logger.debug(f"Nmap scan error: {e}")
            return {'error': str(e)}
        
        return None

    def _detect_service_version(self, target: str, port: int, banner: Optional[str], 
                              nmap_results: Optional[Dict]) -> tuple:
        """Detect service and version from multiple sources"""
        service = self.common_services.get(port, 'unknown')
        version = None
        
        # Check nmap results first
        if nmap_results and 'version' in nmap_results:
            version = nmap_results['version']
        
        # Parse banner for service info
        if banner:
            # HTTP servers
            if 'Apache' in banner:
                service = 'apache'
                apache_match = re.search(r'Apache/(\S+)', banner)
                if apache_match:
                    version = apache_match.group(1)
            elif 'nginx' in banner:
                service = 'nginx'
                nginx_match = re.search(r'nginx/(\S+)', banner)
                if nginx_match:
                    version = nginx_match.group(1)
            elif 'Microsoft-IIS' in banner:
                service = 'iis'
                iis_match = re.search(r'Microsoft-IIS/(\S+)', banner)
                if iis_match:
                    version = iis_match.group(1)
            
            # SSH
            elif 'OpenSSH' in banner:
                service = 'openssh'
                ssh_match = re.search(r'OpenSSH_(\S+)', banner)
                if ssh_match:
                    version = ssh_match.group(1)
            
            # FTP
            elif 'FTP' in banner:
                service = 'ftp'
                # Try to extract version
                version_match = re.search(r'(\d+\.\d+[\.\d]*)', banner)
                if version_match:
                    version = version_match.group(1)
        
        return service, version

    def _is_ssl_port(self, port: int) -> bool:
        """Check if port commonly uses SSL"""
        ssl_ports = {443, 993, 995, 2376, 8443}
        return port in ssl_ports

    def _appears_ssl(self, banner: Optional[str]) -> bool:
        """Check if banner suggests SSL"""
        if not banner:
            return False
        return any(keyword in banner.lower() for keyword in ['ssl', 'tls', 'https'])

    def _analyze_ssl(self, target: str, port: int) -> Optional[Dict]:
        """Comprehensive SSL/TLS analysis"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.read_timeout)
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    ssock.connect((target, port))
                    
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    ssl_info = {
                        'protocol_version': version,
                        'cipher_suite': cipher[0] if cipher else None,
                        'cipher_strength': cipher[2] if cipher else None,
                        'certificate': {
                            'subject': dict(x[0] for x in cert.get('subject', [])),
                            'issuer': dict(x[0] for x in cert.get('issuer', [])),
                            'not_before': cert.get('notBefore'),
                            'not_after': cert.get('notAfter'),
                            'san': cert.get('subjectAltName', [])
                        }
                    }
                    
                    return ssl_info
                    
        except socket.timeout:
            self.logger.debug(f"SSL analysis timeout for {target}:{port}")
            return {'error': 'timeout'}
        except ssl.SSLError as e:
            self.logger.debug(f"SSL error for {target}:{port}: {e}")
            return {'error': f'ssl_error: {str(e)}'}
        except Exception as e:
            self.logger.debug(f"SSL analysis error for {target}:{port}: {e}")
            return {'error': str(e)}
        
        return None

    def _is_http_port(self, port: int) -> bool:
        """Check if port commonly serves HTTP"""
        http_ports = {80, 443, 8080, 8443, 8000, 9000, 9090}
        return port in http_ports

    def _appears_http(self, service: Optional[str]) -> bool:
        """Check if service appears to be HTTP-based"""
        if not service:
            return False
        http_services = ['http', 'https', 'apache', 'nginx', 'iis']
        return any(s in service.lower() for s in http_services)

    def _analyze_http(self, target: str, port: int) -> Optional[Dict]:
        """Basic HTTP analysis - just HEAD and GET requests"""
        schemes = ['https'] if self._is_ssl_port(port) else ['http']
        
        for scheme in schemes:
            try:
                url = f"{scheme}://{target}:{port}/"
                
                # Just try HEAD and GET on root
                http_info = {'url': url, 'methods': {}}
                
                for method in ['HEAD', 'GET']:
                    try:
                        response = self.session.request(
                            method, url, 
                            timeout=(self.connect_timeout, self.read_timeout), 
                            verify=False
                        )
                        
                        method_info = {
                            'status_code': response.status_code,
                            'headers': dict(response.headers),
                            'content_length': len(response.content) if hasattr(response, 'content') else 0
                        }
                        
                        if method == 'GET' and response.content:
                            content = response.text[:200]  # Just first 200 chars
                            # Extract title only
                            title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
                            if title_match:
                                method_info['title'] = title_match.group(1).strip()
                        
                        http_info['methods'][method] = method_info
                        break  # If one works, don't try the other
                        
                    except Exception as e:
                        self.logger.debug(f"HTTP {method} error: {e}")
                        continue
                
                return http_info if http_info['methods'] else None
                
            except requests.exceptions.Timeout:
                self.logger.debug(f"HTTP analysis timeout for {scheme}://{target}:{port}")
                return {'error': 'timeout', 'url': f"{scheme}://{target}:{port}"}
            except requests.exceptions.ConnectionError as e:
                self.logger.debug(f"HTTP connection error for {scheme}://{target}:{port}: {e}")
                return {'error': f'connection_error: {str(e)}', 'url': f"{scheme}://{target}:{port}"}
            except Exception as e:
                self.logger.debug(f"HTTP analysis error for {scheme}://{target}:{port}: {e}")
                continue
        
        return None

    def _protocol_specific_probe(self, target: str, port: int, result: PortScanResult):
        """Minimal protocol-specific probing"""
        
        # Only check obvious cases with single requests
        if port == 2375:  # Unsecured Docker
            try:
                docker_url = f"http://{target}:{port}/version"
                response = self.session.get(
                    docker_url, 
                    timeout=(self.connect_timeout, self.read_timeout), 
                    verify=False
                )
                if response.status_code == 200:
                    result.raw_data['docker_accessible'] = True
            except:
                pass
        
        elif port == 9090:  # Prometheus
            try:
                metrics_url = f"http://{target}:{port}/metrics"
                response = self.session.head(  # Just HEAD request
                    metrics_url, 
                    timeout=(self.connect_timeout, self.read_timeout)
                )
                if response.status_code == 200:
                    result.raw_data['metrics_accessible'] = True
            except:
                pass

    def _calculate_confidence_score(self, result: PortScanResult) -> float:
        """
        Calculate confidence score (0-100) based on data collection success
        Higher score = more confidence in the accuracy and completeness of collected data
        """
        if not result.is_open:
            return 100.0  # High confidence that port is closed
        
        score = 0.0
        max_score = 0.0
        
        # Banner grabbing (20 points possible)
        max_score += 20
        if result.banner:
            if len(result.banner) > 50:
                score += 20  # Good banner data
            else:
                score += 10  # Some banner data
        
        # Nmap results (25 points possible)
        max_score += 25
        if result.nmap_results:
            if result.nmap_results.get('raw_output') and len(result.nmap_results['raw_output']) > 100:
                score += 25  # Comprehensive nmap data
            else:
                score += 15  # Basic nmap data
        
        # Service detection (15 points possible)
        max_score += 15
        if result.service and result.service != 'unknown':
            score += 10
            if result.version:
                score += 5  # Bonus for version info
        
        # SSL analysis (if applicable - 20 points possible)
        if self._is_ssl_port(result.port) or self._appears_ssl(result.banner):
            max_score += 20
            if result.ssl_info:
                if result.ssl_info.get('error'):
                    score += 5  # Partial credit for trying
                else:
                    score += 15
                    if result.ssl_info.get('certificate'):
                        score += 5  # Bonus for certificate details
        
        # HTTP analysis (if applicable - 20 points possible)  
        if self._is_http_port(result.port) or self._appears_http(result.service):
            max_score += 20
            if result.http_info:
                if result.http_info.get('error'):
                    score += 5  # Partial credit for trying
                else:
                    methods_count = len(result.http_info.get('methods', {}))
                    if methods_count >= 1:
                        score += 20  # Any HTTP data is good enough
        
        # Protocol-specific probing (bonus points - up to 10)
        if result.raw_data:
            data_points = len([k for k in result.raw_data.keys() if not k.startswith('_')])
            score += min(10, data_points * 2)
        
        # Error penalty - check scan log for failures
        error_count = len([log for log in result.scan_log if 'Error' in log or 'Failed' in log])
        score -= error_count * 5
        
        # Timeout penalty
        timeout_count = len([log for log in result.scan_log if 'timeout' in log.lower()])
        score -= timeout_count * 8
        
        # Calculate percentage
        if max_score > 0:
            confidence = (score / max_score) * 100
        else:
            confidence = 50.0  # Default for edge cases
        
        return max(0.0, min(100.0, confidence))

    def _generate_scan_report(self, target: str, results: List[PortScanResult], skip_nmap: bool) -> Dict[str, Any]:
        """Generate comprehensive scan report"""
        report = {
            'target': target,
            'scanner_type': self.scanner_type,
            'timestamp': datetime.now().isoformat(),
            'scan_summary': {
                'timestamp': datetime.now().isoformat(),
                'total_ports': len(results),
                'open_ports': sum(1 for r in results if r.is_open),
                'closed_ports': sum(1 for r in results if not r.is_open),
                'average_confidence': sum(r.confidence_score for r in results) / len(results) if results else 0
            },
            'scan_config': {
                'timeout': self.timeout,
                'connect_timeout': self.connect_timeout,
                'read_timeout': self.read_timeout,
                'nmap_timeout': self.nmap_timeout,
                'max_threads': self.max_threads,
                'skip_nmap': skip_nmap
            },
            'detailed_results': [asdict(result) for result in results]
        }
        
        # Round average confidence
        report['scan_summary']['average_confidence'] = round(report['scan_summary']['average_confidence'], 2)
        
        return report