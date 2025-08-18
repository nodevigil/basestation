"""
Web Server Protocol Scanner

Comprehensive web server scanner that performs complete web server analysis including:
- Port scanning and service detection
- TLS/SSL certificate analysis  
- Technology fingerprinting
- WAF/CDN detection using integrated tools
- Security headers analysis
- Admin panel discovery
- Vulnerability detection
"""

import socket
import ssl
import requests
import re
import time
import asyncio
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from .base_protocol_scanner import ProtocolScanner
from ...tools import cloudflare, akamai, sucuri


@dataclass
class WebPortResult:
    """Container for single web port scan results"""
    port: int
    scheme: str  # "http" or "https"
    is_tcp_open: bool = False
    has_web_server: bool = False
    http_status_code: Optional[int] = None
    http_headers: Optional[Dict[str, str]] = None
    server_banner: Optional[str] = None
    tls_info: Optional[Dict[str, Any]] = None
    error_details: Optional[str] = None
    tcp_connect_time: Optional[float] = None
    http_response_time: Optional[float] = None
    content_length: Optional[int] = None
    final_url: Optional[str] = None


class WebServerScanner(ProtocolScanner):
    """
    Web Server protocol scanner for comprehensive web server analysis.
    
    Performs complete scanning in a single pass including:
    - Port scanning and service detection
    - TLS/SSL certificate analysis
    - Technology fingerprinting
    - WAF/CDN detection using integrated tools
    - Security headers analysis
    - Admin panel discovery
    - Vulnerability detection
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize Web Server scanner."""
        super().__init__(config)
        
        # Web server specific configuration
        self.web_ports = self.config.get('web_ports', [80, 443, 8080, 8000, 8443, 3000, 8888])
        self.ssl_ports = self.config.get('ssl_ports', [443, 8443])
        self.timeout = self.config.get('timeout', 10)
        self.exclude_ports = self.config.get('exclude_ports', [])
        
        # Admin panel paths to check
        self.admin_paths = [
            "/admin", "/admin/login", "/cpanel", "/login", 
            "/wp-admin", "/administrator", "/panel", "/dashboard"
        ]
        
        self.logger.info(f"Initialized Web Server scanner with ports {self.web_ports}")

    @property
    def protocol_name(self) -> str:
        """Return the protocol name."""
        return "web"

    def get_supported_levels(self) -> List[int]:
        """Web Server scanner performs comprehensive scanning."""
        return [1]

    def describe_levels(self) -> Dict[int, str]:
        """Describe the comprehensive scan performed."""
        return {
            1: "Comprehensive web server analysis including port scanning, TLS analysis, technology fingerprinting, WAF detection, security headers, admin panels, and vulnerability assessment"
        }

    def scan_protocol(self, target: str, hostname: Optional[str] = None, scan_level: int = 1, exclude_ports: Optional[List[int]] = None, **kwargs) -> Dict[str, Any]:
        """Perform comprehensive web server scan."""
        self.logger.info(f"Starting Web Server scan of {target}")
        scan_start_time = time.time()
        
        # Apply port exclusions
        exclude_ports = exclude_ports or self.exclude_ports or []
        if exclude_ports:
            self.logger.info(f"Excluding ports from web scan: {exclude_ports}")
        
        results = {
            'scan_type': 'web_server_specific',
            'target_ip': target,
            'hostname': hostname,
            'web_server_detected': False,
            'open_ports': [],
            'technologies': [],
            'errors': []
        }
        
        try:
            # Perform comprehensive scan
            comprehensive_results = self._comprehensive_scan(target, hostname, exclude_ports)
            results.update(comprehensive_results)
            
            scan_duration = time.time() - scan_start_time
            results['scan_duration'] = scan_duration
            
            self.logger.info(f"Completed Web Server scan of {target} in {scan_duration:.2f}s")
            
        except Exception as e:
            self.logger.error(f"Web Server scan failed for {target}: {str(e)}")
            results['errors'].append(f"Scan error: {str(e)}")
            results['scan_duration'] = time.time() - scan_start_time
        
        return results

    def _comprehensive_scan(self, target: str, hostname: Optional[str] = None, exclude_ports: Optional[List[int]] = None) -> Dict[str, Any]:
        """Perform comprehensive web server analysis."""
        self.logger.info(f"Comprehensive Web Server scan for {target}")
        
        # Focus on common web ports first for faster scanning
        common_web_ports = [80, 443, 8080, 8000]
        
        # Filter out excluded ports
        exclude_ports = exclude_ports or []
        if exclude_ports:
            common_web_ports = [port for port in common_web_ports if port not in exclude_ports]
            self.logger.debug(f"Filtered common web ports after exclusions: {common_web_ports}")
        
        # Scan ports with detailed validation
        port_results = self._scan_web_ports(target, common_web_ports, hostname)
        
        # Build results structure
        results = {
            'port_results': [asdict(result) for result in port_results],
            'web_server_detected': any(result.has_web_server for result in port_results),
            'technologies': [],
            'summary': {
                'tcp_open_ports': [r.port for r in port_results if r.is_tcp_open],
                'web_server_ports': [r.port for r in port_results if r.has_web_server],
                'total_ports_tested': len(port_results)
            },
            # Legacy compatibility - but now only includes ports with actual web servers
            'open_ports': [r.port for r in port_results if r.has_web_server]
        }
        
        # Collect TLS info from any HTTPS ports
        tls_info = {}
        for result in port_results:
            if result.tls_info:
                tls_info[str(result.port)] = result.tls_info
        if tls_info:
            results['tls_info'] = tls_info
        
        # Extract technologies from successful HTTP responses
        for result in port_results:
            if result.has_web_server and result.http_headers:
                tech_info = self._fingerprint_basic_technologies(result.http_headers)
                if tech_info:
                    results['technologies'].extend(tech_info)
        
        # Build headers dict for backward compatibility
        http_headers = {}
        for result in port_results:
            if result.has_web_server and result.http_headers:
                http_headers[str(result.port)] = result.http_headers
        if http_headers:
            results['http_headers'] = http_headers
        
        if results.get('web_server_detected'):
            # WAF/CDN detection using integrated tools (use web server ports, not just open ports)
            web_server_ports = results['summary']['web_server_ports']
            waf_info = self._detect_waf_comprehensive(target, web_server_ports, exclude_ports)
            if waf_info:
                results['waf'] = waf_info
            
            # Security headers analysis
            security_headers = self._analyze_security_headers(results.get('http_headers', {}))
            results['security_headers'] = security_headers
            
            # Extended technology fingerprinting
            extended_tech = self._fingerprint_extended_technologies(target)
            if extended_tech:
                results['technologies'].extend(extended_tech)
            
            # Admin panel discovery
            admin_panels = self._find_exposed_admin_panels(target)
            if admin_panels:
                results['admin_panels'] = admin_panels
            
            # Known vulnerability matching
            cves = self._match_known_webserver_cves(results.get('http_headers', {}))
            if cves:
                results['cves'] = cves
            
            # Security score calculation
            results['security_score'] = self._calculate_security_score(results)
            
            # Remove duplicate technologies
            results['technologies'] = list(set(results['technologies']))
        
        return results

    def _scan_web_ports(self, target: str, ports: List[int], hostname: Optional[str] = None) -> List[WebPortResult]:
        """Scan ports for actual web server presence, not just TCP connectivity."""
        results = []
        
        for port in ports:
            # Determine scheme based on port
            scheme = "https" if port in self.ssl_ports else "http"
            
            result = WebPortResult(port=port, scheme=scheme)
            
            # Step 1: Test TCP connectivity
            tcp_start = time.time()
            try:
                with socket.create_connection((target, port), timeout=2):
                    result.is_tcp_open = True
                    result.tcp_connect_time = time.time() - tcp_start
                    self.logger.debug(f"TCP connection successful to {target}:{port}")
            except Exception as e:
                result.error_details = f"TCP connection failed: {str(e)}"
                self.logger.debug(f"TCP connection failed to {target}:{port}: {e}")
                results.append(result)
                continue
            
            # Step 2: Test HTTP response (only if TCP connected)
            if result.is_tcp_open:
                http_start = time.time()
                try:
                    url = f"{scheme}://{target}:{port}/"
                    response = requests.get(
                        url, 
                        timeout=self.timeout, 
                        verify=False, 
                        allow_redirects=False,
                        headers={'User-Agent': 'PGDN-Scanner/1.0'}
                    )
                    
                    # Success - we got an HTTP response
                    result.has_web_server = True
                    result.http_status_code = response.status_code
                    result.http_headers = dict(response.headers)
                    result.server_banner = response.headers.get('Server')
                    result.content_length = len(response.content)
                    result.final_url = str(response.url)
                    result.http_response_time = time.time() - http_start
                    
                    self.logger.debug(f"HTTP response received from {target}:{port}: {response.status_code}")
                    
                except requests.exceptions.SSLError as e:
                    # TLS-specific error - still might be a web server with SSL issues
                    result.tls_info = {"error": str(e)}
                    result.error_details = f"TLS/SSL error: {str(e)}"
                    self.logger.debug(f"TLS error on {target}:{port}: {e}")
                    
                except requests.exceptions.Timeout:
                    result.error_details = "HTTP request timeout"
                    self.logger.debug(f"HTTP timeout on {target}:{port}")
                    
                except requests.exceptions.ConnectionError as e:
                    result.error_details = f"HTTP connection error: {str(e)}"
                    self.logger.debug(f"HTTP connection error on {target}:{port}: {e}")
                    
                except Exception as e:
                    result.error_details = f"HTTP request failed: {str(e)}"
                    self.logger.debug(f"HTTP request failed on {target}:{port}: {e}")
                
                # Step 3: If HTTPS port, try to get TLS certificate info even if HTTP failed
                if scheme == "https" and not result.tls_info:
                    try:
                        tls_info = self._analyze_tls_certificate(target, hostname)
                        if tls_info and "error" in tls_info:
                            result.tls_info = tls_info
                    except Exception:
                        pass  # TLS analysis is supplementary
            
            results.append(result)
        
        return results

    def _analyze_tls_certificate(self, target: str, hostname: Optional[str] = None) -> Dict[str, Any]:
        """Analyze TLS certificate information."""
        try:
            context = ssl.create_default_context()
            server_hostname = hostname or target
            with socket.create_connection((target, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        "subject": cert.get("subject"),
                        "issuer": cert.get("issuer"),
                        "notAfter": cert.get("notAfter"),
                        "notBefore": cert.get("notBefore"),
                        "version": cert.get("version"),
                        "serialNumber": cert.get("serialNumber")
                    }
        except Exception as e:
            return {"error": str(e)}

    def _fingerprint_basic_technologies(self, headers: Dict[str, str]) -> List[str]:
        """Basic technology fingerprinting from headers."""
        technologies = []
        server = headers.get("Server", "").lower()
        
        if "nginx" in server:
            technologies.append("nginx")
        if "apache" in server:
            technologies.append("apache")
        if "litespeed" in server:
            technologies.append("litespeed")
        if "cloudflare" in server:
            technologies.append("cloudflare")
        if "iis" in server:
            technologies.append("iis")
        
        # Check other headers
        if "x-powered-by" in headers:
            technologies.append(f"powered-by-{headers['x-powered-by'].lower()}")
        
        return technologies

    def _detect_waf_comprehensive(self, target: str, open_ports: List[int], exclude_ports: Optional[List[int]] = None) -> Optional[Dict[str, Any]]:
        """Comprehensive WAF/CDN detection using integrated tools."""
        detected_wafs = []
        exclude_ports = exclude_ports or []
        
        # Test common web ports for WAF/CDN detection
        all_web_ports = [80, 443, 8080, 8000, 8443]
        allowed_web_ports = [port for port in all_web_ports if port not in exclude_ports]
        web_ports_to_test = [port for port in open_ports if port in allowed_web_ports]
        
        if not web_ports_to_test:
            # Default fallback (also filtered by exclusions)
            fallback_ports = [80, 443]
            web_ports_to_test = [port for port in fallback_ports if port not in exclude_ports]
        
        for port in web_ports_to_test:
            try:
                # Test Cloudflare
                cf_result = cloudflare.probe(target, port=port, timeout=self.timeout)
                if cf_result and cf_result.get('detected'):
                    detected_wafs.append(cf_result)
                    continue  # Found one, no need to test others for this port
                
                # Test Akamai
                akamai_result = akamai.probe(target, port=port, timeout=self.timeout)
                if akamai_result and akamai_result.get('detected'):
                    detected_wafs.append(akamai_result)
                    continue
                
                # Test Sucuri
                sucuri_result = sucuri.probe(target, port=port, timeout=self.timeout)
                if sucuri_result and sucuri_result.get('detected'):
                    detected_wafs.append(sucuri_result)
                    
            except Exception as e:
                self.logger.debug(f"WAF detection failed for {target}:{port}: {e}")
                continue
        
        # Return results
        if detected_wafs:
            # If multiple WAFs detected, return the first one with additional info
            primary_waf = detected_wafs[0]
            return {
                'detected': True,
                'vendor': primary_waf.get('vendor', 'unknown'),
                'method': 'header_signature',
                'details': primary_waf,
                'all_detected': detected_wafs if len(detected_wafs) > 1 else None
            }
        
        return None

    def _analyze_security_headers(self, headers_by_port: Dict[str, Dict[str, str]]) -> Dict[str, Any]:
        """Analyze security headers."""
        security_analysis = {
            "missing_headers": [],
            "present_headers": [],
            "security_score": 0
        }
        
        important_headers = [
            "strict-transport-security",
            "x-frame-options", 
            "x-content-type-options",
            "x-xss-protection",
            "content-security-policy"
        ]
        
        # Analyze headers from all ports
        all_headers = {}
        for port_headers in headers_by_port.values():
            all_headers.update({k.lower(): v for k, v in port_headers.items()})
        
        for header in important_headers:
            if header in all_headers:
                security_analysis["present_headers"].append(header)
                security_analysis["security_score"] += 20
            else:
                security_analysis["missing_headers"].append(header)
        
        return security_analysis

    def _fingerprint_extended_technologies(self, target: str) -> List[str]:
        """Extended technology fingerprinting."""
        technologies = []
        
        # Check common CMS paths
        cms_checks = {
            "wordpress": "/wp-admin/",
            "drupal": "/user/login",
            "joomla": "/administrator/",
            "magento": "/admin/"
        }
        
        for cms, path in cms_checks.items():
            try:
                url = f"http://{target}{path}"
                response = requests.get(url, timeout=5, allow_redirects=False)
                if response.status_code in [200, 301, 302]:
                    technologies.append(cms)
            except:
                continue
        
        return technologies

    def _find_exposed_admin_panels(self, target: str) -> List[str]:
        """Find exposed administrative panels."""
        found_panels = []
        
        for path in self.admin_paths:
            try:
                url = f"http://{target}{path}"
                response = requests.get(url, timeout=5, allow_redirects=False)
                if response.status_code == 200:
                    found_panels.append(path)
            except:
                continue
        
        return found_panels

    def _match_known_webserver_cves(self, headers_by_port: Dict[str, Dict[str, str]]) -> List[Dict[str, str]]:
        """Match known CVEs based on server versions."""
        known_cves = []
        
        # Get all server headers
        for port_headers in headers_by_port.values():
            server = port_headers.get("Server", "")
            
            # Basic CVE matching (expand this with real CVE database)
            version_match = re.search(r"(nginx|Apache|IIS)/([\\d.]+)", server, re.IGNORECASE)
            if version_match:
                name, version = version_match.groups()
                
                if name.lower() == "nginx" and version.startswith("1.14"):
                    known_cves.append({
                        "product": "nginx", 
                        "version": version, 
                        "cve": "CVE-2019-20372",
                        "severity": "medium"
                    })
                elif name.lower() == "apache" and version.startswith("2.4.49"):
                    known_cves.append({
                        "product": "apache", 
                        "version": version, 
                        "cve": "CVE-2021-41773",
                        "severity": "critical"
                    })
        
        return known_cves

    def _calculate_security_score(self, results: Dict[str, Any]) -> int:
        """Calculate overall security score."""
        score = 100  # Start with perfect score
        
        # Deduct points for missing security headers
        missing_headers = results.get('security_headers', {}).get('missing_headers', [])
        score -= len(missing_headers) * 10
        
        # Deduct points for exposed admin panels
        admin_panels = results.get('admin_panels', [])
        score -= len(admin_panels) * 15
        
        # Deduct points for known CVEs
        cves = results.get('cves', [])
        for cve in cves:
            if cve.get('severity') == 'critical':
                score -= 30
            elif cve.get('severity') == 'high':
                score -= 20
            elif cve.get('severity') == 'medium':
                score -= 10
        
        # Ensure score doesn't go below 0
        return max(0, score)


def run(target, hostname=None) -> Dict[str, Any]:
    """Convenience function to run web server scan."""
    scanner = WebServerScanner()
    return asyncio.run(scanner.scan_protocol(target, hostname=hostname))