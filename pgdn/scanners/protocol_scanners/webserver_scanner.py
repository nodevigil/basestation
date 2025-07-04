"""
Web Server Protocol Scanner

An advanced web server scanner that performs comprehensive web server analysis.
This scanner is designed to identify web server technologies, vulnerabilities, and configurations.
"""

import socket
import ssl
import requests
import re
import time
import asyncio
from typing import Dict, Any, Optional, List
from .base_protocol_scanner import ProtocolScanner


class WebServerScanner(ProtocolScanner):
    """
    Web Server protocol scanner for comprehensive web server analysis.
    
    Scan Levels:
    - Level 1: Basic web server detection and technology fingerprinting
    - Level 2: Security headers, WAF detection, and behavioral analysis
    - Level 3: Advanced vulnerability detection and admin panel discovery
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize Web Server scanner."""
        super().__init__(config)
        
        # Web server specific configuration
        self.web_ports = self.config.get('web_ports', [80, 443, 8080, 8000, 8443, 3000, 8888])
        self.ssl_ports = self.config.get('ssl_ports', [443, 8443])
        self.timeout = self.config.get('timeout', 10)
        
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
        """Web Server scanner supports all three levels."""
        return [1, 2, 3]

    def describe_levels(self) -> Dict[int, str]:
        """Describe what each scan level does for web servers."""
        return {
            1: "Basic web server detection, port scanning, and technology fingerprinting",
            2: "Security headers analysis, WAF detection, and behavioral fingerprinting", 
            3: "Advanced vulnerability detection, admin panel discovery, and comprehensive security assessment"
        }

    async def scan_protocol(self, target: str, hostname: Optional[str] = None, scan_level: int = 1, **kwargs) -> Dict[str, Any]:
        """Perform web server specific scan at the specified level."""
        self.logger.info(f"Starting Web Server scan of {target} at level {scan_level}")
        scan_start_time = time.time()
        
        results = {
            'scan_type': 'web_server_specific',
            'scan_level': scan_level,
            'target_ip': target,
            'hostname': hostname,
            'web_server_detected': False,
            'open_ports': [],
            'technologies': [],
            'errors': []
        }
        
        try:
            if scan_level == 1:
                level_results = await self._scan_level_1(target, hostname)
            elif scan_level == 2:
                level_results = await self._scan_level_2(target, hostname)
            elif scan_level == 3:
                level_results = await self._scan_level_3(target, hostname)
            else:
                raise ValueError(f"Invalid scan_level: {scan_level}")
            
            results.update(level_results)
            
            scan_duration = time.time() - scan_start_time
            results['scan_duration'] = scan_duration
            
            self.logger.info(f"Completed Web Server scan of {target} at level {scan_level} in {scan_duration:.2f}s")
            
        except Exception as e:
            self.logger.error(f"Web Server scan failed for {target}: {str(e)}")
            results['errors'].append(f"Scan error: {str(e)}")
            results['scan_duration'] = time.time() - scan_start_time
        
        return results

    async def _scan_level_1(self, target: str, hostname: Optional[str] = None) -> Dict[str, Any]:
        """Level 1: Basic web server detection and technology fingerprinting."""
        self.logger.info(f"Level 1 Web Server scan for {target}")
        
        results = {
            'open_ports': self._check_open_ports(target, [80, 443, 8080, 8000]),
            'tls_info': {},
            'http_headers': {},
            'technologies': []
        }
        
        # Check for TLS on common SSL ports
        if 443 in results['open_ports']:
            results['tls_info'] = self._analyze_tls_certificate(target, hostname)
        
        # Get HTTP headers and basic fingerprinting
        for port in results['open_ports']:
            headers = self._fetch_http_headers(target, port)
            if headers:
                results['http_headers'][str(port)] = headers
                results['web_server_detected'] = True
                
                # Extract technology information
                tech_info = self._fingerprint_basic_technologies(headers)
                if tech_info:
                    results['technologies'].extend(tech_info)
        
        # Add WAF detection at level 1
        if results.get('web_server_detected'):
            waf_info = self._detect_waf(target)
            results['waf'] = waf_info  # Include even if None/null
        
        # Remove duplicate technologies
        results['technologies'] = list(set(results['technologies']))
        
        return results

    async def _scan_level_2(self, target: str, hostname: Optional[str] = None) -> Dict[str, Any]:
        """Level 2: Security headers, WAF detection, and behavioral analysis."""
        # Get level 1 results first
        results = await self._scan_level_1(target, hostname)
        
        # Additional analysis for level 2
        if results.get('web_server_detected'):
            # WAF detection
            waf_info = self._detect_waf(target)
            results['waf'] = waf_info  # Include even if None/null
            
            # Security headers analysis
            security_headers = self._analyze_security_headers(results.get('http_headers', {}))
            results['security_headers'] = security_headers
            
            # Extended technology fingerprinting
            extended_tech = self._fingerprint_extended_technologies(target)
            if extended_tech:
                results['technologies'].extend(extended_tech)
            
            # Remove duplicate technologies
            results['technologies'] = list(set(results['technologies']))
        
        return results

    async def _scan_level_3(self, target: str, hostname: Optional[str] = None) -> Dict[str, Any]:
        """Level 3: Advanced vulnerability detection and admin panel discovery."""
        # Get level 2 results first
        results = await self._scan_level_2(target, hostname)
        
        if results.get('web_server_detected'):
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
        
        return results

    def _check_open_ports(self, target: str, ports: List[int]) -> List[int]:
        """Check which ports are open on the target."""
        open_ports = []
        for port in ports:
            try:
                with socket.create_connection((target, port), timeout=2):
                    open_ports.append(port)
            except:
                continue
        return open_ports

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

    def _fetch_http_headers(self, target: str, port: int) -> Dict[str, str]:
        """Fetch HTTP headers from the target."""
        try:
            scheme = "https" if port in self.ssl_ports else "http"
            url = f"{scheme}://{target}:{port}/"
            response = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=False)
            return dict(response.headers)
        except Exception:
            return {}

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

    def _detect_waf(self, target: str) -> Optional[Dict[str, Any]]:
        """Detect Web Application Firewall."""
        try:
            # Test with suspicious payload
            test_url = f"http://{target}/test?id=1' OR '1'='1"
            response = requests.get(test_url, timeout=self.timeout)
            
            waf_indicators = {
                "cloudflare": ["cloudflare", "cf-ray"],
                "akamai": ["akamai", "x-akamai"],
                "aws": ["x-amzn", "cloudfront"],
                "sucuri": ["x-sucuri", "sucuri"]
            }
            
            response_text = response.text.lower()
            response_headers = {k.lower(): v.lower() for k, v in response.headers.items()}
            
            for waf_name, indicators in waf_indicators.items():
                for indicator in indicators:
                    if indicator in response_text or any(indicator in h for h in response_headers):
                        return {"detected": True, "type": waf_name, "method": "signature"}
            
            # Generic WAF detection
            if response.status_code in [403, 406, 429] or "blocked" in response_text:
                return {"detected": True, "type": "unknown", "method": "behavior"}
        except:
            pass
        
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


def run(target, scan_level=1, hostname=None) -> Dict[str, Any]:
    """Convenience function to run web server scan."""
    scanner = WebServerScanner()
    return asyncio.run(scanner.scan_protocol(target, hostname=hostname, scan_level=scan_level))