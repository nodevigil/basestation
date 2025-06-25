"""
Consolidated scanning orchestrator that coordinates multiple scanner types.
This replaces the old scanner.py with a modular, configurable approach.
"""

from typing import Dict, Any, List, Optional, Tuple
import logging
from pgdn.scanning.base_scanner import ScannerRegistry
from pgdn.tools.nmap import nmap_scan
from pgdn.tools.whatweb import whatweb_scan
from pgdn.tools.ssltester import ssl_test
from pgdn.tools.docker import DockerExposureChecker
from pgdn.core.logging import get_logger

logger = get_logger(__name__)


class ScanOrchestrator:
    """Orchestrates multiple scanner types in a coordinated fashion."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize scan orchestrator.
        
        Args:
            config: Scanning configuration dictionary
        """
        self.config = config or {}
        self.scanner_registry = ScannerRegistry(config)
        
        # Get orchestrator-specific config
        orchestrator_config = self.config.get('orchestrator', {})
        self.enabled_scanners = orchestrator_config.get('enabled_scanners', ['generic', 'web', 'vulnerability'])
        self.use_external_tools = orchestrator_config.get('use_external_tools', True)
        self.enabled_external_tools = orchestrator_config.get('enabled_external_tools', ['nmap', 'whatweb', 'ssl_test', 'docker_exposure'])
        self.logger = get_logger(__name__)
    
    def scan(self, target: str, ports: Optional[List[int]] = None, scan_level: int = 1, **kwargs) -> Dict[str, Any]:
        """Perform comprehensive scan using multiple scanner types.
        
        Args:
            target: Target IP address or hostname
            ports: List of ports to scan
            scan_level: Scan level (1-3, default: 1)
            **kwargs: Additional scan parameters
            
        Returns:
            Comprehensive scan results
        """
        self.logger.info(f"Starting comprehensive scan of {target} (level {scan_level})")
        
        results = {
            "target": target,
            "scan_level": scan_level,
            "scan_timestamp": kwargs.get('scan_timestamp'),
            "scan_results": {}
        }
        
        # Run GeoIP enrichment for level 1 and above
        if scan_level >= 1:
            try:
                from pgdn.scanning.geo_scanner import GeoScanner
                geo_scanner = GeoScanner(self.config.get('scanners', {}).get('geo', {}))
                self.logger.debug(f"Running GeoIP enrichment for {target}")
                geo_result = geo_scanner.scan(target, **kwargs)
                results["scan_results"]["geo"] = geo_result
            except Exception as e:
                self.logger.warning(f"GeoIP enrichment failed for {target}: {e}")
                results["scan_results"]["geo"] = {"error": str(e)}
        
        # Run enabled scanners with scan_level parameter
        for scanner_type in self.enabled_scanners:
            try:
                scanner = self.scanner_registry.get_scanner(scanner_type)
                if scanner:
                    self.logger.debug(f"Running {scanner_type} scanner (level {scan_level})")
                    scan_result = scanner.scan(target, ports=ports, scan_level=scan_level, **kwargs)
                    results["scan_results"][scanner_type] = scan_result
                else:
                    self.logger.warning(f"Scanner {scanner_type} not available")
            except Exception as e:
                self.logger.error(f"Failed to run {scanner_type} scanner: {e}")
                import traceback
                self.logger.error(traceback.format_exc())
                results["scan_results"][scanner_type] = {"error": str(e)}
        
        # Run external tools if enabled
        if self.use_external_tools:
            results["external_tools"] = self._run_external_tools(target, results)
        
        # Post-process results to match legacy format
        legacy_results = self._convert_to_legacy_format(results)
        
        return legacy_results
    
    def _run_external_tools(self, target: str, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Run external scanning tools.
        
        Args:
            target: Target to scan
            scan_results: Results from modular scanners
            
        Returns:
            External tool results
        """
        external_results = {}
        
        # Nmap scan
        if 'nmap' in self.enabled_external_tools:
            try:
                self.logger.info(f"Running nmap scan for {target}")
                nmap_results = nmap_scan(target)
                external_results["nmap"] = nmap_results
                self.logger.debug(f"Nmap results: {nmap_results}")
            except Exception as e:
                self.logger.error(f"Nmap scan failed for {target}: {e}")
                external_results["nmap"] = {"error": str(e)}
        
        # WhatWeb scan (on detected web ports)
        if 'whatweb' in self.enabled_external_tools:
            web_ports = self._extract_web_ports(scan_results, external_results.get("nmap"))
            whatweb_results = {}
            for port, scheme in web_ports:
                try:
                    self.logger.debug(f"Running WhatWeb scan for {scheme}://{target}:{port}")
                    result = whatweb_scan(target, port=port, scheme=scheme)
                    if result and (not isinstance(result, dict) or not result.get("error")):
                        whatweb_results[f"{scheme}://{target}:{port}"] = result
                except Exception as e:
                    self.logger.debug(f"WhatWeb scan failed for {target}:{port}: {e}")
            
            if whatweb_results:
                external_results["whatweb"] = whatweb_results
        
        # SSL test
        if 'ssl_test' in self.enabled_external_tools:
            try:
                self.logger.debug(f"Running SSL test for {target}")
                ssl_results = ssl_test(target, port=443)
                external_results["ssl_test"] = ssl_results
            except Exception as e:
                self.logger.debug(f"SSL test failed for {target}: {e}")
                external_results["ssl_test"] = {"error": str(e)}
        
        # Docker exposure check
        if 'docker_exposure' in self.enabled_external_tools:
            open_ports = self._extract_open_ports(scan_results)
            if 2375 in open_ports:
                try:
                    self.logger.debug(f"Running Docker exposure check for {target}")
                    docker_exposure = DockerExposureChecker.check(target)
                    external_results["docker_exposure"] = docker_exposure
                except Exception as e:
                    self.logger.debug(f"Docker exposure check failed for {target}: {e}")
                    external_results["docker_exposure"] = {"error": str(e)}
            else:
                external_results["docker_exposure"] = {"exposed": False}
        
        return external_results
    
    def _extract_open_ports(self, scan_results: Dict[str, Any]) -> List[int]:
        """Extract open ports from scan results.
        
        Args:
            scan_results: Scan results dictionary
            
        Returns:
            List of open ports
        """
        open_ports = []
        
        # Extract from generic scanner
        generic_results = scan_results.get("scan_results", {}).get("generic", {})
        if "open_ports" in generic_results:
            open_ports.extend(generic_results["open_ports"])
        
        return list(set(open_ports))  # Remove duplicates
    
    def _extract_web_ports(self, scan_results: Dict[str, Any], nmap_results: Optional[Dict[str, Any]] = None) -> List[Tuple[int, str]]:
        """Extract web ports and schemes from scan results.
        
        Args:
            scan_results: Scan results dictionary
            nmap_results: Optional nmap results
            
        Returns:
            List of (port, scheme) tuples
        """
        web_ports = []
        
        # Extract from nmap results if available
        if nmap_results and isinstance(nmap_results, dict) and "ports" in nmap_results:
            for port_info in nmap_results["ports"]:
                service = port_info.get("service", "")
                port = int(port_info["port"])
                if service == "https" or port == 443:
                    web_ports.append((port, "https"))
                elif service in ("http", "http-proxy") or port in (80, 8080):
                    web_ports.append((port, "http"))
        
        # Fallback: check common web ports from generic scan
        open_ports = self._extract_open_ports(scan_results)
        for port in open_ports:
            if port == 443 and (443, "https") not in web_ports:
                web_ports.append((port, "https"))
            elif port in [80, 8080] and not any(p[0] == port for p in web_ports):
                web_ports.append((port, "http"))
        
        return web_ports
    
    def _convert_to_legacy_format(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Convert new format results to legacy format for backward compatibility.
        
        Args:
            results: New format scan results
            
        Returns:
            Legacy format scan results
        """
        target = results["target"]
        scan_level = results.get("scan_level", 1)
        scan_results = results.get("scan_results", {})
        external_tools = results.get("external_tools", {})
        
        # Extract data from different scanners
        generic_results = scan_results.get("generic", {})
        web_results = scan_results.get("web", {})
        vuln_results = scan_results.get("vulnerability", {})
        geo_results = scan_results.get("geo", {})
        
        # Build legacy format
        nmap_data = external_tools.get("nmap", {})
        
        # Extract open ports from nmap if available, otherwise from generic scanner
        open_ports = []
        if nmap_data and "ports" in nmap_data:
            open_ports = [port_info["port"] for port_info in nmap_data["ports"] if port_info.get("state") == "open"]
        else:
            open_ports = generic_results.get("open_ports", [])
        
        legacy = {
            "ip": target,
            "scan_level": scan_level,
            "open_ports": open_ports,
            "banners": generic_results.get("banners", {}),
            "tls": generic_results.get("tls", {}),
            "http_headers": self._extract_http_headers(web_results),
            "vulns": self._format_vulnerabilities(vuln_results),
            "docker_exposure": external_tools.get("docker_exposure", {"exposed": False}),
            "nmap": external_tools.get("nmap", {}),
            "whatweb": external_tools.get("whatweb", {}),
            "ssl_test": external_tools.get("ssl_test", {})
        }
        
        # Add GeoIP data if available
        if geo_results and not geo_results.get("error"):
            legacy["geoip"] = {
                "country_name": geo_results.get("country_name"),
                "city_name": geo_results.get("city_name"),
                "latitude": geo_results.get("latitude"),
                "longitude": geo_results.get("longitude"),
                "asn_number": geo_results.get("asn_number"),
                "asn_organization": geo_results.get("asn_organization")
            }
        
        # Add debugging information if in debug mode  
        if self.logger.isEnabledFor(logging.DEBUG):
            legacy["_debug_info"] = {
                "enabled_scanners": self.enabled_scanners,
                "enabled_external_tools": self.enabled_external_tools,
                "scan_results_keys": list(scan_results.keys()),
                "external_tools_keys": list(external_tools.keys()),
                "nmap_raw": nmap_data
            }
        
        return legacy
    
    def _extract_http_headers(self, web_results: Dict[str, Any]) -> Dict[str, Any]:
        """Extract HTTP headers from web scan results.
        
        Args:
            web_results: Web scanner results
            
        Returns:
            HTTP headers dictionary
        """
        web_scan_results = web_results.get("web_results", {})
        
        # Return headers from first successful web scan
        for url, result in web_scan_results.items():
            if isinstance(result, dict) and "headers" in result:
                return result["headers"]
        
        return {}
    
    def _format_vulnerabilities(self, vuln_results: Dict[str, Any]) -> Dict[int, List[Dict[str, Any]]]:
        """Format vulnerability results for legacy compatibility.
        
        Args:
            vuln_results: Vulnerability scanner results
            
        Returns:
            Formatted vulnerability dictionary
        """
        vulnerabilities = vuln_results.get("vulnerabilities", {})
        
        # Convert string port keys to integers if needed
        formatted_vulns = {}
        for port, vulns in vulnerabilities.items():
            port_int = int(port) if isinstance(port, str) else port
            formatted_vulns[port_int] = vulns
        
        return formatted_vulns
    
    @staticmethod
    def get_web_ports_and_schemes(nmap_result: Dict[str, Any]) -> List[Tuple[int, str]]:
        """Static method for extracting web ports from nmap results."""
        web_ports = []
        if isinstance(nmap_result, dict) and "ports" in nmap_result:
            for port_info in nmap_result["ports"]:
                service = port_info.get("service", "")
                port = int(port_info["port"])
                if service == "https" or port == 443:
                    web_ports.append((port, "https"))
                elif service in ("http", "http-proxy") or port in (80, 8080):
                    web_ports.append((port, "http"))
        return web_ports


# Legacy compatibility: provide the old Scanner class interface
class Scanner(ScanOrchestrator):
    """Legacy Scanner class that wraps ScanOrchestrator for backward compatibility."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.logger.info("Using new modular scanning system (legacy compatibility mode)")
    
    @staticmethod
    def get_web_ports_and_schemes(nmap_result: Dict[str, Any]) -> List[Tuple[int, str]]:
        """Static method for extracting web ports from nmap results."""
        web_ports = []
        if isinstance(nmap_result, dict) and "ports" in nmap_result:
            for port_info in nmap_result["ports"]:
                service = port_info.get("service", "")
                port = int(port_info["port"])
                if service == "https" or port == 443:
                    web_ports.append((port, "https"))
                elif service in ("http", "http-proxy") or port in (80, 8080):
                    web_ports.append((port, "http"))
        return web_ports
