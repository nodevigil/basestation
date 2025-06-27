"""
Consolidated scanning orchestrator that coordinates multiple scanner types.
This replaces the old scanner.py with a modular, configurable approach.
"""

from typing import Dict, Any, List, Optional, Tuple
import logging
import time
from .base_scanner import ScannerRegistry
from .routing import get_scanners_for_level
from ..tools.nmap import nmap_scan
from ..tools.whatweb import whatweb_scan
from ..tools.ssltester import ssl_test
from ..tools.docker import DockerExposureChecker
from ..core.logging import get_logger

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
    
    def scan(self, target: str, ports: Optional[List[int]] = None, scan_level: int = 1, protocol: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """Perform comprehensive scan using multiple scanner types.
        
        Args:
            target: Target IP address or hostname
            ports: List of ports to scan
            scan_level: Scan level (1-3, default: 1)
            protocol: Optional protocol name for routing
            **kwargs: Additional scan parameters
            
        Returns:
            Comprehensive scan results
        """
        # Track overall scan timing
        scan_start_time = int(time.time())
        
        self.logger.info(f"Starting comprehensive scan of {target} (level {scan_level}, protocol: {protocol})")
        
        # Get the list of scanners to run based on level and protocol
        scanners_to_run = get_scanners_for_level(scan_level, protocol)
        self.logger.debug(f"Scanners to run for level {scan_level} ({protocol}): {scanners_to_run}")

        results = {
            "target": target,
            "scan_level": scan_level,
            "protocol": protocol,
            "scan_timestamp": kwargs.get('scan_timestamp'),
            "scan_start_time": scan_start_time,
            "scan_results": {},
            "external_tools": {},
            "stage_timings": {}
        }
        
        # Separate internal scanners from external tools
        internal_scanners = [s for s in scanners_to_run if s in self.scanner_registry.get_registered_scanners()]
        external_tools = [s for s in scanners_to_run if s not in internal_scanners]
        
        # Filter out protocol-specific scanners when no protocol is specified
        if not protocol:
            original_scanners = internal_scanners.copy()
            internal_scanners = self._filter_infrastructure_scanners(internal_scanners)
            if len(internal_scanners) != len(original_scanners):
                filtered_out = [s for s in original_scanners if s not in internal_scanners]
                self.logger.info(f"Filtered out protocol-specific scanners (no protocol specified): {filtered_out}")
                self.logger.debug(f"Running infrastructure scanners only: {internal_scanners}")

        # Run internal scanners with timing
        if internal_scanners:
            scanners_stage_start = int(time.time())
            self.logger.info(f"Starting scanner stage with {len(internal_scanners)} scanners")
            
            for scanner_type in internal_scanners:
                try:
                    scanner = self.scanner_registry.get_scanner(scanner_type)
                    if scanner:
                        scanner_start = int(time.time())
                        self.logger.debug(f"Running {scanner_type} scanner (level {scan_level})")
                        scan_result = scanner.scan(target, ports=ports, scan_level=scan_level, **kwargs)
                        scanner_end = int(time.time())
                        
                        results["scan_results"][scanner_type] = scan_result
                        
                        # Only add timing if scan produced meaningful results
                        if self._has_meaningful_results(scan_result):
                            results["stage_timings"][f"scanner_{scanner_type}"] = {
                                "start_time": scanner_start,
                                "end_time": scanner_end,
                                "duration": scanner_end - scanner_start
                            }
                    else:
                        self.logger.warning(f"Scanner {scanner_type} not available")
                except Exception as e:
                    self.logger.error(f"Failed to run {scanner_type} scanner: {e}")
                    results["scan_results"][scanner_type] = {"error": str(e)}
            
            scanners_stage_end = int(time.time())
            
            # Only add scanners stage timing if any scanner produced meaningful results
            scanner_had_results = any(
                f"scanner_{scanner_type}" in results["stage_timings"] 
                for scanner_type in internal_scanners
            )
            if scanner_had_results:
                results["stage_timings"]["scanners_stage"] = {
                    "start_time": scanners_stage_start,
                    "end_time": scanners_stage_end,
                    "duration": scanners_stage_end - scanners_stage_start
                }
        
        # Run external tools with timing
        if self.use_external_tools and external_tools:
            external_tools_stage_start = int(time.time())
            self.logger.info(f"Starting external tools stage with {len(external_tools)} tools")
            
            results["external_tools"] = self._run_external_tools(target, results, external_tools)
            
            external_tools_stage_end = int(time.time())
            
            # Only add external tools stage timing if any tool produced meaningful results
            tool_had_results = any(
                key.startswith("tool_") and key in results["stage_timings"]
                for key in results["stage_timings"]
            )
            if tool_had_results:
                results["stage_timings"]["external_tools_stage"] = {
                    "start_time": external_tools_stage_start,
                    "end_time": external_tools_stage_end,
                    "duration": external_tools_stage_end - external_tools_stage_start
                }
        
        # Record total scan timing only if any meaningful results were found
        scan_end_time = int(time.time())
        results["scan_end_time"] = scan_end_time
        
        # Only add total scan timing if there were any meaningful stage results
        if results["stage_timings"]:
            results["stage_timings"]["total_scan"] = {
                "start_time": scan_start_time,
                "end_time": scan_end_time,
                "duration": scan_end_time - scan_start_time
            }
        
        self.logger.info(f"Scan completed in {scan_end_time - scan_start_time} seconds")
        
        # Post-process results to match legacy format
        legacy_results = self._convert_to_legacy_format(results)
        
        return legacy_results
    
    def _filter_infrastructure_scanners(self, enabled_scanners: List[str]) -> List[str]:
        """Filter out protocol-specific scanners, keeping only infrastructure scanners.
        
        Args:
            enabled_scanners: List of all enabled scanners
            
        Returns:
            List of infrastructure scanners only
        """
        # Define protocol-specific scanners that should not run during infrastructure scanning
        protocol_scanners = {
            'sui', 'filecoin', 'ethereum', 'solana', 'cosmos', 'polkadot', 
            'avalanche', 'cardano', 'algorand', 'near', 'chainlink',
            'bitcoin', 'litecoin', 'dogecoin', 'monero', 'zcash'
        }
        
        # Return only infrastructure scanners
        infrastructure_scanners = [
            scanner for scanner in enabled_scanners 
            if scanner not in protocol_scanners
        ]
        
        self.logger.debug(f"Filtered infrastructure scanners: {infrastructure_scanners}")
        return infrastructure_scanners
    
    def _run_external_tools(self, target: str, scan_results: Dict[str, Any], enabled_tools: List[str]) -> Dict[str, Any]:
        """Run external scanning tools based on the routing function's output.
        
        Args:
            target: Target to scan
            scan_results: Results from modular scanners
            enabled_tools: List of external tools to run for this scan
            
        Returns:
            External tool results
        """
        external_results = {}
        
        # Nmap scan
        if 'nmap' in enabled_tools:
            nmap_start = int(time.time())
            try:
                self.logger.info(f"Running nmap scan for {target}")
                nmap_results = nmap_scan(target)
                nmap_end = int(time.time())
                
                external_results["nmap"] = nmap_results
                
                # Only add timing if nmap found meaningful results
                if self._has_meaningful_results(nmap_results):
                    scan_results["stage_timings"]["tool_nmap"] = {
                        "start_time": nmap_start,
                        "end_time": nmap_end,
                        "duration": nmap_end - nmap_start
                    }
                    
                self.logger.debug(f"Nmap results: {nmap_results}")
            except Exception as e:
                nmap_end = int(time.time())
                self.logger.error(f"Nmap scan failed for {target}: {e}")
                external_results["nmap"] = {"error": str(e)}
        
        # WhatWeb scan
        if 'whatweb' in enabled_tools:
            whatweb_start = int(time.time())
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
            
            whatweb_end = int(time.time())
            if whatweb_results:
                external_results["whatweb"] = whatweb_results
                
                # Only add timing if whatweb found results
                scan_results["stage_timings"]["tool_whatweb"] = {
                    "start_time": whatweb_start,
                    "end_time": whatweb_end,
                    "duration": whatweb_end - whatweb_start
                }
        
        # SSL test
        if 'ssl' in enabled_tools or 'ssl_test' in enabled_tools:
            ssl_start = int(time.time())
            try:
                self.logger.debug(f"Running SSL test for {target}")
                ssl_results = ssl_test(target, port=443)
                ssl_end = int(time.time())
                
                external_results["ssl_test"] = ssl_results
                
                # Only add timing if SSL test found meaningful results
                if self._has_meaningful_results(ssl_results):
                    scan_results["stage_timings"]["tool_ssl_test"] = {
                        "start_time": ssl_start,
                        "end_time": ssl_end,
                        "duration": ssl_end - ssl_start
                    }
            except Exception as e:
                ssl_end = int(time.time())
                self.logger.debug(f"SSL test failed for {target}: {e}")
                external_results["ssl_test"] = {"error": str(e)}
        
        # Dirbuster scan
        if 'dirbuster' in enabled_tools:
            dirbuster_start = int(time.time())
            # Placeholder for dirbuster logic
            self.logger.info(f"Dirbuster scan requested for {target}, but not yet implemented.")
            dirbuster_end = int(time.time())
            
            external_results["dirbuster"] = {"status": "not_implemented"}
            scan_results["stage_timings"]["tool_dirbuster"] = {
                "start_time": dirbuster_start,
                "end_time": dirbuster_end,
                "duration": dirbuster_end - dirbuster_start
            }

        # DNSDumpster scan
        if 'dnsdumpster' in enabled_tools:
            dnsdumpster_start = int(time.time())
            # Placeholder for dnsdumpster logic
            self.logger.info(f"DNSDumpster scan requested for {target}, but not yet implemented.")
            dnsdumpster_end = int(time.time())
            
            external_results["dnsdumpster"] = {"status": "not_implemented"}
            scan_results["stage_timings"]["tool_dnsdumpster"] = {
                "start_time": dnsdumpster_start,
                "end_time": dnsdumpster_end,
                "duration": dnsdumpster_end - dnsdumpster_start
            }

        # Docker exposure check
        if 'docker' in enabled_tools or 'docker_exposure' in enabled_tools:
            docker_start = int(time.time())
            open_ports = self._extract_open_ports(scan_results)
            if 2375 in open_ports:
                try:
                    self.logger.debug(f"Running Docker exposure check for {target}")
                    docker_exposure = DockerExposureChecker.check(target)
                    docker_end = int(time.time())
                    
                    external_results["docker_exposure"] = docker_exposure
                    
                    # Only add timing if Docker check found exposure
                    if docker_exposure.get("exposed", False):
                        scan_results["stage_timings"]["tool_docker_exposure"] = {
                            "start_time": docker_start,
                            "end_time": docker_end,
                            "duration": docker_end - docker_start
                        }
                except Exception as e:
                    docker_end = int(time.time())
                    self.logger.debug(f"Docker exposure check failed for {target}: {e}")
                    external_results["docker_exposure"] = {"error": str(e)}
            else:
                docker_end = int(time.time())
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
            "ssl_test": external_tools.get("ssl_test", {}),
            # Preserve timing information
            "scan_start_time": results.get("scan_start_time"),
            "scan_end_time": results.get("scan_end_time"),
            "stage_timings": results.get("stage_timings", {})
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

    def _has_meaningful_results(self, results: Dict[str, Any]) -> bool:
        """Check if scan results contain meaningful data.
        
        Args:
            results: Scan results dictionary
            
        Returns:
            True if results contain meaningful data, False otherwise
        """
        if not results or not isinstance(results, dict):
            return False
            
        # Check for error conditions
        if results.get("error"):
            return False
            
        # Check for meaningful content based on result type
        
        # For nmap results
        if "ports" in results:
            ports = results.get("ports", [])
            return len(ports) > 0
            
        # For scanner results with open_ports
        if "open_ports" in results:
            open_ports = results.get("open_ports", [])
            return len(open_ports) > 0
            
        # For web results
        if "web_results" in results:
            web_results = results.get("web_results", {})
            return len(web_results) > 0
            
        # For vulnerability results
        if "vulnerabilities" in results:
            vulns = results.get("vulnerabilities", {})
            return len(vulns) > 0
            
        # For banners
        if "banners" in results:
            banners = results.get("banners", {})
            return len(banners) > 0
            
        # For SSL results - check if there's meaningful SSL data
        if "certificate" in results or "openssl_raw" in results:
            cert = results.get("certificate")
            openssl = results.get("openssl_raw", "")
            return bool(cert) or bool(openssl.strip())
            
        # For GeoIP results
        if "country_name" in results or "city_name" in results:
            country = results.get("country_name", "")
            city = results.get("city_name", "")
            # Don't consider "Private Network" as meaningful
            return bool(country and country != "Private Network") or bool(city and city != "Private Network")
            
        # Default: if there are any non-empty values (excluding common empty indicators)
        meaningful_keys = [k for k, v in results.items() 
                          if v and v != {} and v != "" and k not in ["error", "timestamp"]]
        return len(meaningful_keys) > 0

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
