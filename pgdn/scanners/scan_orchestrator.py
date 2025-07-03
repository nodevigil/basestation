"""
Consolidated scanning orchestrator that coordinates multiple scanner types.
This replaces the old scanner.py with a modular, configurable approach.
"""

from typing import Dict, Any, List, Optional, Tuple
import logging
import time
import socket
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
        self.enabled_scanners = orchestrator_config.get('enabled_scanners', ['web', 'vulnerability'])
        self.use_external_tools = orchestrator_config.get('use_external_tools', True)
        self.enabled_external_tools = orchestrator_config.get('enabled_external_tools', ['nmap', 'whatweb', 'ssl_test', 'docker_exposure'])
        self.logger = get_logger(__name__)
    
    def scan(self, target: str, hostname: Optional[str] = None, ports: Optional[List[int]] = None, scan_level: int = 1, protocol: Optional[str] = None, resolved_ip: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """Perform comprehensive scan using multiple scanner types.
        
        Args:
            target: Target hostname or IP address (usually FQDN)
            hostname: Optional hostname for target IP (for hostname-based scans)
            ports: List of ports to scan
            scan_level: Scan level (1-3, default: 1)
            protocol: Optional protocol name for routing
            resolved_ip: Resolved IP address for IP-based operations
            **kwargs: Additional scan parameters
            
        Returns:
            Comprehensive scan results
        """
        # Track overall scan timing
        scan_start_time = int(time.time())
        
        self.logger.info(f"Starting comprehensive scan of {target} (level {scan_level}, protocol: {protocol})")
        
        # Use enabled_scanners if explicitly set, otherwise use routing for compliance scans
        if hasattr(self, '_enabled_scanners_set') and self._enabled_scanners_set:
            scanners_to_run = self.enabled_scanners
            self.logger.info(f"Running specific scanners: {scanners_to_run}")
        else:
            # Fallback to routing for compliance scans
            scanners_to_run = get_scanners_for_level(scan_level, protocol)
            self.logger.info(f"Scanners to run for level {scan_level} ({protocol}): {scanners_to_run}")

        results = {
            "target": target,
            "resolved_ip": resolved_ip,
            "hostname": hostname,
            "scan_level": scan_level,
            "protocol": protocol,
            "scan_timestamp": kwargs.get('scan_timestamp'),
            "scan_start_time": scan_start_time,
            "scan_results": {},
            "external_tools": {}
        }
        
        # When running individual scanners, use only the specified scanners/tools
        if hasattr(self, '_enabled_scanners_set') and self._enabled_scanners_set:
            # For individual scans, run only what was specified
            internal_scanners = [s for s in self.enabled_scanners if s in self.scanner_registry.get_registered_scanners()]
            external_tools = []  # External tools handled separately via enabled_external_tools
        else:
            # For compliance scans, run only the protocol scanner from scanners_to_run
            internal_scanners = [s for s in scanners_to_run if s in self.scanner_registry.get_registered_scanners()]
            external_tools = []  # No external tools for compliance scans

        # Run internal scanners with timing
        if internal_scanners:
            scanners_stage_start = int(time.time())
            self.logger.info(f"Starting scanner stage with {len(internal_scanners)} scanners")
            
            for scanner_type in internal_scanners:
                try:
                    scanner = self.scanner_registry.get_scanner(scanner_type)
                    if scanner:
                        # For protocol scanners, let them handle their own level validation and fallback
                        # Only skip if scanner explicitly cannot handle any level (shouldn't happen)
                        if hasattr(scanner, 'can_handle_level') and hasattr(scanner, 'get_supported_levels'):
                            supported_levels = scanner.get_supported_levels()
                            if not supported_levels:
                                self.logger.warning(f"Scanner {scanner_type} has no supported levels. Skipping scanner.")
                                continue
                            
                        scanner_start = int(time.time())
                        self.logger.info(f"Running {scanner_type} scanner at level {scan_level}")
                        
                        # Check if this is an async protocol scanner
                        if hasattr(scanner, 'scan_protocol'):
                            # This is a protocol scanner with async support
                            import asyncio
                            scan_result = asyncio.run(scanner.scan_protocol(target, hostname=hostname, scan_level=scan_level, ports=ports, **kwargs))
                        else:
                            # Regular scanner - include protocol in kwargs if provided
                            scanner_kwargs = kwargs.copy()
                            if protocol:
                                scanner_kwargs['protocol'] = protocol
                            scan_result = scanner.scan(target, hostname=hostname, ports=ports, scan_level=scan_level, **scanner_kwargs)
                            
                        scanner_end = int(time.time())
                        self.logger.info(f"Completed {scanner_type} scanner in {scanner_end - scanner_start} seconds")
                        
                        # Embed timing directly into the scan result if it has meaningful results
                        if self._has_meaningful_results(scan_result):
                            scan_result["start_time"] = scanner_start
                            scan_result["end_time"] = scanner_end
                            scan_result["duration"] = scanner_end - scanner_start
                        
                        results["scan_results"][scanner_type] = scan_result
                    else:
                        self.logger.warning(f"Scanner {scanner_type} not available")
                except Exception as e:
                    self.logger.error(f"Failed to run {scanner_type} scanner: {e}")
                    # Include timing and error info for failed scans
                    scanner_end = int(time.time())
                    results["scan_results"][scanner_type] = {
                        "error": str(e),
                        "start_time": scanner_start if 'scanner_start' in locals() else None,
                        "end_time": scanner_end,
                        "duration": scanner_end - scanner_start if 'scanner_start' in locals() else None
                    }
            
            scanners_stage_end = int(time.time())
        
        # Run external tools with timing
        external_tools_to_run = []
        if self.use_external_tools:
            if hasattr(self, '_enabled_external_tools_set') and self._enabled_external_tools_set:
                # For individual external tool runs
                external_tools_to_run = self.enabled_external_tools
            elif external_tools:
                # For compliance scans
                external_tools_to_run = external_tools
        
        if external_tools_to_run:
            external_tools_stage_start = int(time.time())
            self.logger.info(f"Starting external tools stage with {len(external_tools_to_run)} tools")
            
            results["external_tools"] = self._run_external_tools(target, hostname, results, external_tools_to_run, resolved_ip)
            
            external_tools_stage_end = int(time.time())
        
        # Record total scan timing only if any meaningful results were found
        scan_end_time = int(time.time())
        results["scan_end_time"] = scan_end_time
        
        self.logger.info(f"Scan completed in {scan_end_time - scan_start_time} seconds")
        
        # Convert to new structured format
        structured_results = self._convert_to_structured_format(results)
        
        return structured_results
    
    def _filter_infrastructure_scanners(self, enabled_scanners: List[str]) -> List[str]:
        """Filter out protocol-specific scanners, keeping only infrastructure scanners.
        
        Args:
            enabled_scanners: List of all enabled scanners
            
        Returns:
            List of infrastructure scanners only
        """
        # Define protocol-specific scanners that should not run during infrastructure scanning
        protocol_scanners = {
            'sui',      # Sui blockchain protocol scanner
            'filecoin', # Filecoin blockchain protocol scanner
            'ethereum', # Future Ethereum protocol scanner
            'web',      # Web server protocol scanner
            'bitcoin',  # Future Bitcoin protocol scanner
            'solana',   # Future Solana protocol scanner
            'polygon',  # Future Polygon protocol scanner
            'avalanche', # Future Avalanche protocol scanner
            'cosmos',   # Future Cosmos protocol scanner
            'polkadot', # Future Polkadot protocol scanner
            'cardano',  # Future Cardano protocol scanner
            'algorand', # Future Algorand protocol scanner
            'near',     # Future NEAR protocol scanner
            'chainlink', # Future Chainlink protocol scanner
            'litecoin', # Future Litecoin protocol scanner
            'dogecoin', # Future Dogecoin protocol scanner
            'monero',   # Future Monero protocol scanner
            'zcash'     # Future Zcash protocol scanner
        }
        
        # Return only infrastructure scanners
        infrastructure_scanners = [
            scanner for scanner in enabled_scanners 
            if scanner not in protocol_scanners
        ]
        
        self.logger.debug(f"Filtered infrastructure scanners: {infrastructure_scanners}")
        return infrastructure_scanners
    
    def _run_external_tools(self, target: str, hostname: Optional[str], scan_results: Dict[str, Any], enabled_tools: List[str], resolved_ip: Optional[str] = None) -> Dict[str, Any]:
        """Run external scanning tools based on the routing function's output.
        
        Args:
            target: Target hostname (FQDN)
            hostname: Optional hostname for target IP (for hostname-based scans)
            scan_results: Results from modular scanners
            enabled_tools: List of external tools to run for this scan
            resolved_ip: Resolved IP address for IP-based operations
            
        Returns:
            External tool results
        """
        external_results = {}
        
        # Nmap scan
        if 'nmap' in enabled_tools:
            nmap_start = int(time.time())
            try:
                self.logger.info(f"Running nmap scan")
                # Use resolved IP for nmap since it works with IP addresses
                nmap_target = resolved_ip if resolved_ip else target
                nmap_results = nmap_scan(nmap_target)
                nmap_end = int(time.time())
                self.logger.info(f"Completed nmap scan in {nmap_end - nmap_start} seconds")
                
                # Embed timing directly into nmap results if meaningful
                if self._has_meaningful_results(nmap_results):
                    nmap_results["start_time"] = nmap_start
                    nmap_results["end_time"] = nmap_end
                    nmap_results["duration"] = nmap_end - nmap_start
                
                external_results["nmap"] = nmap_results
                self.logger.debug(f"Nmap results: {nmap_results}")
            except Exception as e:
                nmap_end = int(time.time())
                self.logger.error(f"Nmap scan failed for {target}: {e}")
                external_results["nmap"] = {
                    "error": str(e),
                    "start_time": nmap_start,
                    "end_time": nmap_end,
                    "duration": nmap_end - nmap_start
                }
        
        # WhatWeb scan
        if 'whatweb' in enabled_tools:
            whatweb_start = int(time.time())
            self.logger.info(f"Running whatweb scan")
            web_ports = self._extract_web_ports(scan_results, external_results.get("nmap"))
            whatweb_results = {}
            for port, scheme in web_ports:
                try:
                    # Use hostname if target is IP and hostname provided, otherwise use target (FQDN)
                    scan_target = hostname if (hostname and self._is_ip_address(target)) else target
                    self.logger.debug(f"Running WhatWeb scan for {scheme}://{scan_target}:{port}")
                    result = whatweb_scan(scan_target, port=port, scheme=scheme)
                    if result and (not isinstance(result, dict) or not result.get("error")):
                        whatweb_results[f"{scheme}://{scan_target}:{port}"] = result
                except Exception as e:
                    self.logger.debug(f"WhatWeb scan failed for {scan_target}:{port}: {e}")
            
            whatweb_end = int(time.time())
            self.logger.info(f"Completed whatweb scan in {whatweb_end - whatweb_start} seconds")
            if whatweb_results:
                # Embed timing directly into whatweb results
                whatweb_results["start_time"] = whatweb_start
                whatweb_results["end_time"] = whatweb_end
                whatweb_results["duration"] = whatweb_end - whatweb_start
                external_results["whatweb"] = whatweb_results
            else:
                # Even if no results, include timing for empty results
                external_results["whatweb"] = {
                    "start_time": whatweb_start,
                    "end_time": whatweb_end,
                    "duration": whatweb_end - whatweb_start
                }
        
        # SSL test
        if 'ssl' in enabled_tools or 'ssl_test' in enabled_tools:
            ssl_start = int(time.time())
            try:
                self.logger.info(f"Running SSL test")
                ssl_results = ssl_test(target, port=443)
                ssl_end = int(time.time())
                self.logger.info(f"Completed SSL test in {ssl_end - ssl_start} seconds")
                
                # Always embed timing directly into SSL results
                ssl_results["start_time"] = ssl_start
                ssl_results["end_time"] = ssl_end
                ssl_results["duration"] = ssl_end - ssl_start
                
                external_results["ssl_test"] = ssl_results
            except Exception as e:
                ssl_end = int(time.time())
                self.logger.debug(f"SSL test failed for {target}: {e}")
                external_results["ssl_test"] = {
                    "error": str(e),
                    "start_time": ssl_start,
                    "end_time": ssl_end,
                    "duration": ssl_end - ssl_start
                }
        
        # Dirbuster scan
        if 'dirbuster' in enabled_tools:
            dirbuster_start = int(time.time())
            # Placeholder for dirbuster logic
            self.logger.info(f"Running dirbuster scan (not yet implemented)")
            dirbuster_end = int(time.time())
            self.logger.info(f"Completed dirbuster scan in {dirbuster_end - dirbuster_start} seconds")
            
            external_results["dirbuster"] = {
                "status": "not_implemented",
                "start_time": dirbuster_start,
                "end_time": dirbuster_end,
                "duration": dirbuster_end - dirbuster_start
            }

        # DNSDumpster scan
        if 'dnsdumpster' in enabled_tools:
            dnsdumpster_start = int(time.time())
            # Placeholder for dnsdumpster logic
            self.logger.info(f"Running DNSDumpster scan (not yet implemented)")
            dnsdumpster_end = int(time.time())
            self.logger.info(f"Completed DNSDumpster scan in {dnsdumpster_end - dnsdumpster_start} seconds")
            
            external_results["dnsdumpster"] = {
                "status": "not_implemented",
                "start_time": dnsdumpster_start,
                "end_time": dnsdumpster_end,
                "duration": dnsdumpster_end - dnsdumpster_start
            }

        # Docker exposure check
        if 'docker' in enabled_tools or 'docker_exposure' in enabled_tools:
            docker_start = int(time.time())
            self.logger.info(f"Running Docker exposure check")
            open_ports = self._extract_open_ports(scan_results)
            if 2375 in open_ports:
                try:
                    self.logger.debug(f"Running Docker exposure check for {target}")
                    docker_exposure = DockerExposureChecker.check(target)
                    docker_end = int(time.time())
                    self.logger.info(f"Completed Docker exposure check in {docker_end - docker_start} seconds")
                    
                    # Embed timing directly into docker results
                    docker_exposure["start_time"] = docker_start
                    docker_exposure["end_time"] = docker_end
                    docker_exposure["duration"] = docker_end - docker_start
                    
                    external_results["docker_exposure"] = docker_exposure
                except Exception as e:
                    docker_end = int(time.time())
                    self.logger.debug(f"Docker exposure check failed for {target}: {e}")
                    external_results["docker_exposure"] = {
                        "error": str(e),
                        "start_time": docker_start,
                        "end_time": docker_end,
                        "duration": docker_end - docker_start
                    }
            else:
                docker_end = int(time.time())
                self.logger.info(f"Completed Docker exposure check in {docker_end - docker_start} seconds (port 2375 not open)")
                external_results["docker_exposure"] = {
                    "exposed": False,
                    "start_time": docker_start,
                    "end_time": docker_end,
                    "duration": docker_end - docker_start
                }
        
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
    
    def _is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address.
        
        Args:
            target: Target string to check
            
        Returns:
            True if target is an IP address, False otherwise
        """
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            return False
    
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
        
        # Final fallback: if no web ports found, try default web ports
        if not web_ports:
            self.logger.debug("No web ports detected, trying default ports 80 and 443")
            web_ports = [(80, "http"), (443, "https")]
        
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
            "scan_end_time": results.get("scan_end_time")
        }
        
        # Add GeoIP data if available
        if geo_results and not geo_results.get("error"):
            geoip_data = {
                "country_name": geo_results.get("country_name"),
                "city_name": geo_results.get("city_name"),
                "latitude": geo_results.get("latitude"),
                "longitude": geo_results.get("longitude"),
                "asn_number": geo_results.get("asn_number"),
                "asn_organization": geo_results.get("asn_organization")
            }
            
            # Include timing information if available
            if "start_time" in geo_results:
                geoip_data["start_time"] = geo_results["start_time"]
                geoip_data["end_time"] = geo_results["end_time"]
                if "duration" in geo_results:
                    geoip_data["duration"] = geo_results["duration"]
                    
            legacy["geoip"] = geoip_data
        
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
    
    def _convert_to_structured_format(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Convert scan results to new structured format with data array and meta object.
        
        Args:
            results: Raw scan results from orchestrator
            
        Returns:
            Structured format with "data" array and "meta" object
        """
        target = results["target"]
        resolved_ip = results.get("resolved_ip", target)
        scan_level = results.get("scan_level", 1)
        scan_results = results.get("scan_results", {})
        external_tools = results.get("external_tools", {})
        
        # Extract data from different scanners
        generic_results = scan_results.get("generic", {})
        web_results = scan_results.get("web", {})
        vuln_results = scan_results.get("vulnerability", {})
        geo_results = scan_results.get("geo", {})
        
        # Build structured data array
        data = []
        
        # Network data (basic connectivity, ports, banners, TLS, headers)
        nmap_data = external_tools.get("nmap", {})
        open_ports = []
        if nmap_data and "ports" in nmap_data:
            open_ports = [port_info["port"] for port_info in nmap_data["ports"] if port_info.get("state") == "open"]
        elif generic_results.get("open_ports"):
            open_ports = generic_results.get("open_ports", [])
        else:
            # Fall back to node scanner results if available
            node_results = scan_results.get("node_scan", {})
            open_ports = node_results.get("open_ports", [])
        
        network_payload = {
            "ip": target,
            "resolved_ip": resolved_ip,
            "open_ports": open_ports,
            "banners": generic_results.get("banners", {}),
            "tls": generic_results.get("tls", {}),
            "http_headers": self._extract_http_headers(web_results)
        }
        data.append({"type": "network", "payload": network_payload})
        
        # Infrastructure data (docker, nmap)
        infra_payload = {
            "docker_exposure": external_tools.get("docker_exposure", {"exposed": False}),
            "nmap": external_tools.get("nmap", {})
        }
        data.append({"type": "infra", "payload": infra_payload})
        
        # Web data (web scanner results, whatweb, ssl testing)
        web_scanner_results = scan_results.get("web", {})
        web_payload = {
            "web_scan": web_scanner_results,
            "whatweb": external_tools.get("whatweb", {}),
            "ssl_test": external_tools.get("ssl_test", {})
        }
        data.append({"type": "web", "payload": web_payload})
        
        # Analysis data (vulnerabilities and compliance)
        compliance_results = scan_results.get("compliance", {})
        
        # Extract compliance data from protocol scanners for compliance scans
        if not compliance_results:
            for protocol_scanner in ['sui', 'filecoin', 'arweave', 'ethereum', 'bitcoin', 'solana', 'polygon', 'avalanche', 'cosmos', 'polkadot', 'cardano', 'algorand', 'near', 'chainlink', 'litecoin', 'dogecoin', 'monero', 'zcash']:
                if protocol_scanner in scan_results:
                    protocol_data = scan_results[protocol_scanner]
                    if protocol_data and 'results' in protocol_data:
                        # Extract compliance flags from protocol scan results
                        compliance_flags = []
                        vulnerabilities = []
                        
                        for result in protocol_data['results']:
                            if isinstance(result, dict):
                                if 'compliance_flags' in result:
                                    compliance_flags.extend(result['compliance_flags'])
                                if 'known_vulnerabilities' in result:
                                    vulnerabilities.extend(result['known_vulnerabilities'])
                        
                        if compliance_flags or vulnerabilities:
                            compliance_results = {
                                'protocol': protocol_scanner,
                                'compliance_flags': list(set(compliance_flags)),
                                'vulnerabilities': vulnerabilities,
                                'total_nodes_scanned': len(protocol_data['results']),
                                'healthy_nodes': sum(1 for r in protocol_data['results'] if isinstance(r, dict) and r.get('healthy', False)),
                                'scan_timestamp': protocol_data.get('timestamp'),
                                'summary': protocol_data.get('summary', {})
                            }
                        break
        
        analysis_payload = {
            "vulns": self._format_vulnerabilities(vuln_results)
        }
        if compliance_results:
            analysis_payload["compliance"] = compliance_results
        data.append({"type": "analysis", "payload": analysis_payload})
        
        # Location data (GeoIP)
        location_payload = {"geoip": {}}
        if geo_results and not geo_results.get("error"):
            location_payload["geoip"] = {
                "country_name": geo_results.get("country_name"),
                "city_name": geo_results.get("city_name"),
                "latitude": geo_results.get("latitude"),
                "longitude": geo_results.get("longitude"),
                "asn_number": geo_results.get("asn_number"),
                "asn_organization": geo_results.get("asn_organization")
            }
        data.append({"type": "location", "payload": location_payload})
        
        # Protocol data (blockchain/DePIN specific scanners)
        protocol_results = {}
        protocol_scanners = ['sui', 'filecoin', 'arweave', 'web', 'ethereum', 'bitcoin', 'solana', 'polygon', 'avalanche', 'cosmos', 'polkadot', 'cardano', 'algorand', 'near', 'chainlink', 'litecoin', 'dogecoin', 'monero', 'zcash']
        
        for protocol_scanner in protocol_scanners:
            if protocol_scanner in scan_results:
                protocol_data = scan_results[protocol_scanner]
                if protocol_data and self._has_meaningful_results(protocol_data):
                    protocol_results[protocol_scanner] = protocol_data
        
        # Add node scanner results to protocol section
        node_results = scan_results.get("node_scan", {})
        if node_results and self._has_meaningful_results(node_results):
            protocol_results["node_scan"] = node_results
        
        if protocol_results:
            data.append({"type": "protocol", "payload": protocol_results})
        
        # Build meta object
        import uuid
        from datetime import datetime
        import time
        
        current_timestamp_unix = int(time.time())
        
        meta = {
            "operation": "target_scan",
            "stage": "scan",
            "scan_level": scan_level,
            "scan_duration": None,
            "scanners_used": list(scan_results.keys()),
            "tools_used": list(external_tools.keys()),
            "total_scan_duration": results.get("scan_end_time", current_timestamp_unix) - results.get("scan_start_time", current_timestamp_unix),
            "target": target,
            "protocol": results.get("protocol"),
            "scan_start": results.get("scan_start_time", current_timestamp_unix),
            "scan_end": results.get("scan_end_time", current_timestamp_unix),
            "node_id": str(uuid.uuid4())
        }
        
        return {
            "data": data,
            "meta": meta
        }

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
            
        # For protocol scanner results (Sui, Filecoin, etc.)
        if "protocol" in results and "results" in results:
            protocol_results = results.get("results", [])
            # Check if there are any actual scan results
            if isinstance(protocol_results, list) and len(protocol_results) > 0:
                return True
            # Also check summary for successful scans
            summary = results.get("summary", {})
            if isinstance(summary, dict) and summary.get("successful_scans", 0) > 0:
                return True
            # If protocol result has empty results and empty summary, it's not meaningful
            return False
            
        # For protocol results with summary data
        if "summary" in results:
            summary = results.get("summary", {})
            if isinstance(summary, dict):
                # Check for meaningful summary metrics (must have non-zero values)
                meaningful_summary_keys = ["successful_scans", "healthy_nodes", "total_ports_scanned"]
                if any(summary.get(key, 0) > 0 for key in meaningful_summary_keys):
                    return True
            
        # Default: if there are any non-empty values (excluding common empty indicators and summary-only results)
        meaningful_keys = [k for k, v in results.items() 
                          if v and v != {} and v != "" and k not in ["error", "timestamp", "summary", "protocol", "target", "hostname"]]
        
        # If we only have a summary, make sure it has meaningful data
        if not meaningful_keys and "summary" in results:
            summary = results.get("summary", {})
            if isinstance(summary, dict):
                # Only consider summary meaningful if it has non-zero values
                meaningful_summary_keys = ["successful_scans", "healthy_nodes", "total_ports_scanned"]
                return any(summary.get(key, 0) > 0 for key in meaningful_summary_keys)
            
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
