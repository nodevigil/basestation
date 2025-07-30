"""
Consolidated scanning orchestrator that coordinates multiple scanner types.
This replaces the old scanner.py with a modular, configurable approach.
"""

from typing import Dict, Any, List, Optional, Tuple
import logging
import time
import socket
from .base_scanner import ScannerRegistry
from ..tools.nmap import nmap_scan
from ..tools.whatweb import whatweb_scan
from ..tools.ssltester import ssl_test
from ..tools.docker import DockerExposureChecker
from ..core.logging import get_logger
from ..core.schema import ScanResultSchema, ScanType, ScanLevel, ScanStatus, ErrorType

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
            Standardized scan results following strict schema
        """
        # Track overall scan timing
        scan_start_time = time.time()
        
        self.logger.info(f"Starting comprehensive scan of {target} (protocol: {protocol})")
        
        # Determine scan level string
        if scan_level == 1:
            scan_level_str = ScanLevel.BASIC.value
        elif scan_level == 2:
            scan_level_str = ScanLevel.DEEP.value
        else:
            scan_level_str = ScanLevel.DISCOVERY.value
        
        # Use enabled_scanners if explicitly set, otherwise determine based on protocol
        if hasattr(self, '_enabled_scanners_set') and self._enabled_scanners_set:
            scanners_to_run = self.enabled_scanners
            self.logger.info(f"Running specific scanners: {scanners_to_run}")
        else:
            # For protocol_scan, use the protocol-specific scanner
            if protocol:
                scanners_to_run = [protocol]
            else:
                scanners_to_run = self.enabled_scanners
            self.logger.info(f"Scanners to run for protocol {protocol}: {scanners_to_run}")

        # Initialize array for structured scan results
        scan_data = []
        tools_used = []
        
        # Determine which scanners and tools to run
        if hasattr(self, '_enabled_scanners_set') and self._enabled_scanners_set:
            # For individual scans, run only what was specified
            internal_scanners = [s for s in self.enabled_scanners if s in self.scanner_registry.get_registered_scanners()]
            external_tools = []  # External tools handled separately via enabled_external_tools
        else:
            # For protocol scans, run the protocol-specific scanner
            internal_scanners = [s for s in scanners_to_run if s in self.scanner_registry.get_registered_scanners()]
            external_tools = []  # No external tools for protocol scans

        # Run internal scanners with strict schema enforcement
        if internal_scanners:
            scanners_stage_start = time.time()
            self.logger.info(f"Starting scanner stage with {len(internal_scanners)} scanners")
            
            for scanner_type in internal_scanners:
                try:
                    scanner = self.scanner_registry.get_scanner(scanner_type)
                    if scanner:
                        scanner_start = time.time()
                        self.logger.info(f"Running {scanner_type} scanner")
                        
                        # Check if this is an async protocol scanner
                        if hasattr(scanner, 'scan_protocol'):
                            # This is a protocol scanner with async support
                            import asyncio
                            raw_result = asyncio.run(scanner.scan_protocol(target, hostname=hostname, ports=ports, **kwargs))
                        else:
                            # Regular scanner - include protocol in kwargs if provided
                            scanner_kwargs = kwargs.copy()
                            if protocol:
                                scanner_kwargs['protocol'] = protocol
                            raw_result = scanner.scan(target, hostname=hostname, ports=ports, **scanner_kwargs)
                            
                        scanner_end = time.time()
                        scan_duration = scanner_end - scanner_start
                        self.logger.info(f"Completed {scanner_type} scanner in {scan_duration:.3f} seconds")
                        
                        # Convert to structured format and add to scan data
                        if self._has_meaningful_results(raw_result):
                            # Extract clean result data based on scanner type
                            clean_result = self._extract_clean_result(scanner_type, raw_result)
                            
                            # Create standardized scan result
                            scan_result = ScanResultSchema.create_scan_result(
                                scan_type=self._map_scanner_to_scan_type(scanner_type),
                                target=target,
                                result=clean_result,
                                scan_duration=scan_duration,
                                status=ScanStatus.SUCCESS.value
                            )
                            
                            scan_data.append(scan_result)
                            tools_used.append(scanner_type)
                        else:
                            # Create failed scan result
                            scan_result = ScanResultSchema.create_scan_result(
                                scan_type=self._map_scanner_to_scan_type(scanner_type),
                                target=target,
                                result={},
                                scan_duration=scan_duration,
                                status=ScanStatus.FAILED.value
                            )
                            scan_data.append(scan_result)
                    else:
                        self.logger.warning(f"Scanner {scanner_type} not available")
                except Exception as e:
                    scanner_end = time.time()
                    scan_duration = scanner_end - (scanner_start if 'scanner_start' in locals() else scanner_end)
                    self.logger.error(f"Failed to run {scanner_type} scanner: {e}")
                    
                    # Create error scan result
                    scan_result = ScanResultSchema.create_scan_result(
                        scan_type=self._map_scanner_to_scan_type(scanner_type),
                        target=target,
                        result={"error": str(e)},
                        scan_duration=scan_duration,
                        status=ScanStatus.FAILED.value
                    )
                    scan_data.append(scan_result)
            
            scanners_stage_end = time.time()
        
        # Run external tools with schema enforcement
        external_tools_to_run = []
        if self.use_external_tools:
            if hasattr(self, '_enabled_external_tools_set') and self._enabled_external_tools_set:
                # For individual external tool runs
                external_tools_to_run = self.enabled_external_tools
            elif external_tools:
                # For compliance scans
                external_tools_to_run = external_tools
        
        if external_tools_to_run:
            external_tools_stage_start = time.time()
            self.logger.info(f"Starting external tools stage with {len(external_tools_to_run)} tools")
            
            external_results = self._run_external_tools_with_schema(target, hostname, external_tools_to_run, resolved_ip)
            scan_data.extend(external_results)
            tools_used.extend([tool for tool in external_tools_to_run if tool in self.enabled_external_tools])
            
            external_tools_stage_end = time.time()
        
        # Record total scan timing
        scan_end_time = time.time()
        
        self.logger.info(f"Scan completed in {scan_end_time - scan_start_time:.3f} seconds")
        
        # Create standardized response structure
        return ScanResultSchema.create_response_structure(
            data=scan_data,
            scan_level=scan_level_str,
            target=target,
            tools_used=tools_used,
            scan_start_time=scan_start_time,
            scan_end_time=scan_end_time
        )
    
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
            # Check port scanner results
            port_scan_results = scan_results.get("port_scan", {})
            if port_scan_results.get("open_ports"):
                open_ports = port_scan_results.get("open_ports", [])
            else:
                # Fall back to node scanner results if available
                node_results = scan_results.get("node_scan", {})
                open_ports = node_results.get("open_ports", [])
        
        # Extract banners from generic or port scanner results
        banners = generic_results.get("banners", {})
        if not banners:
            port_scan_results = scan_results.get("port_scan", {})
            banners = port_scan_results.get("banners", {})
        
        # Extract TLS from generic or port scanner results
        tls = generic_results.get("tls", {})
        if not tls:
            port_scan_results = scan_results.get("port_scan", {})
            tls = port_scan_results.get("tls", {})
        
        network_payload = {
            "ip": target,
            "resolved_ip": resolved_ip,
            "open_ports": open_ports,
            "banners": banners,
            "tls": tls,
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
        
        # Add port scanner results directly if available
        port_scan_results = scan_results.get("port_scan", {})
        if port_scan_results and self._has_meaningful_results(port_scan_results):
            data.append({"type": "port_scan", "payload": port_scan_results})
        
        # Build meta object
        import uuid
        from datetime import datetime
        import time
        
        current_timestamp_unix = int(time.time())
        
        meta = {
            "operation": "target_scan",
            "stage": "scan",
            "scan_level": None,
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
            
        # For port scanner results specifically
        if "scanner_type" in results and results.get("scanner_type") == "port_scan":
            # Port scanner is meaningful if it has detailed results
            detailed_results = results.get("detailed_results", [])
            return len(detailed_results) > 0
            
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

    def _map_scanner_to_scan_type(self, scanner_type: str) -> str:
        """Map scanner type to standardized scan type.
        
        Args:
            scanner_type: Internal scanner type name
            
        Returns:
            Standardized scan type
        """
        type_mapping = {
            'web': ScanType.WEB.value,
            'port_scan': ScanType.PORT_SCAN.value,
            'vulnerability': ScanType.DISCOVERY.value,
            'geo': ScanType.GEO.value,
            'compliance': ScanType.COMPLIANCE.value,
            'node_scan': ScanType.NODE_SCAN.value,
            'sui': ScanType.DISCOVERY.value,
            'filecoin': ScanType.DISCOVERY.value,
            'ethereum': ScanType.DISCOVERY.value,
            'arweave': ScanType.DISCOVERY.value,
        }
        return type_mapping.get(scanner_type, ScanType.DISCOVERY.value)

    def _extract_clean_result(self, scanner_type: str, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        """Extract clean, essential data from raw scanner results.
        
        Args:
            scanner_type: Type of scanner
            raw_result: Raw result from scanner
            
        Returns:
            Clean result data for schema
        """
        if scanner_type == 'web':
            return self._extract_web_result(raw_result)
        elif scanner_type == 'port_scan':
            return self._extract_port_scan_result(raw_result)
        elif scanner_type == 'geo':
            return self._extract_geo_result(raw_result)
        elif scanner_type in ['sui', 'filecoin', 'ethereum', 'arweave']:
            return self._extract_protocol_result(raw_result)
        elif scanner_type == 'vulnerability':
            return self._extract_vulnerability_result(raw_result)
        elif scanner_type == 'compliance':
            return self._extract_compliance_result(raw_result)
        elif scanner_type == 'node_scan':
            return self._extract_node_scan_result(raw_result)
        else:
            # Generic extraction - remove debugging/metadata fields
            clean = {}
            for key, value in raw_result.items():
                if key not in ['start_time', 'end_time', 'duration', 'timestamp', 'scanner_type', 'scan_level', 'hostname', 'protocol']:
                    clean[key] = value
            return clean

    def _extract_web_result(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        """Extract clean web scan results."""
        from ..core.schema import ScanResultSchema
        
        web_results = raw_result.get('web_results', {})
        if not web_results:
            return {}
        
        # Get first successful web result
        for url, result in web_results.items():
            if isinstance(result, dict) and not result.get('error'):
                return ScanResultSchema.format_web_result(
                    status_code=result.get('status_code'),
                    headers=result.get('headers'),
                    technologies=result.get('technologies', []),
                    security_headers=result.get('security_headers'),
                    endpoints=result.get('fuzzed_endpoints', [])
                )
        
        return {}

    def _extract_port_scan_result(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        """Extract clean port scan results."""
        from ..core.schema import ScanResultSchema
        
        return ScanResultSchema.format_port_scan_result(
            open_ports=raw_result.get('open_ports', []),
            closed_ports=raw_result.get('closed_ports', []),
            filtered_ports=raw_result.get('filtered_ports', []),
            port_details=raw_result.get('detailed_results', [])
        )

    def _extract_geo_result(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        """Extract clean geo scan results."""
        from ..core.schema import ScanResultSchema
        
        return ScanResultSchema.format_geo_result(
            country=raw_result.get('country_name'),
            city=raw_result.get('city_name'),
            latitude=raw_result.get('latitude'),
            longitude=raw_result.get('longitude'),
            asn=raw_result.get('asn_number'),
            organization=raw_result.get('asn_organization')
        )

    def _extract_protocol_result(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        """Extract clean protocol scan results."""
        from ..core.schema import ScanResultSchema
        
        protocols = []
        if raw_result.get('protocol'):
            protocols.append(raw_result['protocol'])
        
        endpoints = []
        results = raw_result.get('results', [])
        if isinstance(results, list):
            for result in results:
                if isinstance(result, dict):
                    # Extract endpoint info if available
                    if result.get('endpoint') or result.get('port'):
                        endpoints.append({
                            'protocol': result.get('protocol', ''),
                            'port': result.get('port'),
                            'status': 'active' if result.get('healthy') else 'inactive',
                            'endpoint': result.get('endpoint', ''),
                            'version': result.get('version', ''),
                            'node_type': result.get('node_type', '')
                        })
        
        # Extract compliance flags and health information
        compliance_flags = []
        healthy_nodes = 0
        total_nodes = len(results) if isinstance(results, list) else 0
        
        if isinstance(results, list):
            for result in results:
                if isinstance(result, dict):
                    # Check for health status
                    if result.get('healthy'):
                        healthy_nodes += 1
                    
                    # Extract compliance flags
                    if result.get('compliance_flags'):
                        compliance_flags.extend(result['compliance_flags'])
        
        # Create base discovery result
        discovery_result = ScanResultSchema.format_discovery_result(
            protocols_detected=protocols,
            node_type=raw_result.get('node_type'),
            network=raw_result.get('network'),
            endpoints=endpoints,
            capabilities=raw_result.get('capabilities', [])
        )
        
        # Add compliance and health information for compliance scans
        if compliance_flags or total_nodes > 0:
            discovery_result.update({
                'compliance_flags': list(set(compliance_flags)),  # Remove duplicates
                'health_summary': {
                    'total_nodes': total_nodes,
                    'healthy_nodes': healthy_nodes,
                    'unhealthy_nodes': total_nodes - healthy_nodes,
                    'health_percentage': round((healthy_nodes / total_nodes * 100), 2) if total_nodes > 0 else 0
                },
                'scan_summary': raw_result.get('summary', {})
            })
        
        return discovery_result

    def _extract_vulnerability_result(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        """Extract clean vulnerability scan results."""
        vulnerabilities = []
        vuln_data = raw_result.get('vulnerabilities', {})
        
        for port, port_vulns in vuln_data.items():
            if isinstance(port_vulns, list):
                for vuln in port_vulns:
                    if isinstance(vuln, dict):
                        vulnerabilities.append({
                            'port': int(port) if isinstance(port, str) else port,
                            'cve': vuln.get('cve'),
                            'severity': vuln.get('severity'),
                            'description': vuln.get('description')
                        })
        
        return {'vulnerabilities': vulnerabilities}

    def _extract_compliance_result(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        """Extract clean compliance scan results."""
        return {
            'compliance_flags': raw_result.get('compliance_flags', []),
            'checks_passed': raw_result.get('checks_passed', 0),
            'checks_failed': raw_result.get('checks_failed', 0),
            'total_checks': raw_result.get('total_checks', 0)
        }

    def _extract_node_scan_result(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        """Extract clean node scan results."""
        # The node scanner returns: target, protocol, results, total_probes, successful_probes, detected_services, open_ports
        results = raw_result.get('results', [])
        detected_services = raw_result.get('detected_services', [])
        open_ports = raw_result.get('open_ports', [])
        
        # Extract meaningful information from the results
        active_endpoints = []
        service_info = {}
        
        for result in results:
            if isinstance(result, dict) and not result.get('error'):
                if result.get('banner') or result.get('service'):
                    endpoint = {
                        'port': result.get('port'),
                        'protocol': result.get('protocol'),
                        'service': result.get('service'),
                        'version': result.get('version'),
                        'ssl': result.get('ssl', False),
                        'latency_ms': result.get('latency_ms')
                    }
                    active_endpoints.append(endpoint)
                    
                    # Aggregate service info
                    if result.get('service'):
                        service_info[result.get('service')] = result.get('version')
        
        # Determine node status based on findings
        if detected_services:
            node_status = 'active'
        elif open_ports:
            node_status = 'responding'
        else:
            node_status = 'inactive'
        
        return {
            'node_status': node_status,
            'protocol': raw_result.get('protocol'),
            'total_probes': raw_result.get('total_probes', 0),
            'successful_probes': raw_result.get('successful_probes', 0),
            'open_ports': open_ports,
            'active_endpoints': active_endpoints,
            'detected_services': [service.get('service') for service in detected_services if service.get('service')],
            'service_versions': service_info,
            'scan_summary': {
                'probes_sent': raw_result.get('total_probes', 0),
                'responses_received': raw_result.get('successful_probes', 0),
                'services_detected': len(detected_services),
                'ports_open': len(open_ports)
            }
        }

    def _run_external_tools_with_schema(self, target: str, hostname: Optional[str], enabled_tools: List[str], resolved_ip: Optional[str] = None) -> List[Dict[str, Any]]:
        """Run external tools and return results in standardized schema format.
        
        Args:
            target: Target hostname (FQDN)
            hostname: Optional hostname for target IP
            enabled_tools: List of external tools to run
            resolved_ip: Resolved IP address for IP-based operations
            
        Returns:
            List of standardized scan results
        """
        external_results = []
        
        # Nmap scan
        if 'nmap' in enabled_tools:
            nmap_start = time.time()
            try:
                self.logger.info(f"Running nmap scan")
                nmap_target = resolved_ip if resolved_ip else target
                nmap_raw = nmap_scan(nmap_target)
                nmap_end = time.time()
                scan_duration = nmap_end - nmap_start
                
                if self._has_meaningful_results(nmap_raw):
                    # Extract port information from nmap
                    open_ports = []
                    port_details = []
                    
                    if nmap_raw and "ports" in nmap_raw:
                        for port_info in nmap_raw["ports"]:
                            if port_info.get("state") == "open":
                                open_ports.append(port_info["port"])
                                port_details.append({
                                    "port": port_info["port"],
                                    "protocol": "tcp",
                                    "service": port_info.get("service", ""),
                                    "version": port_info.get("version", "")
                                })
                    
                    from ..core.schema import ScanResultSchema
                    clean_result = ScanResultSchema.format_port_scan_result(
                        open_ports=open_ports,
                        port_details=port_details
                    )
                    
                    scan_result = ScanResultSchema.create_scan_result(
                        scan_type=ScanType.PORT_SCAN.value,
                        target=target,
                        result=clean_result,
                        scan_duration=scan_duration,
                        status=ScanStatus.SUCCESS.value
                    )
                    external_results.append(scan_result)
                    
            except Exception as e:
                nmap_end = time.time()
                scan_duration = nmap_end - nmap_start
                self.logger.error(f"Nmap scan failed for {target}: {e}")
                
                scan_result = ScanResultSchema.create_scan_result(
                    scan_type=ScanType.PORT_SCAN.value,
                    target=target,
                    result={"error": str(e)},
                    scan_duration=scan_duration,
                    status=ScanStatus.FAILED.value
                )
                external_results.append(scan_result)
        
        # WhatWeb scan
        if 'whatweb' in enabled_tools:
            whatweb_start = time.time()
            self.logger.info(f"Running whatweb scan")
            
            # Try common web ports
            web_ports = [(80, "http"), (443, "https")]
            whatweb_found = False
            
            for port, scheme in web_ports:
                try:
                    scan_target = hostname if (hostname and self._is_ip_address(target)) else target
                    result = whatweb_scan(scan_target, port=port, scheme=scheme)
                    
                    if result and (not isinstance(result, dict) or not result.get("error")):
                        whatweb_end = time.time()
                        scan_duration = whatweb_end - whatweb_start
                        
                        from ..core.schema import ScanResultSchema
                        clean_result = ScanResultSchema.format_web_result(
                            technologies=result.get('technologies', []) if isinstance(result, dict) else []
                        )
                        
                        scan_result = ScanResultSchema.create_scan_result(
                            scan_type=ScanType.WHATWEB.value,
                            target=target,
                            result=clean_result,
                            scan_duration=scan_duration,
                            status=ScanStatus.SUCCESS.value
                        )
                        external_results.append(scan_result)
                        whatweb_found = True
                        break
                        
                except Exception as e:
                    self.logger.debug(f"WhatWeb scan failed for {scan_target}:{port}: {e}")
                    continue
            
            if not whatweb_found:
                whatweb_end = time.time()
                scan_duration = whatweb_end - whatweb_start
                scan_result = ScanResultSchema.create_scan_result(
                    scan_type=ScanType.WHATWEB.value,
                    target=target,
                    result={},
                    scan_duration=scan_duration,
                    status=ScanStatus.FAILED.value
                )
                external_results.append(scan_result)
        
        # SSL test
        if 'ssl' in enabled_tools or 'ssl_test' in enabled_tools:
            ssl_start = time.time()
            try:
                self.logger.info(f"Running SSL test")
                ssl_raw = ssl_test(target, port=443)
                ssl_end = time.time()
                scan_duration = ssl_end - ssl_start
                
                from ..core.schema import ScanResultSchema
                clean_result = ScanResultSchema.format_ssl_result(
                    certificate=ssl_raw.get('certificate'),
                    ssl_version=ssl_raw.get('ssl_version'),
                    cipher_suites=ssl_raw.get('cipher_suites', []),
                    vulnerabilities=ssl_raw.get('vulnerabilities', [])
                )
                
                scan_result = ScanResultSchema.create_scan_result(
                    scan_type=ScanType.SSL.value,
                    target=target,
                    result=clean_result,
                    scan_duration=scan_duration,
                    status=ScanStatus.SUCCESS.value
                )
                external_results.append(scan_result)
                
            except Exception as e:
                ssl_end = time.time()
                scan_duration = ssl_end - ssl_start
                self.logger.debug(f"SSL test failed for {target}: {e}")
                
                scan_result = ScanResultSchema.create_scan_result(
                    scan_type=ScanType.SSL.value,
                    target=target,
                    result={"error": str(e)},
                    scan_duration=scan_duration,
                    status=ScanStatus.FAILED.value
                )
                external_results.append(scan_result)
        
        return external_results

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
