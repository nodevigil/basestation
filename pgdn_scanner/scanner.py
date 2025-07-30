"""
Simplified Scanner - Single Entry Point for All Scanning Operations

This replaces the multiple scanner classes with one clean interface.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime
import socket
import uuid
import time

from .core.config import Config
from .core.result import Result, DictResult
from .scanners.scan_orchestrator import ScanOrchestrator


class Scanner:
    """
    Single entry point for all scanning operations.
    
    This class provides a clean, simple API for scanning targets.
    All complexity is handled internally by the ScanOrchestrator.
    """
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize the scanner.
        
        Args:
            config: Configuration instance. If None, uses default config.
        """
        self.config = config
        
        # Convert config to dict format for orchestrator
        if config:
            scan_config = self._prepare_scan_config(config)
            self.orchestrator = ScanOrchestrator(scan_config)
        else:
            self.orchestrator = ScanOrchestrator()
    
    def scan(self, 
             target: str, 
             hostname: Optional[str] = None,
             scan_level: int = 1,
             protocol: Optional[str] = None,
             run: Optional[str] = None,
             enabled_scanners: Optional[List[str]] = None,
             enabled_external_tools: Optional[List[str]] = None,
             debug: bool = False,
             **kwargs) -> DictResult:
        """
        Scan a target.

        Args:
            target: IP address or hostname to scan
            hostname: Optional hostname for target IP (for hostname-based scans)
            scan_level: Only used for compliance scans (intensity level 1-3). Ignored for other scan types.
            protocol: Optional protocol-specific scanner (sui, filecoin)
            run: Type of scan to run (web, whatweb, geo, ssl_test, compliance, node_scan)
            enabled_scanners: Override which scanners to run (legacy, use 'run' instead)
            enabled_external_tools: Override which external tools to run (legacy, use 'run' instead)
            debug: Enable debug logging

        Returns:
            DictResult: Success with structured scan data or error message

        Note:
            - scan_level is only meaningful for compliance scans. For all other scan types, it is ignored.
        """
        try:
            # Keep original target for hostname-based scans, resolve for IP-based operations
            original_target = target
            try:
                # Check if target is already an IP address
                socket.inet_aton(target)
                resolved_ip = target  # Already an IP address
            except socket.error:
                # Not an IP address, resolve hostname for IP-based operations
                resolved_ip = socket.gethostbyname(target)
            except socket.gaierror as e:
                timestamp = datetime.now().isoformat()
                timestamp_unix = int(time.time())
                
                error_result = {
                    "data": [],
                    "meta": {
                        "operation": "target_scan",
                        "stage": "scan",
                        "scan_level": None,
                        "scan_duration": None,
                        "scanners_used": [],
                        "tools_used": [],
                        "total_scan_duration": 0,
                        "target": target,
                        "protocol": protocol,
                        "timestamp": timestamp,
                        "timestamp_unix": timestamp_unix,
                        "scan_start_timestamp_unix": timestamp_unix,
                        "scan_end_timestamp_unix": timestamp_unix,
                        "error": f"DNS resolution failed: {str(e)}"
                    }
                }
                return DictResult.success(error_result)

            # Map 'run' parameter to scanners and tools
            if run:
                enabled_scanners, enabled_external_tools = self._map_run_to_scanners(run)

            # Override scanner/tool configuration if specified
            # For compliance and protocol_scan, don't override - let orchestrator use routing logic
            if run not in ["compliance", "protocol_scan"] and (enabled_scanners is not None or enabled_external_tools is not None):
                self._update_orchestrator_config(enabled_scanners, enabled_external_tools)


            # Convert port string to ports list for port_scan
            orchestrator_kwargs = kwargs.copy()
            if run == 'port_scan':
                # Handle port conversion
                if 'port' in kwargs:
                    port_str = kwargs['port']
                    try:
                        ports_list = [int(p.strip()) for p in port_str.split(',') if p.strip()]
                        orchestrator_kwargs['ports'] = ports_list
                        orchestrator_kwargs.pop('port', None)  # Remove the string version
                    except ValueError as e:
                        return DictResult.from_error(f"Invalid port format: {e}")
                
                # Ensure rich data by providing default nmap_args if none specified
                if 'nmap_args' not in orchestrator_kwargs:
                    orchestrator_kwargs['nmap_args'] = '-sV'
            
            scan_results = self.orchestrator.scan(
                target=original_target,
                hostname=hostname,
                protocol=protocol,
                resolved_ip=resolved_ip,
                scan_timestamp=datetime.now().isoformat(),
                scan_level=scan_level,
                **orchestrator_kwargs
            )

            # Remove 'infra' section and include ONLY the relevant scan type or tool result
            if isinstance(scan_results, dict) and "data" in scan_results:
                scan_type = None
                if run == "web":
                    scan_type = "web"
                elif run == "geo":
                    scan_type = "location"
                elif run == "compliance":
                    scan_type = "analysis"
                elif run == "whatweb":
                    scan_type = "web"
                elif run == "ssl_test":
                    scan_type = "web"
                elif run == "port_scan":
                    scan_type = "port_scan"
                elif run == "node_scan":
                    scan_type = "node_scan"
                elif run == "protocol_scan":
                    scan_type = "protocol"

                data_entries = scan_results["data"]
                filtered = []
                
                for entry in data_entries:
                    # Skip infra entries
                    if entry.get("type") == "infra":
                        continue
                    
                    # Special handling for node_scan - extract node data from protocol entries
                    if run == "node_scan" and entry.get("type") == "protocol":
                        payload = entry.get("payload", {})
                        if "node_scan" in payload:
                            filtered.append({
                                "type": "node_scan",
                                "payload": payload["node_scan"]
                            })
                        continue
                    
                    # Special handling for protocol_scan - filter to specific protocol
                    if run == "protocol_scan" and entry.get("type") == "protocol":
                        payload = entry.get("payload", {})
                        if protocol and protocol in payload:
                            filtered.append({
                                "type": "protocol",
                                "payload": {protocol: payload[protocol]}
                            })
                        continue
                    
                    # If entry type matches scan_type
                    if entry.get("type") == scan_type:
                        # For tool-specific runs, extract only that tool's data
                        if run in ["whatweb", "ssl_test"] and run in entry.get("payload", {}):
                            filtered.append({
                                "type": entry["type"],
                                "payload": {run: entry["payload"][run]}
                            })
                        else:
                            # For general scans, include the whole entry
                            filtered.append(entry)

                # If only one entry and nothing filtered, keep it regardless of type
                if not filtered and len(data_entries) == 1:
                    scan_results["data"] = data_entries
                else:
                    scan_results["data"] = filtered

            return DictResult.success(scan_results)
            
        except Exception as e:
            timestamp = datetime.now().isoformat()
            timestamp_unix = int(time.time())
            
            error_result = {
                "data": [],
                "meta": {
                    "operation": "target_scan",
                    "stage": "scan",
                    "scan_level": scan_level if run == "compliance" else None,
                    "scan_duration": None,
                    "scanners_used": [],
                    "tools_used": [],
                    "total_scan_duration": 0,
                    "target": target,
                    "protocol": protocol,
                    "timestamp": timestamp,
                    "timestamp_unix": timestamp_unix,
                    "scan_start_timestamp_unix": timestamp_unix,
                    "scan_end_timestamp_unix": timestamp_unix,
                    "error": f"Orchestration error: {str(e)}"
                }
            }
            return DictResult.success(error_result)
    
    def _prepare_scan_config(self, config: Config) -> Dict[str, Any]:
        """
        Convert Config object to dictionary format for ScanOrchestrator.
        
        Args:
            config: Config instance
            
        Returns:
            Dictionary configuration
        """
        scanning_config = config.scanning
        
        # Ensure orchestrator config is a dict
        orchestrator_config = scanning_config.orchestrator
        if not isinstance(orchestrator_config, dict):
            orchestrator_config = vars(orchestrator_config)
        
        # Ensure scanners config is a dict
        scanners_config = scanning_config.scanners
        if not isinstance(scanners_config, dict):
            scanners_config = vars(scanners_config)
        
        return {
            'orchestrator': dict(orchestrator_config),
            'scanners': dict(scanners_config)
        }
    
    def _update_orchestrator_config(self, 
                                   enabled_scanners: Optional[List[str]], 
                                   enabled_external_tools: Optional[List[str]]):
        """
        Update orchestrator configuration with runtime overrides.
        
        Args:
            enabled_scanners: Scanners to enable
            enabled_external_tools: External tools to enable
        """
        if enabled_scanners is not None:
            self.orchestrator.enabled_scanners = enabled_scanners
            self.orchestrator._enabled_scanners_set = True
        
        if enabled_external_tools is not None:
            if not enabled_external_tools:  # Empty list means disable
                self.orchestrator.use_external_tools = False
                self.orchestrator.enabled_external_tools = []
            else:
                self.orchestrator.use_external_tools = True
                self.orchestrator.enabled_external_tools = enabled_external_tools
            self.orchestrator._enabled_external_tools_set = True

    def _map_run_to_scanners(self, run: str) -> tuple[List[str], List[str]]:
        """
        Map 'run' parameter to enabled_scanners and enabled_external_tools.
        
        Args:
            run: Type of scan to run
            
        Returns:
            Tuple of (enabled_scanners, enabled_external_tools)
        """
        if run == 'web':
            return ['web'], []
        elif run == 'whatweb':
            return [], ['whatweb']
        elif run == 'geo':
            return ['geo'], []
        elif run == 'ssl_test':
            return [], ['ssl_test']
        elif run == 'compliance':
            return ['compliance'], []
        elif run == 'node_scan':
            return ['node_scan'], []
        elif run == 'port_scan':
            return ['port_scan'], []
        elif run == 'protocol_scan':
            # Protocol scan will use protocol-specific scanners based on the protocol parameter
            return [], []
        else:
            raise ValueError(f"Unknown run type: {run}. Choose from: web, whatweb, geo, ssl_test, port_scan, compliance, node_scan, protocol_scan")
