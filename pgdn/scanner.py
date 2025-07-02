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
             debug: bool = False) -> DictResult:
        """
        Scan a target.
        
        Args:
            target: IP address or hostname to scan
            hostname: Optional hostname for target IP (for hostname-based scans)
            scan_level: Scan intensity level (1-3)
            protocol: Optional protocol-specific scanner (sui, filecoin)
            run: Type of scan to run (web, whatweb, geo, ssl_test, compliance, node_scan)
            enabled_scanners: Override which scanners to run (legacy, use 'run' instead)
            enabled_external_tools: Override which external tools to run (legacy, use 'run' instead)
            debug: Enable debug logging
            
        Returns:
            DictResult: Success with structured scan data or error message
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
                        "scan_level": scan_level,
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
            if enabled_scanners is not None or enabled_external_tools is not None:
                self._update_orchestrator_config(enabled_scanners, enabled_external_tools)

            # Perform the scan - orchestrator now returns structured format directly
            # Pass original_target (FQDN) for hostname-based scans, resolved_ip for display
            scan_results = self.orchestrator.scan(
                target=original_target,  # Keep FQDN for hostname-based tools like whatweb
                hostname=hostname,
                scan_level=scan_level,
                protocol=protocol,
                resolved_ip=resolved_ip,  # Pass resolved IP for tools that need it
                scan_timestamp=datetime.now().isoformat()
            )

            # Return the orchestrator's structured results directly
            return DictResult.success(scan_results)
            
        except Exception as e:
            timestamp = datetime.now().isoformat()
            timestamp_unix = int(time.time())
            
            error_result = {
                "data": [],
                "meta": {
                    "operation": "target_scan",
                    "stage": "scan",
                    "scan_level": scan_level,
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
            return ['node'], []
        else:
            raise ValueError(f"Unknown run type: {run}. Choose from: web, whatweb, geo, ssl_test, compliance, node_scan")
