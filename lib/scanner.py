"""
Simplified Scanner - Single Entry Point for All Scanning Operations

This replaces the multiple scanner classes with one clean interface.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime
import socket
import uuid

from .core.config import Config
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
             scan_level: int = 1,
             protocol: Optional[str] = None,
             enabled_scanners: Optional[List[str]] = None,
             enabled_external_tools: Optional[List[str]] = None,
             debug: bool = False) -> Dict[str, Any]:
        """
        Scan a target.
        
        Args:
            target: IP address or hostname to scan
            scan_level: Scan intensity level (1-3)
            protocol: Optional protocol-specific scanner (sui, filecoin)
            enabled_scanners: Override which scanners to run
            enabled_external_tools: Override which external tools to run
            debug: Enable debug logging
            
        Returns:
            Complete scan results
        """
        try:
            # Resolve hostname to IP if needed
            try:
                ip_address = socket.gethostbyname(target)
            except socket.gaierror as e:
                return {
                    "success": False,
                    "target": target,
                    "error": f"DNS resolution failed: {str(e)}",
                    "timestamp": datetime.now().isoformat(),
                    "operation": "target_scan"
                }
            
            # Override scanner/tool configuration if specified
            if enabled_scanners is not None or enabled_external_tools is not None:
                self._update_orchestrator_config(enabled_scanners, enabled_external_tools)
            
            # Perform the scan
            scan_results = self.orchestrator.scan(
                target=ip_address,
                scan_level=scan_level,
                protocol=protocol,
                scan_timestamp=datetime.now().isoformat()
            )
            
            # Return formatted results
            return {
                "success": True,
                "stage": "scan",
                "scan_level": scan_level,
                "timestamp": datetime.now().isoformat(),
                "scan_result": scan_results,
                "target": target,
                "resolved_ip": ip_address,
                "node_id": str(uuid.uuid4()),
                "protocol": protocol,
                "operation": "target_scan"
            }
            
        except Exception as e:
            return {
                "success": False,
                "stage": "scan",
                "scan_level": scan_level,
                "timestamp": datetime.now().isoformat(),
                "scan_result": None,
                "target": target,
                "error": f"Orchestration error: {str(e)}",
                "operation": "target_scan"
            }
    
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
        
        if enabled_external_tools is not None:
            if not enabled_external_tools:  # Empty list means disable
                self.orchestrator.use_external_tools = False
                self.orchestrator.enabled_external_tools = []
            else:
                self.orchestrator.use_external_tools = True
                self.orchestrator.enabled_external_tools = enabled_external_tools
