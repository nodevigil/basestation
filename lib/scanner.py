"""
Scanner Module

Provides scanning functionality for individual targets and bulk scanning operations.
This module now uses the new modular scanning system with ScanOrchestrator.
"""

import socket
import concurrent.futures
from typing import Optional, List, Dict, Any
from datetime import datetime

from .core.config import Config


class Scanner:
    """
    Scanner for DePIN infrastructure nodes and targets.
    
    This class provides a clean Python API for scanning individual targets
    or running bulk scanning operations, independent of CLI concerns.
    """
    
    def __init__(self, config: Config, debug: bool = False, 
                 enabled_scanners: Optional[List[str]] = None, enabled_external_tools: Optional[List[str]] = None):
        """
        Initialize the scanner.
        
        Args:
            config: Configuration instance
            debug: Enable debug logging
            enabled_scanners: List of specific scanners to run (overrides config)
            enabled_external_tools: List of specific external tools to run (overrides config)
        """
        self.config = config
        self.debug = debug
        self.enabled_scanners = enabled_scanners
        self.enabled_external_tools = enabled_external_tools
    
    def scan_target(self, target: str, org_id: Optional[str] = None, scan_level: int = 1, force_protocol: Optional[str] = None) -> Dict[str, Any]:
        """
        Scan a specific target (IP or hostname) with orchestration workflow.
        
        Args:
            target: IP address or hostname to scan
            org_id: Organization ID (required for orchestration)
            scan_level: Scan level (1-3, default: 1)
            force_protocol: Optional protocol to force (bypasses discovery)
            
        Returns:
            dict: Scan results or workflow instructions
        """
        # Organization ID is required for orchestration
        if not org_id:
            return {
                "success": False,
                "error": "Organization ID is required for target scanning",
                "suggestion": "Example: pgdn --stage scan --target 139.84.148.36 --org-id myorg"
            }
        
        try:
            # Simplified scanning without database orchestration
            # Generate a simple node_id for tracking
            import uuid
            node_id = str(uuid.uuid4())
            
            # Use force_protocol if provided, otherwise set to None for auto-detection
            protocol = force_protocol
            
            # Proceed with actual scanning
            scan_result = self._perform_scan(target, org_id, protocol, node_id, scan_level)
            
            return scan_result
            
        except Exception as e:
            return {
                "success": False,
                "target": target,
                "error": f"Orchestration error: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
    
    def _perform_scan(self, target: str, org_id: str, protocol: Optional[str], node_id: Optional[str], scan_level: int = 1) -> Dict[str, Any]:
        """
        Perform the actual scan using the new modular scanning system.
        
        Args:
            target: IP address or hostname to scan
            org_id: Organization ID
            protocol: Protocol name (if determined)
            node_id: Node UUID for tracking
            scan_level: Scan level (1-3, default: 1)
            
        Returns:
            dict: Scan results
        """
        try:
            from .scanners.scan_orchestrator import ScanOrchestrator
            
            # Resolve hostname to IP if needed
            try:
                ip_address = socket.gethostbyname(target)
            except socket.gaierror as e:
                return {
                    "success": False,
                    "target": target,
                    "error": f"DNS resolution failed: {str(e)}",
                    "timestamp": datetime.now().isoformat(),
                    "node_id": node_id
                }
            
            # Prepare scanning configuration
            scanning_config = self.config.scanning
            scan_config = {
                'orchestrator': scanning_config.orchestrator,
                'scanners': scanning_config.scanners
            }
            
            # Override enabled scanners if specified
            if self.enabled_scanners is not None:
                scan_config['orchestrator'] = dict(scan_config.get('orchestrator', {}))
                scan_config['orchestrator']['enabled_scanners'] = self.enabled_scanners
            
            # Override external tools if specified
            if self.enabled_external_tools is not None:
                scan_config['orchestrator'] = dict(scan_config.get('orchestrator', {}))
                if not self.enabled_external_tools:  # Empty list means disable external tools
                    scan_config['orchestrator']['use_external_tools'] = False
                    scan_config['orchestrator']['enabled_external_tools'] = []
                else:
                    scan_config['orchestrator']['use_external_tools'] = True
                    scan_config['orchestrator']['enabled_external_tools'] = self.enabled_external_tools
            
            # Create scan orchestrator with configuration
            orchestrator = ScanOrchestrator(scan_config)
            
            # DEBUG: Add logging to see what vulnerability scanner configuration is being used
            if self.debug or scan_level == 1:
                print(f"DEBUG: Scan config orchestrator: {scan_config.get('orchestrator', {})}")
                print(f"DEBUG: Enabled scanners: {self.enabled_scanners}")
                print(f"DEBUG: Scan level: {scan_level}")
                if 'vulnerability' in (self.enabled_scanners or []):
                    print(f"DEBUG: Vulnerability scanner enabled but CVE scanning {'skipped' if scan_level == 1 else 'enabled'} at level {scan_level}")
                    print(f"DEBUG: For CVE scanning, use scan level 2 or 3: --scan-level 2")
            
            # Perform the scan using the new modular system with scan_level
            scan_results = orchestrator.scan(
                target=ip_address,
                scan_level=scan_level,
                protocol=protocol,
                scan_timestamp=datetime.now().isoformat()
            )
            
            # DEBUG: Check if vulnerability results are present and show vulnerability scanner messages
            if (self.debug or scan_level == 1) and scan_results:
                vulns = scan_results.get('vulns', {})
                vuln_scanner_results = scan_results.get('scan_results', {}).get('vulnerability', {})
                
                print(f"DEBUG: Vulnerability scan results: {vulns}")
                if vuln_scanner_message := vuln_scanner_results.get('message'):
                    print(f"DEBUG: Vulnerability scanner message: {vuln_scanner_message}")
                
                if not vulns and scan_level == 1:
                    print("DEBUG: No vulnerability results - CVE scanning is disabled at scan level 1")
                    print("DEBUG: To enable CVE scanning, use --scan-level 2 or --scan-level 3")
            
            if scan_results:
                # Determine scan type based on enabled scanners
                scan_type = self._determine_scan_type()
                
                # Return scan results as JSON (no database save)
                return {
                    "success": True,
                    "target": target,
                    "resolved_ip": ip_address,
                    "scan_result": scan_results,
                    "scan_level": scan_level,
                    "scan_type": scan_type,
                    "timestamp": datetime.now().isoformat(),
                    "node_id": node_id,
                    "org_id": org_id,
                    "protocol": protocol
                }
            else:
                return {
                    "success": False,
                    "target": target,
                    "resolved_ip": ip_address,
                    "error": "No scan results returned",
                    "timestamp": datetime.now().isoformat(),
                    "node_id": node_id
                }
        
        except Exception as e:
            return {
                "success": False,
                "target": target,
                "error": f"Scan failed: {str(e)}",
                "timestamp": datetime.now().isoformat(),
                "node_id": node_id
            }
    
    def _determine_scan_type(self) -> str:
        """
        Determine the scan type based on enabled scanners.
        
        Returns:
            str: Scan type description
        """
        if self.enabled_scanners:
            if len(self.enabled_scanners) == 1:
                # Single scanner type
                return self.enabled_scanners[0]
            else:
                # Multiple scanners - return comma-separated list
                return ','.join(sorted(self.enabled_scanners))
        else:
            # No specific scanners configured - default scan
            return 'default'
    
    def _is_infrastructure_only_scan(self) -> bool:
        """
        Determine if this is an infrastructure-only scan that doesn't require protocol discovery.
        
        Infrastructure-only scans include:
        - External tools only (nmap, whatweb, ssl, docker)
        - Basic infrastructure scanners (generic, web, vulnerability, geo)
        - No protocol-specific scanners
        
        Returns:
            bool: True if this is an infrastructure-only scan
        """
        # If only external tools are enabled, this is infrastructure-only
        if self.enabled_external_tools and not self.enabled_scanners:
            return True
        
        # If enabled scanners are specified, check if they're all infrastructure scanners
        if self.enabled_scanners:
            infrastructure_scanners = {'generic', 'web', 'vulnerability', 'geo'}
            enabled_set = set(self.enabled_scanners)
            
            # If all enabled scanners are infrastructure scanners, this is infrastructure-only
            if enabled_set.issubset(infrastructure_scanners):
                return True
        
        # Default behavior is infrastructure-only if no specific configuration
        if not self.enabled_scanners and not self.enabled_external_tools:
            return True
        
        return False
    
    def scan_parallel_targets(self, targets: List[str], max_parallel: int = 5, org_id: Optional[str] = None, scan_level: int = 1) -> Dict[str, Any]:
        """
        Scan multiple targets in parallel.
        
        Args:
            targets: List of targets to scan
            max_parallel: Maximum number of parallel scans
            org_id: Optional organization ID to filter agentic jobs
            scan_level: Scan level (1-3, default: 1)
            
        Returns:
            dict: Parallel scan results
        """
        if not targets:
            return {
                "success": False,
                "error": "No targets provided for parallel scanning",
                "timestamp": datetime.now().isoformat()
            }
        
        def scan_single_target(target):
            """Helper function for parallel execution."""
            result = self.scan_target(target, org_id=org_id, scan_level=scan_level)
            return {
                "target": target,
                "success": result["success"],
                "result": result
            }
        
        try:
            results = []
            
            # Use ThreadPoolExecutor for parallel execution
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_parallel) as executor:
                futures = {executor.submit(scan_single_target, target): target for target in targets}
                
                for future in concurrent.futures.as_completed(futures):
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        target = futures[future]
                        results.append({
                            "target": target,
                            "success": False,
                            "result": {
                                "success": False,
                                "target": target,
                                "error": f"Parallel scan failed: {str(e)}",
                                "timestamp": datetime.now().isoformat()
                            }
                        })
            
            successful = sum(1 for r in results if r['success'])
            
            return {
                "success": True,
                "execution_type": "direct_parallel",
                "results": results,
                "successful": successful,
                "total": len(targets),
                "max_parallel": max_parallel,
                "scan_level": scan_level,
                "timestamp": datetime.now().isoformat()
            }
        
        except Exception as e:
            return {
                "success": False,
                "error": f"Parallel scanning failed: {str(e)}",
                "targets": targets,
                "timestamp": datetime.now().isoformat()
            }
    
def load_targets_from_file(file_path: str) -> List[str]:
    """
    Load targets from a file.
    
    Args:
        file_path: Path to file containing targets (one per line)
        
    Returns:
        List of target strings
    """
    targets = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                target = line.strip()
                if target and not target.startswith('#'):
                    targets.append(target)
        return targets
    except FileNotFoundError:
        raise FileNotFoundError(f"Targets file not found: {file_path}")
    except Exception as e:
        raise Exception(f"Error reading targets file {file_path}: {str(e)}")
