"""
Scanner Module

Provides scanning functionality for individual targets and bulk scanning operations.
This module abstracts scanning logic from CLI concerns.
"""

import socket
import json
import concurrent.futures
from typing import Optional, List, Dict, Any
from datetime import datetime

from pgdn.core.config import Config


class Scanner:
    """
    Scanner for DePIN infrastructure nodes and targets.
    
    This class provides a clean Python API for scanning individual targets
    or running bulk scanning operations, independent of CLI concerns.
    """
    
    def __init__(self, config: Config, protocol_filter: Optional[str] = None, debug: bool = False):
        """
        Initialize the scanner.
        
        Args:
            config: Configuration instance
            protocol_filter: Optional protocol filter (e.g., 'filecoin', 'sui')
            debug: Enable debug logging
        """
        self.config = config
        self.protocol_filter = protocol_filter
        self.debug = debug
    
    def scan_target(self, target: str, org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Scan a specific target (IP or hostname) with orchestration workflow.
        
        Args:
            target: IP address or hostname to scan
            org_id: Organization ID (required for orchestration)
            
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
            from services.node_orchestration import NodeOrchestrationService
            
            # Use orchestration service to validate request and determine workflow
            orchestration = NodeOrchestrationService()
            validation_result = orchestration.validate_scan_request(
                org_id=org_id,
                target=target,
                protocol_filter=self.protocol_filter
            )
            
            # If validation fails or discovery is required, return immediately
            if not validation_result.get("success", False):
                return validation_result
            
            # If we get here, we're ready to scan
            node_id = validation_result.get("node_id")
            protocol = validation_result.get("protocol")
            
            # Proceed with actual scanning
            scan_result = self._perform_scan(target, org_id, protocol, node_id)
            
            # Update node status after scan
            if node_id:
                orchestration.update_node_after_scan(
                    node_id=node_id,
                    scan_successful=scan_result.get("success", False)
                )
            
            return scan_result
            
        except Exception as e:
            return {
                "success": False,
                "target": target,
                "error": f"Orchestration error: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
    
    def _perform_scan(self, target: str, org_id: str, protocol: Optional[str], node_id: Optional[str]) -> Dict[str, Any]:
        """
        Perform the actual scan using the existing scanning logic.
        
        Args:
            target: IP address or hostname to scan
            org_id: Organization ID
            protocol: Protocol name (if determined)
            node_id: Node UUID for tracking
            
        Returns:
            dict: Scan results
        """
        try:
            from pgdn.agent_modules.scan.node_scanner_agent import NodeScannerAgent
            
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
            
            # Create a mock node entry for the scanner agent
            import uuid
            
            # Determine source based on protocol filter
            if protocol:
                source = f'{protocol}_manual_scan'
                effective_protocol = protocol
            elif self.protocol_filter:
                source = f'{self.protocol_filter}_manual_scan'
                effective_protocol = self.protocol_filter
            else:
                source = 'manual_scan'
                effective_protocol = None
            
            mock_node = {
                'id': 0,
                'uuid': node_id or str(uuid.uuid4()),
                'address': target,
                'source': source,
                'name': f'Direct scan of {target}',
                'protocol_name': effective_protocol,
                'org_id': org_id  # Add org_id for tracking
            }
            
            # Initialize scanner agent
            scanner_agent = NodeScannerAgent(self.config, 
                                           protocol_filter=effective_protocol, 
                                           debug=self.debug)
            
            # Run the scan using the agent
            scan_results = scanner_agent.scan_nodes([mock_node], org_id=org_id)
            
            if scan_results:
                return {
                    "success": True,
                    "target": target,
                    "resolved_ip": ip_address,
                    "scan_result": scan_results[0],
                    "timestamp": datetime.now().isoformat(),
                    "node_id": node_id,
                    "org_id": org_id,
                    "protocol": effective_protocol
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
    
    def scan_nodes_from_database(self, org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Scan nodes discovered in the database using the scan stage.
        
        Args:
            org_id: Optional organization ID to filter agentic jobs
        
        Returns:
            dict: Scan results including success status and scan data
        """
        try:
            from pgdn.agent_modules.scan.node_scanner_agent import NodeScannerAgent
            
            scanner_agent = NodeScannerAgent(self.config, 
                                           protocol_filter=self.protocol_filter, 
                                           debug=self.debug)
            results = scanner_agent.scan_nodes(org_id=org_id)
            
            return {
                "success": True,
                "stage": "scan",
                "results": results,
                "results_count": len(results),
                "protocol_filter": self.protocol_filter,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "success": False,
                "stage": "scan",
                "error": f"Node scanning failed: {str(e)}",
                "protocol_filter": self.protocol_filter,
                "timestamp": datetime.now().isoformat()
            }
    
    def scan_parallel_targets(self, targets: List[str], max_parallel: int = 5, org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Scan multiple targets in parallel.
        
        Args:
            targets: List of targets to scan
            max_parallel: Maximum number of parallel scans
            org_id: Optional organization ID to filter agentic jobs
            
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
            result = self.scan_target(target, org_id=org_id)
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
                "protocol_filter": self.protocol_filter,
                "timestamp": datetime.now().isoformat()
            }
        
        except Exception as e:
            return {
                "success": False,
                "error": f"Parallel scanning failed: {str(e)}",
                "targets": targets,
                "timestamp": datetime.now().isoformat()
            }
    
    def save_scan_result(self, scan_result: Dict[str, Any], target: str) -> str:
        """
        Save scan result to a file.
        
        Args:
            scan_result: Scan result data
            target: Target that was scanned
            
        Returns:
            str: Path to saved file
        """
        # Clean target for filename
        safe_target = target.replace('.', '_').replace(':', '_')
        output_file = f"scan_result_{safe_target}.json"
        
        with open(output_file, 'w') as f:
            json.dump(scan_result, f, indent=2)
        
        return output_file


def load_targets_from_file(file_path: str) -> List[str]:
    """
    Load targets from a file.
    
    Args:
        file_path: Path to file containing targets (one per line)
        
    Returns:
        List of targets
        
    Raises:
        FileNotFoundError: If file doesn't exist
        Exception: If file can't be read
    """
    with open(file_path, 'r') as f:
        targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    return targets
