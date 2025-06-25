"""
Scanner Module

Provides scanning functionality for individual targets and bulk scanning operations.
This module now uses the new modular scanning system with ScanOrchestrator.
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
    
    def __init__(self, config: Config, protocol_filter: Optional[str] = None, debug: bool = False, 
                 enabled_scanners: Optional[List[str]] = None, enabled_external_tools: Optional[List[str]] = None):
        """
        Initialize the scanner.
        
        Args:
            config: Configuration instance
            protocol_filter: Optional protocol filter (e.g., 'filecoin', 'sui')
            debug: Enable debug logging
            enabled_scanners: List of specific scanners to run (overrides config)
            enabled_external_tools: List of specific external tools to run (overrides config)
        """
        self.config = config
        self.protocol_filter = protocol_filter
        self.debug = debug
        self.enabled_scanners = enabled_scanners
        self.enabled_external_tools = enabled_external_tools
    
    def scan_target(self, target: str, org_id: Optional[str] = None, scan_level: int = 1) -> Dict[str, Any]:
        """
        Scan a specific target (IP or hostname) with orchestration workflow.
        
        Args:
            target: IP address or hostname to scan
            org_id: Organization ID (required for orchestration)
            scan_level: Scan level (1-3, default: 1)
            
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
            scan_result = self._perform_scan(target, org_id, protocol, node_id, scan_level)
            
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
            from pgdn.scanning.scan_orchestrator import ScanOrchestrator
            
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
            
            # Perform the scan using the new modular system with scan_level
            scan_results = orchestrator.scan(
                target=ip_address,
                scan_level=scan_level,
                scan_timestamp=datetime.now().isoformat()
            )
            
            if scan_results:
                # Determine scan type based on enabled scanners
                scan_type = self._determine_scan_type()
                
                # Save scan results to database for target scans
                try:
                    scan_record_id = self._save_target_scan_result(target, ip_address, scan_results, org_id, protocol, node_id, scan_level, scan_type)
                    
                    return {
                        "success": True,
                        "target": target,
                        "resolved_ip": ip_address,
                        "scan_result": scan_results,
                        "scan_level": scan_level,
                        "timestamp": datetime.now().isoformat(),
                        "node_id": node_id,
                        "org_id": org_id,
                        "protocol": protocol,
                        "scan_record_id": scan_record_id
                    }
                except Exception as e:
                    # If database save fails, still return the scan results but log the error
                    return {
                        "success": True,
                        "target": target,
                        "resolved_ip": ip_address,
                        "scan_result": scan_results,
                        "scan_level": scan_level,
                        "timestamp": datetime.now().isoformat(),
                        "node_id": node_id,
                        "org_id": org_id,
                        "protocol": protocol,
                        "database_save_error": str(e)
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
    
    def _save_target_scan_result(self, target: str, ip_address: str, scan_results: Dict[str, Any], 
                                org_id: str, protocol: Optional[str], node_id: Optional[str], scan_level: int, 
                                scan_type: Optional[str] = None) -> int:
        """
        Save target scan results to database.
        
        Args:
            target: Original target (hostname or IP)
            ip_address: Resolved IP address
            scan_results: Scan results from orchestrator
            org_id: Organization ID
            protocol: Protocol name (if determined)
            node_id: Node UUID for tracking
            scan_level: Scan level used
            scan_type: Type of scan performed (e.g., 'web', 'geo', 'generic')
            
        Returns:
            int: ID of created scan record
        """
        import hashlib
        import json
        from pgdn.core.database import get_db_session, ValidatorAddress, ValidatorScan, Protocol, SCANNER_VERSION
        
        # Compute scan hash (same logic as NodeScannerAgent)
        hash_data = {
            'ip_address': ip_address,
            'generic_scan': scan_results.get('generic_scan', {}),
            'protocol_scan': scan_results.get('protocol_scan', {})
        }
        content_json = json.dumps(hash_data, sort_keys=True)
        scan_hash = hashlib.sha256(content_json.encode()).hexdigest()
        
        with get_db_session() as session:
            # Find or create protocol
            protocol_record = None
            if protocol:
                protocol_record = session.query(Protocol).filter(Protocol.name == protocol).first()
                if not protocol_record:
                    # Create minimal protocol entry for target scans
                    protocol_record = Protocol(
                        name=protocol,
                        display_name=protocol.title(),
                        category="target_scan",
                        ports=[],
                        endpoints=[],
                        banners=[],
                        rpc_methods=[],
                        metrics_keywords=[],
                        http_paths=[],
                        identification_hints=[]
                    )
                    session.add(protocol_record)
                    session.flush()  # Get the ID
            
            # Find or create validator address for this target
            validator = session.query(ValidatorAddress).filter(ValidatorAddress.address == target).first()
            if not validator:
                # Create new validator address entry
                validator = ValidatorAddress(
                    address=target,
                    name=f"Target scan: {target}",
                    protocol_id=protocol_record.id if protocol_record else None,
                    active=True
                )
                session.add(validator)
                session.flush()  # Get the ID
            
            # Create scan result with proper format (similar to NodeScannerAgent._save_scan_result)
            scan_result_data = {
                'node_id': str(validator.uuid),  # Use validator UUID
                'address': target,
                'ip_address': ip_address,
                'scan_start': int(datetime.now().timestamp()),
                'scan_end': int(datetime.now().timestamp()),
                'generic_scan': scan_results,  # The orchestrator results contain all scan data
                'protocol_scan': None,  # Protocol-specific data is already in generic_scan
                'web_probes': None,
                'source': f"target_scan_{org_id}",
                'failed': False
            }
            
            # Create scan record
            scan_record = ValidatorScan(
                validator_address_id=validator.id,
                scan_date=datetime.now(),
                ip_address=ip_address,
                score=None,  # Will be computed by ProcessAgent
                scan_hash=scan_hash,
                scan_results=scan_result_data,
                failed=False,
                version=SCANNER_VERSION,
                scan_type=scan_type or 'target_scan'  # Default to 'target_scan' if not specified
            )
            
            session.add(scan_record)
            session.commit()
            
            return scan_record.id
    
    def scan_nodes_from_database(self, org_id: Optional[str] = None, scan_level: int = 1) -> Dict[str, Any]:
        """
        Scan nodes discovered in the database using the new modular scanning system.
        
        Args:
            org_id: Optional organization ID to filter nodes
            scan_level: Scan level (1-3, default: 1)
        
        Returns:
            dict: Scan results including success status and scan data
        """
        try:
            from pgdn.scanning.scan_orchestrator import ScanOrchestrator
            from core.database import get_db_session
            from models.ledger import NodeMetadata
            
            # Get nodes from database
            results = []
            with get_db_session() as session:
                query = session.query(NodeMetadata)
                if org_id:
                    query = query.filter(NodeMetadata.org_id == org_id)
                if self.protocol_filter:
                    query = query.filter(NodeMetadata.protocol == self.protocol_filter)
                
                nodes = query.filter(NodeMetadata.status == 'discovered').all()
                
                if not nodes:
                    return {
                        "success": True,
                        "stage": "scan",
                        "results": [],
                        "results_count": 0,
                        "message": "No discovered nodes found to scan",
                        "protocol_filter": self.protocol_filter,
                        "timestamp": datetime.now().isoformat()
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
                
                orchestrator = ScanOrchestrator(scan_config)
                
                # Scan each node
                for node in nodes:
                    try:
                        scan_result = orchestrator.scan(
                            target=node.target,
                            scan_level=scan_level,
                            scan_timestamp=datetime.now().isoformat()
                        )
                        
                        results.append({
                            "node_id": node.node_id,
                            "target": node.target,
                            "protocol": node.protocol,
                            "scan_result": scan_result,
                            "scan_level": scan_level,
                            "success": True
                        })
                        
                        # Update node status to scanned
                        node.status = 'scanned'
                        node.last_scanned = datetime.now()
                        
                    except Exception as e:
                        results.append({
                            "node_id": node.node_id,
                            "target": node.target,
                            "protocol": node.protocol,
                            "success": False,
                            "error": str(e)
                        })
                
                session.commit()
            
            return {
                "success": True,
                "stage": "scan",
                "results": results,
                "results_count": len(results),
                "scan_level": scan_level,
                "protocol_filter": self.protocol_filter,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "success": False,
                "stage": "scan",
                "error": f"Database node scanning failed: {str(e)}",
                "protocol_filter": self.protocol_filter,
                "timestamp": datetime.now().isoformat()
            }
    
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
