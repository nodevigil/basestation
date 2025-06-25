"""
Pipeline Orchestration Module

Provides high-level pipeline orchestration for the DePIN infrastructure scanner.
This module abstracts the business logic from CLI concerns.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime

from pgdn.core.config import Config
from pgdn.utils.pipeline import create_orchestrator


class PipelineOrchestrator:
    """
    High-level orchestrator for running DePIN scanning pipelines.
    
    This class provides a clean Python API for orchestrating the complete
    four-stage pipeline or individual stages, independent of CLI concerns.
    """
    
    def __init__(self, config: Config):
        """
        Initialize the pipeline orchestrator.
        
        Args:
            config: Configuration instance
        """
        self.config = config
        self._orchestrator = None
    
    @property
    def orchestrator(self):
        """Lazy-load the orchestrator."""
        if self._orchestrator is None:
            self._orchestrator = create_orchestrator(self.config)
        return self._orchestrator
    
    def run_full_pipeline(self, recon_agents: Optional[List[str]] = None, org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Run the complete four-stage pipeline.
        
        Args:
            recon_agents: Optional list of specific recon agents to run
            org_id: Optional organization ID to filter agentic jobs
            
        Returns:
            dict: Pipeline execution results including success status, execution_id,
                  timing, and stage results
        """
        try:
            results = self.orchestrator.run_full_pipeline(recon_agents=recon_agents, org_id=org_id)
            
            return {
                "success": results['success'],
                "execution_id": results.get('execution_id'),
                "execution_time_seconds": results.get('execution_time_seconds'),
                "stages": results.get('stages', {}),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Pipeline execution failed: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
    
    def run_recon_stage(self, agent_names: Optional[List[str]] = None, org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Run only the reconnaissance stage.
        
        Args:
            agent_names: Optional list of specific recon agents to run
            org_id: Optional organization ID to filter agentic jobs
            
        Returns:
            dict: Reconnaissance results
        """
        try:
            results = self.orchestrator.run_single_stage('recon', agent_names=agent_names, org_id=org_id)
            
            return {
                "success": True,
                "stage": "recon",
                "results": results,
                "results_count": len(results) if isinstance(results, list) else (1 if results else 0),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "success": False,
                "stage": "recon",
                "error": f"Reconnaissance stage failed: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
    
    def run_scan_stage(
        self, 
        target: Optional[str] = None,
        org_id: Optional[str] = None,
        scan_level: int = 1,
        force_protocol: Optional[str] = None,
        debug: bool = False,
        enabled_scanners: Optional[List[str]] = None,
        enabled_external_tools: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Run only the scanning stage with new orchestration approach.
        
        Args:
            target: Optional specific target to scan (if provided, requires org_id)
            org_id: Organization ID (required for target scanning)
            scan_level: Scan level (1-3, default: 1)
            force_protocol: Optional protocol to force run (bypasses auto-detection)
            debug: Enable debug logging
            enabled_scanners: Optional list of specific scanners to enable
            enabled_external_tools: Optional list of specific external tools to enable
            
        Returns:
            dict: Scan results with both orchestrator and protocol scan results
        """
        try:
            # Use the new Scanner class with modular orchestration (without protocol-specific scanning)
            from pgdn.scanner import Scanner
            
            scanner = Scanner(
                self.config, 
                debug=debug,
                enabled_scanners=enabled_scanners,
                enabled_external_tools=enabled_external_tools
            )
            
            # Results container
            results = {
                "success": True,
                "stage": "scan",
                "scan_level": scan_level,
                "timestamp": datetime.now().isoformat(),
                "orchestrator_scan": None,
                "protocol_scan": None
            }
            
            if target:
                # Target scanning requires org_id
                if not org_id:
                    return {
                        "success": False,
                        "error": "Target scanning requires --org-id argument",
                        "suggestion": "Example: pgdn --stage scan --target 139.84.148.36 --org-id myorg"
                    }
                
                # 1. Run orchestrator scan (infrastructure scanning)
                orchestrator_result = scanner.scan_target(target, org_id=org_id, scan_level=scan_level)
                results["orchestrator_scan"] = orchestrator_result
                results["operation"] = "target_scan"
                results["target"] = target
                
                # 2. Run protocol scan if force_protocol is specified
                if force_protocol:
                    protocol_result = self._run_protocol_scan(target, force_protocol, org_id, scan_level, debug)
                    results["protocol_scan"] = protocol_result
                
                # 3. TODO: Auto-detect protocol from discovery data and run protocol scan
                # This would check if discovery metadata indicates a known protocol type
                
                # Maintain backward compatibility - return orchestrator result as main scan_result
                results["scan_result"] = orchestrator_result
                
                return results
            else:
                # Database scanning - run orchestrator on database nodes
                orchestrator_result = scanner.scan_nodes_from_database(org_id=org_id, scan_level=scan_level)
                results["orchestrator_scan"] = orchestrator_result
                results["operation"] = "database_scan"
                results["results"] = orchestrator_result.get("results", [])
                results["results_count"] = orchestrator_result.get("results_count", 0)
                
                # For database scans, protocol scanning is typically handled by NodeScannerAgent
                # which already includes protocol-specific logic
                
                return results
            
        except Exception as e:
            return {
                "success": False,
                "stage": "scan",
                "error": f"Scanning stage failed: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
    
    def _run_protocol_scan(self, target: str, protocol: str, org_id: str, scan_level: int, debug: bool) -> Dict[str, Any]:
        """
        Run protocol-specific scanning separately from orchestrator.
        
        Args:
            target: Target to scan
            protocol: Protocol name (sui, filecoin, etc.)
            org_id: Organization ID
            scan_level: Scan level
            debug: Debug mode
            
        Returns:
            Protocol scan results
        """
        try:
            # Import protocol scanner dynamically
            if protocol == 'sui':
                from pgdn.scanning.sui_scanner import SuiSpecificScanner
                protocol_scanner = SuiSpecificScanner(debug=debug)
            elif protocol == 'filecoin':
                from pgdn.scanning.filecoin_scanner import FilecoinSpecificScanner
                protocol_scanner = FilecoinSpecificScanner(debug=debug)
            else:
                return {
                    "success": False,
                    "error": f"Unknown protocol: {protocol}",
                    "protocol": protocol
                }
            
            # Resolve target to IP
            import socket
            try:
                ip_address = socket.gethostbyname(target)
            except socket.gaierror as e:
                return {
                    "success": False,
                    "error": f"DNS resolution failed: {str(e)}",
                    "protocol": protocol,
                    "target": target
                }
            
            # Run protocol-specific scan
            protocol_result = protocol_scanner.scan(ip_address, scan_level=scan_level)
            
            return {
                "success": True,
                "protocol": protocol,
                "target": target,
                "resolved_ip": ip_address,
                "scan_level": scan_level,
                "result": protocol_result,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Protocol scan failed: {str(e)}",
                "protocol": protocol,
                "target": target,
                "timestamp": datetime.now().isoformat()
            }

    def run_process_stage(self, agent_name: Optional[str] = None, org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Run only the processing stage.
        
        Args:
            agent_name: Optional specific agent name to use
            org_id: Optional organization ID to filter agentic jobs
            
        Returns:
            dict: Processing results
        """
        try:
            results = self.orchestrator.run_single_stage('process', agent_name, org_id=org_id)
            
            return {
                "success": True,
                "stage": "process",
                "results": results,
                "results_count": len(results) if isinstance(results, list) else (1 if results else 0),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "success": False,
                "stage": "process",
                "error": f"Processing stage failed: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
    
    def run_scoring_stage(self, agent_name: str = 'ScoringAgent', force_rescore: bool = False, org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Run only the scoring stage.
        
        Args:
            agent_name: Agent name to use for scoring
            force_rescore: Whether to force re-scoring of existing results
            org_id: Optional organization ID to filter agentic jobs
            
        Returns:
            dict: Scoring results
        """
        try:
            results = self.orchestrator.run_scoring_stage(agent_name, force_rescore=force_rescore, org_id=org_id)
            
            return {
                "success": True,
                "stage": "score",
                "results": results,
                "results_count": len(results) if isinstance(results, list) else (1 if results else 0),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "success": False,
                "stage": "score",
                "error": f"Scoring stage failed: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
    
    def run_publish_stage(self, agent_name: str, scan_id: int, org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Run only the publishing stage.
        
        Args:
            agent_name: Agent name to use for publishing ('PublishLedgerAgent' or 'PublishReportAgent')
            scan_id: Scan ID to publish results for
            org_id: Optional organization ID to filter agentic jobs
            
        Returns:
            dict: Publishing results
        """
        try:
            results = self.orchestrator.run_publish_stage(agent_name, scan_id=scan_id, org_id=org_id)
            
            return {
                "success": True,
                "stage": "publish",
                "results": results,
                "agent": agent_name,
                "scan_id": scan_id,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "success": False,
                "stage": "publish",
                "error": f"Publishing stage failed: {str(e)}",
                "agent": agent_name,
                "scan_id": scan_id,
                "timestamp": datetime.now().isoformat()
            }
    
    def run_signature_stage(self, agent_name: str = 'ProtocolSignatureGeneratorAgent', org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Run only the signature generation stage.
        
        Args:
            agent_name: Agent name to use for signature generation
            org_id: Optional organization ID to filter agentic jobs
            
        Returns:
            dict: Signature generation results
        """
        try:
            results = self.orchestrator.run_signature_stage(agent_name, org_id=org_id)
            
            return {
                "success": True,
                "stage": "signature",
                "results": results,
                "results_count": len(results) if isinstance(results, list) else (1 if results else 0),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "success": False,
                "stage": "signature",
                "error": f"Signature generation stage failed: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
    
    def run_discovery_stage(self, agent_name: str = 'DiscoveryAgent', host: str = None, org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Run only the network topology discovery stage.
        
        Args:
            agent_name: Agent name to use for discovery
            host: Host/IP address for network topology discovery
            org_id: Optional organization ID to filter agentic jobs
            
        Returns:
            dict: Discovery results
        """
        if not host:
            return {
                "success": False,
                "stage": "discovery",
                "error": "Discovery stage requires host parameter",
                "timestamp": datetime.now().isoformat()
            }
        
        try:
            results = self.orchestrator.run_discovery_stage(agent_name, host=host, org_id=org_id)
            
            return {
                "success": True,
                "stage": "discovery",
                "results": results,
                "results_count": len(results) if isinstance(results, list) else (1 if results else 0),
                "host": host,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "success": False,
                "stage": "discovery",
                "error": f"Discovery stage failed: {str(e)}",
                "host": host,
                "timestamp": datetime.now().isoformat()
            }
