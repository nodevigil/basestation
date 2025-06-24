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
