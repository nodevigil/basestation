"""
Pipeline orchestrator for coordinating agent execution.
"""

from typing import List, Dict, Any, Optional, Union
from datetime import datetime
from enum import Enum

from agents.base import BaseAgent, ReconAgent, ScanAgent, ProcessAgent, PublishAgent
from utils.agent_registry import get_agent_registry
from core.config import Config
from core.logging import get_logger


class PipelineMode(Enum):
    """Pipeline execution modes."""
    SEQUENTIAL = "sequential"  # Run all stages in sequence
    STAGE_ONLY = "stage_only"  # Run only specified stage
    PARALLEL_RECON = "parallel_recon"  # Run multiple recon agents in parallel


class PipelineOrchestrator:
    """
    Orchestrates the execution of the four-stage DePIN scanning pipeline.
    
    This orchestrator manages the execution flow between reconnaissance,
    scanning, processing, and publishing agents, providing flexible
    execution modes and coordination.
    """
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize pipeline orchestrator.
        
        Args:
            config: Configuration instance
        """
        self.config = config or Config()
        self.logger = get_logger(__name__)
        self.agent_registry = get_agent_registry()
        
        # Pipeline execution state
        self.execution_id = self._generate_execution_id()
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.stage_results: Dict[str, Any] = {}
        
    def _generate_execution_id(self) -> str:
        """Generate unique execution ID."""
        return f"pipeline_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    
    def run_full_pipeline(
        self,
        recon_agents: Optional[List[str]] = None,
        scan_agent: str = "NodeScannerAgent",
        process_agent: str = "ProcessorAgent",
        publish_agent: str = "PublisherAgent"
    ) -> Dict[str, Any]:
        """
        Run the complete four-stage pipeline.
        
        Args:
            recon_agents: List of reconnaissance agent names to run
            scan_agent: Name of scan agent to use
            process_agent: Name of process agent to use
            publish_agent: Name of publish agent to use
            
        Returns:
            Pipeline execution results
        """
        self.logger.info(f"🚀 Starting full pipeline execution: {self.execution_id}")
        self.start_time = datetime.utcnow()
        
        try:
            # Stage 1: Reconnaissance
            recon_results = self.run_recon_stage(recon_agents)
            self.stage_results['recon'] = recon_results
            
            # Stage 2: Scanning
            scan_results = self.run_scan_stage(scan_agent)
            self.stage_results['scan'] = scan_results
            
            # Stage 3: Processing
            process_results = self.run_process_stage(process_agent)
            self.stage_results['process'] = process_results
            
            # Stage 4: Publishing
            publish_results = self.run_publish_stage(publish_agent, process_results)
            self.stage_results['publish'] = publish_results
            
            self.end_time = datetime.utcnow()
            execution_time = (self.end_time - self.start_time).total_seconds()
            
            pipeline_results = {
                'execution_id': self.execution_id,
                'execution_time_seconds': execution_time,
                'stages': self.stage_results,
                'success': True,
                'timestamp': self.end_time.isoformat()
            }
            
            self.logger.info(f"✅ Pipeline execution completed successfully in {execution_time:.2f}s")
            return pipeline_results
            
        except Exception as e:
            self.end_time = datetime.utcnow()
            self.logger.error(f"❌ Pipeline execution failed: {e}")
            
            return {
                'execution_id': self.execution_id,
                'error': str(e),
                'stages': self.stage_results,
                'success': False,
                'timestamp': self.end_time.isoformat() if self.end_time else None
            }
    
    def run_recon_stage(self, agent_names: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Run the reconnaissance stage.
        
        Args:
            agent_names: List of recon agent names to run. If None, runs all available.
            
        Returns:
            Combined results from all recon agents
        """
        self.logger.info("🔍 Stage 1: Running reconnaissance agents")
        
        if agent_names is None:
            # Default to running all available recon agents
            available_agents = self.agent_registry.get_recon_agents()
            agent_names = list(available_agents.keys())
        
        if not agent_names:
            self.logger.warning("No reconnaissance agents specified or available")
            return []
        
        all_results = []
        
        for agent_name in agent_names:
            try:
                self.logger.info(f"🎯 Running recon agent: {agent_name}")
                agent = self.agent_registry.create_recon_agent(agent_name, self.config)
                
                if agent:
                    results = agent.execute()
                    all_results.extend(results)
                    self.logger.info(f"✅ {agent_name} discovered {len(results)} nodes")
                else:
                    self.logger.error(f"❌ Failed to create recon agent: {agent_name}")
                    
            except Exception as e:
                self.logger.error(f"❌ Error running recon agent {agent_name}: {e}")
        
        self.logger.info(f"🔍 Reconnaissance stage completed: {len(all_results)} total nodes discovered")
        return all_results
    
    def run_scan_stage(self, agent_name: str = "NodeScannerAgent") -> List[Dict[str, Any]]:
        """
        Run the scanning stage.
        
        Args:
            agent_name: Name of scan agent to use
            
        Returns:
            Scan results
        """
        self.logger.info(f"🛡️  Stage 2: Running scan agent: {agent_name}")
        
        try:
            agent = self.agent_registry.create_scan_agent(agent_name, self.config)
            
            if not agent:
                raise Exception(f"Failed to create scan agent: {agent_name}")
            
            # Run scanning (agent will load nodes needing scans from database)
            results = agent.execute()
            
            self.logger.info(f"🛡️  Scanning stage completed: {len(results)} nodes scanned")
            return results
            
        except Exception as e:
            self.logger.error(f"❌ Error running scan agent {agent_name}: {e}")
            return []
    
    def run_process_stage(self, agent_name: str = "ProcessorAgent") -> List[Dict[str, Any]]:
        """
        Run the processing stage.
        
        Args:
            agent_name: Name of process agent to use
            
        Returns:
            Processed results
        """
        self.logger.info(f"📊 Stage 3: Running process agent: {agent_name}")
        
        try:
            agent = self.agent_registry.create_process_agent(agent_name, self.config)
            
            if not agent:
                raise Exception(f"Failed to create process agent: {agent_name}")
            
            # Run processing (agent will load unprocessed results from database)
            results = agent.execute()
            
            self.logger.info(f"📊 Processing stage completed: {len(results)} results processed")
            return results
            
        except Exception as e:
            self.logger.error(f"❌ Error running process agent {agent_name}: {e}")
            return []
    
    def run_publish_stage(
        self,
        agent_name: str = "PublisherAgent",
        processed_results: Optional[List[Dict[str, Any]]] = None
    ) -> bool:
        """
        Run the publishing stage.
        
        Args:
            agent_name: Name of publish agent to use
            processed_results: Results to publish. If None, loads from database.
            
        Returns:
            True if publishing succeeded, False otherwise
        """
        self.logger.info(f"📤 Stage 4: Running publish agent: {agent_name}")
        
        try:
            agent = self.agent_registry.create_publish_agent(agent_name, self.config)
            
            if not agent:
                raise Exception(f"Failed to create publish agent: {agent_name}")
            
            # Run publishing
            success = agent.execute(processed_results)
            
            if success:
                self.logger.info("📤 Publishing stage completed successfully")
            else:
                self.logger.warning("⚠️  Publishing stage completed with some failures")
            
            return success
            
        except Exception as e:
            self.logger.error(f"❌ Error running publish agent {agent_name}: {e}")
            return False
    
    def run_single_stage(
        self,
        stage: str,
        agent_name: Optional[str] = None,
        **stage_args
    ) -> Any:
        """
        Run a single pipeline stage.
        
        Args:
            stage: Stage name ('recon', 'scan', 'process', 'publish')
            agent_name: Specific agent name to use
            **stage_args: Additional arguments for the stage
            
        Returns:
            Stage execution results
        """
        self.logger.info(f"🎯 Running single stage: {stage}")
        
        if stage == 'recon':
            agent_names = stage_args.get('agent_names', [agent_name] if agent_name else None)
            return self.run_recon_stage(agent_names)
        
        elif stage == 'scan':
            return self.run_scan_stage(agent_name or "NodeScannerAgent")
        
        elif stage == 'process':
            return self.run_process_stage(agent_name or "ProcessorAgent")
        
        elif stage == 'publish':
            processed_results = stage_args.get('processed_results')
            return self.run_publish_stage(agent_name or "PublisherAgent", processed_results)
        
        else:
            raise ValueError(f"Unknown stage: {stage}")
    
    def get_pipeline_status(self) -> Dict[str, Any]:
        """
        Get current pipeline execution status.
        
        Returns:
            Pipeline status information
        """
        return {
            'execution_id': self.execution_id,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_seconds': (
                (self.end_time - self.start_time).total_seconds()
                if self.start_time and self.end_time else None
            ),
            'completed_stages': list(self.stage_results.keys()),
            'available_agents': self.agent_registry.list_all_agents()
        }
    
    def list_available_agents(self) -> Dict[str, List[str]]:
        """
        List all available agents by category.
        
        Returns:
            Dictionary of agent categories and their available agents
        """
        return self.agent_registry.list_all_agents()


def create_orchestrator(config: Optional[Config] = None) -> PipelineOrchestrator:
    """
    Create a pipeline orchestrator instance.
    
    Args:
        config: Configuration instance
        
    Returns:
        PipelineOrchestrator instance
    """
    return PipelineOrchestrator(config)
