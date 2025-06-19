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
    SEQUENTIAL_SCAN = "sequential_scan"  # Force sequential scanning (no threading)


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
        
        # Scan execution mode
        self._original_max_concurrent_scans = self.config.scanning.max_concurrent_scans
        
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
        self.logger.info(f"🔧 Scan mode: {self.get_scan_mode()}")
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
    
    def run_full_pipeline_sequential(
        self,
        recon_agents: Optional[List[str]] = None,
        scan_agent: str = "NodeScannerAgent",
        process_agent: str = "ProcessorAgent",
        publish_agent: str = "PublisherAgent"
    ) -> Dict[str, Any]:
        """
        Run the complete pipeline with sequential scanning (no threading).
        
        This is a convenience method that temporarily disables concurrent scanning
        for this pipeline execution.
        
        Args:
            recon_agents: List of reconnaissance agent names to run
            scan_agent: Name of scan agent to use
            process_agent: Name of process agent to use
            publish_agent: Name of publish agent to use
            
        Returns:
            Pipeline execution results
        """
        # Temporarily enable sequential mode
        original_mode = self.config.scanning.max_concurrent_scans
        self.enable_sequential_scanning()
        
        try:
            return self.run_full_pipeline(
                recon_agents=recon_agents,
                scan_agent=scan_agent,
                process_agent=process_agent,
                publish_agent=publish_agent
            )
        finally:
            # Restore original mode
            self.config.scanning.max_concurrent_scans = original_mode
    
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
    
    def run_scoring_stage(self, agent_name: str = "ScoringAgent", force_rescore: bool = False) -> List[Dict[str, Any]]:
        """
        Run the scoring stage independently.
        
        Args:
            agent_name: Name of scoring agent to use
            force_rescore: Whether to re-score results that already have scores
            
        Returns:
            Scored results
        """
        self.logger.info(f"📊 Running scoring stage: {agent_name} (force_rescore={force_rescore})")
        try:
            agent = self.agent_registry.create_process_agent(agent_name, self.config)
            
            if not agent:
                raise Exception(f"Failed to create scoring agent: {agent_name}")
            
            # Run scoring (agent will load unscored results from database)
            results = agent.execute(force_rescore=force_rescore)
            
            self.logger.info(f"📊 Scoring stage completed: {len(results)} results scored")
            return results
            
        except Exception as e:
            self.logger.error(f"❌ Error running scoring agent {agent_name}: {e}")
            return []
    
    def run_report_stage(self, agent_name: str = "ReportAgent", report_options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Run the report generation stage independently.
        
        Args:
            agent_name: Name of report agent to use
            report_options: Report generation options (input_file, output_file, format, scan_id, force_report, etc.)
            
        Returns:
            Report generation results
        """
        self.logger.info(f"📊 Running report stage: {agent_name}")
        try:
            agent = self.agent_registry.create_process_agent(agent_name, self.config)
            
            if not agent:
                raise Exception(f"Failed to create report agent: {agent_name}")
            
            # Check if we have scan_id or force_report options for database-driven reporting
            scan_id = report_options.get('scan_id') if report_options else None
            force_report = report_options.get('force_report', False) if report_options else False
            
            # Generate report using the agent with provided options
            if scan_id is not None or force_report or not report_options or not report_options.get('input_file'):
                # Use the database-driven execute method
                if hasattr(agent, 'execute'):
                    print(f"📊 Report options: {report_options}")
                    print(f"📊 Report options: {report_options}")
                    print(f"📊 Report options: {report_options}")
                    print(f"📊 Report options: {report_options}")
                    print(f"📊 Report options: {report_options}")
            
                    results = agent.execute(scan_id=scan_id, force_report=force_report)
                else:
                    
                    # Fallback to standard execute method
                    results = agent.execute()
            elif hasattr(agent, 'generate_and_output_report') and report_options:
                # Use file-based report generation
                results = agent.generate_and_output_report(report_options)
            else:
                # Fallback to standard execute method
                results = agent.execute()
            
            self.logger.info(f"📊 Report stage completed successfully")
            return results
            
        except Exception as e:
            self.logger.error(f"❌ Error running report agent {agent_name}: {e}")
            return {}
    
    def run_single_stage(
        self,
        stage: str,
        agent_name: Optional[str] = None,
        **stage_args
    ) -> Any:
        """
        Run a single pipeline stage.
        
        Args:
            stage: Stage name ('recon', 'scan', 'process', 'score', 'report', 'publish')
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
        
        elif stage == 'score':
            return self.run_scoring_stage(agent_name or "ScoringAgent")
        
        elif stage == 'publish':
            processed_results = stage_args.get('processed_results')
            return self.run_publish_stage(agent_name or "PublisherAgent", processed_results)
        
        elif stage == 'report':
            report_options = stage_args.get('report_options')
            return self.run_report_stage(agent_name or "ReportAgent", report_options)
        
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
    
    def enable_sequential_scanning(self) -> None:
        """
        Enable sequential scanning mode (disable threading).
        
        This forces scans to run one at a time instead of concurrently.
        Useful for debugging, rate limiting, or when resources are constrained.
        """
        self.logger.info("🔄 Enabling sequential scanning mode (threading disabled)")
        self.config.scanning.max_concurrent_scans = 1
        
    def enable_concurrent_scanning(self, max_workers: Optional[int] = None) -> None:
        """
        Enable concurrent scanning mode (enable threading).
        
        Args:
            max_workers: Maximum number of concurrent scans. If None, uses original config value.
        """
        if max_workers is None:
            max_workers = self._original_max_concurrent_scans
            
        self.logger.info(f"⚡ Enabling concurrent scanning mode (max_workers={max_workers})")
        self.config.scanning.max_concurrent_scans = max_workers
        
    def get_scan_mode(self) -> str:
        """
        Get current scanning mode.
        
        Returns:
            'sequential' or 'concurrent'
        """
        return "sequential" if self.config.scanning.max_concurrent_scans <= 1 else "concurrent"
        
    def set_scan_concurrency(self, max_concurrent: int) -> None:
        """
        Set the maximum number of concurrent scans.
        
        Args:
            max_concurrent: Maximum concurrent scans (1 = sequential, >1 = concurrent)
        """
        mode = "sequential" if max_concurrent <= 1 else f"concurrent (max={max_concurrent})"
        self.logger.info(f"🔧 Setting scan concurrency: {mode}")
        self.config.scanning.max_concurrent_scans = max_concurrent


def create_orchestrator(config: Optional[Config] = None) -> PipelineOrchestrator:
    """
    Create a pipeline orchestrator instance.
    
    Args:
        config: Configuration instance
        
    Returns:
        PipelineOrchestrator instance
    """
    return PipelineOrchestrator(config)
