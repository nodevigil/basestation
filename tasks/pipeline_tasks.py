"""
Pipeline task definitions for Celery.
"""

from celery.utils.log import get_task_logger
from typing import Dict, Any, List, Optional
import json
import traceback

logger = get_task_logger(__name__)

# Import the celery app
from celery_app import app

@app.task(bind=True, name='tasks.pipeline.run_full_pipeline')
def run_full_pipeline_task(self, config_dict: Dict[str, Any], recon_agents: Optional[List[str]] = None):
    """
    Run the complete four-stage pipeline as a Celery task.
    
    Args:
        config_dict: Configuration dictionary
        recon_agents: Optional list of specific recon agents to run
        
    Returns:
        Dict with execution results
    """
    try:
        # Import here to avoid circular imports
        from pgdn.core.config import Config
        from pgdn.core.logging import setup_logging
        from pgdn.core.database import create_tables
        from pgdn.utils.pipeline import create_orchestrator
        
        # Load configuration
        config = Config(config_overrides=config_dict)
        
        # Setup environment
        setup_logging(config.logging)
        create_tables(config.database)
        
        # Create orchestrator and run pipeline
        orchestrator = create_orchestrator(config)
        results = orchestrator.run_full_pipeline(recon_agents=recon_agents)
        
        logger.info(f"Full pipeline completed successfully. Execution ID: {results.get('execution_id')}")
        return results
        
    except Exception as e:
        logger.error(f"Full pipeline task failed: {e}")
        logger.error(traceback.format_exc())
        self.retry(countdown=60, max_retries=3)


@app.task(bind=True, name='tasks.pipeline.run_single_stage')
def run_single_stage_task(
    self, 
    config_dict: Dict[str, Any], 
    stage: str, 
    agent_name: Optional[str] = None,
    recon_agents: Optional[List[str]] = None,
    protocol_filter: Optional[str] = None,
    debug: bool = False,
    force_rescore: bool = False,
    host: Optional[str] = None,
    **kwargs
):
    """
    Run a single pipeline stage as a Celery task.
    
    Args:
        config_dict: Configuration dictionary
        stage: Stage name to run
        agent_name: Specific agent name to use
        recon_agents: List of recon agents (for recon stage)
        protocol_filter: Protocol filter for scanning
        debug: Enable debug logging
        force_rescore: Force re-scoring of results
        host: Host/IP address for network topology discovery
        **kwargs: Additional stage-specific parameters
        
    Returns:
        Dict with execution results
    """
    try:
        # Import here to avoid circular imports
        from pgdn.core.config import Config
        from pgdn.core.logging import setup_logging
        from pgdn.core.database import create_tables
        from pgdn.utils.pipeline import create_orchestrator
        
        # Load configuration
        config = Config(config_overrides=config_dict)
        
        # Setup environment
        setup_logging(config.logging)
        create_tables(config.database)
        
        # Create orchestrator
        orchestrator = create_orchestrator(config)
        
        logger.info(f"Running single stage: {stage}")
        logger.info(f"Task parameters - agent_name: {agent_name}, host: {host}, force_rescore: {force_rescore}, debug: {debug}")
        
        # Run the appropriate stage
        if stage == 'recon':
            results = orchestrator.run_single_stage(stage, agent_names=recon_agents)
            
        elif stage == 'scan':
            # For scanning, use the new modular scanner to support protocol filtering
            from pgdn.scanner import Scanner
            scanner = Scanner(config, protocol_filter=protocol_filter, debug=debug)
            scan_result = scanner.scan_nodes_from_database()
            results = scan_result.get('results', []) if scan_result.get('success') else []
            
        elif stage == 'process':
            results = orchestrator.run_single_stage(stage, agent_name)
            
        elif stage == 'score':
            results = orchestrator.run_scoring_stage(agent_name or 'ScoringAgent', force_rescore=force_rescore)
            
        elif stage == 'publish':
            results = orchestrator.run_single_stage(stage, agent_name)
            
        elif stage == 'report':
            report_options = kwargs.get('report_options', {
                'format': 'summary',
                'auto_save': False
            })
            results = orchestrator.run_report_stage(agent_name or 'ReportAgent', report_options)
            
        elif stage == 'signature':
            results = orchestrator.run_signature_stage(agent_name or 'ProtocolSignatureGeneratorAgent')
            
        elif stage == 'discovery':
            logger.info(f"Discovery stage - host parameter: {host}")
            if not host:
                raise ValueError("Discovery stage requires host parameter")
            logger.info(f"Calling orchestrator.run_discovery_stage with agent: {agent_name or 'DiscoveryAgent'}, host: {host}, force: {kwargs.get('force', False)}")
            results = orchestrator.run_discovery_stage(agent_name or 'DiscoveryAgent', host=host, force=kwargs.get('force', False))
            logger.info(f"Discovery stage results: {len(results) if results else 0} items returned")
            
        else:
            raise ValueError(f"Unknown stage: {stage}")
        
        logger.info(f"Single stage '{stage}' completed successfully")
        return {
            'success': True,
            'stage': stage,
            'results': results,
            'task_id': self.request.id
        }
        
    except Exception as e:
        logger.error(f"Single stage task '{stage}' failed: {e}")
        logger.error(traceback.format_exc())
        self.retry(countdown=60, max_retries=3)


@app.task(bind=True, name='tasks.pipeline.scan_target')
def scan_target_task(self, config_dict: Dict[str, Any], target: str, debug: bool = False):
    """
    Scan a specific target as a Celery task.
    
    Args:
        config_dict: Configuration dictionary
        target: IP address or hostname to scan
        debug: Enable debug logging
        
    Returns:
        Dict with scan results
    """
    try:
        # Import here to avoid circular imports
        from pgdn.core.config import Config
        from pgdn.core.logging import setup_logging
        from pgdn.core.database import create_tables
        
        # Load configuration
        config = Config(config_overrides=config_dict)
        
        # Setup environment
        setup_logging(config.logging)
        create_tables(config.database)
        
        from pgdn.scanner import Scanner
        import socket
        
        logger.info(f"Scanning target: {target}")
        
        # Use the new modular scanner for target scanning
        scanner = Scanner(config, debug=debug)
        
        # Perform scan using the target scanning method (requires org_id)
        # For pipeline tasks, we'll use a default org_id or make it configurable
        org_id = config_dict.get('org_id') or 'pipeline-default'
        scan_result = scanner.scan_target(target, org_id=org_id)
        
        logger.info(f"Target scan completed for {target}")
        return {
            'success': scan_result.get('success', False) if scan_result else False,
            'target': target,
            'results': [scan_result] if scan_result else [],
            'task_id': self.request.id
        }
        
    except Exception as e:
        logger.error(f"Target scan task failed for {target}: {e}")
        logger.error(traceback.format_exc())
        self.retry(countdown=60, max_retries=3)
