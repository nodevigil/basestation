"""
Processing task definitions for Celery.
"""

from celery.utils.log import get_task_logger
from typing import Dict, Any, List, Optional
import traceback

logger = get_task_logger(__name__)

# Import the celery app
from celery_app import app

@app.task(bind=True, name='tasks.process.batch_process_results')
def batch_process_results_task(
    self, 
    config_dict: Dict[str, Any], 
    results_batch: List[Dict[str, Any]], 
    agent_name: Optional[str] = None
):
    """
    Process a batch of scan results as a Celery task.
    
    Args:
        config_dict: Configuration dictionary
        results_batch: List of scan result dictionaries to process
        agent_name: Specific processing agent name to use
        
    Returns:
        Dict with processing results
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
        
        from pgdn.utils.pipeline import create_orchestrator
        
        logger.info(f"Batch processing {len(results_batch)} results")
        
        # Create orchestrator and run processing
        orchestrator = create_orchestrator(config)
        processed_results = orchestrator.run_single_stage('process', agent_name)
        
        logger.info(f"Batch processing completed for {len(results_batch)} results")
        return {
            'success': True,
            'batch_size': len(results_batch),
            'results': processed_results,
            'task_id': self.request.id
        }
        
    except Exception as e:
        logger.error(f"Batch processing task failed: {e}")
        logger.error(traceback.format_exc())
        self.retry(countdown=60, max_retries=3)


@app.task(bind=True, name='tasks.process.score_results')
def score_results_task(
    self, 
    config_dict: Dict[str, Any], 
    agent_name: Optional[str] = None,
    force_rescore: bool = False
):
    """
    Score scan results as a Celery task.
    
    Args:
        config_dict: Configuration dictionary
        agent_name: Specific scoring agent name to use
        force_rescore: Force re-scoring of results that already have scores
        
    Returns:
        Dict with scoring results
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
        
        from pgdn.utils.pipeline import create_orchestrator
        
        logger.info("Running scoring stage")
        
        # Create orchestrator and run scoring
        orchestrator = create_orchestrator(config)
        scored_results = orchestrator.run_scoring_stage(
            agent_name or 'ScoringAgent', 
            force_rescore=force_rescore
        )
        
        logger.info(f"Scoring completed for {len(scored_results)} results")
        return {
            'success': True,
            'results_count': len(scored_results),
            'results': scored_results,
            'task_id': self.request.id
        }
        
    except Exception as e:
        logger.error(f"Scoring task failed: {e}")
        logger.error(traceback.format_exc())
        self.retry(countdown=60, max_retries=3)
