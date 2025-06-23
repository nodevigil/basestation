"""
Report generation task definitions for Celery.
"""

from celery.utils.log import get_task_logger
from typing import Dict, Any, Optional, List
import traceback

logger = get_task_logger(__name__)

# Import the celery app
from celery_app import app

@app.task(bind=True, name='tasks.report.generate_report')
def generate_report_task(
    self, 
    config_dict: Dict[str, Any], 
    report_options: Dict[str, Any],
    agent_name: Optional[str] = None
):
    """
    Generate security analysis report as a Celery task.
    
    Args:
        config_dict: Configuration dictionary
        report_options: Report generation options
        agent_name: Specific report agent name to use
        
    Returns:
        Dict with report generation results
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
        
        logger.info("Generating security analysis report")
        
        # Create orchestrator and run report generation
        orchestrator = create_orchestrator(config)
        report_results = orchestrator.run_report_stage(
            agent_name or 'ReportAgent', 
            report_options
        )
        
        logger.info("Report generation completed successfully")
        return {
            'success': True,
            'report_options': report_options,
            'results': report_results,
            'task_id': self.request.id
        }
        
    except Exception as e:
        logger.error(f"Report generation task failed: {e}")
        logger.error(traceback.format_exc())
        self.retry(countdown=60, max_retries=3)


@app.task(bind=True, name='tasks.report.batch_generate_reports')
def batch_generate_reports_task(
    self, 
    config_dict: Dict[str, Any], 
    scan_ids: List[int],
    report_options: Dict[str, Any],
    agent_name: Optional[str] = None
):
    """
    Generate reports for a batch of scan IDs as a Celery task.
    
    Args:
        config_dict: Configuration dictionary
        scan_ids: List of scan IDs to generate reports for
        report_options: Report generation options
        agent_name: Specific report agent name to use
        
    Returns:
        Dict with batch report generation results
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
        
        logger.info(f"Generating reports for {len(scan_ids)} scans")
        
        # Create orchestrator
        orchestrator = create_orchestrator(config)
        
        # Generate reports for each scan ID
        all_results = []
        for scan_id in scan_ids:
            scan_report_options = {**report_options, 'scan_id': scan_id}
            result = orchestrator.run_report_stage(
                agent_name or 'ReportAgent', 
                scan_report_options
            )
            all_results.append({
                'scan_id': scan_id,
                'result': result
            })
        
        logger.info(f"Batch report generation completed for {len(scan_ids)} scans")
        return {
            'success': True,
            'scan_count': len(scan_ids),
            'scan_ids': scan_ids,
            'results': all_results,
            'task_id': self.request.id
        }
        
    except Exception as e:
        logger.error(f"Batch report generation task failed: {e}")
        logger.error(traceback.format_exc())
        self.retry(countdown=60, max_retries=3)
