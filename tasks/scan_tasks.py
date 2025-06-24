"""
Scan-specific task definitions for Celery.
"""

from celery.utils.log import get_task_logger
from typing import Dict, Any, List, Optional
import traceback

# Add required imports for the updated Scanner
from pgdn.core.config import Config
from pgdn.core.logging import setup_logging
from pgdn.core.database import create_tables

logger = get_task_logger(__name__)

# Import the celery app
from celery_app import app

@app.task(bind=True, name='tasks.scan.batch_scan_nodes')
def batch_scan_nodes_task(
    self, 
    config_dict: Dict[str, Any], 
    node_batch: List[Dict[str, Any]], 
    protocol_filter: Optional[str] = None,
    debug: bool = False
):
    """
    Scan a batch of nodes as a Celery task.
    
    Args:
        config_dict: Configuration dictionary
        node_batch: List of node dictionaries to scan
        protocol_filter: Protocol filter for scanning
        debug: Enable debug logging
        
    Returns:
        Dict with scan results
    """
    try:
        # Load configuration
        config = Config(config_overrides=config_dict)
        
        # Setup environment
        setup_logging(config.logging)
        create_tables(config.database)
        
        from pgdn.scanner import Scanner
        
        logger.info(f"Batch scanning {len(node_batch)} nodes")
        
        # Initialize scanner with new modular system
        scanner = Scanner(config, protocol_filter=protocol_filter, debug=debug)
        
        # Run scans for the batch using the database scan method
        scan_results = scanner.scan_nodes_from_database()
        
        logger.info(f"Batch scan completed for {len(node_batch)} nodes")
        return {
            'success': True,
            'batch_size': len(node_batch),
            'results': scan_results,
            'task_id': self.request.id
        }
        
    except Exception as e:
        logger.error(f"Batch scan task failed: {e}")
        logger.error(traceback.format_exc())
        self.retry(countdown=60, max_retries=3)


@app.task(bind=True, name='tasks.scan.scan_single_node')
def scan_single_node_task(
    self, 
    config_dict: Dict[str, Any], 
    node_data: Dict[str, Any], 
    protocol_filter: Optional[str] = None,
    debug: bool = False
):
    """
    Scan a single node as a Celery task.
    
    Args:
        config_dict: Configuration dictionary
        node_data: Node dictionary to scan
        protocol_filter: Protocol filter for scanning
        debug: Enable debug logging
        
    Returns:
        Dict with scan results
    """
    try:
        # Load configuration
        config = Config(config_overrides=config_dict)
        
        # Setup environment
        setup_logging(config.logging)
        create_tables(config.database)
        
        from pgdn.scanner import Scanner
        
        logger.info(f"Scanning single node: {node_data.get('address', 'unknown')}")
        
        # Initialize scanner with new modular system
        scanner = Scanner(config, protocol_filter=protocol_filter, debug=debug)
        
        # Run scan for the single node
        target_address = node_data.get('address')
        if target_address:
            scan_result = scanner.scan_target(target_address)
            scan_results = [scan_result] if scan_result else []
        else:
            scan_results = []
        
        logger.info(f"Single node scan completed")
        return {
            'success': True,
            'node_address': node_data.get('address'),
            'results': scan_results[0] if scan_results else None,
            'task_id': self.request.id
        }
        
    except Exception as e:
        logger.error(f"Single node scan task failed: {e}")
        logger.error(traceback.format_exc())
        self.retry(countdown=60, max_retries=3)


@app.task(bind=True, name='tasks.scan.parallel_target_scans')
def parallel_target_scans_task(
    self, 
    config_dict: Dict[str, Any], 
    targets: List[str], 
    protocol_filter: Optional[str] = None,
    debug: bool = False,
    max_concurrent: int = 3
):
    """
    Scan multiple targets with controlled concurrency.
    
    Args:
        config_dict: Configuration dictionary
        targets: List of IP addresses or hostnames to scan
        protocol_filter: Protocol filter for scanning
        debug: Enable debug logging
        max_concurrent: Maximum concurrent scans within this task
        
    Returns:
        Dict with all scan results
    """
    try:
        import asyncio
        import concurrent.futures
        from threading import Semaphore
        
        # Load configuration
        config = Config(config_overrides=config_dict)
        
        # Setup environment
        setup_logging(config.logging)
        create_tables(config.database)
        
        from pgdn.scanner import Scanner
        
        logger.info(f"Parallel scanning {len(targets)} targets with max_concurrent={max_concurrent}")
        
        # Initialize scanner with new modular system
        scanner = Scanner(config, protocol_filter=protocol_filter, debug=debug)
        
        # Create semaphore to limit concurrent scans
        semaphore = Semaphore(max_concurrent)
        all_results = []
        
        def scan_single_target(target):
            """Scan a single target with semaphore control"""
            with semaphore:
                try:
                    logger.info(f"Starting scan for {target}")
                    
                    # Create mock node entry
                    import uuid
                    mock_node = {
                        'id': 0,
                        'uuid': str(uuid.uuid4()),  # Add UUID for scan results
                        'address': target,
                        'source': 'parallel_scan',
                        'name': f'Parallel scan of {target}'
                    }
                    
                    result = scanner.scan_target(target)
                    logger.info(f"Completed scan for {target}")
                    return {
                        'target': target,
                        'success': result.get('success', False) if result else False,
                        'result': result
                    }
                    
                except Exception as e:
                    logger.error(f"Failed to scan {target}: {e}")
                    return {
                        'target': target,
                        'success': False,
                        'error': str(e)
                    }
        
        # Use ThreadPoolExecutor for parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            future_to_target = {executor.submit(scan_single_target, target): target for target in targets}
            
            for future in concurrent.futures.as_completed(future_to_target):
                result = future.result()
                all_results.append(result)
        
        successful_scans = [r for r in all_results if r['success']]
        failed_scans = [r for r in all_results if not r['success']]
        
        logger.info(f"Parallel scanning completed: {len(successful_scans)} successful, {len(failed_scans)} failed")
        
        return {
            'success': True,
            'total_targets': len(targets),
            'successful_scans': len(successful_scans),
            'failed_scans': len(failed_scans),
            'results': all_results,
            'task_id': self.request.id
        }
        
    except Exception as e:
        logger.error(f"Parallel target scanning task failed: {e}")
        logger.error(traceback.format_exc())
        self.retry(countdown=60, max_retries=3)
