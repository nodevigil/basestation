"""
Queue management utilities for Celery task processing.
"""

from typing import Dict, Any, List, Optional, Union
import json
import uuid
from datetime import datetime

from celery import group, chain, chord
from celery.result import AsyncResult, GroupResult
from pgdn.core.config import Config
from pgdn.core.logging import setup_logging

import logging
logger = logging.getLogger(__name__)


class QueueManager:
    """
    Manages Celery task queues and batch processing for the DePIN scanner.
    """
    
    def __init__(self, config: Config):
        """
        Initialize the queue manager.
        
        Args:
            config: Configuration instance
        """
        self.config = config
        self.config_dict = config.to_dict()
        
        # Import tasks after config is set
        from pgdn.tasks.pipeline_tasks import (
            run_full_pipeline_task, 
            run_single_stage_task, 
            scan_target_task
        )
        from pgdn.tasks.scan_tasks import batch_scan_nodes_task, scan_single_node_task, parallel_target_scans_task
        from pgdn.tasks.process_tasks import batch_process_results_task, score_results_task
        from pgdn.tasks.report_tasks import generate_report_task, batch_generate_reports_task
        
        # Store task references
        self.tasks = {
            'run_full_pipeline': run_full_pipeline_task,
            'run_single_stage': run_single_stage_task,
            'scan_target': scan_target_task,
            'batch_scan_nodes': batch_scan_nodes_task,
            'scan_single_node': scan_single_node_task,
            'parallel_target_scans': parallel_target_scans_task,
            'batch_process_results': batch_process_results_task,
            'score_results': score_results_task,
            'generate_report': generate_report_task,
            'batch_generate_reports': batch_generate_reports_task,
        }
    
    def queue_full_pipeline(self, recon_agents: Optional[List[str]] = None) -> str:
        """
        Queue a full pipeline execution.
        
        Args:
            recon_agents: Optional list of specific recon agents to run
            
        Returns:
            Task ID
        """
        task = self.tasks['run_full_pipeline'].delay(self.config_dict, recon_agents)
        logger.info(f"Queued full pipeline task: {task.id}")
        return task.id
    
    def queue_single_stage(
        self, 
        stage: str, 
        agent_name: Optional[str] = None,
        recon_agents: Optional[List[str]] = None,
        protocol_filter: Optional[str] = None,
        debug: bool = False,
        force_rescore: bool = False,
        host: Optional[str] = None,
        **kwargs
    ) -> str:
        """
        Queue a single stage execution.
        
        Args:
            stage: Stage name to run
            agent_name: Specific agent name to use
            recon_agents: List of recon agents (for recon stage)
            protocol_filter: Protocol filter for scanning
            debug: Enable debug logging
            force_rescore: Force re-scoring of results
            host: Host/IP address for network topology discovery
            **kwargs: Additional stage-specific parameters
            
        Returns:
            Task ID
        """
        task = self.tasks['run_single_stage'].delay(
            self.config_dict, 
            stage, 
            agent_name,
            recon_agents,
            protocol_filter,
            debug,
            force_rescore,
            host,
            **kwargs
        )
        logger.info(f"Queued single stage '{stage}' task: {task.id}")
        return task.id
    
    def queue_target_scan(self, target: str, debug: bool = False, org_id: Optional[str] = None) -> str:
        """
        Queue a target scan.
        
        Args:
            target: IP address or hostname to scan
            debug: Enable debug logging
            org_id: Optional organization ID to filter agentic jobs
            
        Returns:
            Task ID
        """
        task = self.tasks['scan_target'].delay(self.config_dict, target, debug, org_id)
        logger.info(f"Queued target scan for {target}: {task.id}")
        return task.id
    
    def queue_batch_scans(
        self, 
        nodes: List[Dict[str, Any]], 
        batch_size: int = 10,
        protocol_filter: Optional[str] = None,
        debug: bool = False
    ) -> List[str]:
        """
        Queue batch scanning of nodes.
        
        Args:
            nodes: List of node dictionaries to scan
            batch_size: Number of nodes per batch
            protocol_filter: Protocol filter for scanning
            debug: Enable debug logging
            
        Returns:
            List of task IDs
        """
        # Split nodes into batches
        batches = [nodes[i:i + batch_size] for i in range(0, len(nodes), batch_size)]
        
        task_ids = []
        for batch in batches:
            task = self.tasks['batch_scan_nodes'].delay(
                self.config_dict, 
                batch, 
                protocol_filter, 
                debug
            )
            task_ids.append(task.id)
            logger.info(f"Queued batch scan task for {len(batch)} nodes: {task.id}")
        
        logger.info(f"Queued {len(task_ids)} batch scan tasks for {len(nodes)} total nodes")
        return task_ids
    
    def queue_batch_reports(
        self, 
        scan_ids: List[int], 
        report_options: Dict[str, Any],
        agent_name: Optional[str] = None
    ) -> str:
        """
        Queue batch report generation.
        
        Args:
            scan_ids: List of scan IDs to generate reports for
            report_options: Report generation options
            agent_name: Specific report agent name to use
            
        Returns:
            Task ID
        """
        task = self.tasks['batch_generate_reports'].delay(
            self.config_dict, 
            scan_ids, 
            report_options, 
            agent_name
        )
        logger.info(f"Queued batch report generation for {len(scan_ids)} scans: {task.id}")
        return task.id
    
    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """
        Get the status of a task.
        
        Args:
            task_id: Task ID to check
            
        Returns:
            Dictionary with task status information
        """
        result = AsyncResult(task_id)
        
        status_info = {
            'task_id': task_id,
            'status': result.status,
            'ready': result.ready(),
            'successful': result.successful() if result.ready() else None,
            'failed': result.failed() if result.ready() else None,
            'result': None,
            'error': None,
            'traceback': None
        }
        
        if result.ready():
            if result.successful():
                status_info['result'] = result.result
            elif result.failed():
                status_info['error'] = str(result.info)
                status_info['traceback'] = result.traceback
        
        return status_info
    
    def get_batch_status(self, task_ids: List[str]) -> Dict[str, Any]:
        """
        Get the status of multiple tasks.
        
        Args:
            task_ids: List of task IDs to check
            
        Returns:
            Dictionary with batch status information
        """
        statuses = {}
        for task_id in task_ids:
            statuses[task_id] = self.get_task_status(task_id)
        
        # Calculate summary statistics
        total_tasks = len(task_ids)
        completed_tasks = sum(1 for status in statuses.values() if status['ready'])
        successful_tasks = sum(1 for status in statuses.values() if status['successful'])
        failed_tasks = sum(1 for status in statuses.values() if status['failed'])
        
        return {
            'total_tasks': total_tasks,
            'completed_tasks': completed_tasks,
            'successful_tasks': successful_tasks,
            'failed_tasks': failed_tasks,
            'pending_tasks': total_tasks - completed_tasks,
            'completion_percentage': (completed_tasks / total_tasks) * 100 if total_tasks > 0 else 0,
            'task_statuses': statuses
        }
    
    def wait_for_tasks(self, task_ids: Union[str, List[str]], timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        Wait for tasks to complete.
        
        Args:
            task_ids: Single task ID or list of task IDs
            timeout: Maximum time to wait in seconds
            
        Returns:
            Dictionary with final results
        """
        if isinstance(task_ids, str):
            task_ids = [task_ids]
        
        results = {}
        for task_id in task_ids:
            result = AsyncResult(task_id)
            try:
                results[task_id] = result.get(timeout=timeout)
            except Exception as e:
                results[task_id] = {'error': str(e)}
        
        return results
    
    def cancel_task(self, task_id: str) -> bool:
        """
        Cancel a task.
        
        Args:
            task_id: Task ID to cancel
            
        Returns:
            True if cancellation was successful
        """
        try:
            result = AsyncResult(task_id)
            result.revoke(terminate=True)
            logger.info(f"Cancelled task: {task_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to cancel task {task_id}: {e}")
            return False
    
    def cancel_batch(self, task_ids: List[str]) -> Dict[str, bool]:
        """
        Cancel multiple tasks.
        
        Args:
            task_ids: List of task IDs to cancel
            
        Returns:
            Dictionary mapping task IDs to cancellation success status
        """
        results = {}
        for task_id in task_ids:
            results[task_id] = self.cancel_task(task_id)
        
        return results
    
    def queue_parallel_scans(
        self, 
        targets: List[str], 
        max_parallel: int = 5,
        protocol_filter: Optional[str] = None,
        debug: bool = False
    ) -> Dict[str, List[str]]:
        """
        Queue multiple scan targets in parallel.
        
        Args:
            targets: List of IP addresses or hostnames to scan
            max_parallel: Maximum number of parallel scan tasks
            protocol_filter: Protocol filter for scanning
            debug: Enable debug logging
            
        Returns:
            Dictionary with task information
        """
        if not targets:
            return {'task_ids': [], 'total_targets': 0}
        
        # Limit parallel tasks to prevent overwhelming the system
        max_parallel = min(max_parallel, len(targets), 20)  # Cap at 20 for safety
        
        task_ids = []
        
        # Queue individual target scans for maximum parallelism
        for target in targets:
            task_id = self.queue_target_scan(target, debug)
            task_ids.append(task_id)
        
        logger.info(f"Queued {len(task_ids)} parallel scan tasks for {len(targets)} targets")
        
        return {
            'task_ids': task_ids,
            'total_targets': len(targets),
            'max_parallel': max_parallel,
            'protocol_filter': protocol_filter
        }
    
    def queue_parallel_stages(
        self, 
        stages: List[str], 
        stage_configs: Optional[Dict[str, Dict]] = None
    ) -> Dict[str, str]:
        """
        Queue multiple stages to run in parallel (for independent stages).
        
        Args:
            stages: List of stage names to run in parallel
            stage_configs: Optional per-stage configuration overrides
            
        Returns:
            Dictionary mapping stage names to task IDs
        """
        stage_task_ids = {}
        
        for stage in stages:
            # Get stage-specific config if provided
            stage_config = (stage_configs or {}).get(stage, {})
            
            task_id = self.queue_single_stage(
                stage,
                stage_config.get('agent_name'),
                stage_config.get('recon_agents'),
                stage_config.get('protocol_filter'),
                stage_config.get('debug', False),
                stage_config.get('force_rescore', False),
                stage_config.get('host'),
                **stage_config.get('extra_args', {})
            )
            
            stage_task_ids[stage] = task_id
            logger.info(f"Queued stage '{stage}' with task ID: {task_id}")
        
        return stage_task_ids
    
    def queue_parallel_pipelines(
        self, 
        pipeline_configs: List[Dict[str, Any]]
    ) -> List[str]:
        """
        Queue multiple full pipelines to run in parallel.
        
        Args:
            pipeline_configs: List of pipeline configuration dictionaries
            
        Returns:
            List of task IDs
        """
        task_ids = []
        
        for i, config in enumerate(pipeline_configs):
            # Override config for this pipeline
            pipeline_config_dict = {**self.config_dict}
            if 'config_overrides' in config:
                pipeline_config_dict.update(config['config_overrides'])
            
            task = self.tasks['run_full_pipeline'].delay(
                pipeline_config_dict, 
                config.get('recon_agents')
            )
            
            task_ids.append(task.id)
            logger.info(f"Queued pipeline {i+1}/{len(pipeline_configs)}: {task.id}")
        
        return task_ids
    
    def queue_parallel_target_scans(
        self, 
        targets: List[str], 
        protocol_filter: Optional[str] = None,
        debug: bool = False,
        max_concurrent: int = 3
    ) -> str:
        """
        Queue a single task that scans multiple targets in parallel with controlled concurrency.
        
        Args:
            targets: List of IP addresses or hostnames to scan
            protocol_filter: Protocol filter for scanning
            debug: Enable debug logging
            max_concurrent: Maximum concurrent scans within the task
            
        Returns:
            Task ID
        """
        task = self.tasks['parallel_target_scans'].delay(
            self.config_dict, 
            targets, 
            protocol_filter, 
            debug,
            max_concurrent
        )
        
        logger.info(f"Queued parallel target scans task for {len(targets)} targets: {task.id}")
        return task.id


def create_queue_manager(config: Config) -> QueueManager:
    """
    Create a queue manager instance.
    
    Args:
        config: Configuration instance
        
    Returns:
        QueueManager instance
    """
    return QueueManager(config)
