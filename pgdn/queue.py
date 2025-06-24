"""
Queue Management Module

Provides background task management using Celery.
This module abstracts queue operations from CLI concerns.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime

from pgdn.core.config import Config


class QueueManager:
    """
    Manager for background task processing using Celery.
    
    This class provides a clean Python API for queueing tasks
    and managing background processing, independent of CLI concerns.
    """
    
    def __init__(self, config: Config):
        """
        Initialize the queue manager.
        
        Args:
            config: Configuration instance
        """
        self.config = config
        self._queue_manager = None
    
    @property
    def queue_manager(self):
        """Lazy-load the queue manager."""
        if self._queue_manager is None:
            from pgdn.utils.queue_manager import create_queue_manager
            self._queue_manager = create_queue_manager(self.config)
        return self._queue_manager
    
    def queue_full_pipeline(self, recon_agents: Optional[List[str]] = None, org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Queue a full pipeline for background processing.
        
        Args:
            recon_agents: Optional list of recon agents to use
            org_id: Optional organization ID to filter agentic jobs
            
        Returns:
            dict: Queue operation results including task ID
        """
        try:
            task_id = self.queue_manager.queue_full_pipeline(recon_agents, org_id=org_id)
            
            return {
                "success": True,
                "operation": "queue_full_pipeline",
                "task_id": task_id,
                "recon_agents": recon_agents,
                "timestamp": datetime.now().isoformat()
            }
            
        except ImportError:
            return {
                "success": False,
                "error": "Celery not available. Install with: pip install celery redis",
                "suggestion": "Also ensure Redis server is running and Celery worker is started.",
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to queue full pipeline: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
    
    def queue_single_stage(self,
                          stage: str,
                          agent_name: Optional[str] = None,
                          recon_agents: Optional[List[str]] = None,
                          protocol_filter: Optional[str] = None,
                          debug: bool = False,
                          force_rescore: bool = False,
                          host: Optional[str] = None,
                          report_options: Optional[Dict[str, Any]] = None,
                          force: bool = False,
                          org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Queue a single stage for background processing.
        
        Args:
            stage: Stage name to queue
            agent_name: Optional specific agent name
            recon_agents: Optional list of recon agents
            protocol_filter: Optional protocol filter
            debug: Enable debug logging
            force_rescore: Force re-scoring
            host: Host for discovery stage
            report_options: Options for report stage
            force: Force operation
            org_id: Optional organization ID to filter agentic jobs
            
        Returns:
            dict: Queue operation results including task ID
        """
        try:
            if stage == 'report' and report_options:
                task_id = self.queue_manager.queue_single_stage(
                    stage, agent_name, recon_agents, protocol_filter,
                    debug, force_rescore, host, report_options=report_options,
                    force=force, org_id=org_id
                )
            else:
                task_id = self.queue_manager.queue_single_stage(
                    stage, agent_name, recon_agents, protocol_filter,
                    debug, force_rescore, host, force=force, org_id=org_id
                )
            
            return {
                "success": True,
                "operation": "queue_single_stage",
                "task_id": task_id,
                "stage": stage,
                "agent_name": agent_name,
                "protocol_filter": protocol_filter,
                "timestamp": datetime.now().isoformat()
            }
            
        except ImportError:
            return {
                "success": False,
                "error": "Celery not available. Install with: pip install celery redis",
                "suggestion": "Also ensure Redis server is running and Celery worker is started.",
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to queue single stage: {str(e)}",
                "stage": stage,
                "timestamp": datetime.now().isoformat()
            }
    
    def queue_target_scan(self, target: str, debug: bool = False, org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Queue a target scan for background processing.
        
        Args:
            target: Target to scan
            debug: Enable debug logging
            org_id: Optional organization ID to filter agentic jobs
            
        Returns:
            dict: Queue operation results including task ID
        """
        try:
            task_id = self.queue_manager.queue_target_scan(target, debug, org_id=org_id)
            
            return {
                "success": True,
                "operation": "queue_target_scan",
                "task_id": task_id,
                "target": target,
                "debug": debug,
                "timestamp": datetime.now().isoformat()
            }
            
        except ImportError:
            return {
                "success": False,
                "error": "Celery not available. Install with: pip install celery redis",
                "suggestion": "Also ensure Redis server is running and Celery worker is started.",
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to queue target scan: {str(e)}",
                "target": target,
                "timestamp": datetime.now().isoformat()
            }
    
    def queue_parallel_scans(self,
                           targets: List[str],
                           max_parallel: int = 5,
                           protocol_filter: Optional[str] = None,
                           debug: bool = False) -> Dict[str, Any]:
        """
        Queue parallel scans for multiple targets.
        
        Args:
            targets: List of targets to scan
            max_parallel: Maximum parallel scans
            protocol_filter: Optional protocol filter
            debug: Enable debug logging
            
        Returns:
            dict: Queue operation results including task IDs
        """
        try:
            result = self.queue_manager.queue_parallel_scans(
                targets, max_parallel, protocol_filter, debug
            )
            
            return {
                "success": True,
                "operation": "queue_parallel_scans",
                "task_ids": result['task_ids'],
                "targets": targets,
                "max_parallel": max_parallel,
                "protocol_filter": protocol_filter,
                "timestamp": datetime.now().isoformat()
            }
            
        except ImportError:
            return {
                "success": False,
                "error": "Celery not available. Install with: pip install celery redis",
                "suggestion": "Also ensure Redis server is running and Celery worker is started.",
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to queue parallel scans: {str(e)}",
                "targets": targets,
                "timestamp": datetime.now().isoformat()
            }
    
    def queue_parallel_stages(self,
                            stages: List[str],
                            stage_configs: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Queue multiple stages for parallel execution.
        
        Args:
            stages: List of stages to run in parallel
            stage_configs: Configuration for each stage
            
        Returns:
            dict: Queue operation results including task IDs
        """
        try:
            stage_task_ids = self.queue_manager.queue_parallel_stages(stages, stage_configs)
            
            return {
                "success": True,
                "operation": "queue_parallel_stages",
                "stages": stages,
                "stage_task_ids": stage_task_ids,
                "timestamp": datetime.now().isoformat()
            }
            
        except ImportError:
            return {
                "success": False,
                "error": "Celery not available. Install with: pip install celery redis",
                "suggestion": "Also ensure Redis server is running and Celery worker is started.",
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to queue parallel stages: {str(e)}",
                "stages": stages,
                "timestamp": datetime.now().isoformat()
            }
    
    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """
        Get the status of a queued task.
        
        Args:
            task_id: Task ID to check
            
        Returns:
            dict: Task status information
        """
        try:
            status = self.queue_manager.get_task_status(task_id)
            
            return {
                "success": True,
                "task_id": task_id,
                "status": status['status'],
                "ready": status['ready'],
                "successful": status['successful'],
                "failed": status['failed'],
                "result": status.get('result'),
                "error": status.get('error'),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to get task status: {str(e)}",
                "task_id": task_id,
                "timestamp": datetime.now().isoformat()
            }
    
    def cancel_task(self, task_id: str) -> Dict[str, Any]:
        """
        Cancel a queued task.
        
        Args:
            task_id: Task ID to cancel
            
        Returns:
            dict: Cancellation results
        """
        try:
            success = self.queue_manager.cancel_task(task_id)
            
            return {
                "success": success,
                "task_id": task_id,
                "message": f"Task {task_id} {'has been cancelled' if success else 'could not be cancelled'}",
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to cancel task: {str(e)}",
                "task_id": task_id,
                "timestamp": datetime.now().isoformat()
            }
    
    def wait_for_tasks(self, task_ids, timeout: int = 3600) -> Dict[str, Any]:
        """
        Wait for tasks to complete.
        
        Args:
            task_ids: Task ID or list of task IDs to wait for
            timeout: Timeout in seconds
            
        Returns:
            dict: Task completion results
        """
        try:
            if isinstance(task_ids, str):
                task_ids = [task_ids]
            
            results = self.queue_manager.wait_for_tasks(task_ids, timeout=timeout)
            
            successful = sum(1 for r in results.values() 
                           if not isinstance(r, dict) or 'error' not in r)
            
            return {
                "success": True,
                "task_ids": task_ids,
                "results": results,
                "successful": successful,
                "total": len(task_ids),
                "timeout": timeout,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to wait for tasks: {str(e)}",
                "task_ids": task_ids,
                "timeout": timeout,
                "timestamp": datetime.now().isoformat()
            }
