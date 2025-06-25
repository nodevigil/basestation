"""
Parallel Operations Module

Provides parallel processing coordination for scanning and pipeline operations.
This module abstracts parallel processing logic from CLI concerns.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime

from pgdn.core.config import Config
from .scanner import Scanner
from .queue import QueueManager


class ParallelOperations:
    """
    Coordinator for parallel scanning and pipeline operations.
    
    This class provides a clean Python API for coordinating parallel
    operations, independent of CLI concerns.
    """
    
    def __init__(self, config: Config):
        """
        Initialize the parallel operations coordinator.
        
        Args:
            config: Configuration instance
        """
        self.config = config
    
    def run_parallel_scans(self,
                          targets: List[str],
                          max_parallel: int = 5,
                          force_protocol: Optional[str] = None,
                          debug: bool = False,
                          use_queue: bool = False,
                          wait_for_completion: bool = False,
                          org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Run parallel scans for multiple targets.
        
        Args:
            targets: List of targets to scan
            max_parallel: Maximum number of parallel scans
            force_protocol: Optional protocol filter
            debug: Enable debug logging
            use_queue: Whether to use queue for background processing
            wait_for_completion: Whether to wait for queued tasks to complete
            org_id: Optional organization ID to filter agentic jobs
            
        Returns:
            dict: Parallel scan results
        """
        if not targets:
            return {
                "success": False,
                "error": "No targets provided for parallel scanning",
                "timestamp": datetime.now().isoformat()
            }
        
        try:
            if use_queue:
                # Use queue for parallel processing
                queue_manager = QueueManager(self.config)
                result = queue_manager.queue_parallel_scans(
                    targets, max_parallel, force_protocol, debug, org_id=org_id
                )
                
                if wait_for_completion and result.get('success'):
                    task_ids = result.get('task_ids', [])
                    if task_ids:
                        wait_result = queue_manager.wait_for_tasks(task_ids, timeout=3600)
                        result['wait_result'] = wait_result
                
                return result
            else:
                # Direct parallel execution
                scanner = Scanner(self.config, force_protocol=force_protocol, debug=debug)
                return scanner.scan_parallel_targets(targets, max_parallel, org_id=org_id)
                
        except Exception as e:
            return {
                "success": False,
                "error": f"Parallel scan operation failed: {str(e)}",
                "targets": targets,
                "max_parallel": max_parallel,
                "force_protocol": force_protocol,
                "timestamp": datetime.now().isoformat()
            }
    
    def run_parallel_stages(self,
                           stages: List[str],
                           stage_configs: Dict[str, Dict[str, Any]],
                           use_queue: bool = True,
                           wait_for_completion: bool = False) -> Dict[str, Any]:
        """
        Run multiple pipeline stages in parallel.
        
        Args:
            stages: List of stages to run in parallel
            stage_configs: Configuration for each stage
            use_queue: Whether to use queue (required for parallel stages)
            wait_for_completion: Whether to wait for completion
            
        Returns:
            dict: Parallel stage execution results
        """
        if not stages:
            return {
                "success": False,
                "error": "No stages provided for parallel execution",
                "timestamp": datetime.now().isoformat()
            }
        
        if not use_queue:
            return {
                "success": False,
                "error": "Parallel stages require queue mode",
                "suggestion": "Set use_queue=True for parallel stage execution",
                "timestamp": datetime.now().isoformat()
            }
        
        # Validate stage dependencies
        dependent_stages = {
            'scan': ['recon'],
            'process': ['scan'],
            'score': ['process'],
            'publish': ['score', 'process'],
            'report': ['scan', 'process']
        }
        
        warnings = []
        for stage in stages:
            deps = dependent_stages.get(stage, [])
            for dep in deps:
                if dep not in stages:
                    warnings.append(f"Stage '{stage}' depends on '{dep}' which is not included in parallel execution")
        
        try:
            queue_manager = QueueManager(self.config)
            result = queue_manager.queue_parallel_stages(stages, stage_configs)
            
            if warnings:
                result['warnings'] = warnings
            
            if wait_for_completion and result.get('success'):
                stage_task_ids = result.get('stage_task_ids', {})
                if stage_task_ids:
                    task_ids = list(stage_task_ids.values())
                    wait_result = queue_manager.wait_for_tasks(task_ids, timeout=3600)
                    result['wait_result'] = wait_result
            
            return result
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Parallel stage operation failed: {str(e)}",
                "stages": stages,
                "warnings": warnings,
                "timestamp": datetime.now().isoformat()
            }
    
    def coordinate_parallel_operation(self,
                                    targets: Optional[List[str]] = None,
                                    target_file: Optional[str] = None,
                                    stages: Optional[List[str]] = None,
                                    max_parallel: int = 5,
                                    force_protocol: Optional[str] = None,
                                    debug: bool = False,
                                    agent_name: Optional[str] = None,
                                    recon_agents: Optional[List[str]] = None,
                                    force_rescore: bool = False,
                                    host: Optional[str] = None,
                                    use_queue: bool = False,
                                    wait_for_completion: bool = False,
                                    org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Coordinate a complete parallel operation based on provided parameters.
        
        Args:
            targets: Direct list of targets
            target_file: File containing targets (alternative to direct list)
            stages: List of stages for parallel stage execution
            max_parallel: Maximum parallel operations
            force_protocol: Optional protocol filter
            debug: Enable debug logging
            agent_name: Specific agent name
            recon_agents: List of recon agents
            force_rescore: Force re-scoring
            host: Host for discovery stage
            use_queue: Whether to use queue
            wait_for_completion: Whether to wait for completion
            org_id: Optional organization ID to filter agentic jobs
            
        Returns:
            dict: Coordination results
        """
        try:
            # Determine operation type and targets
            if stages:
                # Parallel stages operation
                stage_configs = {}
                for stage in stages:
                    stage_configs[stage] = {
                        'agent_name': agent_name,
                        'recon_agents': recon_agents,
                        'force_protocol': force_protocol,
                        'debug': debug,
                        'force_rescore': force_rescore,
                        'host': host,
                        'org_id': org_id
                    }
                
                return self.run_parallel_stages(
                    stages, stage_configs, use_queue, wait_for_completion
                )
            
            elif targets or target_file:
                # Parallel scans operation
                if target_file:
                    from .scanner import load_targets_from_file
                    targets = load_targets_from_file(target_file)
                
                return self.run_parallel_scans(
                    targets, max_parallel, force_protocol, debug, use_queue, wait_for_completion, org_id=org_id
                )
            
            else:
                return {
                    "success": False,
                    "error": "No targets or stages specified for parallel operation",
                    "suggestion": "Provide either targets/target_file for parallel scans or stages for parallel stages",
                    "timestamp": datetime.now().isoformat()
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": f"Parallel operation coordination failed: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
