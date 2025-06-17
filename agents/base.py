"""
Base agent class providing common functionality for all pipeline agents.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import logging
from datetime import datetime
from core.config import Config


class BaseAgent(ABC):
    """
    Abstract base class for all pipeline agents.
    
    Provides common functionality including logging, configuration access,
    and standardized agent lifecycle methods.
    """
    
    def __init__(self, config: Optional[Config] = None, agent_name: Optional[str] = None):
        """
        Initialize the base agent.
        
        Args:
            config: Configuration instance. If None, will create default config.
            agent_name: Name of the agent for logging. If None, uses class name.
        """
        self.config = config or Config()
        self.agent_name = agent_name or self.__class__.__name__
        self.logger = self._setup_logger()
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        
    def _setup_logger(self) -> logging.Logger:
        """Set up logger for this agent."""
        logger = logging.getLogger(f"agents.{self.agent_name}")
        return logger
    
    @abstractmethod
    def run(self, *args, **kwargs) -> Any:
        """
        Main execution method for the agent.
        
        This method must be implemented by all concrete agent classes.
        
        Returns:
            Results from agent execution
        """
        pass
    
    def pre_run_hook(self) -> None:
        """Hook called before run() method. Override for setup logic."""
        self.start_time = datetime.utcnow()
        self.logger.info(f"🚀 Starting {self.agent_name}")
    
    def post_run_hook(self, result: Any) -> None:
        """Hook called after run() method. Override for cleanup logic."""
        self.end_time = datetime.utcnow()
        duration = (self.end_time - self.start_time).total_seconds() if self.start_time else 0
        self.logger.info(f"✅ Completed {self.agent_name} in {duration:.2f}s")
    
    def execute(self, *args, **kwargs) -> Any:
        """
        Execute the agent with lifecycle hooks.
        
        This method wraps the run() method with pre/post hooks for
        consistent agent behavior.
        
        Returns:
            Results from agent execution
        """
        try:
            self.pre_run_hook()
            result = self.run(*args, **kwargs)
            self.post_run_hook(result)
            return result
        except Exception as e:
            self.logger.error(f"❌ Error in {self.agent_name}: {e}")
            raise
    
    def get_execution_stats(self) -> Dict[str, Any]:
        """Get execution statistics for this agent."""
        return {
            "agent_name": self.agent_name,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": (
                (self.end_time - self.start_time).total_seconds() 
                if self.start_time and self.end_time else None
            )
        }


class ReconAgent(BaseAgent):
    """Base class for reconnaissance agents that discover network nodes."""
    
    @abstractmethod
    def discover_nodes(self) -> List[Dict[str, Any]]:
        """
        Discover network nodes for a specific protocol.
        
        Returns:
            List of discovered node information dictionaries
        """
        pass
    
    def run(self, *args, **kwargs) -> List[Dict[str, Any]]:
        """Execute node discovery."""
        return self.discover_nodes()


class ScanAgent(BaseAgent):
    """Base class for scanning agents that perform security scans."""
    
    @abstractmethod
    def scan_nodes(self, nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Perform security scans on network nodes.
        
        Args:
            nodes: List of nodes to scan
            
        Returns:
            List of scan results
        """
        pass
    
    def run(self, nodes: List[Dict[str, Any]], *args, **kwargs) -> List[Dict[str, Any]]:
        """Execute node scanning."""
        return self.scan_nodes(nodes)


class ProcessAgent(BaseAgent):
    """Base class for processing agents that analyze and enrich scan data."""
    
    @abstractmethod
    def process_results(self, scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process and enrich scan results.
        
        Args:
            scan_results: Raw scan results
            
        Returns:
            Processed and enriched results
        """
        pass
    
    def run(self, scan_results: List[Dict[str, Any]], *args, **kwargs) -> List[Dict[str, Any]]:
        """Execute result processing."""
        return self.process_results(scan_results)


class PublishAgent(BaseAgent):
    """Base class for publishing agents that output final results."""
    
    @abstractmethod
    def publish_results(self, processed_results: List[Dict[str, Any]]) -> bool:
        """
        Publish final results to destination.
        
        Args:
            processed_results: Processed scan results
            
        Returns:
            True if publishing succeeded, False otherwise
        """
        pass
    
    def run(self, processed_results: List[Dict[str, Any]], *args, **kwargs) -> bool:
        """Execute result publishing."""
        return self.publish_results(processed_results)
