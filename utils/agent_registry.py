"""
Agent registry for dynamic agent discovery and management.
"""

import importlib
import os
from typing import Dict, List, Type, Optional, Any
from pathlib import Path

from agents.base import BaseAgent, ReconAgent, ScanAgent, ProcessAgent, PublishAgent
from core.logging import get_logger


class AgentRegistry:
    """
    Registry for managing and discovering agents dynamically.
    
    This registry allows for dynamic loading of agents from the agents directory,
    making it easy to add new protocol-specific agents without modifying core code.
    """
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self._recon_agents: Dict[str, Type[ReconAgent]] = {}
        self._scan_agents: Dict[str, Type[ScanAgent]] = {}
        self._process_agents: Dict[str, Type[ProcessAgent]] = {}
        self._publish_agents: Dict[str, Type[PublishAgent]] = {}
        
        # Auto-discover agents
        self._discover_agents()
    
    def _discover_agents(self) -> None:
        """Automatically discover and register agents from the agents directory."""
        try:
            agents_dir = Path(__file__).parent.parent / "agents"
            
            # Discover recon agents
            self._discover_agents_in_directory(
                agents_dir / "recon",
                self._recon_agents,
                ReconAgent
            )
            
            # Discover scan agents
            self._discover_agents_in_directory(
                agents_dir / "scan",
                self._scan_agents,
                ScanAgent
            )
            
            # Discover process agents
            self._discover_agents_in_directory(
                agents_dir / "process",
                self._process_agents,
                ProcessAgent
            )
            
            # Discover score agents (they are also process agents)
            self._discover_agents_in_directory(
                agents_dir / "score",
                self._process_agents,
                ProcessAgent
            )
            
            # Discover report agents (they are also process agents)
            self._discover_agents_in_directory(
                agents_dir / "report",
                self._process_agents,
                ProcessAgent
            )
            
            # Discover signature agents (they are also process agents)
            self._discover_agents_in_directory(
                agents_dir / "signature",
                self._process_agents,
                ProcessAgent
            )
            
            # Discover publish agents
            self._discover_agents_in_directory(
                agents_dir / "publish",
                self._publish_agents,
                PublishAgent
            )
            
            self.logger.info(f"🔍 Discovered agents - Recon: {len(self._recon_agents)}, "
                           f"Scan: {len(self._scan_agents)}, Process: {len(self._process_agents)}, "
                           f"Publish: {len(self._publish_agents)}")
            
        except Exception as e:
            self.logger.error(f"Failed to discover agents: {e}")
    
    def _discover_agents_in_directory(
        self,
        directory: Path,
        registry: Dict[str, Type[BaseAgent]],
        base_class: Type[BaseAgent]
    ) -> None:
        """
        Discover agents in a specific directory.
        
        Args:
            directory: Directory to search for agents
            registry: Registry to store discovered agents
            base_class: Base class that agents should inherit from
        """
        if not directory.exists():
            return
        
        for file_path in directory.glob("*.py"):
            if file_path.name.startswith("__"):
                continue
            
            try:
                # Import module
                module_name = f"agents.{directory.name}.{file_path.stem}"
                module = importlib.import_module(module_name)
                
                # Find agent classes in module
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    
                    if (isinstance(attr, type) and 
                        issubclass(attr, base_class) and 
                        attr != base_class and
                        not attr.__name__.startswith('Base')):
                        
                        registry[attr.__name__] = attr
                        self.logger.debug(f"Registered {base_class.__name__}: {attr.__name__}")
                        
            except Exception as e:
                self.logger.warning(f"Failed to load agent from {file_path}: {e}")
    
    def get_recon_agents(self) -> Dict[str, Type[ReconAgent]]:
        """Get all registered reconnaissance agents."""
        return self._recon_agents.copy()
    
    def get_scan_agents(self) -> Dict[str, Type[ScanAgent]]:
        """Get all registered scan agents."""
        return self._scan_agents.copy()
    
    def get_process_agents(self) -> Dict[str, Type[ProcessAgent]]:
        """Get all registered process agents."""
        return self._process_agents.copy()
    
    def get_publish_agents(self) -> Dict[str, Type[PublishAgent]]:
        """Get all registered publish agents."""
        return self._publish_agents.copy()
    
    def get_recon_agent(self, name: str) -> Optional[Type[ReconAgent]]:
        """Get a specific reconnaissance agent by name."""
        return self._recon_agents.get(name)
    
    def get_scan_agent(self, name: str) -> Optional[Type[ScanAgent]]:
        """Get a specific scan agent by name."""
        return self._scan_agents.get(name)
    
    def get_process_agent(self, name: str) -> Optional[Type[ProcessAgent]]:
        """Get a specific process agent by name."""
        return self._process_agents.get(name)
    
    def get_publish_agent(self, name: str) -> Optional[Type[PublishAgent]]:
        """Get a specific publish agent by name."""
        return self._publish_agents.get(name)
    
    def create_recon_agent(self, name: str, *args, **kwargs) -> Optional[ReconAgent]:
        """Create an instance of a reconnaissance agent."""
        agent_class = self.get_recon_agent(name)
        if agent_class:
            return agent_class(*args, **kwargs)
        return None
    
    def create_scan_agent(self, name: str, *args, **kwargs) -> Optional[ScanAgent]:
        """Create an instance of a scan agent."""
        agent_class = self.get_scan_agent(name)
        if agent_class:
            return agent_class(*args, **kwargs)
        return None
    
    def create_process_agent(self, name: str, *args, **kwargs) -> Optional[ProcessAgent]:
        """Create an instance of a process agent."""
        agent_class = self.get_process_agent(name)
        if agent_class:
            return agent_class(*args, **kwargs)
        return None
    
    def create_publish_agent(self, name: str, *args, **kwargs) -> Optional[PublishAgent]:
        """Create an instance of a publish agent."""
        agent_class = self.get_publish_agent(name)
        if agent_class:
            return agent_class(*args, **kwargs)
        return None
    
    def list_all_agents(self) -> Dict[str, List[str]]:
        """List all available agents by category."""
        return {
            'recon': list(self._recon_agents.keys()),
            'scan': list(self._scan_agents.keys()),
            'process': list(self._process_agents.keys()),
            'publish': list(self._publish_agents.keys())
        }
    
    def register_agent(self, agent_class: Type[BaseAgent], category: str) -> bool:
        """
        Manually register an agent.
        
        Args:
            agent_class: Agent class to register
            category: Category ('recon', 'scan', 'process', 'publish')
            
        Returns:
            True if registration succeeded, False otherwise
        """
        try:
            if category == 'recon' and issubclass(agent_class, ReconAgent):
                self._recon_agents[agent_class.__name__] = agent_class
            elif category == 'scan' and issubclass(agent_class, ScanAgent):
                self._scan_agents[agent_class.__name__] = agent_class
            elif category == 'process' and issubclass(agent_class, ProcessAgent):
                self._process_agents[agent_class.__name__] = agent_class
            elif category == 'publish' and issubclass(agent_class, PublishAgent):
                self._publish_agents[agent_class.__name__] = agent_class
            else:
                return False
            
            self.logger.info(f"Manually registered {category} agent: {agent_class.__name__}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to register agent {agent_class.__name__}: {e}")
            return False


# Global agent registry instance
_agent_registry: Optional[AgentRegistry] = None


def get_agent_registry() -> AgentRegistry:
    """
    Get the global agent registry instance.
    
    Returns:
        AgentRegistry instance
    """
    global _agent_registry
    if _agent_registry is None:
        _agent_registry = AgentRegistry()
    return _agent_registry
