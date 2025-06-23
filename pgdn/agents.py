"""
Agents Management Module

Provides agent listing and registry functionality.
This module abstracts agent operations from CLI concerns.
"""

from typing import Dict, Any
from datetime import datetime

from pgdn.utils.agent_registry import get_agent_registry


class AgentManager:
    """
    Manager for agent registry and listing operations.
    
    This class provides a clean Python API for managing agents
    and retrieving agent information, independent of CLI concerns.
    """
    
    def __init__(self):
        """Initialize the agent manager."""
        pass
    
    def list_all_agents(self) -> Dict[str, Any]:
        """
        List all available agents.
        
        Returns:
            dict: Available agents organized by category
        """
        try:
            registry = get_agent_registry()
            agents = registry.list_all_agents()
            
            return {
                "success": True,
                "agents": agents,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to list agents: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
