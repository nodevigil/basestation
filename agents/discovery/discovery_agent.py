"""
Discovery Agent Base Class

This module provides the base class for discovery agents that analyze network topology,
infrastructure mapping, and protocol-specific discovery functionality.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime

from agents.base import ProcessAgent
from core.config import Config
from core.database import get_db_session


class DiscoveryAgent(ProcessAgent):
    """
    Base discovery agent for network topology and infrastructure mapping.
    
    Discovery agents analyze network infrastructure, map relationships between nodes,
    and discover protocol-specific information that wasn't captured during initial
    reconnaissance or scanning phases.
    """
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize the discovery agent.
        
        Args:
            config: Configuration instance
        """
        super().__init__(config, "DiscoveryAgent")
        self.logger.info("🔍 Discovery Agent initialized")
    
    def run(self, host: Optional[str] = None, *args, **kwargs) -> List[Dict[str, Any]]:
        """
        Execute network discovery for the specified host.
        
        Args:
            host: Target host for discovery (IP address or hostname)
            
        Returns:
            List of discovery results
        """
        if not host:
            self.logger.warning("No host specified for discovery")
            return []
            
        self.logger.info(f"🔍 Starting network discovery for host: {host}")
        
        # This will be implemented by concrete discovery agents
        return self.discover_host(host)
    
    def discover_host(self, host: str) -> List[Dict[str, Any]]:
        """
        Discover network information for a specific host.
        
        This method should be overridden by concrete discovery agent implementations.
        
        Args:
            host: Target host for discovery
            
        Returns:
            List of discovery results
        """
        self.logger.info(f"🔍 Base discovery agent - no specific discovery logic implemented for {host}")
        return []
    
    def process_results(self, scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Legacy method for compatibility with ProcessAgent interface.
        
        This method is kept for backward compatibility but discovery agents
        should primarily use the run() method with host parameter.
        """
        self.logger.warning("process_results() called - consider using execute() with host parameter instead")
        return scan_results
    
    