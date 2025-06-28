"""
Base class for protocol-specific scanners.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from ..base_scanner import BaseScanner


class ProtocolScanner(BaseScanner):
    """Base class for protocol-specific scanners with level support."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize protocol scanner.
        
        Args:
            config: Scanner-specific configuration
        """
        super().__init__(config)
        
        # Default scan level if not specified in config
        self.default_scan_level = 1
        
        # Protocol-specific configuration
        self.timeout = self.config.get('timeout', 10)
        self.debug = self.config.get('debug', False)
    
    @property
    @abstractmethod
    def protocol_name(self) -> str:
        """Return the protocol name this scanner handles."""
        pass
    
    @property
    def scanner_type(self) -> str:
        """Return the scanner type (protocol name)."""
        return self.protocol_name
    
    def get_supported_levels(self) -> List[int]:
        """Return list of supported scan levels.
        
        Protocol scanners typically support multiple levels.
        Override this method to specify which levels are supported.
        
        Returns:
            List of supported scan levels (1-3)
        """
        return [1, 2, 3]  # Default: support all levels
    
    async def scan(self, target: str, hostname: Optional[str] = None, scan_level: int = None, **kwargs) -> Dict[str, Any]:
        """Perform protocol-specific scan.
        
        Args:
            target: Target to scan (IP address, hostname)
            hostname: Optional hostname for SNI/virtual host support
            scan_level: Scan intensity level (1-3)
            **kwargs: Additional scan parameters
            
        Returns:
            Scan results dictionary
        """
        # Use provided scan_level or default
        if scan_level is None:
            scan_level = kwargs.get('scan_level', self.default_scan_level)
        
        # Validate scan level
        if not self.can_handle_level(scan_level):
            supported_levels = self.get_supported_levels()
            self.logger.warning(
                f"Scanner {self.protocol_name} does not support level {scan_level}. "
                f"Supported levels: {supported_levels}. Using level {min(supported_levels)}."
            )
            scan_level = min(supported_levels)
        
        # Call the protocol-specific implementation
        return await self.scan_protocol(target, hostname=hostname, scan_level=scan_level, **kwargs)
    
    @abstractmethod
    async def scan_protocol(self, target: str, hostname: Optional[str] = None, scan_level: int = 1, **kwargs) -> Dict[str, Any]:
        """Perform the actual protocol-specific scan.
        
        This method should be implemented by each protocol scanner.
        
        Args:
            target: Target to scan
            hostname: Optional hostname for SNI/virtual host support
            scan_level: Validated scan level
            **kwargs: Additional parameters
            
        Returns:
            Protocol-specific scan results
        """
        pass
    
    def describe_levels(self) -> Dict[int, str]:
        """Return description of what each scan level does.
        
        Override this method to provide level descriptions.
        
        Returns:
            Dictionary mapping level numbers to descriptions
        """
        return {
            1: "Basic protocol checks and health status",
            2: "Extended metrics, validation, and anomaly detection", 
            3: "Aggressive probing, latency testing, and edge case validation"
        }
