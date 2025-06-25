"""
Base scanner interface and registry for modular scanning.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
import importlib
from pgdn.core.logging import get_logger

logger = get_logger(__name__)


class BaseScanner(ABC):
    """Base interface for all scanners."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize scanner with configuration.
        
        Args:
            config: Scanner-specific configuration
        """
        self.config = config or {}
        self.logger = get_logger(self.__class__.__name__)
    
    @abstractmethod
    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform scan on target.
        
        Args:
            target: Target to scan (IP address, hostname, etc.)
            **kwargs: Additional scan parameters
            
        Returns:
            Scan results dictionary
        """
        pass
    
    @property
    @abstractmethod
    def scanner_type(self) -> str:
        """Return the type of scanner."""
        pass


class ScannerRegistry:
    """Registry for managing scanners in a modular way."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize scanner registry.
        
        Args:
            config: Global configuration
        """
        self.config = config or {}
        self._scanners = {}
        self.logger = get_logger(__name__)
        self._register_builtin_scanners()
        self._register_external_scanners()
    
    def _register_builtin_scanners(self):
        """Register built-in scanners."""
        try:
            from pgdn.scanning.generic_scanner import GenericScanner
            self._scanners['generic'] = GenericScanner
            self.logger.debug("Registered built-in GenericScanner")
        except ImportError as e:
            self.logger.warning(f"Failed to register GenericScanner: {e}")
        
        try:
            from pgdn.scanning.web_scanner import WebScanner
            self._scanners['web'] = WebScanner
            self.logger.debug("Registered built-in WebScanner")
        except ImportError as e:
            self.logger.warning(f"Failed to register WebScanner: {e}")
            
        try:
            from pgdn.scanning.vulnerability_scanner import VulnerabilityScanner
            self._scanners['vulnerability'] = VulnerabilityScanner
            self.logger.debug("Registered built-in VulnerabilityScanner")
        except ImportError as e:
            self.logger.warning(f"Failed to register VulnerabilityScanner: {e}")
            
        try:
            from pgdn.scanning.geo_scanner import GeoScanner
            self._scanners['geo'] = GeoScanner
            self.logger.debug("Registered built-in GeoScanner")
        except ImportError as e:
            self.logger.warning(f"Failed to register GeoScanner: {e}")
    
    def _register_external_scanners(self):
        """Register external/protocol-specific scanners."""
        scanner_configs = self.config.get('scanners', {})
        
        for scanner_name, scanner_config in scanner_configs.items():
            if not scanner_config.get('enabled', True):
                continue
                
            module_path = scanner_config.get('module_path')
            if not module_path:
                continue
                
            try:
                scanner_class = self._load_scanner_class(module_path)
                self._scanners[scanner_name] = scanner_class
                self.logger.info(f"✅ Registered external scanner: {scanner_name} ({module_path})")
            except Exception as e:
                self.logger.warning(f"Failed to register external scanner {scanner_name}: {e}")
    
    def _load_scanner_class(self, module_path: str):
        """Load scanner class from module path.
        
        Args:
            module_path: Full module path to scanner class
            
        Returns:
            Scanner class
        """
        try:
            module_name, class_name = module_path.rsplit('.', 1)
            module = importlib.import_module(module_name)
            return getattr(module, class_name)
        except Exception as e:
            self.logger.debug(f"Failed to load scanner from {module_path}: {e}")
            raise
    
    def get_scanner(self, scanner_type: str, config: Optional[Dict[str, Any]] = None) -> Optional[BaseScanner]:
        """Get scanner instance by type.
        
        Args:
            scanner_type: Type of scanner to get
            config: Scanner-specific configuration
            
        Returns:
            Scanner instance or None if not found
        """
        scanner_class = self._scanners.get(scanner_type)
        if not scanner_class:
            return None
            
        try:
            # Merge global config with scanner-specific config
            scanner_config = self.config.get('scanners', {}).get(scanner_type, {})
            if config:
                scanner_config.update(config)
                
            return scanner_class(config=scanner_config)
        except Exception as e:
            self.logger.error(f"Failed to create scanner {scanner_type}: {e}")
            return None
    
    def get_registered_scanners(self) -> List[str]:
        """Get list of registered scanner types.
        
        Returns:
            List of registered scanner type names
        """
        return list(self._scanners.keys())
    
    def get_available_scanners(self) -> List[str]:
        """Get list of available scanner types.
        
        Returns:
            List of scanner type names
        """
        return list(self._scanners.keys())
    
    def register_scanner(self, scanner_type: str, scanner_class):
        """Register a new scanner type.
        
        Args:
            scanner_type: Type name for the scanner
            scanner_class: Scanner class
        """
        self._scanners[scanner_type] = scanner_class
        self.logger.info(f"Registered scanner: {scanner_type}")
