"""
Base scanner interface and registry for modular scanning.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
import importlib
from ..core.logging import get_logger

logger = get_logger(__name__)


class BaseScanner(ABC):
    """Base interface for all scanners."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize scanner with configuration.
        
        Args:
            config: Scanner-specific configuration
        """
        self.config = config or {}
        # Debug logging to see what type of config is being passed
        if hasattr(config, '__class__') and 'ScanConfig' in str(config.__class__):
            print(f"ERROR: BaseScanner received ScanConfig object instead of dict: {type(config)}")
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
    
    def get_supported_levels(self) -> List[int]:
        """Return list of supported scan levels.
        
        Default implementation supports level 1 only.
        Protocol-specific scanners should override this.
        
        Returns:
            List of supported scan levels (1-3)
        """
        return [1]
    
    def can_handle_level(self, level: int) -> bool:
        """Check if scanner can handle a specific scan level.
        
        Args:
            level: Scan level to check
            
        Returns:
            True if scanner supports the level
        """
        return level in self.get_supported_levels()


class ScannerRegistry:
    """Registry for managing scanners in a modular way."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize scanner registry.
        
        Args:
            config: Global configuration
        """
        # Convert config to dict if it's a dataclass
        if config and hasattr(config, '__class__') and hasattr(config, '__dataclass_fields__'):
            # It's a dataclass, convert to dict
            config = vars(config)
        
        self.config = config or {}
        self._scanners = {}
        self.logger = get_logger(__name__)
        self._register_builtin_scanners()
        self._register_external_scanners()
    
    def _register_builtin_scanners(self):
        """Register built-in scanners."""
        try:
            from .web_scanner import WebScanner
            self._scanners['web'] = WebScanner
            self.logger.debug("Registered built-in WebScanner")
        except ImportError as e:
            self.logger.warning(f"Failed to register WebScanner: {e}")
            
        try:
            from .vulnerability_scanner import VulnerabilityScanner
            self._scanners['vulnerability'] = VulnerabilityScanner
            self.logger.debug("Registered built-in VulnerabilityScanner")
        except ImportError as e:
            self.logger.warning(f"Failed to register VulnerabilityScanner: {e}")
            
        try:
            from .geo_scanner import GeoScanner
            self._scanners['geo'] = GeoScanner
            self.logger.debug("Registered built-in GeoScanner")
        except ImportError as e:
            self.logger.warning(f"Failed to register GeoScanner: {e}")
            
        try:
            from .compliance_scanner import ComplianceScanner
            self._scanners['compliance'] = ComplianceScanner
            self.logger.debug("Registered built-in ComplianceScanner")
        except ImportError as e:
            self.logger.warning(f"Failed to register ComplianceScanner: {e}")
            
        try:
            from .node_scanner import NodeScanner
            self._scanners['node_scan'] = NodeScanner
            self.logger.debug("Registered built-in NodeScanner")
        except ImportError as e:
            self.logger.warning(f"Failed to register NodeScanner: {e}")
    
    def _register_external_scanners(self):
        """Register external/protocol-specific scanners."""
        scanner_configs = self.config.get('scanners', {})
        
        # Register protocol scanners from the protocols folder
        self._register_protocol_scanners()
        
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
    
    def _register_protocol_scanners(self):
        """Register protocol-specific scanners."""
        try:
            from .protocol_scanners.sui_scanner import EnhancedSuiScanner
            self._scanners['sui'] = EnhancedSuiScanner
            self.logger.debug("Registered protocol scanner: EnhancedSuiScanner")
        except ImportError as e:
            self.logger.warning(f"Failed to register EnhancedSuiScanner: {e}")
            
        try:
            from .protocol_scanners.filecoin_scanner import FilecoinScanner
            self._scanners['filecoin'] = FilecoinScanner
            self.logger.debug("Registered protocol scanner: FilecoinScanner")
        except ImportError as e:
            self.logger.warning(f"Failed to register FilecoinScanner: {e}")
            
        try:
            from .protocol_scanners.ethereum_scanner import EthereumScanner
            self._scanners['ethereum'] = EthereumScanner
            self.logger.debug("Registered protocol scanner: EthereumScanner")
        except ImportError as e:
            self.logger.warning(f"Failed to register EthereumScanner: {e}")
            
        try:
            from .protocol_scanners.arweave_scanner import EnhancedArweaveScanner
            self._scanners['arweave'] = EnhancedArweaveScanner
            self.logger.debug("Registered protocol scanner: EnhancedArweaveScanner")
        except ImportError as e:
            self.logger.warning(f"Failed to register EnhancedArweaveScanner: {e}")
            
        try:
            from .protocol_scanners.webserver_scanner import WebServerScanner
            self._scanners['web'] = WebServerScanner
            self.logger.debug("Registered protocol scanner: WebServerScanner")
        except ImportError as e:
            self.logger.warning(f"Failed to register WebServerScanner: {e}")
    
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
