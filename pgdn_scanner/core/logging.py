"""
Centralized logging configuration for the DePIN infrastructure scanner.
"""

import logging
import sys
from typing import Optional
from .config import LoggingConfig


class LoggingManager:
    """
    Manages logging configuration for the entire application.
    
    Provides centralized logging setup with consistent formatting
    and level management across all agents and modules.
    """
    
    _instance: Optional['LoggingManager'] = None
    _initialized: bool = False
    
    def __new__(cls, config: Optional[LoggingConfig] = None) -> 'LoggingManager':
        """Singleton pattern to ensure single logging configuration."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, config: Optional[LoggingConfig] = None):
        """Initialize logging manager with configuration."""
        if self._initialized:
            return
            
        self.config = config or LoggingConfig()
        self._setup_logging()
        self._initialized = True
    
    def _setup_logging(self) -> None:
        """Configure application-wide logging."""
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, self.config.level.upper()))
        
        # Remove existing handlers to avoid duplication
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Create console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, self.config.level.upper()))
        
        # Create formatter
        formatter = logging.Formatter(self.config.format)
        console_handler.setFormatter(formatter)
        
        # Add handler to root logger
        root_logger.addHandler(console_handler)
        
        # Disable SQLAlchemy logging if configured
        if self.config.disable_sqlalchemy:
            logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)
            logging.getLogger('sqlalchemy.pool').setLevel(logging.WARNING)
    
    def get_logger(self, name: str) -> logging.Logger:
        """
        Get a logger instance for the specified name.
        
        Args:
            name: Logger name (typically module or class name)
            
        Returns:
            Configured logger instance
        """
        return logging.getLogger(name)
    
    def set_level(self, level: str) -> None:
        """
        Change the logging level for all loggers.
        
        Args:
            level: New logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        logging_level = getattr(logging, level.upper())
        logging.getLogger().setLevel(logging_level)
        
        # Update handlers
        for handler in logging.getLogger().handlers:
            handler.setLevel(logging_level)


def setup_logging(config: Optional[LoggingConfig] = None) -> LoggingManager:
    """
    Setup application logging.
    
    Args:
        config: Logging configuration. If None, uses default config.
        
    Returns:
        LoggingManager instance
    """
    return LoggingManager(config)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance.
    
    Args:
        name: Logger name
        
    Returns:
        Logger instance
    """
    # Ensure logging is initialized
    if not LoggingManager._initialized:
        setup_logging()
    
    return logging.getLogger(name)
