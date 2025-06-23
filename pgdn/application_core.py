"""
Core Application Module

Provides core application functionality including configuration loading,
environment setup, and application initialization.
This module abstracts core operations from CLI concerns.
"""

import os
import json
from typing import Optional

from pgdn.core.config import Config
from pgdn.core.logging import setup_logging
from pgdn.core.database import create_tables


class ApplicationCore:
    """
    Core application manager for PGDN infrastructure scanner.
    
    This class provides a clean Python API for application initialization,
    configuration management, and environment setup, independent of CLI concerns.
    """
    
    def __init__(self):
        """Initialize the application core."""
        pass
    
    def load_config(self, 
                   config_file: Optional[str] = None,
                   log_level: Optional[str] = None,
                   use_docker_config: bool = False) -> Config:
        """
        Load configuration from file and environment.
        
        Args:
            config_file: Explicit path to config file (takes precedence)
            log_level: Override log level
            use_docker_config: Whether to prefer Docker configuration
            
        Returns:
            Configuration instance
            
        Raises:
            FileNotFoundError: If explicitly specified config file doesn't exist
            Exception: If config file is invalid or cannot be loaded
        """
        config = Config()
        
        # Determine config file: explicit > environment flag > default
        if config_file:
            target_config_file = config_file
        elif use_docker_config or os.getenv('USE_DOCKER_CONFIG', '').lower() in ('true', '1', 'yes'):
            # Only use Docker config if explicitly requested
            target_config_file = 'config.docker.json' if os.path.exists('config.docker.json') else 'config.json'
        else:
            target_config_file = 'config.json'
        
        # Load configuration
        if os.path.exists(target_config_file):
            with open(target_config_file, 'r') as f:
                config_data = json.load(f)
                config = Config(config_overrides=config_data)
        elif config_file:
            # Only error if user explicitly specified a config file that doesn't exist
            raise FileNotFoundError(f"Config file not found: {config_file}")
        # If no explicit config file and default doesn't exist, use defaults (no error)
        
        # Override log level if specified (takes precedence)
        if log_level:
            config.logging.level = log_level
        
        # Validate configuration
        if not config.validate():
            raise ValueError("Invalid configuration")
        
        return config
    
    def setup_environment(self, config: Config) -> None:
        """
        Setup the application environment.
        
        Args:
            config: Configuration instance
            
        Raises:
            Exception: If environment setup fails
        """
        # Setup logging
        setup_logging(config.logging)
        
        # Create database tables
        create_tables(config.database)
    
    def initialize_application(self,
                             config_file: Optional[str] = None,
                             log_level: Optional[str] = None,
                             use_docker_config: bool = False) -> Config:
        """
        Complete application initialization including config loading and environment setup.
        
        Args:
            config_file: Explicit path to config file
            log_level: Override log level
            use_docker_config: Whether to prefer Docker configuration
            
        Returns:
            Loaded and validated configuration instance
            
        Raises:
            FileNotFoundError: If explicitly specified config file doesn't exist
            ValueError: If configuration is invalid
            Exception: If environment setup fails
        """
        # Load configuration
        config = self.load_config(
            config_file=config_file,
            log_level=log_level,
            use_docker_config=use_docker_config
        )
        
        # Setup environment
        self.setup_environment(config)
        
        return config


# Convenience functions for direct usage
def load_config(config_file: Optional[str] = None,
               log_level: Optional[str] = None,
               use_docker_config: bool = False) -> Config:
    """
    Convenience function to load configuration.
    
    Args:
        config_file: Explicit path to config file
        log_level: Override log level
        use_docker_config: Whether to prefer Docker configuration
        
    Returns:
        Configuration instance
    """
    core = ApplicationCore()
    return core.load_config(config_file, log_level, use_docker_config)


def setup_environment(config: Config) -> None:
    """
    Convenience function to setup application environment.
    
    Args:
        config: Configuration instance
    """
    core = ApplicationCore()
    core.setup_environment(config)


def initialize_application(config_file: Optional[str] = None,
                         log_level: Optional[str] = None,
                         use_docker_config: bool = False) -> Config:
    """
    Convenience function for complete application initialization.
    
    Args:
        config_file: Explicit path to config file
        log_level: Override log level
        use_docker_config: Whether to prefer Docker configuration
        
    Returns:
        Loaded and validated configuration instance
    """
    core = ApplicationCore()
    return core.initialize_application(config_file, log_level, use_docker_config)
