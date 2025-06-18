"""
Configuration management for the DePIN infrastructure scanner.
"""

import os
from typing import Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class DatabaseConfig:
    """Database configuration settings."""
    url: str = field(default_factory=lambda: _get_default_database_url())
    echo_sql: bool = field(default_factory=lambda: os.getenv('DB_ECHO_SQL', 'false').lower() == 'true')
    pool_size: int = field(default_factory=lambda: int(os.getenv('DB_POOL_SIZE', '10')))
    max_overflow: int = field(default_factory=lambda: int(os.getenv('DB_MAX_OVERFLOW', '20')))
    pool_timeout: int = field(default_factory=lambda: int(os.getenv('DB_POOL_TIMEOUT', '30')))
    pool_recycle: int = field(default_factory=lambda: int(os.getenv('DB_POOL_RECYCLE', '3600')))


def _get_default_database_url() -> str:
    """
    Get the default database URL based on environment.
    
    Returns:
        Database URL string
    """
    # Only use DATABASE_URL if USE_DOCKER_CONFIG is explicitly set
    if (os.getenv('USE_DOCKER_CONFIG', '').lower() in ('true', '1', 'yes') and 
        os.getenv('DATABASE_URL')):
        return os.getenv('DATABASE_URL')
    
    # Otherwise use local PostgreSQL
    return 'postgresql://simon@localhost/depin'


@dataclass
class ScanConfig:
    """Scanning configuration settings."""
    scan_interval_days: int = field(default_factory=lambda: int(os.getenv('SCAN_INTERVAL_DAYS', '7')))
    sleep_between_scans: float = field(default_factory=lambda: float(os.getenv('SLEEP_BETWEEN_SCANS', '5.0')))
    timeout_seconds: int = field(default_factory=lambda: int(os.getenv('SCAN_TIMEOUT', '30')))
    max_concurrent_scans: int = field(default_factory=lambda: int(os.getenv('MAX_CONCURRENT_SCANS', '5')))
    enable_vulnerability_scanning: bool = field(default_factory=lambda: os.getenv('ENABLE_VULN_SCAN', 'true').lower() == 'true')
    enable_ssl_testing: bool = field(default_factory=lambda: os.getenv('ENABLE_SSL_TEST', 'true').lower() == 'true')


@dataclass
class LoggingConfig:
    """Logging configuration settings."""
    level: str = field(default_factory=lambda: os.getenv('LOG_LEVEL', 'INFO'))
    format: str = field(default_factory=lambda: os.getenv('LOG_FORMAT', '%(asctime)s %(levelname)s [%(name)s]: %(message)s'))
    disable_sqlalchemy: bool = field(default_factory=lambda: os.getenv('DISABLE_SQLALCHEMY_LOGS', 'true').lower() == 'true')


@dataclass
class ReconConfig:
    """Reconnaissance configuration settings."""
    sui_rpc_url: str = field(default_factory=lambda: os.getenv('SUI_RPC_URL', 'https://fullnode.mainnet.sui.io'))
    dns_timeout: float = field(default_factory=lambda: float(os.getenv('DNS_TIMEOUT', '10.0')))
    max_retries: int = field(default_factory=lambda: int(os.getenv('MAX_RETRIES', '3')))


@dataclass
class PublishConfig:
    """Publishing configuration settings."""
    enabled_publishers: list = field(default_factory=lambda: os.getenv('ENABLED_PUBLISHERS', 'database,console').split(','))
    blockchain_endpoint: Optional[str] = field(default_factory=lambda: os.getenv('BLOCKCHAIN_ENDPOINT'))
    api_endpoint: Optional[str] = field(default_factory=lambda: os.getenv('API_ENDPOINT'))


class Config:
    """
    Main configuration class that aggregates all configuration settings.
    
    This class provides a centralized access point for all application configuration
    and supports environment variable overrides.
    """
    
    def __init__(self, config_overrides: Optional[Dict[str, Any]] = None):
        """
        Initialize configuration with optional overrides.
        
        Args:
            config_overrides: Dictionary of configuration overrides
        """
        self.database = DatabaseConfig()
        self.scanning = ScanConfig()
        self.logging = LoggingConfig()
        self.recon = ReconConfig()
        self.publish = PublishConfig()
        
        # Apply any overrides
        if config_overrides:
            self._apply_overrides(config_overrides)
    
    def _apply_overrides(self, overrides: Dict[str, Any]) -> None:
        """Apply configuration overrides."""
        for section, values in overrides.items():
            if hasattr(self, section):
                section_config = getattr(self, section)
                for key, value in values.items():
                    if hasattr(section_config, key):
                        setattr(section_config, key, value)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            'database': self.database.__dict__,
            'scanning': self.scanning.__dict__,
            'logging': self.logging.__dict__,
            'recon': self.recon.__dict__,
            'publish': self.publish.__dict__,
        }
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> 'Config':
        """Create configuration from dictionary."""
        return cls(config_overrides=config_dict)
    
    def validate(self) -> bool:
        """
        Validate configuration settings.
        
        Returns:
            True if configuration is valid, False otherwise
        """
        # Basic validation rules
        if self.scanning.scan_interval_days <= 0:
            return False
        if self.scanning.sleep_between_scans < 0:
            return False
        if self.database.pool_size <= 0:
            return False
        
        return True
