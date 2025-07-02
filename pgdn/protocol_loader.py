"""
Protocol Configuration Loader

Loads protocol configurations from YAML files in the protocols directory.
"""

import os
import yaml
from typing import Dict, List, Optional
from pathlib import Path


class ProtocolLoader:
    """Loads protocol configurations from YAML files."""
    
    def __init__(self, protocols_dir: Optional[str] = None):
        """
        Initialize the protocol loader.
        
        Args:
            protocols_dir: Path to protocols directory. If None, uses default.
        """
        if protocols_dir is None:
            # Default to protocols directory within the pgdn package
            current_dir = Path(__file__).parent
            self.protocols_dir = current_dir / "protocols"
        else:
            self.protocols_dir = Path(protocols_dir)
    
    def list_available_protocols(self) -> List[str]:
        """
        List all available protocols.
        
        Returns:
            List of protocol names (without .yaml extension)
        """
        protocols = []
        if self.protocols_dir.exists():
            for file_path in self.protocols_dir.glob("*.yaml"):
                protocols.append(file_path.stem)
        return sorted(protocols)
    
    def load_protocol(self, protocol_name: str) -> Optional[Dict]:
        """
        Load a specific protocol configuration.
        
        Args:
            protocol_name: Name of the protocol (without .yaml extension)
            
        Returns:
            Protocol configuration dictionary or None if not found
        """
        protocol_file = self.protocols_dir / f"{protocol_name}.yaml"
        
        if not protocol_file.exists():
            return None
        
        try:
            with open(protocol_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading protocol {protocol_name}: {e}")
            return None
    
    def get_protocol_info(self, protocol_name: str) -> Optional[Dict]:
        """
        Get basic info about a protocol.
        
        Args:
            protocol_name: Name of the protocol
            
        Returns:
            Dictionary with protocol info or None if not found
        """
        config = self.load_protocol(protocol_name)
        if not config:
            return None
        
        return {
            'name': config.get('name', protocol_name),
            'network_type': config.get('network_type', 'unknown'),
            'default_ports': config.get('default_ports', []),
            'probes_count': len(config.get('probes', [])),
            'signatures_count': len(config.get('signatures', []))
        }
    
    def validate_protocol(self, protocol_name: str) -> bool:
        """
        Validate that a protocol exists and has required fields.
        
        Args:
            protocol_name: Name of the protocol
            
        Returns:
            True if protocol is valid, False otherwise
        """
        config = self.load_protocol(protocol_name)
        if not config:
            return False
        
        # Check for required fields
        required_fields = ['name', 'network_type']
        for field in required_fields:
            if field not in config:
                return False
        
        return True