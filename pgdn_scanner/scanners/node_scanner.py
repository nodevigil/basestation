#!/usr/bin/env python3
"""
Multi-Protocol DePIN Node Scanner

Node scanner that adapts to different DePIN protocols with protocol-specific configurations.
Based on the original node_scanner.py but integrated into the PGDN library architecture.
"""

import json
import ssl
import socket
import time
import re
import os
from typing import List, Dict, Any, Optional, Union
from pathlib import Path
import yaml

from .base_scanner import BaseScanner
from ..core.logging import get_logger

logger = get_logger(__name__)


class NodeScanner(BaseScanner):
    """Multi-protocol node scanner that adapts to different DePIN protocols."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the node scanner with configuration.
        
        Args:
            config: Scanner configuration including protocols_dir
        """
        super().__init__(config)
        
        # Extract protocols directory from config or use default
        protocols_dir = self.config.get('protocols_dir')
        if protocols_dir is None:
            # Default to protocols directory relative to this package
            package_dir = Path(__file__).parent.parent  # Go up from scanners/ to pgdn/
            protocols_dir = os.getenv('DEPIN_PROTOCOLS_DIR', str(package_dir / 'protocols'))
        
        self.protocols_dir = Path(protocols_dir)
        self.protocol_configs = self._load_protocol_configs()
        self.compiled_signatures = {}
        self._compile_all_signatures()
        
        # Scan settings
        self.concurrency = self.config.get('concurrency', 50)
        self.timeout = self.config.get('timeout', 3.0)
    
    @property
    def scanner_type(self) -> str:
        """Return the type of scanner."""
        return "node_scan"
    
    def get_supported_levels(self) -> List[int]:
        """Return list of supported scan levels."""
        return [1, 2]
    
    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        logger.info(f"Starting node scan for {target}")
        """
        Perform node scan on target.
        
        Args:
            target: Target IP address or hostname
            **kwargs: Additional scan parameters including:
                - protocol: Protocol to scan for (required)
                - ports: Custom ports list
                - scan_level: Scan level (1-3)
                - concurrency: Max concurrent connections
                - timeout: Connection timeout
                
        Returns:
            Node scan results dictionary
        """
        protocol = kwargs.get('protocol')
        if not protocol:
            return {
                "error": "Protocol is required for node scanning",
                "target": target,
                "scanner_type": "node_scan"
            }
        
        if protocol not in self.protocol_configs:
            return {
                "error": f"Unknown protocol: {protocol}. Available: {list(self.protocol_configs.keys())}",
                "target": target,
                "scanner_type": "node_scan"
            }
        
        ports = kwargs.get('ports') or self.get_protocol_ports(protocol)
        scan_level = kwargs.get('scan_level', 1)
        concurrency = kwargs.get('concurrency', self.concurrency)
        timeout = kwargs.get('timeout', self.timeout)
        
        try:
            # Run sync scan
            results = self._scan_host_sync(target, protocol, ports, concurrency, timeout)
            
            # Format results
            return {
                "target": target,
                "protocol": protocol,
                "scanner_type": "node_scan",
                "scan_level": scan_level,
                "results": results,
                "total_probes": len(results),
                "successful_probes": len([r for r in results if not r.get('error')]),
                "detected_services": [r for r in results if r.get('service')],
                "open_ports": list(set([r['port'] for r in results if not r.get('error') and r.get('banner')]))
            }
            
        except Exception as e:
            logger.error(f"Node scan failed for {target}: {e}")
            return {
                "error": f"Scan failed: {str(e)}",
                "target": target,
                "protocol": protocol,
                "scanner_type": "node_scan"
            }
    
    def _load_protocol_configs(self) -> Dict[str, Dict[str, Any]]:
        """Load all protocol configuration files."""
        configs = {}
        
        if not self.protocols_dir.exists():
            logger.warning(f"Protocols directory not found: {self.protocols_dir}")
            return self._get_builtin_configs()
        
        for config_file in self.protocols_dir.glob("*.yaml"):
            protocol_name = config_file.stem
            try:
                with open(config_file, 'r') as f:
                    configs[protocol_name] = yaml.safe_load(f)
                logger.debug(f"Loaded protocol config: {protocol_name}")
            except Exception as e:
                logger.warning(f"Failed to load {config_file}: {e}")
        
        return configs
    
    def _get_builtin_configs(self) -> Dict[str, Dict[str, Any]]:
        """Built-in configurations - returns empty dict, configs should be in files."""
        import sys
        print("Warning: No protocols directory found. Please create 'protocols/' directory with protocol config files.", file=sys.stderr)
        print("Example: protocols/sui.yaml, protocols/arweave.yaml, etc.", file=sys.stderr)
        return {}

    def _compile_all_signatures(self):
        """Pre-compile regex patterns for all protocols."""
        for protocol_name, config in self.protocol_configs.items():
            compiled = []
            for sig in config.get('signatures', []):
                try:
                    pattern = re.compile(sig['regex'], re.IGNORECASE | re.MULTILINE)
                    compiled.append({
                        'label': sig['label'],
                        'pattern': pattern,
                        'version_group': sig.get('version_group')
                    })
                except re.error as e:
                    logger.warning(f"Invalid regex in {protocol_name} signature '{sig['label']}': {e}")
            self.compiled_signatures[protocol_name] = compiled
    
    def get_protocol_probes(self, protocol: str) -> List[Dict[str, Any]]:
        """Get probes for a specific protocol."""
        if protocol not in self.protocol_configs:
            raise ValueError(f"Unknown protocol: {protocol}. Available: {list(self.protocol_configs.keys())}")
        
        config = self.protocol_configs[protocol]
        
        # Combine protocol-specific probes with generic ones
        probes = config.get('probes', []).copy()
        
        # Add generic probes
        generic_probes = [
            {
                'name': 'HTTP_GET_ROOT',
                'payload': 'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n',
                'ports': 'any',
                'requires_ssl': False
            },
            {
                'name': 'HTTPS_GET_ROOT',
                'payload': 'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n',
                'ports': [443, 8443],
                'requires_ssl': True
            },
            {
                'name': 'TCP_BANNER',
                'payload': '',
                'ports': 'any',
                'requires_ssl': False
            }
        ]
        
        probes.extend(generic_probes)
        return probes
    
    def get_protocol_ports(self, protocol: str) -> List[int]:
        """Get default ports for a protocol."""
        if protocol not in self.protocol_configs:
            return [22, 80, 443]  # Generic defaults
        
        return self.protocol_configs[protocol].get('default_ports', [22, 80, 443])
    
    def _match_signatures(self, banner: str, protocol: str) -> tuple[Optional[str], Optional[str]]:
        """Match banner against protocol-specific signatures."""
        signatures = self.compiled_signatures.get(protocol, [])
        
        for sig in signatures:
            match = sig['pattern'].search(banner)
            if match:
                version = None
                if sig['version_group'] and sig['version_group'] in match.groupdict():
                    version = match.group(sig['version_group'])
                return sig['label'], version
        
        return None, None
    
    def _get_applicable_probes(self, port: int, probes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Get probes applicable to a specific port."""
        applicable = []
        
        for probe in probes:
            if probe['ports'] == 'any' or port in probe.get('ports', []):
                applicable.append(probe)
        
        return applicable
    
    def _probe_port(self, ip: str, port: int, probe: Dict[str, Any], protocol: str,
                         timeout: float, semaphore=None) -> Dict[str, Any]:
        """Execute a single probe against a port."""
        start_time = time.time()
        result = {
            'ip': ip,
            'port': port,
            'probe': probe['name'],
            'protocol': protocol,
            'latency_ms': 0,
            'ssl': probe.get('requires_ssl', False),
            'error': None,
            'banner': '',
            'service': None,
            'version': None
        }
        
        try:
            # Create connection using regular sockets
            if probe.get('requires_ssl', False):
                import ssl as ssl_module
                context = ssl_module.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl_module.CERT_NONE
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((ip, port))
                ssl_sock = context.wrap_socket(sock, server_hostname=ip)
                
                # Send probe payload
                if 'payload' in probe and probe['payload']:
                    payload = probe['payload'].replace('\\r\\n', '\r\n').replace('\\r', '\r').replace('\\n', '\n')
                    ssl_sock.send(payload.encode('utf-8'))
                
                # Read response
                try:
                    data = ssl_sock.recv(4096)
                    result['banner'] = data.decode('utf-8', errors='replace').strip()
                except socket.timeout:
                    result['error'] = 'timeout'
                except Exception as e:
                    result['error'] = str(e)
                
                ssl_sock.close()
                
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((ip, port))
                
                # Send probe payload
                if 'payload' in probe and probe['payload']:
                    payload = probe['payload'].replace('\\r\\n', '\r\n').replace('\\r', '\r').replace('\\n', '\n')
                    sock.send(payload.encode('utf-8'))
                
                # Read response
                try:
                    data = sock.recv(4096)
                    result['banner'] = data.decode('utf-8', errors='replace').strip()
                except socket.timeout:
                    result['error'] = 'timeout'
                except Exception as e:
                    result['error'] = str(e)
                
                sock.close()
                
        except socket.timeout:
            result['error'] = 'connection_timeout'
        except ConnectionRefusedError:
            result['error'] = 'connection_refused'
        except Exception as e:
            result['error'] = str(e)
        
        # Calculate latency
        result['latency_ms'] = round((time.time() - start_time) * 1000, 1)
        
        # Try to identify service and version
        if result['banner'] and not result['error']:
            service, version = self._match_signatures(result['banner'], protocol)
            result['service'] = service
            result['version'] = version
        
        return result
    
    def _scan_host_sync(self, ip: str, protocol: str, ports: Optional[List[int]] = None,
                       concurrency: int = 50, timeout: float = 3.0) -> List[Dict[str, Any]]:
        """
        Scan a host using protocol-specific configuration.
        
        Args:
            ip: Target IP address
            protocol: Protocol name (sui, arweave, filecoin, etc.)
            ports: Optional list of ports (uses protocol defaults if None)
            concurrency: Max concurrent connections
            timeout: Connection timeout in seconds
        
        Returns:
            List of scan results
        """
        if ports is None:
            ports = self.get_protocol_ports(protocol)
        
        probes = self.get_protocol_probes(protocol)
        results = []
        
        for port in ports:
            applicable_probes = self._get_applicable_probes(port, probes)
            for probe in applicable_probes:
                try:
                    result = self._probe_port(ip, port, probe, protocol, timeout, None)
                    if isinstance(result, dict):
                        results.append(result)
                except Exception as e:
                    logger.warning(f"Probe failed: {e}")
        
        return results
    
    def list_protocols(self) -> List[str]:
        """List all available protocols."""
        return list(self.protocol_configs.keys())
    
    def get_protocol_info(self, protocol: str) -> Dict[str, Any]:
        """Get information about a protocol."""
        if protocol not in self.protocol_configs:
            return {}
        
        config = self.protocol_configs[protocol]
        return {
            'name': config.get('name', protocol.title()),
            'network_type': config.get('network_type', 'unknown'),
            'default_ports': config.get('default_ports', []),
            'probe_count': len(config.get('probes', [])),
            'signature_count': len(config.get('signatures', []))
        }


# Library interface functions for backward compatibility
def scan_depin_node(ip: str, protocol: str, ports: Optional[List[int]] = None,
                         concurrency: int = 50, timeout: float = 3.0,
                         protocols_dir: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Library interface for scanning DePIN nodes.
    
    Args:
        ip: Target IP address
        protocol: Protocol name (sui, arweave, filecoin, helium, render)
        ports: Optional list of ports (uses protocol defaults if None)
        concurrency: Max concurrent connections  
        timeout: Connection timeout in seconds
        protocols_dir: Custom protocols directory path
    
    Returns:
        List of scan results with protocol-specific analysis
    """
    config = {
        'protocols_dir': protocols_dir,
        'concurrency': concurrency,
        'timeout': timeout
    }
    
    scanner = NodeScanner(config)
    result = scanner.scan(ip, protocol=protocol, ports=ports)
    
    # Return the results list for backward compatibility
    return result.get('results', [])
