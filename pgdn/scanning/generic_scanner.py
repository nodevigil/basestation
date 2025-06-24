"""
Generic network scanner for basic port scanning and service detection.
"""

import socket
import ssl
from typing import Dict, Any, List, Tuple, Optional
from pgdn.scanning.base_scanner import BaseScanner


class GenericScanner(BaseScanner):
    """Generic network scanner for basic port and service scanning."""
    
    @property
    def scanner_type(self) -> str:
        return "generic"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.default_ports = self.config.get('default_ports', [22, 80, 443, 2375, 3306])
        self.connection_timeout = self.config.get('connection_timeout', 1)
        self.banner_timeout = self.config.get('banner_timeout', 2)
    
    def scan(self, target: str, ports: Optional[List[int]] = None, **kwargs) -> Dict[str, Any]:
        """Perform generic network scan.
        
        Args:
            target: IP address or hostname to scan
            ports: List of ports to scan (uses default if not provided)
            **kwargs: Additional scan parameters
            
        Returns:
            Scan results dictionary
        """
        ports = ports or self.default_ports
        
        self.logger.debug(f"Starting generic scan of {target} on ports {ports}")
        
        # Basic port scan
        open_ports = []
        banners = {}
        
        for port in ports:
            if self._is_port_open(target, port):
                open_ports.append(port)
                banner = self._grab_banner(target, port)
                if banner:
                    banners[port] = banner
        
        # Get TLS info for HTTPS ports
        tls_info = {}
        if 443 in open_ports:
            tls_info = self._get_tls_info(target)
        
        return {
            "target": target,
            "open_ports": open_ports,
            "banners": banners,
            "tls": tls_info,
            "scanner_type": self.scanner_type
        }
    
    def _is_port_open(self, target: str, port: int) -> bool:
        """Check if a port is open.
        
        Args:
            target: Target IP/hostname
            port: Port number
            
        Returns:
            True if port is open
        """
        try:
            with socket.socket() as sock:
                sock.settimeout(self.connection_timeout)
                result = sock.connect_ex((target, port))
                return result == 0
        except Exception:
            return False
    
    def _grab_banner(self, target: str, port: int) -> Optional[str]:
        """Grab service banner from a port.
        
        Args:
            target: Target IP/hostname
            port: Port number
            
        Returns:
            Service banner string or None
        """
        try:
            with socket.create_connection((target, port), timeout=self.banner_timeout) as sock:
                sock.sendall(b"\\n")
                banner = sock.recv(1024).decode(errors="ignore").strip()
                return banner if banner else None
        except Exception:
            return None
    
    def _get_tls_info(self, target: str, port: int = 443) -> Dict[str, Any]:
        """Get TLS certificate information.
        
        Args:
            target: Target IP/hostname
            port: HTTPS port (default 443)
            
        Returns:
            TLS certificate information
        """
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=target) as ssock:
                ssock.settimeout(self.banner_timeout)
                ssock.connect((target, port))
                cert = ssock.getpeercert()
                return {
                    "issuer": cert.get("issuer"),
                    "expiry": cert.get("notAfter"),
                    "subject": cert.get("subject")
                }
        except Exception as e:
            return {"error": str(e)}
