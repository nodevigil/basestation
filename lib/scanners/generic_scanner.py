"""
Generic network scanner for basic port scanning and service detection.
"""

import socket
import ssl
from typing import Dict, Any, List, Tuple, Optional
from .base_scanner import BaseScanner


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
    
    def scan(self, target: str, ports: Optional[List[int]] = None, scan_level: int = 1, **kwargs) -> Dict[str, Any]:
        """Perform generic network scan based on scan level.
        
        Args:
            target: IP address or hostname to scan
            ports: List of ports to scan (uses default if not provided)
            scan_level: Scan level (1-3) determining aggressiveness
            **kwargs: Additional scan parameters
            
        Returns:
            Scan results dictionary
        """
        self.logger.debug(f"Starting generic scan of {target} at level {scan_level}")
        
        # Level 1: Light Recon - Top ports, banners
        if scan_level == 1:
            ports = ports or [22, 80, 443, 2375, 3306]  # Top 5 ports
            return self._scan_level_1(target, ports, **kwargs)
        
        # Level 2: Full TCP, service mapping, OS detection
        elif scan_level == 2:
            ports = ports or self.default_ports  # Full default port list
            return self._scan_level_2(target, ports, **kwargs)
        
        # Level 3: Aggressive fingerprinting, fuzz ports
        elif scan_level == 3:
            # Use extended port list for aggressive scanning
            extended_ports = self.default_ports + [8080, 8443, 9000, 9001, 9090, 9091, 9100, 9184]
            ports = ports or extended_ports
            return self._scan_level_3(target, ports, **kwargs)
        
        else:
            raise ValueError(f"Invalid scan_level: {scan_level}. Must be 1, 2, or 3.")
    
    def _scan_level_1(self, target: str, ports: List[int], **kwargs) -> Dict[str, Any]:
        """Level 1: Light recon - basic port scan and banner grab."""
        open_ports = []
        banners = {}
        
        for port in ports:
            if self._is_port_open(target, port):
                open_ports.append(port)
                banner = self._grab_banner(target, port)
                if banner:
                    banners[port] = banner
        
        # Basic TLS info only for 443
        tls_info = {}
        if 443 in open_ports:
            tls_info = self._get_tls_info(target)
        
        return {
            "target": target,
            "scan_level": 1,
            "open_ports": open_ports,
            "banners": banners,
            "tls": tls_info,
            "scanner_type": self.scanner_type
        }
    
    def _scan_level_2(self, target: str, ports: List[int], **kwargs) -> Dict[str, Any]:
        """Level 2: Infrastructure scan - full TCP scan with service detection."""
        open_ports = []
        banners = {}
        services = {}
        
        for port in ports:
            if self._is_port_open(target, port):
                open_ports.append(port)
                banner = self._grab_banner(target, port)
                if banner:
                    banners[port] = banner
                    # Enhanced service detection
                    service = self._detect_service(banner, port)
                    if service:
                        services[port] = service
        
        # TLS info for common HTTPS ports
        tls_info = {}
        for port in [443, 8443]:
            if port in open_ports:
                tls_info[port] = self._get_tls_info(target, port)
        
        # Basic OS fingerprinting based on banners
        os_info = self._fingerprint_os(banners)
        
        return {
            "target": target,
            "scan_level": 2,
            "open_ports": open_ports,
            "banners": banners,
            "services": services,
            "tls": tls_info,
            "os_fingerprint": os_info,
            "scanner_type": self.scanner_type
        }
    
    def _scan_level_3(self, target: str, ports: List[int], **kwargs) -> Dict[str, Any]:
        """Level 3: Deep inspection - aggressive fingerprinting and fuzzing."""
        # Start with level 2 results
        results = self._scan_level_2(target, ports, **kwargs)
        results["scan_level"] = 3
        
        # Additional aggressive techniques
        # Port fuzzing - try additional common ports
        fuzz_ports = [21, 23, 25, 53, 110, 143, 993, 995, 1433, 3389, 5432, 6379, 27017]
        additional_open = []
        
        for port in fuzz_ports:
            if port not in results["open_ports"] and self._is_port_open(target, port):
                additional_open.append(port)
                banner = self._grab_banner(target, port)
                if banner:
                    results["banners"][port] = banner
                    service = self._detect_service(banner, port)
                    if service:
                        results["services"][port] = service
        
        results["open_ports"].extend(additional_open)
        results["fuzzed_ports"] = additional_open
        
        # Enhanced TLS analysis for all HTTPS-capable ports
        for port in results["open_ports"]:
            if port in [443, 8443] or (port in results.get("services", {}) and 
                                      "https" in results["services"][port].lower()):
                if port not in results["tls"]:
                    results["tls"][port] = self._get_tls_info(target, port)
        
        return results
    
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
    
    def _detect_service(self, banner: str, port: int) -> Optional[str]:
        """Detect service type from banner and port.
        
        Args:
            banner: Service banner
            port: Port number
            
        Returns:
            Detected service name or None
        """
        if not banner:
            # Port-based detection
            port_services = {
                21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
                53: "dns", 80: "http", 110: "pop3", 143: "imap",
                443: "https", 993: "imaps", 995: "pop3s",
                1433: "mssql", 3306: "mysql", 3389: "rdp",
                5432: "postgresql", 6379: "redis", 27017: "mongodb",
                2375: "docker", 8080: "http-alt", 8443: "https-alt"
            }
            return port_services.get(port)
        
        banner_lower = banner.lower()
        
        # Banner-based detection
        if "ssh" in banner_lower:
            return "ssh"
        elif "http" in banner_lower or "apache" in banner_lower or "nginx" in banner_lower:
            return "http"
        elif "mysql" in banner_lower:
            return "mysql"
        elif "postgresql" in banner_lower or "postgres" in banner_lower:
            return "postgresql"
        elif "redis" in banner_lower:
            return "redis"
        elif "mongodb" in banner_lower or "mongo" in banner_lower:
            return "mongodb"
        elif "docker" in banner_lower:
            return "docker"
        elif "ftp" in banner_lower:
            return "ftp"
        elif "smtp" in banner_lower:
            return "smtp"
        elif "telnet" in banner_lower:
            return "telnet"
        
        return None
    
    def _fingerprint_os(self, banners: Dict[int, str]) -> Optional[str]:
        """Basic OS fingerprinting from banners.
        
        Args:
            banners: Dictionary of port->banner mappings
            
        Returns:
            OS guess or None
        """
        os_indicators = []
        
        for port, banner in banners.items():
            banner_lower = banner.lower()
            
            if "ubuntu" in banner_lower:
                os_indicators.append("Ubuntu Linux")
            elif "debian" in banner_lower:
                os_indicators.append("Debian Linux")
            elif "centos" in banner_lower or "rhel" in banner_lower:
                os_indicators.append("RedHat Linux")
            elif "windows" in banner_lower or "microsoft" in banner_lower:
                os_indicators.append("Windows")
            elif "linux" in banner_lower:
                os_indicators.append("Linux")
            elif "unix" in banner_lower:
                os_indicators.append("Unix")
        
        # Return most common indication
        if os_indicators:
            return max(set(os_indicators), key=os_indicators.count)
        
        return None
