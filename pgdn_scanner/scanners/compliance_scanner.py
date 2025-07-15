"""
Compliance Scanner for DePIN Validators
Focuses on dangerous/exposed services rather than comprehensive discovery.
"""

import subprocess
import xml.etree.ElementTree as ET
import logging
import json
import sys
import os
import concurrent.futures
import socket
import time
from typing import Dict, List, Any, Optional

from .base_scanner import BaseScanner
from ..core.logging import get_logger

logger = get_logger(__name__)

# Dangerous ports that should NOT be open on validator nodes
DANGEROUS_PORTS = {
    # Database access (should be internal only)
    3306: {"service": "MySQL", "risk": "CRITICAL", "reason": "Database exposed to internet"},
    5432: {"service": "PostgreSQL", "risk": "CRITICAL", "reason": "Database exposed to internet"},
    6379: {"service": "Redis", "risk": "CRITICAL", "reason": "In-memory database exposed"},
    27017: {"service": "MongoDB", "risk": "CRITICAL", "reason": "NoSQL database exposed"},
    1433: {"service": "MSSQL", "risk": "CRITICAL", "reason": "Database exposed to internet"},
    5984: {"service": "CouchDB", "risk": "HIGH", "reason": "Document database exposed"},
    
    # Container/orchestration APIs
    2375: {"service": "Docker API", "risk": "CRITICAL", "reason": "Unencrypted Docker daemon"},
    2376: {"service": "Docker API TLS", "risk": "HIGH", "reason": "Docker daemon with TLS (check certs)"},
    4243: {"service": "Docker API Alt", "risk": "CRITICAL", "reason": "Alternative Docker API port"},
    8080: {"service": "Kubernetes/Jenkins", "risk": "HIGH", "reason": "Often admin interfaces"},
    10250: {"service": "Kubelet", "risk": "CRITICAL", "reason": "Kubernetes node agent API"},
    
    # Admin/management interfaces
    8888: {"service": "Admin Interface", "risk": "HIGH", "reason": "Common admin panel port"},
    9090: {"service": "Prometheus/Admin", "risk": "MEDIUM", "reason": "Monitoring interface exposed"},
    3000: {"service": "Grafana/Dev", "risk": "MEDIUM", "reason": "Dashboard or dev server"},
    8081: {"service": "Admin Interface", "risk": "MEDIUM", "reason": "Alternative admin port"},
    8443: {"service": "HTTPS Admin", "risk": "MEDIUM", "reason": "Admin interface over HTTPS"},
    
    # File sharing/transfer
    21: {"service": "FTP", "risk": "HIGH", "reason": "Unencrypted file transfer"},
    20: {"service": "FTP Data", "risk": "HIGH", "reason": "FTP data channel"},
    69: {"service": "TFTP", "risk": "HIGH", "reason": "Trivial file transfer"},
    139: {"service": "NetBIOS", "risk": "HIGH", "reason": "Windows file sharing"},
    445: {"service": "SMB", "risk": "HIGH", "reason": "Windows file sharing"},
    2049: {"service": "NFS", "risk": "MEDIUM", "reason": "Network file system"},
    
    # Remote access (often misconfigured)
    23: {"service": "Telnet", "risk": "CRITICAL", "reason": "Unencrypted remote access"},
    512: {"service": "rexec", "risk": "CRITICAL", "reason": "Remote execution service"},
    513: {"service": "rlogin", "risk": "CRITICAL", "reason": "Remote login service"},
    514: {"service": "rsh", "risk": "CRITICAL", "reason": "Remote shell service"},
    5900: {"service": "VNC", "risk": "HIGH", "reason": "Remote desktop access"},
    3389: {"service": "RDP", "risk": "HIGH", "reason": "Windows remote desktop"},
    
    # Email (rarely needed on validators)
    25: {"service": "SMTP", "risk": "MEDIUM", "reason": "Mail server exposed"},
    110: {"service": "POP3", "risk": "MEDIUM", "reason": "Email retrieval service"},
    143: {"service": "IMAP", "risk": "MEDIUM", "reason": "Email access service"},
    993: {"service": "IMAPS", "risk": "MEDIUM", "reason": "Secure email access"},
    995: {"service": "POP3S", "risk": "MEDIUM", "reason": "Secure email retrieval"},
    
    # Deprecated/vulnerable services
    79: {"service": "Finger", "risk": "HIGH", "reason": "User information service"},
    111: {"service": "RPCbind", "risk": "HIGH", "reason": "RPC port mapper"},
    135: {"service": "RPC Endpoint", "risk": "HIGH", "reason": "Windows RPC endpoint"},
    1900: {"service": "UPnP", "risk": "MEDIUM", "reason": "Universal Plug and Play"},
    
    # Development/debug services
    4444: {"service": "Debug/Dev", "risk": "HIGH", "reason": "Common debug port"},
    5555: {"service": "Debug/Dev", "risk": "HIGH", "reason": "Common debug port"},
    8000: {"service": "Dev Server", "risk": "MEDIUM", "reason": "Development web server"},
    8001: {"service": "Dev Server", "risk": "MEDIUM", "reason": "Development web server"},
    9001: {"service": "Debug Interface", "risk": "MEDIUM", "reason": "Supervisord or debug interface"},
    
    # Message queues (should be internal)
    5672: {"service": "RabbitMQ", "risk": "HIGH", "reason": "Message queue exposed"},
    15672: {"service": "RabbitMQ Management", "risk": "HIGH", "reason": "RabbitMQ admin interface"},
    9092: {"service": "Kafka", "risk": "HIGH", "reason": "Message streaming platform"},
    4369: {"service": "Erlang Port Mapper", "risk": "MEDIUM", "reason": "Erlang/RabbitMQ discovery"},
    
    # Backup/sync services
    873: {"service": "rsync", "risk": "MEDIUM", "reason": "File synchronization service"},
    548: {"service": "AFP", "risk": "MEDIUM", "reason": "Apple file sharing"},
    
    # Gaming/P2P (suspicious on validators)
    6881: {"service": "BitTorrent", "risk": "HIGH", "reason": "P2P file sharing"},
    6969: {"service": "BitTorrent Tracker", "risk": "HIGH", "reason": "P2P tracker"},
    
    # Misc dangerous services
    1723: {"service": "PPTP VPN", "risk": "HIGH", "reason": "Weak VPN protocol"},
    161: {"service": "SNMP", "risk": "MEDIUM", "reason": "Network monitoring (often default creds)"},
    162: {"service": "SNMP Trap", "risk": "MEDIUM", "reason": "SNMP notifications"},
    623: {"service": "IPMI", "risk": "HIGH", "reason": "Server management interface"},
}


class ComplianceScanner(BaseScanner):
    """Fast compliance scanner focusing on dangerous ports."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.fast_timeout = self.config.get('fast_timeout', 2.0)
        self.nmap_timeout = self.config.get('nmap_timeout', 25)  # Increased from 15
        self.max_workers = self.config.get('max_workers', 50)
    
    @property
    def scanner_type(self) -> str:
        """Return the type of scanner."""
        return "compliance"
    
    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Perform compliance scan on target.
        
        Args:
            target: Target IP address or hostname
            **kwargs: Additional scan parameters
            
        Returns:
            dict: Compliance scan results
        """
        self.logger.info(f"Starting compliance scan of {target}")
        
        # Perform the actual compliance scan
        result = self._compliance_scan(target, self.fast_timeout, self.nmap_timeout)
        
        # Add compliance score
        result["compliance_score"] = self._calculate_compliance_score(result)
        
        # Add scanner metadata
        result.update({
            "scanner_type": self.scanner_type,
            "scan_level": kwargs.get("scan_level", 1),
            "target": target
        })
        
        return result
    
    def _fast_tcp_check(self, ip: str, port: int, timeout: float = 2.0) -> bool:
        """Fast TCP connection check using socket."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _parallel_port_scan(self, ip: str, ports: List[int], max_workers: int = 50, timeout: float = 2.0) -> List[int]:
        """Scan multiple ports in parallel using threading."""
        open_ports = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all port checks
            future_to_port = {
                executor.submit(self._fast_tcp_check, ip, port, timeout): port 
                for port in ports
            }
            
            # Collect results
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        open_ports.append(port)
                        self.logger.info(f"Port {port} open on {ip}")
                except Exception as e:
                    self.logger.debug(f"Error checking port {port}: {e}")
        
        return sorted(open_ports)
    
    def _nmap_detailed_scan(self, ip: str, open_ports: List[int], timeout: int = 25) -> Dict[str, Any]:
        """Run detailed nmap scan on only the open dangerous ports."""
        if not open_ports:
            return {"ip": ip, "ports": []}
        
        ports_str = ",".join(map(str, open_ports))
        
        # Use nmap for service detection on confirmed open ports
        # More conservative settings to avoid timeouts
        cmd = [
            "nmap", 
            "-T3",  # Normal timing (T4 can be too aggressive)
            "-p", ports_str,
            "-sV",  # Version detection
            "--version-intensity", "2",  # Light intensity to avoid hangs
            "--max-retries", "1",  # Don't retry failed probes
            "-sS" if hasattr(os, 'geteuid') and os.geteuid() == 0 else "-sT",  # SYN scan if root, else connect
            "-oX", "-",
            ip
        ]
        
        try:
            self.logger.info(f"Running detailed nmap on {len(open_ports)} open ports: {ports_str}")
            result = subprocess.run(cmd, capture_output=True, timeout=timeout, text=True)
            
            if result.returncode != 0:
                self.logger.warning(f"Nmap stderr: {result.stderr}")
                # Don't treat non-zero return as hard error - nmap often returns 1 for various reasons
            
            if not result.stdout.strip():
                self.logger.warning("Nmap returned no XML output")
                # Fall back to basic port info from our socket scan
                basic_ports = [{"port": p, "state": "open", "service": "unknown", "product": "", "version": ""} for p in open_ports]
                return {"ip": ip, "ports": basic_ports, "warning": "No nmap output, using basic port info"}
            
            # Parse XML output
            try:
                root = ET.fromstring(result.stdout)
            except ET.ParseError as e:
                self.logger.warning(f"XML parse error: {e}")
                # Fall back to basic port info
                basic_ports = [{"port": p, "state": "open", "service": "unknown", "product": "", "version": ""} for p in open_ports]
                return {"ip": ip, "ports": basic_ports, "warning": "XML parse failed, using basic port info"}
            
            parsed_ports = []
            
            for host in root.findall('host'):
                ports_elem = host.find('ports')
                if ports_elem is not None:
                    for port in ports_elem.findall('port'):
                        port_id = int(port.get('portid'))
                        state_elem = port.find('state')
                        state = state_elem.get('state') if state_elem is not None else 'unknown'
                        
                        service_elem = port.find('service')
                        service_info = {
                            "service": "unknown",
                            "product": "",
                            "version": "",
                            "extrainfo": ""
                        }
                        
                        if service_elem is not None:
                            service_info.update({
                                "service": service_elem.get('name', 'unknown'),
                                "product": service_elem.get('product', ''),
                                "version": service_elem.get('version', ''),
                                "extrainfo": service_elem.get('extrainfo', '')
                            })
                        
                        parsed_ports.append({
                            "port": port_id,
                            "state": state,
                            **service_info
                        })
            
            # If no ports found in XML but we know they're open, use basic info
            if not parsed_ports and open_ports:
                self.logger.warning("Nmap XML contained no ports but socket scan found open ports")
                basic_ports = [{"port": p, "state": "open", "service": "unknown", "product": "", "version": ""} for p in open_ports]
                return {"ip": ip, "ports": basic_ports, "warning": "Nmap found no services, using socket scan results"}
            
            return {"ip": ip, "ports": parsed_ports}
            
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Nmap detailed scan timed out after {timeout}s for {ip}, using basic port info")
            # Don't fail - just use the basic port info from our socket scan
            basic_ports = [{"port": p, "state": "open", "service": "unknown", "product": "", "version": ""} for p in open_ports]
            return {"ip": ip, "ports": basic_ports, "warning": f"Nmap timed out after {timeout}s"}
        except FileNotFoundError:
            self.logger.warning("Nmap not found, using basic port info")
            basic_ports = [{"port": p, "state": "open", "service": "unknown", "product": "", "version": ""} for p in open_ports]
            return {"ip": ip, "ports": basic_ports, "warning": "Nmap not installed"}
        except Exception as e:
            self.logger.warning(f"Nmap detailed scan failed: {e}, using basic port info")
            basic_ports = [{"port": p, "state": "open", "service": "unknown", "product": "", "version": ""} for p in open_ports]
            return {"ip": ip, "ports": basic_ports, "warning": f"Nmap failed: {str(e)}"}
    
    def _compliance_scan(self, ip: str, fast_timeout: float = 2.0, nmap_timeout: int = 25) -> Dict[str, Any]:
        """
        Fast compliance scan focusing on dangerous ports.
        
        Two-stage process:
        1. Fast parallel socket scan of dangerous ports
        2. Detailed nmap scan of confirmed open ports
        """
        start_time = time.time()
        self.logger.info(f"Starting compliance scan of {ip}")
        
        # Stage 1: Fast parallel scan of dangerous ports
        dangerous_port_list = list(DANGEROUS_PORTS.keys())
        self.logger.info(f"Fast scanning {len(dangerous_port_list)} dangerous ports...")
        
        open_ports = self._parallel_port_scan(ip, dangerous_port_list, timeout=fast_timeout)
        
        if not open_ports:
            scan_time = time.time() - start_time
            self.logger.info(f"No dangerous ports found on {ip} (scan took {scan_time:.1f}s)")
            return {
                "ip": ip,
                "scan_time_seconds": round(scan_time, 1),
                "dangerous_ports_found": 0,
                "findings": [],
                "compliance_status": "PASS"
            }
        
        # Stage 2: Detailed nmap scan of open ports
        self.logger.info(f"Found {len(open_ports)} open dangerous ports, running detailed scan...")
        detailed_results = self._nmap_detailed_scan(ip, open_ports, timeout=nmap_timeout)
        
        # Analyze findings - now works with both successful nmap and fallback data
        findings = []
        for port_info in detailed_results.get("ports", []):
            if port_info["state"] == "open":
                port_num = port_info["port"]
                danger_info = DANGEROUS_PORTS.get(port_num, {})
                
                finding = {
                    "port": port_num,
                    "service": port_info.get("service", "unknown"),
                    "product": port_info.get("product", ""),
                    "version": port_info.get("version", ""),
                    "risk_level": danger_info.get("risk", "UNKNOWN"),
                    "expected_service": danger_info.get("service", "Unknown"),
                    "security_concern": danger_info.get("reason", "Unexpected open port"),
                    "recommendation": f"Close port {port_num} or restrict access"
                }
                findings.append(finding)
        
        scan_time = time.time() - start_time
        compliance_status = "FAIL" if findings else "PASS"
        
        self.logger.info(f"Compliance scan completed in {scan_time:.1f}s - {compliance_status}")
        
        return {
            "ip": ip,
            "scan_time_seconds": round(scan_time, 1),
            "dangerous_ports_found": len(findings),
            "findings": findings,
            "compliance_status": compliance_status,
            "scan_warning": detailed_results.get("warning")  # Changed from "nmap_error"
        }
    
    def _calculate_compliance_score(self, scan_result: Dict[str, Any]) -> float:
        """Calculate compliance score based on findings."""
        if scan_result["compliance_status"] == "PASS":
            return 100.0
        
        score = 100.0
        for finding in scan_result["findings"]:
            risk_penalties = {
                "CRITICAL": 30,
                "HIGH": 15, 
                "MEDIUM": 8,
                "LOW": 3
            }
            penalty = risk_penalties.get(finding["risk_level"], 10)
            score -= penalty
        
        return max(0.0, score)
    
    def bulk_compliance_scan(self, ip_list: List[str], **kwargs) -> List[Dict[str, Any]]:
        """Scan multiple IPs for compliance."""
        results = []
        for ip in ip_list:
            result = self.scan(ip, **kwargs)
            results.append(result)
        return results


# # Standalone execution for testing
# if __name__ == "__main__":
#     import logging
#     logging.basicConfig(
#         format="%(asctime)s %(levelname)s: %(message)s",
#         level=logging.INFO
#     )
    
#     if len(sys.argv) < 2:
#         print("Usage: python compliance_scanner.py <ip> [fast_timeout] [nmap_timeout]")
#         print("Examples:")
#         print("  python compliance_scanner.py 45.250.254.151")
#         print("  python compliance_scanner.py 45.250.254.151 1.0 20")
#         print()
#         print("This scanner focuses on dangerous ports that shouldn't be open on validators.")
#         print(f"Checking {len(DANGEROUS_PORTS)} dangerous ports including:")
#         print("  - Database services (MySQL, PostgreSQL, Redis, MongoDB)")
#         print("  - Container APIs (Docker, Kubernetes)")
#         print("  - Admin interfaces and development servers")
#         print("  - File sharing and remote access services")
#         sys.exit(1)
    
#     # Simple test without BaseScanner
#     class MockConfig:
#         def get(self, key, default=None):
#             return default
    
#     config = MockConfig()
#     scanner = ComplianceScanner(config)
    
#     ip = sys.argv[1]
#     fast_timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 2.0
#     nmap_timeout = int(sys.argv[3]) if len(sys.argv) > 3 else 25
    
#     result = scanner.scan(ip, fast_timeout=fast_timeout, nmap_timeout=nmap_timeout)
    
#     print(json.dumps(result, indent=2))
    
#     # Print summary
#     if result["compliance_status"] == "PASS":
#         print(f"\n✅ COMPLIANCE PASS - Score: {result['compliance_score']}/100")
#     else:
#         print(f"\n❌ COMPLIANCE FAIL - Score: {result['compliance_score']}/100")
#         print(f"Found {result['dangerous_ports_found']} dangerous open ports:")
#         for finding in result["findings"]:
#             risk_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}
#             emoji = risk_emoji.get(finding["risk_level"], "⚪")
#             print(f"  {emoji} Port {finding['port']}: {finding['security_concern']}")
