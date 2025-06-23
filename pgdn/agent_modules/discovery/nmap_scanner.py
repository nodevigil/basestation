"""
Nmap Scanner - Handles network scanning with fallback
"""

import subprocess
import socket
import logging
import xml.etree.ElementTree as ET
from typing import Dict


class NmapScanner:
    """Handles nmap scanning and result parsing"""
    
    @staticmethod
    def scan_host(hostname: str) -> Dict:
        """Perform nmap scan with fallback"""
        cmd = [
            'nmap', '-sS', '-sV', 
            '--script=http-enum,ssl-cert,banner',
            '-p1-1000',
            '--max-retries=1',
            '--host-timeout=120s',
            '--max-rtt-timeout=1000ms',
            '-oX', '-',
            hostname
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.stdout.strip() and '<?xml' in result.stdout:
                return NmapScanner._parse_nmap_output(result.stdout)
            else:
                return NmapScanner._fallback_scan(hostname)
                
        except (subprocess.TimeoutExpired, Exception) as e:
            logging.error(f"Nmap scan failed for {hostname}: {e}")
            return NmapScanner._fallback_scan(hostname)
    
    @staticmethod
    def _fallback_scan(hostname: str) -> Dict:
        """Simple port scan fallback"""
        try:
            common_ports = [22, 80, 443, 8080, 8443, 9000, 9100, 3000, 5000]
            open_ports = []
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((hostname, port))
                    if result == 0:
                        open_ports.append(port)
                    sock.close()
                except:
                    continue
            
            return {
                'ports': open_ports,
                'services': {},
                'os': None,
                'scripts': {},
                'fallback_scan': True
            }
        except Exception as e:
            logging.error(f"Fallback scan failed: {e}")
            return {'ports': [], 'services': {}, 'os': None, 'scripts': {}, 'scan_error': str(e)}
    
    @staticmethod
    def _parse_nmap_output(xml_output: str) -> Dict:
        """Parse nmap XML output"""
        try:
            xml_output = xml_output.strip()
            if not xml_output.startswith('<?xml'):
                return {}
            
            root = ET.fromstring(xml_output)
            result = {'ports': [], 'services': {}, 'os': None, 'scripts': {}}
            
            for host in root.findall('.//host'):
                for port in host.findall('.//port'):
                    port_num = port.get('portid')
                    protocol = port.get('protocol', 'tcp')
                    state = port.find('state')
                    service = port.find('service')
                    
                    if state is not None and state.get('state') == 'open' and port_num:
                        try:
                            port_int = int(port_num)
                            result['ports'].append(port_int)
                            
                            if service is not None:
                                result['services'][port_int] = {
                                    'name': service.get('name', ''),
                                    'product': service.get('product', ''),
                                    'version': service.get('version', ''),
                                    'banner': service.get('banner', ''),
                                    'protocol': protocol
                                }
                        except ValueError:
                            continue
            
            result['ports'] = sorted(list(set(result['ports'])))
            return result
            
        except Exception as e:
            logging.error(f"Failed to parse nmap output: {e}")
            return {}