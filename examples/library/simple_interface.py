#!/usr/bin/env python3
"""
Simple library interface for common use cases

This provides simplified functions for the most common scanning scenarios.
"""

import os
from typing import List, Dict, Optional, Union
from pgdn_scanner.scanners.port_scanner import PortScanner
from pgdn_scanner.scanner import Scanner

class SimplePGDNScanner:
    """Simplified interface for PGDN scanning"""
    
    def __init__(self, timeout: int = 15, use_sudo: bool = False):
        """
        Initialize scanner with basic configuration
        
        Args:
            timeout: Scan timeout in seconds
            use_sudo: Whether to use sudo for faster SYN scans
        """
        self.timeout = timeout
        
        if use_sudo:
            os.environ['USE_SUDO'] = 'true'
        
        self.port_scanner = PortScanner({
            'timeout': timeout,
            'max_threads': 8,
            'nmap_timeout': timeout + 10
        })
        
        self.main_scanner = Scanner()
    
    def scan_ports(self, target: str, ports: Union[List[int], str], 
                   scripts: Optional[str] = None, skip_host_discovery: bool = False) -> Dict:
        """
        Simple port scanning interface
        
        Args:
            target: Target IP or hostname
            ports: List of ports [80, 443] or string "80,443"
            scripts: nmap scripts to run (e.g., "banner,default")
            skip_host_discovery: Use -Pn flag
            
        Returns:
            Dictionary with scan results
        """
        # Convert ports to list if string
        if isinstance(ports, str):
            ports = [int(p.strip()) for p in ports.split(',')]
        
        # Build nmap arguments
        nmap_args = ['-sV']  # Always include version detection
        
        if skip_host_discovery:
            nmap_args.append('-Pn')
        
        if scripts:
            nmap_args.append(f'--script={scripts}')
        
        # Perform scan
        result = self.port_scanner.scan(
            target=target,
            ports=ports,
            nmap_args=nmap_args
        )
        
        # Return simplified result
        return {
            'target': target,
            'open_ports': result.get('open_ports', []),
            'closed_ports': result.get('closed_ports', []),
            'filtered_ports': result.get('filtered_ports', []),
            'scan_summary': result.get('scan_summary', {}),
            'detailed_results': result.get('detailed_results', [])
        }
    
    def scan_database_ports(self, target: str, include_scripts: bool = True) -> Dict:
        """
        Scan common database ports
        
        Args:
            target: Target to scan
            include_scripts: Whether to include nmap scripts
            
        Returns:
            Scan results focused on database security
        """
        db_ports = [3306, 5432, 27017, 6379, 1433, 1521]  # MySQL, PostgreSQL, MongoDB, Redis, MSSQL, Oracle
        
        scripts = "banner,default,vuln" if include_scripts else "banner"
        
        result = self.scan_ports(
            target=target,
            ports=db_ports,
            scripts=scripts,
            skip_host_discovery=True
        )
        
        # Add security analysis
        result['security_analysis'] = self._analyze_database_security(result)
        
        return result
    
    def scan_web_ports(self, target: str, include_http_info: bool = True) -> Dict:
        """
        Scan web-related ports
        
        Args:
            target: Target to scan
            include_http_info: Include HTTP-specific information
            
        Returns:
            Web-focused scan results
        """
        web_ports = [80, 443, 8080, 8443, 8000, 9000]
        
        scripts = "http-title,http-headers,ssl-cert" if include_http_info else "banner"
        
        result = self.scan_ports(
            target=target,
            ports=web_ports,
            scripts=scripts
        )
        
        # Add web-specific analysis
        result['web_analysis'] = self._analyze_web_services(result)
        
        return result
    
    def quick_scan(self, target: str) -> Dict:
        """
        Quick scan of most common ports
        
        Args:
            target: Target to scan
            
        Returns:
            Quick scan results
        """
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389]
        
        return self.scan_ports(
            target=target,
            ports=common_ports,
            scripts="banner",
            skip_host_discovery=False
        )
    
    def comprehensive_scan(self, target: str) -> Dict:
        """
        Comprehensive security scan
        
        Args:
            target: Target to scan
            
        Returns:
            Comprehensive scan results
        """
        # Combine multiple port categories
        all_ports = [
            # Web
            80, 443, 8080, 8443, 8000, 9000,
            # Remote Access  
            22, 23, 3389, 5900,
            # Mail
            25, 110, 143, 993, 995,
            # Databases
            3306, 5432, 27017, 6379, 1433,
            # Other services
            21, 53, 135, 139, 445, 2375, 5985
        ]
        
        result = self.scan_ports(
            target=target,
            ports=all_ports,
            scripts="banner,default,vuln",
            skip_host_discovery=True
        )
        
        # Add comprehensive analysis
        result['security_assessment'] = self._comprehensive_security_analysis(result)
        
        return result
    
    def _analyze_database_security(self, result: Dict) -> Dict:
        """Analyze database port security"""
        analysis = {
            'risk_level': 'LOW',
            'exposed_databases': [],
            'filtered_databases': [],
            'recommendations': []
        }
        
        db_port_names = {
            3306: 'MySQL',
            5432: 'PostgreSQL', 
            27017: 'MongoDB',
            6379: 'Redis',
            1433: 'MSSQL',
            1521: 'Oracle'
        }
        
        open_db_ports = result.get('open_ports', [])
        filtered_db_ports = result.get('filtered_ports', [])
        
        # Check for exposed databases
        for port in open_db_ports:
            if port in db_port_names:
                analysis['exposed_databases'].append(f"{db_port_names[port]} ({port})")
                analysis['risk_level'] = 'HIGH'
        
        # Check for filtered databases (good)
        for port in filtered_db_ports:
            if port in db_port_names:
                analysis['filtered_databases'].append(f"{db_port_names[port]} ({port})")
        
        # Generate recommendations
        if analysis['exposed_databases']:
            analysis['recommendations'].append("Exposed database ports found - implement firewall rules")
            analysis['recommendations'].append("Ensure strong authentication is configured")
        
        if analysis['filtered_databases']:
            analysis['recommendations'].append("Good: Some database ports are properly firewalled")
        
        return analysis
    
    def _analyze_web_services(self, result: Dict) -> Dict:
        """Analyze web service security"""
        analysis = {
            'web_servers': [],
            'ssl_enabled': [],
            'recommendations': []
        }
        
        open_ports = result.get('open_ports', [])
        
        # Check for web services
        if 80 in open_ports:
            analysis['web_servers'].append('HTTP (80)')
        if 443 in open_ports:
            analysis['web_servers'].append('HTTPS (443)')
            analysis['ssl_enabled'].append(443)
        
        # Check alternative web ports
        alt_web_ports = [8080, 8443, 8000, 9000]
        for port in open_ports:
            if port in alt_web_ports:
                analysis['web_servers'].append(f'HTTP Alternative ({port})')
                if port in [8443]:
                    analysis['ssl_enabled'].append(port)
        
        # Recommendations
        if 80 in open_ports and 443 not in open_ports:
            analysis['recommendations'].append("Only HTTP found - consider enabling HTTPS")
        
        if analysis['ssl_enabled']:
            analysis['recommendations'].append("SSL/TLS enabled - verify certificate configuration")
        
        return analysis
    
    def _comprehensive_security_analysis(self, result: Dict) -> Dict:
        """Comprehensive security analysis"""
        analysis = {
            'overall_risk': 'LOW',
            'service_categories': {},
            'security_issues': [],
            'positive_findings': []
        }
        
        open_ports = result.get('open_ports', [])
        filtered_ports = result.get('filtered_ports', [])
        
        # Categorize services
        categories = {
            'web': [80, 443, 8080, 8443, 8000, 9000],
            'remote_access': [22, 23, 3389, 5900],
            'databases': [3306, 5432, 27017, 6379, 1433],
            'mail': [25, 110, 143, 993, 995],
            'file_sharing': [21, 139, 445],
            'other': []
        }
        
        for port in open_ports:
            categorized = False
            for category, port_list in categories.items():
                if port in port_list:
                    if category not in analysis['service_categories']:
                        analysis['service_categories'][category] = []
                    analysis['service_categories'][category].append(port)
                    categorized = True
                    break
            
            if not categorized:
                analysis['service_categories'].setdefault('other', []).append(port)
        
        # Risk assessment
        if analysis['service_categories'].get('databases'):
            analysis['overall_risk'] = 'HIGH'
            analysis['security_issues'].append("Database ports are exposed")
        
        if analysis['service_categories'].get('remote_access'):
            if analysis['overall_risk'] == 'LOW':
                analysis['overall_risk'] = 'MEDIUM'
            analysis['security_issues'].append("Remote access ports are open")
        
        # Positive findings
        if len(filtered_ports) > len(open_ports):
            analysis['positive_findings'].append("More ports are filtered than open (good firewall)")
        
        if analysis['service_categories'].get('web') and 443 in analysis['service_categories']['web']:
            analysis['positive_findings'].append("HTTPS is enabled")
        
        return analysis

# Convenience functions for one-liner usage
def quick_port_scan(target: str, ports: Union[List[int], str], use_sudo: bool = False) -> Dict:
    """Quick port scan - one function call"""
    scanner = SimplePGDNScanner(use_sudo=use_sudo)
    return scanner.scan_ports(target, ports)

def scan_databases(target: str, use_sudo: bool = False) -> Dict:
    """Quick database port scan"""
    scanner = SimplePGDNScanner(use_sudo=use_sudo)
    return scanner.scan_database_ports(target)

def security_audit(target: str, use_sudo: bool = False) -> Dict:
    """Complete security audit"""
    scanner = SimplePGDNScanner(use_sudo=use_sudo)
    return scanner.comprehensive_scan(target)

# Example usage
if __name__ == "__main__":
    print("Simple PGDN Scanner Interface Examples")
    print("=" * 50)
    
    target = "scanme.nmap.org"
    
    # Example 1: Quick port scan
    print("\\n1. Quick port scan:")
    result = quick_port_scan(target, "22,80,443,3306")
    print(f"   Open: {result['open_ports']}")
    print(f"   Filtered: {result['filtered_ports']}")
    
    # Example 2: Database security check
    print("\\n2. Database security check:")
    db_result = scan_databases(target)
    security = db_result.get('security_analysis', {})
    print(f"   Risk Level: {security.get('risk_level', 'UNKNOWN')}")
    if security.get('exposed_databases'):
        print(f"   Exposed: {security['exposed_databases']}")
    
    # Example 3: Using the class interface
    print("\\n3. Class interface example:")
    scanner = SimplePGDNScanner(timeout=10, use_sudo=False)
    
    web_result = scanner.scan_web_ports(target)
    web_analysis = web_result.get('web_analysis', {})
    if web_analysis.get('web_servers'):
        print(f"   Web servers: {web_analysis['web_servers']}")
    
    print("\\nSimple interface examples completed!")