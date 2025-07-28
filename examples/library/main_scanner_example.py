#!/usr/bin/env python3
"""
Example: Using the main Scanner class as a library

This shows how to use the main Scanner class that orchestrates multiple scanners
including the enhanced port scanner.
"""

import json
from pgdn_scanner.scanner import Scanner
from pgdn_scanner.core.config import Config

def basic_scanner_usage():
    """Basic usage of the main Scanner class"""
    print("=== Basic Scanner Usage ===")
    
    # Create scanner instance
    scanner = Scanner()
    
    # Perform port scan using the main scanner interface
    result = scanner.scan(
        target="scanme.nmap.org",
        run="port_scan",
        port="80,443,22,3306",  # Comma-separated string
        nmap_args="-sV -Pn"
    )
    
    if result.is_success():
        data = result.data
        print(f"Scan completed successfully!")
        print(f"Open ports: {data.get('open_ports', [])}")
        print(f"Closed ports: {data.get('closed_ports', [])}")
        print(f"Filtered ports: {data.get('filtered_ports', [])}")
    else:
        print(f"Scan failed: {result.error}")

def advanced_scanner_with_config():
    """Using Scanner with custom configuration"""
    print("\\n=== Advanced Scanner with Config ===")
    
    # Create custom configuration
    config_data = {
        "scanning": {
            "timeout": 20,
            "max_threads": 8,
            "nmap_timeout": 30
        }
    }
    
    config = Config.from_dict(config_data)
    scanner = Scanner(config)
    
    # Your original command equivalent
    result = scanner.scan(
        target="fullnode.mainnet.sui.io",
        run="port_scan", 
        port="3306,5432,27017,6379",
        nmap_args="-sS -sV -Pn --script=banner,default",
        debug=True
    )
    
    if result.is_success():
        data = result.data
        
        print(f"\\nDatabase port scan results:")
        
        # Check for concerning open database ports
        open_db_ports = data.get('open_ports', [])
        if open_db_ports:
            print(f"⚠️  EXPOSED database ports: {open_db_ports}")
            
            # Show detailed info for each open port
            for port_info in data.get('detailed_results', []):
                if port_info['port'] in open_db_ports:
                    port = port_info['port']
                    service = port_info.get('service', 'unknown')
                    banner = port_info.get('banner', '')
                    
                    print(f"\\n  Port {port} ({service}):")
                    if banner:
                        print(f"    Banner: {banner[:80]}...")
                    
                    # Show nmap script results if available
                    nmap_results = port_info.get('nmap_results', {})
                    if nmap_results.get('raw_output'):
                        lines = nmap_results['raw_output'].split('\\n')
                        script_lines = [l for l in lines if 'script' in l.lower() or '|' in l]
                        if script_lines:
                            print(f"    Script results: {script_lines[0][:80]}...")
        
        # Show filtered ports (good security practice)
        filtered_ports = data.get('filtered_ports', [])
        if filtered_ports:
            print(f"\\n🔒 Filtered (firewalled) ports: {filtered_ports}")
            print("   This indicates proper firewall configuration")
        
        # Summary statistics
        summary = data.get('scan_summary', {})
        print(f"\\n📊 Scan Summary:")
        print(f"   Total ports scanned: {summary.get('total_ports', 0)}")
        print(f"   Open: {summary.get('open_ports', 0)}")
        print(f"   Closed: {summary.get('closed_ports', 0)}")
        print(f"   Filtered: {summary.get('filtered_ports', 0)}")
        print(f"   Average confidence: {summary.get('average_confidence', 0):.1f}%")
    
    else:
        print(f"Scan failed: {result.error}")

def multiple_scan_types():
    """Example using different scan types"""
    print("\\n=== Multiple Scan Types ===")
    
    scanner = Scanner()
    target = "scanme.nmap.org"
    
    # Different scan types available
    scan_configs = [
        {
            "name": "Port Scan",
            "run": "port_scan",
            "port": "80,443,22",
            "nmap_args": "-sV"
        },
        {
            "name": "Web Scan", 
            "run": "web"
        },
        {
            "name": "SSL Test",
            "run": "ssl_test"
        }
    ]
    
    results = {}
    
    for scan_config in scan_configs:
        name = scan_config.pop("name")
        print(f"\\nRunning {name}...")
        
        try:
            result = scanner.scan(target=target, **scan_config)
            
            if result.is_success():
                results[name] = result.data
                print(f"  ✅ {name} completed")
                
                # Show relevant info based on scan type
                if scan_config.get("run") == "port_scan":
                    data = result.data
                    print(f"     Open: {data.get('open_ports', [])}")
                    print(f"     Filtered: {data.get('filtered_ports', [])}")
                
            else:
                print(f"  ❌ {name} failed: {result.error}")
                results[name] = {"error": result.error}
                
        except Exception as e:
            print(f"  ❌ {name} error: {e}")
            results[name] = {"error": str(e)}
    
    return results

def custom_port_analysis():
    """Custom analysis of port scan results"""
    print("\\n=== Custom Port Analysis ===")
    
    scanner = Scanner()
    
    # Scan common service ports
    result = scanner.scan(
        target="scanme.nmap.org",
        run="port_scan",
        port="21,22,23,25,53,80,110,143,443,993,995,3389",
        nmap_args="-sV -Pn --script=banner"
    )
    
    if not result.is_success():
        print(f"Scan failed: {result.error}")
        return
    
    data = result.data
    
    # Custom analysis
    service_analysis = {
        "web_services": [],
        "mail_services": [], 
        "remote_access": [],
        "databases": [],
        "other": []
    }
    
    # Categorize open ports
    for port_info in data.get('detailed_results', []):
        if not port_info.get('is_open'):
            continue
            
        port = port_info['port']
        service = port_info.get('service', 'unknown')
        
        if port in [80, 443]:
            service_analysis["web_services"].append(f"{port}/{service}")
        elif port in [25, 110, 143, 993, 995]:
            service_analysis["mail_services"].append(f"{port}/{service}")
        elif port in [22, 23, 3389]:
            service_analysis["remote_access"].append(f"{port}/{service}")
        elif port in [3306, 5432, 27017, 6379]:
            service_analysis["databases"].append(f"{port}/{service}")
        else:
            service_analysis["other"].append(f"{port}/{service}")
    
    # Print analysis
    print("\\n🔍 Service Analysis:")
    for category, services in service_analysis.items():
        if services:
            print(f"  {category.replace('_', ' ').title()}: {', '.join(services)}")
    
    # Security recommendations
    print("\\n🛡️  Security Recommendations:")
    if service_analysis["databases"]:
        print("  ⚠️  Database ports are open - ensure proper authentication")
    if service_analysis["remote_access"]:
        print("  🔐 Remote access ports detected - use key-based auth")
    
    filtered_count = len(data.get('filtered_ports', []))
    if filtered_count > 0:
        print(f"  ✅ {filtered_count} ports are properly filtered by firewall")

def integration_example():
    """Example of integrating scanner into larger application"""
    print("\\n=== Integration Example ===")
    
    class SecurityAuditor:
        def __init__(self):
            self.scanner = Scanner({
                "scanning": {
                    "timeout": 15,
                    "max_threads": 6
                }
            })
            
        def audit_target(self, target, ports=None):
            """Perform security audit on target"""
            if ports is None:
                ports = "22,80,443,3306,5432,27017,6379,3389"
            
            print(f"🔍 Auditing {target}...")
            
            # Perform comprehensive port scan
            result = self.scanner.scan(
                target=target,
                run="port_scan",
                port=ports,
                nmap_args="-sS -sV -Pn --script=banner,vuln",
                skip_nmap=False
            )
            
            if not result.is_success():
                return {"error": result.error}
            
            data = result.data
            
            # Generate security report
            report = {
                "target": target,
                "timestamp": data.get('timestamp'),
                "risk_level": self._calculate_risk(data),
                "findings": self._analyze_findings(data),
                "recommendations": self._get_recommendations(data)
            }
            
            return report
        
        def _calculate_risk(self, data):
            """Calculate risk level based on open ports"""
            open_ports = data.get('open_ports', [])
            
            high_risk_ports = [3306, 5432, 27017, 6379, 3389]  # Databases, RDP
            medium_risk_ports = [22, 23, 21]  # Remote access, FTP
            
            high_risk_count = len([p for p in open_ports if p in high_risk_ports])
            medium_risk_count = len([p for p in open_ports if p in medium_risk_ports])
            
            if high_risk_count > 0:
                return "HIGH"
            elif medium_risk_count > 1:
                return "MEDIUM" 
            elif len(open_ports) > 5:
                return "MEDIUM"
            else:
                return "LOW"
        
        def _analyze_findings(self, data):
            """Analyze scan findings"""
            findings = []
            
            for port_info in data.get('detailed_results', []):
                if port_info.get('is_open'):
                    port = port_info['port']
                    service = port_info.get('service', 'unknown')
                    version = port_info.get('version', '')
                    
                    finding = f"Port {port} ({service})"
                    if version:
                        finding += f" version {version}"
                    finding += " is open"
                    
                    findings.append(finding)
            
            return findings
        
        def _get_recommendations(self, data):
            """Generate security recommendations"""
            recommendations = []
            
            open_ports = data.get('open_ports', [])
            filtered_ports = data.get('filtered_ports', [])
            
            if 3306 in open_ports:
                recommendations.append("MySQL port is open - ensure strong authentication")
            if 5432 in open_ports:
                recommendations.append("PostgreSQL port is open - verify access controls")
            if 22 in open_ports:
                recommendations.append("SSH is open - use key-based authentication")
            
            if len(filtered_ports) > 0:
                recommendations.append(f"{len(filtered_ports)} ports are properly firewalled")
            
            return recommendations
    
    # Use the auditor
    auditor = SecurityAuditor()
    report = auditor.audit_target("scanme.nmap.org")
    
    if "error" in report:
        print(f"Audit failed: {report['error']}")
    else:
        print(f"\\n📋 Security Audit Report:")
        print(f"   Target: {report['target']}")
        print(f"   Risk Level: {report['risk_level']}")
        print(f"   Findings:")
        for finding in report['findings']:
            print(f"     • {finding}")
        print(f"   Recommendations:")
        for rec in report['recommendations']:
            print(f"     • {rec}")

if __name__ == "__main__":
    print("PGDN Main Scanner Library Examples")
    print("=" * 50)
    
    # Run examples
    basic_scanner_usage()
    advanced_scanner_with_config() 
    multiple_scan_types()
    custom_port_analysis()
    integration_example()
    
    print(f"\\n" + "=" * 50)
    print("Library examples completed!")