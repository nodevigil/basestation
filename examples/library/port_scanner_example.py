#!/usr/bin/env python3
"""
Example: Using the PortScanner directly as a library

This demonstrates how to use the enhanced port scanner with filtered port detection
and nmap arguments programmatically.
"""

import os
import json
from pgdn_scanner.scanners.port_scanner import PortScanner

def basic_port_scan_example():
    """Basic port scanning example"""
    print("=== Basic Port Scan Example ===")
    
    # Create scanner instance
    config = {
        'timeout': 15,
        'max_threads': 5,
        'nmap_args': []  # Can set default nmap args here
    }
    scanner = PortScanner(config)
    
    # Scan some common ports
    target = "scanme.nmap.org"  # Safe target for testing
    ports = [22, 80, 443, 3306, 5432]
    
    print(f"Scanning {target} on ports: {ports}")
    
    # Perform the scan
    result = scanner.scan(target=target, ports=ports)
    
    # Print results
    print(f"\nScan Results:")
    print(f"Open ports: {result.get('open_ports', [])}")
    print(f"Closed ports: {result.get('closed_ports', [])}")
    print(f"Filtered ports: {result.get('filtered_ports', [])}")
    
    # Print detailed port states
    for port_result in result.get('detailed_results', []):
        port = port_result['port']
        state = port_result['port_state']
        confidence = port_result['confidence_score']
        print(f"  Port {port}: {state} (confidence: {confidence:.1f}%)")

def advanced_port_scan_with_nmap_args():
    """Advanced scanning with nmap arguments"""
    print("\n=== Advanced Port Scan with nmap Args ===")
    
    # Create scanner with custom config
    scanner = PortScanner({
        'timeout': 20,
        'nmap_timeout': 30
    })
    
    target = "scanme.nmap.org"
    ports = [80, 443, 22, 25, 53]
    
    # Use nmap arguments for more detailed scanning
    nmap_args = ['-sV', '-Pn', '--script=banner,http-title']
    
    print(f"Scanning {target} with nmap args: {' '.join(nmap_args)}")
    
    result = scanner.scan(
        target=target, 
        ports=ports,
        nmap_args=nmap_args,
        skip_nmap=False
    )
    
    # Print enhanced results
    print(f"\nEnhanced Results:")
    for port_result in result.get('detailed_results', []):
        port = port_result['port']
        state = port_result['port_state']
        service = port_result.get('service', 'unknown')
        version = port_result.get('version', '')
        banner = port_result.get('banner', '')
        
        print(f"\nPort {port} ({state}):")
        if service != 'unknown':
            print(f"  Service: {service}")
        if version:
            print(f"  Version: {version}")
        if banner:
            print(f"  Banner: {banner[:100]}...")
        
        # Show nmap results if available
        if port_result.get('nmap_results'):
            nmap_output = port_result['nmap_results'].get('raw_output', '')
            if nmap_output:
                print(f"  Nmap found: {nmap_output.split('\\n')[0] if nmap_output else 'N/A'}")

def scan_with_sudo_environment():
    """Example using USE_SUDO environment variable"""
    print("\n=== Scan with USE_SUDO Environment ===")
    
    # Set environment variable for sudo scanning
    os.environ['USE_SUDO'] = 'true'
    
    scanner = PortScanner()
    
    target = "scanme.nmap.org"
    ports = [80, 443, 22]
    
    # This will use -sS scan type automatically when USE_SUDO=true
    result = scanner.scan(
        target=target,
        ports=ports,
        nmap_args=['-Pn', '--script=banner']  # Additional args
    )
    
    print(f"Sudo scan results for {target}:")
    print(f"Command used: {result.get('detailed_results', [{}])[0].get('nmap_results', {}).get('command', 'N/A')}")
    
    # Clean up environment
    os.environ.pop('USE_SUDO', None)

def batch_target_scanning():
    """Scan multiple targets"""
    print("\n=== Batch Target Scanning ===")
    
    scanner = PortScanner({'timeout': 10})
    
    targets = [
        "scanme.nmap.org",
        "google.com", 
        "github.com"
    ]
    
    common_ports = [80, 443, 22]
    
    all_results = {}
    
    for target in targets:
        print(f"\\nScanning {target}...")
        
        try:
            result = scanner.scan(
                target=target,
                ports=common_ports,
                nmap_args=['-Pn'],  # Skip host discovery
                skip_nmap=False
            )
            
            all_results[target] = {
                'open': result.get('open_ports', []),
                'closed': result.get('closed_ports', []),
                'filtered': result.get('filtered_ports', [])
            }
            
            print(f"  Open: {result.get('open_ports', [])}")
            print(f"  Filtered: {result.get('filtered_ports', [])}")
            
        except Exception as e:
            print(f"  Error scanning {target}: {e}")
            all_results[target] = {'error': str(e)}
    
    # Summary
    print(f"\\n=== Batch Results Summary ===")
    for target, results in all_results.items():
        if 'error' in results:
            print(f"{target}: ERROR - {results['error']}")
        else:
            total_open = len(results['open'])
            total_filtered = len(results['filtered'])
            print(f"{target}: {total_open} open, {total_filtered} filtered")

def database_port_scanning():
    """Example focused on database port scanning"""
    print("\n=== Database Port Scanning ===")
    
    scanner = PortScanner({
        'timeout': 15,
        'nmap_timeout': 25
    })
    
    target = "scanme.nmap.org"  # Replace with your target
    database_ports = [3306, 5432, 27017, 6379, 1433, 3389]
    
    # Use your original command structure
    nmap_args = ['-sS', '-sV', '-Pn', '--script=banner,default']
    
    print(f"Scanning database ports on {target}")
    print(f"Ports: {database_ports}")
    print(f"nmap args: {' '.join(nmap_args)}")
    
    # Set sudo if available
    os.environ['USE_SUDO'] = 'true'
    
    result = scanner.scan(
        target=target,
        ports=database_ports,
        nmap_args=nmap_args
    )
    
    # Analyze results for security implications
    print(f"\\n=== Security Analysis ===")
    
    open_db_ports = result.get('open_ports', [])
    filtered_db_ports = result.get('filtered_ports', [])
    
    if open_db_ports:
        print(f"⚠️  OPEN database ports found: {open_db_ports}")
        print("   This may indicate exposed databases!")
    
    if filtered_db_ports:
        print(f"🔒 FILTERED database ports: {filtered_db_ports}")
        print("   These appear to be firewalled (good security practice)")
    
    closed_db_ports = result.get('closed_ports', [])
    if closed_db_ports:
        print(f"✅ CLOSED database ports: {closed_db_ports}")
        print("   These services are not running")
    
    # Clean up
    os.environ.pop('USE_SUDO', None)

def save_results_to_file():
    """Example of saving scan results to file"""
    print("\n=== Save Results to File ===")
    
    scanner = PortScanner()
    
    result = scanner.scan(
        target="scanme.nmap.org",
        ports=[80, 443, 22, 25],
        nmap_args=['-sV', '-Pn']
    )
    
    # Save to JSON file
    output_file = "port_scan_results.json"
    with open(output_file, 'w') as f:
        json.dump(result, f, indent=2, default=str)
    
    print(f"Results saved to {output_file}")
    
    # Show summary
    summary = result.get('scan_summary', {})
    print(f"Summary: {summary.get('open_ports', 0)} open, "
          f"{summary.get('filtered_ports', 0)} filtered, "
          f"{summary.get('closed_ports', 0)} closed")

if __name__ == "__main__":
    print("PGDN Port Scanner Library Examples")
    print("=" * 50)
    
    # Run all examples
    basic_port_scan_example()
    advanced_port_scan_with_nmap_args()
    scan_with_sudo_environment()
    batch_target_scanning()
    database_port_scanning()
    save_results_to_file()
    
    print(f"\\n" + "=" * 50)
    print("All examples completed!")