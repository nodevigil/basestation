#!/usr/bin/env python3
"""
Basic PGDN Scanning Example

This example demonstrates simple target scanning using the PGDN library.
"""

from pgdn import initialize_application, Scanner, load_targets_from_file

def main():
    # Initialize PGDN with default configuration
    print("Initializing PGDN...")
    config = initialize_application("config.json", log_level="INFO")
    
    # Create scanner instance
    scanner = Scanner(config, protocol_filter='sui', debug=True)
    
    # Example 1: Scan single target
    print("\n=== Single Target Scan ===")
    target = "192.168.1.100"
    result = scanner.scan_target(target)
    
    if result['success']:
        print(f"✓ Successfully scanned {target}")
        print(f"  Scan ID: {result.get('scan_id')}")
        print(f"  Vulnerabilities found: {result.get('vulnerability_count', 0)}")
    else:
        print(f"✗ Failed to scan {target}: {result['error']}")
    
    # Example 2: Scan multiple targets
    print("\n=== Multiple Target Scan ===")
    targets = ["192.168.1.100", "192.168.1.101", "192.168.1.102"]
    
    for target in targets:
        print(f"Scanning {target}...")
        result = scanner.scan_target(target)
        
        if result['success']:
            print(f"  ✓ {target} - {result.get('vulnerability_count', 0)} vulnerabilities")
        else:
            print(f"  ✗ {target} - {result['error']}")
    
    # Example 3: Parallel scanning
    print("\n=== Parallel Scanning ===")
    result = scanner.scan_parallel_targets(targets, max_parallel=2)
    
    if result['success']:
        print(f"✓ Parallel scan completed")
        print(f"  Total targets: {result.get('total_targets')}")
        print(f"  Successful scans: {result.get('successful_scans')}")
        print(f"  Failed scans: {result.get('failed_scans')}")
    else:
        print(f"✗ Parallel scan failed: {result['error']}")
    
    # Example 4: Scan from database
    print("\n=== Database Scan ===")
    result = scanner.scan_nodes_from_database()
    
    if result['success']:
        print(f"✓ Database scan completed")
        print(f"  Nodes scanned: {result.get('nodes_scanned')}")
    else:
        print(f"✗ Database scan failed: {result['error']}")

if __name__ == "__main__":
    main()