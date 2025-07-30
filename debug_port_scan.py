#!/usr/bin/env python3
"""
Debug script to test port scanning and see what data is being returned.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from pgdn_scanner.scanners.port_scanner import PortScanner
import json

def debug_port_scan():
    """Debug port scan to see raw data."""
    print("🔍 Debug Port Scan Test")
    print("=" * 50)
    
    # Create port scanner
    config = {
        'timeout': 10,
        'max_threads': 4,
        'nmap_timeout': 15
    }
    
    scanner = PortScanner(config)
    
    # Test with a few ports
    target = "sui-mainnet.interestlabs.io"
    ports = [22, 80, 3306]
    
    print(f"🎯 Target: {target}")
    print(f"🔢 Ports: {ports}")
    print()
    
    # Run the scan
    print("🚀 Running port scan...")
    result = scanner.scan(target, ports=ports, nmap_args="-sV")
    
    print("\n📊 Raw Port Scanner Result:")
    print("=" * 50)
    print(json.dumps(result, indent=2, default=str))
    
    # Check if we have detailed results
    if 'detailed_results' in result:
        print(f"\n🔍 Found {len(result['detailed_results'])} detailed results")
        for i, detail in enumerate(result['detailed_results']):
            print(f"\n📋 Detailed Result {i+1}:")
            print(f"  Port: {detail.get('port')}")
            print(f"  Open: {detail.get('is_open')}")
            print(f"  State: {detail.get('port_state')}")
            print(f"  Service: {detail.get('service')}")
            print(f"  Version: {detail.get('version')}")
            print(f"  Banner: {detail.get('banner', 'None')[:100]}...")
            print(f"  SSL Info: {'Yes' if detail.get('ssl_info') else 'No'}")
            print(f"  Nmap Results: {'Yes' if detail.get('nmap_results') else 'No'}")
    
    # Check banners
    banners = result.get('banners', {})
    if banners:
        print(f"\n🏷️  Service Banners Found: {len(banners)}")
        for port, banner in banners.items():
            print(f"  Port {port}: {banner[:100]}...")
    else:
        print("\n🏷️  No service banners found")
    
    # Check TLS info
    tls_info = result.get('tls', {})
    if tls_info:
        print(f"\n🔒 TLS Info Found: {len(tls_info)} ports")
        for port, info in tls_info.items():
            print(f"  Port {port}: {info.get('protocol_version', 'Unknown')}")
    else:
        print("\n🔒 No TLS info found")
    
    print("\n✅ Debug complete!")

if __name__ == "__main__":
    debug_port_scan()