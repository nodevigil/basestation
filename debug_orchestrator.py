#!/usr/bin/env python3
"""
Debug script to test orchestrator port scan extraction.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from pgdn_scanner.scanners.scan_orchestrator import ScanOrchestrator
import json

def debug_orchestrator():
    """Debug orchestrator port scan extraction."""
    print("🔍 Debug Orchestrator Port Scan")
    print("=" * 50)
    
    # Create orchestrator
    config = {
        'orchestrator': {
            'enabled_scanners': ['port_scan'],
            'use_external_tools': False
        }
    }
    
    orchestrator = ScanOrchestrator(config)
    orchestrator._enabled_scanners_set = True
    orchestrator.enabled_scanners = ['port_scan']
    
    # Test target
    target = "sui-mainnet.interestlabs.io"
    
    print(f"🎯 Target: {target}")
    print()
    
    # Run the scan
    print("🚀 Running orchestrator scan...")
    result = orchestrator.scan(
        target=target,
        ports=[22, 80, 3306],
        scan_level=1,
        nmap_args="-sV"
    )
    
    print("\n📊 Orchestrator Result:")
    print("=" * 50)
    print(json.dumps(result, indent=2, default=str))
    
    # Check if we have the expected enhanced data
    if result.get('data'):
        for item in result['data']:
            if item.get('scan_type') == 'port_scan':
                port_result = item['result']
                print(f"\n🔍 Port Scan Result Analysis:")
                print(f"  Open ports: {port_result.get('open_ports', [])}")
                print(f"  Service banners: {len(port_result.get('service_banners', {}))}")
                print(f"  TLS info: {len(port_result.get('tls_info', {}))}")
                print(f"  Services detected: {len(port_result.get('services_detected', []))}")
                print(f"  Has scan statistics: {'scan_statistics' in port_result}")
                print(f"  Has scan configuration: {'scan_configuration' in port_result}")
                print(f"  Has port details: {'port_details' in port_result}")
                
                if port_result.get('services_detected'):
                    print(f"\n📋 Services Detected:")
                    for service in port_result['services_detected']:
                        print(f"    Port {service['port']}: {service['service']} (confidence: {service['confidence']})")
    
    print("\n✅ Debug complete!")

if __name__ == "__main__":
    debug_orchestrator()