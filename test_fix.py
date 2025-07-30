#!/usr/bin/env python3
"""
Test the port scanner fix directly without CLI.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from pgdn_scanner.scanners.port_scanner import PortScanner
import json

def test_port_scanner_fix():
    """Test that port scanner now generates rich data by default."""
    print("🧪 Testing Port Scanner Fix")
    print("=" * 50)
    
    # Create port scanner with basic config
    config = {
        'timeout': 10,
        'max_threads': 4,
        'nmap_timeout': 15
    }
    
    scanner = PortScanner(config)
    
    # Test with a few ports - no nmap_args specified
    target = "httpbin.org"  # Use a more reliable test target
    ports = [80, 443]
    
    print(f"🎯 Target: {target}")
    print(f"🔢 Ports: {ports}")
    print("📋 Testing without explicit nmap_args (should auto-add -sV)")
    print()
    
    # Run the scan with no nmap_args - should now default to rich scanning
    result = scanner.scan(target, ports=ports)
    
    print("📊 Port Scanner Result Keys:")
    print(f"  {list(result.keys())}")
    print()
    
    # Check if we have rich data
    has_detailed_results = 'detailed_results' in result
    has_scan_summary = 'scan_summary' in result
    has_banners = 'banners' in result
    
    print("🔍 Rich Data Check:")
    print(f"  detailed_results: {has_detailed_results}")
    print(f"  scan_summary: {has_scan_summary}")
    print(f"  banners: {has_banners}")
    
    if has_detailed_results:
        print(f"  detailed_results count: {len(result['detailed_results'])}")
        
    if has_scan_summary:
        summary = result['scan_summary']
        print(f"  scan summary keys: {list(summary.keys())}")
        
    print()
    
    # Show a sample of the results
    if has_detailed_results and result['detailed_results']:
        print("📋 Sample Detailed Result:")
        sample = result['detailed_results'][0]
        print(f"  Port: {sample.get('port')}")
        print(f"  Open: {sample.get('is_open')}")
        print(f"  Service: {sample.get('service')}")
        print(f"  Confidence: {sample.get('confidence_score')}")
    
    success = has_detailed_results and has_scan_summary
    print(f"\n{'✅ SUCCESS' if success else '❌ FAILED'}: Port scanner {'now generates' if success else 'still missing'} rich data")
    
    return success

if __name__ == "__main__":
    test_port_scanner_fix()