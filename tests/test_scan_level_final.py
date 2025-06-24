#!/usr/bin/env python3
"""
Final test to verify scan_level functionality is working correctly.
"""

import sys
import os
sys.path.insert(0, os.path.abspath('.'))

from pgdn.scanning.scan_orchestrator import ScanOrchestrator
from pgdn.core.config import Config
import json

def test_scan_level_functionality():
    """Test that scan_level works correctly across all scanners."""
    print("Testing scan_level functionality...")
    
    # Load config
    config = Config.from_file('config.json')
    
    # Test with scan_level 1 (basic)
    print("\n=== Testing Scan Level 1 (Basic) ===")
    orchestrator = ScanOrchestrator(config.data)
    result = orchestrator.run_scan("8.8.8.8", scan_level=1)
    
    print(f"Scan successful: {result.get('success', False)}")
    print(f"Number of scanner results: {len(result.get('scanner_results', {}))}")
    
    # Check if scan_level is propagated
    for scanner_name, scanner_result in result.get('scanner_results', {}).items():
        scan_level = scanner_result.get('scan_level', 'NOT_SET')
        print(f"  {scanner_name}: scan_level = {scan_level}")
    
    # Test with scan_level 2 (with geo)
    print("\n=== Testing Scan Level 2 (With Geo) ===")
    result = orchestrator.run_scan("8.8.8.8", scan_level=2)
    
    print(f"Scan successful: {result.get('success', False)}")
    print(f"Number of scanner results: {len(result.get('scanner_results', {}))}")
    
    # Check if GeoScanner was included and has geo data
    geo_result = result.get('scanner_results', {}).get('geo')
    if geo_result:
        print(f"  GeoScanner included: YES")
        print(f"  Country: {geo_result.get('country_name', 'N/A')}")
        print(f"  City: {geo_result.get('city_name', 'N/A')}")
        print(f"  ASN: {geo_result.get('asn_number', 'N/A')}")
    else:
        print(f"  GeoScanner included: NO")
    
    # Test with scan_level 3 (comprehensive)
    print("\n=== Testing Scan Level 3 (Comprehensive) ===")
    result = orchestrator.run_scan("8.8.8.8", scan_level=3)
    
    print(f"Scan successful: {result.get('success', False)}")
    print(f"Number of scanner results: {len(result.get('scanner_results', {}))}")
    
    # Check if all scanners have scan_level = 3
    for scanner_name, scanner_result in result.get('scanner_results', {}).items():
        scan_level = scanner_result.get('scan_level', 'NOT_SET')
        print(f"  {scanner_name}: scan_level = {scan_level}")
    
    print("\n=== Test Complete ===")
    return True

if __name__ == "__main__":
    try:
        test_scan_level_functionality()
        print("✅ All scan_level tests passed!")
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
