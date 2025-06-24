#!/usr/bin/env python3
"""
Test script for the new scanner selection functionality
"""

import sys
import os
import json

# Add the project root to the path
sys.path.insert(0, '/Users/simon/Documents/Code/depin')

from pgdn import load_config
from pgdn.scanner import Scanner

# Use a valid UUID format for testing
TEST_ORG_ID = "12345678-1234-1234-1234-123456789012"

def test_scanner_selection():
    """Test the new scanner selection functionality."""
    
    # Load config
    try:
        config = load_config()
        print("✅ Config loaded successfully")
    except Exception as e:
        print(f"❌ Failed to load config: {e}")
        return False
    
    # Test nmap-only scan
    print("\n🔬 Testing nmap-only scan...")
    try:
        scanner = Scanner(
            config, 
            debug=True,
            enabled_scanners=[],  # No modular scanners
            enabled_external_tools=['nmap']  # Only nmap
        )
        
        result = scanner.scan_target(
            target="example.com",
            org_id=TEST_ORG_ID,
            scan_level=1
        )
        
        if result.get("success"):
            print("✅ Nmap-only scan completed")
            print(f"   Target: {result.get('target')}")
            print(f"   Open ports: {result.get('scan_result', {}).get('open_ports', [])}")
            print(f"   Nmap data available: {'nmap' in result.get('scan_result', {})}")
            
            # Print debug info if available
            debug_info = result.get('scan_result', {}).get('_debug_info', {})
            if debug_info:
                print(f"   Enabled scanners: {debug_info.get('enabled_scanners', [])}")
                print(f"   Enabled external tools: {debug_info.get('enabled_external_tools', [])}")
            
            return True
        else:
            print(f"❌ Scan failed: {result.get('error')}")
            return False
            
    except Exception as e:
        print(f"❌ Exception during scan: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_geo_only_scan():
    """Test geo-only scan."""
    
    print("\n🌍 Testing geo-only scan...")
    try:
        config = load_config()
        scanner = Scanner(
            config, 
            debug=True,
            enabled_scanners=['geo'],  # Only geo scanner
            enabled_external_tools=[]  # No external tools
        )
        
        result = scanner.scan_target(
            target="example.com",
            org_id=TEST_ORG_ID,
            scan_level=1
        )
        
        if result.get("success"):
            print("✅ Geo-only scan completed")
            print(f"   Target: {result.get('target')}")
            geoip = result.get('scan_result', {}).get('geoip', {})
            if geoip:
                print(f"   Country: {geoip.get('country_name')}")
                print(f"   City: {geoip.get('city_name')}")
            else:
                print("   No GeoIP data found")
            return True
        else:
            print(f"❌ Geo scan failed: {result.get('error')}")
            return False
            
    except Exception as e:
        print(f"❌ Exception during geo scan: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("🧪 Testing Scanner Selection Functionality")
    print("=" * 50)
    
    success = True
    success &= test_scanner_selection()
    success &= test_geo_only_scan()
    
    print("\n" + "=" * 50)
    if success:
        print("✅ All tests passed!")
    else:
        print("❌ Some tests failed!")
        sys.exit(1)
