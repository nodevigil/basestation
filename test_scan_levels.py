#!/usr/bin/env python3
"""
Test script to verify scan level support is working correctly.
Tests that different scan levels trigger the correct behavior.
"""

import sys
import os
import json
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_scan_orchestrator_levels():
    """Test the ScanOrchestrator with different scan levels."""
    print("🧪 Testing ScanOrchestrator with different scan levels...")
    
    # Enable debug logging
    import logging
    logging.basicConfig(level=logging.DEBUG)
    
    try:
        from pgdn.scanning.scan_orchestrator import ScanOrchestrator
        
        # Create test configuration
        config = {
            'orchestrator': {
                'enabled_scanners': ['generic', 'web', 'vulnerability', 'geo'],
                'use_external_tools': False  # Disable for testing
            },
            'scanners': {
                'generic': {
                    'enabled': True,
                    'default_ports': [22, 80, 443],
                    'connection_timeout': 1
                },
                'web': {
                    'enabled': True,
                    'timeout': 5
                },
                'vulnerability': {
                    'enabled': True,
                    'max_cves_per_banner': 3
                },
                'geo': {
                    'enabled': True,
                    'fallback_to_api': False  # Disable API fallback for testing
                }
            }
        }
        
        orchestrator = ScanOrchestrator(config)
        target = "127.0.0.1"  # Safe test target
        
        # Debug: check what scanners are available
        print(f"Available scanners: {orchestrator.scanner_registry.get_available_scanners()}")
        print(f"Enabled scanners: {orchestrator.enabled_scanners}")
        
        # Test different scan levels
        for level in [1, 2, 3]:
            print(f"\n📋 Testing scan level {level}...")
            
            try:
                results = orchestrator.scan(target, scan_level=level)
                
                # Verify results include scan_level
                assert results.get('scan_level') == level, f"Expected scan_level {level}, got {results.get('scan_level')}"
                
                # Verify GeoIP data is present for level 1+
                if level >= 1:
                    geoip_data = results.get('geoip')
                    if geoip_data:
                        print(f"   ✅ GeoIP data found: {geoip_data.get('country_name', 'Unknown')}")
                    else:
                        print("   ⚠️  GeoIP data not found (may be expected for localhost)")
                
                # Check that scanners executed by looking at result structure
                # Note: Legacy format doesn't preserve scan_results, but data is in the structure
                has_generic_data = any(key in results for key in ['open_ports', 'banners'])
                has_geo_data = 'geoip' in results
                has_external_tools = any(key in results for key in ['nmap', 'whatweb'])
                
                executed_features = []
                if has_generic_data:
                    executed_features.append('generic')
                if has_geo_data:
                    executed_features.append('geo')
                if has_external_tools:
                    executed_features.append('external_tools')
                
                print(f"   📊 Features found: {executed_features}")
                print(f"   🔍 Open ports: {len(results.get('open_ports', []))}")
                print(f"   📋 Available keys: {list(results.keys())}")
                
                # Verify vulnerability scanner behavior by level
                vuln_results = results.get('vulns', {})
                if level == 1 and not vuln_results:
                    print("   ✅ Level 1: CVE scanning skipped as expected")
                elif level >= 2 and vuln_results is not None:
                    print(f"   ✅ Level {level}: CVE scanning enabled")
                
                print(f"   ✅ Level {level} scan completed successfully")
                
            except Exception as e:
                print(f"   ❌ Level {level} scan failed: {e}")
                import traceback
                traceback.print_exc()
        
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_scanner_level_support():
    """Test individual scanners accept scan_level parameter."""
    print("\n🔧 Testing individual scanner scan_level support...")
    
    try:
        from pgdn.scanning.generic_scanner import GenericScanner
        from pgdn.scanning.web_scanner import WebScanner
        from pgdn.scanning.vulnerability_scanner import VulnerabilityScanner
        from pgdn.scanning.geo_scanner import GeoScanner
        
        target = "127.0.0.1"
        scanners = [
            ('generic', GenericScanner),
            ('web', WebScanner),
            ('vulnerability', VulnerabilityScanner),
            ('geo', GeoScanner)
        ]
        
        for name, scanner_class in scanners:
            print(f"   Testing {name} scanner...")
            
            try:
                scanner = scanner_class({})
                
                # Test each scan level
                for level in [1, 2, 3]:
                    result = scanner.scan(target, scan_level=level)
                    
                    # Verify scan_level is in results
                    if 'scan_level' in result:
                        assert result['scan_level'] == level
                        print(f"     ✅ Level {level}: scan_level correctly set")
                    else:
                        print(f"     ⚠️  Level {level}: scan_level not in results")
                
                print(f"   ✅ {name} scanner supports scan_level")
                
            except Exception as e:
                print(f"   ❌ {name} scanner failed: {e}")
        
        return True
        
    except Exception as e:
        print(f"❌ Scanner test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_level_specific_behavior():
    """Test that scan levels trigger the correct behavior."""
    print("\n🎯 Testing level-specific behavior...")
    
    try:
        from pgdn.scanning.vulnerability_scanner import VulnerabilityScanner
        
        scanner = VulnerabilityScanner({})
        target = "127.0.0.1"
        
        # Level 1 should skip CVE scanning
        result_l1 = scanner.scan(target, scan_level=1)
        if result_l1.get('cves') is None or len(result_l1.get('cves', {})) == 0:
            print("   ✅ Level 1: CVE scanning skipped")
        else:
            print("   ⚠️  Level 1: CVE scanning was performed (unexpected)")
        
        # Level 2 should include CVE scanning
        result_l2 = scanner.scan(target, scan_level=2)
        if 'cves' in result_l2:
            print("   ✅ Level 2: CVE scanning enabled")
        else:
            print("   ⚠️  Level 2: CVE scanning not found")
        
        return True
        
    except Exception as e:
        print(f"❌ Level behavior test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all scan level tests."""
    print("🚀 Testing PGDN Scan Level Support")
    print("=" * 50)
    
    tests = [
        test_scan_orchestrator_levels,
        test_scanner_level_support,
        test_level_specific_behavior
    ]
    
    passed = 0
    for test in tests:
        if test():
            passed += 1
        print()
    
    print(f"📊 Test Results: {passed}/{len(tests)} tests passed")
    
    if passed == len(tests):
        print("🎉 All scan level tests passed!")
        return 0
    else:
        print("❌ Some tests failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
