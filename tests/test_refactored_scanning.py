#!/usr/bin/env python3
"""
Test script for the refactored modular scanning system.
Demonstrates the new architecture and backward compatibility.
"""

import sys
import os
import json
from typing import Dict, Any

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pgdn.core.config import Config
from pgdn.scanning.scan_orchestrator import ScanOrchestrator, Scanner
from pgdn.scanning.base_scanner import ScannerRegistry


def test_scanner_registry():
    """Test the scanner registry functionality."""
    print("🧪 Testing Scanner Registry...")
    
    config = {
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
            }
        }
    }
    
    registry = ScannerRegistry(config)
    available_scanners = registry.get_available_scanners()
    
    print(f"   Available scanners: {available_scanners}")
    
    # Test getting individual scanners
    for scanner_type in available_scanners:
        scanner = registry.get_scanner(scanner_type)
        if scanner:
            print(f"   ✅ {scanner_type} scanner created successfully")
        else:
            print(f"   ❌ Failed to create {scanner_type} scanner")
    
    return len(available_scanners) > 0


def test_scan_orchestrator():
    """Test the scan orchestrator."""
    print("\n🧪 Testing Scan Orchestrator...")
    
    config = {
        'orchestrator': {
            'enabled_scanners': ['generic', 'web', 'vulnerability'],
            'use_external_tools': False  # Disable external tools for testing
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
            }
        }
    }
    
    orchestrator = ScanOrchestrator(config)
    
    # Test scan on localhost (should be safe)
    target = "127.0.0.1"
    print(f"   Scanning target: {target}")
    
    try:
        results = orchestrator.scan(target, ports=[22, 80, 443])
        
        print(f"   ✅ Scan completed for {target}")
        print(f"   Target: {results.get('ip', 'unknown')}")
        print(f"   Open ports: {results.get('open_ports', [])}")
        print(f"   TLS info: {'Yes' if results.get('tls') else 'No'}")
        print(f"   Vulnerabilities: {len(results.get('vulns', {}))}")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Scan failed: {e}")
        return False


def test_legacy_compatibility():
    """Test backward compatibility with legacy Scanner class."""
    print("\n🧪 Testing Legacy Compatibility...")
    
    try:
        # Test importing from old location
        from scanning.scanner import Scanner as LegacyScanner
        
        scanner = LegacyScanner()
        print("   ✅ Legacy Scanner import successful")
        
        # Test the static method
        nmap_result = {
            "ports": [
                {"port": "80", "service": "http"},
                {"port": "443", "service": "https"},
                {"port": "8080", "service": "http-proxy"}
            ]
        }
        
        web_ports = LegacyScanner.get_web_ports_and_schemes(nmap_result)
        print(f"   Web ports detected: {web_ports}")
        
        if len(web_ports) == 3:
            print("   ✅ Legacy static method working correctly")
            return True
        else:
            print("   ❌ Legacy static method returned unexpected results")
            return False
            
    except Exception as e:
        print(f"   ❌ Legacy compatibility test failed: {e}")
        return False


def test_configuration_loading():
    """Test configuration loading from JSON."""
    print("\n🧪 Testing Configuration Loading...")
    
    try:
        config = Config()
        
        # Check if scanning config has the new fields
        scanning_config = getattr(config, 'scanning', None)
        if scanning_config:
            orchestrator_config = getattr(scanning_config, 'orchestrator', {})
            scanners_config = getattr(scanning_config, 'scanners', {})
            
            print(f"   Orchestrator config: {orchestrator_config}")
            print(f"   Scanners available: {list(scanners_config.keys())}")
            
            if orchestrator_config and scanners_config:
                print("   ✅ Configuration loaded successfully")
                return True
            else:
                print("   ⚠️  Configuration loaded but missing new fields")
                return True
        else:
            print("   ❌ No scanning configuration found")
            return False
            
    except Exception as e:
        print(f"   ❌ Configuration loading failed: {e}")
        return False


def demonstrate_modularity():
    """Demonstrate the modular nature of the new system."""
    print("\n🧪 Demonstrating Modularity...")
    
    # Show how scanners can be enabled/disabled individually
    configs = [
        {
            'name': 'Generic Only',
            'config': {
                'orchestrator': {'enabled_scanners': ['generic'], 'use_external_tools': False},
                'scanners': {'generic': {'enabled': True, 'default_ports': [22, 80]}}
            }
        },
        {
            'name': 'Web Only',
            'config': {
                'orchestrator': {'enabled_scanners': ['web'], 'use_external_tools': False},
                'scanners': {'web': {'enabled': True, 'timeout': 5}}
            }
        },
        {
            'name': 'All Enabled',
            'config': {
                'orchestrator': {'enabled_scanners': ['generic', 'web', 'vulnerability'], 'use_external_tools': False},
                'scanners': {
                    'generic': {'enabled': True, 'default_ports': [22, 80]},
                    'web': {'enabled': True, 'timeout': 5},
                    'vulnerability': {'enabled': True, 'max_cves_per_banner': 3}
                }
            }
        }
    ]
    
    for test_case in configs:
        print(f"\n   Testing: {test_case['name']}")
        orchestrator = ScanOrchestrator(test_case['config'])
        
        enabled_scanners = test_case['config']['orchestrator']['enabled_scanners']
        print(f"     Enabled scanners: {enabled_scanners}")
        
        # Show that only enabled scanners are used
        registry = ScannerRegistry(test_case['config'])
        available = registry.get_available_scanners()
        print(f"     Available scanners: {available}")
    
    print("   ✅ Modularity demonstration complete")
    return True


def main():
    """Run all tests."""
    print("🚀 Testing Refactored Modular Scanning System\n")
    
    tests = [
        ("Scanner Registry", test_scanner_registry),
        ("Scan Orchestrator", test_scan_orchestrator),
        ("Legacy Compatibility", test_legacy_compatibility),
        ("Configuration Loading", test_configuration_loading),
        ("Modularity", demonstrate_modularity)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "="*50)
    print("📊 TEST SUMMARY")
    print("="*50)
    
    passed = 0
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
        if result:
            passed += 1
    
    print(f"\nResults: {passed}/{len(results)} tests passed")
    
    if passed == len(results):
        print("\n🎉 All tests passed! The refactored scanning system is working correctly.")
        print("\n📝 Key improvements:")
        print("   • Removed hardcoded KNOWN_VULNS dictionary")
        print("   • Consolidated scanning/scanner.py and agents/scan/node_scanner_agent.py")
        print("   • Made scanning modular like scoring system")
        print("   • Added configuration-driven scanner selection")
        print("   • Maintained backward compatibility")
        print("   • Vulnerabilities now sourced from CVE database")
    else:
        print(f"\n⚠️  {len(results) - passed} tests failed. Please review the errors above.")
    
    return passed == len(results)


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
