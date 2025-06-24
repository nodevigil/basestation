#!/usr/bin/env python3
"""
Example: Basic usage of the refactored modular scanning system.
Shows how to use the new ScanOrchestrator for scanning targets.
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pgdn.scanning.scan_orchestrator import ScanOrchestrator


def basic_scan_example():
    """Example of basic scanning with default configuration."""
    print("🔍 Basic Scan Example")
    print("-" * 30)
    
    # Create orchestrator with default configuration
    config = {
        'orchestrator': {
            'enabled_scanners': ['generic', 'web', 'vulnerability'],
            'use_external_tools': False  # Disable for example
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
    
    # Scan localhost
    target = "127.0.0.1"
    print(f"Scanning {target}...")
    
    results = orchestrator.scan(target, ports=[22, 80, 443])
    
    print(f"Target: {results['ip']}")
    print(f"Open ports: {results['open_ports']}")
    print(f"Banners found: {len(results['banners'])}")
    print(f"Vulnerabilities: {len(results['vulns'])}")
    
    return results


def selective_scanner_example():
    """Example showing how to enable only specific scanners."""
    print("\n🎯 Selective Scanner Example")
    print("-" * 35)
    
    # Enable only generic scanner
    config = {
        'orchestrator': {
            'enabled_scanners': ['generic'],  # Only generic scanning
            'use_external_tools': False
        },
        'scanners': {
            'generic': {
                'enabled': True,
                'default_ports': [22, 80, 443, 8080],
                'connection_timeout': 2
            }
        }
    }
    
    orchestrator = ScanOrchestrator(config)
    
    target = "127.0.0.1"
    print(f"Scanning {target} with generic scanner only...")
    
    results = orchestrator.scan(target)
    
    print(f"Scan results keys: {list(results.keys())}")
    print("Note: Only generic scan results available")
    
    return results


def custom_ports_example():
    """Example showing custom port configuration."""
    print("\n🔧 Custom Ports Example")
    print("-" * 27)
    
    config = {
        'orchestrator': {
            'enabled_scanners': ['generic'],
            'use_external_tools': False
        },
        'scanners': {
            'generic': {
                'enabled': True,
                'default_ports': [3000, 8000, 9000],  # Custom ports
                'connection_timeout': 1
            }
        }
    }
    
    orchestrator = ScanOrchestrator(config)
    
    target = "127.0.0.1"
    custom_ports = [3000, 8000, 9000, 9090]
    print(f"Scanning {target} on custom ports: {custom_ports}")
    
    results = orchestrator.scan(target, ports=custom_ports)
    
    print(f"Scanned ports: {custom_ports}")
    print(f"Open ports found: {results['open_ports']}")
    
    return results


if __name__ == "__main__":
    print("🚀 Modular Scanning System Examples\n")
    
    try:
        # Run examples
        basic_scan_example()
        selective_scanner_example()
        custom_ports_example()
        
        print("\n✅ All examples completed successfully!")
        print("\n📝 Next steps:")
        print("   • Check docs/scanning.md for detailed documentation")
        print("   • Modify config.json to customize scanner behavior")
        print("   • Create custom scanners by extending BaseScanner")
        
    except Exception as e:
        print(f"\n❌ Example failed: {e}")
        import traceback
        traceback.print_exc()
