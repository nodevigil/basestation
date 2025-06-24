#!/usr/bin/env python3
"""
Debug script to check scanner registry functionality.
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def debug_scanner_registry():
    """Debug the scanner registry to see what's happening."""
    print("🔍 Debugging Scanner Registry...")
    
    try:
        from pgdn.scanning.base_scanner import ScannerRegistry
        
        # Create test configuration
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
                },
                'geo': {
                    'enabled': True,
                    'fallback_to_api': False
                }
            }
        }
        
        registry = ScannerRegistry(config)
        
        print(f"Available scanners: {registry.get_available_scanners()}")
        
        # Test getting each scanner
        for scanner_type in ['generic', 'web', 'vulnerability', 'geo']:
            scanner = registry.get_scanner(scanner_type)
            if scanner:
                print(f"✅ {scanner_type} scanner loaded successfully")
            else:
                print(f"❌ {scanner_type} scanner failed to load")
        
        return True
        
    except Exception as e:
        print(f"❌ Debug failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    debug_scanner_registry()
