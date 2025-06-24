#!/usr/bin/env python3
"""
Debug script to test orchestrator scanner execution directly.
"""

import sys
import os
import logging

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def debug_orchestrator_execution():
    """Debug the orchestrator scanner execution directly."""
    print("🔍 Debugging Orchestrator Scanner Execution...")
    
    # Enable debug logging
    logging.basicConfig(level=logging.DEBUG, 
                       format='%(levelname)s [%(name)s]: %(message)s')
    
    try:
        from pgdn.scanning.scan_orchestrator import ScanOrchestrator
        
        # Create test configuration
        config = {
            'orchestrator': {
                'enabled_scanners': ['generic'],  # Start with just one scanner
                'use_external_tools': False
            },
            'scanners': {
                'generic': {
                    'enabled': True,
                    'default_ports': [22, 80, 443],
                    'connection_timeout': 1
                }
            }
        }
        
        orchestrator = ScanOrchestrator(config)
        target = "127.0.0.1"
        
        print(f"Available scanners: {orchestrator.scanner_registry.get_available_scanners()}")
        print(f"Enabled scanners: {orchestrator.enabled_scanners}")
        
        # Test scanner registry directly
        generic_scanner = orchestrator.scanner_registry.get_scanner('generic')
        if generic_scanner:
            print("✅ Generic scanner loaded directly")
            direct_result = generic_scanner.scan(target, scan_level=1)
            print(f"Direct scanner result keys: {list(direct_result.keys())}")
        else:
            print("❌ Generic scanner failed to load directly")
        
        # Now test orchestrator
        print("\n🎯 Testing orchestrator...")
        results = orchestrator.scan(target, scan_level=1)
        
        print(f"Orchestrator results keys: {list(results.keys())}")
        scan_results = results.get('scan_results', {})
        print(f"Scan results keys: {list(scan_results.keys())}")
        
        return True
        
    except Exception as e:
        print(f"❌ Debug failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    debug_orchestrator_execution()
