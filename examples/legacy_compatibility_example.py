#!/usr/bin/env python3
"""
Example: Legacy compatibility demonstration.
Shows how existing code continues to work with the refactored system.
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_legacy_scanner_import():
    """Test importing Scanner from original location."""
    print("📦 Testing Legacy Scanner Import")
    print("-" * 35)
    
    try:
        # This should still work - imports the new modular system
        from scanning.scanner import Scanner
        
        print("✅ Legacy import successful")
        
        # Create scanner instance
        scanner = Scanner()
        print("✅ Scanner instance created")
        
        # Test static method (legacy compatibility)
        nmap_result = {
            "ports": [
                {"port": "80", "service": "http"},
                {"port": "443", "service": "https"},
                {"port": "8080", "service": "http-proxy"}
            ]
        }
        
        web_ports = Scanner.get_web_ports_and_schemes(nmap_result)
        print(f"✅ Static method result: {web_ports}")
        
        return True
        
    except Exception as e:
        print(f"❌ Legacy import failed: {e}")
        return False


def test_legacy_scan_method():
    """Test the legacy scan method interface."""
    print("\n🔍 Testing Legacy Scan Method")
    print("-" * 32)
    
    try:
        from scanning.scanner import Scanner
        
        scanner = Scanner()
        
        # Test scan with legacy parameters
        target = "127.0.0.1"
        ports = (22, 80, 443)  # Legacy tuple format
        
        print(f"Scanning {target} with legacy method...")
        
        # This should return results in the legacy format
        results = scanner.scan(target, ports)
        
        # Check legacy result format
        expected_keys = ['ip', 'open_ports', 'banners', 'vulns', 'tls', 
                        'http_headers', 'docker_exposure', 'nmap', 
                        'whatweb', 'ssl_test']
        
        missing_keys = [key for key in expected_keys if key not in results]
        
        if not missing_keys:
            print("✅ Legacy result format maintained")
            print(f"   Target: {results['ip']}")
            print(f"   Open ports: {results['open_ports']}")
            print(f"   Result keys: {list(results.keys())}")
        else:
            print(f"⚠️  Missing legacy keys: {missing_keys}")
        
        return len(missing_keys) == 0
        
    except Exception as e:
        print(f"❌ Legacy scan failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_node_scanner_agent_compatibility():
    """Test that NodeScannerAgent still works with new system."""
    print("\n🤖 Testing NodeScannerAgent Compatibility")
    print("-" * 42)
    
    try:
        # Import should work with new scanning system
        from agents.scan.node_scanner_agent import NodeScannerAgent
        from pgdn.core.config import Config
        
        print("✅ NodeScannerAgent import successful")
        
        # Create agent instance
        config = Config()
        agent = NodeScannerAgent(config, debug=True)
        
        print("✅ NodeScannerAgent instance created")
        print(f"   Using ScanOrchestrator: {hasattr(agent, 'scan_orchestrator')}")
        print(f"   Protocol registry available: {hasattr(agent, 'protocol_registry')}")
        
        return True
        
    except Exception as e:
        print(f"❌ NodeScannerAgent compatibility failed: {e}")
        return False


def demonstrate_backward_compatibility():
    """Show that old code patterns still work."""
    print("\n🔄 Backward Compatibility Demo")
    print("-" * 32)
    
    # Old code pattern that should still work
    try:
        from scanning.scanner import Scanner
        
        # Legacy instantiation
        scanner = Scanner()
        
        # Legacy method calls
        target = "127.0.0.1"
        
        # Simulate old workflow
        print("Running legacy workflow...")
        
        # 1. Basic scan (legacy interface)
        scan_results = scanner.scan(target, (80, 443))
        
        # 2. Extract web ports (legacy static method)
        if scan_results.get('nmap'):
            web_ports = Scanner.get_web_ports_and_schemes(scan_results['nmap'])
            print(f"   Web ports found: {web_ports}")
        
        # 3. Check results format
        if 'open_ports' in scan_results and 'vulns' in scan_results:
            print("   ✅ Legacy result format preserved")
        
        print("✅ Legacy workflow completed successfully")
        return True
        
    except Exception as e:
        print(f"❌ Legacy workflow failed: {e}")
        return False


if __name__ == "__main__":
    print("🚀 Legacy Compatibility Examples\n")
    
    tests = [
        ("Legacy Scanner Import", test_legacy_scanner_import),
        ("Legacy Scan Method", test_legacy_scan_method),
        ("NodeScannerAgent Compatibility", test_node_scanner_agent_compatibility),
        ("Backward Compatibility Demo", demonstrate_backward_compatibility)
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
    print("📊 COMPATIBILITY TEST SUMMARY")
    print("="*50)
    
    passed = sum(1 for _, result in results if result)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\nResults: {passed}/{len(results)} compatibility tests passed")
    
    if passed == len(results):
        print("\n🎉 Full backward compatibility maintained!")
        print("\n📝 This means:")
        print("   • Existing code continues to work unchanged")
        print("   • Import paths remain the same")
        print("   • Method signatures are preserved")
        print("   • Result formats are compatible")
    else:
        print(f"\n⚠️  {len(results) - passed} compatibility issues found")
    
    print("\n🔧 Migration recommendations:")
    print("   • Keep using existing imports during transition")
    print("   • Gradually adopt new ScanOrchestrator interface") 
    print("   • Configure new scanners in config.json")
    print("   • Test thoroughly before removing legacy code")
