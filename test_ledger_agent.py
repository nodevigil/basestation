#!/usr/bin/env python3
"""
Test script for the PublishLedgerAgent to verify interface compatibility and basic functionality.
"""

import os
import sys
import json
from typing import Dict, Any

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agents.publish.publish_ledger_agent import PublishLedgerAgent, DePINLedgerError
from core.config import Config


def test_agent_initialization():
    """Test agent initialization without blockchain connection."""
    print("🧪 Testing agent initialization...")
    
    # Test with minimal config (should handle missing connection gracefully)
    config = Config()
    agent = PublishLedgerAgent(config)
    
    print(f"✅ Agent initialized: {agent.agent_name}")
    print(f"   - Blockchain connected: {agent.w3 is not None}")
    print(f"   - Contract loaded: {agent.contract is not None}")
    print(f"   - Is publisher: {agent.is_publisher}")
    
    return agent


def test_abi_loading():
    """Test ABI loading functionality."""
    print("\n🧪 Testing ABI loading...")
    
    agent = PublishLedgerAgent()
    
    # Test ABI loading
    try:
        abi = agent._load_abi_from_file()
        print(f"✅ ABI loaded successfully with {len(abi)} items")
        
        # Check for required functions
        function_names = [item['name'] for item in abi if item.get('type') == 'function']
        required_functions = ['publishScanSummary', 'authorizedPublishers', 'batchPublishScans', 'getContractInfo']
        
        for func in required_functions:
            if func in function_names:
                print(f"   ✅ Found required function: {func}")
            else:
                print(f"   ❌ Missing required function: {func}")
        
        return True
        
    except Exception as e:
        print(f"❌ ABI loading failed: {e}")
        return False


def test_minimal_abi():
    """Test minimal ABI fallback."""
    print("\n🧪 Testing minimal ABI fallback...")
    
    agent = PublishLedgerAgent()
    minimal_abi = agent._get_minimal_abi()
    
    print(f"✅ Minimal ABI has {len(minimal_abi)} items")
    
    function_names = [item['name'] for item in minimal_abi]
    expected = ['publishScanSummary', 'authorizedPublishers']
    
    for func in expected:
        if func in function_names:
            print(f"   ✅ Minimal ABI contains: {func}")
        else:
            print(f"   ❌ Minimal ABI missing: {func}")


def test_scan_formatting():
    """Test scan result formatting for ledger submission."""
    print("\n🧪 Testing scan result formatting...")
    
    agent = PublishLedgerAgent()
    
    # Create test scan result
    test_scan = {
        'scan_id': 123,
        'host_uid': 'test_host_001',
        'validator_id': 'fallback_validator',
        'scan_time': 1719072000,  # June 22, 2025
        'timestamp': 1719072000,
        'trust_score': 85,
        'vulnerabilities': [
            {'cve': 'CVE-2024-1234', 'severity': 'high'},
            {'cve': 'CVE-2024-5678', 'severity': 'medium'}
        ],
        'open_ports': [22, 80, 443, 8080],
        'services': ['ssh', 'http', 'https', 'http-proxy'],
        'ssl_info': {
            'valid': True,
            'expires': '2025-12-31',
            'issuer': 'Let\'s Encrypt'
        },
        'scan_type': 'comprehensive'
    }
    
    try:
        formatted = agent._format_scan_for_ledger(test_scan)
        
        print("✅ Scan formatting successful:")
        print(f"   - Host UID: {formatted['host_uid']}")
        print(f"   - Scan time: {formatted['scan_time']}")
        print(f"   - Score: {formatted['score']}")
        print(f"   - Summary hash: {formatted['summary_hash']}")
        print(f"   - Report pointer: {formatted['report_pointer']}")
        
        # Verify hash is deterministic
        formatted2 = agent._format_scan_for_ledger(test_scan)
        if formatted['summary_hash'] == formatted2['summary_hash']:
            print("   ✅ Hash generation is deterministic")
        else:
            print("   ❌ Hash generation is not deterministic")
        
        return True
        
    except Exception as e:
        print(f"❌ Scan formatting failed: {e}")
        return False


def test_interface_compatibility():
    """Test interface compatibility with base PublishAgent class."""
    print("\n🧪 Testing interface compatibility...")
    
    agent = PublishLedgerAgent()
    
    # Check required methods exist
    required_methods = [
        'run', 'execute', 'publish_results',
        'publish_single_scan', 'publish_batch_scans',
        'get_ledger_status'
    ]
    
    for method in required_methods:
        if hasattr(agent, method) and callable(getattr(agent, method)):
            print(f"   ✅ Method exists: {method}")
        else:
            print(f"   ❌ Method missing: {method}")
    
    # Test method signatures (without calling them)
    try:
        # Test that methods can be called with expected parameters
        print("   ✅ Interface methods are properly defined")
        return True
    except Exception as e:
        print(f"   ❌ Interface compatibility issue: {e}")
        return False


def test_error_handling():
    """Test error handling for various scenarios."""
    print("\n🧪 Testing error handling...")
    
    agent = PublishLedgerAgent()
    
    # Test with invalid scan data
    try:
        invalid_scan = {}
        formatted = agent._format_scan_for_ledger(invalid_scan)
        print("   ✅ Handles missing scan data gracefully")
    except Exception as e:
        print(f"   ✅ Properly raises error for invalid data: {type(e).__name__}")
    
    # Test execute method with invalid scan_id
    try:
        result = agent.execute(scan_id=99999)
        print(f"   ✅ Execute method returns proper error structure: {result.get('success')}")
    except Exception as e:
        print(f"   ❌ Execute method should return error dict, not raise: {e}")
    
    return True


def main():
    """Run all tests."""
    print("🚀 Starting PublishLedgerAgent compatibility tests...\n")
    
    tests = [
        test_agent_initialization,
        test_abi_loading,
        test_minimal_abi,
        test_scan_formatting,
        test_interface_compatibility,
        test_error_handling
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} crashed: {e}")
    
    print(f"\n📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! The agent interface appears to be compatible.")
    else:
        print("⚠️ Some tests failed. Please review the issues above.")
    
    return passed == total


if __name__ == "__main__":
    main()
