#!/usr/bin/env python3
"""
Debug script to test library scanning path specifically.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from pgdn_scanner.scanner import Scanner
import json

def debug_library():
    """Debug library scanning."""
    print("🔍 Debug Library Scanning Path")
    print("=" * 50)
    
    # Create scanner
    scanner = Scanner()
    
    # Test target
    target = "sui-mainnet.interestlabs.io"
    
    print(f"🎯 Target: {target}")
    print()
    
    # Run the scan using library interface
    print("🚀 Running library scan...")
    result = scanner.scan(
        target=target,
        run="port_scan"  # Use the run parameter like CLI does
    )
    
    print("\n📊 Library Result:")
    print("=" * 50)
    print(json.dumps(result.to_dict(), indent=2, default=str))
    
    print("\n✅ Debug complete!")

if __name__ == "__main__":
    debug_library()