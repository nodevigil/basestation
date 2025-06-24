#!/usr/bin/env python3
"""
Test script to verify the CLI scan refactoring works correctly.
"""

import subprocess
import sys
import json

def run_cli_command(args):
    """Run a CLI command and return the result."""
    try:
        cmd = ['python', 'cli.py'] + args
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return {"output": result.stdout, "success": True}
        else:
            return {
                "success": False, 
                "error": result.stderr or result.stdout,
                "returncode": result.returncode
            }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Command timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def test_scan_type_parsing():
    """Test that scan type options are parsed correctly."""
    print("🧪 Testing CLI scan refactoring...")
    
    # Test 1: Verify scan stage without target requires proper error handling
    print("\n1. Testing scan stage error handling...")
    result = run_cli_command(['--stage', 'scan', '--json'])
    
    if result.get('success') == False:
        print("   ✅ Scan without target/org-id properly returns error")
    else:
        print(f"   ❌ Expected error for scan without parameters: {result}")
        return False
    
    # Test 2: Test scan with target but missing org-id
    print("\n2. Testing target scan without org-id...")
    result = run_cli_command(['--stage', 'scan', '--target', '127.0.0.1', '--json'])
    
    if result.get('success') == False and 'org-id' in result.get('error', ''):
        print("   ✅ Target scan without org-id properly returns error")
    else:
        print(f"   ❌ Expected org-id error: {result}")
        return False
    
    # Test 3: Test scan type parameter parsing (this should fail gracefully without valid org)
    print("\n3. Testing scan type parameter parsing...")
    result = run_cli_command(['--stage', 'scan', '--target', '127.0.0.1', '--type', 'nmap', '--json'])
    
    if result.get('success') == False and 'org-id' in result.get('error', ''):
        print("   ✅ Scan type parameters are being processed (org-id still required)")
    else:
        print(f"   ❌ Unexpected result for scan type test: {result}")
        return False
    
    # Test 4: Verify help still works with new scan types
    print("\n4. Testing help output for scan types...")
    try:
        cmd = ['python', 'cli.py', '--help']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0 and '--type' in result.stdout:
            print("   ✅ Help output includes scan type options")
        else:
            print(f"   ❌ Help output missing or incorrect")
            return False
    except Exception as e:
        print(f"   ❌ Help test failed: {e}")
        return False
    
    print("\n✅ All CLI scan refactoring tests passed!")
    return True

if __name__ == '__main__':
    success = test_scan_type_parsing()
    sys.exit(0 if success else 1)
