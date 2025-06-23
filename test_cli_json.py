#!/usr/bin/env python3
"""
Quick test script to verify CLI JSON functionality
"""

import subprocess
import json
import sys

def run_cli_command(args):
    """Run a CLI command and return the result"""
    try:
        result = subprocess.run(
            ['python', 'cli.py'] + args,
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"

def test_json_command(args, expected_keys=None):
    """Test a CLI command with JSON output"""
    print(f"Testing: python cli.py {' '.join(args)}")
    
    returncode, stdout, stderr = run_cli_command(args)
    
    if returncode != 0:
        print(f"  ❌ Command failed with return code {returncode}")
        if stderr:
            print(f"  Error: {stderr}")
        return False
    
    try:
        result = json.loads(stdout)
        print(f"  ✅ Valid JSON returned")
        
        if expected_keys:
            for key in expected_keys:
                if key in result:
                    print(f"    ✅ Has '{key}' key")
                else:
                    print(f"    ❌ Missing '{key}' key")
                    return False
        
        return True
    except json.JSONDecodeError as e:
        print(f"  ❌ Invalid JSON: {e}")
        print(f"  Output: {stdout}")
        return False

def main():
    """Run all JSON CLI tests"""
    print("🧪 Testing CLI JSON Output Functionality")
    print("=" * 50)
    
    tests = [
        # Basic commands that should work
        (['--json', '--list-agents'], ['success', 'agents', 'timestamp']),
        (['--json', '--show-signature-stats'], ['success', 'statistics', 'timestamp']),
        
        # Commands that should return errors
        (['--json', '--stage', 'publish'], ['error', 'timestamp']),
        (['--json', '--stage', 'discovery'], ['error', 'timestamp']),
    ]
    
    passed = 0
    total = len(tests)
    
    for args, expected_keys in tests:
        if test_json_command(args, expected_keys):
            passed += 1
        print()
    
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! CLI JSON functionality is working correctly.")
        return 0
    else:
        print("❌ Some tests failed. Check the output above for details.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
