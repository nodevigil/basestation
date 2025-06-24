#!/usr/bin/env python3
"""
Test nmap-only scan with the CLI
"""

import subprocess
import sys
import json

def test_nmap_cli():
    """Test the nmap-only CLI option."""
    
    # We need a valid org ID and target that exists
    cmd = [
        'python', 'cli.py',
        '--stage', 'scan',
        '--target', 'example.com',
        '--org-id', '12345678-1234-1234-1234-123456789012',
        '--nmap-only',
        '--debug',
        '--json'
    ]
    
    print("🔬 Testing nmap-only CLI command:")
    print(f"   Command: {' '.join(cmd)}")
    print()
    
    try:
        result = subprocess.run(
            cmd,
            cwd='/Users/simon/Documents/Code/depin',
            capture_output=True,
            text=True,
            timeout=60
        )
        
        print(f"Return code: {result.returncode}")
        print(f"STDOUT:\n{result.stdout}")
        if result.stderr:
            print(f"STDERR:\n{result.stderr}")
        
        # Try to parse JSON output
        if result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                print("\n📊 Parsed results:")
                print(f"   Success: {data.get('success')}")
                if data.get('success'):
                    scan_result = data.get('scan_result', {})
                    print(f"   Open ports: {scan_result.get('open_ports', [])}")
                    print(f"   Nmap available: {'nmap' in scan_result}")
                    if 'nmap' in scan_result:
                        nmap_ports = scan_result['nmap'].get('ports', [])
                        print(f"   Nmap ports: {len(nmap_ports)} found")
                        for port in nmap_ports:
                            print(f"     Port {port['port']}: {port['state']} ({port['service']})")
                else:
                    print(f"   Error: {data.get('error')}")
            except json.JSONDecodeError as e:
                print(f"Failed to parse JSON: {e}")
                
    except subprocess.TimeoutExpired:
        print("❌ Command timed out")
    except Exception as e:
        print(f"❌ Command failed: {e}")

if __name__ == "__main__":
    test_nmap_cli()
