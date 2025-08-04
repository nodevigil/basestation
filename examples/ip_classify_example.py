#!/usr/bin/env python3
"""
IP Classification Scanner Example

This example demonstrates how to use the IP Classification Scanner
both via CLI and library API to analyze IP addresses and identify
cloud providers, CDNs, and infrastructure services.
"""

import sys
import json
from pathlib import Path

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from pgdn_scanner.scanner import Scanner
from pgdn_scanner.scanners.ip_classify_scanner import IpClassifyScanner


def example_basic_usage():
    """Basic IP classification examples."""
    print("=== Basic IP Classification ===\n")
    
    scanner = Scanner()
    
    # Single IP classification
    print("🔍 Analyzing Google DNS (8.8.8.8)...")
    result = scanner.scan(target="8.8.8.8", run="ip_classify")
    
    if result.success:
        data = result.data[0]['result']
        print(f"  IP: {data['ip']}")
        print(f"  Reverse DNS: {data.get('reverse_dns', 'None')}")
        print(f"  Organization: {data.get('ipinfo_org', 'Unknown')}")
        print(f"  Classification: {data.get('classification', 'Unknown')}")
        print(f"  Likely Role: {data.get('likely_role', 'Unknown')}")
    else:
        print(f"  Error: {result.error}")
    
    print()


def example_multiple_ips():
    """Multiple IP classification example."""
    print("=== Multiple IP Analysis ===\n")
    
    scanner = Scanner()
    
    # Multiple popular DNS/CDN IPs
    targets = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    
    print(f"🔍 Analyzing {len(targets)} IP addresses...")
    result = scanner.scan(target=",".join(targets), run="ip_classify")
    
    if result.success:
        # For multiple IPs, the scanner returns different format
        print("Results:")
        for i, target in enumerate(targets):
            single_result = scanner.scan(target=target, run="ip_classify")
            if single_result.success:
                data = single_result.data[0]['result']
                print(f"  {data['ip']}: {data.get('ipinfo_org', 'Unknown')} - {data.get('likely_role', 'Unknown')}")
    
    print()


def example_direct_scanner():
    """Direct scanner usage with custom configuration."""
    print("=== Direct Scanner Usage ===\n")
    
    # Custom configuration
    config = {
        'timeout': 10,
        'default_port': 443
    }
    
    scanner = IpClassifyScanner(config)
    
    # Analyze Cloudflare IP with detailed scan
    print("🔍 Detailed analysis of Cloudflare IP (1.1.1.1)...")
    result = scanner.scan("1.1.1.1", scan_level=2)
    
    print(f"  IP: {result['ip']}")
    print(f"  Reverse DNS: {result.get('reverse_dns', 'None')}")
    print(f"  Organization: {result.get('ipinfo_org', 'Unknown')}")
    print(f"  TLS Common Name: {result.get('tls_common_name', 'None')}")
    print(f"  HTTP Headers: {len(result.get('http_headers', {}))} headers")
    print(f"  AWS Service: {result.get('aws_service', 'None')}")
    print(f"  Classification: {result.get('classification', 'Unknown')}")
    print(f"  Likely Role: {result.get('likely_role', 'Unknown')}")
    
    print()


def example_private_ip():
    """Private IP detection example."""
    print("=== Private IP Detection ===\n")
    
    scanner = Scanner()
    
    private_ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1"]
    
    for ip in private_ips:
        print(f"🔍 Analyzing private IP {ip}...")
        result = scanner.scan(target=ip, run="ip_classify")
        
        if result.success:
            data = result.data[0]['result']
            print(f"  Classification: {data.get('classification', 'Unknown')}")
            print(f"  Likely Role: {data.get('likely_role', 'Unknown')}")
        print()


def example_infrastructure_mapping():
    """Infrastructure mapping example."""
    print("=== Infrastructure Mapping ===\n")
    
    scanner = Scanner()
    
    # Mix of different cloud providers
    infrastructure_ips = [
        "8.8.8.8",      # Google
        "1.1.1.1",      # Cloudflare
        "208.67.222.222", # OpenDNS/Cisco
    ]
    
    provider_map = {}
    
    for ip in infrastructure_ips:
        print(f"🔍 Mapping {ip}...")
        result = scanner.scan(target=ip, run="ip_classify")
        
        if result.success:
            data = result.data[0]['result']
            org = data.get('ipinfo_org', 'Unknown Provider')
            role = data.get('likely_role', 'Unknown')
            
            if org not in provider_map:
                provider_map[org] = []
            
            provider_map[org].append({
                'ip': ip,
                'role': role,
                'reverse_dns': data.get('reverse_dns')
            })
    
    print("\n📊 Infrastructure Map:")
    for provider, ips in provider_map.items():
        print(f"\n  {provider}:")
        for ip_info in ips:
            print(f"    {ip_info['ip']} - {ip_info['role']}")
            if ip_info['reverse_dns']:
                print(f"      DNS: {ip_info['reverse_dns']}")


def example_json_output():
    """JSON output example for integration."""
    print("=== JSON Output for Integration ===\n")
    
    scanner = Scanner()
    
    print("🔍 Getting JSON output for Cloudflare...")
    result = scanner.scan(target="1.1.1.1", run="ip_classify")
    
    if result.success:
        # Extract just the classification data
        classification = result.data[0]['result']
        
        # Pretty print JSON
        print("JSON Output:")
        print(json.dumps(classification, indent=2))
    else:
        print(f"Error: {result.error}")


def main():
    """Run all examples."""
    print("🏷️  IP Classification Scanner Examples\n")
    print("This script demonstrates various usage patterns for the IP Classification Scanner.\n")
    
    try:
        example_basic_usage()
        example_multiple_ips()
        example_direct_scanner()
        example_private_ip()
        example_infrastructure_mapping()
        example_json_output()
        
        print("\n✅ All examples completed successfully!")
        print("\n💡 Try these CLI commands:")
        print("   pgdn-scanner --target 1.1.1.1 --run ip_classify")
        print("   pgdn-scanner --target \"8.8.8.8,1.1.1.1\" --run ip_classify --json")
        print("   pgdn-scanner --target 192.168.1.1 --run ip_classify --pretty")
        
    except Exception as e:
        print(f"\n❌ Error running examples: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()