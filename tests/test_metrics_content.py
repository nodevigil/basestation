#!/usr/bin/env python3
"""
Test script to see what's actually in the metrics endpoint.
"""

import httpx

test_ip = "139.84.148.36"
url = f"http://{test_ip}:9184/metrics"

print(f"🔍 Fetching metrics from: {url}")

try:
    r = httpx.get(url, timeout=10, verify=False)
    print(f"📊 Status: {r.status_code}")
    print(f"📏 Content length: {len(r.text)} characters")
    
    # Check for various Sui-related keywords
    keywords = ["sui_validator", "sui", "validator", "consensus", "epoch"]
    print(f"\n🔍 Keyword analysis:")
    for keyword in keywords:
        count = r.text.lower().count(keyword.lower())
        print(f"  '{keyword}': {count} occurrences")
    
    # Show first 500 characters
    print(f"\n📄 First 500 characters of response:")
    print(r.text[:500])
    
    # Show some lines that might contain sui
    print(f"\n🔍 Lines containing 'sui' (case insensitive):")
    sui_lines = [line for line in r.text.split('\n') if 'sui' in line.lower()][:10]
    for line in sui_lines:
        print(f"  {line}")
        
except Exception as e:
    print(f"❌ Error: {e}")
