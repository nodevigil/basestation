#!/usr/bin/env python3
"""
Test script for the new ScoringAgent
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from agents.score.scoring_agent import ScoringAgent
from core.config import Config

def test_scoring_agent():
    """Test the ScoringAgent functionality."""
    print("🧪 Testing ScoringAgent...")
    
    # Create a config instance
    config = Config()
    
    # Create scoring agent
    scoring_agent = ScoringAgent(config)
    print("✅ ScoringAgent created successfully")
    
    # Create sample scan data for testing
    sample_scan_results = [
        {
            'ip_address': '192.168.1.100',
            'raw_results': {
                'generic_scan': {
                    'ip': '192.168.1.100',
                    'open_ports': [22, 80, 443],
                    'tls': {
                        'issuer': 'Let\'s Encrypt',
                        'expiry': '2025-12-31'
                    },
                    'vulns': {}
                }
            }
        },
        {
            'ip_address': '192.168.1.101', 
            'raw_results': {
                'generic_scan': {
                    'ip': '192.168.1.101',
                    'open_ports': [22, 2375],  # Docker socket exposed - critical
                    'tls': {
                        'issuer': 'Self-signed',
                        'expiry': None
                    },
                    'vulns': {
                        'CVE-2023-1234': 'Critical vulnerability'
                    }
                }
            }
        }
    ]
    
    # Process the results
    print("📊 Processing sample scan results...")
    scored_results = scoring_agent.process_results(sample_scan_results)
    
    print(f"✅ Scored {len(scored_results)} results")
    
    # Display results
    for result in scored_results:
        ip = result.get('ip_address', 'Unknown')
        score = result.get('trust_score', 0)
        risk = result.get('risk_level', 'UNKNOWN')
        flags = result.get('trust_flags', [])
        
        print(f"\n📋 Results for {ip}:")
        print(f"   Trust Score: {score}")
        print(f"   Risk Level: {risk}")
        if flags:
            print(f"   Flags: {', '.join(flags)}")
        else:
            print("   Flags: None")

if __name__ == "__main__":
    test_scoring_agent()
