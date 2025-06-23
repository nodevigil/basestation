#!/usr/bin/env python3
"""
Test the refactored scoring agent with built-in and external scorer loading.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from agents.score.scoring_agent import ScoringAgent, DefaultTrustScorer
from pgdn.core.config import Config


def test_default_trust_scorer():
    """Test the built-in DefaultTrustScorer directly."""
    print("🧪 Testing DefaultTrustScorer...")
    
    scorer = DefaultTrustScorer()
    
    # Test with sample scan data
    sample_scan = {
        'ip': '192.168.1.100',
        'open_ports': [22, 80, 443, 2375],  # Include Docker socket
        'tls': {
            'issuer': 'Self-signed',
            'expiry': None
        },
        'vulns': {
            'CVE-2023-1234': 'Test vulnerability'
        },
        'docker_exposure': {'exposed': True}
    }
    
    result = scorer.score(sample_scan)
    
    print(f"   IP: {result['ip']}")
    print(f"   Score: {result['score']}")
    print(f"   Flags: {result['flags']}")
    print(f"   Summary: {result['summary']}")
    print(f"   Docker Exposure: {result['docker_exposure']}")
    
    # Verify expected deductions
    expected_deductions = 30 + 10 + 25 + 15  # Docker + SSH + TLS + 1 vuln
    expected_score = 100 - expected_deductions
    
    assert result['score'] == expected_score, f"Expected score {expected_score}, got {result['score']}"
    assert len(result['flags']) == 4, f"Expected 4 flags, got {len(result['flags'])}"
    print("   ✅ DefaultTrustScorer working correctly")


def test_scoring_agent_fallback():
    """Test ScoringAgent with fallback to built-in scorer."""
    print("\n🧪 Testing ScoringAgent with built-in scorer fallback...")
    
    config = Config()
    scoring_agent = ScoringAgent(config)
    
    # Verify it's using the built-in scorer
    assert isinstance(scoring_agent.trust_scorer, DefaultTrustScorer), "Should use DefaultTrustScorer as fallback"
    
    # Test with sample scan results
    sample_results = [
        {
            'scan_id': 1,
            'validator_id': 'test-validator',
            'scan_date': '2024-06-18T12:00:00',
            'ip_address': '192.168.1.100',
            'raw_results': {
                'generic_scan': {
                    'ip': '192.168.1.100',
                    'open_ports': [22, 80, 443],
                    'tls': {
                        'issuer': 'Let\'s Encrypt',
                        'expiry': '2024-12-31'
                    },
                    'vulns': {},
                    'docker_exposure': {'exposed': False}
                }
            }
        }
    ]
    
    scored_results = scoring_agent.process_results(sample_results)
    
    assert len(scored_results) == 1, "Should have scored 1 result"
    
    result = scored_results[0]
    assert 'trust_score' in result, "Should have trust_score"
    assert 'risk_level' in result, "Should have risk_level"
    assert 'trust_flags' in result, "Should have trust_flags"
    assert 'trust_summary' in result, "Should have trust_summary"
    
    # Should have moderate score (deduction for SSH only)
    expected_score = 90  # 100 - 10 for SSH
    assert result['trust_score'] == expected_score, f"Expected score {expected_score}, got {result['trust_score']}"
    assert result['risk_level'] == 'LOW', f"Expected LOW risk, got {result['risk_level']}"
    
    print(f"   Trust Score: {result['trust_score']}")
    print(f"   Risk Level: {result['risk_level']}")
    print(f"   Flags: {result['trust_flags']}")
    print("   ✅ ScoringAgent fallback working correctly")


def test_external_scorer_loading():
    """Test external scorer loading (will fail gracefully)."""
    print("\n🧪 Testing external scorer loading...")
    
    # Create a mock config with external scorer path
    config = Config()
    config.module_path = "pgdn.scoring.advanced_scorer.AdvancedScorer"
    
    scoring_agent = ScoringAgent(config)
    
    # Should fall back to DefaultTrustScorer since external scorer doesn't exist
    assert isinstance(scoring_agent.trust_scorer, DefaultTrustScorer), "Should fallback to DefaultTrustScorer"
    
    print("   ✅ External scorer loading handles missing library gracefully")


if __name__ == "__main__":
    print("🚀 Testing Refactored Scoring Agent\n")
    
    try:
        test_default_trust_scorer()
        test_scoring_agent_fallback()
        test_external_scorer_loading()
        
        print("\n🎉 All tests passed! Refactored scoring agent is working correctly.")
        print("\n📝 Summary:")
        print("   • Built-in DefaultTrustScorer combines original trust.py logic")
        print("   • Dynamic scorer loading with graceful fallback")
        print("   • External scorer support via importlib")
        print("   • Backward compatible with existing interface")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
