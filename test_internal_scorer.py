#!/usr/bin/env python3
"""
Test script to verify the external scorer logging works.
"""

import logging
import sys
import os

# Set up logging first
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s [%(name)s]: %(message)s'
)

try:
    # Import the external scorer
    from pgdn.scoring.default_scorer import DefaultScorer
    print("🧪 Testing external pgdn.scoring.default_scorer.DefaultScorer...")
    scorer = DefaultScorer()
    external_available = True
except ImportError as e:
    print(f"❌ Failed to import external scorer: {e}")
    print("🔄 Falling back to internal scorer...")
    from agents.score.scoring_agent import DefaultTrustScorer
    scorer = DefaultTrustScorer()
    external_available = False
test_data = {
    'ip': '192.168.1.100',
    'open_ports': [22, 80, 443],
    'tls': {'issuer': 'Test CA', 'expiry': '2024-12-31'},
    'vulns': {},
    'docker_exposure': {'exposed': False}
}

if external_available:
    print("📝 Calling external scorer.score()...")
else:
    print("📝 Calling internal scorer.score()...")

result = scorer.score(test_data)
print(f"✅ Result: {result}")

if external_available:
    print("🎉 External scorer is working!")
else:
    print("🔄 Using internal scorer as fallback")
