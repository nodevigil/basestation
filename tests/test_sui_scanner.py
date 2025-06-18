#!/usr/bin/env python3
"""
Quick test script to verify Sui scanner functionality.
"""

import sys
sys.path.append('.')

from scanning.sui_scanner import SuiSpecificScanner
from core.logging import setup_logging
from core.config import Config

# Setup logging
config = Config()
setup_logging(config.logging)

# Test with a known IP that had metrics in the previous logs
test_ip = "139.84.148.36"

print(f"🧪 Testing Sui scanner on {test_ip}")
scanner = SuiSpecificScanner()
result = scanner.scan(test_ip)

print(f"📊 Results:")
for key, value in result.items():
    print(f"  {key}: {value}")

print(f"\n🔍 Specifically checking metrics:")
metrics_result = scanner.check_metrics_endpoint(test_ip)
print(f"  {metrics_result}")
