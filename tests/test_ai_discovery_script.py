#!/usr/bin/env python3
"""
Quick AI Detector Test Script

Run this to test AI protocol detection directly without the full discovery pipeline.
"""

import os
import json
import logging
from agents.discovery.ai_detector import AIServiceDetector

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def quick_ai_test(hostname, test_data=None):
    """
    Quick test of AI detector with minimal setup
    
    Args:
        hostname: Target hostname to analyze
        test_data: Optional test data, will create sample if None
    """
    
    # Simple config class
    class TestConfig:
        def __init__(self):
            self.openai_api_key = os.environ.get('OPENAI_API_KEY')
            self.anthropic_api_key = os.environ.get('ANTHROPIC_API_KEY')
            self.ai_provider = 'auto'
            self.ai_fallback_threshold = 0.4
    
    # Initialize AI detector
    config = TestConfig()
    ai_detector = AIServiceDetector(config)
    
    # Use provided test data or create sample
    if test_data is None:
        test_data = create_sample_scan_data(hostname)
    
    print(f"\n🤖 Testing AI detection for: {hostname}")
    print(f"📊 Test data: {json.dumps(test_data, indent=2)}")
    print("-" * 60)
    
    # Run AI analysis
    try:
        protocol, confidence, evidence = ai_detector.analyze_service_with_ai(
            hostname, test_data, discovery_id=999
        )
        
        print(f"✅ AI Analysis Results:")
        print(f"   Protocol: {protocol}")
        print(f"   Confidence: {confidence:.3f}")
        print(f"   Provider: {evidence.get('provider', 'unknown')}")
        print(f"   Reasoning: {evidence.get('ai_reasoning', 'No reasoning provided')}")
        print(f"   Key Indicators: {evidence.get('key_indicators', [])}")
        
        return protocol, confidence, evidence
        
    except Exception as e:
        print(f"❌ AI Analysis Failed: {e}")
        return None, 0.0, {'error': str(e)}

def create_sample_scan_data(hostname):
    """Create sample scan data for testing"""
    
    # Sample data templates for different protocols
    samples = {
        'sui': {
            'nmap': {
                'ports': [9000, 9100],
                'services': {
                    9000: {'name': 'http', 'product': 'unknown', 'version': ''},
                    9100: {'name': 'http', 'product': 'unknown', 'version': ''}
                }
            },
            'probes': {
                'http_9000_root': {
                    'status': 200,
                    'headers': {'content-type': 'application/json'},
                    'body': '{"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid Request"},"id":null}',
                    'url': f'http://{hostname}:9000/',
                    'response_time_ms': 45
                }
            }
        },
        'ethereum': {
            'nmap': {
                'ports': [8545, 8546],
                'services': {
                    8545: {'name': 'http', 'product': 'unknown', 'version': ''},
                    8546: {'name': 'websocket', 'product': 'unknown', 'version': ''}
                }
            },
            'probes': {
                'http_8545_root': {
                    'status': 200,
                    'headers': {'content-type': 'application/json'},
                    'body': '{"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid Request"},"id":null}',
                    'url': f'http://{hostname}:8545/',
                    'response_time_ms': 32
                }
            }
        },
        'filecoin': {
            'nmap': {
                'ports': [1234, 3453],
                'services': {
                    1234: {'name': 'http', 'product': 'lotus', 'version': ''},
                    3453: {'name': 'libp2p', 'product': 'unknown', 'version': ''}
                }
            },
            'probes': {
                'http_1234_root': {
                    'status': 200,
                    'headers': {'content-type': 'application/json'},
                    'body': '{"jsonrpc":"2.0","method":"Filecoin.Version","params":[],"id":1}',
                    'url': f'http://{hostname}:1234/',
                    'response_time_ms': 67
                }
            }
        },
        'generic_web': {
            'nmap': {
                'ports': [80, 443],
                'services': {
                    80: {'name': 'http', 'product': 'nginx', 'version': '1.18.0'},
                    443: {'name': 'https', 'product': 'nginx', 'version': '1.18.0'}
                }
            },
            'probes': {
                'http_80_root': {
                    'status': 200,
                    'headers': {'server': 'nginx/1.18.0', 'content-type': 'text/html'},
                    'body': '<html><head><title>Welcome</title></head><body><h1>Hello World</h1></body></html>',
                    'url': f'http://{hostname}:80/',
                    'response_time_ms': 23
                }
            }
        }
    }
    
    # Try to guess protocol from hostname or use generic
    hostname_lower = hostname.lower()
    if 'sui' in hostname_lower:
        return samples['sui']
    elif 'eth' in hostname_lower or 'geth' in hostname_lower:
        return samples['ethereum']
    elif 'fil' in hostname_lower or 'lotus' in hostname_lower:
        return samples['filecoin']
    else:
        return samples['generic_web']

def run_multiple_tests():
    """Run tests with different sample data"""
    test_cases = [
        ("sui-mainnet.example.com", None),  # Will auto-generate Sui data
        ("ethereum-node.test.com", None),   # Will auto-generate Ethereum data
        ("filecoin.storage.com", None),     # Will auto-generate Filecoin data
        ("unknown-service.com", None),      # Will auto-generate generic data
    ]
    
    print("🧪 Running Multiple AI Detection Tests")
    print("=" * 60)
    
    for hostname, test_data in test_cases:
        try:
            protocol, confidence, evidence = quick_ai_test(hostname, test_data)
            print(f"\n{'='*60}")
        except Exception as e:
            print(f"\n❌ Test failed for {hostname}: {e}")
            print(f"{'='*60}")

def custom_test():
    """Interactive test with custom data"""
    print("\n🔧 Custom AI Test")
    print("Enter your test data:")
    
    hostname = input("Hostname: ").strip()
    if not hostname:
        hostname = "test.example.com"
    
    print("Ports (comma-separated, e.g., '9000,9100'): ", end="")
    ports_input = input().strip()
    if ports_input:
        ports = [int(p.strip()) for p in ports_input.split(',') if p.strip().isdigit()]
    else:
        ports = [80]
    
    print("Sample response body (optional): ", end="")
    body = input().strip()
    if not body:
        body = '{"status": "ok"}'
    
    # Create custom test data
    custom_data = {
        'nmap': {
            'ports': ports,
            'services': {port: {'name': 'http', 'product': '', 'version': ''} for port in ports}
        },
        'probes': {
            f'http_{ports[0]}_root': {
                'status': 200,
                'headers': {'content-type': 'application/json'},
                'body': body,
                'url': f'http://{hostname}:{ports[0]}/',
                'response_time_ms': 50
            }
        }
    }
    
    return quick_ai_test(hostname, custom_data)

if __name__ == "__main__":
    # Check for API keys
    if not os.environ.get('OPENAI_API_KEY') and not os.environ.get('ANTHROPIC_API_KEY'):
        print("❌ No API keys found!")
        print("Set environment variables:")
        print("  export OPENAI_API_KEY='your-key'")
        print("  export ANTHROPIC_API_KEY='your-key'  # Optional")
        exit(1)
    
    print("🚀 AI Detector Quick Test")
    print("Choose test mode:")
    print("1. Quick test with sample data")
    print("2. Run multiple test cases")
    print("3. Custom test with your data")
    
    choice = input("\nEnter choice (1-3): ").strip()
    
    if choice == '1':
        hostname = input("Enter hostname to test: ").strip()
        if not hostname:
            hostname = "sui-node.example.com"
        quick_ai_test(hostname)
        
    elif choice == '2':
        run_multiple_tests()
        
    elif choice == '3':
        custom_test()
        
    else:
        print("Running default test...")
        quick_ai_test("sui-node.example.com")