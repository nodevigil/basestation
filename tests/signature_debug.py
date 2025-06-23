#!/usr/bin/env python3
"""
Test script to debug signature matching using database results
"""

import sys
import os
import signal
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from agents.discovery.discovery_agent import DiscoveryAgent
from pgdn.core.database import get_db_session, Protocol, ProtocolSignature
from sqlalchemy import text

def test_signature_matching_from_db():
    """Test signature matching using existing database scan results"""
    print("🧪 Testing signature matching with database results")
    print("=" * 60)
    
    try:
        # First, check database state
        print("🗄️ Checking database state...")
        with get_db_session() as session:
            from pgdn.core.database import Protocol, ProtocolSignature
            
            protocol_count = session.query(Protocol).count()
            signature_count = session.query(ProtocolSignature).count()
            
            print(f"   Protocols in database: {protocol_count}")
            print(f"   Signatures in database: {signature_count}")
            
            if protocol_count == 0:
                print("❌ No protocols found in database - need to run protocol_seeder.py first")
                return
                
            if signature_count == 0:
                print("❌ No signatures found in database - need to generate signatures first")
                return
            
            # Check for Sui protocol specifically
            sui_protocol = session.query(Protocol).filter_by(name='sui').first()
            if sui_protocol:
                print(f"   ✅ Sui protocol found (ID: {sui_protocol.id})")
                sui_signature = session.query(ProtocolSignature).filter_by(protocol_id=sui_protocol.id).first()
                print(f"   {'✅' if sui_signature else '❌'} Sui signature {'found' if sui_signature else 'missing'}")
            else:
                print("   ❌ Sui protocol not found")
        
        # Now test the agent, but with timeout protection
        print("\n🤖 Initializing agent...")
        print("   Step 1: Creating DiscoveryAgent instance...")
        
        # Enable debug logging
        import logging
        logging.basicConfig(level=logging.WARNING)  # Only show warnings and errors
        logger = logging.getLogger('agents.DePINDiscoveryAgent')
        logger.setLevel(logging.WARNING)  # Reduce agent logging to warnings only
        
        agent = DiscoveryAgent()
        print("   Step 1: ✅ DiscoveryAgent created successfully")
        
        print("📚 Loading protocols with timeout...")
        import signal
        
        def timeout_handler(signum, frame):
            raise TimeoutError("Loading protocols timed out after 30 seconds")
        
        # Set timeout for loading protocols
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(30)  # 30 second timeout
        
        try:
            print("   Step 2: Calling _load_protocols_with_signatures()...")
            protocols = agent._load_protocols_with_signatures()
            signal.alarm(0)  # Cancel alarm
            print(f"   Step 2: ✅ Loaded {len(protocols)} protocols successfully")
            
            if len(protocols) == 0:
                print("❌ No protocols loaded - check database join query")
                return
                
        except TimeoutError:
            signal.alarm(0)  # Cancel alarm
            print("❌ Loading protocols timed out - there may be a database issue")
            return
        except Exception as e:
            signal.alarm(0)  # Cancel alarm
            print(f"❌ Error loading protocols: {e}")
            import traceback
            traceback.print_exc()
            return
        
        # Continue with the test if protocols loaded successfully
        hostname = 'prod.sui.infstones.io'
        expected_protocol = 'sui'
        
        print(f"📡 Testing with host: {hostname}")
        print(f"📋 Expected protocol: {expected_protocol}")
        print("🔧 Note: Using mock data to avoid network timeouts")
        
        # Mock nmap data based on known ports
        nmap_data = {
            'ports': [22, 80, 443, 8080, 8443, 9000, 9100, 3000, 5000],
            'services': {
                9000: {'name': 'http', 'product': 'unknown'},
                9100: {'name': 'http', 'product': 'prometheus'},
                443: {'name': 'https', 'product': 'unknown'}
            }
        }
        
        # Mock probe data with Sui-specific responses
        probe_data = {
            'http_9000_/': {
                'status': 405,
                'body': 'Method Not Allowed',
                'headers': {'content-type': 'text/plain', 'server': 'hyper/0.14'}
            },
            'rpc_9000_sui_getChainId': {
                'status': 200,
                'body': '{"jsonrpc":"2.0","result":"35834a8a","id":1}',
                'headers': {'content-type': 'application/json'}
            },
            'http_9100_/metrics': {
                'status': 200,
                'body': '# HELP sui_current_epoch Current epoch\nsui_current_epoch 123\n# HELP sui_validator_status Validator status\nsui_validator_status{status="active"} 1\n',
                'headers': {'content-type': 'text/plain; version=0.0.4; charset=utf-8'}
            }
        }
        
        print(f"📊 Mock data:")
        print(f"   Open ports: {nmap_data['ports']}")
        print(f"   Probe responses: {len(probe_data)}")
        
        # Find Sui protocol
        sui_protocols = [p for p in protocols if p.get('name', '').lower() == 'sui']
        if sui_protocols:
            sui_protocol = sui_protocols[0]
            print(f"🔍 Sui protocol found:")
            print(f"   Name: {sui_protocol['name']}")
            print(f"   Ports: {sui_protocol['ports']}")
            print(f"   Uniqueness: {sui_protocol['signature']['uniqueness_score']}")
        
        # Test signature matching directly (bypass probing)
        print(f"\n🔬 Testing signature matching directly...")
        print("   Step 3: Testing with mock data (no network calls)...")
        
        # Add timeout for signature matching too
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(30)  # 30 second timeout
        
        try:
            # Test signature matching directly with our mock data
            # This bypasses the network probing that causes hanging
            protocol_name, confidence, evidence, perf_metrics = agent._match_protocol_signatures(
                nmap_data, probe_data, protocols
            )
            signal.alarm(0)  # Cancel alarm
            print("   Step 3: ✅ Signature matching completed")
        except TimeoutError:
            signal.alarm(0)  # Cancel alarm
            print("❌ Signature matching timed out")
            return
        except Exception as e:
            signal.alarm(0)  # Cancel alarm
            print(f"❌ Error in signature matching: {e}")
            import traceback
            traceback.print_exc()
            return
        
        print(f"\n📊 Results:")
        print(f"   🎯 Detected: {protocol_name}")
        print(f"   📈 Confidence: {confidence:.3f}")
        print(f"   ⏱️  Time: {perf_metrics.get('signature_matching_time', 0):.3f}s")
        
        # Show evidence
        if 'signature_similarities' in evidence:
            sims = evidence['signature_similarities']
            print(f"   🔍 Signature similarities:")
            print(f"     Port: {sims.get('port', 0):.3f}")
            print(f"     Banner: {sims.get('banner', 0):.3f}")
            print(f"     Endpoint: {sims.get('endpoint', 0):.3f}")
            print(f"     Keyword: {sims.get('keyword', 0):.3f}")
        
        if 'manual_checks' in evidence and evidence['manual_checks']:
            print(f"   🔧 Manual evidence: {evidence['manual_checks']}")
        
        # Check success
        if protocol_name == expected_protocol:
            print(f"\n✅ SUCCESS: Correctly identified {expected_protocol}!")
        else:
            print(f"\n❌ ISSUE: Expected {expected_protocol}, got {protocol_name}")
        
        agent.cleanup_session()
        print(f"\n🎉 Test completed")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    print("🔍 Testing signature matching with existing database results...")
    test_signature_matching_from_db()
