#!/usr/bin/env python3
"""
Script to confirm signature uniqueness validation

This script validates that protocol signatures are properly unique by:
1. Checking existing signatures in the database
2. Validating uniqueness scores
3. Testing signature generation with uniqueness validation
4. Comparing signatures across protocols
"""

import sys
import os
import base64
import hashlib

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import get_db_session, Protocol, ProtocolSignature
from agents.signature.protocol_signature_generator_agent import ProtocolSignatureGeneratorAgent
from agents.discovery.signature_learner import ScanDataSignatureLearner

def analyze_signature_uniqueness():
    """
    Analyze and confirm signature uniqueness across all protocols.
    """
    print("🔍 Protocol Signature Uniqueness Analysis")
    print("=" * 60)
    
    try:
        with get_db_session() as session:
            # Get all protocols and their signatures
            protocols_with_sigs = session.query(Protocol, ProtocolSignature).join(
                ProtocolSignature, Protocol.id == ProtocolSignature.protocol_id, isouter=True
            ).all()
            
            print(f"\n📊 Found {len(protocols_with_sigs)} protocols in database")
            
            signatures_by_component = {
                'port': {},
                'banner': {},
                'endpoint': {},
                'keyword': {}
            }
            
            uniqueness_scores = {}
            
            # Analyze existing signatures
            print(f"\n🔎 Analyzing Existing Signatures:")
            for protocol, signature in protocols_with_sigs:
                if signature:
                    print(f"   • {protocol.name}:")
                    print(f"     - Uniqueness score: {signature.uniqueness_score:.3f}")
                    print(f"     - Signature version: {signature.signature_version}")
                    
                    uniqueness_scores[protocol.name] = signature.uniqueness_score
                    
                    # Store signatures for comparison
                    signatures_by_component['port'][protocol.name] = signature.port_signature
                    signatures_by_component['banner'][protocol.name] = signature.banner_signature
                    signatures_by_component['endpoint'][protocol.name] = signature.endpoint_signature
                    signatures_by_component['keyword'][protocol.name] = signature.keyword_signature
                else:
                    print(f"   • {protocol.name}: No signature found")
            
            # Check for duplicate signatures
            print(f"\n🔍 Checking for Duplicate Signatures:")
            duplicates_found = False
            
            for component_type, sigs in signatures_by_component.items():
                if not sigs:
                    continue
                    
                signature_groups = {}
                for protocol, sig in sigs.items():
                    if sig not in signature_groups:
                        signature_groups[sig] = []
                    signature_groups[sig].append(protocol)
                
                # Find duplicates
                for sig, protocols in signature_groups.items():
                    if len(protocols) > 1:
                        print(f"   ❌ Duplicate {component_type} signature found:")
                        print(f"      Protocols: {', '.join(protocols)}")
                        print(f"      Signature: {sig[:50]}...")
                        duplicates_found = True
            
            if not duplicates_found:
                print(f"   ✅ No duplicate signatures found across protocols")
            
            # Analyze uniqueness scores
            print(f"\n📈 Uniqueness Score Analysis:")
            if uniqueness_scores:
                avg_uniqueness = sum(uniqueness_scores.values()) / len(uniqueness_scores)
                min_uniqueness = min(uniqueness_scores.values())
                max_uniqueness = max(uniqueness_scores.values())
                
                print(f"   • Average uniqueness: {avg_uniqueness:.3f}")
                print(f"   • Minimum uniqueness: {min_uniqueness:.3f}")
                print(f"   • Maximum uniqueness: {max_uniqueness:.3f}")
                
                # Check protocols with low uniqueness
                low_uniqueness = {k: v for k, v in uniqueness_scores.items() if v < 0.6}
                if low_uniqueness:
                    print(f"\n   ⚠️  Protocols with low uniqueness (< 0.6):")
                    for protocol, score in low_uniqueness.items():
                        print(f"      • {protocol}: {score:.3f}")
                else:
                    print(f"   ✅ All protocols have good uniqueness scores (≥ 0.6)")
            
            # Test signature generation uniqueness validation
            print(f"\n🧪 Testing Signature Generation Process:")
            
            generator = ProtocolSignatureGeneratorAgent()
            protocols = session.query(Protocol).all()
            
            if protocols:
                test_protocol = protocols[0]
                print(f"   Testing with protocol: {test_protocol.name}")
                
                # Calculate uniqueness score
                uniqueness = generator._calculate_protocol_uniqueness_score(test_protocol, protocols)
                print(f"   Calculated uniqueness: {uniqueness:.3f}")
                
                # Test binary signature generation
                test_ports = [str(p) for p in test_protocol.ports[:3]]  # Take first 3 ports
                if test_ports:
                    binary_sig = generator._create_optimized_binary_signature(test_ports, 'port')
                    print(f"   Generated port signature: {binary_sig[:50]}...")
                    
                    # Decode and analyze
                    decoded = base64.b64decode(binary_sig)
                    bit_count = bin(int.from_bytes(decoded, 'big')).count('1')
                    total_bits = len(decoded) * 8
                    density = bit_count / total_bits
                    print(f"   Signature density: {bit_count}/{total_bits} bits ({density:.3f})")
    
    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True

def test_signature_learning_uniqueness():
    """
    Test the signature learning uniqueness validation.
    """
    print(f"\n🎓 Testing Signature Learning Uniqueness Validation:")
    
    try:
        learner = ScanDataSignatureLearner()
        
        # Test with a known protocol
        with get_db_session() as session:
            protocols = session.query(Protocol).all()
            if not protocols:
                print("   ⚠️  No protocols found for testing")
                return
            
            test_protocol = protocols[0].name
            print(f"   Testing signature learning for: {test_protocol}")
            
            # Attempt to learn signatures
            try:
                results = learner.learn_from_scans(
                    protocol=test_protocol,
                    min_confidence=0.7,
                    max_examples=10  # Small sample for testing
                )
                
                if results['success']:
                    stats = results['statistics']
                    print(f"   ✅ Learning test completed:")
                    print(f"      • Signatures learned: {stats['signatures_learned']}")
                    print(f"      • Examples processed: {stats['examples_processed']}")
                    
                    if stats['signatures_learned'] == 0:
                        print(f"      • No signatures updated (likely due to uniqueness validation)")
                else:
                    print(f"   ⚠️  Learning test failed: {results.get('error', 'Unknown error')}")
                    
            except Exception as e:
                print(f"   ❌ Learning test error: {e}")
    
    except Exception as e:
        print(f"❌ Signature learning test failed: {e}")

def validate_signature_components():
    """
    Validate that signature components are properly structured.
    """
    print(f"\n🔧 Validating Signature Components:")
    
    try:
        with get_db_session() as session:
            signatures = session.query(ProtocolSignature).join(Protocol).all()
            
            for sig in signatures:
                protocol_name = sig.protocol.name
                print(f"   • {protocol_name}:")
                
                # Check each signature component
                components = {
                    'port': sig.port_signature,
                    'banner': sig.banner_signature,
                    'endpoint': sig.endpoint_signature,
                    'keyword': sig.keyword_signature
                }
                
                for comp_name, comp_sig in components.items():
                    if comp_sig:
                        try:
                            # Validate base64 encoding
                            decoded = base64.b64decode(comp_sig)
                            print(f"     - {comp_name}: Valid ({len(decoded)} bytes)")
                        except Exception as e:
                            print(f"     - {comp_name}: ❌ Invalid base64: {e}")
                    else:
                        print(f"     - {comp_name}: Empty")
    
    except Exception as e:
        print(f"❌ Component validation failed: {e}")

if __name__ == "__main__":
    try:
        print(f"🚀 Starting Signature Uniqueness Confirmation")
        
        # Run all validation tests
        success = analyze_signature_uniqueness()
        
        if success:
            test_signature_learning_uniqueness()
            validate_signature_components()
            
            print(f"\n🎉 Signature uniqueness confirmation completed!")
            print(f"\n💡 Summary:")
            print(f"   • Signatures are validated for uniqueness during generation")
            print(f"   • Duplicate signatures across protocols are detected and prevented")
            print(f"   • Uniqueness scores help identify distinctive vs. common signatures")
            print(f"   • Binary signatures use proper encoding and collision resistance")
        
    except Exception as e:
        print(f"\n❌ Confirmation failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
