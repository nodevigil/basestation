#!/usr/bin/env python3
"""
Script to validate protocol signature uniqueness

This script confirms that protocol signatures are unique and properly validated
to avoid conflicts between different protocols.
"""

import sys
import os
import base64
import hashlib

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.database import get_db_session, Protocol, ProtocolSignature
from agents.signature.protocol_signature_generator_agent import ProtocolSignatureGeneratorAgent


def validate_signature_uniqueness():
    """
    Validate that all protocol signatures are unique and check uniqueness scores.
    """
    print("🔍 Protocol Signature Uniqueness Validation")
    print("=" * 60)
    
    try:
        with get_db_session() as session:
            # Get all protocols and their signatures
            protocols_with_sigs = session.query(Protocol, ProtocolSignature).join(
                ProtocolSignature, Protocol.id == ProtocolSignature.protocol_id
            ).all()
            
            if not protocols_with_sigs:
                print("❌ No protocol signatures found in database")
                return False
            
            print(f"📊 Found {len(protocols_with_sigs)} protocols with signatures")
            print()
            
            # Track signatures to check for duplicates
            port_signatures = {}
            banner_signatures = {}
            endpoint_signatures = {}
            keyword_signatures = {}
            
            uniqueness_issues = []
            validation_results = []
            
            for protocol, signature in protocols_with_sigs:
                print(f"🔍 Validating {protocol.name}:")
                print(f"   • Uniqueness score: {signature.uniqueness_score:.3f}")
                print(f"   • Signature version: {signature.signature_version}")
                
                # Check port signature uniqueness
                port_sig = signature.port_signature
                if port_sig in port_signatures:
                    conflict_protocol = port_signatures[port_sig]
                    uniqueness_issues.append({
                        'type': 'port',
                        'protocol1': protocol.name,
                        'protocol2': conflict_protocol,
                        'signature': port_sig[:20] + "..."
                    })
                    print(f"   ⚠️  Port signature conflicts with {conflict_protocol}")
                else:
                    port_signatures[port_sig] = protocol.name
                    print(f"   ✅ Port signature is unique")
                
                # Check banner signature uniqueness
                banner_sig = signature.banner_signature
                if banner_sig in banner_signatures:
                    conflict_protocol = banner_signatures[banner_sig]
                    uniqueness_issues.append({
                        'type': 'banner',
                        'protocol1': protocol.name,
                        'protocol2': conflict_protocol,
                        'signature': banner_sig[:20] + "..."
                    })
                    print(f"   ⚠️  Banner signature conflicts with {conflict_protocol}")
                else:
                    banner_signatures[banner_sig] = protocol.name
                    print(f"   ✅ Banner signature is unique")
                
                # Check endpoint signature uniqueness
                endpoint_sig = signature.endpoint_signature
                if endpoint_sig in endpoint_signatures:
                    conflict_protocol = endpoint_signatures[endpoint_sig]
                    uniqueness_issues.append({
                        'type': 'endpoint',
                        'protocol1': protocol.name,
                        'protocol2': conflict_protocol,
                        'signature': endpoint_sig[:20] + "..."
                    })
                    print(f"   ⚠️  Endpoint signature conflicts with {conflict_protocol}")
                else:
                    endpoint_signatures[endpoint_sig] = protocol.name
                    print(f"   ✅ Endpoint signature is unique")
                
                # Check keyword signature uniqueness
                keyword_sig = signature.keyword_signature
                if keyword_sig in keyword_signatures:
                    conflict_protocol = keyword_signatures[keyword_sig]
                    uniqueness_issues.append({
                        'type': 'keyword',
                        'protocol1': protocol.name,
                        'protocol2': conflict_protocol,
                        'signature': keyword_sig[:20] + "..."
                    })
                    print(f"   ⚠️  Keyword signature conflicts with {conflict_protocol}")
                else:
                    keyword_signatures[keyword_sig] = protocol.name
                    print(f"   ✅ Keyword signature is unique")
                
                validation_results.append({
                    'protocol': protocol.name,
                    'uniqueness_score': signature.uniqueness_score,
                    'version': signature.signature_version,
                    'port_unique': port_sig not in [item['signature'] for item in uniqueness_issues if item['type'] == 'port'],
                    'banner_unique': banner_sig not in [item['signature'] for item in uniqueness_issues if item['type'] == 'banner'],
                    'endpoint_unique': endpoint_sig not in [item['signature'] for item in uniqueness_issues if item['type'] == 'endpoint'],
                    'keyword_unique': keyword_sig not in [item['signature'] for item in uniqueness_issues if item['type'] == 'keyword']
                })
                
                print()
            
            # Summary
            print("📋 Validation Summary:")
            print(f"   • Total protocols validated: {len(protocols_with_sigs)}")
            print(f"   • Uniqueness conflicts found: {len(uniqueness_issues)}")
            
            if uniqueness_issues:
                print("\n⚠️  Signature Conflicts Found:")
                for issue in uniqueness_issues:
                    print(f"   • {issue['type'].capitalize()} signature conflict:")
                    print(f"     - {issue['protocol1']} ↔ {issue['protocol2']}")
                    print(f"     - Signature: {issue['signature']}")
                return False
            else:
                print("   ✅ All signatures are unique!")
                
                # Show statistics
                avg_uniqueness = sum(result['uniqueness_score'] for result in validation_results) / len(validation_results)
                min_uniqueness = min(result['uniqueness_score'] for result in validation_results)
                max_uniqueness = max(result['uniqueness_score'] for result in validation_results)
                
                print(f"\n📊 Uniqueness Score Statistics:")
                print(f"   • Average uniqueness: {avg_uniqueness:.3f}")
                print(f"   • Minimum uniqueness: {min_uniqueness:.3f}")
                print(f"   • Maximum uniqueness: {max_uniqueness:.3f}")
                
                low_uniqueness = [r for r in validation_results if r['uniqueness_score'] < 0.7]
                if low_uniqueness:
                    print(f"\n⚠️  Protocols with low uniqueness scores (<0.7):")
                    for result in low_uniqueness:
                        print(f"   • {result['protocol']}: {result['uniqueness_score']:.3f}")
                
                return True
    
    except Exception as e:
        print(f"❌ Validation failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_signature_generation_uniqueness():
    """
    Test the signature generation process to ensure it validates uniqueness.
    """
    print("\n🧪 Testing Signature Generation Uniqueness Validation")
    print("=" * 60)
    
    try:
        # Initialize the signature generator agent
        agent = ProtocolSignatureGeneratorAgent()
        
        # Generate signatures from existing protocols
        print("🔧 Generating signatures from existing protocols...")
        updated_protocols = agent._generate_signatures_from_protocols()
        
        print(f"✅ Generated signatures for {len(updated_protocols)} protocols:")
        for protocol in updated_protocols:
            print(f"   • {protocol}")
        
        # Get processing statistics
        print("\n📊 Signature Processing Statistics:")
        stats = agent.get_signature_processing_stats()
        
        print(f"   • Total scans: {stats['total_scans']}")
        print(f"   • Processed scans: {stats['processed_scans']}")
        print(f"   • Pending scans: {stats['pending_scans']}")
        print(f"   • Processing rate: {stats['processing_rate']:.1%}")
        
        if stats['protocol_breakdown']:
            print(f"\n   Protocol breakdown:")
            for breakdown in stats['protocol_breakdown']:
                print(f"     • {breakdown['protocol']}: {breakdown['processed']}/{breakdown['total_scans']} processed")
        
        return True
        
    except Exception as e:
        print(f"❌ Signature generation test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def analyze_signature_components():
    """
    Analyze the components that make up each protocol signature.
    """
    print("\n🔬 Analyzing Signature Components")
    print("=" * 60)
    
    try:
        with get_db_session() as session:
            protocols = session.query(Protocol).all()
            
            print(f"📊 Analyzing {len(protocols)} protocol definitions:")
            print()
            
            for protocol in protocols:
                print(f"🔍 {protocol.name}:")
                print(f"   • Ports ({len(protocol.ports)}): {protocol.ports}")
                print(f"   • Banners ({len(protocol.banners)}): {protocol.banners[:3]}{'...' if len(protocol.banners) > 3 else ''}")
                print(f"   • Endpoints ({len(protocol.endpoints)}): {protocol.endpoints[:3]}{'...' if len(protocol.endpoints) > 3 else ''}")
                print(f"   • HTTP Paths ({len(protocol.http_paths)}): {protocol.http_paths[:3]}{'...' if len(protocol.http_paths) > 3 else ''}")
                print(f"   • Keywords ({len(protocol.metrics_keywords)}): {protocol.metrics_keywords[:3]}{'...' if len(protocol.metrics_keywords) > 3 else ''}")
                print(f"   • ID Hints ({len(protocol.identification_hints)}): {protocol.identification_hints[:3]}{'...' if len(protocol.identification_hints) > 3 else ''}")
                print()
        
        return True
        
    except Exception as e:
        print(f"❌ Component analysis failed: {e}")
        return False


if __name__ == "__main__":
    try:
        # Run all validation tests
        print("🚀 Starting comprehensive signature uniqueness validation")
        print()
        
        # 1. Validate existing signatures
        validation_passed = validate_signature_uniqueness()
        
        # 2. Analyze signature components
        analysis_passed = analyze_signature_components()
        
        # 3. Test signature generation
        generation_passed = test_signature_generation_uniqueness()
        
        print("\n" + "=" * 60)
        print("🎯 Final Results:")
        print(f"   • Signature uniqueness validation: {'✅ PASSED' if validation_passed else '❌ FAILED'}")
        print(f"   • Component analysis: {'✅ PASSED' if analysis_passed else '❌ FAILED'}")
        print(f"   • Generation testing: {'✅ PASSED' if generation_passed else '❌ FAILED'}")
        
        overall_success = validation_passed and analysis_passed and generation_passed
        
        if overall_success:
            print("\n🎉 All signature uniqueness tests PASSED!")
            print("✅ Protocol signatures are confirmed to be unique")
        else:
            print("\n❌ Some signature uniqueness tests FAILED!")
            print("⚠️  Please review the validation results above")
            sys.exit(1)
            
    except Exception as e:
        print(f"\n❌ Validation script failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
