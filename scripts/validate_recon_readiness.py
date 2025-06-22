#!/usr/bin/env python3
"""
Validation script to check protocol signatures before running reconnaissance.

This script ensures that all protocols have their signatures generated
before running reconnaissance agents.
"""

import sys
from typing import List, Dict
from core.database import get_db_session, Protocol, ProtocolSignature
from core.config import Config


def check_protocol_signatures() -> Dict[str, bool]:
    """
    Check which protocols have signatures.
    
    Returns:
        Dictionary mapping protocol names to signature status
    """
    results = {}
    
    try:
        with get_db_session() as session:
            protocols = session.query(Protocol).all()
            
            for protocol in protocols:
                signature = session.query(ProtocolSignature).filter_by(protocol_id=protocol.id).first()
                results[protocol.name] = signature is not None
                
        return results
        
    except Exception as e:
        print(f"❌ Error checking protocol signatures: {e}")
        return {}


def validate_recon_readiness(required_protocols: List[str] = None) -> bool:
    """
    Validate that required protocols have signatures for reconnaissance.
    
    Args:
        required_protocols: List of protocol names to check. If None, checks all.
        
    Returns:
        True if all required protocols have signatures, False otherwise
    """
    if required_protocols is None:
        required_protocols = ['sui', 'filecoin']  # Default protocols for recon
    
    signature_status = check_protocol_signatures()
    
    print("🔍 Protocol Signature Status:")
    print("-" * 40)
    
    all_ready = True
    for protocol_name in required_protocols:
        if protocol_name in signature_status:
            status = "✅ Ready" if signature_status[protocol_name] else "❌ Missing Signature"
            print(f"{protocol_name:20} {status}")
            if not signature_status[protocol_name]:
                all_ready = False
        else:
            print(f"{protocol_name:20} ❌ Protocol Not Found")
            all_ready = False
    
    print("-" * 40)
    
    if all_ready:
        print("🎉 All required protocols have signatures! Reconnaissance can proceed.")
    else:
        print("⚠️  Some protocols are missing signatures. Please run signature generation first.")
        print("\nTo generate signatures, run:")
        print("  python -m agents.signature.protocol_signature_generator_agent")
    
    return all_ready


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Validate protocol signatures for reconnaissance')
    parser.add_argument(
        '--protocols', 
        nargs='+', 
        help='Specific protocols to check (default: sui filecoin)'
    )
    parser.add_argument(
        '--list-all', 
        action='store_true', 
        help='List all protocols and their signature status'
    )
    
    args = parser.parse_args()
    
    if args.list_all:
        signature_status = check_protocol_signatures()
        print("📋 All Protocol Signature Status:")
        print("-" * 40)
        for protocol_name, has_signature in signature_status.items():
            status = "✅ Ready" if has_signature else "❌ Missing Signature"
            print(f"{protocol_name:20} {status}")
        return
    
    required_protocols = args.protocols
    is_ready = validate_recon_readiness(required_protocols)
    
    sys.exit(0 if is_ready else 1)


if __name__ == "__main__":
    main()
