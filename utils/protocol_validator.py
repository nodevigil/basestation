"""
Simple protocol validation for reconnaissance agents.

This module provides a simple way for recon agents to:
1. Check if their protocol exists
2. Verify the protocol has a signature
3. Get the protocol_id for linking validators
"""

from typing import Optional
from core.database import get_db_session, Protocol, ProtocolSignature


def get_protocol_for_recon(protocol_name: str) -> Optional[int]:
    """
    Get protocol ID for reconnaissance agent.
    
    Args:
        protocol_name: Name of the protocol (e.g., 'sui', 'filecoin')
        
    Returns:
        Protocol ID if protocol exists and has signature, None otherwise
    """
    try:
        with get_db_session() as session:
            # Get protocol
            protocol = session.query(Protocol).filter_by(name=protocol_name).first()
            if not protocol:
                print(f"❌ Protocol '{protocol_name}' not found in database")
                print(f"💡 Add it first: python tools/simple_protocol_manager.py --add-protocol {protocol_name}.json")
                return None
            
            # Check if protocol has signature
            signature = session.query(ProtocolSignature).filter_by(protocol_id=protocol.id).first()
            if not signature:
                print(f"❌ Protocol '{protocol_name}' has no signature")
                print(f"💡 Generate one: python tools/simple_protocol_manager.py --generate-signature {protocol_name}")
                return None
            
            print(f"✅ Protocol '{protocol_name}' ready (id: {protocol.id})")
            return protocol.id
            
    except Exception as e:
        print(f"❌ Error checking protocol '{protocol_name}': {e}")
        return None


def validate_recon_readiness(protocol_name: str) -> bool:
    """
    Validate that a protocol is ready for reconnaissance.
    
    Args:
        protocol_name: Name of the protocol
        
    Returns:
        True if ready, False otherwise
    """
    protocol_id = get_protocol_for_recon(protocol_name)
    return protocol_id is not None
