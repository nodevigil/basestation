#!/usr/bin/env python3
"""
Simple Protocol Management Tool

This tool focuses on the core requirements:
1. Add new protocols (with ports from file)
2. Link validator addresses to protocols
3. Ensure recon agents use correct protocol linkage
"""

import json
import sys
import os
from typing import Dict, List, Optional

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import get_db_session, Protocol, ProtocolSignature
from sqlalchemy import text


class SimpleProtocolManager:
    """Simple protocol management focused on core requirements."""
    
    def add_protocol_from_file(self, protocol_file: str) -> bool:
        """
        Add a new protocol from a configuration file.
        
        Expected file format:
        {
            "name": "myprotocol",
            "display_name": "My Protocol",
            "category": "blockchain",
            "ports": [9000, 9001],
            "endpoints": ["/health", "/status"],
            "banners": ["myprotocol-node"],
            "rpc_methods": ["myprotocol_getInfo"],
            "metrics_keywords": ["myprotocol_metrics"],
            "http_paths": ["/metrics"],
            "identification_hints": ["myprotocol blockchain"]
        }
        """
        try:
            with open(protocol_file, 'r') as f:
                protocol_data = json.load(f)
            
            required_fields = ['name', 'display_name', 'category', 'ports']
            for field in required_fields:
                if field not in protocol_data:
                    print(f"❌ Missing required field: {field}")
                    return False
            
            with get_db_session() as session:
                # Check if protocol already exists
                existing = session.query(Protocol).filter_by(name=protocol_data['name']).first()
                if existing:
                    print(f"⚠️  Protocol '{protocol_data['name']}' already exists (id: {existing.id})")
                    return True
                
                # Create new protocol
                protocol = Protocol(
                    name=protocol_data['name'],
                    display_name=protocol_data['display_name'],
                    category=protocol_data['category'],
                    ports=protocol_data['ports'],
                    endpoints=protocol_data.get('endpoints', []),
                    banners=protocol_data.get('banners', []),
                    rpc_methods=protocol_data.get('rpc_methods', []),
                    metrics_keywords=protocol_data.get('metrics_keywords', []),
                    http_paths=protocol_data.get('http_paths', []),
                    identification_hints=protocol_data.get('identification_hints', [])
                )
                
                session.add(protocol)
                session.commit()
                
                print(f"✅ Added protocol '{protocol.name}' (id: {protocol.id})")
                print(f"   Display name: {protocol.display_name}")
                print(f"   Category: {protocol.category}")
                print(f"   Ports: {protocol.ports}")
                
                return True
                
        except FileNotFoundError:
            print(f"❌ Protocol file not found: {protocol_file}")
            return False
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON in protocol file: {e}")
            return False
        except Exception as e:
            print(f"❌ Failed to add protocol: {e}")
            return False
    
    def generate_protocol_signature(self, protocol_name: str) -> bool:
        """Generate signature for a protocol (simplified)."""
        try:
            with get_db_session() as session:
                protocol = session.query(Protocol).filter_by(name=protocol_name).first()
                if not protocol:
                    print(f"❌ Protocol '{protocol_name}' not found")
                    return False
                
                # Check if signature already exists
                existing_sig = session.query(ProtocolSignature).filter_by(protocol_id=protocol.id).first()
                if existing_sig:
                    print(f"✅ Protocol '{protocol_name}' already has signature")
                    return True
                
                # Create simple signature based on protocol data
                signature = ProtocolSignature(
                    protocol_id=protocol.id,
                    port_signature=','.join(map(str, protocol.ports)) if protocol.ports else '',
                    banner_signature=','.join(protocol.banners) if protocol.banners else '',
                    endpoint_signature=','.join(protocol.endpoints) if protocol.endpoints else '',
                    keyword_signature=','.join(protocol.metrics_keywords) if protocol.metrics_keywords else '',
                    uniqueness_score=75.0,  # Default score
                    signature_version=1
                )
                
                session.add(signature)
                session.commit()
                
                print(f"✅ Generated signature for protocol '{protocol_name}'")
                return True
                
        except Exception as e:
            print(f"❌ Failed to generate signature: {e}")
            return False
    
    def link_validator_to_protocol(self, validator_address: str, protocol_name: str) -> bool:
        """Link a validator address to a specific protocol."""
        try:
            with get_db_session() as session:
                # Get protocol
                protocol = session.query(Protocol).filter_by(name=protocol_name).first()
                if not protocol:
                    print(f"❌ Protocol '{protocol_name}' not found")
                    return False
                
                # Update validator address
                result = session.execute(
                    text("UPDATE validator_addresses SET protocol_id = :protocol_id WHERE address = :address"),
                    {"protocol_id": protocol.id, "address": validator_address}
                )
                
                if result.rowcount == 0:
                    print(f"❌ Validator address '{validator_address}' not found")
                    return False
                
                session.commit()
                print(f"✅ Linked validator '{validator_address}' to protocol '{protocol_name}'")
                return True
                
        except Exception as e:
            print(f"❌ Failed to link validator: {e}")
            return False
    
    def list_protocols(self):
        """List all protocols with their validator counts."""
        try:
            with get_db_session() as session:
                result = session.execute(text("""
                    SELECT 
                        p.id,
                        p.name,
                        p.display_name,
                        p.category,
                        COUNT(va.id) as validator_count,
                        ps.protocol_id IS NOT NULL as has_signature
                    FROM protocols p
                    LEFT JOIN validator_addresses va ON p.id = va.protocol_id
                    LEFT JOIN protocol_signatures ps ON p.id = ps.protocol_id
                    GROUP BY p.id, p.name, p.display_name, p.category, ps.protocol_id
                    ORDER BY p.name
                """))
                
                protocols = result.fetchall()
                
                print("\n📋 Available Protocols:")
                print("-" * 70)
                print(f"{'ID':<4} {'Name':<15} {'Display Name':<25} {'Category':<12} {'Validators':<10} {'Signature'}")
                print("-" * 70)
                
                for row in protocols:
                    protocol_id, name, display_name, category, validator_count, has_signature = row
                    sig_status = "✅" if has_signature else "❌"
                    
                    print(f"{protocol_id:<4} {name:<15} {display_name:<25} {category:<12} {validator_count:<10} {sig_status}")
                
                print("-" * 70)
                
        except Exception as e:
            print(f"❌ Failed to list protocols: {e}")


def main():
    """Main CLI interface."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Simple Protocol Management Tool')
    parser.add_argument('--add-protocol', type=str, help='Add protocol from JSON file')
    parser.add_argument('--generate-signature', type=str, help='Generate signature for protocol')
    parser.add_argument('--link-validator', nargs=2, metavar=('ADDRESS', 'PROTOCOL'), 
                       help='Link validator address to protocol')
    parser.add_argument('--list', action='store_true', help='List all protocols')
    
    args = parser.parse_args()
    
    manager = SimpleProtocolManager()
    
    if args.add_protocol:
        success = manager.add_protocol_from_file(args.add_protocol)
        if success:
            # Auto-generate signature
            protocol_name = None
            try:
                with open(args.add_protocol, 'r') as f:
                    data = json.load(f)
                    protocol_name = data.get('name')
                if protocol_name:
                    print(f"🔄 Auto-generating signature for '{protocol_name}'...")
                    manager.generate_protocol_signature(protocol_name)
            except:
                pass
    
    elif args.generate_signature:
        manager.generate_protocol_signature(args.generate_signature)
    
    elif args.link_validator:
        address, protocol = args.link_validator
        manager.link_validator_to_protocol(address, protocol)
    
    elif args.list:
        manager.list_protocols()
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
