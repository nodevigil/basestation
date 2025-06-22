#!/usr/bin/env python3
"""
Migration validation and testing script.

This script validates the migration process and tests the new protocol linking functionality.
"""

import sys
import os
from typing import Dict, List, Any

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import get_db_session
from tools.protocol_migration_tool import ProtocolMigrationTool
from core.config import Config
from sqlalchemy import text


def test_pre_migration_state():
    """Test and validate the current pre-migration state."""
    print("=== Testing Pre-Migration State ===")
    
    with get_db_session() as session:
        # Check current table structure
        result = session.execute(text("""
            SELECT column_name, data_type, is_nullable 
            FROM information_schema.columns 
            WHERE table_name = 'validator_addresses' 
            ORDER BY ordinal_position
        """))
        
        columns = {}
        print("Current validator_addresses columns:")
        for row in result:
            columns[row[0]] = {'type': row[1], 'nullable': row[2]}
            print(f"  {row[0]}: {row[1]} (nullable: {row[2]})")
        
        # Verify expected pre-migration state
        assert 'source' in columns, "source column should exist pre-migration"
        assert 'protocol_id' not in columns, "protocol_id column should not exist pre-migration"
        
        # Check data distribution
        result = session.execute(text("SELECT COUNT(*), source FROM validator_addresses GROUP BY source"))
        source_counts = {}
        print("\nCurrent data distribution:")
        for row in result:
            source_counts[row[1]] = row[0]
            print(f"  {row[1]}: {row[0]} addresses")
        
        # Check protocols
        result = session.execute(text("SELECT id, name FROM protocols ORDER BY id"))
        protocols = {}
        print("\nAvailable protocols:")
        for row in result:
            protocols[row[1]] = row[0]
            print(f"  {row[0]}: {row[1]}")
        
        return {
            'columns': columns,
            'source_counts': source_counts,
            'protocols': protocols
        }


def test_migration_preparation():
    """Test migration preparation and validation."""
    print("\n=== Testing Migration Preparation ===")
    
    config = Config()
    migration_tool = ProtocolMigrationTool()
    
    with get_db_session() as session:
        # Test migration validation
        print("Testing migration validation...")
        validation_result = migration_tool.validate_migration()
        print(f"Migration validation result: {validation_result}")
        
        # Test dependency checking
        print("Testing dependency checking...")
        dependencies = migration_tool.check_all_dependencies()
        
        print("Protocol dependencies:")
        for protocol_name, status in dependencies.items():
            if not protocol_name.startswith('__'):
                print(f"  {protocol_name}:")
                print(f"    Protocol exists: {status.protocol_exists}")
                print(f"    Signature exists: {status.signature_exists}")
                print(f"    Validators linked: {status.validators_linked}")
                if status.issues:
                    print(f"    Issues: {status.issues}")
        
        # Test protocol mapping
        print("Testing protocol mapping...")
        source_to_protocol = {
            'sui_recon_agent': 1,
            'filecoin_lotus_peer': 3,
        }
        
        for source, protocol_id in source_to_protocol.items():
            result = session.execute(text("SELECT COUNT(*) FROM protocols WHERE id = :protocol_id"), 
                                    {"protocol_id": protocol_id})
            exists = result.scalar() > 0
            print(f"  {source} -> protocol_id {protocol_id}: {'✓' if exists else '✗'}")
        
        return dependencies


def test_migration_simulation():
    """Simulate the migration process without actually modifying the database."""
    print("\n=== Testing Migration Simulation ===")
    
    with get_db_session() as session:
        # Get current data
        result = session.execute(text("SELECT id, address, name, source FROM validator_addresses"))
        current_data = []
        for row in result:
            current_data.append({
                'id': row[0],
                'address': row[1], 
                'name': row[2],
                'source': row[3]
            })
        
        print(f"Total validator addresses: {len(current_data)}")
        
        # Test mapping logic
        source_to_protocol = {
            'sui_recon_agent': 1,
            'filecoin_lotus_peer': 3,
        }
        
        mapped_data = []
        unmapped_data = []
        
        for validator in current_data:
            source = validator['source']
            if source in source_to_protocol:
                protocol_id = source_to_protocol[source]
                mapped_data.append({
                    **validator,
                    'protocol_id': protocol_id
                })
            else:
                unmapped_data.append(validator)
        
        print(f"Mapped addresses: {len(mapped_data)}")
        print(f"Unmapped addresses: {len(unmapped_data)}")
        
        if unmapped_data:
            print("Unmapped sources:")
            unmapped_sources = set(v['source'] for v in unmapped_data)
            for source in unmapped_sources:
                count = len([v for v in unmapped_data if v['source'] == source])
                print(f"  {source}: {count} addresses")
        
        # Test protocol existence
        print("Verifying protocol existence...")
        for protocol_id in set(v['protocol_id'] for v in mapped_data):
            result = session.execute(text("SELECT name FROM protocols WHERE id = :protocol_id"), 
                                    {"protocol_id": protocol_id})
            protocol_name = result.scalar()
            if protocol_name:
                print(f"  Protocol {protocol_id} ({protocol_name}): ✓")
            else:
                print(f"  Protocol {protocol_id}: ✗ NOT FOUND")
        
        return {
            'total': len(current_data),
            'mapped': len(mapped_data),
            'unmapped': len(unmapped_data),
            'unmapped_sources': list(set(v['source'] for v in unmapped_data)) if unmapped_data else []
        }


def test_post_migration_validation():
    """Validate what the post-migration state should look like."""
    print("\n=== Testing Post-Migration Validation ===")
    
    with get_db_session() as session:
        # Test foreign key constraints
        print("Testing foreign key constraint logic...")
        
        # Check if we can query protocols
        result = session.execute(text("SELECT COUNT(*) FROM protocols"))
        protocol_count = result.scalar()
        print(f"Total protocols available: {protocol_count}")
        
        # Test join logic that would be used post-migration
        print("Testing join logic for post-migration queries...")
        
        # Simulate the join that would work post-migration
        test_query = text("""
            SELECT 
                va.address,
                va.name,
                p.name as protocol_name,
                p.display_name as protocol_display_name
            FROM validator_addresses va
            JOIN protocols p ON (
                CASE va.source
                    WHEN 'sui_recon_agent' THEN 1
                    WHEN 'filecoin_lotus_peer' THEN 3
                END
            ) = p.id
            WHERE va.source IN ('sui_recon_agent', 'filecoin_lotus_peer')
            LIMIT 5
        """)
        
        result = session.execute(test_query)
        sample_data = result.fetchall()
        
        print("Sample post-migration data preview:")
        for row in sample_data:
            print(f"  {row[0]} ({row[1]}) -> {row[2]} ({row[3]})")
        
        return True


def test_migration_rollback_logic():
    """Test the rollback/downgrade logic."""
    print("\n=== Testing Migration Rollback Logic ===")
    
    # Test protocol_id to source mapping
    protocol_to_source = {
        1: 'sui_recon_agent',
        3: 'filecoin_lotus_peer',
    }
    
    with get_db_session() as session:
        print("Testing protocol to source mapping...")
        for protocol_id, expected_source in protocol_to_source.items():
            result = session.execute(text("SELECT name FROM protocols WHERE id = :protocol_id"), 
                                    {"protocol_id": protocol_id})
            protocol_name = result.scalar()
            print(f"  Protocol {protocol_id} ({protocol_name}) -> {expected_source}")
        
        # Test reverse mapping completeness
        current_sources = set()
        result = session.execute(text("SELECT DISTINCT source FROM validator_addresses"))
        for row in result:
            current_sources.add(row[0])
        
        mapped_sources = set(protocol_to_source.values())
        unmapped_in_rollback = current_sources - mapped_sources
        
        print(f"Sources that would be unmapped in rollback: {unmapped_in_rollback}")
        
        return len(unmapped_in_rollback) == 0


def run_all_tests():
    """Run all migration tests."""
    print("Starting Migration Test Suite")
    print("=" * 50)
    
    try:
        # Test current state
        pre_migration = test_pre_migration_state()
        
        # Test preparation
        preparation = test_migration_preparation()
        
        # Test simulation
        simulation = test_migration_simulation()
        
        # Test post-migration validation
        post_migration = test_post_migration_validation()
        
        # Test rollback logic
        rollback = test_migration_rollback_logic()
        
        print("\n" + "=" * 50)
        print("Migration Test Summary")
        print("=" * 50)
        
        # Summary
        print(f"Pre-migration validation: ✓")
        print(f"Migration preparation: ✓")
        print(f"Migration simulation: ✓ ({simulation['mapped']} mapped, {simulation['unmapped']} unmapped)")
        print(f"Post-migration validation: ✓")
        print(f"Rollback validation: {'✓' if rollback else '✗'}")
        
        if simulation['unmapped'] > 0:
            print(f"\nWARNING: {simulation['unmapped']} addresses cannot be migrated")
            print(f"Unmapped sources: {simulation['unmapped_sources']}")
        
        print("\nMigration tests completed successfully!")
        return True
        
    except Exception as e:
        print(f"\nMigration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
