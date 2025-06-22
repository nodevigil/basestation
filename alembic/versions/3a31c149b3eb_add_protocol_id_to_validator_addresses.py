"""add_protocol_id_to_validator_addresses

This migration:
1. Adds protocol_id column to validator_addresses
2. Migrates existing source data to protocol_id linkage
3. Removes the source column

Revision ID: 3a31c149b3eb
Revises: a41a6ef18da8
Create Date: 2025-06-22 09:39:06.605071

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text


# revision identifiers, used by Alembic.
revision: str = '3a31c149b3eb'
down_revision: Union[str, Sequence[str], None] = 'a41a6ef18da8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Migrate validator_addresses from source string to protocol_id linkage.
    
    Steps:
    1. Add protocol_id column (nullable initially)
    2. Migrate data from source to protocol_id
    3. Make protocol_id NOT NULL and add foreign key
    4. Drop source column
    """
    # Get connection for data migration
    connection = op.get_bind()
    
    print("Starting validator_addresses protocol migration...")
    
    # Step 1: Add protocol_id column (nullable initially)
    print("Step 1: Adding protocol_id column...")
    op.add_column('validator_addresses', 
                  sa.Column('protocol_id', sa.Integer(), nullable=True))
    
    # Step 2: Migrate data from source to protocol_id
    print("Step 2: Migrating data from source to protocol_id...")
    
    # Define source -> protocol_id mappings
    source_to_protocol = {
        'sui_recon_agent': 1,  # sui protocol
        'filecoin_lotus_peer': 3,  # filecoin protocol
        'filecoin_recon_agent': 3,  # filecoin protocol (alternative source)
        'ethereum_recon_agent': 4,  # ethereum protocol
        'celestia_recon_agent': 5,  # celestia protocol
        'bittensor_recon_agent': 6,  # bittensor protocol
        'theta_recon_agent': 7,  # theta protocol
        'akash_recon_agent': 8,  # akash protocol
        'helium_recon_agent': 9,  # helium protocol
        'arweave_recon_agent': 10,  # arweave protocol
        'icp_recon_agent': 11,  # icp protocol
        'livepeer_recon_agent': 12,  # livepeer protocol
        'storj_recon_agent': 13,  # storj protocol
        'ocean_recon_agent': 14,  # ocean protocol
        'graph_recon_agent': 15,  # graph protocol
        'flux_recon_agent': 16,  # flux protocol
        'iota_recon_agent': 17,  # iota protocol
        'jasmy_recon_agent': 18,  # jasmy protocol
        'iotex_recon_agent': 19,  # iotex protocol
        'peaq_recon_agent': 20,  # peaq protocol
        'osmosis_recon_agent': 21,  # osmosis protocol
        'rendernetwork_recon_agent': 22,  # rendernetwork protocol
    }
    
    # Check current source values
    result = connection.execute(text(
        "SELECT DISTINCT source FROM validator_addresses WHERE source IS NOT NULL"
    ))
    current_sources = [row[0] for row in result.fetchall()]
    print(f"Found sources: {current_sources}")
    
    # Update each source to its corresponding protocol_id
    migration_stats = {}
    unmapped_sources = []
    
    for source in current_sources:
        if source in source_to_protocol:
            protocol_id = source_to_protocol[source]
            
            # Verify protocol exists
            protocol_check = connection.execute(text(
                "SELECT COUNT(*) FROM protocols WHERE id = :protocol_id"
            ), {"protocol_id": protocol_id})
            
            if protocol_check.scalar() == 0:
                print(f"ERROR: Protocol ID {protocol_id} does not exist for source '{source}'")
                continue
                
            # Update validator addresses
            result = connection.execute(text(
                "UPDATE validator_addresses SET protocol_id = :protocol_id WHERE source = :source"
            ), {"protocol_id": protocol_id, "source": source})
            
            rows_updated = result.rowcount
            migration_stats[source] = {"protocol_id": protocol_id, "count": rows_updated}
            print(f"  Migrated {rows_updated} addresses from '{source}' to protocol_id {protocol_id}")
        else:
            unmapped_sources.append(source)
            print(f"  WARNING: No protocol mapping found for source '{source}'")
    
    # Handle unmapped sources
    if unmapped_sources:
        print(f"ERROR: Found unmapped sources: {unmapped_sources}")
        print("Migration cannot continue with unmapped sources.")
        print("Please add protocol mappings for these sources and run migration again.")
        raise Exception(f"Unmapped sources found: {unmapped_sources}")
    
    # Verify all addresses have protocol_id
    null_protocol_count = connection.execute(text(
        "SELECT COUNT(*) FROM validator_addresses WHERE protocol_id IS NULL"
    )).scalar()
    
    if null_protocol_count > 0:
        print(f"ERROR: {null_protocol_count} validator addresses still have NULL protocol_id")
        raise Exception(f"Migration incomplete: {null_protocol_count} addresses without protocol_id")
    
    print(f"Data migration completed successfully:")
    for source, stats in migration_stats.items():
        print(f"  {source} -> protocol_id {stats['protocol_id']} ({stats['count']} addresses)")
    
    # Step 3: Make protocol_id NOT NULL and add foreign key constraint
    print("Step 3: Adding constraints...")
    op.alter_column('validator_addresses', 'protocol_id', nullable=False)
    op.create_foreign_key(
        'fk_validator_addresses_protocol_id',
        'validator_addresses', 'protocols',
        ['protocol_id'], ['id']
    )
    
    # Step 4: Drop source column
    print("Step 4: Dropping source column...")
    op.drop_column('validator_addresses', 'source')
    
    print("Migration completed successfully!")


def downgrade() -> None:
    """
    Reverse the migration by restoring the source column.
    
    Steps:
    1. Add source column back
    2. Migrate protocol_id data back to source strings
    3. Drop protocol_id column and constraints
    """
    # Get connection for data migration
    connection = op.get_bind()
    
    print("Starting validator_addresses protocol downgrade...")
    
    # Step 1: Add source column back
    print("Step 1: Adding source column back...")
    op.add_column('validator_addresses', 
                  sa.Column('source', sa.String(255), nullable=True))
    
    # Step 2: Migrate protocol_id back to source strings
    print("Step 2: Migrating protocol_id back to source...")
    
    # Define protocol_id -> source mappings (reverse of upgrade)
    protocol_to_source = {
        1: 'sui_recon_agent',
        3: 'filecoin_lotus_peer',
        4: 'ethereum_recon_agent',
        5: 'celestia_recon_agent',
        6: 'bittensor_recon_agent',
        7: 'theta_recon_agent',
        8: 'akash_recon_agent',
        9: 'helium_recon_agent',
        10: 'arweave_recon_agent',
        11: 'icp_recon_agent',
        12: 'livepeer_recon_agent',
        13: 'storj_recon_agent',
        14: 'ocean_recon_agent',
        15: 'graph_recon_agent',
        16: 'flux_recon_agent',
        17: 'iota_recon_agent',
        18: 'jasmy_recon_agent',
        19: 'iotex_recon_agent',
        20: 'peaq_recon_agent',
        21: 'osmosis_recon_agent',
        22: 'rendernetwork_recon_agent',
    }
    
    # Get current protocol_ids
    result = connection.execute(text(
        "SELECT DISTINCT protocol_id FROM validator_addresses WHERE protocol_id IS NOT NULL"
    ))
    current_protocol_ids = [row[0] for row in result.fetchall()]
    print(f"Found protocol_ids: {current_protocol_ids}")
    
    # Update each protocol_id to its corresponding source
    downgrade_stats = {}
    unmapped_protocols = []
    
    for protocol_id in current_protocol_ids:
        if protocol_id in protocol_to_source:
            source = protocol_to_source[protocol_id]
            
            # Update validator addresses
            result = connection.execute(text(
                "UPDATE validator_addresses SET source = :source WHERE protocol_id = :protocol_id"
            ), {"source": source, "protocol_id": protocol_id})
            
            rows_updated = result.rowcount
            downgrade_stats[protocol_id] = {"source": source, "count": rows_updated}
            print(f"  Migrated {rows_updated} addresses from protocol_id {protocol_id} to '{source}'")
        else:
            unmapped_protocols.append(protocol_id)
            print(f"  WARNING: No source mapping found for protocol_id {protocol_id}")
    
    # Handle unmapped protocols
    if unmapped_protocols:
        print(f"ERROR: Found unmapped protocol_ids: {unmapped_protocols}")
        print("Downgrade cannot continue with unmapped protocol_ids.")
        raise Exception(f"Unmapped protocol_ids found: {unmapped_protocols}")
    
    # Verify all addresses have source
    null_source_count = connection.execute(text(
        "SELECT COUNT(*) FROM validator_addresses WHERE source IS NULL"
    )).scalar()
    
    if null_source_count > 0:
        print(f"ERROR: {null_source_count} validator addresses still have NULL source")
        raise Exception(f"Downgrade incomplete: {null_source_count} addresses without source")
    
    print(f"Data downgrade completed successfully:")
    for protocol_id, stats in downgrade_stats.items():
        print(f"  protocol_id {protocol_id} -> {stats['source']} ({stats['count']} addresses)")
    
    # Step 3: Make source NOT NULL and drop protocol_id constraints/column
    print("Step 3: Removing protocol constraints and column...")
    op.alter_column('validator_addresses', 'source', nullable=False)
    op.drop_constraint('fk_validator_addresses_protocol_id', 'validator_addresses', type_='foreignkey')
    op.drop_column('validator_addresses', 'protocol_id')
    
    print("Downgrade completed successfully!")
