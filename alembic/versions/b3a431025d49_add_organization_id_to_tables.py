"""add_organization_id_to_tables

Revision ID: b3a431025d49
Revises: 0f0cadf53715
Create Date: 2025-06-23 15:26:07.120038

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b3a431025d49'
down_revision: Union[str, Sequence[str], None] = '0f0cadf53715'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add organization_id column to tables for ownership tracking."""
    
    # List of tables to add organization_id to
    tables_to_update = [
        'host_discoveries',
        'ledger_connection_logs', 
        'ledger_publish_logs',
        'network_scan_data',
        'protocol_probe_results',
        'scan_sessions',
        'signature_match_results',
        'validator_addresses',
        'validator_scan_reports',
        'validator_scans'
    ]
    
    # Add organization_id column to each table
    for table_name in tables_to_update:
        # Add the column as nullable initially to handle existing data
        op.add_column(table_name, sa.Column('organization_id', sa.Integer(), nullable=True))
        
        # Add foreign key constraint (assuming organizations table exists or will exist)
        # Note: You may need to create the organizations table separately if it doesn't exist
        # op.create_foreign_key(
        #     f'fk_{table_name}_organization_id',
        #     table_name, 
        #     'organizations', 
        #     ['organization_id'], 
        #     ['id']
        # )
    
    # Create index on organization_id for better query performance
    for table_name in tables_to_update:
        op.create_index(f'idx_{table_name}_organization_id', table_name, ['organization_id'])


def downgrade() -> None:
    """Remove organization_id column from tables."""
    
    # List of tables to remove organization_id from
    tables_to_update = [
        'host_discoveries',
        'ledger_connection_logs',
        'ledger_publish_logs', 
        'network_scan_data',
        'protocol_probe_results',
        'scan_sessions',
        'signature_match_results',
        'validator_addresses',
        'validator_scan_reports',
        'validator_scans'
    ]
    
    # Remove indexes first
    for table_name in tables_to_update:
        op.drop_index(f'idx_{table_name}_organization_id', table_name)
    
    # Remove foreign key constraints if they were added
    # for table_name in tables_to_update:
    #     op.drop_constraint(f'fk_{table_name}_organization_id', table_name, type_='foreignkey')
    
    # Remove organization_id column from each table
    for table_name in tables_to_update:
        op.drop_column(table_name, 'organization_id')
