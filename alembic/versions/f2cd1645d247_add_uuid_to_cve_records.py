"""add_uuid_to_cve_records

Revision ID: f2cd1645d247
Revises: 2d3fdd276f19
Create Date: 2025-06-18 11:49:37.714730

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'f2cd1645d247'
down_revision: Union[str, Sequence[str], None] = '2d3fdd276f19'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Enable UUID extension if not already enabled
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
    
    # Add UUID column to cve_records table
    op.add_column('cve_records', sa.Column('uuid', postgresql.UUID(), nullable=True))
    
    # Add UUID column to cve_update_logs table
    op.add_column('cve_update_logs', sa.Column('uuid', postgresql.UUID(), nullable=True))
    
    # Create function to generate UUID for existing records
    op.execute("""
        CREATE OR REPLACE FUNCTION generate_uuid_for_cve_records()
        RETURNS void AS $$
        BEGIN
            UPDATE cve_records SET uuid = uuid_generate_v4() WHERE uuid IS NULL;
            UPDATE cve_update_logs SET uuid = uuid_generate_v4() WHERE uuid IS NULL;
        END;
        $$ LANGUAGE plpgsql;
    """)
    
    # Generate UUIDs for existing records
    op.execute("SELECT generate_uuid_for_cve_records()")
    
    # Make UUID columns non-nullable
    op.alter_column('cve_records', 'uuid', nullable=False)
    op.alter_column('cve_update_logs', 'uuid', nullable=False)
    
    # Add unique constraints on UUID columns
    op.create_unique_constraint('uq_cve_records_uuid', 'cve_records', ['uuid'])
    op.create_unique_constraint('uq_cve_update_logs_uuid', 'cve_update_logs', ['uuid'])
    
    # Create triggers to automatically generate UUIDs for new records
    op.execute("""
        CREATE OR REPLACE FUNCTION generate_uuid_trigger()
        RETURNS trigger AS $$
        BEGIN
            IF NEW.uuid IS NULL THEN
                NEW.uuid = uuid_generate_v4();
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
    
    # Create triggers for both tables
    op.execute("""
        CREATE TRIGGER cve_records_uuid_trigger
            BEFORE INSERT ON cve_records
            FOR EACH ROW
            EXECUTE FUNCTION generate_uuid_trigger();
    """)
    
    op.execute("""
        CREATE TRIGGER cve_update_logs_uuid_trigger
            BEFORE INSERT ON cve_update_logs
            FOR EACH ROW
            EXECUTE FUNCTION generate_uuid_trigger();
    """)
    
    # Clean up the temporary function
    op.execute("DROP FUNCTION generate_uuid_for_cve_records()")


def downgrade() -> None:
    """Downgrade schema."""
    # Drop triggers
    op.execute("DROP TRIGGER IF EXISTS cve_records_uuid_trigger ON cve_records")
    op.execute("DROP TRIGGER IF EXISTS cve_update_logs_uuid_trigger ON cve_update_logs")
    
    # Drop trigger function
    op.execute("DROP FUNCTION IF EXISTS generate_uuid_trigger()")
    
    # Drop unique constraints
    op.drop_constraint('uq_cve_records_uuid', 'cve_records', type_='unique')
    op.drop_constraint('uq_cve_update_logs_uuid', 'cve_update_logs', type_='unique')
    
    # Drop UUID columns
    op.drop_column('cve_records', 'uuid')
    op.drop_column('cve_update_logs', 'uuid')
