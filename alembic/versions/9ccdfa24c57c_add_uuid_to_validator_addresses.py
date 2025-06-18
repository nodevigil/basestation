"""add_uuid_to_validator_addresses

Revision ID: 9ccdfa24c57c
Revises: 5bff414f390b
Create Date: 2025-06-18 18:03:36.703991

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '9ccdfa24c57c'
down_revision: Union[str, Sequence[str], None] = '5bff414f390b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Enable UUID extension if not already enabled
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
    
    # Add UUID column to validator_addresses table
    op.add_column('validator_addresses', sa.Column('uuid', postgresql.UUID(), nullable=True))
    
    # Create function to generate UUID for existing records
    op.execute("""
        CREATE OR REPLACE FUNCTION generate_uuid_for_validator_addresses()
        RETURNS void AS $$
        BEGIN
            UPDATE validator_addresses SET uuid = uuid_generate_v4() WHERE uuid IS NULL;
        END;
        $$ LANGUAGE plpgsql;
    """)
    
    # Generate UUIDs for existing records
    op.execute("SELECT generate_uuid_for_validator_addresses()")
    
    # Make UUID column non-nullable
    op.alter_column('validator_addresses', 'uuid', nullable=False)
    
    # Add unique constraint on UUID column
    op.create_unique_constraint('uq_validator_addresses_uuid', 'validator_addresses', ['uuid'])
    
    # Create trigger to automatically generate UUIDs for new records
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
    
    # Create trigger for validator_addresses table
    op.execute("""
        CREATE TRIGGER validator_addresses_uuid_trigger
            BEFORE INSERT ON validator_addresses
            FOR EACH ROW
            EXECUTE FUNCTION generate_uuid_trigger();
    """)
    
    # Clean up the temporary function
    op.execute("DROP FUNCTION generate_uuid_for_validator_addresses()")


def downgrade() -> None:
    """Downgrade schema."""
    # Drop trigger
    op.execute("DROP TRIGGER IF EXISTS validator_addresses_uuid_trigger ON validator_addresses")
    
    # Drop trigger function (only if no other tables are using it)
    # Note: We'll keep the function as other tables might be using it
    
    # Drop unique constraint
    op.drop_constraint('uq_validator_addresses_uuid', 'validator_addresses', type_='unique')
    
    # Drop UUID column
    op.drop_column('validator_addresses', 'uuid')
