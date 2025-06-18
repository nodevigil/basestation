"""add_uuid_to_validator_addresses

Revision ID: f651195d01d1
Revises: bca27f5bf102
Create Date: 2025-06-18 18:07:14.494287

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


# revision identifiers, used by Alembic.
revision: str = 'f651195d01d1'
down_revision: Union[str, Sequence[str], None] = 'bca27f5bf102'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Add UUID column to validator_addresses table
    op.add_column('validator_addresses', sa.Column('uuid', UUID(as_uuid=True), nullable=True))
    
    # Create a function to generate UUIDs for existing records
    op.execute("""
        CREATE OR REPLACE FUNCTION gen_random_uuid() RETURNS UUID AS $$
        BEGIN
            RETURN uuid_generate_v4();
        END;
        $$ LANGUAGE plpgsql;
    """)
    
    # Update existing records with UUIDs
    op.execute("UPDATE validator_addresses SET uuid = gen_random_uuid() WHERE uuid IS NULL")
    
    # Make the column NOT NULL and UNIQUE
    op.alter_column('validator_addresses', 'uuid', nullable=False)
    op.create_unique_constraint('uq_validator_addresses_uuid', 'validator_addresses', ['uuid'])
    
    # Set default value for future inserts
    op.alter_column('validator_addresses', 'uuid', server_default=sa.text('gen_random_uuid()'))


def downgrade() -> None:
    """Downgrade schema."""
    # Remove the UUID column and constraints
    op.drop_constraint('uq_validator_addresses_uuid', 'validator_addresses', type_='unique')
    op.drop_column('validator_addresses', 'uuid')
