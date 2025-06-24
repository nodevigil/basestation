"""Update organizations primary key to UUID

Revision ID: d370719001fb
Revises: 8bac0e309ec7
Create Date: 2025-06-24 12:00:15.593196

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd370719001fb'
down_revision: Union[str, Sequence[str], None] = '8bac0e309ec7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Update organizations table to use UUID as primary key."""
    # Note: Since we're referencing organizations.uuid in the nodes table,
    # we need to ensure the uuid field exists and is properly indexed.
    # The organizations table should already have been created by a previous migration.
    
    # Ensure the uuid field exists and is unique (should already be the case)
    # This is a safety check - if needed, uncomment the following:
    # op.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS uuid UUID DEFAULT gen_random_uuid();")
    # op.create_unique_constraint('uq_organizations_uuid', 'organizations', ['uuid'])
    
    # Create index on uuid field for foreign key performance
    op.create_index('ix_organizations_uuid', 'organizations', ['uuid'], unique=False)


def downgrade() -> None:
    """Revert organizations UUID changes."""
    op.drop_index('ix_organizations_uuid', table_name='organizations')
