"""add_version_to_validator_scans

Revision ID: 1dc631b994d0
Revises: f2cd1645d247
Create Date: 2025-06-18 15:05:14.690128

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '1dc631b994d0'
down_revision: Union[str, Sequence[str], None] = 'f2cd1645d247'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Add version column to validator_scans table
    op.add_column('validator_scans', sa.Column('version', sa.String(length=20), nullable=True))
    
    # Set default version for existing records
    op.execute("UPDATE validator_scans SET version = 'v0.1' WHERE version IS NULL")
    
    # Make version column non-nullable (no server default - must be set in code)
    op.alter_column('validator_scans', 'version', nullable=False)


def downgrade() -> None:
    """Downgrade schema."""
    # Remove version column
    op.drop_column('validator_scans', 'version')
