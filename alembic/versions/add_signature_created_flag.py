"""Add signature_created flag to validator_scans

Revision ID: add_signature_created_flag
Revises: ab90d92ecd48
Create Date: 2025-06-22 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'add_signature_created_flag'
down_revision: Union[str, Sequence[str], None] = 'ab90d92ecd48'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Add signature_created column to validator_scans table
    # First add as nullable with default
    op.add_column('validator_scans', sa.Column('signature_created', sa.Boolean(), nullable=True, default=False))
    
    # Update all existing records to False
    from sqlalchemy import text
    connection = op.get_bind()
    connection.execute(text("UPDATE validator_scans SET signature_created = false WHERE signature_created IS NULL"))
    
    # Now make it not nullable
    op.alter_column('validator_scans', 'signature_created', nullable=False)


def downgrade() -> None:
    """Downgrade schema."""
    # Remove signature_created column from validator_scans table
    op.drop_column('validator_scans', 'signature_created')
