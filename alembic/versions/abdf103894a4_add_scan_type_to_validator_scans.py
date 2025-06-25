"""add_scan_type_to_validator_scans

Revision ID: abdf103894a4
Revises: b52b59bcdbd4
Create Date: 2025-06-25 12:27:11.773391

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'abdf103894a4'
down_revision: Union[str, Sequence[str], None] = 'b52b59bcdbd4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Add scan_type column to validator_scans table
    op.add_column('validator_scans', sa.Column('scan_type', sa.String(50), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    # Remove scan_type column from validator_scans table
    op.drop_column('validator_scans', 'scan_type')
