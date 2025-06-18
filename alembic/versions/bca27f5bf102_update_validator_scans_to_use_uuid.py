"""update_validator_scans_to_use_uuid

Revision ID: bca27f5bf102
Revises: 9ccdfa24c57c
Create Date: 2025-06-18 18:04:49.326169

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'bca27f5bf102'
down_revision: Union[str, Sequence[str], None] = '9ccdfa24c57c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
