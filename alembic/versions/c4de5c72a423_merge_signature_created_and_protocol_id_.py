"""merge signature_created and protocol_id branches

Revision ID: c4de5c72a423
Revises: 3a31c149b3eb, add_signature_created_flag
Create Date: 2025-06-22 14:22:25.451960

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c4de5c72a423'
down_revision: Union[str, Sequence[str], None] = ('3a31c149b3eb', 'add_signature_created_flag')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
