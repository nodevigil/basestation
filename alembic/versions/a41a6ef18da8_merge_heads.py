"""merge_heads

Revision ID: a41a6ef18da8
Revises: ce6d69abb6ed, validator_protocol_link
Create Date: 2025-06-22 09:38:59.175847

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a41a6ef18da8'
down_revision: Union[str, Sequence[str], None] = ('ce6d69abb6ed', 'validator_protocol_link')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
