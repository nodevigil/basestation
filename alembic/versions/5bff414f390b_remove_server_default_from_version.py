"""remove_server_default_from_version

Revision ID: 5bff414f390b
Revises: 1dc631b994d0
Create Date: 2025-06-18 15:45:34.568881

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '5bff414f390b'
down_revision: Union[str, Sequence[str], None] = '1dc631b994d0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Remove server default from version column - version must be set explicitly in code
    op.alter_column('validator_scans', 'version', server_default=None)


def downgrade() -> None:
    """Downgrade schema."""
    # Restore server default
    op.alter_column('validator_scans', 'version', server_default='v0.1')
