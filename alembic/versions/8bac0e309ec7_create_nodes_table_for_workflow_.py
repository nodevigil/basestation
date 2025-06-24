"""Create nodes table for workflow orchestration

Revision ID: 8bac0e309ec7
Revises: a64d53aa3896
Create Date: 2025-06-24 11:52:32.923981

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '8bac0e309ec7'
down_revision: Union[str, Sequence[str], None] = 'a64d53aa3896'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create nodes table for workflow orchestration."""
    op.create_table('nodes',
        sa.Column('uuid', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),  # Match organizations.uuid type
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('protocol_id', sa.Integer(), nullable=True),
        sa.Column('meta', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.uuid'], ),
        sa.ForeignKeyConstraint(['protocol_id'], ['protocols.id'], ),
        sa.PrimaryKeyConstraint('uuid')
    )
    
    # Create indexes for performance
    op.create_index(op.f('ix_nodes_org_id'), 'nodes', ['org_id'], unique=False)
    op.create_index(op.f('ix_nodes_status'), 'nodes', ['status'], unique=False)
    op.create_index(op.f('ix_nodes_protocol_id'), 'nodes', ['protocol_id'], unique=False)


def downgrade() -> None:
    """Drop nodes table."""
    op.drop_index(op.f('ix_nodes_protocol_id'), table_name='nodes')
    op.drop_index(op.f('ix_nodes_status'), table_name='nodes')
    op.drop_index(op.f('ix_nodes_org_id'), table_name='nodes')
    op.drop_table('nodes')
