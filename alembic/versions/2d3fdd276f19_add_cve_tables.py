"""Add CVE tables

Revision ID: 2d3fdd276f19
Revises: 813d0142328a
Create Date: 2025-06-17 21:05:27.506812

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '2d3fdd276f19'
down_revision: Union[str, Sequence[str], None] = '813d0142328a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Create CVE records table
    op.create_table(
        'cve_records',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('cve_id', sa.String(length=20), nullable=False),
        sa.Column('published_date', sa.DateTime(), nullable=True),
        sa.Column('last_modified', sa.DateTime(), nullable=True),
        sa.Column('source', sa.String(length=50), nullable=False),
        sa.Column('description', sa.String(length=2000), nullable=True),
        sa.Column('severity', sa.String(length=20), nullable=True),
        sa.Column('cvss_score', sa.String(length=10), nullable=True),
        sa.Column('cvss_vector', sa.String(length=100), nullable=True),
        sa.Column('affected_products', sa.JSON(), nullable=True),
        sa.Column('raw_data', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('cve_id')
    )
    
    # Create CVE update logs table
    op.create_table(
        'cve_update_logs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('update_date', sa.DateTime(), nullable=False),
        sa.Column('total_cves_processed', sa.Integer(), nullable=False),
        sa.Column('new_cves_added', sa.Integer(), nullable=False),
        sa.Column('updated_cves', sa.Integer(), nullable=False),
        sa.Column('source', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('error_message', sa.String(length=1000), nullable=True),
        sa.Column('processing_time_seconds', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('cve_update_logs')
    op.drop_table('cve_records')
