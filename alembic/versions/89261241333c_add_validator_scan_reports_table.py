"""add_validator_scan_reports_table

Revision ID: 89261241333c
Revises: f651195d01d1
Create Date: 2025-06-19 17:35:43.767416

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


# revision identifiers, used by Alembic.
revision: str = '89261241333c'
down_revision: Union[str, Sequence[str], None] = 'f651195d01d1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Create validator_scan_reports table
    op.create_table(
        'validator_scan_reports',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('uuid', UUID(as_uuid=True), nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('report_date', sa.DateTime(), nullable=False),
        sa.Column('report_type', sa.String(length=50), nullable=False),
        sa.Column('report_format', sa.String(length=20), nullable=False),
        sa.Column('overall_risk_level', sa.String(length=20), nullable=True),
        sa.Column('total_vulnerabilities', sa.Integer(), nullable=False),
        sa.Column('critical_vulnerabilities', sa.Integer(), nullable=False),
        sa.Column('report_data', sa.JSON(), nullable=False),
        sa.Column('report_summary', sa.String(length=1000), nullable=True),
        sa.Column('processed', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['scan_id'], ['validator_scans.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('uuid')
    )


def downgrade() -> None:
    """Downgrade schema."""
    # Drop validator_scan_reports table
    op.drop_table('validator_scan_reports')
