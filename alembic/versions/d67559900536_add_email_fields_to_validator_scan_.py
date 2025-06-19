"""add_email_fields_to_validator_scan_reports

Revision ID: d67559900536
Revises: 89261241333c
Create Date: 2025-06-19 20:20:46.115562

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd67559900536'
down_revision: Union[str, Sequence[str], None] = '89261241333c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Add email fields to validator_scan_reports table
    op.add_column('validator_scan_reports', sa.Column('report_email_body', sa.Text(), nullable=True))
    op.add_column('validator_scan_reports', sa.Column('report_email_subject', sa.String(length=255), nullable=True))
    op.add_column('validator_scan_reports', sa.Column('report_email_to', sa.String(length=255), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    # Remove email fields from validator_scan_reports table
    op.drop_column('validator_scan_reports', 'report_email_to')
    op.drop_column('validator_scan_reports', 'report_email_subject')
    op.drop_column('validator_scan_reports', 'report_email_body')
