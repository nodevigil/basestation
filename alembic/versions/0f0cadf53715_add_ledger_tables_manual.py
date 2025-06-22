"""add_ledger_tables_manual

Revision ID: 0f0cadf53715
Revises: 240bfb393ac9
Create Date: 2025-06-22 20:35:52.690093

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '0f0cadf53715'
down_revision: Union[str, Sequence[str], None] = '240bfb393ac9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Create ledger_publish_logs table
    op.create_table('ledger_publish_logs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('uuid', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('attempt_timestamp', sa.DateTime(), nullable=False),
        sa.Column('publishing_agent', sa.String(length=100), nullable=False),
        sa.Column('agent_version', sa.String(length=20), nullable=True),
        sa.Column('blockchain_network', sa.String(length=50), nullable=True),
        sa.Column('rpc_url', sa.String(length=255), nullable=True),
        sa.Column('contract_address', sa.String(length=42), nullable=True),
        sa.Column('publisher_address', sa.String(length=42), nullable=True),
        sa.Column('success', sa.Boolean(), nullable=False),
        sa.Column('is_batch', sa.Boolean(), nullable=False),
        sa.Column('batch_id', sa.Integer(), nullable=True),
        sa.Column('transaction_hash', sa.String(length=66), nullable=True),
        sa.Column('block_number', sa.Integer(), nullable=True),
        sa.Column('gas_used', sa.Integer(), nullable=True),
        sa.Column('gas_price_gwei', sa.DECIMAL(precision=10, scale=2), nullable=True),
        sa.Column('transaction_confirmed', sa.Boolean(), nullable=False),
        sa.Column('confirmation_timestamp', sa.DateTime(), nullable=True),
        sa.Column('host_uid', sa.String(length=100), nullable=True),
        sa.Column('scan_time', sa.Integer(), nullable=True),
        sa.Column('summary_hash', sa.String(length=66), nullable=True),
        sa.Column('trust_score', sa.Integer(), nullable=True),
        sa.Column('report_pointer', sa.String(length=255), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('error_type', sa.String(length=100), nullable=True),
        sa.Column('retry_count', sa.Integer(), nullable=False),
        sa.Column('processing_duration_ms', sa.Integer(), nullable=True),
        sa.Column('confirmation_duration_ms', sa.Integer(), nullable=True),
        sa.Column('extra_data', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['scan_id'], ['validator_scans.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('uuid')
    )

    # Create ledger_batches table
    op.create_table('ledger_batches',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('uuid', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('batch_timestamp', sa.DateTime(), nullable=False),
        sa.Column('batch_size', sa.Integer(), nullable=False),
        sa.Column('successful_publishes', sa.Integer(), nullable=False),
        sa.Column('failed_publishes', sa.Integer(), nullable=False),
        sa.Column('blockchain_network', sa.String(length=50), nullable=True),
        sa.Column('contract_address', sa.String(length=42), nullable=True),
        sa.Column('publisher_address', sa.String(length=42), nullable=True),
        sa.Column('transaction_hash', sa.String(length=66), nullable=True),
        sa.Column('block_number', sa.Integer(), nullable=True),
        sa.Column('blockchain_batch_id', sa.Integer(), nullable=True),
        sa.Column('gas_used', sa.Integer(), nullable=True),
        sa.Column('gas_price_gwei', sa.DECIMAL(precision=10, scale=2), nullable=True),
        sa.Column('success', sa.Boolean(), nullable=False),
        sa.Column('confirmed', sa.Boolean(), nullable=False),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('processing_duration_ms', sa.Integer(), nullable=True),
        sa.Column('confirmation_duration_ms', sa.Integer(), nullable=True),
        sa.Column('extra_data', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('uuid')
    )

    # Create ledger_connection_logs table
    op.create_table('ledger_connection_logs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('uuid', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('agent_name', sa.String(length=100), nullable=False),
        sa.Column('rpc_url', sa.String(length=255), nullable=True),
        sa.Column('network_name', sa.String(length=50), nullable=True),
        sa.Column('contract_address', sa.String(length=42), nullable=True),
        sa.Column('connection_successful', sa.Boolean(), nullable=False),
        sa.Column('contract_loaded', sa.Boolean(), nullable=False),
        sa.Column('is_authorized_publisher', sa.Boolean(), nullable=False),
        sa.Column('account_address', sa.String(length=42), nullable=True),
        sa.Column('account_balance_wei', sa.String(length=50), nullable=True),
        sa.Column('account_balance_eth', sa.DECIMAL(precision=20, scale=10), nullable=True),
        sa.Column('contract_version', sa.String(length=20), nullable=True),
        sa.Column('contract_paused', sa.Boolean(), nullable=True),
        sa.Column('total_summaries', sa.Integer(), nullable=True),
        sa.Column('publish_cooldown', sa.Integer(), nullable=True),
        sa.Column('reputation_threshold', sa.Integer(), nullable=True),
        sa.Column('active_hosts', sa.Integer(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('error_type', sa.String(length=100), nullable=True),
        sa.Column('connection_duration_ms', sa.Integer(), nullable=True),
        sa.Column('extra_data', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('uuid')
    )

    # Add indexes for performance
    op.create_index('idx_ledger_publish_logs_scan_id', 'ledger_publish_logs', ['scan_id'])
    op.create_index('idx_ledger_publish_logs_success', 'ledger_publish_logs', ['success'])
    op.create_index('idx_ledger_publish_logs_tx_hash', 'ledger_publish_logs', ['transaction_hash'])
    op.create_index('idx_ledger_publish_logs_timestamp', 'ledger_publish_logs', ['attempt_timestamp'])
    
    op.create_index('idx_ledger_batches_timestamp', 'ledger_batches', ['batch_timestamp'])
    op.create_index('idx_ledger_batches_success', 'ledger_batches', ['success'])
    
    op.create_index('idx_ledger_connection_logs_timestamp', 'ledger_connection_logs', ['timestamp'])
    op.create_index('idx_ledger_connection_logs_success', 'ledger_connection_logs', ['connection_successful'])


def downgrade() -> None:
    """Downgrade schema."""
    # Drop indexes first
    op.drop_index('idx_ledger_connection_logs_success', table_name='ledger_connection_logs')
    op.drop_index('idx_ledger_connection_logs_timestamp', table_name='ledger_connection_logs')
    op.drop_index('idx_ledger_batches_success', table_name='ledger_batches')
    op.drop_index('idx_ledger_batches_timestamp', table_name='ledger_batches')
    op.drop_index('idx_ledger_publish_logs_timestamp', table_name='ledger_publish_logs')
    op.drop_index('idx_ledger_publish_logs_tx_hash', table_name='ledger_publish_logs')
    op.drop_index('idx_ledger_publish_logs_success', table_name='ledger_publish_logs')
    op.drop_index('idx_ledger_publish_logs_scan_id', table_name='ledger_publish_logs')
    
    # Drop tables
    op.drop_table('ledger_connection_logs')
    op.drop_table('ledger_batches')
    op.drop_table('ledger_publish_logs')
