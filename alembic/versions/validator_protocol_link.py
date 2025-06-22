"""Link validator addresses to protocols

Revision ID: validator_protocol_link
Revises: 
Create Date: 2025-06-22 

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'validator_protocol_link'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add protocol_id column
    op.add_column('validator_addresses', sa.Column('protocol_id', sa.Integer(), nullable=True))
    
    # Add foreign key constraint
    op.create_foreign_key(
        'fk_validator_addresses_protocol_id', 
        'validator_addresses', 
        'protocols', 
        ['protocol_id'], 
        ['id']
    )
    
    # Update existing records to link to protocols based on source field
    # First, ensure we have the protocols (sui, filecoin, etc.) in the database
    protocols_table = sa.table('protocols',
        sa.column('id', sa.Integer),
        sa.column('name', sa.String)
    )
    
    validator_addresses_table = sa.table('validator_addresses',
        sa.column('id', sa.Integer),
        sa.column('source', sa.String),
        sa.column('protocol_id', sa.Integer)
    )
    
    # Update validator addresses to link to the correct protocol
    conn = op.get_bind()
    
    # Update Sui validators
    sui_protocol = conn.execute(
        sa.select(protocols_table.c.id).where(protocols_table.c.name == 'sui')
    ).scalar()
    
    if sui_protocol:
        conn.execute(
            sa.update(validator_addresses_table)
            .where(validator_addresses_table.c.source.in_(['sui_recon_agent', 'sui']))
            .values(protocol_id=sui_protocol)
        )
    
    # Update Filecoin validators
    filecoin_protocol = conn.execute(
        sa.select(protocols_table.c.id).where(protocols_table.c.name == 'filecoin')
    ).scalar()
    
    if filecoin_protocol:
        conn.execute(
            sa.update(validator_addresses_table)
            .where(validator_addresses_table.c.source.in_(['filecoin_lotus_peer', 'filecoin_api', 'filecoin']))
            .values(protocol_id=filecoin_protocol)
        )
    
    # Handle any other manual entries - create a 'manual' protocol if it doesn't exist
    manual_protocol = conn.execute(
        sa.select(protocols_table.c.id).where(protocols_table.c.name == 'manual')
    ).scalar()
    
    if not manual_protocol:
        # Create manual protocol
        manual_protocol_id = conn.execute(
            sa.insert(protocols_table).values(
                name='manual',
                display_name='Manual Entry',
                category='Manual',
                ports=[],
                endpoints=[],
                banners=[],
                rpc_methods=[],
                metrics_keywords=[],
                http_paths=[],
                identification_hints=[]
            ).returning(protocols_table.c.id)
        ).scalar()
        manual_protocol = manual_protocol_id
    
    # Update any remaining validators with no protocol_id
    conn.execute(
        sa.update(validator_addresses_table)
        .where(validator_addresses_table.c.protocol_id.is_(None))
        .values(protocol_id=manual_protocol)
    )
    
    # Make protocol_id non-nullable after updating all records
    op.alter_column('validator_addresses', 'protocol_id', nullable=False)
    
    # Drop the old source column
    op.drop_column('validator_addresses', 'source')


def downgrade() -> None:
    # Add back source column
    op.add_column('validator_addresses', sa.Column('source', sa.String(100), nullable=True))
    
    # Update source field based on protocol relationship
    protocols_table = sa.table('protocols',
        sa.column('id', sa.Integer),
        sa.column('name', sa.String)
    )
    
    validator_addresses_table = sa.table('validator_addresses',
        sa.column('id', sa.Integer),
        sa.column('source', sa.String),
        sa.column('protocol_id', sa.Integer)
    )
    
    conn = op.get_bind()
    
    # Update source based on protocol name
    protocols = conn.execute(sa.select(protocols_table)).fetchall()
    for protocol in protocols:
        source_value = f"{protocol.name}_recon_agent" if protocol.name in ['sui', 'filecoin'] else protocol.name
        conn.execute(
            sa.update(validator_addresses_table)
            .where(validator_addresses_table.c.protocol_id == protocol.id)
            .values(source=source_value)
        )
    
    # Make source non-nullable
    op.alter_column('validator_addresses', 'source', nullable=False)
    
    # Drop foreign key constraint
    op.drop_constraint('fk_validator_addresses_protocol_id', 'validator_addresses', type_='foreignkey')
    
    # Drop protocol_id column
    op.drop_column('validator_addresses', 'protocol_id')
