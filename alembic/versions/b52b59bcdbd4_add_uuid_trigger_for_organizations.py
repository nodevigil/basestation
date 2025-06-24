"""Add UUID trigger for organizations

Revision ID: b52b59bcdbd4
Revises: d370719001fb
Create Date: 2025-06-24 12:35:32.142040

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b52b59bcdbd4'
down_revision: Union[str, Sequence[str], None] = 'd370719001fb'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add UUID trigger for organizations table."""
    
    # Create a function that generates UUID if not provided
    op.execute("""
        CREATE OR REPLACE FUNCTION generate_uuid_for_organizations()
        RETURNS TRIGGER AS $$
        BEGIN
            -- Only generate UUID if it's NULL or empty
            IF NEW.uuid IS NULL OR NEW.uuid = '' THEN
                NEW.uuid := gen_random_uuid()::text;
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
    
    # Create trigger that fires before insert
    op.execute("""
        CREATE TRIGGER trigger_generate_organization_uuid
            BEFORE INSERT ON organizations
            FOR EACH ROW
            EXECUTE FUNCTION generate_uuid_for_organizations();
    """)
    
    # Also create a trigger for updates in case uuid is set to NULL
    op.execute("""
        CREATE TRIGGER trigger_update_organization_uuid
            BEFORE UPDATE ON organizations
            FOR EACH ROW
            WHEN (NEW.uuid IS NULL OR NEW.uuid = '')
            EXECUTE FUNCTION generate_uuid_for_organizations();
    """)


def downgrade() -> None:
    """Remove UUID trigger for organizations table."""
    
    # Drop triggers
    op.execute("DROP TRIGGER IF EXISTS trigger_update_organization_uuid ON organizations;")
    op.execute("DROP TRIGGER IF EXISTS trigger_generate_organization_uuid ON organizations;")
    
    # Drop function
    op.execute("DROP FUNCTION IF EXISTS generate_uuid_for_organizations();")
