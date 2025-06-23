"""add_organizations_users_and_roles

Revision ID: e9f923004c65
Revises: b3a431025d49
Create Date: 2025-06-23 15:28:10.383037

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e9f923004c65'
down_revision: Union[str, Sequence[str], None] = 'b3a431025d49'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add organizations, users, and role management tables."""
    
    # Create organizations table
    op.create_table('organizations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('uuid', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('slug', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('website', sa.String(length=255), nullable=True),
        sa.Column('contact_email', sa.String(length=255), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('created_by', sa.Integer(), nullable=True),  # Will reference users.id
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('uuid'),
        sa.UniqueConstraint('slug')
    )
    
    # Create users table
    op.create_table('users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('uuid', sa.String(length=36), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('username', sa.String(length=100), nullable=True),
        sa.Column('first_name', sa.String(length=100), nullable=True),
        sa.Column('last_name', sa.String(length=100), nullable=True),
        sa.Column('password_hash', sa.String(length=255), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('is_superuser', sa.Boolean(), nullable=False, default=False),
        sa.Column('email_verified', sa.Boolean(), nullable=False, default=False),
        sa.Column('last_login', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('uuid'),
        sa.UniqueConstraint('email'),
        sa.UniqueConstraint('username')
    )
    
    # Create roles table for future extensibility
    op.create_table('roles',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('permissions', sa.JSON(), nullable=True),  # Store permissions as JSON
        sa.Column('is_system_role', sa.Boolean(), nullable=False, default=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )
    
    # Create user_organizations join table (many-to-many with roles)
    op.create_table('user_organizations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('role_id', sa.Integer(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('joined_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('invited_by', sa.Integer(), nullable=True),  # References users.id
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['role_id'], ['roles.id']),
        sa.ForeignKeyConstraint(['invited_by'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'organization_id', name='uk_user_organization')
    )
    
    # Add foreign key from organizations.created_by to users.id
    op.create_foreign_key(
        'fk_organizations_created_by',
        'organizations', 
        'users', 
        ['created_by'], 
        ['id']
    )
    
    # Create indexes for better performance
    op.create_index('idx_organizations_name', 'organizations', ['name'])
    op.create_index('idx_organizations_slug', 'organizations', ['slug'])
    op.create_index('idx_organizations_active', 'organizations', ['is_active'])
    op.create_index('idx_organizations_created_at', 'organizations', ['created_at'])
    
    op.create_index('idx_users_email', 'users', ['email'])
    op.create_index('idx_users_username', 'users', ['username'])
    op.create_index('idx_users_active', 'users', ['is_active'])
    op.create_index('idx_users_superuser', 'users', ['is_superuser'])
    op.create_index('idx_users_created_at', 'users', ['created_at'])
    
    op.create_index('idx_roles_name', 'roles', ['name'])
    op.create_index('idx_roles_system', 'roles', ['is_system_role'])
    
    op.create_index('idx_user_organizations_user', 'user_organizations', ['user_id'])
    op.create_index('idx_user_organizations_org', 'user_organizations', ['organization_id'])
    op.create_index('idx_user_organizations_role', 'user_organizations', ['role_id'])
    op.create_index('idx_user_organizations_active', 'user_organizations', ['is_active'])
    
    # Insert default roles
    op.execute("""
        INSERT INTO roles (name, description, permissions, is_system_role, created_at, updated_at) VALUES
        ('admin', 'Organization Administrator', '{"can_manage_users": true, "can_manage_scans": true, "can_view_reports": true, "can_manage_settings": true}', true, NOW(), NOW()),
        ('member', 'Organization Member', '{"can_view_scans": true, "can_view_reports": true, "can_run_scans": true}', true, NOW(), NOW()),
        ('viewer', 'Organization Viewer', '{"can_view_scans": true, "can_view_reports": true}', true, NOW(), NOW())
    """)


def downgrade() -> None:
    """Remove organizations, users, and role management tables."""
    
    # Drop indexes first
    op.drop_index('idx_user_organizations_active', 'user_organizations')
    op.drop_index('idx_user_organizations_role', 'user_organizations')
    op.drop_index('idx_user_organizations_org', 'user_organizations')
    op.drop_index('idx_user_organizations_user', 'user_organizations')
    
    op.drop_index('idx_roles_system', 'roles')
    op.drop_index('idx_roles_name', 'roles')
    
    op.drop_index('idx_users_created_at', 'users')
    op.drop_index('idx_users_superuser', 'users')
    op.drop_index('idx_users_active', 'users')
    op.drop_index('idx_users_username', 'users')
    op.drop_index('idx_users_email', 'users')
    
    op.drop_index('idx_organizations_created_at', 'organizations')
    op.drop_index('idx_organizations_active', 'organizations')
    op.drop_index('idx_organizations_slug', 'organizations')
    op.drop_index('idx_organizations_name', 'organizations')
    
    # Drop foreign key constraints
    op.drop_constraint('fk_organizations_created_by', 'organizations', type_='foreignkey')
    
    # Drop tables in reverse order
    op.drop_table('user_organizations')
    op.drop_table('roles')
    op.drop_table('users')
    op.drop_table('organizations')
