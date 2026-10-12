"""add oauth_authorizations table and mcp_tokens.oauth_client_id

Revision ID: d6e0b4f8c253
Revises: c5d9a3e7b142
Create Date: 2026-10-12 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd6e0b4f8c253'
down_revision: Union[str, Sequence[str], None] = 'c5d9a3e7b142'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'oauth_authorizations',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('client_id', sa.String(length=64), nullable=False),
        sa.Column('redirect_uri', sa.Text(), nullable=False),
        sa.Column('redirect_uri_provided_explicitly', sa.Boolean(), nullable=False),
        sa.Column('state', sa.Text(), nullable=True),
        sa.Column('code_challenge', sa.String(length=128), nullable=False),
        sa.Column('scope', sa.String(length=255), nullable=False),
        sa.Column('resource', sa.Text(), nullable=True),
        sa.Column('username', sa.String(length=255), nullable=True),
        sa.Column('code_hash', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('code_hash'),
    )
    op.create_index(op.f('ix_oauth_authorizations_client_id'), 'oauth_authorizations', ['client_id'], unique=False)
    op.create_index(op.f('ix_oauth_authorizations_expires_at'), 'oauth_authorizations', ['expires_at'], unique=False)
    op.add_column('mcp_tokens', sa.Column('oauth_client_id', sa.String(length=64), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('mcp_tokens', 'oauth_client_id')
    op.drop_index(op.f('ix_oauth_authorizations_expires_at'), table_name='oauth_authorizations')
    op.drop_index(op.f('ix_oauth_authorizations_client_id'), table_name='oauth_authorizations')
    op.drop_table('oauth_authorizations')
