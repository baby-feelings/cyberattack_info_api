"""add oauth_refresh_tokens table

Revision ID: e7f1c5a9d364
Revises: d6e0b4f8c253
Create Date: 2026-10-12 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e7f1c5a9d364'
down_revision: Union[str, Sequence[str], None] = 'd6e0b4f8c253'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'oauth_refresh_tokens',
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('family_id', sa.String(length=36), nullable=False),
        sa.Column('client_id', sa.String(length=64), nullable=False),
        sa.Column('username', sa.String(length=255), nullable=False),
        sa.Column('scope', sa.String(length=255), nullable=False),
        sa.Column('resource', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('token_hash'),
    )
    op.create_index(op.f('ix_oauth_refresh_tokens_family_id'), 'oauth_refresh_tokens', ['family_id'], unique=False)
    op.create_index(op.f('ix_oauth_refresh_tokens_client_id'), 'oauth_refresh_tokens', ['client_id'], unique=False)
    op.create_index(op.f('ix_oauth_refresh_tokens_username'), 'oauth_refresh_tokens', ['username'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_oauth_refresh_tokens_username'), table_name='oauth_refresh_tokens')
    op.drop_index(op.f('ix_oauth_refresh_tokens_client_id'), table_name='oauth_refresh_tokens')
    op.drop_index(op.f('ix_oauth_refresh_tokens_family_id'), table_name='oauth_refresh_tokens')
    op.drop_table('oauth_refresh_tokens')
