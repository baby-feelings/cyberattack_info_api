"""add oauth_clients table

Revision ID: c5d9a3e7b142
Revises: b4e8f2a6c931
Create Date: 2026-10-12 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c5d9a3e7b142'
down_revision: Union[str, Sequence[str], None] = 'b4e8f2a6c931'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'oauth_clients',
        sa.Column('client_id', sa.String(length=64), nullable=False),
        sa.Column('client_info_json', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('client_id'),
    )
    op.create_index(op.f('ix_oauth_clients_created_at'), 'oauth_clients', ['created_at'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_oauth_clients_created_at'), table_name='oauth_clients')
    op.drop_table('oauth_clients')
