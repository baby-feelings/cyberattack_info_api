"""add mcp_tokens.expiry_notified_at

Revision ID: b4e8f2a6c931
Revises: a7c3d91f2b40
Create Date: 2026-10-12 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b4e8f2a6c931'
down_revision: Union[str, Sequence[str], None] = 'a7c3d91f2b40'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('mcp_tokens', sa.Column('expiry_notified_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('mcp_tokens', 'expiry_notified_at')
