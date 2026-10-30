"""add commit_watch_states table (commit watch, Issue #405)

Revision ID: b5e0a9f38d72
Revises: a4d9f8e27c61
Create Date: 2026-10-31 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b5e0a9f38d72'
down_revision: Union[str, Sequence[str], None] = 'a4d9f8e27c61'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'commit_watch_states',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('repo_full_name', sa.String(length=255), nullable=False),
        sa.Column('last_sha', sa.String(length=40), nullable=False),
        sa.Column('checked_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('repo_full_name'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('commit_watch_states')
