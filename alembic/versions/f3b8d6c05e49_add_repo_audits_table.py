"""add repo_audits table (repository security settings audit, Issue #398)

Revision ID: f3b8d6c05e49
Revises: e2a7c5b94d38
Create Date: 2026-10-31 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f3b8d6c05e49'
down_revision: Union[str, Sequence[str], None] = 'e2a7c5b94d38'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'repo_audits',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('repo_full_name', sa.String(length=255), nullable=False),
        sa.Column('score', sa.Integer(), nullable=True),
        sa.Column('checks', sa.JSON(), nullable=False),
        sa.Column('snapshot', sa.JSON(), nullable=False),
        sa.Column('changes', sa.JSON(), nullable=False),
        sa.Column('audited_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            'updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('repo_full_name'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('repo_audits')
