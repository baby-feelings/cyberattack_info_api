"""add runtime_releases and repo_runtimes tables (runtime version monitoring)

Revision ID: b8d4f2a61c93
Revises: a3c9e1d27b58
Create Date: 2026-10-28 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b8d4f2a61c93'
down_revision: Union[str, Sequence[str], None] = 'a3c9e1d27b58'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'runtime_releases',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('runtime', sa.String(length=20), nullable=False),
        sa.Column('cycle', sa.String(length=20), nullable=False),
        sa.Column('latest_version', sa.String(length=50), nullable=False),
        sa.Column('release_date', sa.Date(), nullable=True),
        sa.Column('eol_date', sa.Date(), nullable=True),
        sa.Column('is_eol', sa.Boolean(), nullable=False),
        sa.Column('is_lts', sa.Boolean(), nullable=False),
        sa.Column(
            'updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('runtime', 'cycle', name='uq_runtime_releases'),
    )
    op.create_table(
        'repo_runtimes',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('repo_full_name', sa.String(length=255), nullable=False),
        sa.Column('runtime', sa.String(length=20), nullable=False),
        sa.Column('cycle', sa.String(length=20), nullable=False),
        sa.Column('source_path', sa.String(length=1000), nullable=False),
        sa.Column('pinned', sa.Boolean(), nullable=False),
        sa.Column(
            'scanned_at', sa.DateTime(timezone=True), server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'repo_full_name', 'runtime', 'cycle', 'source_path', name='uq_repo_runtimes',
        ),
    )
    op.create_index('ix_repo_runtimes_repo', 'repo_runtimes', ['repo_full_name'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_repo_runtimes_repo', table_name='repo_runtimes')
    op.drop_table('repo_runtimes')
    op.drop_table('runtime_releases')
