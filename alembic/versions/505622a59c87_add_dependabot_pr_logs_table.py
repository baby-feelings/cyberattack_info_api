"""add dependabot_pr_logs table

Revision ID: 505622a59c87
Revises: 1d779893ad98
Create Date: 2026-09-07 20:58:38.030085

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '505622a59c87'
down_revision: Union[str, Sequence[str], None] = '1d779893ad98'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'dependabot_pr_logs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('repo_full_name', sa.String(length=255), nullable=False),
        sa.Column('pr_number', sa.Integer(), nullable=False),
        sa.Column('title', sa.Text(), nullable=False),
        sa.Column('action', sa.String(length=20), nullable=False),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('processed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            'created_at', sa.DateTime(timezone=True),
            server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False,
        ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_dependabot_pr_logs_action', 'dependabot_pr_logs', ['action'], unique=False)
    op.create_index(
        'ix_dependabot_pr_logs_processed_at', 'dependabot_pr_logs', ['processed_at'], unique=False,
    )
    op.create_index('ix_dependabot_pr_logs_repo', 'dependabot_pr_logs', ['repo_full_name'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_dependabot_pr_logs_repo', table_name='dependabot_pr_logs')
    op.drop_index('ix_dependabot_pr_logs_processed_at', table_name='dependabot_pr_logs')
    op.drop_index('ix_dependabot_pr_logs_action', table_name='dependabot_pr_logs')
    op.drop_table('dependabot_pr_logs')
