"""add github_alerts and github_alert_sources tables (GitHub security alerts, Issue #402)

Revision ID: e2a7c5b94d38
Revises: d1f6b4a83c27
Create Date: 2026-10-31 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e2a7c5b94d38'
down_revision: Union[str, Sequence[str], None] = 'd1f6b4a83c27'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'github_alerts',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('kind', sa.String(length=20), nullable=False),
        sa.Column('repo_full_name', sa.String(length=255), nullable=False),
        sa.Column('number', sa.Integer(), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=True),
        sa.Column('title', sa.Text(), nullable=False),
        sa.Column('html_url', sa.String(length=500), nullable=False),
        sa.Column('detail', sa.JSON(), nullable=False),
        sa.Column('detected_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            'updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('kind', 'repo_full_name', 'number', name='uq_github_alerts'),
    )
    op.create_index('ix_github_alerts_repo', 'github_alerts', ['repo_full_name'])
    op.create_table(
        'github_alert_sources',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('kind', sa.String(length=20), nullable=False),
        sa.Column('repo_full_name', sa.String(length=255), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('reason', sa.String(length=200), nullable=True),
        sa.Column('checked_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('kind', 'repo_full_name', name='uq_github_alert_sources'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('github_alert_sources')
    op.drop_index('ix_github_alerts_repo', table_name='github_alerts')
    op.drop_table('github_alerts')
