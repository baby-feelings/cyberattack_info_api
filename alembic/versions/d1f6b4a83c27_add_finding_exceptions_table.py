"""add finding_exceptions table (exception / acceptance management, Issue #403)

Revision ID: d1f6b4a83c27
Revises: c9e5a3b72d14
Create Date: 2026-10-31 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd1f6b4a83c27'
down_revision: Union[str, Sequence[str], None] = 'c9e5a3b72d14'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'finding_exceptions',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('kind', sa.String(length=20), nullable=False),
        sa.Column('repo_full_name', sa.String(length=255), nullable=False),
        sa.Column('finding_key', sa.String(length=1000), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('approver', sa.String(length=100), nullable=False),
        sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('ended_reason', sa.String(length=20), nullable=True),
        sa.Column('expiry_notified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            'created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.Column(
            'updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_finding_exceptions_target', 'finding_exceptions', ['kind', 'repo_full_name'],
    )
    op.create_index('ix_finding_exceptions_ended_at', 'finding_exceptions', ['ended_at'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_finding_exceptions_ended_at', table_name='finding_exceptions')
    op.drop_index('ix_finding_exceptions_target', table_name='finding_exceptions')
    op.drop_table('finding_exceptions')
