"""add audit_logs table (audit log of admin operations and authentication, Issue #406)

Revision ID: c6f1b0a49e83
Revises: b5e0a9f38d72
Create Date: 2026-10-31 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c6f1b0a49e83'
down_revision: Union[str, Sequence[str], None] = 'b5e0a9f38d72'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('actor', sa.String(length=100), nullable=False),
        sa.Column('action', sa.String(length=200), nullable=False),
        sa.Column('outcome', sa.String(length=20), nullable=False),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_audit_logs_occurred_at', 'audit_logs', ['occurred_at'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_audit_logs_occurred_at', table_name='audit_logs')
    op.drop_table('audit_logs')
