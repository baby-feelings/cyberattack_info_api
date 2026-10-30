"""add site_checks table (external monitoring of public sites, Issue #401)

Revision ID: a4d9f8e27c61
Revises: f3b8d6c05e49
Create Date: 2026-10-31 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a4d9f8e27c61'
down_revision: Union[str, Sequence[str], None] = 'f3b8d6c05e49'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'site_checks',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('url', sa.String(length=500), nullable=False),
        sa.Column('source', sa.String(length=30), nullable=False),
        sa.Column('repo_full_name', sa.String(length=255), nullable=True),
        sa.Column('tls_days_left', sa.Integer(), nullable=True),
        sa.Column('findings', sa.JSON(), nullable=False),
        sa.Column('checked_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            'updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('url'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('site_checks')
