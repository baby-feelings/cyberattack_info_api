"""add runtime_alerts table (sent runtime version notifications)

Revision ID: c9e5a3b72d14
Revises: b8d4f2a61c93
Create Date: 2026-10-28 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c9e5a3b72d14'
down_revision: Union[str, Sequence[str], None] = 'b8d4f2a61c93'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'runtime_alerts',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('alert_key', sa.String(length=100), nullable=False),
        sa.Column(
            'sent_at', sa.DateTime(timezone=True), server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('alert_key'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('runtime_alerts')
