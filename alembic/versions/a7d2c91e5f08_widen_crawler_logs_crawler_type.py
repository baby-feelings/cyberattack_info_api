"""widen crawler_logs.crawler_type to 20 characters

COMMITWATCH（11文字）が String(10) に収まらず、実行記録を保存できなかったため広げる。
列を広げるだけで、既存の値は変わらない。

Revision ID: a7d2c91e5f08
Revises: c6f1b0a49e83
Create Date: 2026-11-06 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a7d2c91e5f08'
down_revision: Union[str, Sequence[str], None] = 'c6f1b0a49e83'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('crawler_logs') as batch_op:
        batch_op.alter_column(
            'crawler_type',
            existing_type=sa.String(length=10),
            type_=sa.String(length=20),
            existing_nullable=False,
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('crawler_logs') as batch_op:
        batch_op.alter_column(
            'crawler_type',
            existing_type=sa.String(length=20),
            type_=sa.String(length=10),
            existing_nullable=False,
        )
