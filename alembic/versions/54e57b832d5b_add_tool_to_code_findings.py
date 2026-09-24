"""add tool to code_findings

Revision ID: 54e57b832d5b
Revises: fe0a60aefadf
Create Date: 2026-09-24 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '54e57b832d5b'
down_revision: Union[str, Sequence[str], None] = 'fe0a60aefadf'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # 既存レコードは全て gitleaks 導入以前の Semgrep 検知のため、server_default で
    # "semgrep" を設定し後方互換を確保する（Issue #219: gitleaks 統合）。
    op.add_column(
        'code_findings',
        sa.Column(
            'tool', sa.String(length=20), nullable=False, server_default='semgrep',
        ),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('code_findings', 'tool')
