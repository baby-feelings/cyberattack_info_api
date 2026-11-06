"""drop jvn_vulnerabilities table and JVN crawler logs (JVN 廃止)

JVN は、MyJVN API が 404 を返し続け、このアプリの用途にもほとんど関係しないため廃止した。
クローラー・API・MCP・TAXII を削除したのに合わせて、テーブルと、実行履歴（crawler_logs）の
JVN の行も削除する。downgrade は、テーブルの構造だけを戻す（削除したデータは戻らない）。

Revision ID: b3e8f4a1c697
Revises: a7d2c91e5f08
Create Date: 2026-11-06 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b3e8f4a1c697'
down_revision: Union[str, Sequence[str], None] = 'a7d2c91e5f08'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # 実行履歴の JVN の行（廃止したため、一覧に出し続けない）
    op.execute("DELETE FROM crawler_logs WHERE crawler_type = 'JVN'")
    op.drop_table('jvn_vulnerabilities')


def downgrade() -> None:
    """Downgrade schema（構造だけを戻す。データは戻らない）."""
    op.create_table(
        'jvn_vulnerabilities',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('jvndb_id', sa.String(length=50), nullable=False),
        sa.Column('title', sa.Text(), nullable=False),
        sa.Column('overview', sa.Text(), nullable=False),
        sa.Column('cve_ids', sa.JSON(), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=True),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('cvss_vector', sa.String(length=200), nullable=True),
        sa.Column('affected_products', sa.JSON(), nullable=False),
        sa.Column('references', sa.JSON(), nullable=False),
        sa.Column('jvn_url', sa.String(length=500), nullable=False),
        sa.Column('date_published', sa.DateTime(timezone=True), nullable=False),
        sa.Column('date_last_modified', sa.DateTime(timezone=True), nullable=False),
        sa.Column('fetched_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('jvndb_id', name='uq_jvn_vulnerabilities_jvndb_id'),
    )
    op.create_index('ix_jvn_vulnerabilities_severity', 'jvn_vulnerabilities', ['severity'], unique=False)
    op.create_index(
        'ix_jvn_vulnerabilities_date_last_modified', 'jvn_vulnerabilities', ['date_last_modified'], unique=False,
    )
