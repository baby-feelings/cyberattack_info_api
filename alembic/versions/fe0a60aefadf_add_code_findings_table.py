"""add code_findings table (CODESCAN)

Revision ID: fe0a60aefadf
Revises: d33e94df618f
Create Date: 2026-09-24 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'fe0a60aefadf'
down_revision: Union[str, Sequence[str], None] = 'd33e94df618f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'code_findings',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('repo_full_name', sa.String(length=255), nullable=False),
        sa.Column('file_path', sa.String(length=1000), nullable=False),
        sa.Column('line_start', sa.Integer(), nullable=False),
        sa.Column('line_end', sa.Integer(), nullable=False),
        sa.Column('rule_id', sa.String(length=500), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column(
            'cwe_ids', sa.JSON(), nullable=False, server_default=sa.text("'[]'"),
        ),
        sa.Column(
            'owasp_categories', sa.JSON(), nullable=False, server_default=sa.text("'[]'"),
        ),
        sa.Column('code_snippet', sa.Text(), nullable=False),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('cvss_vector', sa.String(length=100), nullable=True),
        sa.Column('detected_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            'created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.Column(
            'updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'repo_full_name', 'file_path', 'rule_id', 'line_start',
            name='uq_code_findings',
        ),
    )
    op.create_index(
        'ix_code_findings_repo', 'code_findings', ['repo_full_name'], unique=False,
    )
    op.create_index(
        'ix_code_findings_severity', 'code_findings', ['severity'], unique=False,
    )
    op.create_index(
        'ix_code_findings_resolved_at', 'code_findings', ['resolved_at'], unique=False,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_code_findings_resolved_at', table_name='code_findings')
    op.drop_index('ix_code_findings_severity', table_name='code_findings')
    op.drop_index('ix_code_findings_repo', table_name='code_findings')
    op.drop_table('code_findings')
