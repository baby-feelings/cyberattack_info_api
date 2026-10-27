"""add repo_dependencies table (DEPSCAN dependency inventory for SBOM)

Revision ID: a3c9e1d27b58
Revises: e7f1c5a9d364
Create Date: 2026-10-27 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a3c9e1d27b58'
down_revision: Union[str, Sequence[str], None] = 'e7f1c5a9d364'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'repo_dependencies',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('repo_full_name', sa.String(length=255), nullable=False),
        sa.Column('ecosystem', sa.String(length=50), nullable=False),
        sa.Column('package_name', sa.String(length=255), nullable=False),
        sa.Column('version', sa.String(length=100), nullable=False),
        sa.Column('manifest_path', sa.String(length=1000), nullable=False),
        sa.Column(
            'scanned_at', sa.DateTime(timezone=True), server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'repo_full_name', 'ecosystem', 'package_name', 'version', 'manifest_path',
            name='uq_repo_dependencies',
        ),
    )
    op.create_index(
        'ix_repo_dependencies_repo', 'repo_dependencies', ['repo_full_name'], unique=False,
    )
    op.create_index(
        'ix_repo_dependencies_package', 'repo_dependencies',
        ['ecosystem', 'package_name'], unique=False,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_repo_dependencies_package', table_name='repo_dependencies')
    op.drop_index('ix_repo_dependencies_repo', table_name='repo_dependencies')
    op.drop_table('repo_dependencies')
