"""DBマイグレーション実行モジュール（app.core.migrate）のテスト。
alembic の実際のDB操作はモックし、stamp判定ロジックのみを検証する。
"""
from unittest.mock import MagicMock, patch

from app.core.migrate import run_migrations


def test_stamps_baseline_when_pre_alembic_db_detected():
    """vulnerabilitiesテーブルはあるがalembic_versionが無い（導入前のDB）場合、
    ベースラインへstampしてからupgradeすること。
    """
    mock_inspector = MagicMock()
    mock_inspector.get_table_names.return_value = ["vulnerabilities", "osv_vulnerabilities"]

    with (
        patch("app.core.migrate.inspect", return_value=mock_inspector),
        patch("app.core.migrate.command") as mock_command,
        patch("app.core.migrate.Config"),
    ):
        run_migrations()

    mock_command.stamp.assert_called_once()
    mock_command.upgrade.assert_called_once()


def test_skips_stamp_when_alembic_already_tracked():
    """alembic_versionテーブルが既に存在する場合はstampせずupgradeのみ行うこと。"""
    mock_inspector = MagicMock()
    mock_inspector.get_table_names.return_value = ["vulnerabilities", "alembic_version"]

    with (
        patch("app.core.migrate.inspect", return_value=mock_inspector),
        patch("app.core.migrate.command") as mock_command,
        patch("app.core.migrate.Config"),
    ):
        run_migrations()

    mock_command.stamp.assert_not_called()
    mock_command.upgrade.assert_called_once()


def test_skips_stamp_when_database_is_fresh():
    """vulnerabilitiesテーブル自体が無い（真に新規のDB）場合はstampせずupgradeのみ行うこと。"""
    mock_inspector = MagicMock()
    mock_inspector.get_table_names.return_value = []

    with (
        patch("app.core.migrate.inspect", return_value=mock_inspector),
        patch("app.core.migrate.command") as mock_command,
        patch("app.core.migrate.Config"),
    ):
        run_migrations()

    mock_command.stamp.assert_not_called()
    mock_command.upgrade.assert_called_once()
