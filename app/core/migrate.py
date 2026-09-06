"""DB マイグレーション実行モジュール（デプロイ時に呼び出す）。

`python -m app.core.migrate` として、アプリ起動前（Render の Start Command 等）から
明示的に呼び出すことを想定する。FastAPI の lifespan には組み込まない
（tests/conftest.py が Base.metadata.create_all で直接テーブルを作る既存の
テストDBに対して、意図せず alembic の管理外操作が走るのを避けるため）。

本プロジェクトはこれまで Base.metadata.create_all（新規テーブル作成のみ、
既存テーブルへの列追加はしない）のみでスキーマを管理してきたため、
本番・開発の既存DBには alembic のバージョン管理テーブル（alembic_version）が
存在しない。これを検知した場合は、現在のスキーマに一致するベースラインの
リビジョンへ自動的に stamp（DDLを実行せず「そこまでは適用済み」と記録するだけ）
してから head まで upgrade する。真にDBが空の新規デプロイの場合は
alembic_version・対象テーブルのいずれも存在しないため、stamp をスキップし
先頭のリビジョンから全て適用する。
"""
import logging

from alembic.config import Config
from sqlalchemy import inspect

from alembic import command
from app.core.database import engine

logger = logging.getLogger(__name__)

# 既存DB（alembic導入前に create_all で作られたもの）が一致するベースラインリビジョン
_BASELINE_REVISION = "eac4893a0796"


def run_migrations() -> None:
    """DBを最新のスキーマ（alembic head）まで移行する。"""
    alembic_cfg = Config("alembic.ini")

    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    if "vulnerabilities" in existing_tables and "alembic_version" not in existing_tables:
        logger.info(
            "Pre-alembic database detected; stamping baseline revision %s before upgrading",
            _BASELINE_REVISION,
        )
        command.stamp(alembic_cfg, _BASELINE_REVISION)

    command.upgrade(alembic_cfg, "head")
    logger.info("Database migrations applied (head)")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_migrations()
