"""削除済みGitHubリポジトリのDEPSCAN/CODESCAN/DEPSOPSデータをDBから削除する
モジュール（Issue #228）。

DEPSCAN/CODESCAN/DEPSOPSはいずれも「今回のスキャンで取得できたリポジトリ一覧」
を基準に検知結果を更新するが、リポジトリ自体がGitHub上で削除されると
`list_target_repos`の結果から静かに消えるだけで、そのリポジトリに紐づく
既存のDBレコードは一切触れられない（DEPSCANは全体横断の解決判定があるため
未解決→解決済みへは変わるが、CODESCAN/DEPSOPSはリポジトリ単位の解決判定しか
持たないため「未解決」のまま永久に残り、ダッシュボードに表示され続けてしまう
実害があった）。

本モジュールは、DBに記録が残っているが今回の対象リポジトリ一覧に含まれない
リポジトリについて、GitHub APIで実際に削除されたことを個別に確認した上で
（`repo_exists`）、3ドメインのレコードをまとめて削除する。アーカイブ化・
可視性変更・一時的なAPI障害等で一覧から除外されているだけのリポジトリを
誤って削除しないよう、必ず個別に存在確認してから削除する（安全側に倒す）。
"""
import logging

from sqlalchemy.orm import Session

from app.codescan.models import CodeFinding
from app.core.config import settings
from app.core.database import SessionLocal
from app.crawler_logs.writer import now_utc, write_crawler_log
from app.depscan.github_client import list_target_repos, repo_exists
from app.depscan.models import DependencyFinding
from app.depsops.models import DependabotPrLog

logger = logging.getLogger(__name__)


def _find_known_repos(db: Session, owner: str) -> set[str]:
    """DEPSCAN/CODESCAN/DEPSOPSのいずれかにレコードが存在する、
    `{owner}/...`形式のリポジトリ名一覧を返す（重複除去済み）。
    """
    known: set[str] = set()
    prefix = f"{owner}/"
    for model in (DependencyFinding, CodeFinding, DependabotPrLog):
        rows = (
            db.query(model.repo_full_name)
            .filter(model.repo_full_name.like(f"{prefix}%"))
            .distinct()
            .all()
        )
        known.update(row[0] for row in rows)
    return known


def _purge_repo_data(db: Session, repo_full_name: str) -> dict[str, int]:
    """指定リポジトリの3ドメイン分のレコードをまとめて削除する。"""
    counts = {
        "dependency_findings": (
            db.query(DependencyFinding)
            .filter(DependencyFinding.repo_full_name == repo_full_name)
            .delete(synchronize_session=False)
        ),
        "code_findings": (
            db.query(CodeFinding)
            .filter(CodeFinding.repo_full_name == repo_full_name)
            .delete(synchronize_session=False)
        ),
        "dependabot_pr_logs": (
            db.query(DependabotPrLog)
            .filter(DependabotPrLog.repo_full_name == repo_full_name)
            .delete(synchronize_session=False)
        ),
    }
    db.commit()
    return counts


def purge_deleted_repos(username: str, token: str, current_repo_full_names: set[str]) -> int:
    """`username`配下でDBに記録が残っているが、今回のスキャン対象一覧
    （`current_repo_full_names`）に含まれないリポジトリについて、GitHub上で
    実際に削除されたことを確認できたものだけデータを削除する。

    Args:
        username: 対象GitHubアカウント（DEPSCAN/CODESCAN/DEPSOPSのスキャン対象と同じ）
        token: 存在確認に使うGitHub PAT（本人のトークン、またはGITHUB_TOKEN）
        current_repo_full_names: 今回のスキャンで実際に取得できたリポジトリ
            （`repo_info["full_name"]`）の集合

    Returns:
        パージ（データ削除）したリポジトリ数
    """
    db: Session = SessionLocal()
    try:
        known = _find_known_repos(db, username)
        candidates = sorted(known - current_repo_full_names)
        if not candidates:
            return 0

        purged = 0
        for full_name in candidates:
            owner, repo = full_name.split("/", 1)
            exists = repo_exists(owner, repo, token)
            if exists is False:
                counts = _purge_repo_data(db, full_name)
                total = sum(counts.values())
                logger.info(
                    "Purged deleted repo %s: %s (total %d rows)", full_name, counts, total,
                )
                purged += 1
            elif exists is None:
                logger.info(
                    "repo_cleanup: existence check inconclusive for %s, skipping this run",
                    full_name,
                )
            # exists is True: アーカイブ化・可視性変更等で一覧から除外されている
            # だけで実在するため、データは削除しない

        return purged
    finally:
        db.close()


def run_repo_cleanup() -> int:
    """baby-feelings（GITHUB_USERNAME）向けの毎日クロールの後段として実行する
    エントリポイント。crawler_logs にも記録する（`crawler_type="CLEANUP"`。
    `deleted`フィールドにパージしたリポジトリ数を格納）。

    Returns:
        パージしたリポジトリ数
    """
    logger.info("=== Repo cleanup (deleted repo purge) started ===")
    started_at = now_utc()
    try:
        repos = list_target_repos(settings.GITHUB_USERNAME, settings.GITHUB_TOKEN)
        current_names = {r["full_name"] for r in repos}
        purged = purge_deleted_repos(settings.GITHUB_USERNAME, settings.GITHUB_TOKEN, current_names)
    except Exception as exc:
        write_crawler_log(
            crawler_type="CLEANUP", status="error",
            started_at=started_at, finished_at=now_utc(),
            error_message=str(exc),
        )
        raise

    logger.info("=== Repo cleanup completed: purged=%d ===", purged)
    write_crawler_log(
        crawler_type="CLEANUP", status="success",
        started_at=started_at, finished_at=now_utc(),
        deleted=purged,
    )
    return purged
