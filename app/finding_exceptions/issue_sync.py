"""例外の登録・解除に合わせた、GitHub Issue の整合（Issue #403）。

DEPSCAN の Issue は、リポジトリごとに1つ。有効な検知（未解決から例外を除いたもの）が0件に
なったら閉じ、例外が終わって有効な検知が戻ったら、コメントの追記（無ければ新規起票）で再び示す。
CODESCAN の Issue は、もともと閉じる処理が無い（新規検知の起票のみ）ため、
解除のときの再通知だけを行う。
GitHub への書き込みの失敗は、握りつぶす（例外の登録・解除そのものを失敗させない）。
"""
import logging

from app.codescan.issue_management import file_github_issues as file_code_issues
from app.core.database import SessionLocal
from app.depscan.issue_management import close_resolved_repo_issues
from app.depscan.issue_management import file_github_issues as file_dependency_issues
from app.finding_exceptions.matching import findings_for, snapshot_of
from app.finding_exceptions.models import KIND_DEPENDENCY, FindingException

logger = logging.getLogger(__name__)


def refile_issues(db, exceptions: list[FindingException]) -> None:
    """終了した例外の検知が、まだ未解決なら、リポジトリの Issue に再び示す。"""
    dependency: list[dict] = []
    code: list[dict] = []
    for exc in exceptions:
        target = dependency if exc.kind == KIND_DEPENDENCY else code
        target.extend(snapshot_of(row) for row in findings_for(db, exc))
    try:
        file_dependency_issues(dependency)
        file_code_issues(code)
    except Exception as exc:
        logger.warning("exception refile: failed to file issues: %s", exc, exc_info=True)


def sync_issues_after_change(
    kind: str, repo_full_name: str, finding_key: str, *, accepted: bool,
) -> None:
    """例外を登録（accepted=True）・解除（False）した後の、Issue の整合（バックグラウンド用）。"""
    db = SessionLocal()
    try:
        if accepted:
            if kind == KIND_DEPENDENCY:
                close_resolved_repo_issues(db, {repo_full_name})
        else:
            refile_issues(
                db, [FindingException(kind=kind, repo_full_name=repo_full_name,
                                      finding_key=finding_key)],
            )
    except Exception as exc:
        logger.warning(
            "exception issue sync failed (%s %s): %s", repo_full_name, finding_key, exc,
            exc_info=True,
        )
    finally:
        db.close()
