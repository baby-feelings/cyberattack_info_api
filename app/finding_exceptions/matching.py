"""検知と例外の結び付け（同一性キーの組み立て・例外の除外・例外の取得）。

検知の同一性キー（`FindingException.finding_key`）:
- 依存ライブラリ（DEPSCAN）: `エコシステム|パッケージ名|OSV ID`
  （版を含めない。更新後も同じ脆弱性なら、例外が続く）
- コード・設定（CODESCAN）: `ファイルパス|ルールID`
  （行番号を含めない。コードの行がずれても、例外が外れない）
"""
from collections.abc import Callable, Iterable
from datetime import datetime
from typing import Any

from sqlalchemy import and_, exists, or_
from sqlalchemy.orm import Query, Session

from app.codescan.models import CodeFinding
from app.crawler_logs.writer import now_utc
from app.depscan.models import DependencyFinding
from app.finding_exceptions.models import (
    KIND_CODE,
    KIND_DEPENDENCY,
    FindingException,
)

KEY_SEPARATOR = "|"


def dependency_key(ecosystem: str, package_name: str, osv_id: str) -> str:
    """依存ライブラリの検知の同一性キー。"""
    return KEY_SEPARATOR.join((ecosystem, package_name, osv_id))


def code_key(file_path: str, rule_id: str) -> str:
    """コード・設定の検知の同一性キー。"""
    return KEY_SEPARATOR.join((file_path, rule_id))


def key_of_finding(kind: str, finding: Any) -> str:
    """検知（ORM の行、または同じ属性・キーを持つ辞書）の同一性キー。"""
    get: Callable[[str], Any] = (
        finding.get if isinstance(finding, dict) else (lambda name: getattr(finding, name))
    )
    if kind == KIND_DEPENDENCY:
        return dependency_key(get("ecosystem"), get("package_name"), get("osv_id"))
    return code_key(get("file_path"), get("rule_id"))


def _is_active(now: datetime) -> Any:
    """有効な例外の条件（終了しておらず、期限が切れていない）。"""
    return and_(
        FindingException.ended_at.is_(None),
        or_(FindingException.expires_at.is_(None), FindingException.expires_at > now),
    )


def active_exceptions(
    db: Session, kind: str, now: datetime | None = None,
) -> Query[FindingException]:
    """有効な例外のクエリ（期限切れは、定期ジョブが終了にする前でも、有効に数えない）。"""
    return db.query(FindingException).filter(
        FindingException.kind == kind, _is_active(now or now_utc()),
    )


def exception_map(
    db: Session, kind: str, repo_names: Iterable[str],
) -> dict[tuple[str, str], FindingException]:
    """指定リポジトリの有効な例外を、(リポジトリ, 同一性キー) で引ける辞書にする。"""
    names = set(repo_names)
    if not names:
        return {}
    rows = active_exceptions(db, kind).filter(FindingException.repo_full_name.in_(names)).all()
    return {(row.repo_full_name, row.finding_key): row for row in rows}


def not_excepted(query: Query[Any], kind: str) -> Query[Any]:
    """検知のクエリから、有効な例外のある検知を除く（件数・集計用）。"""
    if kind == KIND_DEPENDENCY:
        model: Any = DependencyFinding
        key_expr = (
            model.ecosystem + KEY_SEPARATOR + model.package_name + KEY_SEPARATOR + model.osv_id
        )
    else:
        model = CodeFinding
        key_expr = model.file_path + KEY_SEPARATOR + model.rule_id
    has_exception = exists().where(
        FindingException.kind == kind,
        FindingException.repo_full_name == model.repo_full_name,
        FindingException.finding_key == key_expr,
        _is_active(now_utc()),
    )
    return query.filter(~has_exception)


def drop_excepted(
    db: Session, kind: str, snapshots: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """新規検知のスナップショットから、有効な例外のあるものを除く（通知・Issue 起票用）。"""
    if not snapshots:
        return snapshots
    excepted = exception_map(db, kind, {s["repo_full_name"] for s in snapshots})
    if not excepted:
        return snapshots
    return [
        s for s in snapshots
        if (s["repo_full_name"], key_of_finding(kind, s)) not in excepted
    ]


def finding_exists(db: Session, kind: str, repo_full_name: str, finding_key: str) -> bool:
    """その同一性キーの検知が、実在する（解決済みを含む）か。"""
    if kind == KIND_DEPENDENCY:
        parts = finding_key.split(KEY_SEPARATOR)
        if len(parts) != 3:
            return False
        return db.query(
            exists().where(
                DependencyFinding.repo_full_name == repo_full_name,
                DependencyFinding.ecosystem == parts[0],
                DependencyFinding.package_name == parts[1],
                DependencyFinding.osv_id == parts[2],
            ),
        ).scalar() or False
    if kind == KIND_CODE:
        file_path, sep, rule_id = finding_key.rpartition(KEY_SEPARATOR)
        if not sep:
            return False
        return db.query(
            exists().where(
                CodeFinding.repo_full_name == repo_full_name,
                CodeFinding.file_path == file_path,
                CodeFinding.rule_id == rule_id,
            ),
        ).scalar() or False
    return False


def findings_for(db: Session, exc: FindingException) -> list[Any]:
    """例外に対応する、未解決の検知（コードは、同じファイル・ルールの全行）。"""
    if exc.kind == KIND_DEPENDENCY:
        parts = exc.finding_key.split(KEY_SEPARATOR)
        if len(parts) != 3:
            return []
        return db.query(DependencyFinding).filter(
            DependencyFinding.repo_full_name == exc.repo_full_name,
            DependencyFinding.ecosystem == parts[0],
            DependencyFinding.package_name == parts[1],
            DependencyFinding.osv_id == parts[2],
            DependencyFinding.resolved_at.is_(None),
        ).all()
    file_path, sep, rule_id = exc.finding_key.rpartition(KEY_SEPARATOR)
    if not sep:
        return []
    return db.query(CodeFinding).filter(
        CodeFinding.repo_full_name == exc.repo_full_name,
        CodeFinding.file_path == file_path,
        CodeFinding.rule_id == rule_id,
        CodeFinding.resolved_at.is_(None),
    ).all()


def snapshot_of(row: Any) -> dict[str, Any]:
    """ORM の検知を、Issue 起票・通知に渡す辞書（列名→値）にする。"""
    return {column.name: getattr(row, column.name) for column in row.__table__.columns}
