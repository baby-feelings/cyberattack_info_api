"""`GithubAlert`・`GithubAlertSource` の永続化と、DEPSCAN の検知との突き合わせ。"""
from typing import Any

from sqlalchemy.orm import Session

from app.crawler_logs.writer import now_utc
from app.depscan.models import DependencyFinding
from app.github_alerts.models import (
    KIND_DEPENDABOT,
    SOURCE_AVAILABLE,
    SOURCE_UNAVAILABLE,
    GithubAlert,
    GithubAlertSource,
)


class GithubAlertRepository:
    """GitHub のアラートの保存・検索。"""

    def __init__(self, db: Session) -> None:
        self._db = db

    def record_unavailable(self, kind: str, repo: str, reason: str) -> None:
        """取得できなかった（既存のアラートは、触らない）ことを記録する。"""
        self._set_source(kind, repo, SOURCE_UNAVAILABLE, reason)
        self._db.commit()

    def sync(self, kind: str, repo: str, alerts: list[dict[str, Any]]) -> list[GithubAlert]:
        """1リポジトリ・1種類の、今回のアラートを反映する。新規に検知したアラートを返す。

        今回の結果に無い未解決のアラートは、GitHub 側で解決された（修正・却下）ため、
        解決済みにする。
        """
        now = now_utc()
        self._set_source(kind, repo, SOURCE_AVAILABLE, None)
        existing = {
            a.number: a for a in self._db.query(GithubAlert).filter(
                GithubAlert.kind == kind, GithubAlert.repo_full_name == repo,
            )
        }
        new: list[GithubAlert] = []
        current = set()
        for item in alerts:
            current.add(item["number"])
            row = existing.get(item["number"])
            if row is None:
                row = GithubAlert(**item)
                self._db.add(row)
                new.append(row)
                continue
            # 再び開かれた・内容が変わった場合も、最新にする
            row.severity, row.title = item["severity"], item["title"]
            row.html_url = item["html_url"]
            row.detail = item["detail"]
            row.resolved_at = None
        for number, row in existing.items():
            if number not in current and row.resolved_at is None:
                row.resolved_at = now
        self._db.commit()
        return new

    def _set_source(self, kind: str, repo: str, status: str, reason: str | None) -> None:
        row = self._db.query(GithubAlertSource).filter_by(kind=kind, repo_full_name=repo).first()
        if row is None:
            row = GithubAlertSource(kind=kind, repo_full_name=repo, status=status,
                                    reason=reason, checked_at=now_utc())
            self._db.add(row)
            return
        row.status, row.reason, row.checked_at = status, reason, now_utc()


def dependabot_vs_depscan(
    db: Session, repo_prefix: str | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Dependabot alerts と DEPSCAN の検知を、(エコシステム・パッケージ・勧告ID) で突き合わせる。

    片方だけが検知したものが、検知の抜け（または、データ源の違い）。両方が検知したものは、重複として
    1件にまとめる。DEPSCAN の OSV ID は GHSA のことが多く、GitHub 側の勧告 ID と一致する。
    """
    alerts = db.query(GithubAlert).filter(
        GithubAlert.kind == KIND_DEPENDABOT, GithubAlert.resolved_at.is_(None),
    )
    findings = db.query(DependencyFinding).filter(DependencyFinding.resolved_at.is_(None))
    if repo_prefix:
        alerts = alerts.filter(GithubAlert.repo_full_name.like(f"{repo_prefix}/%"))
        findings = findings.filter(DependencyFinding.repo_full_name.like(f"{repo_prefix}/%"))

    def key(repo: str, ecosystem: str | None, package: str | None, advisory: str | None):
        return (repo, (ecosystem or "").lower(), (package or "").lower(), advisory or "")

    github = {
        key(a.repo_full_name, a.detail.get("ecosystem"), a.detail.get("package"),
            a.detail.get("ghsa_id")): a for a in alerts
    }
    depscan = {
        key(f.repo_full_name, f.ecosystem, f.package_name, f.osv_id): f for f in findings
    }
    both = github.keys() & depscan.keys()
    return {
        "both": [_row(github[k]) for k in sorted(both)],
        "only_github": [_row(github[k]) for k in sorted(github.keys() - both)],
        "only_depscan": [
            {"repo_full_name": f.repo_full_name, "ecosystem": f.ecosystem,
             "package": f.package_name, "advisory_id": f.osv_id, "severity": f.severity}
            for k, f in sorted(depscan.items()) if k not in both
        ],
    }


def _row(alert: GithubAlert) -> dict[str, Any]:
    return {
        "repo_full_name": alert.repo_full_name, "ecosystem": alert.detail.get("ecosystem"),
        "package": alert.detail.get("package"), "advisory_id": alert.detail.get("ghsa_id"),
        "severity": alert.severity, "html_url": alert.html_url,
    }
