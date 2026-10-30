"""公開サイトの外形監視（EXTMON）のジョブの組み立て（Issue #401）。

対象サイトを集め（`targets`）、1サイトずつ点検して（`probes`）保存する。前回より悪化したとき
（新しい問題・証明書の期限がしきい値を下回った）は、管理者に Slack で知らせる。
毎日 APScheduler から呼ばれる。
"""
import logging
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.crawler_runner import CrawlCounters, CrawlJob
from app.core.github.accounts import list_target_repos
from app.core.notifications.site_alerts import SiteAlertNotifier
from app.crawler_logs.writer import now_utc
from app.external_monitor import probes
from app.external_monitor.models import SiteCheck
from app.external_monitor.targets import Target, discover_targets

logger = logging.getLogger(__name__)

# 悪化として通知する、重要度（INFO のヘッダー不足は、一覧で確認する）
_ALERT_SEVERITIES = (probes.ERROR, probes.WARNING)


def _keys(findings: list[dict[str, str]]) -> set[str]:
    return {f["rule"] for f in findings if f["severity"] in _ALERT_SEVERITIES}


def check_target(db: Session, target: Target) -> list[dict[str, str]]:
    """1サイトを点検して保存する。前回より増えた問題（悪化）を返す。内部アドレス等は、点検しない。"""
    if not probes.is_safe_target(target.url):
        logger.warning("EXTMON: skipped unsafe target %s", target.url)
        return []
    host = target.url.removeprefix("https://")
    days_left, findings = probes.probe_site(target.url, target.firebase_project)
    row = db.query(SiteCheck).filter_by(url=target.url).first()
    previous = _keys(row.findings) if row else None
    if row is None:
        row = SiteCheck(url=target.url)
        db.add(row)
    row.source, row.repo_full_name = target.source, target.repo_full_name
    row.tls_days_left, row.findings, row.checked_at = days_left, findings, now_utc()
    db.commit()
    # 初回は、既存の問題を「悪化」として通知しない（一覧で確認する。通知が溢れるため）
    if previous is None:
        return []
    return [dict(f, url=target.url, host=host) for f in findings
            if f["severity"] in _ALERT_SEVERITIES and f["rule"] not in previous]


class _SiteMonitorJob(CrawlJob):
    """EXTMON の1回分の実行。

    `CrawlCounters` へのマッピング: inserted=点検したサイト数、
    updated=問題（ERROR・WARNING）があるサイト数、deleted=悪化（新しい問題）の件数。
    """

    crawler_type = "EXTMON"

    def __init__(self) -> None:
        self.worsened: list[dict[str, Any]] = []

    def execute(self, db: Session, counters: CrawlCounters) -> None:
        targets = discover_targets(list_target_repos(settings.GITHUB_TOKEN), settings.GITHUB_TOKEN)
        logger.info("EXTMON: %d sites", len(targets))
        for target in targets:
            # 1サイトの失敗で、他のサイトの点検を止めない
            try:
                worsened = check_target(db, target)
            except Exception as exc:
                logger.warning("EXTMON: %s failed: %s", target.url, exc, exc_info=True)
                continue
            counters.inserted += 1
            self.worsened.extend(worsened)
        counters.deleted = len(self.worsened)
        counters.updated = sum(
            1 for row in db.query(SiteCheck) if _keys(row.findings)
        )

    def after_success(self, counters: CrawlCounters) -> None:
        logger.info(
            "=== EXTMON completed: sites=%d, with_issues=%d, worsened=%d ===",
            counters.inserted, counters.updated, counters.deleted,
        )
        try:
            SiteAlertNotifier(self.worsened).send()
        except Exception as exc:
            logger.error("EXTMON: failed to notify: %s", exc, exc_info=True)

    def result(self, counters: CrawlCounters) -> tuple[int, ...]:
        return counters.inserted, counters.deleted, counters.updated


def fetch_and_monitor_sites(*, force: bool = False) -> tuple[int, int, int]:
    """EXTMON のメインエントリポイント。APScheduler から毎日呼び出される。

    Returns:
        (sites, worsened, with_issues) のタプル（スキップ時は (0, 0, 0)）
    """
    logger.info("=== EXTMON started ===")
    return _SiteMonitorJob().run(force=force)  # type: ignore[return-value]
