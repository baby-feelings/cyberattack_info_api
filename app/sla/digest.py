"""脆弱性への対応状況の、週次のまとめを Slack に送る定期ジョブ（Issue #404）。"""
import logging

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.notifications.sla_digest import SlaDigestNotifier
from app.depscan.filters import DepscanListFilter
from app.sla.policy import SlaPolicy
from app.sla.report import build_report

logger = logging.getLogger(__name__)


def run_sla_digest() -> bool:
    """管理者（`GITHUB_USERNAME`）自身のリポジトリの対応状況を集計し、週次のまとめを送る。

    運用停止中のアプリは、対応が急がれないため含めない。登録済みの他ユーザーへの通知は、
    本人の Webhook・リポジトリ単位の仕組みが別に要るため、対象にしない。
    送信に成功したら True（送るものが無い・失敗は False）。
    """
    db = SessionLocal()
    try:
        flt = DepscanListFilter(
            repo=None, owner=settings.GITHUB_USERNAME, ecosystem=None, severity=None,
            resolved=None, operating="active",
        )
        report = build_report(
            db, flt, SlaPolicy.from_settings(), window_days=settings.SLA_MTTR_WINDOW_DAYS,
        )
    finally:
        db.close()

    sent = SlaDigestNotifier(report.model_dump()).send()
    logger.info(
        "SLA digest: overdue=%d open_with_deadline=%d sent=%s",
        report.summary.overdue, report.summary.open_with_deadline, sent,
    )
    return sent
