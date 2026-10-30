"""対応期限（SLA）の方針。重要度などから、検知から解決までの目標日数を決める純粋なロジック。"""
from dataclasses import dataclass

from app.core.config import settings


@dataclass(frozen=True)
class SlaPolicy:
    """重要度ごとの対応期限（日）と、期限の計算から外す検知。

    - 期限があるのは CRITICAL・HIGH・MEDIUM。LOW・重要度不明は期限なし
    - CISA KEV に掲載済み（実際に悪用が確認された）検知は、重要度によらず `kev_days` に短縮する
    - 悪意あるパッケージ（`MAL-*`）は重要度が CRITICAL になるため、CRITICAL の期限になる
    """

    critical_days: int
    high_days: int
    medium_days: int
    kev_days: int
    excluded_osv_ids: frozenset[str] = frozenset()

    @classmethod
    def from_settings(cls) -> "SlaPolicy":
        """環境変数（`SLA_*`）から方針を作る。"""
        return cls(
            critical_days=settings.SLA_CRITICAL_DAYS,
            high_days=settings.SLA_HIGH_DAYS,
            medium_days=settings.SLA_MEDIUM_DAYS,
            kev_days=settings.SLA_KEV_DAYS,
            excluded_osv_ids=frozenset(
                osv_id.strip()
                for osv_id in settings.SLA_EXCLUDE_OSV_IDS.split(",")
                if osv_id.strip()
            ),
        )

    def days_for_severity(self, severity: str | None) -> int | None:
        """重要度に応じた対応期限（日）。期限が無い重要度（LOW・不明）は None。"""
        return {
            "CRITICAL": self.critical_days,
            "HIGH": self.high_days,
            "MEDIUM": self.medium_days,
        }.get((severity or "").upper())

    def deadline_days(self, severity: str | None, *, is_kev: bool = False) -> int | None:
        """検知から解決までの目標日数。KEV 掲載済みは、重要度の期限より短い場合に短縮する。

        重要度が LOW・不明でも、KEV に掲載されていれば `kev_days` の期限がつく。
        """
        by_severity = self.days_for_severity(severity)
        if not is_kev:
            return by_severity
        return self.kev_days if by_severity is None else min(by_severity, self.kev_days)

    def is_excluded(self, osv_id: str) -> bool:
        """期限の計算から外す検知か（受容した検知の手動除外）。"""
        return osv_id in self.excluded_osv_ids
