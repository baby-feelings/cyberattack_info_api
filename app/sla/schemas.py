"""脆弱性への対応状況（SLA・MTTR）API の出力スキーマ。"""
from pydantic import BaseModel, Field


class SlaPolicyOut(BaseModel):
    """適用中の対応期限（検知から解決までの目標日数）。"""

    critical_days: int = Field(description="CRITICAL の対応期限（日）")
    high_days: int = Field(description="HIGH の対応期限（日）")
    medium_days: int = Field(description="MEDIUM の対応期限（日）")
    kev_days: int = Field(description="CISA KEV 掲載済みの対応期限（日。重要度によらず短縮）")
    excluded_osv_ids: list[str] = Field(
        description="期限の計算から外している OSV ID（例外〈受容など〉にした検知）",
    )


class SlaSummary(BaseModel):
    """全体の件数と平均対応日数。"""

    open_with_deadline: int = Field(description="未解決で、期限がある検知の件数")
    overdue: int = Field(description="そのうち、期限を超えている件数")
    resolved: int = Field(description="集計期間内に解決した件数")
    mttr_days: float | None = Field(
        None, description="平均対応日数（MTTR。検知から解決まで）。解決が0件なら null",
    )


class SlaSeverityStat(BaseModel):
    """重要度別の件数と平均対応日数。"""

    severity: str = Field(description="重要度（CRITICAL/HIGH/MEDIUM/LOW/N/A）")
    deadline_days: int | None = Field(None, description="対応期限（日）。期限なしは null")
    open: int = Field(description="未解決の件数")
    overdue: int = Field(description="期限超過の件数")
    resolved: int = Field(description="集計期間内に解決した件数")
    mttr_days: float | None = Field(None, description="平均対応日数。解決が0件なら null")


class SlaRepoStat(BaseModel):
    """リポジトリ別の件数と平均対応日数（期限超過が多い順）。"""

    repo_full_name: str
    open: int = Field(description="未解決の件数")
    overdue: int = Field(description="期限超過の件数")
    resolved: int = Field(description="集計期間内に解決した件数")
    mttr_days: float | None = Field(None, description="平均対応日数。解決が0件なら null")


class SlaOverdueItem(BaseModel):
    """期限を超えている検知（超過日数が多い順）。"""

    repo_full_name: str
    package_name: str
    installed_version: str
    osv_id: str
    severity: str | None
    is_kev: bool = Field(description="CISA KEV に掲載済みか（期限が短縮される）")
    is_malicious: bool = Field(description="悪意あるパッケージ（MAL-*）か")
    detected_at: str = Field(description="検知日時（ISO 8601）")
    deadline_days: int = Field(description="適用された対応期限（日）")
    due_at: str = Field(description="期限日時（ISO 8601）")
    overdue_days: int = Field(description="期限を超えた日数")


class SlaReportOut(BaseModel):
    """対応状況（SLA・MTTR）のレポート。"""

    generated_at: str = Field(description="集計日時（ISO 8601）")
    mttr_window_days: int = Field(description="MTTR を集計する、解決済みの期間（日）")
    policy: SlaPolicyOut
    summary: SlaSummary
    by_severity: list[SlaSeverityStat]
    by_repo: list[SlaRepoStat]
    overdue: list[SlaOverdueItem]
