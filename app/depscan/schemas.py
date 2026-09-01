"""DEPSCAN（依存ライブラリ脆弱性スキャン）ドメインの Pydantic スキーマ定義。"""
from typing import Any

from pydantic import BaseModel, Field, field_serializer

from app.core.schemas import SeverityStat


class DependencyFindingOut(BaseModel):
    """依存ライブラリ脆弱性の検知結果の出力スキーマ。"""

    repo_full_name: str = Field(description="対象リポジトリ（例: baby-feelings/baby_grow）")
    ecosystem: str = Field(description="エコシステム（例: PyPI / npm / Pub）")
    package_name: str = Field(description="パッケージ名")
    installed_version: str = Field(description="インストール済みバージョン")
    osv_id: str = Field(description="OSV ID（例: GHSA-xxxx-xxxx-xxxx）")
    severity: str | None = Field(None, description="重要度（CRITICAL/HIGH/MEDIUM/LOW）")
    cvss_score: float | None = Field(None, description="CVSS スコア")
    summary: str = Field(description="脆弱性の概要")
    fixed_versions: list[str] = Field(default_factory=list, description="修正済みバージョン")
    manifest_path: str = Field(description="検知元のロックファイルパス")
    detected_at: str = Field(description="初回検知日時（ISO 8601）")
    resolved_at: str | None = Field(None, description="解決日時（未解決なら null）")

    model_config = {"from_attributes": True}

    @field_serializer("detected_at", "resolved_at")
    def _serialize_datetime(self, value: Any) -> str | None:
        """datetime を ISO 文字列に変換する。"""
        if value is None:
            return None
        return value.isoformat() if hasattr(value, "isoformat") else str(value)

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> "DependencyFindingOut":
        """ORM オブジェクトを dict に変換し、Pydantic 検証経路へ委譲する。"""
        if hasattr(obj, "__dict__"):
            data = {
                "repo_full_name": obj.repo_full_name,
                "ecosystem": obj.ecosystem,
                "package_name": obj.package_name,
                "installed_version": obj.installed_version,
                "osv_id": obj.osv_id,
                "severity": obj.severity,
                "cvss_score": obj.cvss_score,
                "summary": obj.summary,
                "fixed_versions": obj.fixed_versions or [],
                "manifest_path": obj.manifest_path,
                "detected_at": obj.detected_at.isoformat(),
                "resolved_at": obj.resolved_at.isoformat() if obj.resolved_at else None,
            }
            return super().model_validate(data, **kwargs)
        return super().model_validate(obj, **kwargs)


class DependencyFindingListResponse(BaseModel):
    """DEPSCAN 一覧取得レスポンス（ページネーション付き）。"""

    total: int = Field(description="総件数")
    page: int = Field(description="現在のページ番号")
    per_page: int = Field(description="1ページあたりの件数")
    data: list[DependencyFindingOut] = Field(description="依存ライブラリ脆弱性一覧")


class RepoStat(BaseModel):
    """リポジトリ別件数（DEPSCAN）。"""

    repo_full_name: str
    count: int


class DependencyFindingStatsResponse(BaseModel):
    """DEPSCAN 統計エンドポイントのレスポンス。"""

    total: int = Field(description="未解決の総件数")
    repos: list[RepoStat] = Field(description="リポジトリ別件数")
    severities: list[SeverityStat] = Field(description="重要度別件数")


class DepscanCrawlResponse(BaseModel):
    """DEPSCAN 手動実行レスポンス。"""

    message: str
    new_findings: int
    resolved: int
    repos_scanned: int
