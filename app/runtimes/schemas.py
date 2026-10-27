"""言語・実行環境のバージョン監視（RUNTIME）の Pydantic スキーマ。"""
from pydantic import BaseModel, Field


class RepoRuntimeOut(BaseModel):
    """リポジトリが使っている言語・実行環境1件と、その状態。"""

    repo_full_name: str = Field(description="使っているリポジトリ（例: baby-feelings/baby_grow）")
    runtime: str = Field(description="言語・実行環境（python / nodejs / flutter / dart）")
    runtime_label: str = Field(description="表示名（Python / Node.js / Flutter / Dart）")
    cycle: str = Field(description="使っているバージョン系列（例: 3.13 / 24）")
    source_path: str = Field(description="由来の設定ファイルのパス")
    pinned: bool = Field(
        description="版を固定しているか（false は「この版以上」のような下限の指定）",
    )
    state: str = Field(
        description="状態: eol（サポート終了）/ eol_soon（期限間近）"
        "/ update_available（新しい系列あり）/ latest（最新）"
        "/ reference（下限の指定のため参考）/ unknown（リリース情報なし）",
    )
    latest_version: str | None = Field(None, description="使っている系列の最新版")
    recommended_cycle: str | None = Field(None, description="推奨の系列（サポート中の最新）")
    recommended_version: str | None = Field(None, description="推奨の系列の最新版")
    eol_date: str | None = Field(None, description="サポート終了日（YYYY-MM-DD）")
    days_to_eol: int | None = Field(None, description="サポート終了までの日数（過ぎていれば負）")


class RepoRuntimeListResponse(BaseModel):
    """言語・実行環境の一覧レスポンス。"""

    total: int = Field(description="総件数")
    data: list[RepoRuntimeOut] = Field(description="対応が急ぐものが先頭")


class RepoRuntimeRepoStat(BaseModel):
    """リポジトリごとの件数（閲覧画面の、左のリポジトリ一覧用）。"""

    repo_full_name: str
    total: int = Field(description="検出した言語・実行環境の数")
    needs_action: int = Field(description="うち、対応が必要な数（期限切れ・期限間近・更新あり）")


class RepoRuntimeRepoListResponse(BaseModel):
    """リポジトリ別の件数（対応が必要なリポジトリが先頭）。"""

    repos: list[RepoRuntimeRepoStat]


class RuntimeReleaseOut(BaseModel):
    """バージョン系列1つ分の、最新版とサポート期限。"""

    runtime: str
    runtime_label: str
    cycle: str
    latest_version: str
    release_date: str | None = None
    eol_date: str | None = None
    is_eol: bool
    is_lts: bool
    recommended: bool = Field(description="推奨の系列か（サポート中の最新。Node.js は LTS のみ）")


class RuntimeReleaseListResponse(BaseModel):
    """最新版・サポート期限の一覧（言語ごとに新しい系列が先頭）。"""

    data: list[RuntimeReleaseOut]


class RuntimeCrawlResponse(BaseModel):
    """手動実行（POST /admin/runtime-crawl）のレスポンス。"""

    message: str
