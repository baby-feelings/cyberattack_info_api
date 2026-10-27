"""DEPSCAN（依存ライブラリ脆弱性スキャン）ドメインの Pydantic スキーマ定義。"""
from typing import Literal

from pydantic import BaseModel, Field

from app.core.schemas import OrmDatetimeModel, SeverityStat


class RepoAssetContextOut(OrmDatetimeModel):
    """リポジトリ単位の資産コンテキストの出力スキーマ（Issue #131）。"""

    repo_full_name: str = Field(description="対象リポジトリ（例: baby-feelings/baby_grow）")
    is_production: bool = Field(description="本番デプロイ済みか")
    is_internet_facing: bool = Field(description="インターネットに公開されたサービスか")
    importance: Literal["high", "medium", "low"] | None = Field(
        None, description="資産重要度（high/medium/low）。未評価なら null",
    )
    updated_at: str = Field(description="最終更新日時（ISO 8601）")

    model_config = {"from_attributes": True}


class RepoAssetContextIn(BaseModel):
    """リポジトリ単位の資産コンテキストの設定リクエスト
    （PUT /admin/depscan/assets/{owner}/{repo}）。
    """

    is_production: bool = Field(False, description="本番デプロイ済みか")
    is_internet_facing: bool = Field(False, description="インターネットに公開されたサービスか")
    importance: Literal["high", "medium", "low"] | None = Field(
        None, description="資産重要度（high/medium/low）。未評価なら null",
    )


class RepoAssetContextListResponse(BaseModel):
    """資産コンテキスト一覧取得レスポンス。"""

    data: list[RepoAssetContextOut] = Field(description="設定済みの資産コンテキスト一覧")


class DependencyFindingOut(OrmDatetimeModel):
    """依存ライブラリ脆弱性の検知結果の出力スキーマ。

    datetime → ISO 文字列変換は OrmDatetimeModel（app.core.schemas）が
    フィールド列挙なしで自動的に行う。
    """

    repo_full_name: str = Field(description="対象リポジトリ（例: baby-feelings/baby_grow）")
    ecosystem: str = Field(description="エコシステム（例: PyPI / npm / Pub）")
    package_name: str = Field(description="パッケージ名")
    installed_version: str = Field(description="インストール済みバージョン")
    osv_id: str = Field(description="OSV ID（例: GHSA-xxxx-xxxx-xxxx）")
    severity: str | None = Field(None, description="重要度（CRITICAL/HIGH/MEDIUM/LOW）")
    cvss_score: float | None = Field(None, description="CVSS スコア")
    summary: str = Field(description="脆弱性の概要")
    fixed_versions: list[str] = Field(default_factory=list, description="修正済みバージョン")
    cve_ids: list[str] = Field(
        default_factory=list,
        description="OSVエントリのaliasesから抽出したCVE ID一覧（無ければ空配列）",
    )
    # cve_ids/priority_reasons と同様、DependencyFindingには存在しない計算フィールド
    # （list_depscan が model_copy で必ず上書きする）。Issue #133: 他のSBOM/SCA
    # ツールとの相互運用性のため、パッケージ識別にpurl（Package URL）を使う
    purl: str | None = Field(
        default=None,
        description="パッケージURL（例: pkg:pypi/cryptography@3.4.7）。"
        "app.depscan.sbom.build_purlによるbest-effort生成",
    )
    manifest_path: str = Field(description="検知元のロックファイルパス")
    reachability: str | None = Field(
        None,
        description="到達可能性（import レベルのヒューリスティック判定）: "
        "reachable（importを確認） / unreachable（該当拡張子のソースはあるがimportなし） / "
        "unknown（判定不能）",
    )
    repo_visibility: str | None = Field(
        None,
        description="対象リポジトリの公開範囲（GitHub APIの\"private\"フィールドから自動取得。"
        "public/private。旧レコードで未取得の場合は null）",
    )
    asset_context: RepoAssetContextOut | None = Field(
        None,
        description="対象リポジトリの資産コンテキスト（本番デプロイ済みか・インターネット公開か・"
        "重要度。PUT /admin/depscan/assets/{owner}/{repo} で手動設定。未設定なら null）",
    )
    # OrmDatetimeModel.model_validate は宣言済みフィールドをORMオブジェクトから
    # getattr(obj, name, None) で取得するため、DependencyFindingには存在しない
    # このフィールドは常に None を経由する（型を list[str] | None にする必要がある
    # 理由）。実際の値は list_depscan が model_copy で必ず上書きするため、
    # クライアントに返る時点では常にリストになる
    priority_reasons: list[str] | None = Field(
        default=None,
        description="優先度判定に寄与した要因の機械可読な一覧（Issue #135）。"
        "kev_listed（CISA KEV掲載）/ epss_high（EPSSスコア高） / reachable（到達可能）/ "
        "public_repo（公開リポジトリ）/ internet_facing_asset（インターネット公開資産）/ "
        "production_asset（本番資産）/ high_importance_asset（重要度high）のいずれか0件以上",
    )
    detected_at: str = Field(description="初回検知日時（ISO 8601）")
    resolved_at: str | None = Field(None, description="解決日時（未解決なら null）")

    model_config = {"from_attributes": True}


class DependencyFindingListResponse(BaseModel):
    """DEPSCAN 一覧取得レスポンス（ページネーション付き）。"""

    total: int = Field(description="総件数")
    page: int = Field(description="現在のページ番号")
    per_page: int = Field(description="1ページあたりの件数")
    data: list[DependencyFindingOut] = Field(description="依存ライブラリ脆弱性一覧")


class RepoDependencyOut(OrmDatetimeModel):
    """リポジトリが使っている依存パッケージ1件（横断検索の結果）。"""

    repo_full_name: str = Field(description="使っているリポジトリ（例: baby-feelings/baby_grow）")
    ecosystem: str = Field(description="エコシステム（PyPI / npm / Pub など）")
    package_name: str
    version: str = Field(description="ロックファイルに記載されていたバージョン")
    manifest_path: str = Field(description="由来のロックファイルのパス")
    scanned_at: str = Field(description="最後にスキャンで確認した日時（ISO 8601）")
    # RepoDependency には存在しない計算フィールド（DependencyFindingOut.purl と同様）。
    # OrmDatetimeModel は ORM に無い属性を None として渡すため、None を許容する
    purl: str | None = Field(None, description="Package URL（purl）")
    open_vulnerabilities: int | None = Field(
        None, description="この版に対する、未解決の脆弱性の検知件数（0なら検知なし）",
    )

    model_config = {"from_attributes": True}


class RepoDependencyRepoStat(BaseModel):
    """リポジトリごとの、使っている依存の数（依存パッケージの閲覧画面の、左のリポジトリ一覧用）。"""

    repo_full_name: str
    total: int = Field(description="使っている依存の数")
    vulnerable: int = Field(description="うち、未解決の検知がある依存の数")


class RepoDependencyRepoListResponse(BaseModel):
    """リポジトリ別の依存の数（対応が必要なリポジトリが先頭）。"""

    repos: list[RepoDependencyRepoStat]


class RepoDependencyListResponse(BaseModel):
    """依存パッケージの横断検索レスポンス（ページネーション付き）。"""

    total: int = Field(description="総件数")
    page: int = Field(description="現在のページ番号")
    per_page: int = Field(description="1ページあたりの件数")
    data: list[RepoDependencyOut] = Field(description="該当した依存の一覧")


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
