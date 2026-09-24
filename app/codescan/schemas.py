"""CODESCAN（自アプリのコード脆弱性診断）ドメインの Pydantic スキーマ定義。"""
from pydantic import BaseModel, Field

from app.core.schemas import OrmDatetimeModel, SeverityStat


class CodeFindingOut(OrmDatetimeModel):
    """コード脆弱性の検知結果の出力スキーマ。

    datetime → ISO 文字列変換は OrmDatetimeModel（app.core.schemas）が
    フィールド列挙なしで自動的に行う。
    """

    repo_full_name: str = Field(description="対象リポジトリ（例: baby-feelings/baby_grow）")
    file_path: str = Field(description="リポジトリルートからの相対パス")
    line_start: int = Field(description="該当コードの開始行")
    line_end: int = Field(description="該当コードの終了行")
    rule_id: str = Field(description="Semgrep のルールID")
    message: str = Field(description="検知内容の説明")
    severity: str = Field(description="重要度（ERROR/WARNING/INFO）")
    cwe_ids: list[str] = Field(default_factory=list, description="CWE ID一覧（無ければ空配列）")
    owasp_categories: list[str] = Field(
        default_factory=list, description="OWASP カテゴリ一覧（無ければ空配列）",
    )
    code_snippet: str = Field(description="該当コード抜粋")
    cvss_score: float | None = Field(
        None,
        description="CVSS 3.1 基本値（app.codescan.cvss_mapping によるベストエフォート推定。"
        "静的解析結果からの機械的な近似値であり、精度は保証しない）",
    )
    cvss_vector: str | None = Field(None, description="CVSS 3.1 ベクター文字列（同上）")
    tool: str = Field(description="検知したツール（semgrep / gitleaks）")
    detected_at: str = Field(description="初回検知日時（ISO 8601）")
    resolved_at: str | None = Field(None, description="解決日時（未解決なら null）")

    model_config = {"from_attributes": True}


class CodeFindingListResponse(BaseModel):
    """CODESCAN 一覧取得レスポンス（ページネーション付き）。"""

    total: int = Field(description="総件数")
    page: int = Field(description="現在のページ番号")
    per_page: int = Field(description="1ページあたりの件数")
    data: list[CodeFindingOut] = Field(description="コード脆弱性検知結果一覧")


class RepoStat(BaseModel):
    """リポジトリ別件数（CODESCAN）。"""

    repo_full_name: str
    count: int


class CodeFindingStatsResponse(BaseModel):
    """CODESCAN 統計エンドポイントのレスポンス。"""

    total: int = Field(description="未解決の総件数")
    repos: list[RepoStat] = Field(description="リポジトリ別件数")
    severities: list[SeverityStat] = Field(description="重要度別件数")


class CodescanCrawlResponse(BaseModel):
    """CODESCAN 手動実行レスポンス。"""

    message: str
