"""DEPSOPS（Dependabot PR 自動運用）ドメインの Pydantic スキーマ定義。"""
from pydantic import BaseModel, Field

from app.core.schemas import OrmDatetimeModel


class DependabotPrLogOut(OrmDatetimeModel):
    """DEPSOPS が判定した Dependabot PR 1件分の出力スキーマ。

    datetime → ISO 文字列変換は OrmDatetimeModel（app.core.schemas）が
    フィールド列挙なしで自動的に行う。
    """

    repo_full_name: str = Field(description="対象リポジトリ（例: baby-feelings/baby_grow）")
    pr_number: int = Field(description="Dependabot PR 番号")
    title: str = Field(description="PR タイトル")
    action: str = Field(description="判定結果（merged: 自動マージ済み / flagged: 要確認）")
    reason: str | None = Field(
        None, description="action=flagged の場合の理由（メジャーバージョンアップ等）"
    )
    is_security_update: bool | None = Field(
        None,
        description="セキュリティ更新（GitHub Dependabot alertの対象パッケージと一致）の"
        "ヒューリスティック判定。true=セキュリティ更新の可能性が高い / "
        "false=通常のバージョン更新 / null=判定不能",
    )
    compatibility_badge_url: str | None = Field(
        None,
        description="Dependabot が PR 本文に埋め込む Compatibility score バッジ画像のURL。"
        "exact version bump のPRにのみ存在し、範囲指定の requirement 更新PR等は null",
    )
    processed_at: str = Field(description="判定を行った DEPSOPS 実行日時（ISO 8601）")

    model_config = {"from_attributes": True}


class DependabotPrLogListResponse(BaseModel):
    """DEPSOPS PR 履歴一覧取得レスポンス（ページネーション付き）。"""

    total: int = Field(description="総件数")
    page: int = Field(description="現在のページ番号")
    per_page: int = Field(description="1ページあたりの件数")
    data: list[DependabotPrLogOut] = Field(description="PR 履歴一覧")
