"""検知の例外 API の入出力スキーマ。"""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.finding_exceptions.models import STATUS_ACCEPTED


class FindingExceptionIn(BaseModel):
    """例外の登録（受容・誤検知・影響なし）。同じ検知に有効な例外があれば、内容を更新する。"""

    kind: Literal["dependency", "code"] = Field(
        description="検知の種別（dependency=DEPSCAN・code=CODESCAN）",
    )
    repo_full_name: str = Field(description="リポジトリ（owner/name）", max_length=255)
    finding_key: str = Field(
        description="検知の同一性キー（一覧の `exception_key`）", max_length=1000,
    )
    status: Literal["accepted", "false_positive", "not_affected"] = Field(
        description="accepted=受容（期限つき）/ false_positive=誤検知 / not_affected=影響なし",
    )
    reason: str = Field(min_length=1, max_length=2000, description="理由（必須）")
    expires_at: datetime | None = Field(
        None, description="期限。受容は必須（現在より後で、EXCEPTION_MAX_DAYS 日以内）",
    )

    @field_validator("reason")
    @classmethod
    def _strip_reason(cls, value: str) -> str:
        """空白だけの理由は認めない。"""
        stripped = value.strip()
        if not stripped:
            raise ValueError("理由を入力してください")
        return stripped

    def requires_expiry(self) -> bool:
        """期限が必須か（受容のみ。誤検知・影響なしは、期限なしでも良い）。"""
        return self.status == STATUS_ACCEPTED


class FindingExceptionSummary(BaseModel):
    """検知の一覧に埋め込む、有効な例外の要約。"""

    model_config = ConfigDict(from_attributes=True)

    id: int
    status: str = Field(description="accepted / false_positive / not_affected")
    reason: str
    expires_at: datetime | None
    approver: str


class FindingExceptionOut(BaseModel):
    """検知の例外。"""

    model_config = ConfigDict(from_attributes=True)

    id: int
    kind: str
    repo_full_name: str
    finding_key: str
    status: str = Field(description="accepted / false_positive / not_affected")
    reason: str
    expires_at: datetime | None
    approver: str = Field(description="承認者（登録した GitHub ユーザー）")
    ended_at: datetime | None = Field(description="終了した日時。有効な間は null")
    ended_reason: str | None = Field(
        description="終了の理由（expired=期限切れ / fix_available=修正版の公開 / revoked=解除）",
    )
    created_at: datetime


class FindingExceptionListResponse(BaseModel):
    """例外の一覧。"""

    total: int
    data: list[FindingExceptionOut]
