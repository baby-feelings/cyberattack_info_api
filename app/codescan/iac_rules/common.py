"""診断ルールの共通部（重要度・`IacIssue`・スニペット・シークレット値の判定）。

【重要・セキュリティ】シークレットの値そのものは、検知結果（スニペット・メッセージ）に残さない
（診断が、認証情報を漏らす側になってしまうため。gitleaks と同じ方針）。キー名だけを示す。
"""
import re
from dataclasses import dataclass

# 重要度（CODESCAN の重要度と同じ語）
ERROR = "ERROR"
WARNING = "WARNING"
INFO = "INFO"


@dataclass(frozen=True)
class IacIssue:
    """診断で見つけた不備1件（1行に紐づく）。"""

    line: int               # 1始まり
    rule: str               # `iac:` を除いたルール名（例: firestore-open-write）
    severity: str
    message: str            # 何が問題か＋「対策:」（修正方法）
    snippet: str            # 該当行（シークレットの値は伏せる）
    cwe: str | None = None  # 例: CWE-250


# 認証情報らしい名前（環境変数・ARG のキー名）
_SECRET_NAME = re.compile(
    r"(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIAL)", re.IGNORECASE,
)
_MAX_SNIPPET = 200


def _snippet(line: str) -> str:
    return line.strip()[:_MAX_SNIPPET]


# 明らかなダミー値（診断用・サンプル）。認証情報の直書きとは扱わない（誤検知を減らす）
_PLACEHOLDER = re.compile(
    r"dummy|example|changeme|change-me|placeholder|your[-_]|xxx|<.*>", re.IGNORECASE,
)


def _is_literal_value(value: str) -> bool:
    """値が、直書きのリテラルか。

    空・変数の参照（`$VAR`・`${VAR}`）・未設定・明らかなダミー値は、直書きの認証情報ではない。
    """
    cleaned = value.strip().strip("\"'")
    return bool(cleaned) and not cleaned.startswith("$") and not _PLACEHOLDER.search(cleaned)
