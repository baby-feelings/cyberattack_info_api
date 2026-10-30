"""コミットの判定（純粋なロジック。GitHub API への問い合わせは `crawler`）。

【重要・セキュリティ】通知に載せるのは、危険な内容の「行そのもの」の短い抜粋のみ（シークレットの参照
`secrets.NAME` は名前であり、値ではない）。ワークフローの全文・差分の全体は載せない。
"""
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

# ワークフローのパス
WORKFLOW_PREFIX = ".github/workflows/"

# 追加された行に含まれると危険な内容: (ルール名, 説明, 正規表現)
_RISKY_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("secrets-reference", "シークレットの参照（`secrets.*`）を追加",
     re.compile(r"\$\{\{\s*secrets\.")),
    ("external-upload", "外部 URL への送信（`curl`・`wget`）を追加",
     re.compile(r"\b(curl|wget)\b[^\n]*https?://", re.IGNORECASE)),
    ("pull-request-target", "`pull_request_target`（外部の PR で、シークレットが使われうる）を追加",
     re.compile(r"\bpull_request_target\b")),
    ("write-all", "権限 `write-all` を追加",
     re.compile(r"permissions\s*:\s*write-all", re.IGNORECASE)),
    ("encoded-exec", "エンコードした内容の実行（`base64 -d` 等）を追加",
     re.compile(r"base64\s+(-d|--decode)", re.IGNORECASE)),
)
# 抜粋する行の最大文字数
_MAX_EXCERPT = 160


@dataclass(frozen=True)
class RiskyChange:
    """ワークフローに追加された、危険な行。"""

    file: str
    rule: str
    description: str
    excerpt: str


def added_lines(patch: str) -> list[str]:
    """差分（patch）の、追加された行（先頭の `+` を除く）。"""
    return [
        line[1:] for line in patch.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]


def find_risky_changes(files: Iterable[dict[str, Any]]) -> list[RiskyChange]:
    """コミットの変更ファイルのうち、ワークフローに追加された危険な行を見つける。"""
    found: list[RiskyChange] = []
    for item in files:
        name = str(item.get("filename", ""))
        if not name.startswith(WORKFLOW_PREFIX):
            continue
        for line in added_lines(str(item.get("patch") or "")):
            for rule, description, pattern in _RISKY_PATTERNS:
                if pattern.search(line):
                    found.append(RiskyChange(name, rule, description, line.strip()[:_MAX_EXCERPT]))
    return found


def trusted_logins(admin: str, extra: str) -> set[str]:
    """信頼するコミッター（管理者・設定で追加したユーザー・自動化のボット）。小文字。"""
    names = {admin, "dependabot[bot]", "github-actions[bot]"}
    names.update(n.strip() for n in extra.split(",") if n.strip())
    return {n.lower() for n in names}


def author_login(commit: dict[str, Any]) -> str | None:
    """コミットの作者の GitHub ログイン名（GitHub のアカウントに紐づかないコミットは None）。"""
    author = commit.get("author")
    return str(author["login"]) if author and author.get("login") else None


def is_verified(commit: dict[str, Any]) -> bool:
    """コミットに、有効な署名があるか。"""
    return bool(((commit.get("commit") or {}).get("verification") or {}).get("verified"))


def is_trusted(
    commit: dict[str, Any], trusted: set[str], *, require_signature: bool = False,
) -> bool:
    """信頼するコミッターの変更か。アカウントに紐づかない（作者が不明の）コミットは、信頼しない。

    【限界】作者・コミッターの名前は、コミットのメール欄から決まるため、他人のメールを名乗れば、
    なりすませる（GitHub は、そのアカウントのコミットとして表示する）。確実に防げるのは、署名だけ。
    `require_signature=True` にすると、信頼するユーザーでも、署名がないコミットは信頼しない
    （自分のコミットを、すべて署名している場合に使う。既定は、通知が増えすぎないよう、False）。
    """
    login = author_login(commit)
    if login is None or login.lower() not in trusted:
        return False
    return is_verified(commit) or not require_signature


def touches_workflow(files: Iterable[dict[str, Any]]) -> bool:
    """コミットの変更ファイルに、ワークフローが含まれるか。"""
    return any(str(f.get("filename", "")).startswith(WORKFLOW_PREFIX) for f in files)


def commit_title(commit: dict[str, Any]) -> str:
    """コミットメッセージの1行目（長すぎる場合は短くする）。"""
    message = str((commit.get("commit") or {}).get("message", ""))
    return (message.splitlines() or [""])[0][:100]
