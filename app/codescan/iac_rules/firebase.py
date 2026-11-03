"""Firebase（Firestore・Storage・Realtime Database のルール・`firebase.json`）の診断。
"""
import re

from app.codescan.iac_rules.common import (
    ERROR,
    WARNING,
    IacIssue,
    _snippet,
)

# `allow read, write: if <条件>;`（条件は複数行にまたがりうる。`;` まで）
_ALLOW = re.compile(
    r"allow\s+(?P<ops>[a-z,\s]+?)\s*(?::\s*if\s+(?P<cond>[^;]*?))?\s*;", re.IGNORECASE | re.DOTALL,
)
_WRITE_OPS = {"write", "create", "update", "delete"}
_TIME_LIMITED = re.compile(r"request\.time\s*<\s*timestamp\.date\(", re.IGNORECASE)
_ANY_SIGNED_IN = re.compile(r"^request\.auth\s*!=\s*null$")


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def check_firebase_rules(text: str) -> list[IacIssue]:
    """`firestore.rules`・`storage.rules` の過剰な公開を検知する。"""
    issues: list[IacIssue] = []
    for match in _ALLOW.finditer(text):
        ops = {op.strip().lower() for op in match.group("ops").split(",") if op.strip()}
        cond = " ".join((match.group("cond") or "").split())
        line = _line_of(text, match.start())
        snippet = _snippet(" ".join(match.group(0).split()))
        writes = bool(ops & _WRITE_OPS)

        if cond.lower() == "true":
            if writes:
                issues.append(IacIssue(
                    line, "firebase-open-write", ERROR,
                    "認証なしで、誰でも書き込み・削除できます（`if true`）。"
                    " 対策: `request.auth != null` に加え、所有者の確認"
                    "（例: `request.auth.uid == userId`）を条件にする。",
                    snippet, "CWE-862",
                ))
            else:
                issues.append(IacIssue(
                    line, "firebase-open-read", WARNING,
                    "認証なしで、誰でも読み取れます（`if true`）。意図した公開か確認してください。"
                    " 対策: 公開が不要なら `request.auth != null` と所有者の確認を条件にする。",
                    snippet, "CWE-862",
                ))
        elif _TIME_LIMITED.search(cond):
            issues.append(IacIssue(
                line, "firebase-test-mode", ERROR if writes else WARNING,
                "期限つきの公開（テストモードのルール）です。期限まで、誰でも読み書きできます。"
                " 対策: 本番では、認証と所有者の確認を条件にしたルールに置き換える。",
                snippet, "CWE-862",
            ))
        elif writes and _ANY_SIGNED_IN.match(cond):
            issues.append(IacIssue(
                line, "firebase-any-user-write", WARNING,
                "ログインしていれば、誰でも（他人のデータにも）書き込めます。"
                " 対策: 所有者の確認（例: `request.auth.uid == resource.data.ownerId`）を加える。",
                snippet, "CWE-285",
            ))
    return issues


# Realtime Database のルール（JSON）: `".read": true` / `".write": true`
_RTDB_OPEN = re.compile(r'"\.(?P<kind>read|write)"\s*:\s*(?P<value>true|"true")', re.IGNORECASE)


def check_realtime_db_rules(text: str) -> list[IacIssue]:
    """`database.rules.json`（Realtime Database）の、認証なしの読み書きを検知する。"""
    issues: list[IacIssue] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        match = _RTDB_OPEN.search(raw)
        if not match:
            continue
        writes = match.group("kind").lower() == "write"
        issues.append(IacIssue(
            number, "firebase-open-write" if writes else "firebase-open-read",
            ERROR if writes else WARNING,
            f"認証なしで、誰でも{'書き込み' if writes else '読み取り'}できます"
            f"（`.{match.group('kind')}: true`）。"
            " 対策: `auth != null` に加え、所有者の確認（例: `auth.uid === $uid`）を条件にする。",
            _snippet(raw), "CWE-862",
        ))
    return issues


# ---------------------------------------------------------------------------
# firebase.json
# ---------------------------------------------------------------------------

_HOSTING_PUBLIC_ROOT = re.compile(r'"public"\s*:\s*"(?:\.|\./?|)"')


def check_firebase_json(text: str) -> list[IacIssue]:
    """`firebase.json` の、リポジトリ全体の公開（`"public": "."`）を検知する。"""
    issues: list[IacIssue] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        if _HOSTING_PUBLIC_ROOT.search(raw):
            issues.append(IacIssue(
                number, "firebase-hosting-public-root", ERROR,
                "Hosting の公開ディレクトリがリポジトリのルートです。ソースコードや設定ファイル"
                "（`.env`・`firebase.json` 等）まで公開されるおそれがあります。"
                " 対策: ビルド成果物のディレクトリ（例: `build/web`・`dist`）だけを指定する。",
                _snippet(raw), "CWE-538",
            ))
    return issues
