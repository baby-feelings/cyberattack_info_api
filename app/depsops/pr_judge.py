"""DEPSOPS の PR 判定（自動マージするか・要確認にするか）を担当するモジュール。

Dependabot が作成した PR を、バージョン更新の種別・CI 有無・マージ可否から判定し、
安全なものだけを自動マージする。判定の副作用（マージ・リベース依頼）はここに閉じ込め、
履歴の永続化（`pr_log_repository`）・走査の組み立て（`runner`）とは分離する。
"""
import re
from typing import Any

from app.depsops.classify import classify_bump
from app.depsops.github_client import (
    get_pull_request,
    merge_pull_request,
    request_rebase,
)


def matches_security_alert(title: str, alert_package_names: set[str] | None) -> bool | None:
    """PRタイトルが、Open な Dependabot alert のいずれかの対象パッケージ名を
    含んでいるかをヒューリスティックに判定する。

    Returns:
        True: 一致する alert あり（セキュリティ更新の可能性が高い）
        False: alert 取得は成功したが一致なし（通常のバージョン更新）
        None: alert 自体を取得できなかった（判定不能。GITHUB_TOKEN に
            Dependabot alerts: Read-only 権限が無い場合等）

    Note:
        パッケージ名の単純な部分文字列一致（単語境界のみ考慮）のため、
        あるパッケージ名が別のパッケージ名の接頭辞になっているケース等で
        誤判定しうる（あくまで参考情報。判定基準は GitHub の Dependabot alert
        そのものであり、この関数は照合のヒューリスティックに過ぎない）。
    """
    if alert_package_names is None:
        return None
    lowered_title = title.lower()
    return any(
        re.search(rf"\b{re.escape(pkg.lower())}\b", lowered_title)
        for pkg in alert_package_names
    )


_COMPATIBILITY_BADGE_PATTERN = re.compile(
    r"!\[Dependabot compatibility score\]\((https://dependabot-badges\.githubapp\.com/[^)\s]+)\)",
)


def extract_compatibility_badge_url(body: str | None) -> str | None:
    """PR本文から Dependabot の Compatibility score バッジ画像URLを抽出する。

    exact version bump のPR（"Bump X from A to B"）にのみ Dependabot が
    埋め込む（範囲指定の requirement 更新PR等には存在しない）。
    """
    if not body:
        return None
    match = _COMPATIBILITY_BADGE_PATTERN.search(body)
    return match.group(1) if match else None


def pr_summary(
    full_name: str, pr: dict[str, Any], is_security_update: bool | None,
    compatibility_badge_url: str | None = None,
) -> dict[str, Any]:
    return {
        "repo_full_name": full_name,
        "pr_number": pr["number"],
        "title": pr["title"],
        "is_security_update": is_security_update,
        "compatibility_badge_url": compatibility_badge_url,
    }


class PrJudge:
    """1リポジトリ分の Dependabot PR を判定・処理する（リポジトリ固有の文脈を保持）。

    所有者・リポジトリ名・トークン・CI 有無・Dependabot alert のパッケージ名集合は、
    同じリポジトリの全 PR で共通のためインスタンスに持たせ、PR ごとの `judge` は
    PR だけを受け取る（以前は 7 引数の関数だった）。
    """

    def __init__(
        self,
        full_name: str,
        owner: str,
        repo: str,
        token: str,
        *,
        has_ci: bool,
        alert_package_names: set[str] | None = None,
    ) -> None:
        self._full_name = full_name
        self._owner = owner
        self._repo = repo
        self._token = token
        self._has_ci = has_ci
        # 対象リポジトリの Open な Dependabot alert のパッケージ名集合
        # （`matches_security_alert` 参照）。取得できなかった場合は None。
        self._alert_package_names = alert_package_names

    def judge(self, pr: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
        """1件の PR を判定・処理する。

        Returns:
            (action, item) のタプル。action は "merged" / "flagged" / "skipped"。
            "merged"/"flagged" の場合 item は Slack 通知用の辞書（"flagged" のみ "reason" 付き）。
        """
        owner, repo, token = self._owner, self._repo, self._token
        number = pr["number"]
        bump = classify_bump(pr["title"])
        is_security_update = matches_security_alert(pr["title"], self._alert_package_names)

        detail = get_pull_request(owner, repo, number, token)
        mergeable_state = detail.get("mergeable_state")
        compatibility_badge_url = extract_compatibility_badge_url(detail.get("body"))

        if mergeable_state == "dirty":
            request_rebase(owner, repo, number, token)
            item = pr_summary(self._full_name, pr, is_security_update, compatibility_badge_url)
            item["reason"] = "コンフリクトのためリベースを依頼"
            return "flagged", item

        reason = None
        if not self._has_ci:
            reason = "CI未設定のリポジトリ"
        elif bump == "major":
            reason = "メジャーバージョンアップ"
        elif bump == "unknown":
            reason = "バージョン判定不可（複数パッケージのグループ更新等）"
        elif mergeable_state != "clean":
            reason = f"マージ可否が不明確（mergeable_state={mergeable_state}）"

        if reason is not None:
            item = pr_summary(self._full_name, pr, is_security_update, compatibility_badge_url)
            item["reason"] = reason
            return "flagged", item

        merge_pull_request(owner, repo, number, token)
        return "merged", pr_summary(
            self._full_name, pr, is_security_update, compatibility_badge_url,
        )
