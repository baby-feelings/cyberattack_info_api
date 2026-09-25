"""GitHub REST API 呼び出しの共通部分（DEPSCAN/CODESCAN/DEPSOPS で共有）。

3つのドメイン（`app.depscan.github_client` / `app.codescan.github_client` /
`app.depsops.github_client`）はそれぞれ異なる目的（ロックファイル収集・
tarball取得・PR運用）で GitHub API を呼ぶため、高レベルの関数群は意図的に
分離している（ドメインごとの責務が異なるため、まとめると低凝集になる）。
ただし認証ヘッダーの組み立てと API ベース URL は3ドメインで完全に同一であり、
コピペで揃え続けるのは事故の元（ヘッダー仕様変更時の修正漏れ）になるため、
ここに一箇所だけ切り出す（DRY原則）。
"""

GITHUB_API_BASE = "https://api.github.com"


def github_headers(token: str) -> dict[str, str]:
    """GitHub REST API 呼び出し用の認証ヘッダーを組み立てる。"""
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
