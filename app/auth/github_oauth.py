"""GitHub OAuth（Web Application Flow）クライアント。

DEPSCAN ダッシュボードへのログインに使用する。認可コードをアクセストークンに
交換し、そのトークンでログインユーザーの GitHub ユーザー名を取得する。
app.depscan.github_client（サービスレベル PAT を使うロックファイル収集用）とは
別モジュール（OAuth 認可フローと PAT ベースの API 呼び出しでは責務が異なるため）。
"""
import httpx

_GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
_GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
_GITHUB_API_BASE = "https://api.github.com"
_TIMEOUT = 15.0

# private リポジトリを読み取るには repo スコープが必要（GitHub OAuth App は
# fine-grained PAT と異なり読み取り専用の粒度指定ができない）
_SCOPE = "repo"


def build_authorize_url(client_id: str, redirect_uri: str, state: str) -> str:
    """GitHub の認可画面へのリダイレクト先 URL を組み立てる。"""
    with httpx.Client() as client:
        req = client.build_request(
            "GET", _GITHUB_AUTHORIZE_URL,
            params={
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": _SCOPE,
                "state": state,
            },
        )
    return str(req.url)


def exchange_code_for_token(
    client_id: str, client_secret: str, code: str, redirect_uri: str,
) -> str:
    """認可コードをアクセストークンに交換する。"""
    with httpx.Client(timeout=_TIMEOUT) as client:
        resp = client.post(
            _GITHUB_TOKEN_URL,
            headers={"Accept": "application/json"},
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "code": code,
                "redirect_uri": redirect_uri,
            },
        )
        resp.raise_for_status()
    data = resp.json()
    token = data.get("access_token")
    if not token:
        raise ValueError(f"GitHub OAuth token exchange failed: {data}")
    return str(token)


def get_authenticated_user_login(access_token: str) -> str:
    """アクセストークンからログインユーザーの GitHub ユーザー名（login）を取得する。"""
    with httpx.Client(timeout=_TIMEOUT) as client:
        resp = client.get(
            f"{_GITHUB_API_BASE}/user",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github+json",
            },
        )
        resp.raise_for_status()
    return str(resp.json()["login"])
