"""GitHub のログイン戻り（コールバック）を、別の機能（MCP の OAuth 等）が引き受けるための登録口。

`/auth/github/callback` は、ダッシュボードのログインと、MCP サーバーの OAuth 2.1 ログインの両方に
使われる（GitHub の OAuth App のコールバック URL を1つで済ませるため）。`auth` が MCP の実装を
直接 import すると依存が循環するため、**引き受ける側が自分を登録する**形にする
（`auth` は `mcp_server` を知らず、`mcp_server` が `auth` に登録する。依存の向きは一方向）。

`state` を見て、登録された流れのどれかのものなら、その流れに処理を任せる。どれでもなければ
通常のダッシュボードのログイン。
"""
from collections.abc import Callable
from dataclasses import dataclass

from fastapi import Request
from fastapi.responses import Response
from sqlalchemy.orm import Session


@dataclass(frozen=True)
class ExternalLoginFlow:
    """GitHub ログインの戻りを引き受ける流れ。

    name: 登録名（同じ名前で再登録すると置き換わる）
    decode_state: `state` がこの流れのものなら、流れ側の識別子（リクエストID等）を、違えば None
    complete: GitHub の認可コードを受け取って本人確認を済ませ、ブラウザへ返すレスポンスを作る
    """

    name: str
    decode_state: Callable[[str], str | None]
    complete: Callable[[Session, str, str, Request], Response]


_flows: dict[str, ExternalLoginFlow] = {}


def register(flow: ExternalLoginFlow) -> None:
    """流れを登録する（同じ名前なら置き換える。マウントを繰り返しても重複しない）。"""
    _flows[flow.name] = flow


def find(state: str) -> tuple[ExternalLoginFlow, str] | None:
    """`state` を引き受ける流れと、その識別子を返す。どれのものでもなければ None。"""
    for flow in _flows.values():
        identifier = flow.decode_state(state)
        if identifier is not None:
            return flow, identifier
    return None
