# リモート MCP サーバー

AI エージェント（Claude Code など）から、このサービスの脆弱性情報を **MCP ツール**として使うための
リモートサーバー。エンドポイントは `https://<API のドメイン>/mcp`（Streamable HTTP）。
REST API の読み取り系 GET をツール化した薄い層で、REST と挙動が一致する。

## 見える範囲（認証の種類）

| 認証 | 方法 | 見えるもの |
|------|------|-----------|
| 運用者（admin） | `X-API-KEY: <API_KEY>` | すべて |
| 公開用の鍵（public） | `X-API-KEY: <PUBLIC_API_KEY>` | KEV / OSV / JVN の公開情報のみ |
| ユーザー（user） | `Authorization: Bearer <MCPトークン>` | 公開情報 + **自分が所有するリポジトリ**の DEPSCAN / CODESCAN |

- **他の人に自分のリポジトリを見せない**: DEPSCAN / CODESCAN は、MCP トークンに紐づく GitHub ユーザーが
  所有するリポジトリ（`<ユーザー名>/...`）だけが返る。他人のリポジトリを `repo` で指定すると拒否される。
  応答に他人のリポジトリが混じった場合は、応答を返さず失敗させる（fail closed）
- `PUBLIC_API_KEY` はダッシュボードの JS に含まれる前提の鍵のため、これだけでは DEPSCAN / CODESCAN は見えない
- 管理系（`/admin/*`）や書き込み系はツール化していない（読み取り専用）

## MCP トークンの発行

1. ダッシュボードを開き、メニューの「設定」から GitHub でログインする
2. 「MCP トークン」欄で「MCPトークンを発行」を押す
3. 表示された登録コマンドをコピーして実行する（トークンは再表示できない）

```bash
claude mcp add --transport http cyberattack-info https://<API のドメイン>/mcp \
  --header "Authorization: Bearer <MCPトークン>"
```

- 有効期限は発行時に **7 / 30 / 90 日**から選ぶ（既定 30 日）。切れたら再発行する
- トークンは設定ファイルに保存される。**他の人に共有しない**（共有すると、その人があなたのリポジトリの検知結果を見られる）
- **個別に失効できる**: 設定画面の「発行済みのトークン」に一覧（状態・期限・最終使用日）が出る。漏えいが
  疑われるトークンは「失効」を押すと、以後そのトークンでの接続は 401 になる（他のトークンは影響を受けない）
- 有効なトークンは 1 ユーザー 10 個まで（超えると発行できない。不要なものを失効する）
- 最終手段として `SESSION_SECRET_KEY` を入れ替えると、全トークンと全ユーザーのログインセッションが失効する

公開情報だけ使うなら、トークンは不要で `--header "X-API-KEY: <PUBLIC_API_KEY>"` で接続できる。

## ツール一覧

| ツール | 内容 | 権限 |
|--------|------|------|
| `search_kev` | KEV を検索（ベンダー・製品・EPSS 下限） | 全員 |
| `get_recent_kev` | 直近 N 日に追加された KEV | 全員 |
| `get_kev` | CVE ID で KEV を1件取得 | 全員 |
| `search_osv` | OSV を検索（エコシステム・重要度・期間） | 全員 |
| `search_jvn` | JVN を検索（重要度・期間） | 全員 |
| `list_depscan_findings` | 依存ライブラリの脆弱性（DEPSCAN） | user / admin |
| `get_depscan_stats` | DEPSCAN の件数（リポジトリ別・重要度別） | user / admin |
| `list_codescan_findings` | コードの脆弱性（CODESCAN） | user / admin |
| `get_codescan_stats` | CODESCAN の件数 | user / admin |
| `whoami` | 現在の権限と見える範囲（接続確認用） | 全員 |

1回の取得は最大 50 件（エージェントのコンテキストを圧迫しないため）。

## 設計メモ

- **実装**: `app/mcp_server/`（`server.py` = ツール、`auth.py` = 認証）。ツールはアプリ自身の REST を
  プロセス内（ASGI）で呼ぶ。検索・検証・所有者による絞り込みのロジックを複製しない
- **ステートレス**: セッションをサーバーに持たない（再起動や複数台構成で壊れない）
- **トークン**: `app/auth/mcp_token.py`（JWT: sub・jti・aud・exp）。ダッシュボードのセッション（24 時間）とは
  `aud` で区別し、相互に流用できない
- **台帳**: `app/auth/mcp_token_store.py`・テーブル `mcp_tokens`（トークンID=jti・ユーザー・期限・失効日時・
  最終使用日時。トークン本体は保存しない）。接続のたびに、署名・期限に加えて「台帳にあり、発行者本人の
  もので、失効していない」ことを確認する。台帳に無い（jti の無い旧形式を含む）トークンは 401。台帳の確認に
  失敗したら fail closed（拒否）。最終使用日時は 5 分間隔で更新する
- **REST**（ダッシュボードのログインで認証。API キーでは不可）: `POST /auth/mcp-token`（`{"days": 7|30|90}`）、
  `GET /auth/mcp-tokens`（本人の一覧。トークン本体は含まない）、`DELETE /auth/mcp-tokens/{id}`（本人のみ。
  他人のトークンは 404）
- **CODESCAN の REST も同時に絞り込み対象にした**: これまでログイン済みなら誰でも全リポジトリの検知結果を
  取得できた。DEPSCAN と同様に、ログイン中ユーザー本人のリポジトリのみに強制した

## 今後

- OAuth 2.1（MCP 標準の認可フロー）に対応すれば、トークンの貼り付けが不要になる
- 期限が近づいたトークンの通知（Slack）
