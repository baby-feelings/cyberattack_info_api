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
- **期限の 3 日前に Slack で通知**する（設定画面で Slack Webhook を登録している場合。1 トークンにつき 1 回、毎日 JST 8:45 に判定。
  未登録のユーザーには送らず、登録後に通知される。通知にトークン本体は含まない）
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

- **実装**: `app/mcp_server/`（`server.py` = サーバーの組み立て、`tools/` = ツール〈`public`=KEV/OSV/JVN・
  `private`=DEPSCAN/CODESCAN・`identity`=whoami〉、`gateway.py` = REST への窓口〈`RestGateway`。認証ヘッダーの
  決定・パラメータ整形・応答の所有者検証〉、`auth.py` = 認証）。ツールはアプリ自身の REST を
  プロセス内（ASGI）で呼ぶ。検索・検証・所有者による絞り込みのロジックを複製しない。ツールを足すときは
  該当グループの `tools/*.py` に追加する
- **ステートレス**: セッションをサーバーに持たない（再起動や複数台構成で壊れない）
- **トークン**: `app/mcp_server/mcp_token.py`（JWT: sub・jti・aud・exp）。ダッシュボードのセッション（24 時間）とは
  `aud` で区別し、相互に流用できない
- **台帳**: `app/mcp_server/mcp_token_store.py`・テーブル `mcp_tokens`（トークンID=jti・ユーザー・期限・失効日時・
  最終使用日時。トークン本体は保存しない）。接続のたびに、署名・期限に加えて「台帳にあり、発行者本人の
  もので、失効していない」ことを確認する。台帳に無い（jti の無い旧形式を含む）トークンは 401。台帳の確認に
  失敗したら fail closed（拒否）。最終使用日時は 5 分間隔で更新する
- **REST**（ダッシュボードのログインで認証。API キーでは不可）: `POST /auth/mcp-token`（`{"days": 7|30|90}`）、
  `GET /auth/mcp-tokens`（本人の一覧。トークン本体は含まない）、`DELETE /auth/mcp-tokens/{id}`（本人のみ。
  他人のトークンは 404）
- **CODESCAN の REST も同時に絞り込み対象にした**: これまでログイン済みなら誰でも全リポジトリの検知結果を
  取得できた。DEPSCAN と同様に、ログイン中ユーザー本人のリポジトリのみに強制した

## OAuth 2.1 対応（実装中。Issue #303）
貼り付け不要で接続できるよう、MCP 標準の OAuth 2.1 認可フローに段階的に対応する。
`MCP_OAUTH_ISSUER` が空（既定）の間は何も公開されず、従来のトークン方式のみ動く。

- **PR1（実装済み）**: 認可サーバーのメタデータ（`/.well-known/oauth-authorization-server`、
  `oauth-protected-resource/mcp`）と動的クライアント登録（`/register`、`oauth_clients` テーブル）
- 登録は誰でも呼べる（標準クライアントはログイン前に登録するため）が、**登録だけではデータは
  見えない**（本人の GitHub ログインと同意が必須）。悪用対策: redirect_uri は https か
  ループバックの http のみ・1 クライアント 5 件まで、1 時間 60 件・総数 1000 件の上限、
  未使用のまま 30 日を過ぎた登録は自動削除、スコープは `mcp:read` のみ
- **構成**: `oauth_provider.McpOAuthProvider` は SDK との橋渡し（async への変換・SDK の型への詰め替え・
  DB セッションの管理）だけを担い、判断は `oauth_services` の同期サービス（`AuthorizationService`=
  `/authorize` の検証・認可コードの取得と交換、`RefreshService`=リフレッシュのローテーション・許可の
  取り消し、`AccessTokenService`=アクセストークンの取得と失効）にある。`Session` を引数に取るため、
  async や HTTP を介さず単体でテストできる（`tests/mcp_server/test_oauth_services.py`）
- **PR2（実装済み）**: 認可フロー。`/authorize`（SDK）→ 同意画面 `GET/POST /oauth/consent`
  （バックエンドの HTML）→ GitHub ログイン → 既存の `/auth/github/callback` → 認可コード → `/token`
  - GitHub のログインは**スコープなし**（本人確認だけ。リポジトリの内容は読まず、GitHub の
    トークンも保存しない）。コールバックは既存のものを再利用するため、GitHub OAuth App の
    設定変更は不要。MCP 用かどうかは署名付き `state`（JWT、`oauth_flow`）で判別し、Cookie は使わない
  - 認可リクエスト〜認可コードは `oauth_authorizations` の1行（コードはハッシュのみ保存。
    認可リクエスト 10 分・認可コード 5 分・使い捨て）。PKCE（S256）は SDK が検証する
  - アクセストークンは既存の台帳（`mcp_tokens`、`oauth_client_id` 付き）へ **1 時間**で発行し、
    `/mcp` の認証・個別失効は手動発行のトークンと同じ仕組み。手動発行の一覧・上限・
    期限前の Slack 通知の対象外（リフレッシュトークンで自動更新される前提）
  - 同意画面は、クライアント名（自己申告・未確認）と戻り先ホストを表示し、文字列はエスケープ
  - 許可・拒否と、GitHub から戻るコールバックは、**同意画面を最初に開いたブラウザ**だけが行える
    （HttpOnly・Secure・SameSite=Lax の Cookie の乱数のハッシュを `oauth_authorizations.browser_hash`
    と照合）。URL の横取りや画面を開かない CSRF、さらに「攻撃者の認可リクエストの state を被害者に
    GitHub 認可 URL として踏ませ、被害者の本人確認を攻撃者の認可リクエストに紐づける」攻撃を防ぐ
  - **`MCP_OAUTH_ISSUER` は `API_BASE_URL_FOR_OAUTH`（GitHub コールバック）と同じホスト**にする。
    Cookie がホスト単位のため、違うと起動時にエラーにする（Fail Fast）。ドメインを切り替えるときは
    GitHub OAuth App の callback URL・`API_BASE_URL_FOR_OAUTH`・ダッシュボードの API URL と揃える
- **PR3（実装済み）**: リフレッシュトークン（`oauth_refresh_tokens`、30 日、ハッシュのみ保存）と `/revoke`
  - **ローテーション**: 使うたびに新しいトークンへ交換し、元のトークンは使用済みにする。条件付き UPDATE の
    件数で判定するため、同じトークンを同時に2回使っても成功は片方だけ
  - **盗用の検知**: 使用済みのトークンが再び提示されたら、同じ系統（最初の認可から連なるもの）を
    すべて失効する（正規のクライアントも再認可が必要になる）
  - スコープは元の認可の範囲内（広げられない）。別クライアントのトークンは使えない
  - **失効（`/revoke`、RFC 7009）**: リフレッシュトークンを失効すると、そのクライアントへの本人の許可を
    すべて取り消す（リフレッシュトークン全系統と、発行済みの OAuth アクセストークン）。アクセストークンを
    失効すると、そのトークン 1 つだけ。手動発行のトークンには触れない。未知のトークンは 200（RFC）
- **ダッシュボード（実装済み）**: 設定画面は「OAuth で接続（推奨）」欄を先に、「MCPトークン（OAuth 非対応の
  クライアント向け）」欄を後に並べる。OAuth 欄は接続が 1 件も無くても登録コマンド
  （`claude mcp add --scope user --transport http ...`。トークンの貼り付けは不要）を常に表示し、接続があれば
  アプリ名（登録時の自己申告）・接続日・最終使用（一度も使われなければ「未使用」）・許可の期限と、
  「接続解除」ボタンを出す
  （`GET /auth/oauth-connections`・`DELETE /auth/oauth-connections/{client_id}`。`/revoke` でリフレッシュ
  トークンを失効したのと同じく、本人のそのクライアントへの許可をすべて取り消す）。アプリ名は React の
  テキストとして出し、HTML として解釈しない。MCPトークン欄の失効済み・期限切れは折りたたみ（標準は
  有効なものだけ表示）
- **使われない接続・登録の自動整理（実装済み）**: 毎日 UTC 23:50 の定期ジョブ（`oauth_cleanup`）。
  接続（初回の許可）から 7 日を過ぎても一度も使われていない接続は、「接続解除」と同じ処理で解除する
  （使われた接続には触れない。必要になれば認可し直す）。一度もトークン交換に使われず 30 日を過ぎた
  クライアント登録も削除する。Claude Code は `/mcp` で認証するたびにクライアントを自動登録するため、
  認証のやり直しで「未使用」の接続が残りやすい
