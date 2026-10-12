"""MCP サーバーの OAuth 2.1 認可サーバー（Issue #303）。

- `routes`: SDK の認可ルートと同意画面・GitHub ログイン連携の組み立て
  （`MCP_OAUTH_ISSUER` 未設定なら何も公開しない）
- `provider`: SDK との橋渡し（`McpOAuthProvider`）。判断は `services` の同期サービスに任せる
- `services`: 認可・トークン交換・リフレッシュ・失効の判断（`Session` を引数に取る）
- `clients`: 動的クライアント登録の保存と検証
- `flow`: 認可リクエスト〜認可コード、署名付き state
- `refresh`: リフレッシュトークン（ローテーション・盗用の検知）
- `consent`: 同意画面（Cookie によるブラウザの紐づけ）
- `connections`: 接続中のクライアントの一覧と解除
- `cleanup`: 使われない接続・登録の自動整理（定期ジョブ）
"""
