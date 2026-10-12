"""Slack 通知（クローラー結果・DEPSCAN・DEPSOPS・MCP トークン期限・Webhook 登録テスト）。

- `slack`: Slack Incoming Webhook への送信と、Webhook URL の検証
- `recipients`: 通知の送信先（登録ユーザーの Webhook）の解決
- `base`: 通知の共通フロー（`Notifier`。Template Method）と、クローラー種別の表示設定
- `crawler` / `dependency_findings` / `dependabot_ops` / `mcp_token` / `webhook_test`:
  用途ごとの通知（`Notifier` のサブクラスと、呼び出し用の関数）

Issue #227 より前は固定の `SLACK_WEBHOOK_URL` 環境変数1本のみへ送信していたが、ダッシュボードから
各ユーザーが自分の Slack Webhook を登録できるようになったのに伴い、検知結果の通知先は
`app.auth.account_store`（`UserAccount` テーブル）から動的に解決する方式へ移行した（`recipients`）。
"""
