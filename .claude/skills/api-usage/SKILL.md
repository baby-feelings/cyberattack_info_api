---
name: api-usage
description: サイバー攻撃情報API（本番稼働中のREST API）の使い方リファレンス。KEV/OSV/JVN脆弱性検索、DEPSCAN依存ライブラリスキャン、DEPSOPS判定履歴、STIX/TAXII配信、クローラーログ、Grafana監視、リモートMCPサーバー（/mcp）など、APIを叩いて何かを調べたい・分析したい時に読む。フィールド定義・エラーレスポンス・データ更新スケジュールも含む。
---

# Cyberattack Info API — スキルガイド

Claude Code や AI エージェントがこの API を「スキル（道具）」として活用するためのリファレンスです。
各エンドポイントの詳細なcurl例・パラメータ表・レスポンス例・フィールド定義は、トークン節約のため
`reference/` 配下の別ファイルに分離してあります。実際に該当エンドポイントを使う際にそちらを読んでください。

---

## 概要

| 項目 | 内容 |
|------|------|
| **ベース URL（本番）** | `https://168.138.213.240.nip.io` |
| **ベース URL（開発）** | `http://localhost:8000` |
| **認証方式** | `X-API-KEY` リクエストヘッダー |
| **レスポンス形式** | JSON |
| **データソース** | CISA KEV／OSV API／JVN MyJVN API／DEPSCAN（GitHub API + OSV API）（毎日 JST 04:05 に一括順次実行） |
| **Swagger UI** | `https://168.138.213.240.nip.io/docs` |

---

## 認証

全エンドポイント（`/health` を除く）に `X-API-KEY` ヘッダーが必要です。

```bash
export CYBERATTACK_API_KEY="your-secret-key"
curl -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/vulnerabilities"
```

キーが不正または未設定の場合は `403 Forbidden` が返ります。
API キーの比較には `hmac.compare_digest` を使用し、タイミング攻撃を防止しています。

> **Note:** 上記の `API_KEY` は管理者用・フルアクセスキー（`/admin/*` を含む全エンドポイントに使用可）。
> 別途、読み取り専用エンドポイント（KEV/OSV/JVN/crawler-logs）だけに通用する `PUBLIC_API_KEY`
> も存在する（React ダッシュボードのビルド成果物に埋め込まれるキーで、ブラウザから誰でも
> 抽出できるため管理者用キーとは分離してある）。Claude Code からの利用では引き続き
> `API_KEY` を使えばよく、影響はない。

> **Note:** 本番環境では Swagger UI（`/docs`）と ReDoc（`/redoc`）はセキュリティ上の理由で無効化されています。
> API 仕様の詳細は本ドキュメントまたは `README.md` を参照してください。
> ローカル開発時は `http://localhost:8000/docs` で OpenAPI ドキュメントを参照できます。

---

## MCPサーバーとして使う（AIエージェント向け・推奨）
curlの代わりに、リモートMCPサーバー（`https://168.138.213.240.nip.io/mcp`、Streamable HTTP）を
登録すると、ツール（`search_kev`/`get_recent_kev`/`get_kev`/`search_osv`/`search_jvn`/
`list_depscan_findings`/`get_depscan_stats`/`list_codescan_findings`/`get_codescan_stats`/`whoami`）として
使える。キーはMCPの設定に閉じ、CLAUDE.mdにcurl例を書く必要がない。読み取り専用で`/admin/*`は無い。

| 認証 | 見えるもの |
|------|-----------|
| `X-API-KEY`=`PUBLIC_API_KEY` | KEV/OSV/JVNの公開情報のみ |
| `Authorization: Bearer <MCPトークン>`（ダッシュボードの設定画面で発行。期限7/30/90日、個別に失効可） | 公開情報＋**自分が所有する**リポジトリのDEPSCAN/CODESCAN |
| `X-API-KEY`=`API_KEY`（運用者） | すべて |

登録: `claude mcp add --scope user --transport http cyberattack-info <URL> --header "Authorization: Bearer <トークン>"`、
接続確認は`/mcp`と`whoami`ツール。1回の取得は最大50件。詳細・設計は`docs/mcp-server.md`。

---

## スキル一覧（詳細は reference/endpoints-feeds.md・reference/endpoints-ops.md）

**KEV/OSV/JVN/DEPSCAN**（`reference/endpoints-feeds.md`）:

1. 直近の脅威を取得する（CISA KEV） — `GET /api/vulnerabilities/recent`
2. 脆弱性を検索・フィルタリングする（CISA KEV） — `GET /api/vulnerabilities`
3. CVE を 1 件取得する — `GET /api/vulnerabilities/{cve_id}`（`?format=stix`対応）
4. 統計情報を取得する（CISA KEV） — `GET /api/vulnerabilities/stats`
5. OSV 脆弱性を検索する — `GET /api/osv`
6. OSV 統計情報を取得する — `GET /api/osv/stats`
7. JVN 脆弱性を検索する — `GET /api/jvn`
8. JVN 統計情報を取得する — `GET /api/jvn/stats`
9. 自作アプリの依存ライブラリ脆弱性を確認する（DEPSCAN） — `GET /api/depscan`
10. DEPSCAN 統計情報を取得する — `GET /api/depscan/stats`
11. DEPSCAN検知結果をSBOM形式でエクスポートする — `GET /api/depscan/export`
12. リポジトリの資産コンテキストを設定・確認する — `PUT/GET /api/depscan/assets`

**DEPSOPS/CODESCAN/運用系**（`reference/endpoints-ops.md`）:

13. Dependabot PR 自動運用（DEPSOPS）の判定履歴を確認する — `GET /api/depsops`
13.5. 自アプリのコード脆弱性を確認する（CODESCAN） — `GET /api/codescan`
14. クローラーの実行ログを確認する — `GET /api/crawler-logs`
15. サービス状態を確認する — `GET /health`
16. 運用監視ダッシュボード（Grafana）を確認する
17. KEV/OSV/JVNデータをTAXII 2.1で購読する — `GET /taxii2/...`

同ファイルに「Claude Code での活用パターン」（`claude -p`との組み合わせ例・CI死活監視例）も掲載。

---

## 参考: GitHub ログイン API（DEPSCAN ダッシュボード用・ブラウザ専用）

React ダッシュボードの DEPSCAN タブ向けの GitHub OAuth ログイン機能。ブラウザでの
インタラクティブな認可が前提のため、Claude Code や CI から `curl` で直接呼び出す
スキルではない（詳細は `reference/endpoints-ops.md` 参照）。

| エンドポイント | 用途 |
|---------------|------|
| `GET /auth/github/login` | GitHub 認可画面へリダイレクト |
| `POST /auth/exchange` | 交換コードをセッションJWTに交換する（使い捨て） |
| `GET /auth/scan-status` | オンデマンドスキャン進捗（`Authorization: Bearer` 必須） |

ログインすると、その GitHub アカウント自身が所有するリポジトリを対象にオンデマンドで
DEPSCAN スキャンが実行され、`/api/depscan`・`/api/depscan/stats` はそのユーザー本人が
所有するリポジトリのみに強制的に絞り込まれる。`X-API-KEY` によるフルアクセスには影響しない。

---

## フィールド定義

各レスポンスのフィールド定義（`VulnerabilityOut`・`OsvVulnerabilityOut`・`JvnVulnerabilityOut`・
`DependencyFindingOut`・`CodeFindingOut`・`DependabotPrLogOut`・`CrawlerLogOut`）は
`reference/fields.md` を参照。

---

## エラーレスポンス

| HTTP ステータス | 原因 |
|--------------|------|
| `403 Forbidden` | `X-API-KEY` が不正または未設定 |
| `404 Not Found` | 指定した CVE ID が存在しない |
| `422 Unprocessable Entity` | リクエストボディ・パラメータの形式エラー |
| `500 Internal Server Error` | サーバー内部エラー |

---

## データ更新スケジュール

| タイミング | 処理 |
|----------|------|
| 毎日 JST 04:05（UTC 19:05） | GitHub Actions 単一 cron で KEV → OSV → JVN → DEPSCAN → CODESCAN → DEPSOPS を順次実行（Upsert・古いレコード削除） |
| アプリ起動時 | DB テーブルの自動作成 |
| `POST /admin/*-crawl` 実行時 | 各クローラーをバックグラウンド取得（202 即時返却。KEV/OSV/JVN/DEPSCAN/CODESCAN/DEPSOPSは`?force=true`で同日重複実行スキップをバイパス可能、Issue #239） |

Upsertロジックの概要:
- **KEV**: 新規→INSERT、内容変更あり→UPDATE、変更なし→スキップ。新規・更新時はSlack通知。
  削除は「今回のCISAフィードに存在しないレコードのみ」（Issue #239でage-based削除の
  重大バグを修正済み。詳細は`crawler-internals`スキル参照）
- **OSV/JVN**: KEVと同様のUpsertだが、削除は保持期間（既定180日、`*_RETENTION_DAYS`）超過
  レコードが対象（フェッチ自体が直近30日限定のため、KEVと違い削除後に復活しない）
- **DEPSCAN**: OSV APIとリアルタイム照合。新規検知はSlack通知＋対象リポジトリへの
  GitHub Issue自動起票（未解決findingが0件になると自動クローズ）。実際の修正はDependabot
  が担当（DEPSCANは検知・通知のみ）
- **DEPSOPS**: 安全なPR（マイナー/パッチ・CIあり・コンフリクトなし）のみ自動マージ、それ
  以外はSlack通知のみで人の判断に委ねる。毎日JST 08:00に自動実行、手動実行も可能

Upsertロジック・自動化の実装詳細（フィールド単位の判定条件・GitHub権限要件等）は
`.claude/skills/crawler-internals/SKILL.md`・`.claude/skills/depscan-depsops/SKILL.md`を参照。
