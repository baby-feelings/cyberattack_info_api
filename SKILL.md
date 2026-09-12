# Cyberattack Info API — スキルガイド

Claude Code や AI エージェントがこの API を「スキル（道具）」として活用するためのリファレンスです。

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
# 環境変数から API キーを渡す（推奨）
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

## スキル一覧

### スキル 1: 直近の脅威を取得する（CISA KEV）

**用途:** 「最近 N 日間に新たに悪用が確認された脆弱性」を一括取得する。

```bash
# 直近 30 日（デフォルト）
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/vulnerabilities/recent"

# 直近 7 日
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/vulnerabilities/recent?days=7"
```

| パラメータ | 型 | 範囲 | デフォルト |
|-----------|-----|------|-----------|
| `days` | int | 1〜365 | 30 |

---

### スキル 2: 脆弱性を検索・フィルタリングする（CISA KEV）

**用途:** ベンダー名・製品名・キーワードで絞り込んで脆弱性を検索する。

```bash
# キーワード検索
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/vulnerabilities?search=Apache"

# ベンダー完全一致
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/vulnerabilities?vendor=Microsoft"

# 製品名部分一致
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/vulnerabilities?product=Exchange"

# EPSS スコア（悪用確率）0.5 以上のみに絞り込み
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/vulnerabilities?min_epss=0.5"
```

| パラメータ | 型 | 説明 |
|-----------|-----|------|
| `page` | int | ページ番号（デフォルト: 1） |
| `per_page` | int | 件数（デフォルト: 50、最大: 500） |
| `search` | string | ベンダー名・製品名の部分一致 |
| `vendor` | string | ベンダー名の完全一致 |
| `product` | string | 製品名の部分一致 |
| `min_epss` | float | EPSS スコアの下限（0.0〜1.0）。KEV 掲載に加え悪用確率でも絞り込みたい場合に使用 |
| `updated_since` | string (ISO 8601) | この日時以降に内容が更新されたレコードのみ返す（差分取得・増分同期用） |

---

### スキル 3: CVE を 1 件取得する

**用途:** CVE ID を直接指定して詳細を取得する。

```bash
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/vulnerabilities/CVE-2021-44228"
```

存在しない CVE ID の場合は `404 Not Found` が返ります（大文字小文字不問）。

---

### スキル 4: 統計情報を取得する（CISA KEV）

**用途:** ベンダー別ランキングや月別トレンドを把握する。定期レポートや分析に活用。

```bash
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/vulnerabilities/stats"
```

**レスポンス例:**
```json
{
  "total_vulnerabilities": 1619,
  "top_vendors": [
    { "vendor_project": "Microsoft", "count": 312 },
    { "vendor_project": "Apple", "count": 89 }
  ],
  "monthly_trend": [
    { "year_month": "2026-05", "count": 23 },
    { "year_month": "2026-06", "count": 8 }
  ]
}
```

---

### スキル 5: OSV 脆弱性を検索する

**用途:** OSV データベースから特定エコシステム・重要度の脆弱性を検索する（ダッシュボードは過去 6 ヶ月表示）。  
対象: PyPI / npm / Go / Maven / RubyGems / NuGet / crates.io / Packagist / Hex / **Pub**（Dart / Flutter）の主要パッケージ。

```bash
# PyPI の HIGH 以上の脆弱性を取得
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/osv?ecosystem=PyPI&severity=HIGH"

# パッケージ名で検索
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/osv?search=django"

# CRITICAL のみ全エコシステムで取得（CVSS スコア降順）
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/osv?severity=CRITICAL&sort_by=cvss"
```

| パラメータ | 型 | 説明 |
|-----------|-----|------|
| `page` | int | ページ番号（デフォルト: 1） |
| `per_page` | int | 件数（デフォルト: 50、最大: 500） |
| `ecosystem` | string | エコシステム名（`PyPI` / `npm` / `Go` / `Pub` 等） |
| `severity` | string | 重要度（`CRITICAL` / `HIGH` / `MEDIUM` / `LOW`） |
| `search` | string | パッケージ名の部分一致 |
| `sort_by` | string | ソート基準（`modified`（デフォルト） / `cvss`） |
| `updated_since` | string (ISO 8601) | この日時以降に内容が更新されたレコードのみ返す（差分取得・増分同期用） |

---

### スキル 6: OSV 統計情報を取得する

**用途:** エコシステム別・重要度別の脆弱性件数や月別トレンドを把握する。

```bash
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/osv/stats"
```

**レスポンス例:**
```json
{
  "total": 646,
  "ecosystems": [
    { "ecosystem": "PyPI", "count": 210 },
    { "ecosystem": "npm", "count": 180 }
  ],
  "severities": [
    { "severity": "HIGH", "count": 280 },
    { "severity": "CRITICAL", "count": 95 }
  ],
  "monthly_trend": [
    { "year_month": "2026-06", "count": 120 }
  ]
}
```

---

### スキル 7: JVN 脆弱性を検索する

**用途:** JVN (Japan Vulnerability Notes) から日本国内の脆弱性情報を検索する（ダッシュボードは過去 6 ヶ月表示）。  
MyJVN API（jvndb.jvn.jp）から取得した JVNDB 登録脆弱性を対象とする。

```bash
# High 重要度の脆弱性を取得
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/jvn?severity=High"

# キーワードで検索
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/jvn?search=Apache"

# CVSS スコア降順で取得
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/jvn?sort_by=cvss"
```

| パラメータ | 型 | 説明 |
|-----------|-----|------|
| `page` | int | ページ番号（デフォルト: 1） |
| `per_page` | int | 件数（デフォルト: 50、最大: 500） |
| `severity` | string | 重要度（`High` / `Medium` / `Low`） |
| `search` | string | JVNDB ID・タイトル・概要の部分一致 |
| `sort_by` | string | ソート基準（`modified`（デフォルト） / `cvss`） |
| `days` | int | 取得対象の直近日数（デフォルト: 30） |
| `updated_since` | string (ISO 8601) | この日時以降に内容が更新されたレコードのみ返す（差分取得・増分同期用） |

---

### スキル 8: JVN 統計情報を取得する

**用途:** 重要度別の JVN 脆弱性件数や月別トレンドを把握する。

```bash
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/jvn/stats"
```

**レスポンス例:**
```json
{
  "total": 129,
  "severities": [
    { "severity": "High", "count": 45 },
    { "severity": "Medium", "count": 62 },
    { "severity": "Low", "count": 22 }
  ],
  "monthly_trend": [
    { "year_month": "2026-06", "count": 129 }
  ]
}
```

---

### スキル 9: 自作アプリの依存ライブラリ脆弱性を確認する（DEPSCAN）

**用途:** GitHub 上の自作アプリ（`baby-feelings` アカウント配下、プライベートリポジトリ含む・
fork・archived 除く）が依存するライブラリに脆弱性がないか確認する。OSV API とリアルタイム照合
するため、`POPULAR_PACKAGES` に含まれない任意のパッケージも検知対象になる。対応ロックファイル
（`requirements.txt` / `package-lock.json` / `pubspec.lock` 等 10 エコシステム）が存在しない
リポジトリはスキャン対象外。新規検知はリポジトリ自身に GitHub Issue も自動起票し、その後の
再スキャンで当該リポジトリの未解決 finding が0件になったことを確認できると自動でクローズする。
各検知結果には `reachability`（到達可能性のヒューリスティック判定）フィールドも含まれる。

```bash
# 未解決の HIGH 以上の検知結果を取得
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/depscan?resolved=false&severity=HIGH"

# 特定リポジトリのみ絞り込み
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/depscan?repo=baby-feelings/baby_grow"

# リポジトリオーナー単位で絞り込み
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/depscan?owner=baby-feelings"
```

| パラメータ | 型 | 説明 |
|-----------|-----|------|
| `page` | int | ページ番号（デフォルト: 1） |
| `per_page` | int | 件数（デフォルト: 50、最大: 200） |
| `repo` | string | リポジトリ名で絞り込み（完全一致。例: `owner/repo`） |
| `owner` | string | リポジトリオーナーで絞り込み（前方一致。例: `baby-feelings`） |
| `ecosystem` | string | エコシステムで絞り込み |
| `severity` | string | 重要度（`CRITICAL` / `HIGH` / `MEDIUM` / `LOW`） |
| `resolved` | bool | 解決状態で絞り込み（省略時は全件） |

> **Note:** `X-API-KEY` での呼び出しは上記の通り絞り込みなしのフルアクセス（Claude Code
> 等の既存クライアント向け）。React ダッシュボードの DEPSCAN タブは別途 GitHub ログイン
> （`Authorization: Bearer <セッショントークン>`）を要求し、ログイン中のユーザー本人が
> 所有するリポジトリのみに強制的に絞り込まれる（下記「GitHub ログイン API」参照）。
> Claude Code からの利用では引き続き `X-API-KEY` を使えばよく、影響はない。

各検知結果には `repo_visibility`（`"public"`/`"private"`、GitHub APIから自動取得）と
`asset_context`（本番デプロイ済みか・インターネット公開か・重要度。未設定なら`null`。
スキル11参照）も含まれる（Issue #131）。

さらに `priority_reasons`（文字列配列。`kev_listed`/`epss_high`/`reachable`/
`public_repo`/`internet_facing_asset`/`production_asset`/`high_importance_asset`の
いずれか0件以上）も含まれ、なぜその検知結果の優先度が高いと判断されるかを
機械可読な形で確認できる（Issue #135）。

---

### スキル 10: DEPSCAN 統計情報を取得する

**用途:** 未解決の依存ライブラリ脆弱性について、リポジトリ別・重要度別の件数を把握する。

```bash
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/depscan/stats"
```

**レスポンス例:**
```json
{
  "total": 3,
  "repos": [
    { "repo_full_name": "baby-feelings/baby_grow", "count": 2 }
  ],
  "severities": [
    { "severity": "HIGH", "count": 2 },
    { "severity": "MEDIUM", "count": 1 }
  ]
}
```

---

### スキル 11: リポジトリの資産コンテキストを設定・確認する（Issue #131）

**用途:** DEPSCANの検知結果に「本番デプロイ済みか」「インターネット公開サービスか」
「資産重要度」を紐付けるための設定を行う。GitHub APIから自動判定できない情報のため
手動設定が必要（`repo_visibility`は自動取得のため対象外、スキル9参照）。

```bash
# 設定（Upsert。既存設定があれば上書き）
curl -s -X PUT -H "X-API-KEY: $CYBERATTACK_API_KEY" -H "Content-Type: application/json" \
  -d '{"is_production": true, "is_internet_facing": true, "importance": "high"}' \
  "https://168.138.213.240.nip.io/admin/depscan/assets/baby-feelings/cyberattack_info_api"

# 設定済み一覧を取得
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/depscan/assets"
```

| フィールド | 型 | 説明 |
|-----------|-----|------|
| `is_production` | bool | 本番デプロイ済みか（デフォルト: `false`） |
| `is_internet_facing` | bool | インターネットに公開されたサービスか（デフォルト: `false`） |
| `importance` | string \| null | 資産重要度（`high`/`medium`/`low`）。未評価なら`null` |

> 設定した内容は `GET /api/depscan` の各検知結果に `asset_context` として自動的に
> 埋め込まれる（スキル9参照）。未設定のリポジトリは `GET /api/depscan/assets` の
> 一覧には含まれず、`asset_context` は `null` になる。

---

### スキル 12: Dependabot PR 自動運用（DEPSOPS）の判定履歴を確認する

**用途:** `POST /admin/dependabot-ops` が判定した Dependabot PR の履歴（自動マージ済み・
要確認いずれも）を確認する。Slack 通知は実行時点のスナップショットのみで履歴を持たないため、
「要確認」PR がどのリポジトリ・どんな理由で自動マージされなかったかを後から振り返るのに使う。

```bash
# 要確認（自動マージされなかった）PR のみ取得
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/depsops?action=flagged"

# 特定リポジトリのみ絞り込み
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/depsops?repo=baby-feelings/baby_grow"
```

| パラメータ | 型 | 説明 |
|-----------|-----|------|
| `page` | int | ページ番号（デフォルト: 1） |
| `per_page` | int | 件数（デフォルト: 50、最大: 200） |
| `repo` | string | リポジトリ名で絞り込み（完全一致。例: `owner/repo`） |
| `action` | string | 判定結果で絞り込み（`merged` / `flagged` / `closed`） |

**レスポンス例:**
```json
{
  "total": 1,
  "page": 1,
  "per_page": 50,
  "data": [
    {
      "repo_full_name": "baby-feelings/baby_grow",
      "pr_number": 55,
      "title": "chore(deps-dev): Bump typescript from 6.0.3 to 7.0.2",
      "action": "flagged",
      "reason": "メジャーバージョンアップ",
      "is_security_update": false,
      "compatibility_badge_url": null,
      "processed_at": "2026-09-07T12:05:21+00:00"
    }
  ]
}
```

> React ダッシュボードでは、DEPSOPS 専用タブは無く DEPSCAN タブ内のボタンから開く
> 「Dependabot 運用状況」全画面モーダルからこの一覧を閲覧できる。
> `is_security_update` が常に `null` の場合、`GITHUB_TOKEN` に Dependabot alerts の
> 読み取り権限（classic PAT: `security_events` スコープ / fine-grained PAT: 「Dependabot
> alerts: Read-only」）が付与されていない可能性がある。付与後に実行された分から反映される
> （過去に記録済みの履歴行は遡って再判定されない）。
>
> `action=closed` は、過去に `flagged`（要確認）と記録した PR が、Dependabotの自動
> クローズや手動マージ等 DEPSOPS の関知しないところで解消されたことを検知した記録
> （詳細は [CLAUDE.md](CLAUDE.md) の「DEPSOPS」節参照）。ダッシュボードの「未解決」
> 件数計算はこれを`flagged`と区別して除外するため、実態に合った件数になる。

---

## 参考: GitHub ログイン API（DEPSCAN ダッシュボード用・ブラウザ専用）

React ダッシュボードの DEPSCAN タブ向けの GitHub OAuth ログイン機能。ブラウザでの
インタラクティブな認可が前提のため、Claude Code や CI から `curl` で直接呼び出す
スキルではない（参考情報として記載）。

| エンドポイント | 用途 |
|---------------|------|
| `GET /auth/github/login` | GitHub 認可画面へリダイレクト（`<a href>` で開く） |
| `GET /auth/github/callback` | OAuth コールバック（内部利用のみ）。数十秒で失効する使い捨ての交換コードを発行し、URLクエリにはそれのみ載せる（セッションJWT自体は載せない。RFC 9700対応） |
| `POST /auth/exchange` | 交換コードをセッションJWTに交換する（使い捨て） |
| `GET /auth/scan-status` | ログイン中ユーザーのオンデマンドスキャン進捗を取得（`Authorization: Bearer <セッショントークン>` 必須） |

ログインすると、その GitHub アカウント自身が所有するリポジトリを対象にオンデマンドで
DEPSCAN スキャンが実行され（直近24時間以内にスキャン済みならスキップ）、`/api/depscan`・
`/api/depscan/stats` はそのユーザー本人が所有するリポジトリのみに強制的に絞り込まれる。
`X-API-KEY` によるフルアクセス（スキル 9・10 で解説した既存の利用方法）には一切影響しない。

---

### スキル 13: クローラーの実行ログを確認する

**用途:** KEV / OSV / JVN / DEPSCAN クローラーが正常に動作しているか、最新の実行結果（件数・所要時間・エラー）を確認する。

```bash
# 直近 10 件の実行ログを取得
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/crawler-logs?limit=10"

# JVN のみ絞り込み
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/crawler-logs?crawler_type=JVN"

# エラーのみ確認
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/crawler-logs?status=error"
```

| パラメータ | 型 | 説明 |
|-----------|-----|------|
| `crawler_type` | string | `KEV` / `OSV` / `JVN` / `DEPSCAN` / `DEPSOPS`（省略時は全種別） |
| `status` | string | `success` / `error`（省略時は両方） |
| `limit` | int | 取得件数（デフォルト: 30、最大: 100） |

**レスポンス例:**
```json
[
  {
    "id": 42,
    "crawler_type": "JVN",
    "status": "success",
    "started_at": "2026-06-18T21:05:03+00:00",
    "finished_at": "2026-06-18T21:05:18+00:00",
    "duration_seconds": 15.2,
    "inserted": 129,
    "updated": 0,
    "deleted": 0,
    "error_message": null
  }
]
```

---

### スキル 14: サービス状態を確認する

**用途:** API サーバーと DB が正常稼働しているか確認する。

```bash
curl -s "https://168.138.213.240.nip.io/health"
```

**レスポンス:**
```json
{
  "status": "ok",
  "environment": "production",
  "db_connected": true
}
```

---

### スキル 15: 運用監視ダッシュボード（Grafana）を確認する

**用途:** クローラー（KEV/OSV/JVN/DEPSCAN/DEPSOPS）が実際に成功し続けているか、OCIホストの
CPU/メモリ/ディスク使用率を可視化されたダッシュボードで確認する。`curl`ではなくブラウザで
アクセスする（ログイン必須）。

```
https://grafana.168.138.213.240.nip.io/
```

ダッシュボード名「サイバー攻撃情報API」に、クローラー実行結果（成否・経過時間・所要時間・
新規/更新/削除件数）・ホストリソース使用率・外部API呼び出しのリトライ発生回数
（レート制限/一時的エラー別、Issue #130）のパネルがある。ログイン情報は管理者に確認する
（`deploy/.env`の`GRAFANA_ADMIN_USER`/`GRAFANA_ADMIN_PASSWORD`）。

Prometheus形式の生データが必要な場合は `GET /metrics`（`Authorization: Bearer
$METRICS_API_KEY`で保護、未設定時は503）から直接取得することも可能。

---

## Claude Code での活用パターン

### パターン 1: 直近の脅威を分析させる

```bash
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/vulnerabilities/recent?days=30" \
  | claude -p "これらの脆弱性のうち、Python / FastAPI プロジェクトに影響するものを
               優先度順に整理し、対策案を教えてください"
```

### パターン 2: CI/CD でクローラー死活監視を自動化する

```yaml
# .github/workflows/crawler-health.yml の例
- name: Check crawler health
  run: |
    RESULT=$(curl -s -H "X-API-KEY: ${{ secrets.CYBERATTACK_API_KEY }}" \
      "https://168.138.213.240.nip.io/api/crawler-logs?limit=3&crawler_type=JVN")
    STATUS=$(echo "$RESULT" | python -c "import sys,json; d=json.load(sys.stdin); print(d[0]['status'] if d else 'no_log')")
    echo "最新 JVN クロール: $STATUS"
    if [ "$STATUS" = "error" ]; then
      echo "クローラーエラーを検知"
      exit 1
    fi
```

### パターン 3: 特定 CVE の詳細を素早く調べる

```bash
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/vulnerabilities/CVE-2021-44228" \
  | claude -p "この脆弱性の影響と対策を日本語で説明してください"
```

### パターン 4: OSV で使用ライブラリのリスクを確認する

```bash
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/osv?ecosystem=PyPI&severity=CRITICAL" \
  | claude -p "自分のプロジェクトで使っているパッケージが含まれているか確認し、
               影響があれば修正バージョンを教えてください"
```

### パターン 5: JVN で国内脆弱性の最新動向を把握する

```bash
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/jvn?severity=High&sort_by=cvss" \
  | claude -p "直近の高重要度 JVN 脆弱性を整理し、対処優先度を教えてください"
```

### パターン 6: 自作アプリ群の未対応脆弱性を棚卸しする（DEPSCAN）

```bash
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/depscan?resolved=false" \
  | claude -p "リポジトリ別に整理し、CRITICAL/HIGH を優先度順にリストアップしてください。
               各項目に修正済みバージョンへの更新コマンド案も添えてください"
```

> **実際の修正は Dependabot が担当。** DEPSCAN は検知・通知のみで、修正コードは生成しない。
> `POST /admin/dependabot-ops`（DEPSOPS）が毎日JST 08:00に自動実行され、安全なPR
> （マイナー/パッチ・CIあり・コンフリクトなし）のみ自動マージし、それ以外はSlack通知で
> 人の判断に委ねる（判定結果はスキル11の`GET /api/depsops`で確認できる）。

---

## フィールド定義

### VulnerabilityOut（CISA KEV 脆弱性情報）

| フィールド | 型 | 説明 |
|-----------|-----|------|
| `cve_id` | string | CVE 識別子（例: `CVE-2024-12345`） |
| `vendor_project` | string | 影響を受けるベンダー・プロジェクト名 |
| `product` | string | 影響を受ける製品名 |
| `vulnerability_name` | string | 脆弱性の名称 |
| `description` | string | 脆弱性の概要説明 |
| `required_action` | string \| null | CISA が推奨する対処アクション |
| `date_added` | string (date) | KEV カタログに追加された日付（`YYYY-MM-DD`） |
| `epss_score` | float \| null | EPSS スコア（今後30日以内に悪用される確率、0.0〜1.0。FIRST が日次算出） |
| `epss_percentile` | float \| null | EPSS パーセンタイル（全 CVE 中での相対順位、0.0〜1.0） |
| `epss_updated_at` | string (ISO 8601) \| null | EPSS スコアの取得日時 |
| `fetched_at` | string (ISO 8601) \| null | このレコードを最後に CISA KEV フィードで存在確認した日時（内容変更が無くても毎回のクロールで更新される） |

### OsvVulnerabilityOut（OSV 脆弱性情報）

| フィールド | 型 | 説明 |
|-----------|-----|------|
| `osv_id` | string | OSV ID（例: `GHSA-xxxx` / `OSV-2024-xxxx`） |
| `ecosystem` | string | エコシステム（`PyPI` / `npm` / `Go` 等） |
| `package_name` | string | パッケージ名 |
| `aliases` | string[] | エイリアス ID（CVE ID 等） |
| `summary` | string | 脆弱性の概要 |
| `details` | string \| null | 詳細説明 |
| `severity` | string \| null | 重要度（`CRITICAL` / `HIGH` / `MEDIUM` / `LOW`） |
| `cvss_score` | float \| null | CVSS スコア |
| `affected_versions` | string[] | 影響を受けるバージョン（最大 30 件） |
| `fixed_versions` | string[] | 修正済みバージョン |
| `references` | string[] | 参考リンク（最大 5 件） |
| `published` | string (ISO 8601) | 公開日時 |
| `modified` | string (ISO 8601) | 最終更新日時 |
| `withdrawn_at` | string (ISO 8601) \| null | 撤回日時。設定されていればソース側（OSV）で撤回済み |
| `fetched_at` | string (ISO 8601) \| null | このレコードを最後に OSV API で存在確認した日時（内容変更が無くても毎回のクロールで更新される） |

### JvnVulnerabilityOut（JVN 脆弱性情報）

| フィールド | 型 | 説明 |
|-----------|-----|------|
| `jvndb_id` | string | JVNDB 識別子（例: `JVNDB-2026-020172`） |
| `title` | string | 脆弱性のタイトル |
| `overview` | string | 概要説明 |
| `cve_ids` | string[] | 関連 CVE ID リスト |
| `severity` | string \| null | 重要度（`High` / `Medium` / `Low`） |
| `cvss_score` | float \| null | CVSS スコア |
| `cvss_vector` | string \| null | CVSS ベクター文字列 |
| `affected_products` | object[] | 影響製品（`vendor` / `product` / `cpe` を含む） |
| `references` | object[] | 参考情報 |
| `jvn_url` | string | JVN 詳細ページ URL |
| `date_published` | string (ISO 8601) | 公開日時 |
| `date_last_modified` | string (ISO 8601) | 最終更新日時 |
| `fetched_at` | string (ISO 8601) \| null | このレコードを最後に MyJVN API で存在確認した日時（内容変更が無くても毎回のクロールで更新される） |

### DependencyFindingOut（DEPSCAN 検知結果）

| フィールド | 型 | 説明 |
|-----------|-----|------|
| `repo_full_name` | string | 検知元リポジトリ（例: `baby-feelings/baby_grow`） |
| `ecosystem` | string | エコシステム（`PyPI` / `npm` / `Pub` 等） |
| `package_name` | string | パッケージ名 |
| `installed_version` | string | ロックファイルに記載されていたインストール済みバージョン |
| `osv_id` | string | OSV ID（例: `GHSA-xxxx-xxxx-xxxx`） |
| `severity` | string \| null | 重要度（`CRITICAL` / `HIGH` / `MEDIUM` / `LOW`） |
| `cvss_score` | float \| null | CVSS スコア |
| `summary` | string | 脆弱性の概要 |
| `fixed_versions` | string[] | 修正済みバージョン |
| `manifest_path` | string | 検知元のロックファイルパス（例: `dashboard/package-lock.json`） |
| `reachability` | string \| null | 到達可能性のヒューリスティック判定（`reachable` / `unreachable` / `unknown`）。脆弱なパッケージがソースコード内で import/require/use されているかを判定（関数呼び出しレベルの解析は行わない best-effort） |
| `detected_at` | string (ISO 8601) | 初回検知日時 |
| `resolved_at` | string \| null (ISO 8601) | 解決日時（未解決なら `null`） |

### DependabotPrLogOut（DEPSOPS の PR 判定履歴）

| フィールド | 型 | 説明 |
|-----------|-----|------|
| `repo_full_name` | string | 対象リポジトリ（例: `baby-feelings/baby_grow`） |
| `pr_number` | int | Dependabot PR 番号 |
| `title` | string | PR タイトル |
| `action` | string | 判定結果（`merged`: 自動マージ済み / `flagged`: 要確認 / `closed`: 過去のflaggedがDEPSOPS外の要因で解消済み） |
| `reason` | string \| null | `action=flagged`/`closed` の場合の理由（メジャーバージョンアップ等）。`merged` の場合は `null` |
| `is_security_update` | bool \| null | セキュリティ更新（GitHub Dependabot alertの対象パッケージと一致）のヒューリスティック判定。`true`=セキュリティ更新の可能性が高い / `false`=通常のバージョン更新 / `null`=判定不能（`GITHUB_TOKEN` に Dependabot alerts の読み取り権限が無い等） |
| `compatibility_badge_url` | string \| null | Dependabot が PR 本文に埋め込む Compatibility score バッジ画像のURL。exact version bump のPRにのみ存在し、範囲指定の requirement 更新PR等は `null` |
| `processed_at` | string (ISO 8601) | 判定を行った DEPSOPS 実行日時 |

### CrawlerLogOut（クローラー実行ログ）

| フィールド | 型 | 説明 |
|-----------|-----|------|
| `id` | int | ログ ID |
| `crawler_type` | string | クローラー種別（`KEV` / `OSV` / `JVN` / `DEPSCAN` / `DEPSOPS`） |
| `status` | string | 実行結果（`success` / `error`） |
| `started_at` | string (ISO 8601) | 開始日時 |
| `finished_at` | string (ISO 8601) | 終了日時 |
| `duration_seconds` | float | 所要時間（秒） |
| `inserted` | int | 新規挿入件数 |
| `updated` | int | 更新件数（KEV/OSV/JVN）。DEPSCAN では保持期間超過による削除件数を表す |
| `deleted` | int | 削除件数（KEV/OSV/JVN）。DEPSCAN では解決済みにした件数を表す |
| `error_message` | string \| null | エラーメッセージ（エラー時のみ） |

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
| 毎日 JST 04:05（UTC 19:05） | GitHub Actions 単一 cron で KEV → OSV → JVN → DEPSCAN → DEPSOPS を順次実行（Upsert・古いレコード削除） |
| アプリ起動時 | DB テーブルの自動作成 |
| `POST /admin/crawl` 実行時 | KEV バックグラウンド取得（202 即時返却） |
| `POST /admin/osv-crawl` 実行時 | OSV バックグラウンド取得（202 即時返却・`?days=N` 対応） |
| `POST /admin/jvn-crawl` 実行時 | JVN バックグラウンド取得（202 即時返却・`?days=N` 対応） |
| `POST /admin/depscan-crawl` 実行時 | DEPSCAN バックグラウンド取得（202 即時返却・GitHub 全リポジトリ再スキャン） |
| `POST /admin/dependabot-ops` 実行時 | DEPSOPS バックグラウンド実行（202 即時返却・毎日 JST 08:00 自動実行 + 手動トリガー可） |

Upsertロジックの概要:
- **KEV/OSV/JVN**: 新規→INSERT、内容変更あり→UPDATE、変更なし→スキップ。新規・更新時は
  Slack通知。保持期間（既定180日、`*_RETENTION_DAYS`）超過レコードは自動削除
- **DEPSCAN**: OSV APIとリアルタイム照合。新規検知はSlack通知＋対象リポジトリへの
  GitHub Issue自動起票（未解決findingが0件になると自動クローズ）。実際の修正はDependabot
  が担当（DEPSCANは検知・通知のみ）
- **DEPSOPS**: 安全なPR（マイナー/パッチ・CIあり・コンフリクトなし）のみ自動マージ、それ
  以外はSlack通知のみで人の判断に委ねる。毎日JST 08:00に自動実行、手動実行も可能

Upsertロジック・自動化の実装詳細（フィールド単位の判定条件・GitHub権限要件等）は
リポジトリの`CLAUDE.md`を参照。
