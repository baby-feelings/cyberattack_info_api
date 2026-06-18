# Cyberattack Info API — スキルガイド

Claude Code や AI エージェントがこの API を「スキル（道具）」として活用するためのリファレンスです。

---

## 概要

| 項目 | 内容 |
|------|------|
| **ベース URL（本番）** | `https://cyberattack-info-api.onrender.com` |
| **ベース URL（開発）** | `http://localhost:8000` |
| **認証方式** | `X-API-KEY` リクエストヘッダー |
| **レスポンス形式** | JSON |
| **データソース** | CISA KEV（毎日 JST 04:05）／OSV API（毎日 JST 05:05）／JVN MyJVN API（毎日 JST 06:05） |
| **Swagger UI** | `https://cyberattack-info-api.onrender.com/docs` |

---

## 認証

全エンドポイント（`/health` を除く）に `X-API-KEY` ヘッダーが必要です。

```bash
# 環境変数から API キーを渡す（推奨）
export CYBERATTACK_API_KEY="your-secret-key"
curl -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/vulnerabilities"
```

キーが不正または未設定の場合は `403 Forbidden` が返ります。

---

## スキル一覧

### スキル 1: 直近の脅威を取得する（CISA KEV）

**用途:** 「最近 N 日間に新たに悪用が確認された脆弱性」を一括取得する。

```bash
# 直近 30 日（デフォルト）
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/vulnerabilities/recent"

# 直近 7 日
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/vulnerabilities/recent?days=7"
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
  "https://cyberattack-info-api.onrender.com/api/vulnerabilities?search=Apache"

# ベンダー完全一致
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/vulnerabilities?vendor=Microsoft"

# 製品名部分一致
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/vulnerabilities?product=Exchange"
```

| パラメータ | 型 | 説明 |
|-----------|-----|------|
| `page` | int | ページ番号（デフォルト: 1） |
| `per_page` | int | 件数（デフォルト: 50、最大: 500） |
| `search` | string | ベンダー名・製品名の部分一致 |
| `vendor` | string | ベンダー名の完全一致 |
| `product` | string | 製品名の部分一致 |

---

### スキル 3: CVE を 1 件取得する

**用途:** CVE ID を直接指定して詳細を取得する。

```bash
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/vulnerabilities/CVE-2021-44228"
```

存在しない CVE ID の場合は `404 Not Found` が返ります（大文字小文字不問）。

---

### スキル 4: 統計情報を取得する（CISA KEV）

**用途:** ベンダー別ランキングや月別トレンドを把握する。定期レポートや分析に活用。

```bash
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/vulnerabilities/stats"
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

**用途:** OSV データベースから特定エコシステム・重要度の脆弱性を検索する（直近 30 日）。  
対象: PyPI / npm / Go / Maven / RubyGems / NuGet / crates.io / Packagist / Hex の主要パッケージ。

```bash
# PyPI の HIGH 以上の脆弱性を取得
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/osv?ecosystem=PyPI&severity=HIGH"

# パッケージ名で検索
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/osv?search=django"

# CRITICAL のみ全エコシステムで取得（CVSS スコア降順）
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/osv?severity=CRITICAL&sort_by=cvss"
```

| パラメータ | 型 | 説明 |
|-----------|-----|------|
| `page` | int | ページ番号（デフォルト: 1） |
| `per_page` | int | 件数（デフォルト: 50、最大: 500） |
| `ecosystem` | string | エコシステム名（`PyPI` / `npm` / `Go` 等） |
| `severity` | string | 重要度（`CRITICAL` / `HIGH` / `MEDIUM` / `LOW`） |
| `search` | string | パッケージ名の部分一致 |
| `sort_by` | string | ソート基準（`modified`（デフォルト） / `cvss`） |

---

### スキル 6: OSV 統計情報を取得する

**用途:** エコシステム別・重要度別の脆弱性件数や月別トレンドを把握する。

```bash
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/osv/stats"
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

**用途:** JVN (Japan Vulnerability Notes) から日本国内の脆弱性情報を検索する（直近 30 日）。  
MyJVN API（jvndb.jvn.jp）から取得した JVNDB 登録脆弱性を対象とする。

```bash
# High 重要度の脆弱性を取得
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/jvn?severity=High"

# キーワードで検索
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/jvn?search=Apache"

# CVSS スコア降順で取得
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/jvn?sort_by=cvss"
```

| パラメータ | 型 | 説明 |
|-----------|-----|------|
| `page` | int | ページ番号（デフォルト: 1） |
| `per_page` | int | 件数（デフォルト: 50、最大: 500） |
| `severity` | string | 重要度（`High` / `Medium` / `Low`） |
| `search` | string | JVNDB ID・タイトル・概要の部分一致 |
| `sort_by` | string | ソート基準（`modified`（デフォルト） / `cvss`） |
| `days` | int | 取得対象の直近日数（デフォルト: 30） |

---

### スキル 8: JVN 統計情報を取得する

**用途:** 重要度別の JVN 脆弱性件数や月別トレンドを把握する。

```bash
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/jvn/stats"
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

### スキル 9: クローラーの実行ログを確認する

**用途:** KEV / OSV / JVN クローラーが正常に動作しているか、最新の実行結果（件数・所要時間・エラー）を確認する。

```bash
# 直近 10 件の実行ログを取得
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/crawler-logs?limit=10"

# JVN のみ絞り込み
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/crawler-logs?crawler_type=JVN"

# エラーのみ確認
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/crawler-logs?status=error"
```

| パラメータ | 型 | 説明 |
|-----------|-----|------|
| `crawler_type` | string | `KEV` / `OSV` / `JVN`（省略時は全種別） |
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

### スキル 10: サービス状態を確認する

**用途:** API サーバーと DB が正常稼働しているか確認する。

```bash
curl -s "https://cyberattack-info-api.onrender.com/health"
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

## Claude Code での活用パターン

### パターン 1: 直近の脅威を分析させる

```bash
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/vulnerabilities/recent?days=30" \
  | claude -p "これらの脆弱性のうち、Python / FastAPI プロジェクトに影響するものを
               優先度順に整理し、対策案を教えてください"
```

### パターン 2: CI/CD でクローラー死活監視を自動化する

```yaml
# .github/workflows/crawler-health.yml の例
- name: Check crawler health
  run: |
    RESULT=$(curl -s -H "X-API-KEY: ${{ secrets.CYBERATTACK_API_KEY }}" \
      "https://cyberattack-info-api.onrender.com/api/crawler-logs?limit=3&crawler_type=JVN")
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
  "https://cyberattack-info-api.onrender.com/api/vulnerabilities/CVE-2021-44228" \
  | claude -p "この脆弱性の影響と対策を日本語で説明してください"
```

### パターン 4: OSV で使用ライブラリのリスクを確認する

```bash
# 使用中の PyPI パッケージに CRITICAL な OSV 脆弱性がないか確認
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/osv?ecosystem=PyPI&severity=CRITICAL" \
  | claude -p "自分のプロジェクトで使っているパッケージが含まれているか確認し、
               影響があれば修正バージョンを教えてください"
```

### パターン 5: JVN で国内脆弱性の最新動向を把握する

```bash
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/jvn?severity=High&sort_by=cvss" \
  | claude -p "直近の高重要度 JVN 脆弱性を整理し、対処優先度を教えてください"
```

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

### CrawlerLogOut（クローラー実行ログ）

| フィールド | 型 | 説明 |
|-----------|-----|------|
| `id` | int | ログ ID |
| `crawler_type` | string | クローラー種別（`KEV` / `OSV` / `JVN`） |
| `status` | string | 実行結果（`success` / `error`） |
| `started_at` | string (ISO 8601) | 開始日時 |
| `finished_at` | string (ISO 8601) | 終了日時 |
| `duration_seconds` | float | 所要時間（秒） |
| `inserted` | int | 新規挿入件数 |
| `updated` | int | 更新件数 |
| `deleted` | int | 削除件数（OSV のみ） |
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
| 毎日 JST 04:05（UTC 19:05） | GitHub Actions が CISA KEV フィードを取得し Upsert |
| 毎日 JST 05:05（UTC 20:05） | GitHub Actions が OSV API から主要パッケージの脆弱性を取得・Upsert・古いレコード削除 |
| 毎日 JST 06:05（UTC 21:05） | GitHub Actions が MyJVN API から JVN 脆弱性を取得・Upsert |
| アプリ起動時 | DB テーブルの自動作成 |
| `POST /admin/crawl` 実行時 | KEV 即時取得（スケジュール外） |
| `POST /admin/osv-crawl` 実行時 | OSV 即時取得（スケジュール外） |
| `POST /admin/jvn-crawl` 実行時 | JVN 即時取得（スケジュール外） |

Upsert ロジック:

**CISA KEV:**
- **新規 CVE** → INSERT → Slack 通知（`SLACK_WEBHOOK_URL` 設定時）
- **既存 CVE で内容変更あり** → UPDATE → Slack 通知
- **既存 CVE で変更なし** → スキップ

**OSV:**
- **新規レコード** → INSERT
- **既存レコードで `modified` 更新あり** → UPDATE
- **既存レコードで変更なし** → スキップ
- **`modified` が 180 日以上前のレコード** → 自動削除（`OSV_RETENTION_DAYS` で変更可）
- クロール完了後（新規・更新あり）→ Slack 通知（`SLACK_WEBHOOK_URL` 設定時）

**JVN:**
- **新規 JVNDB エントリ** → INSERT
- **既存エントリで `date_last_modified` 更新あり** → UPDATE
- **既存エントリで変更なし** → スキップ
- クロール完了後（新規・更新あり）→ Slack 通知（`SLACK_WEBHOOK_URL` 設定時）
- 実行結果は `crawler_logs` テーブルに自動記録
