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
| **データソース** | CISA KEV Catalog（毎日 JST 04:00 自動更新）／OSV API（毎日 JST 05:00 自動更新） |
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

**用途:** CVE ID を直接指定して詳細を取得する。スキャン結果の CVE ID からの詳細確認に便利。

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

**用途:** OSV データベースから特定エコシステム・重要度の脆弱性を検索する。  
対象: PyPI / npm / Go / Maven / RubyGems / NuGet / crates.io / Packagist / Hex の主要パッケージ。

```bash
# PyPI の HIGH 以上の脆弱性を取得
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/osv?ecosystem=PyPI&severity=HIGH"

# パッケージ名で検索
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/osv?search=django"

# CRITICAL のみ全エコシステムで取得
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/osv?severity=CRITICAL"
```

| パラメータ | 型 | 説明 |
|-----------|-----|------|
| `page` | int | ページ番号（デフォルト: 1） |
| `per_page` | int | 件数（デフォルト: 50、最大: 500） |
| `ecosystem` | string | エコシステム名（`PyPI` / `npm` / `Go` 等） |
| `severity` | string | 重要度（`CRITICAL` / `HIGH` / `MEDIUM` / `LOW`） |
| `search` | string | パッケージ名の部分一致 |

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

### スキル 7: ライブラリの脆弱性をスキャンする

**用途:** 使用しているパッケージを OSV + CISA KEV の両方で横断診断する。

#### パッケージリストでスキャン

```bash
curl -s -X POST \
  -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"packages":[{"name":"fastapi","version":"0.115.6"},{"name":"requests","version":"2.32.0"}]}' \
  "https://cyberattack-info-api.onrender.com/api/scan"
```

#### requirements.txt をそのままスキャン（Python）

```bash
curl -s -X POST \
  -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  -H "Content-Type: text/plain" \
  --data-binary @requirements.txt \
  "https://cyberattack-info-api.onrender.com/api/scan/requirements"
```

#### package.json をそのままスキャン（npm）

```bash
curl -s -X POST \
  -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  -H "Content-Type: text/plain" \
  --data-binary @package.json \
  "https://cyberattack-info-api.onrender.com/api/scan/package-json"
```

**スキャンレスポンス例:**
```json
{
  "scanned_packages": 10,
  "total_findings": 1,
  "findings": [
    {
      "package_name": "python-dotenv",
      "package_version": "1.0.1",
      "source": "OSV",
      "vuln_id": "CVE-2026-28684",
      "severity": "MODERATE",
      "summary": "Symlink following in set_key allows arbitrary file overwrite",
      "fixed_versions": ["1.2.2"],
      "references": ["https://github.com/theskumar/python-dotenv/security/advisories/..."]
    }
  ]
}
```

---

### スキル 8: スキャン履歴を参照する

**用途:** 過去のスキャン結果を振り返る。CI/CD で定期実行した結果の差分確認に活用。

```bash
# 履歴一覧（最新 20 件）
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/scan/history"

# 特定スキャンの詳細
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/scan/history/1"
```

---

### スキル 9: サービス状態を確認する

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

### パターン 2: プロジェクトの依存関係をまとめて診断する

```bash
curl -s -X POST \
  -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  -H "Content-Type: text/plain" \
  --data-binary @requirements.txt \
  "https://cyberattack-info-api.onrender.com/api/scan/requirements" \
  | claude -p "検出された脆弱性への対応策と優先度を教えてください"
```

### パターン 3: CI/CD に組み込んで脆弱性チェックを自動化する

```yaml
# .github/workflows/security-check.yml の例
- name: Scan dependencies
  run: |
    RESULT=$(curl -s -X POST \
      -H "X-API-KEY: ${{ secrets.CYBERATTACK_API_KEY }}" \
      -H "Content-Type: text/plain" \
      --data-binary @requirements.txt \
      "https://cyberattack-info-api.onrender.com/api/scan/requirements")
    FINDINGS=$(echo "$RESULT" | python -c "import sys,json; print(json.load(sys.stdin)['total_findings'])")
    echo "脆弱性検出数: $FINDINGS 件"
    if [ "$FINDINGS" -gt 0 ]; then
      echo "$RESULT" | python -m json.tool
      exit 1
    fi
```

### パターン 4: 特定 CVE の詳細を素早く調べる

```bash
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/vulnerabilities/CVE-2021-44228" \
  | claude -p "この脆弱性の影響と対策を日本語で説明してください"
```

### パターン 5: OSV で使用ライブラリのリスクを確認する

```bash
# 使用中の PyPI パッケージに CRITICAL な OSV 脆弱性がないか確認
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/osv?ecosystem=PyPI&severity=CRITICAL" \
  | claude -p "自分のプロジェクトで使っているパッケージが含まれているか確認し、
               影響があれば修正バージョンを教えてください"
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

### VulnerabilityFinding（スキャン検出結果）

| フィールド | 型 | 説明 |
|-----------|-----|------|
| `package_name` | string | パッケージ名 |
| `package_version` | string \| null | スキャンしたバージョン |
| `source` | string | 情報源（`OSV` / `CISA_KEV`） |
| `vuln_id` | string | 脆弱性 ID（CVE-xxxx または OSV ID） |
| `severity` | string \| null | 重要度（`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `MODERATE`） |
| `summary` | string | 脆弱性の概要 |
| `details` | string \| null | 詳細説明 |
| `fixed_versions` | string[] | 修正済みバージョン一覧 |
| `references` | string[] | 参考 URL 一覧（最大 5 件） |

---

## エラーレスポンス

| HTTP ステータス | 原因 |
|--------------|------|
| `403 Forbidden` | `X-API-KEY` が不正または未設定 |
| `404 Not Found` | 指定した CVE ID またはスキャン ID が存在しない |
| `422 Unprocessable Entity` | リクエストボディ・パラメータの形式エラー |
| `500 Internal Server Error` | サーバー内部エラー |

---

## データ更新スケジュール

| タイミング | 処理 |
|----------|------|
| 毎日 JST 04:00（UTC 19:00） | CISA KEV フィードを取得し Upsert |
| 毎日 JST 05:00（UTC 20:00） | OSV API から主要パッケージの脆弱性を取得・Upsert・古いレコード削除 |
| アプリ起動時 | DB テーブルの自動作成 |
| `POST /admin/crawl` 実行時 | KEV 即時取得（スケジュール外） |
| `POST /admin/osv-crawl` 実行時 | OSV 即時取得（スケジュール外） |

Upsert ロジック:

**CISA KEV:**
- **新規 CVE** → INSERT → Slack 通知（`SLACK_WEBHOOK_URL` 設定時）
- **既存 CVE で内容変更あり** → UPDATE
- **既存 CVE で変更なし** → スキップ

**OSV:**
- **新規レコード** → INSERT
- **既存レコードで `modified` 更新あり** → UPDATE
- **既存レコードで変更なし** → スキップ
- **`modified` が 180 日以上前のレコード** → 自動削除（`OSV_RETENTION_DAYS` で変更可）
- クロール完了後（新規・更新あり）→ Slack 通知（`SLACK_WEBHOOK_URL` 設定時）
