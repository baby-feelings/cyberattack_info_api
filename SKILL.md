# Cyberattack Info API — スキルガイド

Claude Code や AI エージェントがこの API を「スキル（道具）」として活用するためのリファレンスです。

---

## 概要

| 項目 | 内容 |
|------|------|
| **ベース URL（本番）** | `https://your-api.onrender.com` |
| **ベース URL（開発）** | `http://localhost:8000` |
| **認証方式** | `X-API-KEY` リクエストヘッダー |
| **レスポンス形式** | JSON |
| **データソース** | CISA KEV Catalog（毎日 JST 04:00 自動更新） |

---

## 認証

全エンドポイント（`/health` を除く）に `X-API-KEY` ヘッダーが必要です。

```bash
# 環境変数から API キーを渡す（推奨）
export CYBERATTACK_API_KEY="your-secret-key"
curl -H "X-API-KEY: $CYBERATTACK_API_KEY" "http://localhost:8000/api/vulnerabilities"
```

キーが不正または未設定の場合は `403 Forbidden` が返ります。

---

## スキル一覧

### スキル 1: 直近の脅威を取得する

**用途:** 「最近 N 日間に新たに発見・悪用が確認された脆弱性」を一括取得する。  
Claude Code のコンテキストに渡してセキュリティ分析させる主要ユースケース。

```bash
# 直近 30 日（デフォルト）
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "http://localhost:8000/api/vulnerabilities/recent"

# 直近 7 日
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "http://localhost:8000/api/vulnerabilities/recent?days=7"
```

**パラメータ:**

| パラメータ | 型 | 範囲 | デフォルト |
|-----------|-----|------|-----------|
| `days` | int | 1〜365 | 30 |

**レスポンス:** 脆弱性オブジェクトの配列

```json
[
  {
    "cve_id": "CVE-2024-12345",
    "vendor_project": "Microsoft",
    "product": "Windows",
    "vulnerability_name": "Windows Remote Code Execution Vulnerability",
    "description": "A critical vulnerability that allows...",
    "required_action": "Apply the security update immediately.",
    "date_added": "2024-06-01"
  }
]
```

---

### スキル 2: 脆弱性を検索・フィルタリングする

**用途:** ベンダー名・製品名・キーワードで絞り込んで脆弱性を検索する。

```bash
# キーワード検索（ベンダー名・製品名を部分一致）
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "http://localhost:8000/api/vulnerabilities?search=Apache"

# ベンダー完全一致
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "http://localhost:8000/api/vulnerabilities?vendor=Microsoft"

# 製品名部分一致
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "http://localhost:8000/api/vulnerabilities?product=Exchange"

# ページネーション
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "http://localhost:8000/api/vulnerabilities?page=2&per_page=20"

# 複合フィルタ
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "http://localhost:8000/api/vulnerabilities?vendor=Cisco&per_page=50"
```

**パラメータ:**

| パラメータ | 型 | 説明 |
|-----------|-----|------|
| `page` | int | ページ番号（デフォルト: 1） |
| `per_page` | int | 件数（デフォルト: 50、最大: 500） |
| `search` | string | ベンダー名・製品名の部分一致 |
| `vendor` | string | ベンダー名の完全一致 |
| `product` | string | 製品名の部分一致 |

**レスポンス:**

```json
{
  "total": 1205,
  "page": 1,
  "per_page": 20,
  "data": [ /* VulnerabilityOut の配列 */ ]
}
```

---

### スキル 3: サービス状態を確認する

**用途:** API サーバーと DB が正常稼働しているか確認する。

```bash
curl -s http://localhost:8000/health
```

**レスポンス:**

```json
{
  "status": "ok",
  "environment": "production",
  "db_connected": true
}
```

| `status` | 意味 |
|---------|------|
| `ok` | 正常稼働中 |
| `degraded` | DB 接続に問題あり |

---

## Claude Code での活用パターン

### パターン 1: 直近の脅威を分析させる

```bash
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "http://localhost:8000/api/vulnerabilities/recent?days=30" \
  | claude -p "これらの脆弱性のうち、Python / FastAPI プロジェクトに影響するものを
               CVSSスコア相当の優先度順に整理し、対策案を教えてください"
```

### パターン 2: 特定製品の脆弱性を調査させる

```bash
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "http://localhost:8000/api/vulnerabilities?product=Log4j&per_page=100" \
  | claude -p "これらの Log4j 関連脆弱性について、緊急度と影響範囲を要約してください"
```

### パターン 3: CI/CD に組み込んで脆弱性チェックを自動化する

```yaml
# .github/workflows/security-check.yml の例
- name: Check recent CVEs
  run: |
    RECENT=$(curl -s -H "X-API-KEY: ${{ secrets.CYBERATTACK_API_KEY }}" \
      "https://your-api.onrender.com/api/vulnerabilities/recent?days=7")
    echo "$RECENT" | python -c "
    import sys, json
    data = json.load(sys.stdin)
    print(f'直近 7 日間の新規 CVE: {len(data)} 件')
    for v in data[:5]:
        print(f'  - {v[\"cve_id\"]}: {v[\"vendor_project\"]} / {v[\"product\"]}')
    "
```

---

## フィールド定義

各脆弱性オブジェクト（`VulnerabilityOut`）のフィールド:

| フィールド | 型 | 説明 |
|-----------|-----|------|
| `cve_id` | string | CVE 識別子（例: `CVE-2024-12345`） |
| `vendor_project` | string | 影響を受けるベンダー・プロジェクト名 |
| `product` | string | 影響を受ける製品名 |
| `vulnerability_name` | string | 脆弱性の名称 |
| `description` | string | 脆弱性の概要説明 |
| `required_action` | string \| null | CISA が推奨する対処アクション |
| `date_added` | string (date) | KEV カタログに追加された日付（`YYYY-MM-DD`） |

---

## エラーレスポンス

| HTTP ステータス | 原因 |
|--------------|------|
| `403 Forbidden` | `X-API-KEY` が不正または未設定 |
| `422 Unprocessable Entity` | クエリパラメータの型・範囲エラー |
| `500 Internal Server Error` | サーバー内部エラー |

---

## データ更新スケジュール

| タイミング | 処理 |
|----------|------|
| 毎日 JST 04:00（UTC 19:00） | CISA KEV フィードを取得し Upsert |
| アプリ起動時 | DB テーブルの自動作成 |

Upsert ロジック:
- **新規 CVE** → INSERT
- **既存 CVE で内容変更あり** → UPDATE
- **既存 CVE で変更なし** → スキップ
