# API エンドポイント詳細 1/2: KEV・OSV・JVN・DEPSCAN（curl例・パラメータ一覧）

各エンドポイントの詳細なcurl例・パラメータ表・レスポンス例。SKILL.mdから分離（500行制限対応）。DEPSOPS/CODESCAN以降は reference/endpoints-ops.md 参照。

---

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

`?format=stix` を付けると STIX 2.1 の Vulnerability SDO 形式で返す（Issue #134。
MISP等の既存CTI共有基盤・SIEM/TIPとの連携用）:

```bash
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/vulnerabilities/CVE-2021-44228?format=stix"
```

継続的な購読には、下記スキル（TAXII 2.1配信）も利用できる。

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

`osv_id`を指定して単体取得することもできる（`(osv_id, ecosystem, package_name)`が
自然キーのため、同一`osv_id`が複数パッケージに影響する場合は複数行がリストで返る）。
`?format=stix`を付けるとSTIX 2.1 Bundle形式で返す（Issue #134）:

```bash
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/osv/GHSA-78mq-xcr3-xm33?format=stix"
```

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

JVNDB IDを直接指定して1件取得することもできる。`?format=stix`を付けるとSTIX 2.1の
Vulnerability SDO形式で返す（Issue #134）:

```bash
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/jvn/JVNDB-2026-000001?format=stix"
```

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
スキル12参照）も含まれる（Issue #131）。

さらに `priority_reasons`（文字列配列。`kev_listed`/`epss_high`/`reachable`/
`public_repo`/`internet_facing_asset`/`production_asset`/`high_importance_asset`の
いずれか0件以上）も含まれ、なぜその検知結果の優先度が高いと判断されるかを
機械可読な形で確認できる（Issue #135）。

パッケージ識別には `purl`（Package URL、`pkg:pypi/cryptography@3.4.7` 形式）も
含まれ、他のSBOM/SCAツールとの相互運用に使える（Issue #133、スキル11参照）。

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

### スキル 11: DEPSCAN検知結果をSBOM形式でエクスポートする（Issue #133）

**用途:** 指定リポジトリの検知結果をCycloneDX 1.5またはSPDX 2.3形式でエクスポートし、
他のSBOM/SCAツール（Dependency-Track・Grype等）に取り込む。パッケージ識別には
purl（Package URL）を使用する。

```bash
# CycloneDX形式（既定。脆弱性情報を含む）
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/depscan/export?repo=baby-feelings/baby_grow" \
  -o baby_grow.cdx.json

# SPDX形式（パッケージ一覧のみ。コア仕様に脆弱性を表現する概念が無いため）
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/depscan/export?repo=baby-feelings/baby_grow&format=spdx" \
  -o baby_grow.spdx.json

# 未解決の検知結果のみに絞り込む
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/depscan/export?repo=baby-feelings/baby_grow&resolved=false"
```

| パラメータ | 型 | 説明 |
|-----------|-----|------|
| `repo` | string | 対象リポジトリ（必須。例: `owner/repo`） |
| `format` | string | 出力形式（`cyclonedx` / `spdx`、デフォルト: `cyclonedx`） |
| `resolved` | bool | 解決状態で絞り込み（未指定なら全件） |

> `Content-Type`はSBOM専用のメディアタイプ（`application/vnd.cyclonedx+json` /
> `application/spdx+json`）を返す。外部SBOMの入力受け付け・VEX
> （Vulnerability Exploitability eXchange）状態拡張は現時点では未対応。

---

### スキル 12: リポジトリの資産コンテキストを設定・確認する（Issue #131）

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

