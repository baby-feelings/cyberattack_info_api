# レスポンスフィールド定義

各エンドポイントのレスポンススキーマのフィールド定義。SKILL.mdから分離（500行制限対応）。

---

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
| `cve_ids` | string[] | OSVエントリのaliasesから抽出したCVE ID一覧（無ければ空配列） |
| `purl` | string \| null | パッケージURL（例: `pkg:pypi/cryptography@3.4.7`）。他のSBOM/SCAツールとの相互運用用（Issue #133） |
| `manifest_path` | string | 検知元のロックファイルパス（例: `dashboard/package-lock.json`） |
| `reachability` | string \| null | 到達可能性のヒューリスティック判定（`reachable` / `unreachable` / `unknown`）。脆弱なパッケージがソースコード内で import/require/use されているかを判定（関数呼び出しレベルの解析は行わない best-effort） |
| `repo_visibility` | string \| null | 対象リポジトリの公開範囲（`public` / `private`）。GitHub APIから自動取得（Issue #131） |
| `asset_context` | object \| null | 資産コンテキスト（`is_production`・`is_internet_facing`・`importance`）。`PUT /admin/depscan/assets/{owner}/{repo}`で手動設定。未設定なら `null`（Issue #131） |
| `priority_reasons` | string[] | 優先度判定に寄与した要因（`kev_listed` / `epss_high` / `reachable` / `public_repo` / `internet_facing_asset` / `production_asset` / `high_importance_asset`）。Issue #135 |
| `detected_at` | string (ISO 8601) | 初回検知日時 |
| `resolved_at` | string \| null (ISO 8601) | 解決日時（未解決なら `null`） |

### CodeFindingOut（CODESCAN 検知結果）

| フィールド | 型 | 説明 |
|-----------|-----|------|
| `repo_full_name` | string | 検知元リポジトリ（例: `baby-feelings/baby_grow`） |
| `file_path` | string | リポジトリルートからの相対パス |
| `line_start` / `line_end` | int | 該当コードの開始行・終了行 |
| `rule_id` | string | 検知ルールid（Semgrep例: `python.lang.security.audit.hardcoded-password`。gitleaksは`gitleaks:`プレフィックス付き、例: `gitleaks:aws-access-token`） |
| `message` | string | 検知内容の説明 |
| `severity` | string | 重要度（`ERROR` / `WARNING` / `INFO`。Semgrep検知はSemgrepのseverityそのまま、gitleaks検知は常に`ERROR`固定。ダッシュボードでは「重大/警告/情報」の日本語表示に変換される） |
| `tool` | string | 検知したツール（`semgrep` / `gitleaks`。Issue #219） |
| `cwe_ids` | string[] | CWE ID一覧（無ければ空配列） |
| `owasp_categories` | string[] | OWASPカテゴリ一覧（無ければ空配列） |
| `code_snippet` | string | 該当コード抜粋。gitleaks検知の場合はシークレットの実値を含めず、`検知内容: {ルールの説明}`という固定文言のみ（漏洩防止） |
| `cvss_score` | float \| null | CVSS 3.1基本値。Semgrepのseverity・CWEからのベストエフォート推定値であり、精度は保証しない（`.claude/skills/codescan/SKILL.md`参照） |
| `cvss_vector` | string \| null | CVSS 3.1ベクター文字列（同上、ベストエフォート） |
| `detected_at` | string (ISO 8601) | 初回検知日時 |
| `resolved_at` | string \| null (ISO 8601) | 解決日時（未解決なら `null`） |

### DependabotPrLogOut（DEPSOPS の PR 判定履歴）

| フィールド | 型 | 説明 |
|-----------|-----|------|
| `repo_full_name` | string | 対象リポジトリ（例: `baby-feelings/baby_grow`） |
| `pr_number` | int | Dependabot PR 番号 |
| `title` | string | PR タイトル |
| `action` | string | 判定結果（`merged`: 自動マージ済み / `flagged`: 要確認。解決済みのPRは履歴ごと削除されるため2種のみ） |
| `reason` | string \| null | `action=flagged` の場合の理由（メジャーバージョンアップ等）。`merged` の場合は `null` |
| `is_security_update` | bool \| null | セキュリティ更新（GitHub Dependabot alertの対象パッケージと一致）のヒューリスティック判定。`true`=セキュリティ更新の可能性が高い / `false`=通常のバージョン更新 / `null`=判定不能（`GITHUB_TOKEN` に Dependabot alerts の読み取り権限が無い等） |
| `compatibility_badge_url` | string \| null | Dependabot が PR 本文に埋め込む Compatibility score バッジ画像のURL。exact version bump のPRにのみ存在し、範囲指定の requirement 更新PR等は `null` |
| `processed_at` | string (ISO 8601) | 判定を行った DEPSOPS 実行日時 |

### CrawlerLogOut（クローラー実行ログ）

| フィールド | 型 | 説明 |
|-----------|-----|------|
| `id` | int | ログ ID |
| `crawler_type` | string | クローラー種別（`KEV` / `OSV` / `JVN` / `DEPSCAN` / `DEPSOPS` / `CODESCAN`） |
| `status` | string | 実行結果（`success` / `error`） |
| `started_at` | string (ISO 8601) | 開始日時 |
| `finished_at` | string (ISO 8601) | 終了日時 |
| `duration_seconds` | float | 所要時間（秒） |
| `inserted` | int | 新規挿入件数 |
| `updated` | int | 更新件数（KEV/OSV/JVN）。DEPSCAN/CODESCAN では保持期間超過による削除件数を表す |
| `deleted` | int | 削除件数（KEV/OSV/JVN）。DEPSCAN/CODESCAN では解決済みにした件数を表す |
| `error_message` | string \| null | エラーメッセージ（エラー時のみ） |

