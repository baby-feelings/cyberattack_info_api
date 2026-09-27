# API エンドポイント詳細 2/2: DEPSOPS・CODESCAN・運用系・活用パターン

各エンドポイントの詳細なcurl例・パラメータ表・レスポンス例。KEV/OSV/JVN/DEPSCANは reference/endpoints-feeds.md 参照。

---

### スキル 13: Dependabot PR 自動運用（DEPSOPS）の判定履歴を確認する

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
> （詳細は `.claude/skills/depscan-depsops/SKILL.md` の「DEPSOPS」節参照）。ダッシュボードの
> 「未解決」件数計算はこれを`flagged`と区別して除外するため、実態に合った件数になる。

---

### スキル 13.5: 自アプリのコード脆弱性を確認する（CODESCAN）

**用途:** GitHub上の自作アプリ全リポジトリのソースコードをSemgrep（`p/security-audit`
+ `p/secrets`）で静的解析した結果を確認する。DEPSCAN（依存ライブラリの既知脆弱性）
とは異なり、SQLi・ハードコード認証情報・XSS等、自アプリのコード自体に潜む脆弱性
パターンを検知する。CVSSスコアはベストエフォート推定であり精度は保証しない
（詳細は `.claude/skills/codescan/SKILL.md` 参照）。認証は KEV/OSV/JVN と同じ
`X-API-KEY`（`API_KEY` または `PUBLIC_API_KEY`）で、DEPSCANのようなGitHubログイン
によるオーナー制限は無い。

```bash
# 未解決かつCVSS 7.0以上（要対応優先度が高いもの）
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/codescan?resolved=false&min_cvss=7.0"

# 特定リポジトリのみ絞り込み
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/codescan?repo=baby-feelings/baby_grow"

# 統計情報（リポジトリ別・重要度別件数、未解決分のみ）
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/api/codescan/stats"
```

| パラメータ | 型 | 説明 |
|-----------|-----|------|
| `page` | int | ページ番号（デフォルト: 1） |
| `per_page` | int | 件数（デフォルト: 50、最大: 200） |
| `repo` | string | リポジトリ名で絞り込み（完全一致。例: `owner/repo`） |
| `owner` | string | リポジトリオーナーで絞り込み（例: `baby-feelings`） |
| `severity` | string | Semgrepの重要度で絞り込み（`ERROR` / `WARNING` / `INFO`） |
| `resolved` | bool | 解決状態で絞り込み（未指定なら全件） |
| `min_cvss` | float | CVSS基本値の下限値で絞り込み（0〜10） |

**レスポンス例:**
```json
{
  "total": 1,
  "page": 1,
  "per_page": 50,
  "data": [
    {
      "repo_full_name": "baby-feelings/baby_grow",
      "file_path": "app/main.py",
      "line_start": 10,
      "line_end": 10,
      "rule_id": "python.lang.security.audit.hardcoded-password",
      "message": "Hardcoded password detected",
      "severity": "ERROR",
      "cwe_ids": ["CWE-798: Use of Hard-coded Credentials"],
      "owasp_categories": ["A07:2021 - Identification and Authentication Failures"],
      "code_snippet": "PASSWORD = \"hunter2\"",
      "cvss_score": 7.4,
      "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
      "detected_at": "2026-09-24T00:00:00+00:00",
      "resolved_at": null
    }
  ]
}
```

> 新規検知は検知されたリポジトリ自身に GitHub Issue として自動起票される（1リポジトリ
> につき常に1つのOpen Issueに集約。タイトル `🔎 自アプリのコード脆弱性が検出されました
> (CODESCAN)`。DEPSCANのIssueとはタイトルで区別できる）。`POST /admin/codescan-crawl`
> （`X-API-KEY`必須）で手動実行できる。

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

### スキル 14: クローラーの実行ログを確認する

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

### スキル 15: サービス状態を確認する

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

### スキル 16: 運用監視ダッシュボード（Grafana）を確認する

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

### スキル 17: KEV/OSV/JVNデータをTAXII 2.1で購読する（Issue #134）

**用途:** MISP等の既存CTI共有基盤・SIEM/TIPからKEV/OSV/JVNデータを継続的に購読する
（最小構成のTAXII 2.1サーバー。単一API root配下にKEV/OSV/JVNの3コレクションを持つ）。

```bash
# Discovery（利用可能なAPI rootを確認）
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/taxii2/"

# コレクション一覧（KEV/OSV/JVNの3件が返る）
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/taxii2/cyberattack-info-api/collections/"

# コレクション内のSTIXオブジェクトを取得（コレクションIDで対象ドメインを指定）
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/taxii2/cyberattack-info-api/collections/d4d8f0c0-3f5f-5b1e-9c1a-6f6f6a6b6a6a/objects/"

# 差分取得（前回取得以降に更新されたオブジェクトのみ）
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://168.138.213.240.nip.io/taxii2/cyberattack-info-api/collections/d4d8f0c0-3f5f-5b1e-9c1a-6f6f6a6b6a6a/objects/?added_after=2026-06-01T00:00:00Z"
```

**コレクションID一覧**（固定値）:

| ドメイン | コレクションID |
|---------|----------------|
| CISA KEV | `d4d8f0c0-3f5f-5b1e-9c1a-6f6f6a6b6a6a` |
| OSV | `84be1117-7e69-58ed-a0dc-d2f2bb7f60ca` |
| JVN | `1c34f413-fd30-56cc-bf87-daf79113b5a8` |

> 認証はTAXII固有の方式ではなく、既存APIと同じ`X-API-KEY`/`Authorization: Bearer
> <PUBLIC_API_KEY>`を使う。manifestエンドポイント・フルのTAXIIページネーション
> （`Content-Range`ヘッダー等）には対応していない簡易実装（`added_after`/`limit`
> クエリパラメータのみ）。

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
