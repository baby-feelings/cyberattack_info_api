---
name: deployment-ops
description: CI/CD（GitHub Actions）・OCI本番デプロイ手順・環境変数一覧・Prometheus/Grafana運用監視・OCI移行の教訓を扱う。deploy/配下の変更、本番デプロイ作業、環境変数の追加・変更、GitHub Secretsの設定、監視パネルの追加時に読む。
---

# デプロイ・CI/CD・運用監視リファレンス

## CI（ci.yml）
PR 作成・main/develop へのプッシュで自動実行。
1. `ruff check app/ tests/` — Linting
2. `mypy app/ --ignore-missing-imports` — 型チェック
3. `pytest --cov=app --cov-fail-under=90` — テスト（カバレッジ 90% 未満で失敗）
4. `htmlcov/` を GitHub Actions Artifact として 30 日間保持（Python 3.11 のみ）
5. Python 3.10 / 3.11 の matrix で並列実行

## CD（deploy.yml）— ダッシュボードのみ自動デプロイ
`dashboard/` 配下に変更がある場合のみ、main ブランチへのマージ後に自動実行。
- Vercel デプロイ: `VERCEL_TOKEN`/`VERCEL_ORG_ID`/`VERCEL_PROJECT_ID`（GitHub Secrets）
  経由のCLI実行（`vercel deploy --prod`）のみが本番デプロイを担う。Vercel側のネイティブ
  Git連携による本番自動デプロイは`dashboard/vercel.json`の`ignoreCommand`で無効化してあり、
  PRプレビューデプロイは従来通り機能する（Issue #106）。`VERCEL_TOKEN`未設定のまま放置すると
  ダッシュボードが本番に一切反映されなくなるため、明示的に`exit 1`で失敗させる
- `concurrency`（グループ`vercel-deploy-production`・`cancel-in-progress: true`）により、
  短時間に複数PRが連続マージされても最新コミットの分だけが実際にデプロイされる
- **注意:** `secrets` コンテキストは `if` 条件式で直接参照できないため、`run` ブロック内の
  シェル分岐で判定する
- バックエンド（FastAPI）は GitHub Actions からの自動デプロイは無く、
  `deploy/deploy_to_oci.ps1` を都度手動実行する運用

## 毎日クロール（daily-crawl.yml）
「ネットワーク障害等でAPSchedulerが不発火だった場合の二重バックアップ」として維持。
**単一 cron（`5 19 * * *` / JST 翌 04:05）で KEV → OSV → JVN → DEPSCAN → CODESCAN → DEPSOPS
を順次実行**（GitHub Actions 無料プランでは複数 cron の発火が不安定なため単一 cron に統合）。

| 実行順 | ジョブ | 対象 |
|--------|--------|------|
| 1 | `wake-up` | ヘルスチェック |
| 2 | `crawl-kev` | `POST /admin/crawl` |
| 3 | `crawl-osv` | `POST /admin/osv-crawl`（timeout 600s） |
| 4 | `crawl-jvn` | `POST /admin/jvn-crawl`（timeout 600s） |
| 5 | `crawl-depscan` | `POST /admin/depscan-crawl`（timeout 600s） |
| 6 | `crawl-codescan` | `POST /admin/codescan-crawl`（timeout 600s） |
| 7 | `dependabot-ops` | `POST /admin/dependabot-ops` |

各ジョブは `always()` で前段の失敗に関わらず実行。`workflow_dispatch` で手動実行可能
（`target: kev / osv / jvn / depscan / codescan / dependabot-ops / all`）。`API_BASE_URL`は
OCIインスタンスのドメイン（インスタンスを作り直した場合はここも更新）。GitHub Secretsに
`API_KEY`の設定が必要。

## OCI本番デプロイ手順（手動、都度実行）
1. **SCP転送**: `deploy/deploy_to_oci.ps1`相当の手順、または変更範囲に応じて個別に
   `scp -i <key> -r .\app\* ubuntu@168.138.213.240:/home/ubuntu/cyberattack_info_api/app/`
   （DBスキーマ変更があれば`alembic.ini`・`alembic/`も転送）
2. **再ビルド・起動**: `ssh` で
   `cd /home/ubuntu/cyberattack_info_api/deploy && docker compose up -d --build api-prod caddy prometheus grafana node-exporter`
3. **ヘルスチェック・機能検証**: `curl https://168.138.213.240.nip.io/health` +
   変更に対応するエンドポイントの実データ確認
4. **ビルドキャッシュ掃除**: `docker image prune -f && docker builder prune -af`
   （デプロイのたびにビルドキャッシュ・タグなしイメージが蓄積するため。自動クリーンアップの
   crontab/systemdタイマーは意図的に設置せず、手動デプロイのたびに掃除する方式に統一）

DBマイグレーションは`Dockerfile`の`CMD`（`python -m app.core.migrate && uvicorn ...`）で
コンテナ起動時に自動適用される。ファイルが削除されたPRをデプロイする際は、SCPが削除を
反映しないため、リモート側の不要ファイルを`ssh`で手動削除すること。

## デプロイ構成

| 役割 | サービス | 備考 |
|------|---------|------|
| **アプリサーバー** | OCI（Compute VM、Ampere A1） | Docker Compose、手動デプロイ |
| **データベース** | Neon（PostgreSQL 16） | Free プラン、0.5 GB |
| **ダッシュボード** | Vercel | `deploy.yml`経由で自動デプロイ |
| **CI/CD** | GitHub Actions | PR → CI → Merge → Vercel自動デプロイ。バックエンドは手動 |

**稼働先**: `cyberattack-info-api`インスタンス（Ampere A1、1 OCPU/6GB、Ubuntu 24.04 aarch64、
IP `168.138.213.240`）。

### 環境変数（`.env.production`、OCIへ転送）
`DATABASE_URL`・`API_KEY`・`ENVIRONMENT=production`・`GITHUB_USERNAME`
（**未設定だとアプリが起動しない**）・`GITHUB_TOKEN`
（DEPSCAN/DEPSOPS/CODESCAN共用PAT。Contents: Read-only + Issues: Write + Pull requests:
Write推奨）・`GITHUB_OAUTH_CLIENT_ID`/`GITHUB_OAUTH_CLIENT_SECRET`/`SESSION_SECRET_KEY`
（DEPSCAN/CODESCAN共有のダッシュボードログイン用、未設定だと`/auth/*`が503を返すのみで
DEPSCAN・CODESCAN両タブが機能しない）・`TOKEN_ENCRYPTION_KEY`（ユーザー別Slack通知登録
〈Issue #227〉用、GitHubアクセストークンをDBへ暗号化保存するFernet鍵。未設定時は登録済み
ユーザーの定期実行が機能しない）・`FRONTEND_URL`・`API_BASE_URL_FOR_OAUTH`（GitHub
OAuth Appのcallback URLとscheme含め一致させる必要あり。インスタンスを作り直した場合は
`.env.production`・`app/core/config.py`のデフォルト値・GitHub OAuth Appのcallback URLの
3箇所を同時に更新）・`METRICS_API_KEY`（運用監視、任意）。`SLACK_WEBHOOK_URL`は
Issue #227でダッシュボードからのユーザー別登録方式（`UserAccount`テーブル）に移行済みで、
もはや参照されない（設定していても無害だが不要）。

### GitHub Secrets

| Secret 名 | 説明 |
|-----------|------|
| `API_KEY` | OCI の `.env.production` と同じ値（daily-crawl.yml用） |
| `VERCEL_TOKEN` | ダッシュボード本番デプロイの唯一の経路のため必須 |
| `VERCEL_ORG_ID` / `VERCEL_PROJECT_ID` | `dashboard/`で`vercel link`実行時に生成される`.vercel/project.json`から取得 |

## OCI運用上の注意点（Issue #165、移行完了済み）
- crypto_forecast（`crypto-bot-server`）とAlways FreeのAmpere A1枠（合計4 OCPU/24GB）を
  共有するため、新規インスタンス作成前に残り容量を確認すること
- ポート80/443の開放はOCIセキュリティリストとインスタンスOS側の両方が必要。
  **本インスタンスはufwではなくiptables + iptables-persistentで管理されている**
  （crypto_forecastと異なる点）: `sudo iptables -I INPUT <ufwの手前> -p tcp -m state
  --state NEW -m tcp --dport <port> -j ACCEPT` → `sudo netfilter-persistent save`
- **ディスク容量管理**: 上記デプロイ手順のステップ4で毎回掃除する（稼働中コンテナが参照
  するイメージは対象外のため安全）

**教訓（`.env.production`取り扱いの事故）**: 秘密情報ファイルを`cat`/`awk -F=`等の
全内容表示コマンドで確認すると値が露出する（`=`を含まない行はそのまま出力されるため
`awk -F=`でも防げない）。キー名だけの確認には`grep -oE '^[A-Z_]+='`、行数確認には
`grep -c '^KEY='`を使う。ファイルへの追記前は末尾に改行があるか確認する。`python3`は
この環境ではWindowsストアの無効なスタブのため使わず`python`を使う。

**教訓（`.env.prod`と`.env.production`の二重管理事故）**: 別ファイルを2つ運用すると
秘密情報ローテーション時に片方だけ更新し忘れる事故が起きる（実際に本番ログイン不能障害が
発生した）。`.env.production`を唯一の本番設定ファイルとしてそのままOCIへ転送する構成に
統一済み。同じ内容を持つはずのファイルを2つ運用しないこと（DRY原則）。

## 運用監視（Prometheus + Grafana、Issue #167）
- **`app/core/metrics.py`**: `Authorization: Bearer`（`METRICS_API_KEY`、未設定時は
  503でopt-in）で保護する`/metrics`エンドポイント。クローラー実行結果を
  `crawler_last_run_success`/`_timestamp_seconds`/`_duration_seconds`/`_inserted`/
  `_updated`/`_deleted`のGauge（`crawler_type`ラベル付き）として公開する。Counterでは
  なくGaugeなのは「直近の実行結果」を一目で見たいため
- **`deploy/docker-compose.yml`**: `prometheus`（30秒間隔でスクレイプ、`127.0.0.1`のみ
  バインド）・`node-exporter`・`grafana`（Caddy経由でHTTPS公開）。**`node-exporter`の
  `/:/host:ro,rslave`マウントはWindows Docker Desktop（WSL2）ではエラーになる**が、
  OCI（ネイティブLinux）では問題ない（ローカル検証時は`--no-deps prometheus grafana`で除外）
- **`deploy/grafana/`**: `provisioning/datasources/prometheus.yml`で`uid: prometheus_ds`
  を固定（自動生成uidだと再プロビジョニングのたびに変わりダッシュボードJSON側の参照が
  壊れるため）
- **Grafana管理者ユーザー名の変更**: `GF_SECURITY_ADMIN_USER`は初回シードのみに効くため、
  既存adminユーザーの改名にはGrafana API（`PUT /api/users/:id`）が必要

## 環境ファイル

| ファイル | 用途 | Git 管理 |
|---------|------|---------|
| `.env.example` | テンプレート（値なし） | ✅ 追跡 |
| `.env.development` | ローカル開発（SQLite） | ❌ gitignore |
| `.env.production` | 本番設定（Neon PostgreSQL） | ❌ gitignore |
| `.env.test` | テスト実行用 | ❌ gitignore |

## lifespan の scan_results テーブル削除はベストエフォート
旧スキャン機能廃止に伴い、起動時に `DROP TABLE IF EXISTS scan_results` を実行しているが、
DDL 競合や権限不足で失敗してもサービスを止めないよう `try/except SQLAlchemyError` で囲んである。

## 依存パッケージの脆弱性スキャン（OSV-Scanner / pip-audit）とセキュリティピン留め
`osv-scanner-pr.yml`（PRで新規導入された脆弱性のみ差分検出）・`osv-scanner-scheduled.yml`/
`pip-audit.yml`（本リポジトリ自身の`requirements.txt`を週次・mainマージ時にスキャン）が
CIで自動実行される。間接依存（他パッケージ経由で入る依存）に明示的なバージョン下限が無いと、
スキャナーが「理論上インストールされ得る最古のバージョン」を対象に既知CVEを検出することがある
（実際に`pip`が解決するバージョンがそれより新しくても指摘される）。対応方針は`requirements.txt`
末尾の「セキュリティピン留め」セクションに、実際にpipが解決するバージョンを下限として明示的に
追加し、なぜそのパッケージ・バージョンが必要かをコメントで残すこと（例: `anyio>=4.14.2`は
`httpx`/`starlette`経由の間接依存でGHSA-5p39-cfhj-2xmp対策、`python-multipart>=0.0.31`は
`fastapi`の`python-multipart`extra経由の間接依存対策）。`semgrep`（CODESCAN用）のように
特定パッケージが他パッケージのバージョン範囲を狭く固定している場合（例: `pyjwt~=2.13.0`）、
自プロジェクト側の同名パッケージのバージョン指定と競合して`pip install`が
`ResolutionImpossible`になることがあるため、上げすぎず両立する範囲に収める。

## CORS・Swagger の本番制限
- CORS: 本番は `["https://cyberattackinfoapi.vercel.app"]` のみ許可。開発時は localhost も追加
- Swagger UI / ReDoc: `settings.ENVIRONMENT != "production"` の場合のみ有効
- **`allow_methods`に新しいHTTPメソッドを使うエンドポイントを追加したら必ず更新する**:
  `PUT/DELETE /auth/notification-settings`（Issue #227）追加時、CORSミドルウェアの
  `allow_methods`に`GET`/`POST`しか含まれておらず、ブラウザからのプリフライト
  （OPTIONS）が失敗しダッシュボードから呼び出せない不具合が本番で実際に発生した
  （`app/main.py`）。新しいメソッドを使うエンドポイントを追加する際は、ローカルの
  `pytest`だけでは検知できない（`TestClient`はブラウザのCORS制約を再現しないため）
  ことに注意し、`allow_methods`/`allow_headers`も忘れず更新すること
