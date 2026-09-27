# Cyberattack Info API

[![CI](https://github.com/baby-feelings/cyberattack_info_api/actions/workflows/ci.yml/badge.svg)](https://github.com/baby-feelings/cyberattack_info_api/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-98%25-brightgreen)](https://github.com/baby-feelings/cyberattack_info_api/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11-blue)](https://www.python.org/)

米 CISA の [Known Exploited Vulnerabilities (KEV) Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)・[OSV (Open Source Vulnerabilities)](https://osv.dev/)・[JVN (Japan Vulnerability Notes)](https://jvndb.jvn.jp/) を定期収集し、REST API として配信するプラットフォームです。  
Claude Code や CI/CD ツールから「今まさに悪用されているサイバー脅威」をリアルタイムに取得するために最適化されています。

詳細なドキュメントは [docs/](docs/) 配下に分離しています（本READMEはトップレベルの概要のみ）。

---

## 機能

| 機能 | 説明 |
|------|------|
| **KEV / OSV / JVN 自動クローラー** | 毎日 JST 04:05 に KEV → OSV → JVN → DEPSCAN → CODESCAN → DEPSOPS を順次実行（各フィード取得・Upsert） |
| **依存ライブラリ脆弱性スキャン（DEPSCAN）** | GitHub 上の自作アプリ全リポジトリのロックファイルを OSV API とリアルタイム照合。新規検知はリポジトリへ GitHub Issue も自動起票し、解消を確認すると自動クローズ |
| **自アプリコード脆弱性診断（CODESCAN）** | GitHub 上の自作アプリ全リポジトリのソースコードを Semgrep + gitleaks で静的解析。CVSSはベストエフォート推定 |
| **Dependabot PR 自動運用（DEPSOPS）** | 安全性の高い Dependabot PR（マイナー/パッチ・CIあり・コンフリクトなし）のみ自動マージ、それ以外はSlack通知 |
| **DEPSCAN/CODESCAN ダッシュボードの GitHub ログイン** | 任意の GitHub アカウントでログインし、本人が所有するリポジトリの検知結果のみ閲覧可能 |
| **ユーザー別 Slack 通知登録** | ダッシュボードから任意の GitHub アカウントで自分専用の Slack Webhook を登録可能（詳細: [docs/slack-notifications.md](docs/slack-notifications.md)） |
| **削除済みリポジトリ・古いデータの自動削除** | GitHub上で削除確認できたリポジトリのデータ、保持期間超過レコードを自動削除 |
| **運用監視** | Prometheus + Grafana によるクローラー実行結果・ホストリソースの可視化（OCI上、任意） |
| **一覧・統計・実行ログ API** | ページネーション・検索・フィルタリング対応（詳細: [docs/api-reference.md](docs/api-reference.md)） |
| **React ダッシュボード** | KEV・OSV・JVN・DEPSCAN・CODESCANを画面下部固定タブで切り替え表示（Vercel デプロイ） |

---

## クイックスタート

```bash
# 1. クローン・仮想環境
git clone https://github.com/baby-feelings/cyberattack_info_api.git
cd cyberattack_info_api
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt

# 2. 環境変数の設定（.env.development を編集して DATABASE_URL・API_KEY・GITHUB_USERNAME を設定）
cp .env.example .env.development

# 3. DBマイグレーションの適用（新規マイグレーション追加時は git pull 後も毎回実行）
DATABASE_URL=sqlite:///./cyberattack_dev.db API_KEY=your-secret-key-here \
ENVIRONMENT=development GITHUB_USERNAME=your-github-username \
alembic upgrade head

# 4. 開発サーバーの起動
uvicorn app.main:app --reload --env-file .env.development
```

Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)

開発環境（SQLite）・本番環境（PostgreSQL/Neon）の設定例、環境変数の全一覧は
[docs/environment-variables.md](docs/environment-variables.md) を参照。

---

## API リファレンス

全エンドポイント（`/health` を除く）で `X-API-KEY` ヘッダーが必要です。エンドポイント一覧は
[docs/api-reference.md](docs/api-reference.md)、curlの実行例・パラメータ詳細は
[.claude/skills/api-usage/SKILL.md](.claude/skills/api-usage/SKILL.md) を参照。

---

## テスト・静的解析

```bash
pytest                                # 全テスト実行（カバレッジ付き）
pytest tests/kev/ -v                  # 特定ドメインのみ実行
ruff check app/ tests/                # Linting
mypy app/ --ignore-missing-imports    # 型チェック
```

**テスト結果（最新）:** 828 テスト / カバレッジ 98%

---

## プロジェクト構成

`app/` はドメイン（KEV / OSV / JVN / DEPSCAN / CODESCAN / DEPSOPS / クローラーログ / 横断的
共通処理）単位のパッケージ構成。詳細なディレクトリツリーは
[docs/project-structure.md](docs/project-structure.md) を参照。

---

## デプロイ・運用

バックエンド（FastAPI）は OCI（Oracle Cloud Infrastructure）の Compute VM 上で Docker
Compose により稼働し、`deploy/deploy_to_oci.ps1` を都度手動実行してデプロイする。
ダッシュボード（Vercel）は `dashboard/` 配下に変更がある `main` マージ時に自動デプロイされる。

- セットアップ手順・GitHub Secrets: [docs/deployment.md](docs/deployment.md)
- 環境変数の全一覧: [docs/environment-variables.md](docs/environment-variables.md)
- Slack通知の登録方法・通知先ルール: [docs/slack-notifications.md](docs/slack-notifications.md)
- Claude Code / AIエージェントからの活用例: [.claude/skills/api-usage/SKILL.md](.claude/skills/api-usage/SKILL.md)

---

## ライセンス

[GNU Affero General Public License v3.0（AGPL-3.0）](LICENSE)

AGPL-3.0 は、コードを改変してネットワーク経由で提供する場合（本 API のようなサーバー型サービスとしての利用を含む）も、改変後のソースコードを利用者に公開する義務を課す強めのコピーレフトライセンスです。無断でコードをコピーして非公開の競合サービスとして運営することを防ぐ目的で選択しています。個人利用・学習目的の閲覧・フォークは自由ですが、本コードを基にしたサービスを公開する場合はソースコードの公開が必要です。商用利用や別ライセンスでの利用を希望する場合は個別にご相談ください。
