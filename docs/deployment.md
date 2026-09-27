# デプロイ（OCI + Neon）

[README.md](../README.md) から分離した詳細ページ。バックエンド（FastAPI）はOracle Cloud
Infrastructure（OCI）のCompute VM（Always Free、Ampere A1）上でDocker Composeにより
稼働する（旧Renderから移行済み）。デプロイは`deploy/deploy_to_oci.ps1`を都度手動実行する
運用で、GitHub Actions経由の自動デプロイは無い（ダッシュボード＝Vercelのみ、`dashboard/`
配下に変更がある`main`マージ時にのみ自動デプロイされる）。

## Step 1: Neon で PostgreSQL を作成

1. [Neon](https://neon.tech) でアカウント作成・プロジェクト作成
2. **Project name:** `cyberattack-info-api`、**Postgres version:** `16`、**Region:** `Singapore`
3. 接続文字列（`postgresql://...`）をコピー

## Step 2: OCI で Compute インスタンスを作成

1. [OCI コンソール](https://cloud.oracle.com/)で `Compute > Instances > Create Instance`
2. **Image:** Canonical Ubuntu（最新版）、**Shape:** `VM.Standard.A1.Flex`（Always Free対象。
   本APIは低負荷なため 1 OCPU / 6GB 程度で十分）
3. パブリックIPv4アドレスを割り当てる、SSHキーペアを生成してダウンロード
4. OCIセキュリティリスト・インスタンスOS側（`iptables` + `iptables-persistent`。Ubuntu標準
   イメージは `ufw` ではないため注意）の両方で80/443番ポートを開放する
5. SSH接続し、Docker Engine + Composeプラグインをインストール
   （`curl -fsSL https://get.docker.com | sh`）

## Step 3: デプロイ設定ファイルを準備

1. `deploy/.env.example` を `deploy/.env` にコピーし、`BACKEND_DOMAIN`（例:
   `<インスタンスのパブリックIP>.nip.io`。Let's EncryptのHTTPS自動化にドメイン名が必要な
   ため、IPアドレスをそのまま解決してくれる無料DNS `nip.io` を利用する）・
   `GRAFANA_DOMAIN`・`GRAFANA_ADMIN_PASSWORD` を設定する
2. `.env.example`（リポジトリルート）を元に `.env.production` を作成する
   （ローカル開発と同じファイルをそのままOCIへ転送して使う。本番専用の別ファイルは作らない）。
   設定する変数の一覧は [environment-variables.md](environment-variables.md) を参照
3. `deploy/prometheus.yml.example` を `deploy/prometheus.yml` にコピーし、
   `credentials` に `METRICS_API_KEY` と同じ値を設定する（運用監視を使う場合）

## Step 4: デプロイ実行

`deploy/deploy_to_oci.ps1` 内の `$OciHost`（パブリックIP）・`$SshKey`（秘密鍵パス）を
実環境に合わせて書き換えた上で実行する:

```powershell
cd deploy
.\deploy_to_oci.ps1
```

SCPでコード一式を転送し、OCI上で `docker compose up -d --build` を実行する
（`api-prod`・`caddy`・`prometheus`・`grafana`・`node-exporter`）。

## GitHub Secrets の設定

| Secret 名 | 説明 |
|-----------|------|
| `API_KEY` | OCI の `.env.production` に設定した API キーと同じ値（`.github/workflows/daily-crawl.yml` 用） |
| `VERCEL_TOKEN` | [Vercelのアカウント設定](https://vercel.com/account/tokens)で発行したトークン（`.github/workflows/deploy.yml` 用。ダッシュボードの本番デプロイの唯一の経路のため必須） |
| `VERCEL_ORG_ID` / `VERCEL_PROJECT_ID` | Vercelプロジェクトの識別子（`dashboard/`で`vercel link`実行時に生成される`.vercel/project.json`から取得） |

ダッシュボード（Vercel）は `dashboard/` 配下に変更がある `main` ブランチへのマージで
自動デプロイされる（`.github/workflows/deploy.yml`。Vercel側のネイティブGit連携による
本番自動デプロイは無効化済みで、GitHub Actions経由のデプロイのみが本番に反映される）。

## データ更新スケジュール

| タイミング | 処理 |
|----------|------|
| 毎日 JST 04:05（UTC 19:05）| GitHub Actions 単一 cron で KEV → OSV → JVN → DEPSCAN → CODESCAN → DEPSOPS を順次実行 |
| アプリ起動時 | DB テーブルの自動作成 |
| `POST /admin/*-crawl` 実行時 | 各クローラーをバックグラウンド取得（詳細は [api-reference.md](api-reference.md)） |

> **Note:** APScheduler（アプリ内スケジューラ）は UTC 19:00 / 20:00 / 21:00 / 22:00 / 22:30 / 23:00 /
> 23:15 / 23:30（KEV/OSV/JVN/DEPSCAN/CODESCAN/DEPSOPS/削除済みリポジトリ掃除/登録済み他ユーザー向け
> の順）に設定されており、OCI移行後はこちらが主経路として機能する（OCIは常時稼働のためスリープしない）。
> GitHub Actions の単一 cron（KEV〜DEPSOPSのみ）は、ネットワーク障害等で APScheduler が不発火だった
> 場合の二重バックアップとして維持している（削除済みリポジトリ掃除・登録済み他ユーザー向け実行は
> APScheduler側のみ）。KEV/OSV/JVN/DEPSCAN/CODESCAN/DEPSOPSは今日（UTC日付）既に成功実行済みなら
> 2回目の実行を自動的にスキップするため、この二重トリガー自体は無害（Issue #239）。
