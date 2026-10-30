# =====================================================================
# バックエンド (FastAPI) OCIデプロイスクリプト
# 実行場所: Windows側 cyberattack_info_api/deploy/ ディレクトリ内
# crypto_forecast/deploy/deploy_to_oci.ps1 と同じ SSH/SCP + docker compose 方式
# =====================================================================

# --- 1. 環境設定（ご自身の環境に合わせて修正してください） ---
$OciUser   = "ubuntu"
$OciHost   = "168.138.213.240"
$SshKey    = "C:\Users\masud\.ssh\oci_cyberattack_info_api_key.key"
$RemoteDir = "/home/ubuntu/cyberattack_info_api"

# 以前設定したOpenSSHのパス環境を引き継ぎ、パスフレーズ入力を回避してスムーズに実行します
$SshCmd = "ssh -i $SshKey -o StrictHostKeyChecking=no"
$ScpCmd = "scp -i $SshKey -o StrictHostKeyChecking=no"

# --- Fail Fast: 失敗したコマンドの後ろを実行しない ---
# 以前は終了コードを見ておらず、docker compose が失敗しても「デプロイ完了」と表示していた。
# ssh/scp は警告を標準エラーに出すため、$ErrorActionPreference は変えず、終了コードで判定する。
function Invoke-Checked {
    param([string]$Command)
    Invoke-Expression $Command
    if ($LASTEXITCODE -ne 0) {
        throw "コマンドが失敗しました（終了コード $LASTEXITCODE）: $Command"
    }
}

# deploy/.env から、キーの値を取り出す（未設定・空なら $null）。値は表示しない
function Get-DeployEnvValue {
    param([string]$Key)
    if (-not (Test-Path "./.env")) { return $null }
    foreach ($line in Get-Content "./.env") {
        if ($line -match "^\s*$Key=(.+)$") { return $Matches[1].Trim().Trim('"').Trim("'") }
    }
    return $null
}

# 転送・再起動の前に、必須の設定が揃っているか確認する（欠けたまま進めない）
$RequiredEnvKeys = @("BACKEND_DOMAIN", "GRAFANA_DOMAIN", "GRAFANA_ADMIN_PASSWORD")
if (-not (Test-Path "./.env")) {
    throw "deploy/.env が見つかりません。deploy/.env.example を参考に設定してください。"
}
$MissingKeys = $RequiredEnvKeys | Where-Object { -not (Get-DeployEnvValue $_) }
if ($MissingKeys) {
    throw "deploy/.env に必須の設定がありません: $($MissingKeys -join ', ')（値は deploy/.env.example を参照）"
}
if (-not (Test-Path "../.env.production")) {
    throw "../.env.production が見つかりません。.env.example を参考に本番用の値で作成してください。"
}

Write-Host "🚀 1. OCI上のディレクトリ階層を準備しています..." -ForegroundColor Cyan
Invoke-Checked "$SshCmd ${OciUser}@${OciHost} 'mkdir -p $RemoteDir/app $RemoteDir/alembic/versions $RemoteDir/deploy/grafana/provisioning/datasources $RemoteDir/deploy/grafana/provisioning/dashboards $RemoteDir/deploy/grafana/dashboards'"

Write-Host "📦 2. 本番稼働に必要なファイルのみを転送中..." -ForegroundColor Cyan
# -- アプリケーション本体と Dockerfile・依存パッケージ定義 --
Invoke-Checked "$ScpCmd -r ../app/* ${OciUser}@${OciHost}:${RemoteDir}/app/"
Invoke-Checked "$ScpCmd ../Dockerfile ../requirements.txt ../semgrep-cli.txt ../zizmor-cli.txt ${OciUser}@${OciHost}:${RemoteDir}/"

# -- Alembicマイグレーション定義 (DBスキーマ管理。DB自体は Neon を継続利用) --
Invoke-Checked "$ScpCmd ../alembic.ini ${OciUser}@${OciHost}:${RemoteDir}/"
Invoke-Checked "$ScpCmd -r ../alembic/* ${OciUser}@${OciHost}:${RemoteDir}/alembic/"

# -- デプロイ設定ファイル (docker-compose.yml, Caddyfile) --
Invoke-Checked "$ScpCmd ./docker-compose.yml ./Caddyfile ${OciUser}@${OciHost}:${RemoteDir}/deploy/"

# -- 運用監視: Grafanaのプロビジョニング設定・ダッシュボード定義
#    (機密情報を含まないためgit管理対象、crypto_forecastと同じ方針) --
Invoke-Checked "$ScpCmd ./grafana/provisioning/datasources/prometheus.yml ${OciUser}@${OciHost}:${RemoteDir}/deploy/grafana/provisioning/datasources/"
Invoke-Checked "$ScpCmd ./grafana/provisioning/dashboards/dashboards.yml ${OciUser}@${OciHost}:${RemoteDir}/deploy/grafana/provisioning/dashboards/"
Invoke-Checked "$ScpCmd ./grafana/dashboards/cyberattack-info-api-overview.json ${OciUser}@${OciHost}:${RemoteDir}/deploy/grafana/dashboards/"

# -- docker-compose の ${BACKEND_DOMAIN}/${GRAFANA_DOMAIN}/${GRAFANA_ADMIN_PASSWORD} 変数展開用
#    (deploy/.env)。事前に deploy/.env.example を deploy/.env にコピーし値を設定しておくこと
Invoke-Checked "$ScpCmd ./.env ${OciUser}@${OciHost}:${RemoteDir}/deploy/"

# -- アプリの環境変数 (DATABASE_URL=Neon の接続文字列 等。API_KEY・GITHUB_TOKEN・
#    METRICS_API_KEY 等を含むため機密情報)
#    ローカル開発と同じ ../.env.production をそのまま本番用としてOCIへ転送する
#    （以前は別ファイル ../.env.prod を使っていたが、秘密情報ローテーション時に
#    .env.production 側だけ更新して .env.prod への反映を忘れる事故が発生したため統一した）
Invoke-Checked "$ScpCmd ../.env.production ${OciUser}@${OciHost}:${RemoteDir}/"

# -- Prometheusのスクレイプ設定 (METRICS_API_KEY の実値を含むためgit管理対象外、.env等と同じ理由)
#    事前に deploy/prometheus.yml.example を deploy/prometheus.yml にコピーし
#    credentials に .env.production の METRICS_API_KEY と同じ値を設定しておくこと
if (Test-Path "./prometheus.yml") {
    Invoke-Checked "$ScpCmd ./prometheus.yml ${OciUser}@${OciHost}:${RemoteDir}/deploy/"
} else {
    Write-Warning "deploy/prometheus.yml が見つかりません。deploy/prometheus.yml.example を参考に設定してください（未設定の場合、Prometheusコンテナは起動に失敗します）。"
}

Write-Host "🔄 3. OCI上でコンテナを再ビルドし、最新状態で起動します..." -ForegroundColor Cyan
# BACKEND_DOMAIN/GRAFANA_DOMAIN は deploy/.env で設定する (例: <インスタンスIP>.nip.io)
# Caddy が Let's Encrypt で HTTPS 化する (Vercel からの API 呼び出し・Grafanaアクセスに必須)
# DB は Neon（マネージドPostgreSQL）を継続利用するため、Postgresコンテナは無い
Invoke-Checked "$SshCmd ${OciUser}@${OciHost} 'cd $RemoteDir/deploy && docker compose up -d --build api-prod caddy prometheus grafana node-exporter'"

Write-Host "🧹 4. 不要になったDockerイメージ・ビルドキャッシュを削除しています..." -ForegroundColor Cyan
# デプロイ（docker compose build）のたびにビルドキャッシュ・タグなしイメージが蓄積し、
# 自動クリーンアップの仕組みが無いとディスクを逼迫させる（crontab/systemdタイマーは
# 意図的に使わず、手動デプロイのたびにここで掃除する方式に統一する）。
# 稼働中のコンテナ（api-prod・caddy・prometheus・grafana・node-exporter）が使用する
# イメージは対象外（-f フィルタでも稼働中コンテナの参照先は削除されない）
Invoke-Checked "$SshCmd ${OciUser}@${OciHost} 'docker image prune -f && docker builder prune -af'"

# --- 5. ヘルスチェック: 応答しなければ失敗として終了する ---
$BackendDomain = Get-DeployEnvValue "BACKEND_DOMAIN"
$HealthUrl = "https://$BackendDomain/health"
Write-Host "🩺 5. ヘルスチェック（$HealthUrl）..." -ForegroundColor Cyan
$Healthy = $false
foreach ($Attempt in 1..12) {
    try {
        $Response = Invoke-WebRequest -Uri $HealthUrl -UseBasicParsing -TimeoutSec 10
        if ($Response.StatusCode -eq 200) { $Healthy = $true; break }
    } catch {
        # 起動直後は接続できないことがあるため、少し待って再試行する
    }
    Start-Sleep -Seconds 5
}
if (-not $Healthy) {
    throw "ヘルスチェックに失敗しました（$HealthUrl）。OCI上で 'docker compose logs' を確認してください。"
}

Write-Host "✅ デプロイ完了！バックエンドは最新のコードで稼働しています。" -ForegroundColor Green
Write-Host "   ヘルスチェック: $HealthUrl" -ForegroundColor Green
Write-Host "   運用監視ダッシュボード: https://$(Get-DeployEnvValue 'GRAFANA_DOMAIN')/" -ForegroundColor Green
