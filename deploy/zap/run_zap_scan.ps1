# OWASP ZAP API Scan をローカルの Docker Desktop で実行する。
# 使い捨ての API コンテナ（SQLite・ダミー鍵・外部通信なし）に対してのみスキャンする。
# 結果: deploy/zap/reports/zap-report.html / zap-report.json
# 注意: Windows PowerShell 5.1 で日本語を読めるよう、このファイルは UTF-8 (BOM付き) で保存する。
# docker は警告・進捗を標準エラーに出すため、Stop だと PowerShell 5.1 が例外にしてしまう。
# 成否は $LASTEXITCODE で判定する。
$ErrorActionPreference = "Continue"
$compose = Join-Path $PSScriptRoot "docker-compose.yml"

# Docker Desktop が起動していなければ早めに失敗させる
docker info *> $null
if ($LASTEXITCODE -ne 0) { throw "Docker Desktop が起動していません。起動してから再実行してください。" }

try {
    # zap の終了コード（0=問題なし / 1=失敗 / 2=警告 / 3=その他）をそのまま受け取る
    docker compose -f $compose up --build --abort-on-container-exit --exit-code-from zap
    $code = $LASTEXITCODE
}
finally {
    # 成否にかかわらずコンテナ・ネットワークを片付ける
    docker compose -f $compose down --remove-orphans
}

$report = Join-Path $PSScriptRoot "reports\zap-report.html"
if (Test-Path $report) { Write-Host "レポート: $report" }
exit $code
