# OWASP ZAP による API の動的診断

本 API に対して OWASP ZAP の **API Scan**（OpenAPI 定義からエンドポイントを網羅してアクティブスキャン）を行う。
静的解析の CODESCAN（Semgrep）では見つからない、実行時の挙動（ヘッダー不備・エラー応答・入力検証など）を確認する。

## 安全性

スキャン対象は、同じ Docker ネットワーク内に起動する **使い捨ての API コンテナ**のみ。

| 項目 | 内容 |
|------|------|
| 接続先 | `http://api:8000`（コンテナ内。本番 URL は指定しない） |
| DB | コンテナ内の SQLite。Neon・本番 DB には接続しない |
| 鍵・環境変数 | ダミー値。`.env.production` は読まない |
| 外部通信 | `internal: true` のネットワークで遮断（`/admin/*` が動いても CISA・GitHub に出られない） |
| 対象外 URL | `/admin/*`（クローラー起動など副作用のある管理系）は ZAP の除外設定でスキャンしない |

> ZAP を実環境に向けるのは、`-t` に本番 URL を指定したときだけ。本番へのアクティブスキャンは行わないこと。

## ローカル（Docker Desktop）で実行

```powershell
deploy/zap/run_zap_scan.ps1
```

結果は `deploy/zap/reports/zap-report.html`（人が読む用）と `zap-report.json`（Issue 起票用）に出力される
（`reports/` は `.gitignore` 済み）。

検出結果を Issue に起票する場合（要 `GITHUB_TOKEN`。`.env.development` に設定済みの値を使う）:

```bash
python -m app.zapscan deploy/zap/reports/zap-report.json --min-risk 2
```

## CI（GitHub Actions）で実行

`.github/workflows/zap-scan.yml`。**手動実行（workflow_dispatch）**と**毎週月曜 03:00 JST の定期実行**。

1. 使い捨て API と ZAP を `docker compose` で起動してスキャン
2. レポート（HTML/JSON）を artifact に保存（30 日）
3. `python -m app.zapscan` で、Medium 以上のアラートを GitHub Issue に起票

手動実行時は `min_risk` で起票する下限を変えられる（1=Low / 2=Medium / 3=High）。

## Issue 起票の仕様

DEPSCAN / CODESCAN と同じ運用（`app/core/issue_filing.py` を共用）。

- タイトル固定: `🕷️ API の脆弱性が検出されました (OWASP ZAP)`
- Open な同名 Issue があればコメント追記、無ければ新規作成
- 既定の起票対象は **Medium 以上**（Low / Informational は多くが軽微なヘッダー指摘で、Issue が増えすぎるため）
- GitHub API の失敗はスキャンの成否に影響させない

## スキャン結果の読み方

- 終了コードは `-I` により、警告（WARN）では失敗にしない。失敗するのはスキャン自体が失敗したとき
- **コンテナ内では設定が無いため 503 になる URL**（`/metrics`・`/auth/github/*`）は、
  「Server Error」の指摘として出るが、本番では設定済みのため誤検知
- ビジネスロジック（他ユーザーのデータを操作できるか等）は ZAP では検出できない

## 他のアプリへの適用

ZAP は動的診断のため、診断対象を起動する必要がある。CODESCAN のように全リポジトリへ一括適用はできない。
デプロイ済みの自分のアプリには、攻撃的でない **baseline（受動）スキャン**のみ行う方法がある。
