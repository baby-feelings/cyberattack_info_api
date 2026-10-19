# セキュリティ対策の対応表（IPA「安全なウェブサイトの作り方」第7版）

IPA のチェックリスト（11 の脆弱性）を、本アプリの実装と突き合わせた一覧。新しい機能を足すときは、
該当する行の対策を崩していないかを確認する。動的な確認は OWASP ZAP（[zap-scan.md](zap-scan.md)）。

| # | 脆弱性 | 本アプリの対策 | 場所 |
|---|--------|----------------|------|
| 1 | SQL インジェクション | SQLAlchemy の ORM・バインドのみ（生の SQL 連結なし）。エラー詳細は画面に出さない | `app/**/repository`・`models.py` |
| 2 | OS コマンド・インジェクション | `subprocess.run` は引数をリストで渡し `shell=True` なし。対象は一時ディレクトリ（外部入力を引数にしない） | `app/codescan/scanners.py` |
| 3 | パス名パラメータの未チェック | tarball は `extractall(filter="data")` で展開（`../` は拒否。フォールバックなし）。テストあり | `app/codescan/archive.py` |
| 4 | セッション管理の不備 | セッションは Bearer の JWT（URL に載せない。ログイン後に新規発行）。7 日・利用で延長、ログインから 30 日で再認証 | `app/auth/session.py` |
| 5 | XSS | React の自動エスケープ。外部データの URL は `http(s)` のみリンク化（`safeHttpUrl`）。ダッシュボードに CSP | `dashboard/src/components/shared/safeUrl.ts`・`dashboard/vercel.json` |
| 6 | CSRF | 認証は Cookie ではなく Bearer ヘッダー（他サイトから送れない）。OAuth の state・同意画面はブラウザ紐づけ。MCP トークン・OAuth 接続の発行は本人の Slack へ事後通知 | `app/core/notifications/mcp_token.py` |
| 7 | HTTP ヘッダ・インジェクション | ヘッダーは FastAPI/Starlette の API で出力（外部入力を直接入れない） | - |
| 8 | メールヘッダ・インジェクション | メール送信なし。Slack の宛先は `https://hooks.slack.com/` のみ許可 | `app/core/notifications/slack.py` |
| 9 | クリックジャッキング | API は `X-Frame-Options: DENY`、ダッシュボードは `X-Frame-Options`・`frame-ancestors 'none'` | `app/core/security_headers.py`・`dashboard/vercel.json` |
| 10 | バッファオーバーフロー | Python（メモリ直接操作なし）。依存は pip-audit・OSV-Scanner・Dependabot で最新化 | `.github/workflows/` |
| 11 | アクセス制御・認可の欠落 | DEPSCAN/CODESCAN は本人所有のリポジトリのみ（セッション・MCP とも）。管理 API は API キー | `app/auth/dependencies.py` |

追加の対策: API の HSTS（`deploy/Caddyfile`）、nosniff・Referrer-Policy（API・ダッシュボード）。

## 運用上の注意
- **ダッシュボードの CSP（`dashboard/vercel.json`）の `connect-src` に、API のオリジン**
  （`https://<BACKEND_DOMAIN>`）を書いている。**API のドメイン・IP を変えたら、`vercel.json` も更新する**
  （忘れると、本番のダッシュボードが API に接続できず、何も表示されない）。
- 画面が外部のオリジンから画像などを読み込む場合も、CSP に足す必要がある（現在は DEPSOPS の互換性スコアの
  バッジ `https://dependabot-badges.githubapp.com` を `img-src` に許可）。**E2E は同一オリジンのモックで動くため、
  足し忘れには気づけない**。`dashboard/src/csp.test.ts` が、許可すべきオリジンの抜けを検査する。
- CSP の確認は、ビルド済みの画面を `vercel.json` のヘッダー付きで配信して E2E を流す
  （違反は `report-uri` で記録して 0 件を確認する）。ZAP の対象は API のコンテナのみで、
  ダッシュボード（Vercel）は対象外。
