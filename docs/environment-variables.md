# 環境変数一覧

[README.md](../README.md) から分離した詳細ページ。

| 変数名 | 必須 | 説明 |
|--------|------|------|
| `DATABASE_URL` | ✅ | DB 接続文字列（SQLite or PostgreSQL） |
| `API_KEY` | ✅ | X-API-KEY 認証キー（管理者用・フルアクセス。十分に長いランダム文字列。**ダッシュボードには絶対に設定しないこと**） |
| `PUBLIC_API_KEY` | - | 公開ダッシュボード用の読み取り専用 X-API-KEY（任意。未設定時は読み取り専用エンドポイントも `API_KEY` のみで認証される） |
| `ENVIRONMENT` | - | `development` / `production`（デフォルト: `development`） |
| `CISA_KEV_URL` | - | CISA KEV フィード URL（通常は変更不要） |
| `CRON_HOUR_UTC` | - | KEV クローラー実行時刻（時・UTC）（デフォルト: `19`） |
| `CRON_MINUTE_UTC` | - | KEV クローラー実行時刻（分・UTC）（デフォルト: `0`） |
| `OSV_CRON_HOUR_UTC` | - | OSV クローラー実行時刻（時・UTC）（デフォルト: `20`） |
| `JVN_CRON_HOUR_UTC` | - | JVN クローラー実行時刻（時・UTC）（デフォルト: `21`） |
| `OSV_DAYS` | - | OSV 取得対象の直近日数（デフォルト: `30`） |
| `OSV_RETENTION_DAYS` | - | OSV データ保持期間（日数・デフォルト: `180`） |
| `JVN_DAYS` | - | JVN 取得対象の直近日数（デフォルト: `30`） |
| `JVN_RETENTION_DAYS` | - | JVN データ保持期間（日数・デフォルト: `180`） |
| `GITHUB_TOKEN` | - | DEPSCAN/DEPSOPS/CODESCAN 共用の GitHub PAT（fine-grained: Contents Read-only + **Issues Write** + **Pull requests Write** / classic: repo スコープ）。未設定時は DEPSCAN/DEPSOPS/CODESCAN のみエラー終了。Issues Write が無い場合、Issue自動起票・自動クローズのみ失敗（DEPSCAN/CODESCAN自体は成功扱い）。Pull requests Write が無い場合、DEPSOPSのPRマージ・rebase依頼のみ失敗。DEPSOPS の `is_security_update` 判定には別途 Dependabot alerts の読み取り権限（fine-grained: 「Dependabot alerts: Read-only」/ classic: `security_events` スコープ）が必要（無い場合は判定結果が `null` のまま記録されるのみで、DEPSOPS本来のマージ判定には影響しない） |
| `GITHUB_USERNAME` | ✅ | DEPSCAN/CODESCAN のスキャン対象 GitHub アカウント。コード側にデフォルト値は持たないため、**未設定だとアプリ全体が起動しない** |
| `SCAN_EXCLUDE_REPOS` | - | スキャン対象外にするリポジトリ（カンマ区切りの `owner/name`。例 `baby-feelings/AppGoat_web_v305`）。DEPSCAN・CODESCAN・DEPSOPS のすべてで対象外にし、すでにあるデータと起票済みの Issue は、毎日のクリーンアップ（UTC 23:15）で片付ける。形式が不正なら起動時にエラー（Issue #342） |
| `DASHBOARD_URL` | - | ダッシュボードの URL（末尾スラッシュなし。デフォルト: `https://cyberattackinfoapi.vercel.app`）。Slack 通知・GitHub Issue のリンクと、本番で CORS を許可するオリジンに使う。ダッシュボードのドメインを変えたら変更する |
| `INACTIVE_REPOS` | - | 運用を止めたアプリのリポジトリ（カンマ区切りの `owner/name`）。ダッシュボードの DEPSCAN・DEPSOPS・CODESCAN で「運用中」「運用停止中」に分けて見られる（初期表示は運用中）。**スキャンは止めない**（止めるのは `SCAN_EXCLUDE_REPOS`）。載っていないリポジトリは運用中。取得のたびに照合するため、運用を再開するときは外して再起動（デプロイ）するだけで、過去の検知もすぐに入れ替わる。形式が不正なら起動時にエラー |
| `DEPSCAN_CRON_HOUR_UTC` | - | DEPSCAN 実行時刻（時・UTC）（デフォルト: `22`） |
| `DEPSCAN_RETENTION_DAYS` | - | DEPSCAN データの保持期間（日数・デフォルト: `180`）。解決済み（`resolved_at` 設定済み）のままこの日数を超えたレコードのみ自動削除（未解決レコードは対象外） |
| `CODESCAN_CRON_HOUR_UTC` / `CODESCAN_CRON_MINUTE_UTC` | - | CODESCAN 実行時刻（時・分・UTC）（デフォルト: `22`時`30`分。DEPSCANの後段） |
| `RUNTIME_CRON_HOUR_UTC` / `RUNTIME_CRON_MINUTE_UTC` | - | 言語・実行環境のバージョン監視（RUNTIME）の実行時刻（時・分・UTC）（デフォルト: `22`時`45`分。CODESCANの後段） |
| `SLA_CRITICAL_DAYS` / `SLA_HIGH_DAYS` / `SLA_MEDIUM_DAYS` / `SLA_KEV_DAYS` | - | 脆弱性の対応期限（検知から解決までの日数。Issue #404）（デフォルト: `7`/`30`/`90`、KEV掲載済みは`7`）。LOW・重要度不明は期限なし。1以上 |
| `RATE_LIMIT_ENABLED` / `RATE_LIMIT_PER_MINUTE` / `RATE_LIMIT_LOCKOUT_FAILURES` / `RATE_LIMIT_LOCKOUT_MINUTES` | - | 管理 API・認証系のレート制限（1分あたりの上限）と、認証失敗の連続によるロックアウト（デフォルト: 有効・`60`・`10`回・`15`分）（#406） |
| `AUDIT_RETENTION_DAYS` | - | 監査ログの保持期間（日・デフォルト: `180`）（#406） |
| `API_KEY_EXPIRES_ON` / `GITHUB_TOKEN_EXPIRES_ON` / `SECRETS_EXPIRY_NOTICE_DAYS` | - | 鍵の更新期限（YYYY-MM-DD。空なら通知しない）と、何日前から毎日通知するか（デフォルト: `14`）。形式の誤りは起動時に失敗（#406） |
| `MCP_EXPIRY_NOTICE_CRON_HOUR_UTC` / `MCP_EXPIRY_NOTICE_CRON_MINUTE_UTC` | - | MCPトークンの期限切れ間近の通知の実行時刻（時・分・UTC）（デフォルト: `23`:`45`） |
| `OAUTH_CLEANUP_CRON_HOUR_UTC` / `OAUTH_CLEANUP_CRON_MINUTE_UTC` | - | 期限切れのOAuthコード・トークンの掃除の実行時刻（時・分・UTC）（デフォルト: `23`:`50`） |
| `SECRET_EXPIRY_CRON_HOUR_UTC` / `SECRET_EXPIRY_CRON_MINUTE_UTC` | - | 鍵の更新期限の通知と、監査ログの掃除の実行時刻（時・分・UTC）（デフォルト: `23`:`40`）（#406） |
| `TRUSTED_COMMITTERS` | - | コミットの監視で信頼するコミッター（管理者・dependabot・github-actions に足す GitHub ログイン名。カンマ区切り）（#405） |
| `COMMITWATCH_REQUIRE_SIGNATURE` | - | `true` で、信頼するユーザーでも署名のないコミットを通知（なりすまし対策。デフォルト: `false`）（#405） |
| `COMMITWATCH_CRON_HOUR_UTC` / `COMMITWATCH_CRON_MINUTE_UTC` | - | コミットの監視の実行時刻（時・分・UTC）（デフォルト: `22`:`20`）（#405） |
| `EXTERNAL_MONITOR_URLS` | - | 外形監視の対象に追加する公開サイトのURL（https・カンマ区切り。自分の所有するドメインのみ）。リポジトリのHomepage・Firebase・GitHub Pagesは自動検出（#401） |
| `EXTMON_CRON_HOUR_UTC` / `EXTMON_CRON_MINUTE_UTC` | - | 公開サイトの外形監視の実行時刻（時・分・UTC）（デフォルト: `22`:`35`）（#401） |
| `REPOAUDIT_CRON_HOUR_UTC` / `REPOAUDIT_CRON_MINUTE_UTC` | - | リポジトリの設定の監査の実行時刻（時・分・UTC）（デフォルト: `22`:`40`）（#398） |
| `GHALERT_CRON_HOUR_UTC` / `GHALERT_CRON_MINUTE_UTC` | - | GitHubのセキュリティアラート取り込みの実行時刻（時・分・UTC）（デフォルト: `22`:`50`）（#402） |
| `EXCEPTION_MAX_DAYS` / `EXCEPTION_EXPIRY_NOTICE_DAYS` | - | 検知の例外（受容）の期限の上限（日・デフォルト: `365`）と、期限の何日前に通知するか（デフォルト: `7`）（#403） |
| `EXCEPTION_CRON_HOUR_UTC` / `EXCEPTION_CRON_MINUTE_UTC` | - | 例外の期限切れ・修正版の公開の確認と通知の実行時刻（時・分・UTC）（デフォルト: `22`:`55`。DEPSCAN・CODESCANの後）（#403） |
| `SLA_MTTR_WINDOW_DAYS` | - | 平均対応日数（MTTR）を集計する、解決済みの期間（日・デフォルト: `90`。`DEPSCAN_RETENTION_DAYS`以内） |
| `SLA_DIGEST_DAY_OF_WEEK` / `SLA_DIGEST_CRON_HOUR_UTC` / `SLA_DIGEST_CRON_MINUTE_UTC` | - | 対応状況の週次まとめ（Slack）の実行曜日・時・分（UTC）（デフォルト: `mon` 0時0分＝JST月曜9時） |
| `CODESCAN_RETENTION_DAYS` | - | CODESCAN データの保持期間（日数・デフォルト: `180`）。解決済みのままこの日数を超えたレコードのみ自動削除（未解決レコードは対象外） |
| `DEPSOPS_CRON_HOUR_UTC` | - | DEPSOPS 実行時刻（時・UTC）（デフォルト: `23`） |
| `DEPSOPS_RETENTION_DAYS` | - | DEPSOPS のPR判定履歴ログの保持期間（日数・デフォルト: `180`）。`processed_at`基準で削除（解決済みPRの履歴は保持期間を待たず実行時に削除される） |
| `REPO_CLEANUP_CRON_HOUR_UTC` / `REPO_CLEANUP_CRON_MINUTE_UTC` | - | 削除済みリポジトリのデータ削除実行時刻（時・分・UTC）（デフォルト: `23`時`15`分。DEPSOPSの後段、Issue #228） |
| `USER_CRAWL_CRON_HOUR_UTC` / `USER_CRAWL_CRON_MINUTE_UTC` | - | 登録済み他ユーザー向けDEPSCAN/CODESCAN/DEPSOPS実行時刻（時・分・UTC）（デフォルト: `23`時`30`分。削除済みリポジトリ掃除の後段、Issue #227） |
| `GITHUB_OAUTH_CLIENT_ID` | - | DEPSCAN ダッシュボードの GitHub ログイン用 OAuth App の Client ID。未設定時は `/auth/github/login` が `503` を返すのみ |
| `GITHUB_OAUTH_CLIENT_SECRET` | - | 同 OAuth App の Client Secret |
| `SESSION_SECRET_KEY` | - | セッショントークン（JWT・HS256）の署名鍵。未設定のまま本番運用しないこと |
| `TOKEN_ENCRYPTION_KEY` | - | ユーザー別Slack通知登録（Issue #227）用、GitHubアクセストークンをDBへ暗号化保存するFernet鍵。未設定時は登録済みユーザーの定期実行（DEPSCAN/CODESCAN/DEPSOPS）が機能しない |
| `FRONTEND_URL` | - | OAuth コールバック後にリダイレクトするダッシュボード URL（デフォルト: Vercel の本番URL） |
| `API_BASE_URL_FOR_OAUTH` | - | OAuth の `redirect_uri` 組み立てに使う本 API 自身の公開 URL。GitHub OAuth App の Authorization callback URL と一致させる必要がある（デフォルト・現在値: OCI インスタンスの URL） |
| `MCP_OAUTH_ISSUER` | - | MCP サーバーを OAuth 2.1 の認可サーバーとして公開する際の issuer URL（`https://...`、末尾スラッシュなし。Issue #303）。空なら OAuth 機能は無効（デフォルト）。ドメイン変更時は `BACKEND_DOMAIN`・`API_BASE_URL_FOR_OAUTH`・GitHub OAuth App の callback URL とあわせて更新する |
| `METRICS_API_KEY` | - | 運用監視（Prometheus）用の `/metrics` エンドポイント保護キー（`Authorization: Bearer` で認証）。未設定時は `/metrics` 自体が `503` を返すのみ |

設定手順は [deployment.md](deployment.md) を参照。
