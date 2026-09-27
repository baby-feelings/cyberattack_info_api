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
| `DEPSCAN_CRON_HOUR_UTC` | - | DEPSCAN 実行時刻（時・UTC）（デフォルト: `22`） |
| `DEPSCAN_RETENTION_DAYS` | - | DEPSCAN データの保持期間（日数・デフォルト: `180`）。解決済み（`resolved_at` 設定済み）のままこの日数を超えたレコードのみ自動削除（未解決レコードは対象外） |
| `CODESCAN_CRON_HOUR_UTC` / `CODESCAN_CRON_MINUTE_UTC` | - | CODESCAN 実行時刻（時・分・UTC）（デフォルト: `22`時`30`分。DEPSCANの後段） |
| `CODESCAN_RETENTION_DAYS` | - | CODESCAN データの保持期間（日数・デフォルト: `180`）。解決済みのままこの日数を超えたレコードのみ自動削除（未解決レコードは対象外） |
| `DEPSOPS_CRON_HOUR_UTC` | - | DEPSOPS 実行時刻（時・UTC）（デフォルト: `23`） |
| `DEPSOPS_RETENTION_DAYS` | - | DEPSOPS のPR判定履歴ログの保持期間（日数・デフォルト: `180`）。`processed_at`基準で削除 |
| `REPO_CLEANUP_CRON_HOUR_UTC` / `REPO_CLEANUP_CRON_MINUTE_UTC` | - | 削除済みリポジトリのデータ削除実行時刻（時・分・UTC）（デフォルト: `23`時`15`分。DEPSOPSの後段、Issue #228） |
| `USER_CRAWL_CRON_HOUR_UTC` / `USER_CRAWL_CRON_MINUTE_UTC` | - | 登録済み他ユーザー向けDEPSCAN/CODESCAN/DEPSOPS実行時刻（時・分・UTC）（デフォルト: `23`時`30`分。削除済みリポジトリ掃除の後段、Issue #227） |
| `GITHUB_OAUTH_CLIENT_ID` | - | DEPSCAN ダッシュボードの GitHub ログイン用 OAuth App の Client ID。未設定時は `/auth/github/login` が `503` を返すのみ |
| `GITHUB_OAUTH_CLIENT_SECRET` | - | 同 OAuth App の Client Secret |
| `SESSION_SECRET_KEY` | - | セッショントークン（JWT・HS256）の署名鍵。未設定のまま本番運用しないこと |
| `TOKEN_ENCRYPTION_KEY` | - | ユーザー別Slack通知登録（Issue #227）用、GitHubアクセストークンをDBへ暗号化保存するFernet鍵。未設定時は登録済みユーザーの定期実行（DEPSCAN/CODESCAN/DEPSOPS）が機能しない |
| `FRONTEND_URL` | - | OAuth コールバック後にリダイレクトするダッシュボード URL（デフォルト: Vercel の本番URL） |
| `API_BASE_URL_FOR_OAUTH` | - | OAuth の `redirect_uri` 組み立てに使う本 API 自身の公開 URL。GitHub OAuth App の Authorization callback URL と一致させる必要がある（デフォルト・現在値: OCI インスタンスの URL） |
| `METRICS_API_KEY` | - | 運用監視（Prometheus）用の `/metrics` エンドポイント保護キー（`Authorization: Bearer` で認証）。未設定時は `/metrics` 自体が `503` を返すのみ |

設定手順は [deployment.md](deployment.md) を参照。
