---
name: security-posture
description: 各アプリのセキュリティ態勢を保つ機能の内部設計。検知の例外（受容・誤検知・影響なし。理由・期限・VEX。app/finding_exceptions/）・GitHubのセキュリティアラートの取り込み（secret scanning・Dependabot・code scanning。app/github_alerts/）・リポジトリ設定の監査とスコア化（app/repo_audit/）を扱う。これらの変更・拡張時に読む。
---

# セキュリティ態勢の機能（例外・GitHubアラート・設定の監査）

DEPSCAN/CODESCANの検知を補い、運用を回すための機能。検知そのものの設計は`depscan-depsops`・`codescan`スキル。

## 検知の例外（受容・誤検知・影響なし。Issue #403。`app/finding_exceptions/`）

修正版が無い・到達できない検知を、理由・期限・承認者つきで「例外」にし、通知・「要対応」の件数・SLAから外す（一覧では確認できる）。
DEPSCAN（`dependency`）とCODESCAN（`code`）の両方が対象。

- **別テーブル`finding_exceptions`**: 検知の行は、スキャンのたびに更新・解決済み化・削除されるため、例外は同一性キーで結び付ける。
  キー: dependency=`ecosystem|package|osv_id`（版を含めない）/ code=`file_path|rule_id`（**行番号を含めない**＝行がずれても外れない。
  同じファイル・ルールの全行がまとめて例外になる）。キーは`matching.py`（`key_of_finding`）に1か所
- **有効の条件**: `ended_at IS NULL`かつ（期限なし or 期限が未来）。期限切れは、定期ジョブが終了にする前でも、クエリ上で有効に数えない
- **状態**: `accepted`（受容。期限必須・`EXCEPTION_MAX_DAYS`以内）/`false_positive`/`not_affected`（期限は任意）。解除は行を消さず
  `ended_at`・`ended_reason`（`expired`/`fix_available`/`revoked`）を記録する。同じ検知の有効な例外は1件（再登録は更新）
- **反映先**: 一覧API（`exception_key`・`exception`を付与。検知は消さない）/ 統計（`not_excepted`のNOT EXISTS）/ SLA（`exception_map`）/
  新規検知の通知・Issue起票（クローラーで`drop_excepted`）/ DEPSCAN Issueのクローズ判定（有効な検知＝未解決−例外が0件で閉じる。
  IssueはリポジトリごとなのでIssue単位でなくこの判定に乗せた。CODESCANはもともと閉じない）/ CycloneDX SBOMの`analysis`
- **毎日の`lifecycle.py`**（UTC 22:55）: 修正版が公開された受容（`fixed_versions`あり）を自動解除・期限切れを終了・期限の
  `EXCEPTION_EXPIRY_NOTICE_DAYS`日前に1度だけ通知（`expiry_notified_at`）。解除・期限切れの検知は`issue_sync.refile_issues`でIssueに
  再び示す。通知・Issueは**管理者（`GITHUB_USERNAME`）のリポジトリのみ**（他ユーザー分は状態の更新だけ）
- **VEX**: `vex.py`。受容=affected（`action_statement`に理由と期限）・誤検知/影響なし=not_affected（`impact_statement`）。
  OpenVEX 0.2.0とCycloneDX 1.5（`analysis.state`: 受容=exploitable＋`will_not_fix`）。依存ライブラリのみ
- **認可**: `require_api_key_or_session`。セッション認証時は本人所有のリポジトリのみ（他人の例外IDは404）。承認者＝ログインユーザー
  （APIキーは`GITHUB_USERNAME`）。ダッシュボードは検知の展開部の`ExceptionControl`（登録後は一覧を読み直すため行が閉じる）。
  E2EはDEP-28・COD-14

## GitHubのセキュリティアラートの取り込み（Issue #402。`app/github_alerts/`）

tarball方式のCODESCANは現在のツリーしか見えないため、GitHub自身のアラートで補う。

- **取得**: `client.fetch_alerts`が、secret scanning・Dependabot alerts・code scanningの未解決（open）を、リポジトリごと・種類ごとに取得
  （ページング・最大10ページ）。**403・404は「取得不可」**（機能が無効・権限不足）として`None`で返し、0件と区別する
  （0件と見なすと既存のアラートを解決済みにしてしまう）。取得不可は`github_alert_sources`に理由つきで記録し、APIの`unavailable`に出す
- **シークレットの値は保存・通知しない**: secret scanningの応答には値（`secret`）が含まれるが、`normalize_secret`は参照しない
  （種類・有効性・公開状況だけ）。有効（`validity=active`）はCRITICAL・それ以外はHIGH
- **保存**: `github_alerts`（kind・repo・numberで一意）。今回の結果に無い未解決は解決済み（GitHub側で修正・却下）。取得不可のときは触らない
- **DEPSCANとの突き合わせ**: `repository.dependabot_vs_depscan`が(リポジトリ・エコシステム・パッケージ・勧告ID)で、`both`（重複は1件）・
  `only_github`・`only_depscan`に分ける。`GET /api/github-alerts/compare`
- **通知**: 新規のsecret scanningだけ、管理者のWebhookへ（`core/notifications/github_alerts.py`。有効なものが先・無効化と再発行・
  履歴の書き換えの手順つき）。毎日UTC 22:50（`GHALERT_*`）。クローラー種別は`GHALERT`
- **トークン**: 現状は`repo`スコープの classic PAT（secret scanning・Dependabot・code scanningの読み取りを含む）。fine-grainedに
  する場合は、Secret scanning alerts・Dependabot alerts・Code scanning alertsの読み取りが要る
- 認可は他のAPIと同じ（`require_api_key_or_session`・セッション認証時は本人所有のみ）。ダッシュボードの画面は未実装

## リポジトリの設定の監査（Issue #398。`app/repo_audit/`）

- **点検項目**（`checks.py`。重み）: Secret scanning(3)・Push protection(2)・Dependabot alerts(3)・Dependabot security updates(2)・
  既定ブランチの保護(3。必須レビュー・必須チェック)・フォークの許可(1。非公開のみ)・デプロイキー(2。書き込み権限つき)・Webhook(2。http・SSL検証なし)
- **状態の区別**: `ok`/`ng`（スコアの分母）と、`unavailable`（取得不可＝権限不足・プランの対象外）・`not_enforceable`（強制できない＝
  **非公開の無料リポジトリのブランチ保護**は403「Upgrade」）。後者2つは不備と区別し、分母に含めない。スコア＝重み付きの達成率
- **収集**（`collector.py`）: 403・404は例外にせず`None`（取得不可）。「保護されていない」と「見えない」は404のメッセージで区別。
  5xx・通信は例外で伝わり、そのリポジトリは飛ばして続ける
- **変化の検知**: デプロイキー・Webhook・共同編集者の名前を`snapshot`に持ち、前回との追加・削除を`changes`に出す。**初回は変化なし**
  （全件が追加になり通知が溢れるため）。取得不可の種類は比べない。変化は管理者のSlackへ（乗っ取りの兆候の確認）
- **保存**: `repo_audits`（リポジトリごとに最新の1行）。クローラー種別`REPOAUDIT`・毎日UTC 22:40（`REPOAUDIT_*`）
- **トークン**: `repo`スコープのclassic PATで、所有リポジトリの設定を読める。fine-grainedにする場合は、Administration（読み取り）が要る。
  最小権限化は、この点検で取れる範囲に影響するため、ユーザー判断
- API: `GET /api/repo-audit`（スコアの低い順・`only_issues`）。認可は他のAPIと同じ。ダッシュボードの画面は未実装

## 公開サイトの外形監視（Issue #401。`app/external_monitor/`）

全アプリの公開サイトを、毎日、**非侵入**（GETのみ・少数のパス・リダイレクトを辿らない）で点検する（ZAPは月1回・手動・一部のみのため）。

- **対象URL**（`targets.py`）: リポジトリのHomepage欄・Firebase（`.firebaserc`のプロジェクトID→`https://<id>.web.app`。Firestoreの確認先も）・
  GitHub Pages（`has_pages`→`https://<owner>.github.io`）を自動検出し、`EXTERNAL_MONITOR_URLS`（https・カンマ区切り）で追加できる。
  URLは`normalize_url`でスキーム＋ホストに整える。**自分の所有するドメインのみ**（リポジトリの情報由来か、明示した設定）
- **SSRF対策**（`probes.is_safe_target`）: https以外・IPの直接指定・**内部アドレス**（プライベート・ループバック・リンクローカル・予約）に
  解決されるホスト（1つでも）は、点検しない。リポジトリのHomepage等は外部入力のため、点検の直前に毎回検査する
- **点検**（`probes.py`。判定は純粋な`evaluate_*`・`looks_like_exposure`）: TLS証明書の残り日数（30日以内=WARNING・7日以内/期限切れ/検証失敗=ERROR）・
  セキュリティヘッダー（CSP・HSTSが無い=WARNING、nosniff・frame・Referrer-Policyは INFO）・露出ファイル（`/.env`・`/.git/HEAD`・`/.git/config`・
  `/firebase.json`・`/backup.zip`。**内容で判定**し、何でも200のHTMLを返すSPAを誤検知しない。内容は記録しない=ERROR）・宙ぶらりんのDNS
  （名前が解決できない・サービス側のリソースが無い表示=ERROR）・Firestore RESTの認証なし読み取り（WARNING。意図した公開範囲か確認）
- **保存**: `site_checks`（URLごとに最新の1行）。クローラー種別`EXTMON`・毎日UTC 22:35（`EXTMON_*`）
- **通知**（`core/notifications/site_alerts.py`）: **前回より増えた**ERROR・WARNING（INFOは一覧で確認）だけ、管理者のSlackへ。**初回は通知しない**
  （既存の問題が溢れるため）。外部由来の文字列は`escape_mrkdwn`で無害化
- API: `GET /api/site-monitor`（問題の重いサイトが先・`only_issues`）。セッション認証時は本人所有のリポジトリに紐づくサイトのみ
  （設定で足したサイトは管理者のみ）。ダッシュボードの画面は未実装
