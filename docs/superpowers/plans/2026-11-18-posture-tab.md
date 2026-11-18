# ダッシュボード「態勢」タブ 実装計画

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** ダッシュボードに新タブ「態勢」を足し、GitHub アラート・設定の監査・外形監視を、1画面で見られるようにする。

**Architecture:** 既存の3つの API（`/api/github-alerts`・`/api/repo-audit`・`/api/site-monitor`）に、`operating` の絞り込みだけを足す。フロントは、API の生データを受け取る小さな不変クラス（`model/`）が、集計・絞り込みを担い、画面は描くだけにする。文言・配色・順位は `postureConfig.ts` の1か所に置く。

**Tech Stack:** FastAPI・SQLAlchemy・pytest／React 19・TypeScript・Tailwind・lucide-react・Vitest・Playwright。

**Spec:** `docs/superpowers/specs/2026-11-18-posture-tab-design.md`

## Global Constraints
- 文言・配色・順位・件数は `components/posture/postureConfig.ts` だけに置く。点検項目の名前・直し方は、API の `label`・`fix` を使う（画面に項目名を持たない）。
- 外形監視の判定は、API の `findings` に従う。画面でしきい値を再計算しない。
- 状態は、色と記号（✓ ✕ －）の両方で示す。マトリクスのセルは `<button>`、名前に「リポジトリ・項目・状態」を含める。
- 外部データの URL は `safeHttpUrl`（`shared/safeUrl.ts`）で http(s) のみリンク化する。シークレットの値・コードの断片は出さない。
- 継承を使わず、合成で作る。クラスは不変（`readonly`）。画面は、クラスのメソッドの結果を描くだけ。
- E2E のシナリオ網羅率90%を保つ。CSP は変更しない。
- 行数: CLAUDE.md は200行以内（現在200。**1行の中で直す**）、README・docs の分割ファイルは200行以内、スキルは500行以内。
- コミット: `feat:`/`test:`/`docs:`。ブランチは PR ごとに `main` から切る（PR1 `feat/operating-filter-posture-api`・PR2 `feat/posture-model`・PR3 `feat/dashboard-posture-tab`）。

## Review Focus
1. API が、未知の状態文字列（例 `foo`）を返す → 「取得不可」として描く。クラッシュしない（Task 3）。
2. 一部のリポジトリに、他にある点検項目が無い → そのセルは「取得不可」。列は、全リポジトリの項目の和集合（Task 3）。
3. 3つの取得のうち1つが失敗 → ほかのセクションは表示し、失敗した部分に原因と再試行を出す（Task 5・6）。
4. データが0件（リポジトリ0・アラート0・サイト0）→ 空の状態を、次の行動つきで出す（Task 6）。
5. `html_url` が `javascript:` など http(s) 以外 → リンクにしない（Task 4）。
6. 運用停止中のアプリが大半 → 初期表示は「運用中」（Task 5・6）。サイトの `repo_full_name` が NULL → 運用中として扱う（Task 1）。

---

## PR1: バックエンド（Task 1）

### Task 1: 3つの GET に `operating` を足す
**Files:** Modify `app/repo_audit/router.py`・`app/github_alerts/router.py`・`app/external_monitor/router.py`／Test `tests/repo_audit/test_repo_audit.py`・`tests/github_alerts/test_github_alerts.py`・`tests/external_monitor/test_external_monitor.py`

**Interfaces:**
- Consumes: `OperatingQuery`・`apply_operating_status(query, repo_column, operating)`（`app/core/findings/operating_status.py`。CODESCAN の `router.py` の使い方が手本）。
- Produces: 3つの一覧 API の、クエリ `operating: OperatingQuery = "all"`。`all` は従来どおり。

- [ ] **Step 1: 失敗するテストを書く**（各ファイルに1件。`INACTIVE_REPOS` は `tests/core/findings/test_operating_status.py` の `_CFG` と同じパッチ方法）
  - `test_operating_active_excludes_inactive_repos`: 運用停止中の1件と運用中の1件を保存し、`?operating=active` で運用中だけ、`inactive` で停止中だけ、指定なしで両方。
  - 外形監視だけ: `test_operating_treats_null_repo_as_active`: `repo_full_name=None` の行は、`active` と `all` に出て、`inactive` に出ない。
- [ ] **Step 2: 失敗を確認** `pytest tests/repo_audit tests/github_alerts tests/external_monitor -q` → 追加した3件が FAIL。
- [ ] **Step 3: 実装** 各 `get_*` に `operating: OperatingQuery = "all"` を足し、`query = apply_operating_status(query, <モデル>.repo_full_name, operating)` を、所有者の絞り込みの直後に入れる。外形監視は、NULL の行を `or_(col.is_(None), …)` で、`active` に含める（`~in_inactive` は NULL を落とすため）。
- [ ] **Step 4: 通過を確認** 同じコマンド → PASS。`ruff check app/ tests/` と `mypy app/ --ignore-missing-imports` も通す。
- [ ] **Step 5: コミット・PR** `feat: 態勢の3つのAPIに運用状態（operating）の絞り込みを足す`。`api-usage` スキルの該当 API の表に `operating` を1行足す（同じコミット）。PR を作る（マージは、依頼があったとき）。

---

## PR2: フロントの土台（Task 2〜4）

### Task 2: API クライアント
**Files:** Create `dashboard/src/api/posture.ts`・`dashboard/src/api/posture.test.ts`／Modify `dashboard/src/api/client.ts`（`export * from './posture'` を1行）

**Interfaces — Produces:**
```ts
export interface AuditCheckOut { key: string; label: string; status: string; weight: number; detail: string; fix: string }
export interface RepoAuditOut { repo_full_name: string; score: number | null; issues: number; checks: AuditCheckOut[]; changes: Record<string, unknown>[]; audited_at: string }
export interface RepoAuditResponse { total: number; repos_with_issues: number; data: RepoAuditOut[] }
export interface GithubAlertOut { kind: string; repo_full_name: string; number: number; severity: string | null; title: string; html_url: string; detail: Record<string, unknown>; detected_at: string; resolved_at: string | null }
export interface UnavailableSource { kind: string; repo_full_name: string; reason: string | null }
export interface GithubAlertListResponse { total: number; data: GithubAlertOut[]; unavailable: UnavailableSource[] }
export interface SiteFindingOut { rule: string; severity: string; message: string }
export interface SiteCheckOut { url: string; source: string; repo_full_name: string | null; tls_days_left: number | null; issues: number; findings: SiteFindingOut[]; checked_at: string }
export interface SiteMonitorResponse { total: number; sites_with_issues: number; data: SiteCheckOut[] }
export function fetchRepoAudit(p: { onlyIssues?: boolean; operating?: OperatingStatus; authToken?: string }): Promise<RepoAuditResponse>
export function fetchGithubAlerts(p: { kind?: string | null; repo?: string | null; resolved?: boolean; operating?: OperatingStatus; authToken?: string }): Promise<GithubAlertListResponse>
export function fetchSiteMonitor(p: { onlyIssues?: boolean; operating?: OperatingStatus; authToken?: string }): Promise<SiteMonitorResponse>
```
URL の接頭辞は、定数 `POSTURE_PATHS = { audit: '/api/repo-audit', alerts: '/api/github-alerts', sites: '/api/site-monitor' } as const`。クエリは `withOperating`（`api/shared.ts`）と `apiFetch` を使う（`codescan.ts` が手本）。

- [ ] **Step 1: テスト**（`codescan.test.ts` の方式。`fetch` をモック）: `fetchRepoAudit({ onlyIssues: true, operating: 'active' })` が `…/api/repo-audit?only_issues=true&operating=active` を呼ぶ／`fetchGithubAlerts({ kind: 'code', resolved: false })` が `kind=code` を付け、`resolved` は付けない／`operating: 'all'` は付けない／`authToken` 指定で `Authorization: Bearer` を送る。
- [ ] **Step 2: 失敗を確認** `cd dashboard && npx vitest run src/api/posture.test.ts`
- [ ] **Step 3: 実装** 上記のインターフェースどおり。
- [ ] **Step 4: 通過を確認**、`npm run lint` と `npx tsc --noEmit`。
- [ ] **Step 5: コミット** `feat(dashboard): 態勢の3つのAPIクライアントを追加する`

### Task 3: 設定と、設定の監査のクラス
**Files:** Create `dashboard/src/components/posture/postureConfig.ts`・`model/AuditStatus.ts`・`model/AuditCheck.ts`・`model/RepoAudit.ts`・`model/AuditMatrix.ts`と、各 `*.test.ts`

**Interfaces — Produces:**
```ts
// postureConfig.ts
export const AUDIT_STATUS_VIEW: Record<AuditStatusKind, { label: string; glyph: string; cls: string }>  // ok / ng / unavailable / not_enforceable
export const POSTURE_PER_PAGE: number   // numberFromEnv(import.meta.env.VITE_POSTURE_PER_PAGE, 50)
// model
export type AuditStatusKind = 'ok' | 'ng' | 'unavailable' | 'not_enforceable'
export class AuditStatus { static from(raw: string): AuditStatus; readonly kind: AuditStatusKind; isScored(): boolean }   // 未知の値は 'unavailable'
export class AuditCheck { constructor(raw: AuditCheckOut); readonly key; label; status: AuditStatus; weight; detail; fix }
export class RepoAudit { constructor(raw: RepoAuditOut); readonly repo: string; score: number | null; issues: number; checkOf(key: string): AuditCheck | undefined }
export class AuditMatrix {
  constructor(rows: RepoAudit[]); static fromResponse(r: RepoAuditResponse): AuditMatrix
  columns(): { key: string; label: string }[]                       // 全リポジトリの項目の和集合。初出の順
  rows(opts?: { query?: string; onlyIssues?: boolean }): RepoAudit[] // query は大文字小文字を区別しない部分一致
  averageScore(): number | null                                      // 点検できたリポジトリだけの平均（四捨五入）。0件は null
}
```
- [ ] **Step 1: テスト** `AuditStatus.from('foo').kind === 'unavailable'`・`from('ok')`・`isScored()` は ok と ng だけ true／`AuditMatrix.columns()` は、2つのリポジトリで項目が食い違っても和集合・初出順で、ラベルは API の値／`rows({ onlyIssues: true })`・`rows({ query: 'BABY' })`／`averageScore()` が、`score: null` を除いて平均し、全て null なら `null`／`checkOf('無い項目')` が `undefined`。
- [ ] **Step 2: 失敗を確認** `npx vitest run src/components/posture/model`
- [ ] **Step 3: 実装** クラスは `readonly` と合成で作る（継承なし）。`AUDIT_STATUS_VIEW` に、状態ごとの表示名・記号（✓・✕・－・－）・Tailwind のクラスを置く。`not_enforceable` の表示名は「強制できない」。
- [ ] **Step 4: 通過を確認**、lint・型。
- [ ] **Step 5: コミット** `feat(dashboard): 設定の監査のクラス（AuditMatrix など）と設定を追加する`

### Task 4: アラート・外形監視・見出しのクラス
**Files:** Create `model/AlertKind.ts`・`model/GithubAlert.ts`・`model/AlertList.ts`・`model/SiteCheck.ts`・`model/PostureSummary.ts`と各テスト／Modify `postureConfig.ts`

**Interfaces — Produces:**
```ts
// postureConfig.ts に追加
export const ALERT_KIND_VIEW: Record<'secret' | 'dependabot' | 'code', { label: string; icon: 'KeyRound' | 'Package' | 'ScanSearch' }>
export const ALERT_SEVERITY_RANK: Record<string, number>        // critical 0 / high 1 / medium 2 / low 3。未知は最後
export const ALERT_SEVERITY_CLASS: Record<string, string>
// model
export class AlertKind { static of(kind: string): AlertKind; readonly kind: string; label(): string }  // 未知の種類は、値をそのまま表示名にする
export class GithubAlert { constructor(raw: GithubAlertOut); readonly repo: string; title: string; severity: string | null; kind: AlertKind; safeUrl(): string | null; severityRank(): number; tool(): string | null }  // tool は detail.tool を文字列のときだけ
export class AlertList {
  constructor(alerts: GithubAlert[], unavailable: UnavailableSource[]); static fromResponse(r: GithubAlertListResponse): AlertList
  filter(opts: { kind?: string | null; severity?: string | null }): AlertList
  sorted(): GithubAlert[]            // 重要度の順位、次にリポジトリ名
  count(): number; countsByKind(): Record<string, number>; readonly unavailable: UnavailableSource[]
}
export class SiteCheck { constructor(raw: SiteCheckOut); worstSeverity(): 'ERROR' | 'WARNING' | null; readonly issues: number; tlsDaysLeft: number | null; findings: SiteFindingOut[] }
export class PostureSummary {
  constructor(src: { alerts: AlertList | null; audit: AuditMatrix | null; sites: SiteCheck[] | null })
  openAlerts(): number | null; auditRate(): number | null; siteIssues(): number | null   // 取得できなかった源は null（0 と区別する）
}
```
- [ ] **Step 1: テスト** `GithubAlert.safeUrl()` は `https://…` を返し、`javascript:alert(1)`・空文字は `null`（`safeHttpUrl` を使う）／`AlertList.sorted()` の順位／`filter` が不変（元の `AlertList` を変えない）／`AlertKind.of('unknown').label() === 'unknown'`／`SiteCheck.worstSeverity()` は ERROR があれば ERROR、INFO だけなら `null`／`PostureSummary` は、`alerts: null` のとき `openAlerts() === null`（0 ではない）。
- [ ] **Step 2: 失敗を確認** `npx vitest run src/components/posture/model`
- [ ] **Step 3: 実装** 判定の基準値は、すべて `postureConfig.ts`（順位・クラス）から読む。外形監視の判定は、`findings` の `severity` をそのまま使う。
- [ ] **Step 4: 通過を確認**、lint・型。
- [ ] **Step 5: コミット・PR2** `feat(dashboard): アラート・外形監視・見出しのクラスを追加する`。PR を作る。

---

## PR3: 画面（Task 5〜9）

### Task 5: データ取得とログインゲート
**Files:** Create `components/posture/usePostureData.ts`・`components/shared/GithubLoginGate.tsx`・`components/posture/PostureAuthGate.tsx`と各テスト

**Interfaces:**
- Consumes: Task 2〜4 の `fetch*` とクラス。`useGithubSession()`（`hooks/useGithubSession.ts`。`session.token`・`checked`）。
- Produces:
```ts
export type Source<T> = { status: 'loading' } | { status: 'ready'; value: T } | { status: 'error'; message: string }
export function usePostureData(authToken: string, operating: OperatingStatus): { audit: Source<AuditMatrix>; alerts: Source<AlertList>; sites: Source<SiteCheck[]>; reload: (which?: 'audit' | 'alerts' | 'sites') => void }
export function GithubLoginGate(p: { description: string; children: (session: GithubSession) => ReactNode }): JSX.Element
```
- [ ] **Step 1: テスト** 3つのうち `fetchGithubAlerts` だけ失敗 → `alerts.status === 'error'`・`audit`・`sites` は `ready`／`reload('alerts')` が、アラートだけを取り直す／`operating` を変えると3つとも取り直す／`GithubLoginGate` が、未ログインでログインのリンクを出し、ログイン済みで `children(session)` を描く（`CodescanAuthGate.test.tsx` が手本）。
- [ ] **Step 2: 失敗を確認** → **Step 3: 実装**（`useCodescanData.ts` の構成パターン。3つの取得を独立に `Promise` で行う）→ **Step 4: 通過を確認**
- [ ] **Step 5: コミット** `feat(dashboard): 態勢のデータ取得とログインゲートを追加する`

### Task 6: 画面のセクション
**Files:** Create `components/posture/PosturePanel.tsx`・`PostureSummaryBand.tsx`・`AuditMatrixSection.tsx`・`AlertsSection.tsx`・`SiteMonitorSection.tsx`と各テスト

**Interfaces — Consumes:** `usePostureData`・各クラス・`StatBand`・`SeverityBadge`・`OperatingFilter`・`LastFetched`・`CollapsibleSection`（`components/shared/`）。`PosturePanel({ authToken }: { authToken: string })`。

- [ ] **Step 1: テスト（コンポーネント）**
  - マトリクス: 列の見出しが API の `label`／セルは `button`、名前が「`<repo> <項目> <状態の表示名>`」／押すと、その場で、詳細と直し方が開く／`unavailable` のセルは「－」と「取得不可」／0件で空の状態（「点検の結果がありません。リポジトリ設定の監査は、毎日の取得のあとに表示されます」の趣旨）。
  - アラート: 種類・重要度の絞り込み、`unavailable` が理由つきで一覧の下に出る、`html_url` が `javascript:` ならリンクにならない。
  - 外形監視: TLS 残日数と指摘の表示、0件の空の状態。
  - 見出し: 取得失敗の源は「不明」と表示し、0 と区別する。
  - 失敗したセクションに「再試行」ボタンがあり、押すと `reload(その源)` が呼ばれる。
- [ ] **Step 2: 失敗を確認** `npx vitest run src/components/posture`
- [ ] **Step 3: 実装** 文言は、`postureConfig.ts` に追加して使う。マトリクスは、横スクロール＋リポジトリ名の列を固定（`sticky left-0`）。初期の運用状態は `'active'`。自動の動きは、つけない。
- [ ] **Step 4: 通過を確認**、`npm run lint`（警告の上限を超えない）・`npx tsc --noEmit`。
- [ ] **Step 5: コミット** `feat(dashboard): 態勢の各セクションを追加する`

### Task 7: タブの登録と最終取得
**Files:** Modify `components/layout/tabs.tsx`（`TabKey` に `'posture'`、`TAB_DEFINITIONS` に1件。`panel` は `<PostureAuthGate />`）・`components/freshness/freshnessConfig.ts`（`FetchedCrawlerType` に `'GHALERT' | 'REPOAUDIT' | 'EXTMON'`）・`App.tsx` の「データソース」の文言・`components/layout/layout.test.tsx`・`App.test.tsx`

- [ ] **Step 1: テスト** タブが5つ、新タブの見出し「態勢」、各セクションの見出しに、対応する `LastFetched` が出る（`crawlerType` が GHALERT／REPOAUDIT／EXTMON）。既存の「4つ」を前提にしたテストを、5つに直す。
- [ ] **Step 2〜4:** 失敗を確認 → 実装（タブ見出しの最終取得は、`TabDefinition.crawlerType` に GHALERT を指定し、各セクションに、それぞれの最終取得を足す）→ `npx vitest run`（全件）。
- [ ] **Step 5: コミット** `feat(dashboard): 態勢タブを登録する`

### Task 8: E2E
**Files:** Modify `e2e/support/scenarios.ts`・`e2e/support/mockApi.ts`・`e2e/support/mockData.ts`・`e2e/support/test.ts`（`openTab` の型に `'態勢'`）・`e2e/app.spec.ts`（APP-02 を5タブに）／Create `e2e/posture.spec.ts`

- [ ] **Step 1: カタログ**（`scenarios.ts`）に追加: `POS-01` 未ログインでログイン案内／`POS-02` 3つの見出しの数値／`POS-03` マトリクスの列がAPIの項目名／`POS-04` セルを押すと詳細と直し方／`POS-05` 「改善が必要なものだけ」と検索／`POS-06` アラートを種類で絞る／`POS-07` 取得不可の項目が理由つきで出る／`POS-08` 1つの取得が失敗してもほかは表示し、再試行で復帰／`POS-09` 運用状態の切り替え（`operating` が API に渡る）／`POS-10` スマホ幅で横スクロールし、リポジトリ名の列が固定される／`POS-11` 0件の空の状態。
- [ ] **Step 2: モック** `GET /api/repo-audit`・`/api/github-alerts`・`/api/site-monitor` を `mockApi.ts` に足す（`operatingKeep` の方式で `operating` に反応）。
- [ ] **Step 3: テスト** `posture.spec.ts` に、上の `scenario('POS-xx', …)` を書く。
- [ ] **Step 4: 実行** `npm run e2e:typecheck && npm run e2e` → 全件 PASS、網羅率90%以上。
- [ ] **Step 5: コミット** `test(dashboard): 態勢タブのE2Eを追加する`

### Task 9: ドキュメントと PR3
**Files:** Modify `.claude/skills/dashboard-frontend/SKILL.md`（態勢タブの構成・クラス・設定の置き場所・E2E の追加）・`CLAUDE.md`（103行目「4タブ切替」→「5タブ切替」。**行を足さない**）・`README.md`（タブの説明）・`docs/` のタブに触れる箇所

- [ ] **Step 1:** `grep -rn "4タブ\|4つのタブ" README.md CLAUDE.md docs .claude` で、直す箇所を洗い出して、直す。
- [ ] **Step 2: 行数を確認** `wc -l CLAUDE.md README.md .claude/skills/*/SKILL.md docs/*.md` → CLAUDE.md が200以内、スキルが500以内、README・docs が200以内。
- [ ] **Step 3: 全体の確認** `cd dashboard && npx vitest run && npm run lint && npm run e2e:typecheck && npm run e2e`、`pytest -q`。
- [ ] **Step 4: コミット・PR3** `docs: 態勢タブを、ドキュメントに反映する`。PR を作り、CI を確認する（マージは、依頼があったとき）。
