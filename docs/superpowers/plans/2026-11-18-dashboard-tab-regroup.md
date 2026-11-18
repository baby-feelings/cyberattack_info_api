# ダッシュボードのタブ組み替えと概要タブ Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 5つのタブ（KEV / OSV / DEPSCAN / CODESCAN / POSTURE）を、概要・依存ライブラリ・コードと設定・運用・公開情報の5タブ（小タブ付き）に組み替え、「概要」を足す。

**Architecture:** `TabDefinition` に `subTabs` を足し、タブ・小タブとも定義（データ）から描く。DEPSCAN のモーダル4つは、枠（`FullScreenModal`）を外した `…Panel` にして小タブの中身にする。POSTURE の3セクションは、取得を単独で呼べるフックに分け、運用中／運用停止中の2区画（`OperatingGroups`）で包んで各タブに置く。概要は、既存 API の結果を `OverviewMetric`（クラス）にして集める。バックエンドは変更しない。

**Tech Stack:** React 19・TypeScript・Vite・Tailwind・Vitest・Playwright（`dashboard/`）

**Spec:** `docs/superpowers/specs/2026-11-18-dashboard-tab-regroup-design.md`

## Global Constraints
- 継承は使わず合成。文言・色分けの基準・移動先・タブ名は設定ファイル（`tabs.tsx` / `overviewConfig.ts` / `postureConfig.ts`）に置き、コンポーネントに直書きしない
- 既存の機能・画面が減らないこと。モーダルの中身のロジックは変えず、移動のみ
- 0件と「取得できない（不明）」を区別する。1つの取得失敗が他を壊さない
- 運用状態は `operating=active|inactive`（運用停止中は折りたたみで、開いたときだけ取得）。API は変更しない
- 新タブの表記: `概要` / `依存ライブラリ` / `コードと設定` / `運用` / `公開情報`（承認済み）。見出しは日本語の説明を添える既存の形式
- テスト: Vitest・型チェック（`npx tsc -b`）・ESLint（警告数上限）・E2E（網羅率100%維持。`dashboard/e2e/support/scenarios.ts` にシナリオを足す）
- ブランチは PR ごとに `main` から切る（下記の各タスクの PR）。各 PR のマージ後も、画面が壊れないこと。コミットは `feat:`/`refactor:`/`test:`/`docs:`、末尾に `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`
- `package-lock.json` は変更しない。`git add` はファイルを指定する（`dashboard/e2e/tmp-debug.spec.ts` などの未追跡ファイルを巻き込まない）

## Review Focus
- 小タブの選択状態: タブを離れて戻ると、直前の小タブが復元される（初期は先頭）
- 運用停止中の区画が空（0件）のときに、エラーでなく空の表示になる
- 概要で、1つの API が失敗しても、他の件数は出る。失敗は「不明」で、0件（緑）と区別される
- 概要のカードから移動すると、該当のタブ・小タブが選ばれる
- GitHub ログイン前は、全タブがログインの案内を出す（概要も同じ）
- OAuth のコールバック（`?depscan_code=`）から戻ると、依存ライブラリのタブが選ばれる
- モーダルをパネルにしたあとも、モーダルの Esc・閉じるボタンに依存した操作が残っていない（テスト・E2E）

---

### Task 1: 小タブの土台と「公開情報」（KEV＋OSV）  — PR 1

**Files:**
- Create: `dashboard/src/components/layout/SubTabBar.tsx`, `SubTabBar.test.tsx`
- Modify: `dashboard/src/components/layout/tabs.tsx`, `TabPanel.tsx`, `layout.test.tsx`, `dashboard/src/App.tsx`
- Modify: KEV・OSV・タブ名に依存する E2E（`grep -rn "KEV\|OSV" dashboard/e2e`）、`dashboard/e2e/support/scenarios.ts`

**Interfaces:**
- Produces: `interface SubTabDefinition { key: string; label: string; panel: ReactNode; crawlerType?: FetchedCrawlerType }`（`tabs.tsx`）。`TabDefinition` に `subTabs?: SubTabDefinition[]` を追加（`panel` は `subTabs` が無いタブだけが使う）。`TabKey` に `'public'` を追加し、`'kev'`・`'osv'` は削除
- Produces: `SubTabBar({ tabs: { key: string; label: string }[]; active: string; onSelect: (key: string) => void; idPrefix: string })` — `role="tablist"` のボタン列。選択中は `aria-selected`
- `TabPanel` は、`subTabs` があれば `SubTabBar` と選択中の小タブの `panel` を描く。選択状態は `App.tsx` が `Record<TabKey, string>` で持ち、`TabPanel` へ `subTabKey`・`onSubTabChange` として渡す（タブを離れても、戻れば復元される）。見出しの「最終取得」は、小タブの `crawlerType` があればそれ、なければタブの値

- [ ] **Step 1: Write the failing tests** — `SubTabBar.test.tsx`: 3つのボタンが `tab` ロールで出る／選択中が `aria-selected=true`／クリックで `onSelect(key)`。`layout.test.tsx`: `public` タブを選ぶと、小タブ「KEV」「OSV」が出る／OSV を押すと OSV パネルに変わる／別のタブへ移って戻ると OSV のまま
- [ ] **Step 2: Run to verify it fails** — `npx vitest run src/components/layout` → FAIL（`SubTabBar` が無い）
- [ ] **Step 3: Implement** `SubTabBar`・`TabDefinition.subTabs`・`TabPanel` の小タブ描画・`App.tsx` の選択状態。`tabs.tsx` の `kev`・`osv` を、`public`（小タブ `kev`＝`<KevPanel />`〈crawlerType `KEV`〉、`osv`＝`<OsvPanel />`〈`OSV`〉）に置き換える。この PR では、最初に開くタブは `public`（概要は Task 5）。`TabBar` は定義から描くので変更しない
- [ ] **Step 4: E2E** — KEV・OSV を前提にしたシナリオを、`公開情報` タブ→小タブの操作に直す。ヘルパー `openPublic(page, 'kev' | 'osv')` を `e2e/support/` に1か所で定義し、全シナリオで使う。`npx playwright test` が全件通り、網羅率100%
- [ ] **Step 5: 全体確認** — `npx tsc -b`、`npm run lint`、`npx vitest run` が通る
- [ ] **Step 6: Commit・PR** — `feat(dashboard): タブに小タブを足し、KEVとOSVを「公開情報」にまとめる`

### Task 2: モーダル4つをパネル化  — PR 2（Task 3 と同じ PR）

**Files:**
- Create: `dashboard/src/components/shared/PanelFrame.tsx`, `PanelFrame.test.tsx`
- Modify（ファイル名を `…Panel.tsx` に変更し、テストも改名）: `depscan/SlaModal.tsx`, `DependabotOpsModal.tsx`, `DependenciesModal.tsx`, `RuntimesModal.tsx`

**Interfaces:**
- Produces: `PanelFrame({ label, title?, icon, children })` — `FullScreenModal` と同じ見出し行（アイコン＋タイトル）を、固定配置・閉じるボタン・Esc なしで、インラインに描く
- Produces: `SlaPanel({ authToken?: string })`、`DependabotOpsPanel()`、`DependenciesPanel({ authToken?: string })`、`RuntimesPanel({ authToken?: string })`。中身（取得・表・フィルター）は既存のまま。`open`・`onClose` の props は削除

- [ ] **Step 1: Write the failing tests** — 各 `…Panel.test.tsx`: 既存の `…Modal.test.tsx` を改名し、`open`・`onClose` を使った描画を `<SlaPanel authToken="tok" />` の直接描画に直す。`role="dialog"` と閉じるボタンの検証は削除。`PanelFrame.test.tsx`: `dialog` ロールが無く、タイトルとアイコンが出る
- [ ] **Step 2: Run to verify it fails** — 該当テストが FAIL
- [ ] **Step 3: Implement** — 各 Modal の内部の `FullScreenModal` を `PanelFrame` に置き換え、外側の `open` 判定と `onClose` を削除してエクスポート名を `…Panel` にする。この時点で `DepscanPanel` はモーダル版を参照できなくなるので、Task 3 と同じブランチで続けて直し、型チェックが通る状態でコミットする（Task 2 のコミットは、`DepscanPanel` 側の呼び出しの削除を含めてよい）。`FullScreenModal` を使う場所が無くなれば、`FullScreenModal.tsx` とテストも削除する（`grep -rn FullScreenModal src`）
- [ ] **Step 4: Verify** — `npx vitest run src/components/depscan src/components/shared`、`npx tsc -b` が通る
- [ ] **Step 5: Commit** — `refactor(dashboard): DEPSCAN のモーダル4つを、枠なしのパネルにする`

### Task 3: 「依存ライブラリ」タブ  — PR 2

**Files:**
- Create: `dashboard/src/components/posture/OperatingGroups.tsx`, `OperatingGroups.test.tsx`
- Modify: `DepscanPanel.tsx`（モーダルのボタン・状態・呼び出しを削除）, `DepscanAuthGate.tsx`, `posture/usePostureData.ts`, `posture/AlertsSection.tsx`, `posture/PosturePanel.tsx`, `posture/PostureGroup.tsx`, `layout/tabs.tsx`, `App.tsx`（OAuth 復帰）
- Modify: `e2e/depscan.spec.ts` ほか、モーダルを開くシナリオ（DEP-08 など）

**Interfaces:**
- Produces: `usePostureData.ts` に取得元ごとのフック `useAuditSource(authToken, operating)`・`useAlertsSource(authToken, operating)`・`useSitesSource(authToken, operating)`（戻り値: `{ source: Source<T>; reload: () => void }`）。`usePostureData` はこの3つを束ねる形で残す（既存テストを壊さない）
- Produces: `OperatingGroups({ render }: { render: (operating: 'active' | 'inactive') => ReactNode })` — 「運用中」の見出しと `render('active')`、折りたたみの「運用停止中」（開いたときだけ `render('inactive')`）。文言は `POSTURE_TEXT.groups`
- Produces: `AlertsSection` に `kinds?: string[]`（表示する種別。省略で全種別）。`AlertKind.kind` が含まれるものだけを、一覧・件数・種別フィルターに出す
- Produces: 「依存ライブラリ」タブ（キー `'dependencies'`、`crawlerType: 'DEPSCAN'`）: 小タブ `scan`（検知＝DEPSCAN 本体）・`sla`（`SlaPanel`）・`depsops`（`DependabotOpsPanel`）・`deps`（`DependenciesPanel`）・`runtimes`（`RuntimesPanel`）・`alerts`（`OperatingGroups` ＋ `AlertsSection kinds={['dependabot']}`）。GitHub ログインは、全小タブを1つの `GithubLoginGate` で包む

- [ ] **Step 1: Write the failing tests** — `OperatingGroups.test.tsx`: 運用中は常に `render('active')`／運用停止中は閉じている間 `render('inactive')` を呼ばない／開くと呼ぶ／閉じると消える（既存 `PosturePanel.test.tsx` の該当テストを移す）。`AlertsSection.test.tsx`: `kinds={['dependabot']}` のとき他の種別が出ず、件数が合う。`layout.test.tsx`: `dependencies` タブに小タブ6つが出て、`sla` を押すと SLA パネルが出る
- [ ] **Step 2: Run to verify it fails** — FAIL
- [ ] **Step 3: Implement** — フック分割、`OperatingGroups`、`AlertsSection` の `kinds`。`DepscanPanel` からモーダル用の状態（`searchOpen`・`runtimesOpen`・`slaOpen`・`depsOpsOpen`）・ボタン・呼び出しを削除。`tabs.tsx` に `dependencies` を足し `depscan` を削除。`App.tsx` の OAuth 復帰を `'dependencies'` に変更。DEPSCAN 内の運用状態の切り替え（`OperatingFilter`）は、そのまま残す
- [ ] **Step 4: E2E** — モーダルを開くシナリオ（DEP-08・SLA・EOL・依存一覧ほか）を、`依存ライブラリ` タブ→小タブの操作に直す。ヘルパー `openDependencies(page, subTab?)` を1か所に定義する。POSTURE の dependabot 種別のシナリオは、`依存ライブラリ`→`アラート` に直す。全件通り、網羅率100%
- [ ] **Step 5: 全体確認・Commit・PR** — `feat(dashboard): 「依存ライブラリ」タブに、DEPSCAN・対応状況・依存一覧・EOL・アラートをまとめる`

### Task 4: 「コードと設定」「運用」タブ（POSTURE の解体）  — PR 3

**Files:**
- Modify: `layout/tabs.tsx`、`posture/PosturePanel.tsx`・`PostureGroup.tsx`・`PostureAuthGate.tsx`（削除）、関連テスト
- Modify: `e2e/posture.spec.ts`（分割してもよい）、`e2e/support/scenarios.ts`

**Interfaces:**
- Consumes: Task 3 の `OperatingGroups`・`useAuditSource`・`useAlertsSource`・`useSitesSource`・`AlertsSection kinds`
- Produces: 「コードと設定」タブ（キー `'code'`、`crawlerType: 'CODESCAN'`）: 小タブ `scan`（CODESCAN 本体）・`alerts`（`AlertsSection kinds={['code', 'secret']}`）・`audit`（`AuditMatrixSection`）。「運用」タブ（キー `'ops'`）: 小タブ `sites`（`SiteMonitorSection`）。`ops` の見出しの最終取得は、`freshnessConfig` に外形監視のクローラー種別があればそれを使い、無ければ表示しない（実際の定義を読んで合わせる）
- Produces: `tabs.tsx` から `TAB_KEYS`・`SUB_TAB_KEYS`（キーの定数）を export し、`overviewConfig` から移動先として参照できるようにする
- `PostureSummaryBand` と、その集計クラスは、概要で再利用する可能性があるので、この PR では削除せず `components/posture/` に残す

- [ ] **Step 1: Write the failing tests** — `layout.test.tsx`: `code` タブに小タブ3つ、`ops` タブに小タブ1つ。`code`→`alerts` で、code・secret 種別だけが出る
- [ ] **Step 2: Run to verify it fails** — FAIL
- [ ] **Step 3: Implement** — `tabs.tsx` で `codescan`・`posture` を `code`・`ops` に置き換える。不要になった `POSTURE_TAB` などの定数と文言を `postureConfig.ts` から整理する
- [ ] **Step 4: E2E** — POSTURE のシナリオ（POS-xx）と CODESCAN のシナリオを、`コードと設定`・`運用` の操作に直す。全件通り、網羅率100%
- [ ] **Step 5: Commit・PR** — `feat(dashboard): 「コードと設定」「運用」タブを作り、POSTUREを解体する`

### Task 5: 「概要」タブ  — PR 4

**Files:**
- Create: `dashboard/src/components/overview/OverviewMetric.ts`・`OverviewMetric.test.ts`・`overviewConfig.ts`・`useOverviewData.ts`・`useOverviewData.test.tsx`・`OverviewPanel.tsx`・`OverviewPanel.test.tsx`
- Modify: `layout/tabs.tsx`（先頭に `overview` を追加）、`App.tsx`（最初のタブを `overview`。移動用の `navigate`）、`e2e/`（シナリオ `OVW-01`〜）、`e2e/support/mockApi.ts`（必要なら）

**Interfaces:**
- Produces: `type MetricState = 'ok' | 'warn' | 'unknown'`。`class OverviewMetric { constructor(init: { id: string; label: string; value: number | null; target: { tab: TabKey; subTab?: string } }); readonly state: MetricState; display(): string }` — `value` が `null` なら `unknown`（`display()` は `不明`）、`0` なら `ok`、1以上なら `warn`（しきい値・文言は `overviewConfig`）
- Produces: `overviewConfig.ts`: `OVERVIEW_METRICS: { id: string; label: string; group: 'dependency' | 'code' | 'ops'; target: { tab: TabKey; subTab?: string } }[]`、グループ名、状態ごとの色クラス、文言
- Produces: `useOverviewData(authToken: string): { metrics: OverviewMetric[]; loading: boolean }`。取得元（すべて `operating: 'active'`）: 依存の未解決＝`fetchDepscanStats`（`open_total`）、対応期限超過＝`fetchSlaReport`（`overdue`の合計）、EOL間近＝`fetchRuntimes`（`status` が `eol`・`eol_soon` の件数）、コードの未解決＝`fetchCodescanStats`（`open_total`）、アラート＝`fetchGithubAlerts`（未対応の件数）、設定の達成率＝`fetchRepoAudit`（平均スコア）、外形監視の問題＝`fetchSiteMonitor`（`sites_with_issues`）。各取得は独立で、失敗は `value: null`。フィールド名は `src/api/*.ts` を読んで合わせる
- Produces: `OverviewPanel({ authToken, onNavigate }: { authToken: string; onNavigate: (target: { tab: TabKey; subTab?: string }) => void })` — グループごとにカードを並べ、押すと `onNavigate`。`App.tsx` は `setActiveTab` と小タブの選択（Task 1）を更新する

- [ ] **Step 1: Write the failing tests** — `OverviewMetric.test.ts`: `null` → `不明`・`unknown`、`0` → `ok`、`3` → `warn`。`useOverviewData.test.tsx`: 1つの取得が失敗しても、他は値が入り、失敗した指標だけ `value: null`。`OverviewPanel.test.tsx`: 件数が出る／`不明` が出る／カードを押すと `onNavigate` が `{ tab, subTab }` で呼ばれる
- [ ] **Step 2: Run to verify it fails** — FAIL
- [ ] **Step 3: Implement** — 上記のとおり。ログイン前は `GithubLoginGate` の案内を出す
- [ ] **Step 4: E2E** — `OVW-01`: 最初に開くタブが概要。`OVW-02`: 件数が出て、API 失敗でその指標だけ「不明」。`OVW-03`: カードを押すと、該当のタブ・小タブ（例: 依存ライブラリ→対応状況）が開く。Task 1 で `public` にした「最初のタブ」前提のシナリオを、「最初は概要」に直す。全件通り、網羅率100%
- [ ] **Step 5: Commit** — `feat(dashboard): 「概要」タブを足す`

### Task 6: ドキュメント  — PR 4 に含める

**Files:**
- Modify: `CLAUDE.md`（`dashboard/` の行のタブ数・名前を1行で直す。200行以内）、`README.md`（200行以内）、`.claude/skills/dashboard-frontend/SKILL.md`（500行以内。超えるなら別ファイルへ分割）、`docs/` のタブ名の記述（`grep -rn "POSTURE\|DEPSCAN タブ\|CODESCAN タブ" docs README.md .claude/skills`）

- [ ] **Step 1:** タブの構成・小タブ・概要の仕組み（`OverviewMetric`・`overviewConfig`）・小タブの状態の持ち方を、スキルに書く。旧タブ名（POSTURE・KEV／OSV のタブ）の記述を新しい構成に直す
- [ ] **Step 2:** 行数の上限を `wc -l` で確認する
- [ ] **Step 3: Commit** — `docs: タブの組み替えと概要タブを反映する`
