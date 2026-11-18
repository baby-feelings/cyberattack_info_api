import { githubAlertItems, repoAuditItems, siteMonitorItems } from './support/mockData'
import { expect, openTab, scenario, seedSession, type Page } from './support/test'

const MATRIX = 'リポジトリ × 点検項目'
const ALERTS = 'GitHub のセキュリティアラート'
const SITES = '公開サイトの外形監視'
const STOPPED = 'baby-feelings/app-stopped'

// ログイン済みの状態で、POSTURE タブを開く
async function openPosture(page: Page) {
  await seedSession(page)
  await page.goto('/')
  await openTab(page, 'POSTURE')
}

const matrix = (page: Page) => page.getByRole('table', { name: MATRIX })
const alerts = (page: Page) => page.getByRole('table', { name: ALERTS })
const sites = (page: Page) => page.getByRole('table', { name: SITES })
// 見出しの数字: ラベルの隣の数字（例: 「4」「アラート（未対応）」）
const statValue = (page: Page, label: string) =>
  page.getByRole('group', { name: '件数の集計' }).getByText(label).locator('..')

scenario('POS-01', '未ログイン時はGitHubログイン案内とログインリンクが表示される', async ({ page }) => {
  await page.goto('/')
  await openTab(page, 'POSTURE')

  await expect(page.getByText('GitHubアカウントでログインしてください')).toBeVisible()
  await expect(page.getByText(/自分のリポジトリのアラート・設定の監査・外形監視/)).toBeVisible()
  await expect(page.getByRole('link', { name: 'GitHubでログイン' })).toHaveAttribute(
    'href', `${new URL(page.url()).origin}/__api/auth/github/login`,
  )
})

scenario('POS-02', '見出しに、未対応のアラート・設定の達成率・外形監視の問題の数が表示される', async ({ page }) => {
  await openPosture(page)

  const openAlerts = githubAlertItems.filter((a) => !a.resolved_at).length
  const rate = Math.round(repoAuditItems.reduce((sum, r) => sum + r.score, 0) / repoAuditItems.length)
  const siteIssues = siteMonitorItems.reduce((sum, s) => sum + s.issues, 0)
  await expect(statValue(page, 'アラート（未対応）')).toContainText(String(openAlerts))
  await expect(statValue(page, '設定の達成率（%）')).toContainText(String(rate))
  await expect(statValue(page, '外形監視の問題')).toContainText(String(siteIssues))
  // 外形監視の表には、取得元の列がある
  await expect(sites(page).getByRole('columnheader', { name: '取得元' })).toBeVisible()
})

scenario('POS-03', 'マトリクスの列の見出しが、APIの点検項目名で、状態が記号と文言で示される', async ({ page }) => {
  await openPosture(page)

  await expect(matrix(page).getByRole('columnheader')).toHaveText([
    'リポジトリ', 'シークレットスキャン', 'push 保護', 'ブランチ保護',
  ])
  // 不合格は ✕、強制できない・取得不可は －。色だけでなく、記号と文言でも示す
  const failed = page.getByRole('button', { name: 'baby-feelings/app-two シークレットスキャン 不合格' })
  await expect(failed).toContainText('✕')
  const notEnforceable = page.getByRole('button', { name: 'baby-feelings/app-two ブランチ保護 強制できない' })
  await expect(notEnforceable).toContainText('－')
  const unavailable = page.getByRole('button', { name: `${STOPPED} ブランチ保護 取得不可` })
  await expect(unavailable).toContainText('－')
})

scenario('POS-04', 'セルを押すと、その場で、詳細と直し方が開き、もう一度押すと閉じる', async ({ page }) => {
  await openPosture(page)
  const cell = page.getByRole('button', { name: 'baby-feelings/app-two シークレットスキャン 不合格' })

  await cell.click()
  await expect(cell).toHaveAttribute('aria-expanded', 'true')
  const detail = page.getByRole('region', { name: /app-two.*シークレットスキャン/ })
  await expect(detail).toContainText('無効になっています')
  await expect(detail).toContainText('設定の「セキュリティ」で、シークレットスキャンを有効にする')

  await cell.click()
  await expect(detail).toHaveCount(0)
})

scenario('POS-05', '「改善が必要なものだけ」の切り替えと、リポジトリ名の検索ができる', async ({ page }) => {
  await openPosture(page)
  const onlyIssues = page.getByRole('checkbox', { name: '改善が必要なものだけ' })

  // 既定は、改善が必要なものだけ（app-one は全部合格のため、出ない）
  await expect(onlyIssues).toBeChecked()
  await expect(matrix(page).getByRole('rowheader', { name: 'baby-feelings/app-one' })).toHaveCount(0)
  await expect(matrix(page).getByRole('rowheader', { name: 'baby-feelings/app-two' })).toBeVisible()

  await onlyIssues.uncheck()
  await expect(matrix(page).getByRole('rowheader', { name: 'baby-feelings/app-one' })).toBeVisible()

  await page.getByRole('searchbox', { name: 'リポジトリ名で検索' }).fill('STOPPED')
  await expect(matrix(page).getByRole('rowheader')).toHaveText([STOPPED])
})

scenario('POS-06', 'アラートを、重要度の順に並べ、種類で絞り込める', async ({ page }) => {
  await openPosture(page)

  // CRITICAL → HIGH → MEDIUM → LOW の順（解決済みは、既定では出ない）
  const rows = alerts(page).getByRole('row')
  await expect(rows).toHaveCount(1 + 4)
  await expect(rows.nth(1)).toContainText('AWS のアクセスキー')
  await expect(rows.nth(2)).toContainText('XSS の可能性')
  await expect(rows.nth(3)).toContainText('lodash の脆弱性')
  await expect(rows.nth(4)).toContainText('停止中のアプリの指摘')
  // 検知元のツール名と、外部リンクの安全な属性
  await expect(rows.nth(2)).toContainText('CodeQL')
  await expect(alerts(page).getByRole('link', { name: /XSS の可能性/ })).toHaveAttribute('rel', 'noopener noreferrer')

  await page.getByRole('combobox', { name: '種類' }).selectOption('code')
  await expect(rows).toHaveCount(1 + 2)
  await expect(alerts(page)).not.toContainText('lodash の脆弱性')
})

scenario('POS-07', '取得できなかった項目が、理由つきで、アラートの下に出る', async ({ page }) => {
  await openPosture(page)

  const note = page.getByRole('region', { name: '取得できなかった項目（機能が無効・権限不足）' })
  await expect(note).toContainText('baby-feelings/app-web')
  await expect(note).toContainText('HTTP 404')
  await expect(note).toContainText('理由不明')
})

scenario('POS-08', '1つの取得が失敗しても、ほかは表示され、再試行で復帰する', async ({ page, api }) => {
  let down = true
  api.override('GET', '/api/github-alerts', () => (down ? { status: 500, body: null } : undefined))
  await openPosture(page)

  await expect(page.getByRole('alert')).toContainText('読み込めませんでした')
  await expect(page.getByRole('alert')).not.toContainText('API error')
  await expect(matrix(page)).toBeVisible()
  await expect(sites(page)).toBeVisible()
  // 取得できなかった元は、0 ではなく、名前で示す
  await expect(page.getByText('取得できなかった項目: アラート')).toBeVisible()

  down = false
  await page.getByRole('button', { name: '再試行' }).click()

  await expect(alerts(page)).toBeVisible()
  await expect(page.getByRole('alert')).toHaveCount(0)
})

scenario('POS-09', '運用状態を切り替えると、3つのセクションが、運用中・運用停止中で絞り込まれる', async ({ page, api }) => {
  api.state.inactiveRepos = [STOPPED]
  await openPosture(page)

  // 既定は運用中。運用停止中のアプリは、どのセクションにも出ない。リポジトリに紐づかないサイトは、運用中に出る
  await expect(matrix(page).getByRole('rowheader', { name: 'baby-feelings/app-two' })).toBeVisible()
  await expect(matrix(page).getByRole('rowheader', { name: STOPPED })).toHaveCount(0)
  await expect(alerts(page)).not.toContainText('停止中のアプリの指摘')
  await expect(sites(page)).not.toContainText('app-stopped.example')
  await expect(sites(page)).toContainText('config.example')
  expect(api.lastQuery('/api/repo-audit')?.get('operating')).toBe('active')

  const filter = page.getByRole('group', { name: '運用状態フィルター' })
  await filter.getByRole('button', { name: '運用停止中' }).click()
  await expect(matrix(page).getByRole('rowheader')).toHaveText([STOPPED])
  await expect(alerts(page)).toContainText('停止中のアプリの指摘')
  await expect(sites(page)).toContainText('app-stopped.example')
  await expect(sites(page)).not.toContainText('config.example')

  await filter.getByRole('button', { name: 'すべて' }).click()
  await expect(matrix(page).getByRole('rowheader', { name: STOPPED })).toBeVisible()
  await expect(matrix(page).getByRole('rowheader', { name: 'baby-feelings/app-two' })).toBeVisible()
  // すべて＝ operating を付けない（従来どおり全件）
  expect(api.lastQuery('/api/repo-audit')?.get('operating')).toBeNull()
})

scenario('POS-10', 'スマホ幅でも、ページが横にはみ出さず、マトリクスが横スクロールし、リポジトリ名の列が固定される', async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 812 })
  await openPosture(page)
  await expect(matrix(page)).toBeVisible()

  // ページ全体は、横にスクロールしない
  const pageOverflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
  expect(pageOverflow).toBeLessThanOrEqual(1)

  // 表の入れ物が、横にスクロールできる
  const scroller = matrix(page).locator('xpath=..')
  const overflows = await scroller.evaluate((el) => el.scrollWidth > el.clientWidth)
  expect(overflows).toBe(true)

  // リポジトリ名の列は、横にスクロールしても、固定される
  const rowHeader = matrix(page).getByRole('rowheader').first()
  await expect(rowHeader).toHaveCSS('position', 'sticky')
})

scenario('POS-11', 'データが0件のとき、次の行動つきの空の状態が表示される', async ({ page, api }) => {
  api.override('GET', '/api/repo-audit', () => ({ body: { total: 0, repos_with_issues: 0, data: [] } }))
  api.override('GET', '/api/github-alerts', () => ({ body: { total: 0, data: [], unavailable: [] } }))
  api.override('GET', '/api/site-monitor', () => ({ body: { total: 0, sites_with_issues: 0, data: [] } }))
  await openPosture(page)

  await expect(page.getByText('点検の結果がありません。リポジトリ設定の監査は、毎日の取得のあとに表示されます。')).toBeVisible()
  await expect(page.getByText('未対応のアラートはありません。')).toBeVisible()
  await expect(page.getByText('外形監視の結果がありません。')).toBeVisible()
  // 0件は 0 として出す（取得できなかった、とは区別する）
  await expect(statValue(page, 'アラート（未対応）')).toContainText('0')
  await expect(page.getByText(/取得できなかった項目:/)).toHaveCount(0)
})
