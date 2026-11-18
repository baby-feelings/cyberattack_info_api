import { siteMonitorItems } from './support/mockData'
import { expect, openCode, openTab, scenario, seedSession, type Page } from './support/test'

// 「コードと設定」タブ（アラート・設定の監査）と「運用」タブ（外形監視）のシナリオ。
// 以前は1つの「態勢」タブだったため、シナリオ番号（POS-xx）は引き継いでいる。

const MATRIX = 'リポジトリ × 点検項目'
const ALERTS = 'GitHub のセキュリティアラート'
const SITES = '公開サイトの外形監視'
const STOPPED = 'baby-feelings/app-stopped'

// ログイン済みの状態で、「コードと設定」タブの小タブを開く
async function openCodeLoggedIn(page: Page, sub: 'アラート' | '設定の監査') {
  await seedSession(page)
  await page.goto('/')
  await openCode(page, sub)
}

// ログイン済みの状態で、「運用」タブを開く
async function openOps(page: Page) {
  await seedSession(page)
  await page.goto('/')
  await openTab(page, '運用')
}

const matrix = (page: Page) => page.getByRole('table', { name: MATRIX })
const alerts = (page: Page) => page.getByRole('table', { name: ALERTS })
const sites = (page: Page) => page.getByRole('table', { name: SITES })

scenario('POS-01', '未ログイン時は、コードと設定・運用のタブに、GitHubログイン案内とログインリンクが表示される', async ({ page }) => {
  await page.goto('/')
  await openTab(page, '運用')

  await expect(page.getByText('GitHubアカウントでログインしてください')).toBeVisible()
  await expect(page.getByText(/公開サイトの外形監視の結果/)).toBeVisible()
  await expect(page.getByRole('link', { name: 'GitHubでログイン' })).toHaveAttribute(
    'href', `${new URL(page.url()).origin}/__api/auth/github/login`,
  )

  await openTab(page, 'コードと設定')
  await expect(page.getByText('GitHubアカウントでログインしてください')).toBeVisible()
  await expect(page.getByText(/GitHub のアラート・リポジトリ設定の監査/)).toBeVisible()
})

scenario('POS-02', '外形監視の表に、取得元・TLS・指摘の列が表示される', async ({ page }) => {
  await openOps(page)

  await expect(sites(page)).toBeVisible()
  await expect(sites(page).getByRole('columnheader', { name: '取得元' })).toBeVisible()
  // 指摘のあるサイトの件数が、表に出ている
  const withIssues = siteMonitorItems.filter((s) => s.issues > 0).length
  expect(withIssues).toBeGreaterThan(0)
})

scenario('POS-03', 'マトリクスの列の見出しが、APIの点検項目名で、状態が記号と文言で示される', async ({ page }) => {
  await openCodeLoggedIn(page, '設定の監査')

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
  await openCodeLoggedIn(page, '設定の監査')
  const cell = page.getByRole('button', { name: 'baby-feelings/app-two シークレットスキャン 不合格' })

  await cell.click()
  await expect(cell).toHaveAttribute('aria-expanded', 'true')
  const detail = page.getByRole('region', { name: /app-two.*シークレットスキャン/ })
  await expect(detail).toContainText('無効になっています')
  await expect(detail).toContainText('設定の「セキュリティ」で、シークレットスキャンを有効にする')

  // 詳細は、押したセルの行の、すぐ下に出る（表の下ではない）
  const cellBox = (await cell.boundingBox())!
  const detailBox = (await detail.boundingBox())!
  expect(detailBox.y).toBeGreaterThan(cellBox.y)
  expect(detailBox.y - cellBox.y).toBeLessThan(120)

  await cell.click()
  await expect(detail).toHaveCount(0)

  // 「閉じる」でも閉じる
  await cell.click()
  await detail.getByRole('button', { name: '閉じる' }).click()
  await expect(detail).toHaveCount(0)
})

scenario('POS-05', '「改善が必要なものだけ」の切り替えと、リポジトリ名の検索ができる', async ({ page }) => {
  await openCodeLoggedIn(page, '設定の監査')
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

scenario('POS-06', 'コードのアラートを、重要度の順に並べ、種類で絞り込める（Dependabot は、依存ライブラリのタブに出る）', async ({ page }) => {
  await openCodeLoggedIn(page, 'アラート')

  // CRITICAL → HIGH → LOW の順（解決済みは、既定では出ない。Dependabot は、このタブには出ない）
  const rows = alerts(page).getByRole('row')
  await expect(rows).toHaveCount(1 + 3)
  await expect(rows.nth(1)).toContainText('AWS のアクセスキー')
  await expect(rows.nth(2)).toContainText('XSS の可能性')
  await expect(rows.nth(3)).toContainText('停止中のアプリの指摘')
  await expect(alerts(page)).not.toContainText('lodash の脆弱性')
  // 検知元のツール名と、外部リンクの安全な属性
  await expect(rows.nth(2)).toContainText('CodeQL')
  await expect(alerts(page).getByRole('link', { name: /XSS の可能性/ })).toHaveAttribute('rel', 'noopener noreferrer')

  await page.getByRole('combobox', { name: '種類' }).selectOption('code')
  await expect(rows).toHaveCount(1 + 2)
  await expect(alerts(page)).not.toContainText('AWS のアクセスキー')
})

scenario('POS-07', '取得できなかった項目が、理由つきで、アラートの下に出る', async ({ page }) => {
  await openCodeLoggedIn(page, 'アラート')

  const note = page.getByRole('region', { name: '取得できなかった項目（機能が無効・権限不足）' })
  await expect(note).toContainText('baby-feelings/app-web')
  await expect(note).toContainText('HTTP 404')
  await expect(note).toContainText('理由不明')
})

scenario('POS-08', '1つの取得が失敗しても、ほかの小タブは表示され、再試行で復帰する', async ({ page, api }) => {
  let down = true
  api.override('GET', '/api/github-alerts', () => (down ? { status: 500, body: null } : undefined))
  await openCodeLoggedIn(page, 'アラート')

  await expect(page.getByRole('alert')).toContainText('読み込めませんでした')
  await expect(page.getByRole('alert')).not.toContainText('API error')

  // ほかの取得元（設定の監査）は、影響を受けない
  await openCode(page, '設定の監査')
  await expect(matrix(page)).toBeVisible()

  // 戻ると、取得し直す（まだ失敗している）。復旧してから、再試行を押す
  await openCode(page, 'アラート')
  await expect(page.getByRole('alert')).toContainText('読み込めませんでした')
  down = false
  await page.getByRole('button', { name: '再試行' }).click()

  await expect(alerts(page)).toBeVisible()
  await expect(page.getByRole('alert')).toHaveCount(0)
})

scenario('POS-09', '運用中と運用停止中が別の区画に分かれ、運用停止中は開いたときにだけ表示される', async ({ page, api }) => {
  api.state.inactiveRepos = [STOPPED]
  await openCodeLoggedIn(page, '設定の監査')

  // 運用中の区画: 運用停止中のアプリは、出ない
  await expect(matrix(page).getByRole('rowheader', { name: 'baby-feelings/app-two' })).toBeVisible()
  await expect(matrix(page).getByRole('rowheader', { name: STOPPED })).toHaveCount(0)
  expect(api.lastQuery('/api/repo-audit')?.get('operating')).toBe('active')

  // 運用停止中の区画は、閉じている間は取得しない
  const toggle = page.getByRole('button', { name: /運用停止中/ })
  await expect(toggle).toHaveAttribute('aria-expanded', 'false')
  await expect(matrix(page)).toHaveCount(1)

  // 開くと、運用停止中のアプリだけが、もう1つの表に出る
  await toggle.click()
  await expect(toggle).toHaveAttribute('aria-expanded', 'true')
  await expect(matrix(page)).toHaveCount(2)
  const stopped = page.getByRole('region', { name: '運用停止中' })
  await expect(stopped.getByRole('rowheader')).toHaveText([STOPPED])
  expect(api.lastQuery('/api/repo-audit')?.get('operating')).toBe('inactive')

  // 閉じると、運用停止中の区画は消える（運用中の区画は残る）
  await toggle.click()
  await expect(matrix(page)).toHaveCount(1)

  // 外形監視（運用タブ）も同じ。リポジトリに紐づかないサイトは、運用中に出る
  await openTab(page, '運用')
  await expect(sites(page)).toContainText('config.example')
  await expect(sites(page)).not.toContainText('app-stopped.example')
  await page.getByRole('button', { name: /運用停止中/ }).click()
  await expect(page.getByRole('region', { name: '運用停止中' })).toContainText('app-stopped.example')
})

scenario('POS-10', 'スマホ幅でも、ページが横にはみ出さず、マトリクスが横スクロールし、リポジトリ名の列が固定される', async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 812 })
  await openCodeLoggedIn(page, '設定の監査')
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
  await openCodeLoggedIn(page, '設定の監査')
  await expect(page.getByText('点検の結果がありません。リポジトリ設定の監査は、毎日の取得のあとに表示されます。')).toBeVisible()

  await openCode(page, 'アラート')
  await expect(page.getByText('未対応のアラートはありません。')).toBeVisible()

  await openTab(page, '運用')
  await expect(page.getByText('外形監視の結果がありません。')).toBeVisible()
  // 0件は 0 として出す（取得できなかった、とは区別する）。エラーは出ない
  await expect(page.getByRole('alert')).toHaveCount(0)
})
