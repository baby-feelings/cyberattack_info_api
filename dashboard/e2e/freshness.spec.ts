import { RECENT_CRAWL_HOURS_AGO } from './support/mockApi'
import { expect, openTab, scenario, seedSession } from './support/test'

// 現在時刻の hoursAgo 時間前に終わった実行（モックの実行履歴 1 件分）
function crawlerLog(status: string, hoursAgo: number, inserted = 0) {
  const finished = new Date(Date.now() - hoursAgo * 3_600_000).toISOString()
  return {
    id: 1, crawler_type: 'KEV', status, started_at: finished, finished_at: finished,
    duration_seconds: 60, inserted, updated: 0, deleted: 0,
    error_message: status === 'success' ? null : 'boom',
  }
}

const lastFetched = (page: import('@playwright/test').Page) => page.getByTestId('last-fetched')

scenario('FRS-01', '各タブの見出しに、そのタブのクローラーの最終取得が表示される', async ({ page, api }) => {
  await page.goto('/')
  await expect(lastFetched(page)).toBeVisible()
  const tabs = [
    ['KEV', 'KEV'], ['OSV', 'OSV'], ['JVN', 'JVN'], ['DEPSCAN', 'DEPSCAN'], ['CODESCAN', 'CODESCAN'],
  ] as const
  for (const [tab, crawlerType] of tabs) {
    await openTab(page, tab)
    // 見出しは、ログイン前でも表示される（ログインが要るのは、見出しの下の本体だけ）
    await expect(lastFetched(page)).toBeVisible()
    await expect.poll(() => api.requestsTo('/api/crawler-logs')
      .some((r) => r.query.get('crawler_type') === crawlerType)).toBe(true)
  }
})

scenario('FRS-02', '成功から日が浅いと、相対時間・日時・新規件数が表示される', async ({ page, api }) => {
  api.override('GET', '/api/crawler-logs', () => ({ body: [crawlerLog('success', RECENT_CRAWL_HOURS_AGO, 2)] }))
  await page.goto('/')

  const box = lastFetched(page)
  await expect(box).toHaveAttribute('data-state', 'fresh')
  await expect(box).toContainText('最終取得')
  await expect(box).toContainText(`${RECENT_CRAWL_HOURS_AGO} 時間前`)
  await expect(box).toContainText('新規 2 件')
  await expect(box.locator('time')).toHaveAttribute('datetime', /^\d{4}-\d{2}-\d{2}T/)
})

scenario('FRS-03', '成功から時間が空くと「更新が遅れています」と表示される', async ({ page, api }) => {
  api.override('GET', '/api/crawler-logs', () => ({ body: [crawlerLog('success', 40)] }))
  await page.goto('/')

  const box = lastFetched(page)
  await expect(box).toHaveAttribute('data-state', 'stale')
  await expect(box).toContainText('更新が遅れています')
  // 「昨日」ではなく、24時間ごとに数えた「1 日前」と表示される
  await expect(box).toContainText('1 日前')
})

scenario('FRS-04', '直近の実行が失敗していると、失敗と最終成功が表示される', async ({ page, api }) => {
  api.override('GET', '/api/crawler-logs', () => ({ body: [crawlerLog('error', 1), crawlerLog('success', 26)] }))
  await page.goto('/')

  const box = lastFetched(page)
  await expect(box).toHaveAttribute('data-state', 'failed')
  await expect(box).toContainText('直近の実行が失敗')
  await expect(box).toContainText('最終成功')
})

scenario('FRS-05', '実行履歴を取得できなくても、画面は動き「確認できません」と表示される', async ({ page, api }) => {
  api.override('GET', '/api/crawler-logs', () => ({ status: 500, body: { detail: 'down' } }))
  await page.goto('/')

  await expect(lastFetched(page)).toContainText('取得状況を確認できません')
  await expect(lastFetched(page)).toHaveAttribute('data-state', 'unknown')
  // 他の表示は、そのまま動く
  await expect(page.getByText('サーバー稼働状況')).toBeVisible()
})

scenario('FRS-06', '言語・実行環境の画面にも、最終取得が表示される', async ({ page, api }) => {
  await seedSession(page)
  await page.goto('/')
  await openTab(page, 'DEPSCAN')
  await page.getByRole('button', { name: '言語・実行環境' }).click()

  const dialog = page.getByRole('dialog', { name: '言語・実行環境' })
  await expect(dialog.getByTestId('last-fetched')).toBeVisible()
  await expect.poll(() => api.requestsTo('/api/crawler-logs')
    .some((r) => r.query.get('crawler_type') === 'RUNTIME')).toBe(true)
})

scenario('FRS-07', '依存パッケージ・対応状況・Dependabot運用状況の画面にも、最終取得が表示される', async ({ page, api }) => {
  await seedSession(page)
  await page.goto('/')
  await openTab(page, 'DEPSCAN')

  // 画面（ボタン名＝ダイアログ名）と、その画面が表示するデータを取得するクローラーの種別
  const screens = [
    ['依存パッケージ', 'DEPSCAN'], ['対応状況', 'DEPSCAN'], ['Dependabot運用状況', 'DEPSOPS'],
  ] as const
  for (const [name, crawlerType] of screens) {
    await page.getByRole('button', { name }).click()
    const dialog = page.getByRole('dialog')
    await expect(dialog.getByTestId('last-fetched')).toBeVisible()
    await expect.poll(() => api.requestsTo('/api/crawler-logs')
      .some((r) => r.query.get('crawler_type') === crawlerType)).toBe(true)
    await page.keyboard.press('Escape')
    await expect(dialog).toBeHidden()
  }
})
