import { expect, openTab, scenario, type Page } from './support/test'
import { OSV_TOTAL, osvItems } from './support/mockData'

const PER_PAGE = 30
const count = (pred: (v: (typeof osvItems)[number]) => boolean) => osvItems.filter(pred).length

async function openOsv(page: Page) {
  await page.goto('/')
  await openTab(page, 'OSV')
  await expect(page.getByRole('table', { name: 'OSV 脆弱性一覧' })).toBeVisible()
  return page.getByRole('table', { name: 'OSV 脆弱性一覧' })
}

scenario('OSV-01', '一覧・CRIT/HIGH件数・グラフが表示される', async ({ page }) => {
  const table = await openOsv(page)

  await expect(table.getByRole('row')).toHaveCount(PER_PAGE + 1)
  await expect(table.getByRole('link', { name: 'GHSA-e2e0001' })).toBeVisible()

  // ヘッダーの件数バッジ（統計APIの深刻度別件数）
  const crit = count((v) => v.severity === 'CRITICAL')
  const high = count((v) => v.severity === 'HIGH')
  await expect(page.getByText(`CRIT ${crit}`, { exact: true })).toBeVisible()
  // 円グラフの凡例にも同じ「HIGH n」があるため、ヘッダーのバッジ（DOM上で先）を対象にする
  await expect(page.getByText(`HIGH ${high}`, { exact: true }).first()).toBeVisible()
  await expect(page.getByText(`/ ${OSV_TOTAL} 件`)).toBeVisible()

  // 深刻度別・エコシステム別・月別トレンドの3グラフ
  await expect(page.getByText('月別 OSV 更新トレンド')).toBeVisible()
  await expect(page.locator('.recharts-wrapper').first()).toBeVisible()
  await expect(page.getByText('データなし')).toHaveCount(0)

  // 深刻度が未設定の脆弱性は N/A バッジで表示される
  await expect(table.getByText('N/A').first()).toBeVisible()
})

scenario('OSV-02', 'エコシステムフィルターでリクエストと一覧が絞り込まれる', async ({ page, api }) => {
  const table = await openOsv(page)
  const eco = page.getByRole('group', { name: 'エコシステムフィルター' })

  await expect(eco.getByRole('button', { name: 'ALL' })).toHaveAttribute('aria-pressed', 'true')
  await eco.getByRole('button', { name: /^npm/ }).click()

  const npm = count((v) => v.ecosystem === 'npm')
  await expect(eco.getByRole('button', { name: /^npm/ })).toHaveAttribute('aria-pressed', 'true')
  await expect(eco.getByRole('button', { name: 'ALL' })).toHaveAttribute('aria-pressed', 'false')
  await expect(table.getByRole('row')).toHaveCount(npm + 1)
  expect(api.lastQuery('/api/osv')?.get('ecosystem')).toBe('npm')
  // ボタンにはエコシステム別件数が併記される
  await expect(eco.getByRole('button', { name: new RegExp(`^npm${npm}$`) })).toBeVisible()

  await eco.getByRole('button', { name: 'ALL' }).click()
  await expect(table.getByRole('row')).toHaveCount(PER_PAGE + 1)
  expect(api.lastQuery('/api/osv')?.get('ecosystem')).toBeNull()
})

scenario('OSV-03', '深刻度フィルターで絞り込まれ、ALLで解除される', async ({ page, api }) => {
  const table = await openOsv(page)
  const sev = page.getByRole('group', { name: '深刻度フィルター' })

  await sev.getByRole('button', { name: 'HIGH' }).click()
  const high = count((v) => v.severity === 'HIGH')
  await expect(sev.getByRole('button', { name: 'HIGH' })).toHaveAttribute('aria-pressed', 'true')
  await expect(table.getByRole('row')).toHaveCount(Math.min(high, PER_PAGE) + 1)
  expect(api.lastQuery('/api/osv')?.get('severity')).toBe('HIGH')

  await sev.getByRole('button', { name: 'CRITICAL' }).click()
  await expect(sev.getByRole('button', { name: 'CRITICAL' })).toHaveAttribute('aria-pressed', 'true')
  await expect(sev.getByRole('button', { name: 'HIGH' })).toHaveAttribute('aria-pressed', 'false')
  expect(api.lastQuery('/api/osv')?.get('severity')).toBe('CRITICAL')

  await sev.getByRole('button', { name: 'ALL' }).click()
  await expect(sev.getByRole('button', { name: 'ALL' })).toHaveAttribute('aria-pressed', 'true')
  expect(api.lastQuery('/api/osv')?.get('severity')).toBeNull()
})

scenario('OSV-04', 'キーワード検索とクリア', async ({ page, api }) => {
  const table = await openOsv(page)
  const search = page.getByRole('textbox', { name: 'OSV ID・パッケージ名・概要' })

  await search.fill('GHSA-e2e0007')
  await expect(table.getByRole('row')).toHaveCount(2)
  await expect(table.getByRole('link', { name: 'GHSA-e2e0007' })).toBeVisible()
  expect(api.lastQuery('/api/osv')?.get('search')).toBe('GHSA-e2e0007')

  await page.getByRole('button', { name: '検索をクリア' }).click()
  await expect(search).toHaveValue('')
  await expect(table.getByRole('row')).toHaveCount(PER_PAGE + 1)
})

scenario('OSV-05', 'ソートを更新日/CVSSで切り替えられる', async ({ page, api }) => {
  const table = await openOsv(page)
  const sort = page.getByRole('group', { name: 'ソート' })

  await expect(sort.getByRole('button', { name: '更新日' })).toHaveAttribute('aria-pressed', 'true')
  await expect(table.getByRole('row').nth(2)).toContainText('GHSA-e2e0002')

  await sort.getByRole('button', { name: 'CVSS' }).click()
  await expect(sort.getByRole('button', { name: 'CVSS' })).toHaveAttribute('aria-pressed', 'true')
  expect(api.lastQuery('/api/osv')?.get('sort_by')).toBe('cvss')
  // CVSS降順（9.8が先）。添字0,8,12,… の順に並ぶ
  await expect(table.getByRole('row').nth(2)).toContainText('GHSA-e2e0009')

  await sort.getByRole('button', { name: '更新日' }).click()
  expect(api.lastQuery('/api/osv')?.get('sort_by')).toBe('modified')
  await expect(table.getByRole('row').nth(2)).toContainText('GHSA-e2e0002')
})

scenario('OSV-06', '行クリックで詳細（修正版・エイリアス・参考リンク）が展開される', async ({ page }) => {
  await openOsv(page)
  const row = page.getByRole('row', { name: /GHSA-e2e0002/ })

  await expect(row).toHaveAttribute('aria-expanded', 'false')
  await row.click()
  await expect(row).toHaveAttribute('aria-expanded', 'true')

  await expect(page.getByText('OSV詳細 2: 入力検証の不備により任意コード実行が可能。')).toBeVisible()
  await expect(page.getByText('修正済みバージョン:')).toBeVisible()
  await expect(page.getByText('2.0.1', { exact: true })).toBeVisible()
  await expect(page.getByText('エイリアス:')).toBeVisible()
  const reference = page.getByRole('link', { name: 'https://example.test/advisory/2' })
  await expect(reference).toHaveAttribute('target', '_blank')

  // 一覧行のCVEエイリアスはNVDへのリンク
  await expect(row.getByRole('link', { name: 'CVE-2026-90002' }))
    .toHaveAttribute('href', 'https://nvd.nist.gov/vuln/detail/CVE-2026-90002')

  await row.click()
  await expect(row).toHaveAttribute('aria-expanded', 'false')
  await expect(page.getByText('エイリアス:')).toBeHidden()
})

scenario('OSV-07', 'ページ送り', async ({ page, api }) => {
  const table = await openOsv(page)
  const bottom = page.getByRole('navigation', { name: 'ページ送り（下部）' })

  await expect(bottom).toContainText('1 / 3')
  await expect(bottom.getByRole('button', { name: '← 前へ' })).toBeDisabled()
  await bottom.getByRole('button', { name: '次へ →' }).click()

  await expect(bottom).toContainText('2 / 3')
  await expect(table.getByRole('link', { name: 'GHSA-e2e0031' })).toBeVisible()
  expect(api.lastQuery('/api/osv')?.get('page')).toBe('2')
  expect(api.lastQuery('/api/osv')?.get('per_page')).toBe(String(PER_PAGE))
})

scenario('OSV-08', '該当なしのとき空状態メッセージが表示される', async ({ page, api }) => {
  api.override('GET', '/api/osv', () => ({ body: { total: 0, page: 1, per_page: 30, data: [] } }))
  await page.goto('/')
  await openTab(page, 'OSV')

  await expect(page.getByText('該当する OSV 脆弱性はありません')).toBeVisible()
  await expect(page.getByRole('table', { name: 'OSV 脆弱性一覧' })).toHaveCount(0)
})

scenario('OSV-09', 'フィルター変更時にページが1に戻る', async ({ page, api }) => {
  const table = await openOsv(page)
  const bottom = page.getByRole('navigation', { name: 'ページ送り（下部）' })

  await bottom.getByRole('button', { name: '次へ →' }).click()
  await expect(bottom).toContainText('2 / 3')

  await page.getByRole('group', { name: 'エコシステムフィルター' }).getByRole('button', { name: /^Go/ }).click()
  await expect.poll(() => api.lastQuery('/api/osv')?.get('ecosystem')).toBe('Go')
  expect(api.lastQuery('/api/osv')?.get('page')).toBe('1')
  // Go は 16 件（1ページに収まる）ためページ送りは出ない
  await expect(table.getByRole('row')).toHaveCount(count((v) => v.ecosystem === 'Go') + 1)
  await expect(bottom).toHaveCount(0)
})
