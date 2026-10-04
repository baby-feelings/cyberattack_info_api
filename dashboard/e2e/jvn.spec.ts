import { expect, openTab, scenario, type Page } from './support/test'
import { JVN_TOTAL, jvnItems } from './support/mockData'

const PER_PAGE = 30
const count = (severity: string) => jvnItems.filter((v) => v.severity === severity).length

async function openJvn(page: Page) {
  await page.goto('/')
  await openTab(page, 'JVN')
  await expect(page.getByRole('table', { name: 'JVN 脆弱性一覧' })).toBeVisible()
  return page.getByRole('table', { name: 'JVN 脆弱性一覧' })
}

scenario('JVN-01', '一覧・HIGH/MED件数・グラフが表示される', async ({ page }) => {
  const table = await openJvn(page)

  await expect(table.getByRole('row')).toHaveCount(PER_PAGE + 1)
  await expect(table.getByRole('link', { name: 'JVNDB-2026-000001' })).toBeVisible()
  await expect(page.getByText(`HIGH ${count('High')}`, { exact: true })).toBeVisible()
  await expect(page.getByText(`MED ${count('Medium')}`, { exact: true })).toBeVisible()
  await expect(page.getByText(`/ ${JVN_TOTAL} 件`)).toBeVisible()
  await expect(page.getByText('月別 JVN 更新トレンド')).toBeVisible()
  await expect(page.getByText('データなし')).toHaveCount(0)

  // 影響製品: 先頭製品＋残件数、影響製品なしは「—」
  const first = page.getByRole('row', { name: /JVNDB-2026-000001/ })
  await expect(first).toContainText('ACME /')
  await expect(first).toContainText('+1 製品')
  await expect(page.getByRole('row', { name: /JVNDB-2026-000002/ }).getByText('—')).toBeVisible()
})

scenario('JVN-02', '深刻度フィルターで絞り込まれる', async ({ page, api }) => {
  const table = await openJvn(page)
  const sev = page.getByRole('group', { name: '深刻度フィルター' })

  await sev.getByRole('button', { name: 'High', exact: true }).click()
  await expect(sev.getByRole('button', { name: 'High', exact: true })).toHaveAttribute('aria-pressed', 'true')
  await expect(table.getByRole('row')).toHaveCount(count('High') + 1)
  expect(api.lastQuery('/api/jvn')?.get('severity')).toBe('High')

  await sev.getByRole('button', { name: 'Low', exact: true }).click()
  await expect(table.getByRole('row')).toHaveCount(count('Low') + 1)
  expect(api.lastQuery('/api/jvn')?.get('severity')).toBe('Low')

  await sev.getByRole('button', { name: 'ALL' }).click()
  await expect(table.getByRole('row')).toHaveCount(PER_PAGE + 1)
  expect(api.lastQuery('/api/jvn')?.get('severity')).toBeNull()
})

scenario('JVN-03', 'キーワード検索とクリア', async ({ page, api }) => {
  const table = await openJvn(page)
  const search = page.getByRole('textbox', { name: 'JVNDB ID・タイトル・概要' })

  await search.fill('JVNDB-2026-000007')
  await expect(table.getByRole('row')).toHaveCount(2)
  await expect(table.getByRole('link', { name: 'JVNDB-2026-000007' })).toBeVisible()
  expect(api.lastQuery('/api/jvn')?.get('search')).toBe('JVNDB-2026-000007')

  await page.getByRole('button', { name: '検索をクリア' }).click()
  await expect(search).toHaveValue('')
  await expect(table.getByRole('row')).toHaveCount(PER_PAGE + 1)
})

scenario('JVN-04', 'ソートを更新日/CVSSで切り替えられる', async ({ page, api }) => {
  const table = await openJvn(page)
  const sort = page.getByRole('group', { name: 'ソート' })

  await expect(table.getByRole('row').nth(2)).toContainText('JVNDB-2026-000002')
  await sort.getByRole('button', { name: 'CVSS' }).click()
  await expect(sort.getByRole('button', { name: 'CVSS' })).toHaveAttribute('aria-pressed', 'true')
  expect(api.lastQuery('/api/jvn')?.get('sort_by')).toBe('cvss')
  // CVSS降順（8.1が先）。添字0,3,6,… の順に並ぶ
  await expect(table.getByRole('row').nth(2)).toContainText('JVNDB-2026-000004')

  await sort.getByRole('button', { name: '更新日' }).click()
  expect(api.lastQuery('/api/jvn')?.get('sort_by')).toBe('modified')
  await expect(table.getByRole('row').nth(2)).toContainText('JVNDB-2026-000002')
})

scenario('JVN-05', '行クリックで詳細（概要・CVSSベクター・影響製品）が展開される', async ({ page }) => {
  await openJvn(page)
  const row = page.getByRole('row', { name: /JVNDB-2026-000001/ })

  await row.click()
  await expect(row).toHaveAttribute('aria-expanded', 'true')
  // 展開された詳細は、クリックした行の直後の行
  const detail = row.locator('xpath=following-sibling::tr[1]')
  await expect(detail.getByText('JVN概要 1: クロスサイトスクリプティングの脆弱性。')).toBeVisible()
  await expect(detail.getByText('CVSS ベクター:')).toBeVisible()
  await expect(detail.getByText('CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N')).toBeVisible()
  await expect(detail.getByText('関連 CVE:')).toBeVisible()
  await expect(detail.getByText('ACME / Widget 1', { exact: true })).toBeVisible()
  await expect(detail.getByText('ACME / Gadget', { exact: true })).toBeVisible()
  await expect(detail.getByRole('link', { name: 'JVNDB で詳細を確認' }))
    .toHaveAttribute('href', /jvndb\.jvn\.jp\/ja\/contents\/2026\/JVNDB-2026-000001\.html/)

  await row.click()
  await expect(row).toHaveAttribute('aria-expanded', 'false')
  await expect(page.getByText('CVSS ベクター:')).toBeHidden()
})

scenario('JVN-06', 'ページ送り', async ({ page, api }) => {
  const table = await openJvn(page)
  const bottom = page.getByRole('navigation', { name: 'ページ送り（下部）' })

  // 40件 / 30件 = 2ページ、最終ページは10件
  await expect(bottom).toContainText('1 / 2')
  await bottom.getByRole('button', { name: '次へ →' }).click()
  await expect(bottom).toContainText('2 / 2')
  await expect(table.getByRole('row')).toHaveCount(JVN_TOTAL - PER_PAGE + 1)
  await expect(bottom.getByRole('button', { name: '次へ →' })).toBeDisabled()
  expect(api.lastQuery('/api/jvn')?.get('page')).toBe('2')
})

scenario('JVN-07', '該当なしのとき空状態メッセージが表示される', async ({ page, api }) => {
  api.override('GET', '/api/jvn', () => ({ body: { total: 0, page: 1, per_page: 30, data: [] } }))
  await page.goto('/')
  await openTab(page, 'JVN')

  await expect(page.getByText('該当する JVN 脆弱性はありません')).toBeVisible()
  await expect(page.getByRole('table', { name: 'JVN 脆弱性一覧' })).toHaveCount(0)
})

scenario('JVN-08', '再読み込みボタンで再取得される', async ({ page, api }) => {
  await openJvn(page)
  const before = { list: api.requestsTo('/api/jvn').length, stats: api.requestsTo('/api/jvn/stats').length }

  await page.getByRole('button', { name: '再読み込み' }).click()

  await expect.poll(() => api.requestsTo('/api/jvn').length).toBe(before.list + 1)
  await expect.poll(() => api.requestsTo('/api/jvn/stats').length).toBe(before.stats + 1)
})

scenario('JVN-09', 'ページ送りの最初/最後ボタンとページ番号の直接入力', async ({ page, api }) => {
  await openJvn(page)
  const bottom = page.getByRole('navigation', { name: 'ページ送り（下部）' })
  const first = bottom.getByRole('button', { name: '最初のページへ' })
  const last = bottom.getByRole('button', { name: '最後のページへ' })
  const jump = bottom.getByLabel('ページ番号を入力')
  const move = bottom.getByRole('button', { name: '入力したページへ移動' })

  // 1ページ目: 「最初」は押せず「最後」は押せる。入力欄が空のうちは「移動」も押せない
  await expect(bottom).toContainText('1 / 2')
  await expect(first).toBeDisabled()
  await expect(last).toBeEnabled()
  await expect(move).toBeDisabled()

  // 「最後」で最終ページへ一気に移動する
  await last.click()
  await expect(bottom).toContainText('2 / 2')
  await expect(last).toBeDisabled()
  expect(api.lastQuery('/api/jvn')?.get('page')).toBe('2')

  // 「最初」で1ページ目へ戻る
  await first.click()
  await expect(bottom).toContainText('1 / 2')
  expect(api.lastQuery('/api/jvn')?.get('page')).toBe('1')

  // 数字以外は入力できず、「移動」ボタンで指定ページへ移動する
  await jump.fill('2')
  await expect(jump).toHaveValue('2')
  await move.click()
  await expect(bottom).toContainText('2 / 2')
  expect(api.lastQuery('/api/jvn')?.get('page')).toBe('2')
  await expect(jump).toHaveValue('')

  // 範囲外は最終ページに丸められ、Enterでも確定できる
  await jump.fill('999')
  await jump.press('Enter')
  await expect(bottom).toContainText('2 / 2')
  expect(api.lastQuery('/api/jvn')?.get('page')).toBe('2')

  // 0 は1ページ目に丸められる
  await jump.fill('0')
  await move.click()
  await expect(bottom).toContainText('1 / 2')
})
