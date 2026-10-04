import { expect, openTab, scenario, seedSession, type Page } from './support/test'
import { API_PREFIX } from './support/mockApi'
import { codescanItems } from './support/mockData'

const TABLE = 'コード脆弱性一覧'
const PER_PAGE = 30
const open = codescanItems.filter((f) => !f.resolved_at)
const bySeverity = (severity: string) => open.filter((f) => f.severity === severity).length

async function openCodescan(page: Page) {
  await seedSession(page)
  await page.goto('/')
  await openTab(page, 'CODESCAN')
  const table = page.getByRole('table', { name: TABLE })
  await expect(table).toBeVisible()
  return table
}

scenario('COD-01', '未ログイン時はGitHubログイン案内が表示される', async ({ page, api }) => {
  await page.goto('/')
  await openTab(page, 'CODESCAN')

  await expect(page.getByText('GitHubアカウントでログインしてください')).toBeVisible()
  await expect(page.getByText('ログインすると、自アプリのコード脆弱性診断結果を閲覧できます')).toBeVisible()
  await expect(page.getByRole('link', { name: 'GitHubでログイン' }))
    .toHaveAttribute('href', `${new URL(page.url()).origin}${API_PREFIX}/auth/github/login`)
  expect(api.requestsTo('/api/codescan')).toHaveLength(0)
})

scenario('COD-02', 'ログイン済みで一覧・統計・注記が表示される', async ({ page, api }) => {
  const table = await openCodescan(page)

  await expect(page.getByText('ログイン中:')).toBeVisible()
  await expect(table.getByRole('row')).toHaveCount(PER_PAGE + 1)
  await expect(page.getByText(`未解決 ${open.length} 件`)).toBeVisible()
  await expect(page.getByText(`重大 ${bySeverity('ERROR')}`, { exact: true })).toBeVisible()
  // CVSSがベストエフォート推定であることの注記
  await expect(page.getByText(/ベストエフォート推定値/)).toBeVisible()
  await expect(page.getByText('リポジトリ別件数（未解決）')).toBeVisible()
  await expect(page.locator('.recharts-wrapper').first()).toBeVisible()

  // 先頭行: 重要度・CVSS・リポジトリ・ファイル:行・ツール・ルール
  const first = table.getByRole('row').nth(1)
  await expect(first).toContainText('重大')
  await expect(first).toContainText('8.6')
  await expect(first).toContainText('baby-feelings/app-one')
  await expect(first).toContainText('src/module1.ts:10')
  await expect(first).toContainText('Gitleaks')
  await expect(first).toContainText('gitleaks:generic-api-key')

  // 既定は未解決のみで、Bearerトークンで取得する
  expect(api.requestsTo('/api/codescan')[0].query.get('resolved')).toBe('false')
  expect(api.requestsTo('/api/codescan')[0].headers['authorization']).toBe('Bearer test-session-token')
})

scenario('COD-03', '重要度フィルター（重大/警告/情報）で絞り込まれる', async ({ page, api }) => {
  const table = await openCodescan(page)
  const sev = page.getByRole('group', { name: '深刻度フィルター' })

  await sev.getByRole('button', { name: '警告' }).click()
  await expect(sev.getByRole('button', { name: '警告' })).toHaveAttribute('aria-pressed', 'true')
  await expect(table.getByRole('row')).toHaveCount(bySeverity('WARNING') + 1)
  await expect(table.getByText('警告').first()).toBeVisible()
  expect(api.lastQuery('/api/codescan')?.get('severity')).toBe('WARNING')

  await sev.getByRole('button', { name: '情報' }).click()
  expect(api.lastQuery('/api/codescan')?.get('severity')).toBe('INFO')
  await expect(table.getByRole('row')).toHaveCount(bySeverity('INFO') + 1)

  await sev.getByRole('button', { name: '重大' }).click()
  expect(api.lastQuery('/api/codescan')?.get('severity')).toBe('ERROR')

  await sev.getByRole('button', { name: 'ALL' }).click()
  await expect(sev.getByRole('button', { name: 'ALL' })).toHaveAttribute('aria-pressed', 'true')
  expect(api.lastQuery('/api/codescan')?.get('severity')).toBeNull()
})

scenario('COD-04', '状態フィルター（未解決/解決済み/全件）が切り替わる', async ({ page, api }) => {
  const table = await openCodescan(page)
  const state = page.getByRole('group', { name: '状態フィルター' })

  await expect(state.getByRole('button', { name: '未解決' })).toHaveAttribute('aria-pressed', 'true')

  await state.getByRole('button', { name: '解決済み' }).click()
  await expect(state.getByRole('button', { name: '解決済み' })).toHaveAttribute('aria-pressed', 'true')
  expect(api.lastQuery('/api/codescan')?.get('resolved')).toBe('true')
  await expect(table.getByRole('row')).toHaveCount(codescanItems.length - open.length + 1)

  await state.getByRole('button', { name: '全件' }).click()
  await expect(state.getByRole('button', { name: '全件' })).toHaveAttribute('aria-pressed', 'true')
  expect(api.lastQuery('/api/codescan')?.has('resolved')).toBe(false)
  await expect(page.getByRole('navigation', { name: 'ページ送り（下部）' })).toContainText(`（${codescanItems.length} 件）`)

  await state.getByRole('button', { name: '未解決' }).click()
  expect(api.lastQuery('/api/codescan')?.get('resolved')).toBe('false')
})

scenario('COD-05', '行クリックで詳細（メッセージ・スニペット・CWE・OWASP）が展開される', async ({ page }) => {
  const table = await openCodescan(page)
  const row = table.getByRole('row').nth(1)
  const detail = row.locator('xpath=following-sibling::tr[1]')

  await row.click()
  await expect(row).toHaveAttribute('aria-expanded', 'true')
  await expect(detail).toContainText('CODESCAN検知メッセージ 1')
  await expect(detail.locator('pre')).toContainText('const secret = "***REDACTED-1"')
  await expect(detail).toContainText('CWE:')
  await expect(detail).toContainText('CWE-798')
  await expect(detail).toContainText('OWASP:')
  await expect(detail).toContainText('A07:2021 - Identification and Authentication Failures')
  await expect(detail).toContainText('CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N')

  await row.click()
  await expect(row).toHaveAttribute('aria-expanded', 'false')

  // スニペット・CWE・OWASPが無い検知（6件目: 添字5は奇数かつ3で割って2余る）は該当項目が表示されない
  const bare = page.getByRole('row', { name: /src\/module6\.ts:15/ })
  await bare.click()
  const bareDetail = bare.locator('xpath=following-sibling::tr[1]')
  await expect(bareDetail).toContainText('CODESCAN検知メッセージ 6')
  await expect(bareDetail.locator('pre')).toHaveCount(0)
  await expect(bareDetail).not.toContainText('CWE:')
  await expect(bareDetail).not.toContainText('OWASP:')
})

scenario('COD-06', '該当なしのとき空状態メッセージが表示される', async ({ page, api }) => {
  api.override('GET', '/api/codescan', () => ({ body: { total: 0, page: 1, per_page: 30, data: [] } }))
  await seedSession(page)
  await page.goto('/')
  await openTab(page, 'CODESCAN')

  await expect(page.getByText('該当するコード脆弱性はありません')).toBeVisible()
  await expect(page.getByRole('table', { name: TABLE })).toHaveCount(0)
})

scenario('COD-07', 'DEPSCANとCODESCANでログインセッションが共有される', async ({ page, api }) => {
  // DEPSCANタブのOAuthコールバックでログインする
  await page.goto('/?depscan_code=shared-code')
  await expect(page.getByText('ログイン中:')).toBeVisible()

  // CODESCANタブに切り替えるだけで、再ログインなしに閲覧できる
  await openTab(page, 'CODESCAN')
  await expect(page.getByText('ログイン中:')).toBeVisible()
  await expect(page.getByRole('table', { name: TABLE })).toBeVisible()
  expect(api.requestsTo('/api/codescan')[0].headers['authorization']).toBe('Bearer exchanged-token')
  await expect(page.getByText('GitHubアカウントでログインしてください')).toHaveCount(0)
})

scenario('COD-08', 'ログアウトで未ログインに戻る', async ({ page }) => {
  await openCodescan(page)

  page.once('dialog', (dialog) => void dialog.accept())
  await page.getByRole('button', { name: 'ログアウト' }).click()

  await expect(page.getByText('GitHubアカウントでログインしてください')).toBeVisible()
  expect(await page.evaluate(() => localStorage.getItem('depscan_session_token'))).toBeNull()

  // セッションはDEPSCANと共有のため、DEPSCANタブでも未ログインになる
  await openTab(page, 'DEPSCAN')
  await expect(page.getByText('GitHubアカウントでログインしてください')).toBeVisible()
})

scenario('COD-09', 'ページ送り', async ({ page, api }) => {
  const table = await openCodescan(page)
  const bottom = page.getByRole('navigation', { name: 'ページ送り（下部）' })

  // 未解決32件 / 30件 = 2ページ
  await expect(bottom).toContainText('1 / 2')
  await expect(bottom.getByRole('button', { name: '← 前へ' })).toBeDisabled()
  await bottom.getByRole('button', { name: '次へ →' }).click()

  await expect(bottom).toContainText('2 / 2')
  await expect(table.getByRole('row')).toHaveCount(open.length - PER_PAGE + 1)
  await expect(bottom.getByRole('button', { name: '次へ →' })).toBeDisabled()
  expect(api.lastQuery('/api/codescan')?.get('page')).toBe('2')
  expect(api.lastQuery('/api/codescan')?.get('per_page')).toBe(String(PER_PAGE))
})

scenario('COD-10', 'CVSS 7.0以上のバッジ強調・未算出表示・ツールバッジ', async ({ page }) => {
  const table = await openCodescan(page)
  const rows = table.getByRole('row')

  // 7.0以上は赤バッジ、それ未満は強調なし
  await expect(rows.nth(1).getByText('8.6')).toHaveClass(/text-red-300/)
  await expect(rows.nth(3).getByText('4.3')).not.toHaveClass(/text-red-300/)
  // CVSSが算出できなかった検知は「未算出」
  await expect(rows.nth(2).getByText('未算出')).toBeVisible()

  // 検知ツールのバッジと重要度の日本語ラベル
  await expect(rows.nth(1).getByText('Gitleaks', { exact: true })).toBeVisible()
  await expect(rows.nth(2).getByText('Semgrep', { exact: true })).toBeVisible()
  await expect(rows.nth(1).getByText('重大', { exact: true })).toBeVisible()
  await expect(rows.nth(2).getByText('警告', { exact: true })).toBeVisible()
  await expect(rows.nth(3).getByText('情報', { exact: true })).toBeVisible()
})

scenario('COD-11', 'ページ送りの最初/最後ボタンとページ番号の直接入力', async ({ page, api }) => {
  await openCodescan(page)
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
  expect(api.lastQuery('/api/codescan')?.get('page')).toBe('2')

  // 「最初」で1ページ目へ戻る
  await first.click()
  await expect(bottom).toContainText('1 / 2')
  expect(api.lastQuery('/api/codescan')?.get('page')).toBe('1')

  // 数字以外は入力できず、「移動」ボタンで指定ページへ移動する
  await jump.fill('2')
  await expect(jump).toHaveValue('2')
  await move.click()
  await expect(bottom).toContainText('2 / 2')
  expect(api.lastQuery('/api/codescan')?.get('page')).toBe('2')
  await expect(jump).toHaveValue('')

  // 範囲外は最終ページに丸められ、Enterでも確定できる
  await jump.fill('999')
  await jump.press('Enter')
  await expect(bottom).toContainText('2 / 2')
  expect(api.lastQuery('/api/codescan')?.get('page')).toBe('2')

  // 0 は1ページ目に丸められる
  await jump.fill('0')
  await move.click()
  await expect(bottom).toContainText('1 / 2')
})
