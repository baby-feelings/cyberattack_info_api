import { API_PREFIX } from './support/mockApi'
import { expect, openTab, scenario, seedSession, type Page } from './support/test'
import { DEPSOPS_TOTAL, depsopsItems } from './support/mockData'

const TABLE = '依存ライブラリ脆弱性一覧'

// ログイン済みの状態で DEPSCAN タブを開き、一覧が表示されるまで待つ
async function openDepscan(page: Page) {
  await seedSession(page)
  await page.goto('/')
  await openTab(page, 'DEPSCAN')
  const table = page.getByRole('table', { name: TABLE })
  await expect(table).toBeVisible()
  return table
}

scenario('DEP-01', '未ログイン時はGitHubログイン案内とログインリンクが表示される', async ({ page, api }) => {
  await page.goto('/')
  await openTab(page, 'DEPSCAN')

  await expect(page.getByText('GitHubアカウントでログインしてください')).toBeVisible()
  await expect(page.getByText(/あなた自身が所有する GitHub リポジトリ/)).toBeVisible()
  await expect(page.getByRole('link', { name: 'GitHubでログイン' }))
    .toHaveAttribute('href', `${new URL(page.url()).origin}${API_PREFIX}/auth/github/login`)

  // 未ログインでは検知データの取得は行われない
  expect(api.requestsTo('/api/depscan')).toHaveLength(0)
  expect(api.requestsTo('/auth/scan-status')).toHaveLength(0)
})

scenario('DEP-02', 'ログイン済みでスキャン中表示から完了後にパネルへ遷移する', async ({ page, api }) => {
  api.state.scanStatuses = [
    { username: 'octocat', status: 'running' },
    { username: 'octocat', status: 'done', repos_scanned: 3 },
  ]
  await seedSession(page)
  await page.goto('/')
  await openTab(page, 'DEPSCAN')

  await expect(page.getByText('octocat のリポジトリをスキャン中です')).toBeVisible()
  await expect(page.getByRole('table', { name: TABLE })).toHaveCount(0)

  // 4秒間隔のポーリングで完了を検知し、パネルが表示される
  await expect(page.getByRole('table', { name: TABLE })).toBeVisible({ timeout: 15_000 })
  await expect(page.getByText('octocat のリポジトリをスキャン中です')).toHaveCount(0)
  await expect(page.getByText('ログイン中:')).toBeVisible()
})

scenario('DEP-03', 'パッケージ単位に集約した一覧と件数サマリーが表示される', async ({ page }) => {
  const table = await openDepscan(page)

  // 未解決4件 → 3パッケージ（lodash は同一パッケージ・同一バージョンで2件を集約）
  await expect(table.getByRole('row')).toHaveCount(4)
  await expect(page.getByText('/ 4 件（3 パッケージ）')).toBeVisible()
  await expect(page.getByText('CRIT 1', { exact: true })).toBeVisible()
  await expect(page.getByText('HIGH 1', { exact: true }).first()).toBeVisible()

  // 重大度が高いグループが先頭
  const lodash = table.getByRole('row').nth(1)
  await expect(lodash).toContainText('lodash')
  await expect(lodash).toContainText('4.17.15')
  await expect(lodash).toContainText('CRITICAL')
  await expect(lodash).toContainText('KEV')
  await expect(lodash).toContainText('計2件')
  await expect(lodash).toContainText('Public')
  await expect(lodash).toContainText('到達可能')
  await expect(lodash).toContainText('4.17.19 +1')
  await expect(lodash).toContainText('CRITICAL×1')
  await expect(lodash).toContainText('HIGH×1')

  // 修正版なし・Private・未使用の可能性
  const requests = page.getByRole('row', { name: /requests/ })
  await expect(requests).toContainText('未提供')
  await expect(requests).toContainText('Private')
  await expect(requests).toContainText('未使用の可能性')
  // 公開範囲・到達可能性が未取得（null）の旧レコードは「不明」、公開範囲バッジなし
  const express = page.getByRole('row', { name: /express/ })
  await expect(express).toContainText('不明')
  await expect(express).not.toContainText('Public')
  await expect(express).not.toContainText('Private')

  await expect(page.getByText('リポジトリ別件数（未解決）')).toBeVisible()
  await expect(page.locator('.recharts-wrapper').first()).toBeVisible()
})

scenario('DEP-04', '行クリックで個別CVE・ロックファイル・修正版が展開される', async ({ page }) => {
  const table = await openDepscan(page)
  const row = table.getByRole('row').nth(1)
  const detail = row.locator('xpath=following-sibling::tr[1]')

  await row.click()
  await expect(row).toHaveAttribute('aria-expanded', 'true')
  await expect(detail).toContainText('ロックファイル:')
  await expect(detail).toContainText('package-lock.json')
  await expect(detail.getByRole('link', { name: 'GHSA-lodash-1' }))
    .toHaveAttribute('href', 'https://osv.dev/vulnerability/GHSA-lodash-1')
  await expect(detail.getByRole('link', { name: 'GHSA-lodash-2' })).toBeVisible()
  await expect(detail).toContainText('lodash の脆弱性 (GHSA-lodash-1)')
  // 優先度判定に寄与した要因のバッジ
  await expect(detail).toContainText('KEV掲載')
  await expect(detail).toContainText('到達可能')
  await expect(detail).toContainText('公開リポジトリ')
  await expect(detail).toContainText('修正版:')
  await expect(detail).toContainText('4.17.21')

  await row.click()
  await expect(row).toHaveAttribute('aria-expanded', 'false')
  await expect(page.getByText('ロックファイル:')).toBeHidden()
})

scenario('DEP-05', '深刻度フィルターでリクエストと一覧が絞り込まれる', async ({ page, api }) => {
  const table = await openDepscan(page)
  const sev = page.getByRole('group', { name: '深刻度フィルター' })

  await sev.getByRole('button', { name: 'MEDIUM' }).click()
  await expect(sev.getByRole('button', { name: 'MEDIUM' })).toHaveAttribute('aria-pressed', 'true')
  await expect(table.getByRole('row')).toHaveCount(2)
  await expect(table.getByRole('row').nth(1)).toContainText('requests')
  expect(api.lastQuery('/api/depscan')?.get('severity')).toBe('MEDIUM')

  await sev.getByRole('button', { name: 'ALL' }).click()
  await expect(table.getByRole('row')).toHaveCount(4)
  expect(api.lastQuery('/api/depscan')?.get('severity')).toBeNull()
})

scenario('DEP-06', '「解決済みを含む」切替で解決済みが表示される', async ({ page, api }) => {
  const table = await openDepscan(page)
  const toggle = page.getByRole('button', { name: '解決済みを含む' })

  // 既定は未解決のみ（resolved=false）
  expect(api.lastQuery('/api/depscan')?.get('resolved')).toBe('false')
  await expect(toggle).toHaveAttribute('aria-pressed', 'false')
  await expect(page.getByRole('row', { name: /minimist/ })).toHaveCount(0)

  await toggle.click()
  await expect(toggle).toHaveAttribute('aria-pressed', 'true')
  const minimist = page.getByRole('row', { name: /minimist/ })
  await expect(minimist).toBeVisible()
  await expect(minimist).toContainText('解決済み')
  await expect(table.getByRole('row')).toHaveCount(5)
  expect(api.lastQuery('/api/depscan')?.has('resolved')).toBe(false)

  await toggle.click()
  await expect(page.getByRole('row', { name: /minimist/ })).toHaveCount(0)
})

scenario('DEP-07', '複数オーナーのときオーナーフィルターが表示され絞り込める', async ({ page, api }) => {
  const table = await openDepscan(page)
  const owners = page.getByRole('group', { name: 'オーナーフィルター' })

  await expect(owners.getByRole('button')).toHaveText(['ALL', 'baby-feelings', 'other-owner'])
  await owners.getByRole('button', { name: 'other-owner' }).click()

  await expect(owners.getByRole('button', { name: 'other-owner' })).toHaveAttribute('aria-pressed', 'true')
  await expect(table.getByRole('row')).toHaveCount(2)
  await expect(table.getByRole('row').nth(1)).toContainText('express')
  expect(api.lastQuery('/api/depscan')?.get('owner')).toBe('other-owner')

  await owners.getByRole('button', { name: 'ALL' }).click()
  await expect(table.getByRole('row')).toHaveCount(4)
})

scenario('DEP-08', 'Dependabot運用状況モーダルを開き一覧・フィルターを操作できる', async ({ page, api }) => {
  await openDepscan(page)
  await page.getByRole('button', { name: 'Dependabot運用状況' }).click()

  const dialog = page.getByRole('dialog', { name: 'Dependabot 運用状況' })
  const table = dialog.getByRole('table', { name: 'Dependabot PR 判定履歴' })
  await expect(dialog).toBeVisible()
  await expect(dialog.getByText('Dependabot 運用状況（DEPSOPS）')).toBeVisible()
  // 1ページ20件
  await expect(table.getByRole('row')).toHaveCount(21)
  await expect(dialog.locator('.recharts-wrapper').first()).toBeVisible()

  // 判定バッジ・種別バッジ・互換性スコア画像・PRリンク
  const first = table.getByRole('row').nth(1)
  await expect(first).toContainText('自動マージ')
  await expect(first).toContainText('セキュリティ更新')
  await expect(first.getByRole('img', { name: 'Dependabot compatibility score' })).toBeVisible()
  await expect(first.getByRole('link', { name: /#100 Bump dep-1/ }))
    .toHaveAttribute('href', 'https://github.com/baby-feelings/app-one/pull/100')
  await expect(table.getByRole('row').nth(2)).toContainText('要確認')
  await expect(table.getByRole('row').nth(2)).toContainText('バージョン更新')
  await expect(table.getByRole('row').nth(2)).toContainText('メジャーアップデートのため要確認 (#101)')
  await expect(table.getByRole('row').nth(3)).toContainText('解消済み')
  await expect(table.getByRole('row').nth(3)).toContainText('不明')

  // 判定フィルター
  const filters = dialog.getByRole('group', { name: '判定フィルター' })
  await expect(filters.getByRole('button', { name: 'すべて' })).toHaveAttribute('aria-pressed', 'true')
  await filters.getByRole('button', { name: '要確認' }).click()
  await expect(filters.getByRole('button', { name: '要確認' })).toHaveAttribute('aria-pressed', 'true')
  const flagged = depsopsItems.filter((d) => d.action === 'flagged').length
  await expect(table.getByRole('row')).toHaveCount(Math.min(flagged, 20) + 1)
  expect(api.lastQuery('/api/depsops')?.get('action')).toBe('flagged')
  await expect(table.getByText('自動マージ')).toHaveCount(0)

  await filters.getByRole('button', { name: '自動マージ' }).click()
  expect(api.lastQuery('/api/depsops')?.get('action')).toBe('merged')
  await filters.getByRole('button', { name: '解消済み' }).click()
  expect(api.lastQuery('/api/depsops')?.get('action')).toBe('closed')
  await filters.getByRole('button', { name: 'すべて' }).click()
  expect(api.lastQuery('/api/depsops')?.has('action')).toBe(false)
})

scenario('DEP-09', 'モーダルを閉じるボタン/Escapeで閉じられる', async ({ page, api }) => {
  await openDepscan(page)
  const open = page.getByRole('button', { name: 'Dependabot運用状況' })
  const dialog = page.getByRole('dialog', { name: 'Dependabot 運用状況' })

  await open.click()
  await expect(dialog).toBeVisible()
  await dialog.getByRole('button', { name: '閉じる' }).click()
  await expect(dialog).toBeHidden()

  await open.click()
  await expect(dialog).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(dialog).toBeHidden()

  // 閉じている間は DEPSOPS のデータを取得しない（開いた2回分のみ）
  const callsWhileClosed = api.requestsTo('/api/depsops').length
  await page.getByRole('button', { name: '再読み込み' }).click()
  await expect(page.getByRole('table', { name: TABLE })).toBeVisible()
  expect(api.requestsTo('/api/depsops')).toHaveLength(callsWhileClosed)
})

scenario('DEP-10', 'ログアウトは確認ダイアログを経て未ログインに戻る（キャンセルで維持）', async ({ page }) => {
  await openDepscan(page)
  const logout = page.getByRole('button', { name: 'ログアウト' })

  // キャンセルすると、ログイン状態のまま
  page.once('dialog', (dialog) => {
    expect(dialog.message()).toBe('ログアウトしますか？')
    void dialog.dismiss()
  })
  await logout.click()
  await expect(page.getByText('ログイン中:')).toBeVisible()
  expect(await page.evaluate(() => localStorage.getItem('depscan_session_token'))).toBe('test-session-token')

  // 承認するとセッションが破棄され、ログイン案内に戻る
  page.once('dialog', (dialog) => void dialog.accept())
  await logout.click()
  await expect(page.getByText('GitHubアカウントでログインしてください')).toBeVisible()
  expect(await page.evaluate(() => localStorage.getItem('depscan_session_token'))).toBeNull()
  expect(await page.evaluate(() => localStorage.getItem('depscan_session_user'))).toBeNull()
})

scenario('DEP-11', 'スキャンエラー状態のときエラーバナーが表示される', async ({ page, api }) => {
  api.state.scanStatuses = [{ username: 'octocat', status: 'error', error_message: 'rate limit exceeded' }]
  await seedSession(page)
  await page.goto('/')
  await openTab(page, 'DEPSCAN')

  await expect(page.getByText('スキャン中にエラーが発生しました: rate limit exceeded')).toBeVisible()
  // エラーでもスキャン中表示にはならず、既存データのパネルは閲覧できる
  await expect(page.getByRole('table', { name: TABLE })).toBeVisible()
})

scenario('DEP-12', 'セッション失効（401）で自動的にログアウトされる', async ({ page, api }) => {
  api.override('GET', '/auth/scan-status', () => ({ status: 401, body: { detail: 'expired' } }))
  await seedSession(page)
  await page.goto('/')
  await openTab(page, 'DEPSCAN')

  await expect(page.getByText('GitHubアカウントでログインしてください')).toBeVisible()
  expect(await page.evaluate(() => localStorage.getItem('depscan_session_token'))).toBeNull()
})

scenario('DEP-13', '新しいクロールを検知すると更新バナーが表示され更新できる', async ({ page, api }) => {
  // 2分間隔の確認ポーリングを待たずに進められるよう、ブラウザの時計を制御する
  await page.clock.install()
  await seedSession(page)
  await page.goto('/')
  await openTab(page, 'DEPSCAN')
  await expect(page.getByRole('table', { name: TABLE })).toBeVisible()
  // 表示データの基準となるクロールログIDが記録されるまで待つ
  await expect.poll(() => api.requestsTo('/api/crawler-logs').length).toBeGreaterThan(0)
  await expect(page.getByText('新しいデータがあります')).toHaveCount(0)

  // 新しいクロールが完了した状態にして2分以上進める
  api.state.crawlerLogId = 101
  await page.clock.runFor(125_000)
  await expect(page.getByText('新しいデータがあります')).toBeVisible()

  // バナーの「更新」で再取得し、バナーは消える
  const before = api.requestsTo('/api/depscan').length
  await page.getByRole('button', { name: '更新', exact: true }).click()
  await expect(page.getByText('新しいデータがあります')).toHaveCount(0)
  expect(api.requestsTo('/api/depscan').length).toBeGreaterThan(before)

  // 以降、同じIDのままではバナーは再表示されない
  await page.clock.runFor(125_000)
  await expect(page.getByText('新しいデータがあります')).toHaveCount(0)
})

scenario('DEP-14', '該当なしのとき空状態メッセージが表示される', async ({ page, api }) => {
  api.override('GET', '/api/depscan', () => ({ body: { total: 0, page: 1, per_page: 200, data: [] } }))
  await seedSession(page)
  await page.goto('/')
  await openTab(page, 'DEPSCAN')

  await expect(page.getByText('該当する依存ライブラリ脆弱性はありません')).toBeVisible()
  await expect(page.getByRole('table', { name: TABLE })).toHaveCount(0)
})

scenario('DEP-15', 'リクエストにBearerトークンが付与される（X-API-KEYではない）', async ({ page, api }) => {
  await openDepscan(page)

  for (const path of ['/api/depscan', '/api/depscan/stats', '/auth/scan-status']) {
    const [req] = api.requestsTo(path)
    expect(req.headers['authorization'], path).toBe('Bearer test-session-token')
    expect(req.headers['x-api-key'], path).toBeUndefined()
  }
  // ログインユーザー向けではない公開エンドポイントは従来どおり公開キー
  expect(api.requestsTo('/api/crawler-logs')[0].headers['x-api-key']).toBe('e2e-public-key')
  // 全件取得は API の最大 per_page=200 で行う
  expect(api.requestsTo('/api/depscan')[0].query.get('per_page')).toBe('200')
})

scenario('DEP-16', 'モーダルのページ送りと該当なし状態', async ({ page, api }) => {
  await openDepscan(page)
  await page.getByRole('button', { name: 'Dependabot運用状況' }).click()
  const dialog = page.getByRole('dialog', { name: 'Dependabot 運用状況' })
  const bottom = dialog.getByRole('navigation', { name: 'ページ送り（下部）' })

  // 45件 / 20件 = 3ページ。最終ページは5件
  await expect(bottom).toContainText('1 / 3')
  await expect(bottom).toContainText(`（${DEPSOPS_TOTAL} 件）`)
  await bottom.getByRole('button', { name: '次へ →' }).click()
  await expect(bottom).toContainText('2 / 3')
  expect(api.lastQuery('/api/depsops')?.get('page')).toBe('2')
  expect(api.lastQuery('/api/depsops')?.get('per_page')).toBe('20')
  await bottom.getByRole('button', { name: '次へ →' }).click()
  await expect(dialog.getByRole('table', { name: 'Dependabot PR 判定履歴' }).getByRole('row')).toHaveCount(6)

  // 該当するPRがない判定フィルターでは空状態になる
  api.override('GET', '/api/depsops', (req) => (
    req.query.get('action') === 'closed' ? { body: { total: 0, page: 1, per_page: 20, data: [] } } : undefined
  ))
  await dialog.getByRole('group', { name: '判定フィルター' }).getByRole('button', { name: '解消済み' }).click()
  await expect(dialog.getByText('該当する PR はありません')).toBeVisible()
})
