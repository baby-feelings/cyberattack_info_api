import { API_PREFIX } from './support/mockApi'
import { expect, openTab, scenario, seedSession, type Page } from './support/test'
import { DEPSOPS_TOTAL, depscanFindings, depsopsItems } from './support/mockData'

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
  // 帯: 対応が必要な件数（CRITICAL 1 + HIGH 1）と、未解決の総件数
  await expect(page.getByText('件が対応必要（CRITICAL・HIGH）')).toBeVisible()
  await expect(page.getByText('未解決 4 件のうち')).toBeVisible()

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

  // グラフは最初から表示されている
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
  await expect(table.getByRole('row').nth(3)).toContainText('自動マージ')
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
  // 解決済みPRは履歴ごと削除されるため「解消済み」フィルターは存在しない
  await expect(filters.getByRole('button', { name: '解消済み' })).toHaveCount(0)
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

scenario('DEP-18', '表示時にセッションが延長され、新しいトークンが保存される（Issue #337）', async ({ page, api }) => {
  api.override('POST', '/auth/refresh', () => ({
    body: { token: 'refreshed-token', username: 'octocat' },
  }))
  await seedSession(page)
  await page.goto('/')
  await openTab(page, 'DEPSCAN')

  await expect.poll(() => page.evaluate(() => localStorage.getItem('depscan_session_token')))
    .toBe('refreshed-token')
  expect(api.requestsTo('/auth/refresh', 'POST')).toHaveLength(1)
})

scenario('DEP-19', '延長できない（ログインから上限日数を超えた等）セッションはログアウトされる', async ({ page, api }) => {
  api.override('POST', '/auth/refresh', () => ({ status: 401, body: { detail: 'expired' } }))
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
    req.query.get('action') === 'flagged' ? { body: { total: 0, page: 1, per_page: 20, data: [] } } : undefined
  ))
  await dialog.getByRole('group', { name: '判定フィルター' }).getByRole('button', { name: '要確認' }).click()
  await expect(dialog.getByText('該当する PR はありません')).toBeVisible()
})

scenario('DEP-17', 'モーダルのページ送りの最初/最後ボタンとページ番号の直接入力', async ({ page, api }) => {
  await openDepscan(page)
  await page.getByRole('button', { name: 'Dependabot運用状況' }).click()
  const dialog = page.getByRole('dialog', { name: 'Dependabot 運用状況' })
  const bottom = dialog.getByRole('navigation', { name: 'ページ送り（下部）' })
  const first = bottom.getByRole('button', { name: '最初のページへ' })
  const last = bottom.getByRole('button', { name: '最後のページへ' })
  const jump = bottom.getByLabel('ページ番号を入力')
  const move = bottom.getByRole('button', { name: '入力したページへ移動' })

  // 1ページ目: 「最初」は押せず「最後」は押せる。入力欄が空のうちは「移動」も押せない
  await expect(bottom).toContainText('1 / 3')
  await expect(first).toBeDisabled()
  await expect(last).toBeEnabled()
  await expect(move).toBeDisabled()

  // 「最後」で最終ページへ一気に移動する
  await last.click()
  await expect(bottom).toContainText('3 / 3')
  await expect(last).toBeDisabled()
  expect(api.lastQuery('/api/depsops')?.get('page')).toBe('3')

  // 「最初」で1ページ目へ戻る
  await first.click()
  await expect(bottom).toContainText('1 / 3')
  expect(api.lastQuery('/api/depsops')?.get('page')).toBe('1')

  // 数字以外は入力できず、「移動」ボタンで指定ページへ移動する
  await jump.fill('2')
  await expect(jump).toHaveValue('2')
  await move.click()
  await expect(bottom).toContainText('2 / 3')
  expect(api.lastQuery('/api/depsops')?.get('page')).toBe('2')
  await expect(jump).toHaveValue('')

  // 範囲外は最終ページに丸められ、Enterでも確定できる
  await jump.fill('999')
  await jump.press('Enter')
  await expect(bottom).toContainText('3 / 3')
  expect(api.lastQuery('/api/depsops')?.get('page')).toBe('3')

  // 0 は1ページ目に丸められる
  await jump.fill('0')
  await move.click()
  await expect(bottom).toContainText('1 / 3')
})

scenario('DEP-20', '運用中／運用停止中を切り替えると、リクエストと一覧が分かれる', async ({ page, api }) => {
  api.state.inactiveRepos = ['baby-feelings/app-two']
  const table = await openDepscan(page)
  const group = page.getByRole('group', { name: '運用状態フィルター' })

  // 初期表示は運用中のみ（lodash と express。停止中の app-two の requests は出ない）
  await expect(group.getByRole('button', { name: '運用中' })).toHaveAttribute('aria-pressed', 'true')
  expect(api.lastQuery('/api/depscan')?.get('operating')).toBe('active')
  expect(api.lastQuery('/api/depscan/stats')?.get('operating')).toBe('active')
  await expect(table.getByRole('row')).toHaveCount(3)
  await expect(table).not.toContainText('requests')

  await group.getByRole('button', { name: '運用停止中' }).click()
  await expect(group.getByRole('button', { name: '運用停止中' })).toHaveAttribute('aria-pressed', 'true')
  expect(api.lastQuery('/api/depscan')?.get('operating')).toBe('inactive')
  await expect(table.getByRole('row')).toHaveCount(2)
  await expect(table).toContainText('requests')

  // すべては、従来どおり operating を付けない
  await group.getByRole('button', { name: 'すべて' }).click()
  expect(api.lastQuery('/api/depscan')?.has('operating')).toBe(false)
  await expect(table.getByRole('row')).toHaveCount(4)
})

scenario('DEP-21', 'Dependabot運用状況モーダルも運用中／運用停止中で分かれる', async ({ page, api }) => {
  api.state.inactiveRepos = ['baby-feelings/app-two']
  await openDepscan(page)
  await page.getByRole('button', { name: 'Dependabot運用状況' }).click()
  const dialog = page.getByRole('dialog', { name: 'Dependabot 運用状況' })
  const bottom = dialog.getByRole('navigation', { name: 'ページ送り（下部）' })
  const group = dialog.getByRole('group', { name: '運用状態フィルター' })

  // 45件のうち、app-one（運用中）は23件
  await expect(bottom).toContainText('（23 件）')
  expect(api.lastQuery('/api/depsops')?.get('operating')).toBe('active')
  expect(api.lastQuery('/api/depsops/stats')?.get('operating')).toBe('active')
  await expect(dialog).not.toContainText('baby-feelings/app-two')

  // 運用停止中の app-two は22件。切り替えるとページは1に戻る
  await group.getByRole('button', { name: '運用停止中' }).click()
  await expect(bottom).toContainText('（22 件）')
  expect(api.lastQuery('/api/depsops')?.get('operating')).toBe('inactive')
  expect(api.lastQuery('/api/depsops')?.get('page')).toBe('1')
  await expect(dialog).not.toContainText('baby-feelings/app-one')

  await group.getByRole('button', { name: 'すべて' }).click()
  await expect(bottom).toContainText('（45 件）')
  expect(api.lastQuery('/api/depsops')?.has('operating')).toBe(false)
})

scenario('DEP-22', '左のアプリ一覧で、対応が必要なアプリが上に並び、選ぶと一覧がそのアプリに絞られる', async ({ page }) => {
  const table = await openDepscan(page)
  const rail = page.getByRole('navigation', { name: 'アプリ一覧' })

  // 先頭は「すべてのアプリ」、次に対応が必要（CRITICAL・HIGH）を持つ app-one
  const buttons = rail.getByRole('button')
  await expect(buttons.first()).toContainText('すべてのアプリ')
  await expect(buttons.nth(1)).toContainText('app-one')
  await expect(table.getByRole('row')).toHaveCount(4)

  // app-one を選ぶと lodash だけになり、リポジトリ列は消える
  await buttons.nth(1).click()
  await expect(table.getByRole('row')).toHaveCount(2)
  await expect(table.getByRole('row').nth(1)).toContainText('lodash')
  await expect(table.getByRole('columnheader', { name: 'リポジトリ' })).toHaveCount(0)

  // 「すべてのアプリ」で元に戻る
  await buttons.first().click()
  await expect(table.getByRole('row')).toHaveCount(4)
  await expect(table.getByRole('columnheader', { name: 'リポジトリ' })).toBeVisible()
})


scenario('DEP-23', '依存パッケージのモーダルで、アプリごとに閲覧し、パッケージ・版・エコシステムで検索できる', async ({ page, api }) => {
  await openDepscan(page)
  await page.getByRole('button', { name: '依存パッケージ' }).click()

  const dialog = page.getByRole('dialog', { name: '依存パッケージ' })
  await expect(dialog).toBeVisible()
  // 開いただけで、運用中のアプリすべての依存が一覧に出る（何も入力しなくてよい）。Bearer トークンで取得する
  const table = dialog.getByRole('table', { name: '依存パッケージ一覧' })
  // ヘッダー行 + 4件
  await expect(table.getByRole('row')).toHaveCount(5)
  expect(api.lastQuery('/api/depscan/dependencies')?.get('operating')).toBe('active')
  expect(api.requestsTo('/api/depscan/dependencies')[0].headers.authorization).toMatch(/^Bearer /)

  // 左のアプリ一覧: 検知がある依存の多いアプリが先頭。「すべてのアプリ」には依存の総数
  const rail = dialog.getByRole('navigation', { name: 'アプリ一覧' })
  await expect(rail.getByRole('button').first()).toContainText('すべてのアプリ')
  await expect(rail.getByRole('button').nth(1)).toContainText('app-one')
  await expect(rail.getByRole('button').nth(1)).toContainText('1')

  // アプリを選ぶと、そのアプリの依存だけになり、アプリ列は消える
  await rail.getByRole('button', { name: /app-two/ }).click()
  await expect(table.getByRole('row')).toHaveCount(3)
  expect(api.lastQuery('/api/depscan/dependencies')?.get('repo')).toBe('baby-feelings/app-two')
  await expect(table.getByRole('columnheader', { name: 'アプリ' })).toHaveCount(0)
  await rail.getByRole('button', { name: /すべてのアプリ/ }).click()
  await expect(table.getByRole('columnheader', { name: 'アプリ' })).toBeVisible()

  // 脆弱性ありのみ: 未解決の検知がある版は赤いバッジ
  await dialog.getByRole('button', { name: '脆弱性ありのみ' }).click()
  await expect(table.getByRole('row')).toHaveCount(4)
  await expect(table.getByRole('row').nth(1)).toContainText('未解決 2 件')
  expect(api.lastQuery('/api/depscan/dependencies')?.get('vulnerable')).toBe('true')
  await dialog.getByRole('button', { name: '脆弱性ありのみ' }).click()
  await expect(table.getByRole('row')).toHaveCount(5)

  // パッケージ名（部分一致）で検索
  await dialog.getByLabel('パッケージ名（部分一致）').fill('lodash')
  await dialog.getByRole('button', { name: '検索' }).click()
  await expect(table.getByRole('row')).toHaveCount(3)
  await expect(table.getByRole('row').nth(2)).toContainText('検知なし')
  expect(api.lastQuery('/api/depscan/dependencies')?.get('package')).toBe('lodash')

  // バージョン（完全一致）を足す
  await dialog.getByLabel('バージョン（完全一致）').fill('4.17.21')
  await dialog.getByRole('button', { name: '検索' }).click()
  await expect(table.getByRole('row')).toHaveCount(2)
  await expect(table.getByRole('row').nth(1)).toContainText('baby-feelings/app-two')

  // エコシステムで絞り込み、該当なしの表示
  await dialog.getByLabel('バージョン（完全一致）').fill('')
  await dialog.getByLabel('パッケージ名（部分一致）').fill('')
  await dialog.getByLabel('エコシステム').selectOption('Pub')
  await expect(dialog.getByText('該当する依存パッケージはありません')).toBeVisible()
  expect(api.lastQuery('/api/depscan/dependencies')?.get('ecosystem')).toBe('Pub')
})

scenario('DEP-24', 'スマホ幅でも、操作ボタンが縦に崩れず、タイトルの下に折り返して並ぶ', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await openDepscan(page)

  const heading = page.getByText('自作アプリの依存ライブラリ脆弱性（未解決）')
  const packages = page.getByRole('button', { name: '依存パッケージ' })
  const runtimes = page.getByRole('button', { name: '言語・実行環境' })
  const depsops = page.getByRole('button', { name: 'Dependabot運用状況' })
  await expect(packages).toBeVisible()
  await expect(runtimes).toBeVisible()
  await expect(depsops).toBeVisible()

  // ボタンの文字は折り返されず、1行の高さに収まる（以前は幅が足りず、1文字ずつ縦に折り返していた）
  for (const button of [packages, runtimes, depsops]) {
    const box = await button.boundingBox()
    expect(box!.height).toBeLessThan(40)
    expect(box!.width).toBeGreaterThan(90)
  }
  // 操作ボタンは、タイトルの下の段に並ぶ
  const headingBox = await heading.boundingBox()
  const packagesBox = await packages.boundingBox()
  expect(packagesBox!.y).toBeGreaterThan(headingBox!.y + headingBox!.height - 1)
})

scenario('DEP-25', '言語・実行環境のモーダルで、アプリごとに版と状態を閲覧し、更新が必要なものだけに絞れる', async ({ page, api }) => {
  await openDepscan(page)
  await page.getByRole('button', { name: '言語・実行環境' }).click()

  const dialog = page.getByRole('dialog', { name: '言語・実行環境' })
  await expect(dialog).toBeVisible()
  // 開いただけで、運用中のアプリすべての言語・実行環境が一覧に出る（何も入力しなくてよい）。Bearer トークンで取得する
  const table = dialog.getByRole('table', { name: '言語・実行環境一覧' })
  // ヘッダー行 + 5件
  await expect(table.getByRole('row')).toHaveCount(6)
  expect(api.lastQuery('/api/runtimes')?.get('operating')).toBe('active')
  expect(api.requestsTo('/api/runtimes')[0].headers.authorization).toMatch(/^Bearer /)

  // 対応が急ぐもの（サポート終了）が先頭の行に、状態のバッジと終了済みの表示が出る
  await expect(table.getByRole('row').nth(1)).toContainText('サポート終了')
  await expect(table.getByRole('row').nth(1)).toContainText('終了済み')
  // 下限の指定は「参考」として、警告にしない
  await expect(table).toContainText('参考（下限の指定）')

  // 言語ごとの推奨の版（サポート中で公開から経った最新）。公開直後の 3.15 は出さない
  const strip = dialog.getByLabel('推奨の版')
  await expect(strip).toContainText('Python 3.14')
  await expect(strip).toContainText('Node.js 24')
  await expect(strip).not.toContainText('3.15')

  // 左のアプリ一覧: 対応が必要な数が多いアプリが先頭。「すべてのアプリ」には検出した数の合計
  const rail = dialog.getByRole('navigation', { name: 'アプリ一覧' })
  await expect(rail.getByRole('button').first()).toContainText('すべてのアプリ')
  await expect(rail.getByRole('button').nth(1)).toContainText('app-one')

  // アプリを選ぶと、そのアプリの設定だけになり、アプリ列は消える
  await rail.getByRole('button', { name: /app-two/ }).click()
  await expect(table.getByRole('row')).toHaveCount(3)
  expect(api.lastQuery('/api/runtimes')?.get('repo')).toBe('baby-feelings/app-two')
  await expect(table.getByRole('columnheader', { name: 'アプリ' })).toHaveCount(0)
  await rail.getByRole('button', { name: /すべてのアプリ/ }).click()
  await expect(table.getByRole('columnheader', { name: 'アプリ' })).toBeVisible()

  // 更新が必要なものだけ（サポート終了・期限間近・更新あり）
  await dialog.getByRole('button', { name: '更新が必要なものだけ' }).click()
  await expect(table.getByRole('row')).toHaveCount(3)
  expect(api.lastQuery('/api/runtimes')?.get('needs_action')).toBe('true')
  await dialog.getByRole('button', { name: '更新が必要なものだけ' }).click()
  await expect(table.getByRole('row')).toHaveCount(6)

  // 言語で絞り込み、該当なしの表示
  // 「言語」は、一覧の列見出しとは別の、絞り込みの選択欄（コンボボックス）を指す
  await dialog.getByRole('combobox', { name: '言語' }).selectOption('dart')
  await expect(dialog.getByText('該当する言語・実行環境はありません')).toBeVisible()
  expect(api.lastQuery('/api/runtimes')?.get('runtime')).toBe('dart')
})

scenario('DEP-26', '悪意あるパッケージ（MAL-*）は「悪意あり」バッジで区別され、対応が削除であることが分かる', async ({ page, api }) => {
  // 既存の検知を1件だけ、悪意あるパッケージ（脆弱性ではなくマルウェア）に差し替えて返す
  const malicious = {
    ...depscanFindings[0],
    package_name: 'evil-pkg',
    installed_version: '1.0.0',
    osv_id: 'MAL-2026-1234',
    severity: 'CRITICAL',
    cvss_score: null,
    summary: 'Malicious code in evil-pkg (npm)',
    fixed_versions: [],
    is_malicious: true,
    priority_reasons: ['malicious_package'],
  }
  api.override('GET', '/api/depscan', () => ({
    body: { total: 1, page: 1, per_page: 200, data: [malicious] },
  }))

  const table = await openDepscan(page)

  const badge = table.getByText('🛑 悪意あり')
  await expect(badge).toBeVisible()
  await expect(badge).toHaveAttribute('title', /削除/)
  await expect(table).toContainText('evil-pkg')

  // 展開すると、優先度の理由として「悪意あるパッケージ」が示される
  await table.getByText('evil-pkg').click()
  await expect(table.getByText('悪意あるパッケージ', { exact: true })).toBeVisible()
})
