import { expect, scenario } from './support/test'
import { KEV_TOTAL } from './support/mockData'

// KEVタブ（初期表示タブ）のテスト。一覧は1ページ30件。

scenario('KEV-01', '一覧・件数サマリー・グラフが表示される', async ({ page }) => {
  await page.goto('/')

  const table = page.getByRole('table', { name: 'KEV 脆弱性一覧' })
  // ヘッダー行 + 30件
  await expect(table.getByRole('row')).toHaveCount(31)
  await expect(table.getByRole('link', { name: 'CVE-2026-0001' })).toBeVisible()
  await expect(table.getByRole('columnheader', { name: 'EPSS' })).toBeVisible()

  // 件数サマリー（直近30日の新規 / 全件数）
  await expect(page.getByText('直近30日 3')).toBeVisible()
  await expect(page.getByText(`/ ${KEV_TOTAL} 件`)).toBeVisible()

  // グラフ（ベンダー別・月別トレンド）。データ取得後は「データなし」にならない
  await expect(page.getByText('ベンダー別件数 TOP8')).toBeVisible()
  await expect(page.getByText('月別 CVE 追加数トレンド')).toBeVisible()
  await expect(page.locator('.recharts-wrapper')).toHaveCount(2)
  await expect(page.getByText('データなし')).toHaveCount(0)
})

scenario('KEV-02', '行クリックで詳細（説明・推奨対処・EPSS）が展開/折りたたみされる', async ({ page }) => {
  await page.goto('/')
  const row = page.getByRole('row', { name: /CVE-2026-0001/ })

  await expect(row).toHaveAttribute('aria-expanded', 'false')
  await expect(page.getByText('説明文 1:')).toBeHidden()

  await row.click()
  await expect(row).toHaveAttribute('aria-expanded', 'true')
  await expect(page.getByText(/説明文 1: Microsoft 製品にリモートコード実行/)).toBeVisible()
  await expect(page.getByText(/推奨対処:/)).toBeVisible()
  await expect(page.getByText('ベンダーの指示に従い修正パッチを適用する (#1)')).toBeVisible()
  await expect(page.getByText('97.32%')).toBeVisible()
  await expect(page.getByText(/パーセンタイル 98.0%/)).toBeVisible()

  await row.click()
  await expect(row).toHaveAttribute('aria-expanded', 'false')
  await expect(page.getByText('説明文 1:')).toBeHidden()
})

scenario('KEV-03', 'キーワード検索で絞り込まれ、クリアで元に戻る', async ({ page, api }) => {
  await page.goto('/')
  const table = page.getByRole('table', { name: 'KEV 脆弱性一覧' })
  const search = page.getByRole('textbox', { name: 'ベンダー名・製品名' })

  await search.fill('Cisco')
  // Cisco は 65 件中 16 件（添字を4で割った余りが2）
  await expect(table.getByRole('row')).toHaveCount(17)
  await expect(table.getByRole('cell', { name: 'Cisco', exact: true })).toHaveCount(16)
  await expect(table.getByText('Microsoft')).toHaveCount(0)
  expect(api.lastQuery('/api/vulnerabilities')?.get('search')).toBe('Cisco')
  expect(api.lastQuery('/api/vulnerabilities')?.get('page')).toBe('1')

  await page.getByRole('button', { name: '検索をクリア' }).click()
  await expect(search).toHaveValue('')
  await expect(table.getByRole('row')).toHaveCount(31)
  await expect(page.getByRole('button', { name: '検索をクリア' })).toBeHidden()
})

scenario('KEV-04', 'ページ送り（次へ/前へ）と境界でのボタン無効化', async ({ page, api }) => {
  await page.goto('/')
  const table = page.getByRole('table', { name: 'KEV 脆弱性一覧' })
  const bottom = page.getByRole('navigation', { name: 'ページ送り（下部）' })
  const top = page.getByRole('navigation', { name: 'ページ送り（上部）' })

  // 65件 / 30件 = 3ページ。1ページ目では「前へ」は押せない
  await expect(bottom).toContainText('1 / 3')
  await expect(bottom).toContainText(`（${KEV_TOTAL} 件）`)
  await expect(bottom.getByRole('button', { name: '← 前へ' })).toBeDisabled()
  await expect(bottom.getByRole('button', { name: '次へ →' })).toBeEnabled()

  await bottom.getByRole('button', { name: '次へ →' }).click()
  await expect(top).toContainText('2 / 3')
  await expect(table.getByRole('link', { name: 'CVE-2026-0031' })).toBeVisible()
  expect(api.lastQuery('/api/vulnerabilities')?.get('page')).toBe('2')

  // 上部のページ送りからも操作できる
  await top.getByRole('button', { name: '次へ →' }).click()
  await expect(bottom).toContainText('3 / 3')
  // 最終ページは 65 - 60 = 5 件、「次へ」は押せない
  await expect(table.getByRole('row')).toHaveCount(6)
  await expect(bottom.getByRole('button', { name: '次へ →' })).toBeDisabled()

  await bottom.getByRole('button', { name: '← 前へ' }).click()
  await expect(bottom).toContainText('2 / 3')
})

scenario('KEV-05', '該当なしのとき空状態メッセージが表示される', async ({ page, api }) => {
  api.override('GET', '/api/vulnerabilities', () => ({
    body: { total: 0, page: 1, per_page: 30, data: [] },
  }))
  await page.goto('/')

  await expect(page.getByText('該当する CVE はありません')).toBeVisible()
  await expect(page.getByText('クローラーがデータを取得すると表示されます')).toBeVisible()
  await expect(page.getByRole('table', { name: 'KEV 脆弱性一覧' })).toHaveCount(0)
})

scenario('KEV-06', '再読み込みボタンで一覧と統計が再取得される', async ({ page, api }) => {
  await page.goto('/')
  await expect(page.getByRole('table', { name: 'KEV 脆弱性一覧' })).toBeVisible()
  const before = {
    list: api.requestsTo('/api/vulnerabilities').length,
    stats: api.requestsTo('/api/vulnerabilities/stats').length,
    recent: api.requestsTo('/api/vulnerabilities/recent').length,
  }

  await page.getByRole('button', { name: '再読み込み' }).click()

  await expect.poll(() => api.requestsTo('/api/vulnerabilities').length).toBe(before.list + 1)
  await expect.poll(() => api.requestsTo('/api/vulnerabilities/stats').length).toBe(before.stats + 1)
  await expect.poll(() => api.requestsTo('/api/vulnerabilities/recent').length).toBe(before.recent + 1)
  await expect(page.getByRole('table', { name: 'KEV 脆弱性一覧' })).toBeVisible()
})

scenario('KEV-07', 'EPSS未取得は「—」、CVE IDはNVDへの外部リンクになる', async ({ page }) => {
  await page.goto('/')

  // 2件目はEPSS未取得（null）のため「—」を表示する
  const noEpss = page.getByRole('row', { name: /CVE-2026-0002/ })
  await expect(noEpss.getByRole('cell', { name: '—' })).toBeVisible()
  // 1件目はEPSSが割合で表示される
  await expect(page.getByRole('row', { name: /CVE-2026-0001/ }).getByText('97.3%')).toBeVisible()

  const link = page.getByRole('link', { name: 'CVE-2026-0001' })
  await expect(link).toHaveAttribute('href', 'https://nvd.nist.gov/vuln/detail/CVE-2026-0001')
  await expect(link).toHaveAttribute('target', '_blank')
  await expect(link).toHaveAttribute('rel', /noopener/)

  // リンクのクリックでは行の展開が起きない（stopPropagation）
  await link.evaluate((a) => a.addEventListener('click', (e) => e.preventDefault()))
  await link.click()
  await expect(page.getByRole('row', { name: /CVE-2026-0001/ })).toHaveAttribute('aria-expanded', 'false')
})

scenario('KEV-08', 'APIエラー時もクラッシュせずデータなし状態になる', async ({ page, api }) => {
  for (const path of ['/api/vulnerabilities', '/api/vulnerabilities/stats', '/api/vulnerabilities/recent']) {
    api.override('GET', path, () => ({ status: 500, body: { detail: 'boom' } }))
  }
  await page.goto('/')

  // グラフは「データなし」、一覧は表示されないが、画面は操作可能なまま
  await expect(page.getByText('データなし')).toHaveCount(2)
  await expect(page.getByRole('table', { name: 'KEV 脆弱性一覧' })).toHaveCount(0)
  await expect(page.getByRole('textbox', { name: 'ベンダー名・製品名' })).toBeVisible()
  await expect(page.getByRole('button', { name: '再読み込み' })).toBeEnabled()
})

scenario('KEV-09', 'リクエストに公開用 X-API-KEY ヘッダーが付与される', async ({ page, api }) => {
  await page.goto('/')
  await expect(page.getByRole('table', { name: 'KEV 脆弱性一覧' })).toBeVisible()

  for (const path of ['/api/vulnerabilities', '/api/vulnerabilities/stats', '/api/vulnerabilities/recent']) {
    const [req] = api.requestsTo(path)
    expect(req.headers['x-api-key'], path).toBe('e2e-public-key')
    expect(req.headers['authorization'], path).toBeUndefined()
  }
  // /health は認証不要
  expect(api.requestsTo('/health')[0].headers['x-api-key']).toBeUndefined()
})

scenario('KEV-10', 'ページ送りの最初/最後ボタンとページ番号の直接入力', async ({ page, api }) => {
  await page.goto('/')
  const bottom = page.getByRole('navigation', { name: 'ページ送り（下部）' })
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
  expect(api.lastQuery('/api/vulnerabilities')?.get('page')).toBe('3')

  // 「最初」で1ページ目へ戻る
  await first.click()
  await expect(bottom).toContainText('1 / 3')
  expect(api.lastQuery('/api/vulnerabilities')?.get('page')).toBe('1')

  // 数字以外は入力できず、「移動」ボタンで指定ページへ移動する
  await jump.fill('2')
  await expect(jump).toHaveValue('2')
  await move.click()
  await expect(bottom).toContainText('2 / 3')
  expect(api.lastQuery('/api/vulnerabilities')?.get('page')).toBe('2')
  await expect(jump).toHaveValue('')

  // 範囲外は最終ページに丸められ、Enterでも確定できる
  await jump.fill('999')
  await jump.press('Enter')
  await expect(bottom).toContainText('3 / 3')
  expect(api.lastQuery('/api/vulnerabilities')?.get('page')).toBe('3')

  // 0 は1ページ目に丸められる
  await jump.fill('0')
  await move.click()
  await expect(bottom).toContainText('1 / 3')
})

scenario('KEV-11', 'スマホ幅でもページ送りが画面内に収まり横スクロールしない', async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 812 })
  await page.goto('/')
  const bottom = page.getByRole('navigation', { name: 'ページ送り（下部）' })
  await expect(bottom).toContainText('1 / 3')

  // 全ボタン・入力欄が表示され、画面幅（375px）の内側に収まっている
  for (const name of ['最初のページへ', '← 前へ', '次へ →', '最後のページへ', '入力したページへ移動']) {
    const box = await bottom.getByRole('button', { name }).boundingBox()
    expect(box, name).not.toBeNull()
    expect(box!.x, name).toBeGreaterThanOrEqual(0)
    expect(box!.x + box!.width, name).toBeLessThanOrEqual(375)
  }
  const input = await bottom.getByLabel('ページ番号を入力').boundingBox()
  expect(input!.x + input!.width).toBeLessThanOrEqual(375)

  // ページ全体が横にはみ出していない
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  )
  expect(overflow).toBeLessThanOrEqual(0)

  // スマホ幅でも「最後」へ移動できる
  await bottom.getByRole('button', { name: '最後のページへ' }).click()
  await expect(bottom).toContainText('3 / 3')
})
