import { expect, scenario, type Page } from './support/test'
import { KEV_TOTAL, kevItems } from './support/mockData'

// KEVタブ（初期表示タブ）のテスト。一覧は1ページ30件。
// 初期表示は「直近30日」で、期間内の全件を取得して画面側で検索・ページ分割する
// （モックは1日1件ずつ追加されているため、直近30日は 31 件＝2 ページ）。「すべて」だけサーバー側のページ分割。

const RECENT_30 = 31
const TABLE = 'KEV 脆弱性一覧'

// 表の CVE ID リンク（日付の区切り行を数えないため、行ではなくリンクで件数を数える）
const cveLinks = (page: Page) => page.getByRole('table', { name: TABLE }).getByRole('link', { name: /^CVE-2026-/ })

// 期間を「すべて」に切り替える（サーバー側のページ分割に切り替わる）
async function showAll(page: Page) {
  await page.getByRole('group', { name: '期間フィルター' }).getByRole('button', { name: 'すべて' }).click()
  await expect(page.getByRole('navigation', { name: 'ページ送り（下部）' })).toContainText(`（${KEV_TOTAL} 件）`)
}

scenario('KEV-01', '一覧・件数サマリー・グラフが表示される', async ({ page }) => {
  await page.goto('/')

  const table = page.getByRole('table', { name: TABLE })
  await expect(cveLinks(page)).toHaveCount(30)
  await expect(table.getByRole('link', { name: 'CVE-2026-0001' })).toBeVisible()
  await expect(table.getByRole('columnheader', { name: 'EPSS' })).toBeVisible()

  // 件数の帯（直近30日の追加件数 / そのうち EPSS 10%以上の件数）
  const band = page.getByRole('group', { name: '件数の集計' })
  await expect(band.getByText('31', { exact: true })).toBeVisible()
  await expect(band.getByText('件が直近30日に追加')).toBeVisible()
  await expect(band.getByText('1', { exact: true })).toBeVisible()
  await expect(band.getByText('件は悪用されやすい（EPSS 10%以上）')).toBeVisible()

  // グラフ（ベンダー別・月別トレンド）は初期は畳まれていて、開くと表示される
  await expect(page.getByText('ベンダー別件数 TOP8')).toHaveCount(0)
  await page.getByText('グラフ（ベンダー別・月別トレンド）を開く').click()
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
  const table = page.getByRole('table', { name: TABLE })
  const search = page.getByRole('textbox', { name: 'ベンダー名・製品名' })
  await expect(cveLinks(page)).toHaveCount(30)

  await search.fill('Cisco')
  // 直近30日の 31 件のうち Cisco は 8 件（添字を4で割った余りが2）。期間内の一覧は取得済みのため、画面側で絞る
  await expect(cveLinks(page)).toHaveCount(8)
  await expect(table.getByRole('cell', { name: 'Cisco', exact: true })).toHaveCount(8)
  await expect(table.getByText('Microsoft')).toHaveCount(0)
  expect(api.requestsTo('/api/vulnerabilities/recent')).toHaveLength(1)
  expect(api.requestsTo('/api/vulnerabilities')).toHaveLength(0)

  await page.getByRole('button', { name: '検索をクリア' }).click()
  await expect(search).toHaveValue('')
  await expect(cveLinks(page)).toHaveCount(30)
  await expect(page.getByRole('button', { name: '検索をクリア' })).toBeHidden()
})

scenario('KEV-04', 'ページ送り（次へ/前へ）と境界でのボタン無効化', async ({ page, api }) => {
  await page.goto('/')
  const bottom = page.getByRole('navigation', { name: 'ページ送り（下部）' })
  const top = page.getByRole('navigation', { name: 'ページ送り（上部）' })

  // 31件 / 30件 = 2ページ（画面側で分割）。1ページ目では「前へ」は押せない
  await expect(bottom).toContainText('1 / 2')
  await expect(bottom).toContainText(`（${RECENT_30} 件）`)
  await expect(bottom.getByRole('button', { name: '← 前へ' })).toBeDisabled()
  await expect(bottom.getByRole('button', { name: '次へ →' })).toBeEnabled()

  await bottom.getByRole('button', { name: '次へ →' }).click()
  await expect(top).toContainText('2 / 2')
  // 最終ページは 31 - 30 = 1 件、「次へ」は押せない
  await expect(cveLinks(page)).toHaveCount(1)
  await expect(page.getByRole('table', { name: TABLE }).getByRole('link', { name: 'CVE-2026-0031' })).toBeVisible()
  await expect(bottom.getByRole('button', { name: '次へ →' })).toBeDisabled()

  // 上部のページ送りからも操作できる
  await top.getByRole('button', { name: '← 前へ' }).click()
  await expect(bottom).toContainText('1 / 2')
  // ページを送っても、期間内の一覧は取り直さない
  expect(api.requestsTo('/api/vulnerabilities/recent')).toHaveLength(1)
})

scenario('KEV-05', '該当なしのとき空状態メッセージが表示される', async ({ page, api }) => {
  api.override('GET', '/api/vulnerabilities/recent', () => ({ body: [] }))
  await page.goto('/')

  await expect(page.getByText('該当する CVE はありません')).toBeVisible()
  await expect(page.getByText('クローラーがデータを取得すると表示されます')).toBeVisible()
  await expect(page.getByRole('table', { name: TABLE })).toHaveCount(0)
})

scenario('KEV-06', '再読み込みボタンで一覧と統計が再取得される', async ({ page, api }) => {
  await page.goto('/')
  await expect(page.getByRole('table', { name: TABLE })).toBeVisible()
  const before = {
    stats: api.requestsTo('/api/vulnerabilities/stats').length,
    recent: api.requestsTo('/api/vulnerabilities/recent').length,
  }

  await page.getByRole('button', { name: '再読み込み' }).click()

  await expect.poll(() => api.requestsTo('/api/vulnerabilities/stats').length).toBe(before.stats + 1)
  await expect.poll(() => api.requestsTo('/api/vulnerabilities/recent').length).toBe(before.recent + 1)
  await expect(page.getByRole('table', { name: TABLE })).toBeVisible()
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

  // 一覧は表示されないが、画面は操作可能なまま
  await expect(page.getByRole('table', { name: TABLE })).toHaveCount(0)
  await expect(page.getByRole('textbox', { name: 'ベンダー名・製品名' })).toBeVisible()
  await expect(page.getByRole('button', { name: '再読み込み' })).toBeEnabled()
  // グラフは「データなし」
  await page.getByText('グラフ（ベンダー別・月別トレンド）を開く').click()
  await expect(page.getByText('データなし')).toHaveCount(2)
})

scenario('KEV-09', 'リクエストに公開用 X-API-KEY ヘッダーが付与される', async ({ page, api }) => {
  await page.goto('/')
  await expect(page.getByRole('table', { name: TABLE })).toBeVisible()
  // 「すべて」にすると、一覧APIも呼ばれる
  await showAll(page)

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
  await showAll(page)
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
  await showAll(page)
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

scenario('KEV-12', '期間（7日/30日/90日/すべて）を切り替えると、件数の帯と一覧が変わる', async ({ page, api }) => {
  await page.goto('/')
  const period = page.getByRole('group', { name: '期間フィルター' })
  const band = page.getByRole('group', { name: '件数の集計' })
  await expect(period.getByRole('button', { name: '30日' })).toHaveAttribute('aria-pressed', 'true')
  expect(api.lastQuery('/api/vulnerabilities/recent')?.get('days')).toBe('30')

  // 7日 → 8件（0〜7日前）。直近 N 日の API を、その日数で取得する
  await period.getByRole('button', { name: '7日' }).click()
  await expect(band.getByText('件が直近7日に追加')).toBeVisible()
  await expect(band.getByText('8', { exact: true })).toBeVisible()
  await expect(cveLinks(page)).toHaveCount(8)
  expect(api.lastQuery('/api/vulnerabilities/recent')?.get('days')).toBe('7')

  // 90日 → 全65件（2ページ）
  await period.getByRole('button', { name: '90日' }).click()
  await expect(band.getByText(String(KEV_TOTAL), { exact: true })).toBeVisible()
  await expect(page.getByRole('navigation', { name: 'ページ送り（下部）' })).toContainText('1 / 3')

  // すべて → 総件数と、EPSS 10%以上の件数（min_epss を指定した検索API）
  await period.getByRole('button', { name: 'すべて' }).click()
  await expect(band.getByText('件が登録済み')).toBeVisible()
  await expect(band.getByText(String(KEV_TOTAL), { exact: true })).toBeVisible()
  await expect(band.getByText('1', { exact: true })).toBeVisible()
  expect(api.requestsTo('/api/vulnerabilities').some((r) => r.query.get('min_epss') === '0.1')).toBe(true)
})

scenario('KEV-13', '一覧は追加日ごとに区切られる', async ({ page }) => {
  await page.goto('/')
  const table = page.getByRole('table', { name: TABLE })

  // モックは1日1件ずつ追加されているため、1ページ30件＝30日分の区切り。先頭は最新の日付
  const days = table.getByRole('row', { name: /に追加$/ })
  await expect(days).toHaveCount(30)
  await expect(days.first()).toHaveText('2026年9月20日')
  expect(kevItems[0].date_added).toBe('2026-09-20')
})

scenario('KEV-14', '自分のスタックのキーワードを登録すると、該当件数が出て、押すと絞り込まれる', async ({ page, api }) => {
  await page.goto('/')
  const group = page.getByRole('group', { name: '自分のスタックのキーワード' })
  await expect(page.getByText(/使っている製品名（例: Python・nginx）を追加すると/)).toBeVisible()

  await page.getByRole('textbox', { name: 'キーワードを追加' }).fill('cisco')
  await page.getByRole('textbox', { name: 'キーワードを追加' }).press('Enter')
  // 直近30日の 31 件のうち Cisco は 8 件。取得済みの期間内の一覧から数えるため、追加の通信はない
  await expect(group.getByRole('button', { name: /^cisco\s*\d+$/ })).toContainText('8')
  expect(api.requestsTo('/api/vulnerabilities')).toHaveLength(0)

  // 押すと、そのキーワードで一覧が絞られる。「すべて」で戻る
  await group.getByRole('button', { name: /^cisco\s*\d+$/ }).click()
  await expect(page.getByRole('textbox', { name: 'ベンダー名・製品名' })).toHaveValue('cisco')
  await expect(cveLinks(page)).toHaveCount(8)
  await group.getByRole('button', { name: /^すべて/ }).click()
  await expect(cveLinks(page)).toHaveCount(30)

  // ブラウザに保存され、再読み込みしても残る。0 件のキーワードは緑
  await page.reload()
  await expect(group.getByRole('button', { name: /^cisco\s*\d+$/ })).toBeVisible()
  await page.getByRole('textbox', { name: 'キーワードを追加' }).fill('nginx')
  await page.getByRole('textbox', { name: 'キーワードを追加' }).press('Enter')
  await expect(group.getByRole('button', { name: /^nginx\s*\d+$/ }).getByText('0')).toHaveClass(/text-emerald-400/)

  // 削除できる
  await group.getByRole('button', { name: 'nginxを削除' }).click()
  await expect(group.getByRole('button', { name: /^nginx/ })).toHaveCount(0)
})
