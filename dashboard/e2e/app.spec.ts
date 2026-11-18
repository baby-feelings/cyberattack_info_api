import { expect, openPublic, openTab, scenario, seedSession } from './support/test'

scenario('APP-01', '初期表示でヘッダー・KEVタブ・フッターが表示される', async ({ page }) => {
  await page.goto('/')

  await expect(page.getByText('サイバー攻撃情報ダッシュボード')).toBeVisible()
  // 最初のタブは「公開情報」で、その中の先頭の小タブは KEV
  await expect(page.getByRole('tab', { name: '公開情報', exact: true })).toHaveAttribute('aria-selected', 'true')
  await expect(page.getByRole('tab', { name: 'KEV', exact: true })).toHaveAttribute('aria-selected', 'true')
  await expect(page.getByRole('tabpanel', { name: 'KEV' })).toBeVisible()
  await expect(page.getByRole('heading', { name: /CISA KEV/ })).toBeVisible()
  await expect(page.getByText('毎日 JST 00:00〜00:55 に自動更新')).toBeVisible()
})

scenario('APP-02', '4つのタブが切り替わり対応するタブパネルが表示される', async ({ page }) => {
  await page.goto('/')

  const expectations = [
    { tab: '依存ライブラリ', heading: /DEPSCAN — 自作アプリの依存ライブラリ脆弱性/ },
    { tab: 'コードと設定', heading: /CODESCAN — 自アプリのコード脆弱性診断/ },
    { tab: '公開情報', heading: /CISA KEV — Known Exploited Vulnerabilities/ },
    { tab: '運用', heading: /運用 — 公開サイトの外形監視/ },
  ] as const

  for (const { tab, heading } of expectations) {
    await openTab(page, tab)
    // 表示中のタブパネル（タブバーに対応するもの）は常に1つだけで、アクティブなタブに対応する
    await expect(page.locator('[role="tabpanel"][id^="tabpanel-"]')).toHaveCount(1)
    await expect(page.getByRole('tabpanel', { name: tab, exact: true })).toBeVisible()
    await expect(page.getByRole('heading', { name: heading })).toBeVisible()
  }
})

scenario('APP-09', '公開情報の小タブ（KEV・OSV）を切り替えられ、他のタブへ移って戻っても選択が残る', async ({ page }) => {
  await page.goto('/')

  await openPublic(page, 'OSV')
  await expect(page.getByRole('heading', { name: /OSV — Open Source Vulnerabilities/ })).toBeVisible()
  await expect(page.getByRole('table', { name: 'OSV 脆弱性一覧' })).toBeVisible()

  // 別のタブへ移って戻ると、直前の小タブ（OSV）が復元される
  await openTab(page, '依存ライブラリ')
  await openTab(page, '公開情報')
  await expect(page.getByRole('tab', { name: 'OSV', exact: true })).toHaveAttribute('aria-selected', 'true')
  await expect(page.getByRole('heading', { name: /OSV — Open Source Vulnerabilities/ })).toBeVisible()

  await openPublic(page, 'KEV')
  await expect(page.getByRole('heading', { name: /CISA KEV/ })).toBeVisible()
})

scenario('APP-03', 'ハンバーガーメニューの開閉（外側クリック・Escapeで閉じる）', async ({ page }) => {
  await page.goto('/')
  const menuButton = page.getByRole('button', { name: 'メニュー' })

  await expect(menuButton).toHaveAttribute('aria-expanded', 'false')
  await menuButton.click()
  await expect(menuButton).toHaveAttribute('aria-expanded', 'true')
  await expect(page.getByRole('button', { name: '設定', exact: true })).toBeVisible()

  // メニュー外（全画面の透明オーバーレイ）をクリックすると閉じる
  await page.mouse.click(5, 300)
  await expect(menuButton).toHaveAttribute('aria-expanded', 'false')
  await expect(page.getByRole('button', { name: '設定', exact: true })).toBeHidden()

  // Escapeキーでも閉じる
  await menuButton.click()
  await expect(menuButton).toHaveAttribute('aria-expanded', 'true')
  await page.keyboard.press('Escape')
  await expect(menuButton).toHaveAttribute('aria-expanded', 'false')
})

scenario('APP-04', 'OAuthコールバック（?depscan_code）で依存ライブラリタブが自動選択されログインされる', async ({ page, api }) => {
  await page.goto('/?depscan_code=one-time-code')

  await expect(page.getByRole('tab', { name: '依存ライブラリ', exact: true })).toHaveAttribute('aria-selected', 'true')
  await expect(page.getByText('ログイン中:')).toBeVisible()
  await expect(page.getByText('octocat', { exact: true })).toBeVisible()

  // 交換コードがPOSTされ、取得したセッショントークンが保存される
  const exchange = api.requestsTo('/auth/exchange', 'POST')
  expect(exchange).toHaveLength(1)
  expect(exchange[0].body).toEqual({ code: 'one-time-code' })
  expect(await page.evaluate(() => localStorage.getItem('depscan_session_token'))).toBe('exchanged-token')

  // リロード時の再送信を防ぐため、交換コードはURLから取り除かれる
  expect(new URL(page.url()).search).toBe('')
})

scenario('APP-05', 'OAuth交換コードが無効ならログイン画面のまま', async ({ page, api }) => {
  api.override('POST', '/auth/exchange', () => ({ status: 400, body: { detail: 'invalid code' } }))
  await page.goto('/?depscan_code=expired-code')

  await expect(page.getByRole('tab', { name: '依存ライブラリ', exact: true })).toHaveAttribute('aria-selected', 'true')
  await expect(page.getByText('GitHubアカウントでログインしてください')).toBeVisible()
  expect(await page.evaluate(() => localStorage.getItem('depscan_session_token'))).toBeNull()
})

scenario('APP-06', 'アクセシビリティツリー（ARIAスナップショット）がタブUIの意味構造を表す', async ({ page }) => {
  await page.goto('/')

  // セマンティクス: タブバーは tablist/tab として公開され、選択状態が伝わる
  const mainTabs = page.locator('nav').getByRole('tablist')
  await expect(mainTabs).toMatchAriaSnapshot(`
    - tablist:
      - tab "公開情報" [selected]
      - tab "依存ライブラリ"
      - tab "コードと設定"
      - tab "運用"
  `)
  await openTab(page, '依存ライブラリ')
  await expect(mainTabs).toMatchAriaSnapshot(`
    - tablist:
      - tab "公開情報"
      - tab "依存ライブラリ" [selected]
      - tab "コードと設定"
      - tab "運用"
  `)

  // タブとタブパネルは aria-controls / aria-labelledby で相互に関連付けられている
  await expect(page.getByRole('tab', { name: '依存ライブラリ', exact: true })).toHaveAttribute('aria-controls', 'tabpanel-dependencies')
  await expect(page.getByRole('tabpanel', { name: '依存ライブラリ', exact: true })).toHaveAttribute('id', 'tabpanel-dependencies')
  await expect(page.getByRole('banner')).toBeVisible()
  await expect(page.getByRole('main')).toBeVisible()
  await expect(page.getByRole('contentinfo')).toBeVisible()
})

scenario('APP-07', 'モバイル幅でもタブバーとコンテンツが操作できる', async ({ page }) => {
  await seedSession(page)
  await page.setViewportSize({ width: 375, height: 812 })
  await page.goto('/')

  await expect(page.getByRole('tab', { name: '公開情報', exact: true })).toBeVisible()
  await openTab(page, 'コードと設定')
  await expect(page.getByRole('tabpanel', { name: 'コードと設定', exact: true })).toBeVisible()

  // 横スクロールがページ全体に発生しない（テーブルは自身のコンテナ内でスクロールする）
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  )
  expect(overflow).toBeLessThanOrEqual(1)
})

scenario('APP-08', '下部のタブの横幅が均等で、タブバー全体を使い切る', async ({ page }) => {
  await page.goto('/')

  const mainTabs = page.locator('nav').getByRole('tablist')
  const tabs = mainTabs.getByRole('tab')
  const boxes = await tabs.evaluateAll((els) => els.map((el) => el.getBoundingClientRect()))
  const list = await mainTabs.evaluate((el) => el.getBoundingClientRect().width)

  // 幅がそろっている（小数の丸めを許す）
  const widths = boxes.map((b) => b.width)
  expect(Math.max(...widths) - Math.min(...widths)).toBeLessThan(1)
  // 隙間なく並び、タブの合計がタブバーの幅に一致する（右側が空かない）
  expect(widths.reduce((sum, w) => sum + w, 0)).toBeCloseTo(list, 0)
})
