import { expect, openTab, scenario, seedSession } from './support/test'

scenario('APP-01', '初期表示でヘッダー・KEVタブ・フッターが表示される', async ({ page }) => {
  await page.goto('/')

  await expect(page.getByText('サイバー攻撃情報ダッシュボード')).toBeVisible()
  await expect(page.getByRole('tab', { name: 'KEV', exact: true })).toHaveAttribute('aria-selected', 'true')
  await expect(page.getByRole('tabpanel', { name: 'KEV' })).toBeVisible()
  await expect(page.getByRole('heading', { name: /CISA KEV/ })).toBeVisible()
  await expect(page.getByText('JST 04:05 一括自動更新')).toBeVisible()
})

scenario('APP-02', '5つのタブが切り替わり対応するタブパネルが表示される', async ({ page }) => {
  await page.goto('/')

  const expectations = [
    { tab: 'OSV', heading: /OSV — Open Source Vulnerabilities/ },
    { tab: 'JVN', heading: /JVN — Japan Vulnerability Notes/ },
    { tab: 'DEPSCAN', heading: /DEPSCAN — 自作アプリの依存ライブラリ脆弱性/ },
    { tab: 'CODESCAN', heading: /CODESCAN — 自アプリのコード脆弱性診断/ },
    { tab: 'KEV', heading: /CISA KEV — Known Exploited Vulnerabilities/ },
  ] as const

  for (const { tab, heading } of expectations) {
    await openTab(page, tab)
    // 表示中のタブパネルは常に1つだけで、アクティブなタブに対応する
    await expect(page.getByRole('tabpanel')).toHaveCount(1)
    await expect(page.getByRole('tabpanel', { name: tab })).toBeVisible()
    await expect(page.getByRole('heading', { name: heading })).toBeVisible()
  }
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

scenario('APP-04', 'OAuthコールバック（?depscan_code）でDEPSCANタブが自動選択されログインされる', async ({ page, api }) => {
  await page.goto('/?depscan_code=one-time-code')

  await expect(page.getByRole('tab', { name: 'DEPSCAN', exact: true })).toHaveAttribute('aria-selected', 'true')
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

  await expect(page.getByRole('tab', { name: 'DEPSCAN', exact: true })).toHaveAttribute('aria-selected', 'true')
  await expect(page.getByText('GitHubアカウントでログインしてください')).toBeVisible()
  expect(await page.evaluate(() => localStorage.getItem('depscan_session_token'))).toBeNull()
})

scenario('APP-06', 'アクセシビリティツリー（ARIAスナップショット）がタブUIの意味構造を表す', async ({ page }) => {
  await page.goto('/')

  // セマンティクス: タブバーは tablist/tab として公開され、選択状態が伝わる
  await expect(page.getByRole('tablist')).toMatchAriaSnapshot(`
    - tablist:
      - tab "KEV" [selected]
      - tab "OSV"
      - tab "JVN"
      - tab "DEPSCAN"
      - tab "CODESCAN"
  `)
  await openTab(page, 'JVN')
  await expect(page.getByRole('tablist')).toMatchAriaSnapshot(`
    - tablist:
      - tab "KEV"
      - tab "OSV"
      - tab "JVN" [selected]
      - tab "DEPSCAN"
      - tab "CODESCAN"
  `)

  // タブとタブパネルは aria-controls / aria-labelledby で相互に関連付けられている
  await expect(page.getByRole('tab', { name: 'JVN', exact: true })).toHaveAttribute('aria-controls', 'tabpanel-jvn')
  await expect(page.getByRole('tabpanel', { name: 'JVN' })).toHaveAttribute('id', 'tabpanel-jvn')
  await expect(page.getByRole('banner')).toBeVisible()
  await expect(page.getByRole('main')).toBeVisible()
  await expect(page.getByRole('contentinfo')).toBeVisible()
})

scenario('APP-07', 'モバイル幅でもタブバーとコンテンツが操作できる', async ({ page }) => {
  await seedSession(page)
  await page.setViewportSize({ width: 375, height: 812 })
  await page.goto('/')

  await expect(page.getByRole('tab', { name: 'KEV', exact: true })).toBeVisible()
  await openTab(page, 'CODESCAN')
  await expect(page.getByRole('tabpanel', { name: 'CODESCAN' })).toBeVisible()

  // 横スクロールがページ全体に発生しない（テーブルは自身のコンテナ内でスクロールする）
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  )
  expect(overflow).toBeLessThanOrEqual(1)
})
