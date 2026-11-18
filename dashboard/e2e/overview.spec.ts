import { expect, openTab, scenario, seedSession } from './support/test'

scenario('OVW-01', '最初に開くタブが概要で、未ログインならログイン案内が出る', async ({ page }) => {
  await page.goto('/')

  await expect(page.getByRole('tab', { name: '概要', exact: true })).toHaveAttribute('aria-selected', 'true')
  await expect(page.getByText('GitHubアカウントでログインしてください')).toBeVisible()
  await expect(page.getByText('ログインすると、あなたのリポジトリの、対応が必要な件数をまとめて確認できます')).toBeVisible()
})

scenario('OVW-02', 'ログイン済みで指標の件数が出て、取得できなかった指標だけ「不明」と出る', async ({ page, api }) => {
  await seedSession(page)
  // 対応期限の取得だけ失敗させる
  api.override('GET', '/api/sla', () => ({ status: 500, body: { detail: 'error' } }))
  await page.goto('/')

  const card = (name: RegExp) => page.getByRole('button', { name })
  await expect(card(/対応期限を超過/)).toContainText('不明')
  await expect(card(/未解決の脆弱性/)).toContainText(/\d+ 件/)
  await expect(card(/リポジトリ設定の達成率/)).toContainText('%')
  expect(api.lastQuery('/api/depscan/stats')?.get('operating')).toBe('active')
})

scenario('OVW-03', 'カードを押すと、該当のタブ・小タブが開く', async ({ page }) => {
  await seedSession(page)
  await page.goto('/')

  await page.getByRole('button', { name: /リポジトリ設定の達成率/ }).click()
  await expect(page.getByRole('tab', { name: 'コードと設定', exact: true })).toHaveAttribute('aria-selected', 'true')
  await expect(page.getByRole('tab', { name: '設定の監査', exact: true })).toHaveAttribute('aria-selected', 'true')

  // 概要へ戻って、別のカードも押せる
  await openTab(page, '概要')
  await page.getByRole('button', { name: /問題のある公開サイト/ }).click()
  await expect(page.getByRole('tab', { name: '運用', exact: true })).toHaveAttribute('aria-selected', 'true')
})
