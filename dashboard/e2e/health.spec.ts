import { expect, scenario } from './support/test'

scenario('HLT-01', '正常時に OK・DB接続正常・本番環境が表示される', async ({ page }) => {
  await page.goto('/')

  await expect(page.getByText('サーバー稼働状況')).toBeVisible()
  await expect(page.getByText('OK', { exact: true })).toBeVisible()
  await expect(page.getByText('正常', { exact: true })).toBeVisible()
  await expect(page.getByText('本番環境')).toBeVisible()
  await expect(page.getByText(/最終確認:/)).toBeVisible()
})

scenario('HLT-02', 'degraded かつ DB 未接続のときエラー表示になる', async ({ page, api }) => {
  api.state.health = { status: 'degraded', environment: 'production', db_connected: false }
  await page.goto('/')

  await expect(page.getByText('DEGRADED', { exact: true })).toBeVisible()
  await expect(page.getByText('エラー', { exact: true })).toBeVisible()
})

scenario('HLT-03', 'APIが到達不能のとき UNREACHABLE が表示される', async ({ page, api }) => {
  api.override('GET', '/health', () => ({ status: 503, body: { detail: 'down' } }))
  await page.goto('/')

  await expect(page.getByText('UNREACHABLE')).toBeVisible()
})

scenario('HLT-04', '再確認ボタンで /health を再取得し状態が更新される', async ({ page, api }) => {
  // 障害中は500、復旧後は既定（正常）のレスポンスに戻す
  // （開発モードのStrictModeで初回取得が複数回走るため、回数ではなくフラグで切り替える）
  let down = true
  api.override('GET', '/health', () => (down ? { status: 500, body: null } : undefined))
  await page.goto('/')
  await expect(page.getByText('UNREACHABLE')).toBeVisible()
  const callsBeforeRecheck = api.requestsTo('/health').length

  down = false
  await page.getByRole('button', { name: '再確認' }).click()

  await expect(page.getByText('OK', { exact: true })).toBeVisible()
  expect(api.requestsTo('/health')).toHaveLength(callsBeforeRecheck + 1)
})

scenario('HLT-05', '開発環境の表記（development）が日本語化される', async ({ page, api }) => {
  api.state.health = { status: 'ok', environment: 'development', db_connected: true }
  await page.goto('/')

  await expect(page.getByText('開発環境')).toBeVisible()
})
