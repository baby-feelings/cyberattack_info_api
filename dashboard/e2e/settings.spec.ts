import { expect, openSettings, scenario, seedSession } from './support/test'
import { API_PREFIX } from './support/mockApi'

const WEBHOOK = 'https://hooks.slack.com/services/T000/B000/XXXXXXXX'

scenario('SET-01', 'メニュー→設定で開き、未ログイン時はログイン案内が表示される', async ({ page, api }) => {
  await page.goto('/')
  await openSettings(page)

  const dialog = page.getByRole('dialog', { name: '設定' })
  await expect(dialog.getByText('Slack通知の登録にはGitHubアカウントでのログインが必要です。')).toBeVisible()
  await expect(dialog.getByRole('link', { name: 'GitHubでログイン' }))
    .toHaveAttribute('href', `${new URL(page.url()).origin}${API_PREFIX}/auth/github/login`)
  // メニューは設定を開くと閉じる。未ログインでは設定APIを呼ばない
  await expect(page.getByRole('button', { name: 'メニュー' })).toHaveAttribute('aria-expanded', 'false')
  expect(api.requestsTo('/auth/notification-settings')).toHaveLength(0)
})

scenario('SET-02', '閉じるボタン・背景クリックで閉じられる', async ({ page }) => {
  await page.goto('/')
  const dialog = page.getByRole('dialog', { name: '設定' })

  await openSettings(page)
  await dialog.getByRole('button', { name: '閉じる' }).click()
  await expect(dialog).toBeHidden()

  await openSettings(page)
  // ダイアログ内のクリックでは閉じない
  await dialog.getByRole('heading', { name: '設定' }).click()
  await expect(dialog).toBeVisible()
  // 背景（ダイアログの外側）をクリックすると閉じる
  await page.getByTestId('settings-backdrop').click({ position: { x: 5, y: 5 } })
  await expect(dialog).toBeHidden()
})

scenario('SET-03', 'ログイン済みで既存の登録URLが読み込まれる', async ({ page, api }) => {
  api.state.notification = { slack_webhook_url: WEBHOOK, notifications_enabled: true }
  await seedSession(page)
  await page.goto('/')
  await openSettings(page)

  const dialog = page.getByRole('dialog', { name: '設定' })
  await expect(dialog.getByLabel('Slack Incoming Webhook URL')).toHaveValue(WEBHOOK)
  await expect(dialog.getByText(/octocat さん自身のGitHubリポジトリ/)).toBeVisible()
  await expect(dialog.getByRole('button', { name: '登録解除' })).toBeVisible()
  expect(api.requestsTo('/auth/notification-settings')[0].headers['authorization'])
    .toBe('Bearer test-session-token')
})

scenario('SET-04', 'Webhook URLを保存すると成功メッセージが表示される', async ({ page, api }) => {
  await seedSession(page)
  await page.goto('/')
  await openSettings(page)
  const dialog = page.getByRole('dialog', { name: '設定' })

  await expect(dialog.getByRole('button', { name: '登録解除' })).toHaveCount(0)
  await dialog.getByLabel('Slack Incoming Webhook URL').fill(`  ${WEBHOOK}  `)
  await dialog.getByRole('button', { name: 'テスト送信して保存' }).click()

  await expect(dialog.getByText('テスト送信に成功し、登録しました。')).toBeVisible()
  // 前後の空白は取り除いて送信される
  const [put] = api.requestsTo('/auth/notification-settings', 'PUT')
  expect(put.body).toEqual({ slack_webhook_url: WEBHOOK })
  expect(put.headers['authorization']).toBe('Bearer test-session-token')
  // 登録後は「登録解除」が使えるようになる
  await expect(dialog.getByRole('button', { name: '登録解除' })).toBeVisible()
})

scenario('SET-05', '保存失敗時にサーバーのエラー詳細が表示される', async ({ page, api }) => {
  api.override('PUT', '/auth/notification-settings', () => ({
    status: 400, body: { detail: 'Slackへのテスト送信に失敗しました' },
  }))
  await seedSession(page)
  await page.goto('/')
  await openSettings(page)
  const dialog = page.getByRole('dialog', { name: '設定' })

  await dialog.getByLabel('Slack Incoming Webhook URL').fill(WEBHOOK)
  await dialog.getByRole('button', { name: 'テスト送信して保存' }).click()

  await expect(dialog.getByText('Slackへのテスト送信に失敗しました')).toBeVisible()
  await expect(dialog.getByText('テスト送信に成功し、登録しました。')).toHaveCount(0)
  await expect(dialog.getByRole('button', { name: '登録解除' })).toHaveCount(0)
  // 失敗しても再試行できるよう、保存ボタンは押せる状態に戻る
  await expect(dialog.getByRole('button', { name: 'テスト送信して保存' })).toBeEnabled()
})

scenario('SET-06', '登録解除でURLがクリアされる', async ({ page, api }) => {
  api.state.notification = { slack_webhook_url: WEBHOOK, notifications_enabled: true }
  await seedSession(page)
  await page.goto('/')
  await openSettings(page)
  const dialog = page.getByRole('dialog', { name: '設定' })

  await dialog.getByRole('button', { name: '登録解除' }).click()

  await expect(dialog.getByLabel('Slack Incoming Webhook URL')).toHaveValue('')
  await expect(dialog.getByRole('button', { name: '登録解除' })).toHaveCount(0)
  expect(api.requestsTo('/auth/notification-settings', 'DELETE')).toHaveLength(1)
  expect(api.state.notification.slack_webhook_url).toBeNull()
})

scenario('SET-07', '入力が空の間は保存ボタンが無効', async ({ page }) => {
  await seedSession(page)
  await page.goto('/')
  await openSettings(page)
  const dialog = page.getByRole('dialog', { name: '設定' })
  const save = dialog.getByRole('button', { name: 'テスト送信して保存' })
  const input = dialog.getByLabel('Slack Incoming Webhook URL')

  await expect(save).toBeDisabled()
  await input.fill('   ')
  await expect(save).toBeDisabled()
  await input.fill(WEBHOOK)
  await expect(save).toBeEnabled()
  await input.fill('')
  await expect(save).toBeDisabled()
})

scenario('SET-08', '設定の取得失敗時にエラーメッセージが表示される', async ({ page, api }) => {
  api.override('GET', '/auth/notification-settings', () => ({ status: 500, body: { detail: 'boom' } }))
  await seedSession(page)
  await page.goto('/')
  await openSettings(page)
  const dialog = page.getByRole('dialog', { name: '設定' })

  await expect(dialog.getByText('通知設定の取得に失敗しました')).toBeVisible()
  // フォーム自体は表示され、新規登録は試せる
  await expect(dialog.getByLabel('Slack Incoming Webhook URL')).toBeVisible()
})

scenario('SET-09', '設定画面からのログアウト', async ({ page }) => {
  await seedSession(page)
  await page.goto('/')
  await openSettings(page)
  const dialog = page.getByRole('dialog', { name: '設定' })

  page.once('dialog', (confirm) => void confirm.accept())
  await dialog.getByRole('button', { name: 'ログアウト' }).click()

  await expect(dialog.getByText('Slack通知の登録にはGitHubアカウントでのログインが必要です。')).toBeVisible()
  expect(await page.evaluate(() => localStorage.getItem('depscan_session_token'))).toBeNull()
})

scenario('SET-10', 'MCPトークンを発行すると登録コマンドと有効期限が表示される', async ({ page, api }) => {
  await seedSession(page)
  await page.goto('/')
  await openSettings(page)
  const dialog = page.getByRole('dialog', { name: '設定' })

  // 発行前はコマンドを表示しない
  await expect(dialog.getByLabel('Claude Code に登録するコマンド')).toHaveCount(0)
  await dialog.getByRole('button', { name: 'MCPトークンを発行' }).click()

  const command = dialog.getByLabel('Claude Code に登録するコマンド')
  await expect(command).toHaveValue(/claude mcp add --transport http cyberattack-info .*\/mcp /)
  await expect(command).toHaveValue(/Authorization: Bearer mcp-test-token/)
  await expect(dialog.getByText('有効期限: 2026-11-08')).toBeVisible()
  await expect(dialog.getByText('このトークンは再表示できません。', { exact: false })).toBeVisible()
  // ログイン中のセッショントークンで発行を要求する
  const [req] = api.requestsTo('/auth/mcp-token', 'POST')
  expect(req.headers['authorization']).toBe('Bearer test-session-token')
  await expect(dialog.getByRole('button', { name: 'トークンを再発行' })).toBeVisible()
})

scenario('SET-11', 'MCPトークンの発行に失敗するとエラーが表示される', async ({ page, api }) => {
  api.override('POST', '/auth/mcp-token', () => ({ status: 500, body: { detail: 'boom' } }))
  await seedSession(page)
  await page.goto('/')
  await openSettings(page)
  const dialog = page.getByRole('dialog', { name: '設定' })

  await dialog.getByRole('button', { name: 'MCPトークンを発行' }).click()

  await expect(dialog.getByText('トークンの発行に失敗しました')).toBeVisible()
  await expect(dialog.getByLabel('Claude Code に登録するコマンド')).toHaveCount(0)
})
