import {
  expect, test as base,
  type Page, type PlaywrightTestArgs, type PlaywrightTestOptions, type TestInfo,
} from '@playwright/test'
import { installMockApi, type MockApi } from './mockApi'
import type { ScenarioId } from './scenarios'

// 全E2Eテスト共通のフィクスチャ。
//  - api: バックエンドAPIのモック。{ auto: true } により、テストが引数に取らなくても
//    必ず有効化される（有効化されないと実サーバーに問い合わせてしまうため）
//  - ブラウザ内で未捕捉の例外（pageerror）が起きたらテストを失敗させる
export const test = base.extend<{ api: MockApi }>({
  api: [async ({ page }, use) => {
    const pageErrors: string[] = []
    page.on('pageerror', (error) => pageErrors.push(error.message))
    const api = await installMockApi(page)
    await use(api)
    expect(pageErrors, 'ブラウザ内で未捕捉の例外が発生した').toEqual([])
  }, { auto: true }],
})

type ScenarioArgs = PlaywrightTestArgs & PlaywrightTestOptions & { api: MockApi }

// シナリオカタログ（scenarios.ts）のIDに紐づけてテストを登録する。
// annotation にIDを載せ、シナリオ網羅率レポーターが集計に使う。
export function scenario(
  id: ScenarioId,
  title: string,
  body: (args: ScenarioArgs, testInfo: TestInfo) => Promise<void>,
) {
  test(`[${id}] ${title}`, { annotation: { type: 'scenario', description: id } }, body)
}

export { expect }
export type { Page }

// GitHubログイン済みのセッションを localStorage に仕込む
// （キー名は src/hooks/useGithubSession.ts と同じ。DEPSCAN/CODESCAN/設定で共有される）
export async function seedSession(
  page: Page, session: { token?: string; username?: string } = {},
) {
  const { token = 'test-session-token', username = 'octocat' } = session
  await page.addInitScript(([t, u]) => {
    localStorage.setItem('depscan_session_token', t)
    localStorage.setItem('depscan_session_user', u)
  }, [token, username])
}

// 下部固定タブバーのタブを選択する（タブは role=tab・名前＝タブ名）
export async function openTab(page: Page, name: 'KEV' | 'OSV' | 'JVN' | 'DEPSCAN' | 'CODESCAN') {
  await page.getByRole('tab', { name, exact: true }).click()
  await expect(page.getByRole('tab', { name, exact: true })).toHaveAttribute('aria-selected', 'true')
}

// ハンバーガーメニューから設定画面を開く
export async function openSettings(page: Page) {
  await page.getByRole('button', { name: 'メニュー' }).click()
  await page.getByRole('button', { name: '設定', exact: true }).click()
  await expect(page.getByRole('heading', { name: '設定' })).toBeVisible()
}
