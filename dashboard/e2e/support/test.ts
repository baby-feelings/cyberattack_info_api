import {
  expect, test as base,
  type Locator, type Page, type PlaywrightTestArgs, type PlaywrightTestOptions, type TestInfo,
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

// 表の「データ行」（日付の区切り行を除く）。区切りが入る一覧（KEV・OSV・CODESCAN）で行数や位置を見るときに使う
export const dataRows = (table: Locator) => table.locator('tr:not([data-divider])')
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
export async function openTab(page: Page, name: '概要' | '公開情報' | '依存ライブラリ' | 'コードと設定' | '運用') {
  await page.getByRole('tab', { name, exact: true }).click()
  await expect(page.getByRole('tab', { name, exact: true })).toHaveAttribute('aria-selected', 'true')
}

// 「公開情報」タブを開き、小タブ（KEV / OSV）を選ぶ
export async function openPublic(page: Page, sub: 'KEV' | 'OSV') {
  await openTab(page, '公開情報')
  const subTab = page.getByRole('tablist', { name: '小タブ' }).getByRole('tab', { name: sub, exact: true })
  await subTab.click()
  await expect(subTab).toHaveAttribute('aria-selected', 'true')
}

// 「依存ライブラリ」タブを開き、小タブを選ぶ（省略は、先頭の「検知」のまま）
export type DependenciesSubTab = '検知' | '対応状況' | 'Dependabot運用' | '依存パッケージ' | '言語・実行環境' | 'アラート'
export async function openDependencies(page: Page, sub?: DependenciesSubTab) {
  await openTab(page, '依存ライブラリ')
  if (!sub) return
  const subTab = page.getByRole('tablist', { name: '小タブ' }).getByRole('tab', { name: sub, exact: true })
  await subTab.click()
  await expect(subTab).toHaveAttribute('aria-selected', 'true')
}

// 「コードと設定」タブを開き、小タブを選ぶ（省略は、先頭の「検知」のまま）
export type CodeSubTab = '検知' | 'アラート' | '設定の監査'
export async function openCode(page: Page, sub?: CodeSubTab) {
  await openTab(page, 'コードと設定')
  if (!sub) return
  const subTab = page.getByRole('tablist', { name: '小タブ' }).getByRole('tab', { name: sub, exact: true })
  await subTab.click()
  await expect(subTab).toHaveAttribute('aria-selected', 'true')
}

// ハンバーガーメニューから設定画面を開く
export async function openSettings(page: Page) {
  await page.getByRole('button', { name: 'メニュー' }).click()
  await page.getByRole('button', { name: '設定', exact: true }).click()
  await expect(page.getByRole('heading', { name: '設定', exact: true })).toBeVisible()
}
