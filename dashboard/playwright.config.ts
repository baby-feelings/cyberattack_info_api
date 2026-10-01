import { defineConfig, devices } from '@playwright/test'

// E2Eテスト用の開発サーバーポート。ローカルで起動中の `npm run dev`（5173）と
// 衝突しないよう専用ポートを使う。
const PORT = 5199
const ORIGIN = `http://localhost:${PORT}`

// ダッシュボードはビルド時の VITE_API_BASE_URL で API の向き先を決める。E2Eでは
// 同一オリジン配下の `/__api` に向け、Playwright の page.route で全リクエストを
// モックする（本番APIや APIキーに依存せず、CORS プリフライトも発生しない）。
export const API_BASE = `${ORIGIN}/__api`

// シナリオ網羅率の合格ライン（e2e/reporters/scenario-coverage-reporter.ts が判定）
const SCENARIO_COVERAGE_THRESHOLD = 0.9

export default defineConfig({
  testDir: './e2e',
  testMatch: '**/*.spec.ts',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: process.env.CI ? 2 : undefined,
  reporter: [
    ['list'],
    // HTMLレポート（playwright-report/index.html）。失敗時のトレース・スクリーンショット付き
    ['html', { open: 'never', outputFolder: 'playwright-report' }],
    // シナリオ網羅率レポート（playwright-report/scenario-coverage.html）。
    // htmlレポーターが出力先を作り直した後に書き込めるよう、必ずhtmlの後ろに置く
    ['./e2e/reporters/scenario-coverage-reporter.ts', {
      threshold: SCENARIO_COVERAGE_THRESHOLD,
      outputFile: 'playwright-report/scenario-coverage.html',
    }],
  ],
  use: {
    baseURL: ORIGIN,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    locale: 'ja-JP',
    timezoneId: 'Asia/Tokyo',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
  webServer: {
    command: `npx vite --port ${PORT} --strictPort`,
    url: ORIGIN,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    env: {
      VITE_API_BASE_URL: API_BASE,
      VITE_PUBLIC_API_KEY: 'e2e-public-key',
    },
  },
})
