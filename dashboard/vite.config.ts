/// <reference types="vitest/config" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    globals: true,
    css: false,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      // include を指定すると、テストが一切 import しないファイルもレポートに
      // 含まれる（未着手箇所を可視化するため）
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/main.tsx', 'src/vite-env.d.ts', 'src/test/**', '**/*.test.{ts,tsx}'],
      // バックエンド（pytest --cov-fail-under=90）に合わせ、プロジェクト全体で
      // 90%を下回ったらテスト失敗にする（ファイル単位のしきい値ではない。
      // RepoBarChart.tsx の recharts tooltip formatter 等、jsdom では現実的に
      // 到達できない分岐が一部あるため）
      thresholds: {
        statements: 90,
        lines: 90,
        functions: 85,
        branches: 85,
      },
    },
  },
})
