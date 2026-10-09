import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([
  // coverage・playwright-report は生成物のため lint 対象外
  globalIgnores(['dist', 'coverage', 'playwright-report']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      globals: globals.browser,
    },
    rules: {
      // 下記2つは React の描画性能・開発時ホットリロード向けのルールで、バグや脆弱性の検出ではない。
      // 既存コード（各パネルの「effect 内でのデータ取得」等）に多数あり、挙動を変えずに一括で
      // 書き直すのはリスクが大きいため warn に下げ、件数の上限を package.json の lint で固定する
      // （--max-warnings。新たな違反を増やさないための歯止め。減らしたら上限も下げること）
      'react-hooks/set-state-in-effect': 'warn',
      'react-refresh/only-export-components': 'warn',
    },
  },
])
