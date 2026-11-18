// CODESCAN（検知）の画面の、文言・色・既定値（画面は、これを読んで描くだけ）
export const SEVERITY_CLS: Record<string, string> = {
  ERROR: 'bg-red-500/15 text-red-400 border-red-500/30',
  WARNING: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  INFO: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
}

export const SEVERITIES = ['ALL', 'ERROR', 'WARNING', 'INFO']

// 重要度の表示ラベル。ERRORはシステムエラーと紛らわしいため日本語表記にする
export const SEVERITY_LABELS: Record<string, string> = {
  ERROR: '重大',
  WARNING: '警告',
  INFO: '情報',
}

// 解決状態の絞り込み（未解決・解決済み・全件）
export const RESOLVED_OPTIONS: { label: string; value: boolean | null }[] = [
  { label: '未解決', value: false },
  { label: '解決済み', value: true },
  { label: '全件', value: null },
]

export const TH = 'text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3'

export const CODESCAN_TEXT = {
  title: 'CODESCAN（Semgrep + Gitleaks + Zizmor + インフラ設定）',
  reload: '再読み込み',
  // CVSSはベストエフォート推定であることを明記（Issue #203の要件）
  note:
    'Semgrep（コードパターン診断）・Gitleaks（ハードコードされたシークレット検知）・'
    + 'Zizmor（GitHub Actionsのワークフロー設定の診断。未固定のアクション・過剰な権限など）の'
    + 'インフラ設定（FirebaseのルールやDockerfile・docker-composeの不備）の4つで検知します。'
    + 'CVSSスコアは検知結果（重要度・CWE）からのベストエフォート推定値であり、正式なCVSS評価に'
    + '代わるものではありません（Zizmor・インフラ設定の検知にはCVSSが付きません）。'
    + '7.0以上は赤バッジで強調表示します。',
  charts: 'グラフ（リポジトリ別）',
  resolvedGroup: '状態フィルター',
  resolvedLabel: '状態:',
  actionCriteria: '重大',
  excepted: (count: number, showExcepted: boolean) =>
    `例外（受容・影響なし など）に登録した未解決の ${count} 件は、「対応が必要」の件数には`
    + `含めていません。${showExcepted
      ? '一覧にも表示しています（「例外を含む」を外すと隠せます）。'
      : '一覧は非表示です（「例外を含む」で表示できます）。'}`
    + 'グラフと左のアプリ一覧では、灰色の「例外」として併記しています。',
  emptyHidden: (count: number) => `対応が必要なコード脆弱性はありません（例外 ${count} 件は非表示）`,
  empty: '該当するコード脆弱性はありません',
  tableLabel: 'コード脆弱性一覧',
  columns: {
    severity: '重要度', cvss: 'CVSS', repo: 'リポジトリ', file: 'ファイル:行', rule: 'ルール', detected: '検知日',
  },
} as const
