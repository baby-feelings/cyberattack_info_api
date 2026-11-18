// KEV の画面の、文言・既定値（画面は、これを読んで描くだけ）
export const TH = 'text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3'

export const KEV_TEXT = {
  title: 'CISA KEV — 悪用が確認された脆弱性',
  reload: '再読み込み',
  charts: 'グラフ（ベンダー別・月別トレンド）',
  monthlyTitle: '月別 CVE 追加数トレンド（6ヶ月）',
  searchPlaceholder: 'ベンダー名・製品名',
  // 期間の表示（全期間は「登録済み」）
  periodLabel: (period: number | null) => (period === null ? '登録済み' : `直近${period}日に追加`),
  addedInPeriod: (periodLabel: string) => `件が${periodLabel}`,
  epssHigh: '件は悪用されやすい（EPSS 10%以上）',
  empty: '該当する CVE はありません',
  tableLabel: 'KEV 脆弱性一覧',
  columns: {
    cve: 'CVE ID', epss: 'EPSS', vendor: 'ベンダー', product: '製品', name: '脆弱性名', added: '追加日',
  },
} as const
