import { CheckCircle2 } from 'lucide-react'

interface ActionSummaryProps {
  // 対応が必要な脆弱性の件数
  count: number
  // 「対応が必要」とみなす深刻度の説明（例: CRITICAL・HIGH）
  criteria: string
  // 未解決の総件数（補足として「N 件のうち」を出す。不明なら null）
  total: number | null
  loading: boolean
}

// 一覧の上に出す「いま対応が必要な脆弱性の件数」。画面を開いて最初に知りたい答えを、大きく見せる。
// 0 件のときは、安心して閉じられるよう、緑の完了表示にする
export function ActionSummary({ count, criteria, total, loading }: ActionSummaryProps) {
  if (loading) {
    return <div role="status" aria-label="集計中" className="h-12 w-64 rounded-lg bg-slate-800/60 animate-pulse" />
  }
  if (count === 0) {
    return (
      <div className="flex items-center gap-2 text-emerald-400">
        <CheckCircle2 size={22} />
        <span className="text-base font-semibold">対応が必要な脆弱性はありません</span>
        {total !== null && total > 0 && (
          <span className="text-xs text-slate-500">（未解決 {total} 件は、{criteria}以外）</span>
        )}
      </div>
    )
  }
  return (
    <div className="flex flex-wrap items-end gap-x-3 gap-y-1">
      <span className="text-4xl font-bold leading-none tabular-nums text-red-400">{count}</span>
      <span className="text-sm text-slate-300">件が対応必要（{criteria}）</span>
      {total !== null && (
        <span className="text-xs text-slate-500 tabular-nums">未解決 {total} 件のうち</span>
      )}
    </div>
  )
}
