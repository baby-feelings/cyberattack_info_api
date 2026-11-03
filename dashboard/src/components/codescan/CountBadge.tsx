// 左のアプリ一覧の件数。対応が必要な件数に、例外（受容・影響なし など）の件数を灰色で併記する
export function CountBadge({ count, excepted, muted = false }: { count: number; excepted: number; muted?: boolean }) {
  return (
    <span className="tabular-nums">
      <span className={muted ? 'text-slate-500' : 'text-slate-300'}>{count}</span>
      {excepted > 0 && (
        <span className="ml-1 text-[10px] text-slate-500" title="例外（受容・影響なし など）">+{excepted}</span>
      )}
    </span>
  )
}
