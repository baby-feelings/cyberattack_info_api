// OsvPanel・JvnPanel・KevPanel で共有する深刻度バッジ。
// 深刻度の値・配色はドメイン固有のため、呼び出し側から classMap として渡す。

export function SeverityBadge({
  severity, classMap,
}: {
  severity: string | null
  classMap: Record<string, string>
}) {
  const cls = severity
    ? (classMap[severity] ?? 'bg-slate-800 text-slate-400 border-slate-700')
    : 'bg-slate-800 text-slate-500 border-slate-700'
  return (
    <span className={`inline-block px-1.5 py-0.5 rounded border text-xs font-semibold whitespace-nowrap ${cls}`}>
      {severity ?? 'N/A'}
    </span>
  )
}
