// OsvPanel・JvnPanel・KevPanel で共有する深刻度バッジ。
// 深刻度の値・配色はドメイン固有のため、呼び出し側から classMap として渡す。

export function SeverityBadge({
  severity, classMap, labels,
}: {
  severity: string | null
  classMap: Record<string, string>
  // 表示用ラベル（例: CODESCANのERROR/WARNING/INFOを日本語表記にする場合）。
  // 未指定時は severity の値をそのまま表示する
  labels?: Record<string, string>
}) {
  const cls = severity
    ? (classMap[severity] ?? 'bg-slate-800 text-slate-400 border-slate-700')
    : 'bg-slate-800 text-slate-500 border-slate-700'
  const label = severity ? (labels?.[severity] ?? severity) : 'N/A'
  return (
    <span className={`inline-block px-1.5 py-0.5 rounded border text-xs font-semibold whitespace-nowrap ${cls}`}>
      {label}
    </span>
  )
}
