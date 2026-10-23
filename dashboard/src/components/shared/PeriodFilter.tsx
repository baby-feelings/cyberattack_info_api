// 期間の選択肢。value が null のときは「期間を絞らない（すべて）」
export interface PeriodOption {
  value: number | null
  label: string
}

// KEV・OSV・JVN 共通の期間切り替え（直近 N 日）。新しく出た脆弱性を先に見られるようにする
export function PeriodFilter({
  value, options, onChange,
}: {
  value: number | null
  options: PeriodOption[]
  onChange: (next: number | null) => void
}) {
  return (
    <div
      role="group"
      aria-label="期間フィルター"
      className="flex items-center gap-1 bg-slate-800/60 border border-slate-700 rounded-lg px-2.5 py-1.5"
    >
      <span className="text-[10px] text-slate-500 whitespace-nowrap">期間:</span>
      {options.map(opt => (
        <button
          key={opt.label}
          onClick={() => onChange(opt.value)}
          aria-pressed={value === opt.value}
          className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${
            value === opt.value
              ? 'bg-violet-600 text-white'
              : 'text-slate-400 hover:text-slate-300'
          }`}
        >
          {opt.label}
        </button>
      ))}
    </div>
  )
}
