export type DepscanSort = 'severity' | 'date'

const OPTIONS: { value: DepscanSort; label: string }[] = [
  { value: 'severity', label: '重要度' },
  { value: 'date', label: '検知日' },
]

// 一覧の並び順の切り替え。既定は重要度順（対応が必要なものが上）。
// 検知日順にすると、検知した日ごとに区切って表示する
export function DepscanSortSelector({
  value, onChange,
}: {
  value: DepscanSort
  onChange: (sort: DepscanSort) => void
}) {
  return (
    <div role="group" aria-label="並び順" className="flex items-center gap-1 bg-slate-800/60 border border-slate-700 rounded-lg px-2.5 py-1.5">
      <span className="text-[10px] text-slate-500 whitespace-nowrap">並び順:</span>
      {OPTIONS.map(opt => (
        <button
          key={opt.value}
          onClick={() => onChange(opt.value)}
          aria-pressed={value === opt.value}
          className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${
            value === opt.value ? 'bg-violet-600 text-white' : 'text-slate-400 hover:text-slate-300'
          }`}
        >
          {opt.label}
        </button>
      ))}
    </div>
  )
}
