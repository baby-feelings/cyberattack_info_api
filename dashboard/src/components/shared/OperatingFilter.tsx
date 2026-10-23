import type { OperatingStatus } from '../../api/client'

// 運用中／運用停止中の切り替え（DEPSCAN・DEPSOPS・CODESCAN で共通）。
// 運用を止めたアプリ（バックエンドの INACTIVE_REPOS）の脆弱性が、運用中のものに混ざって
// 見にくくなるのを避けるため、分けて見られるようにする。表示名はポートフォリオと同じ
const OPTIONS: { value: OperatingStatus; label: string }[] = [
  { value: 'active', label: '運用中' },
  { value: 'inactive', label: '運用停止中' },
  { value: 'all', label: 'すべて' },
]

export function OperatingFilter({
  value, onChange,
}: { value: OperatingStatus; onChange: (next: OperatingStatus) => void }) {
  return (
    <div
      role="group"
      aria-label="運用状態フィルター"
      className="flex items-center gap-1 bg-slate-800/60 border border-slate-700 rounded-lg px-2.5 py-1.5"
    >
      <span className="text-[10px] text-slate-500 whitespace-nowrap">運用状態:</span>
      {OPTIONS.map(opt => (
        <button
          key={opt.value}
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
