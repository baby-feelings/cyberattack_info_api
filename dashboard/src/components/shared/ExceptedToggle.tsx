import { Eye, EyeOff } from 'lucide-react'

// 例外（受容・影響なし・誤検知）にした検知を、一覧に含めるかの切り替え（DEPSCAN・CODESCAN で共通）。
// 初期表示は「含めない」（本当に対応が必要な検知だけを見せるため）。例外の件数が分かるときは添える
export function ExceptedToggle({
  active, onToggle, count,
}: { active: boolean; onToggle: () => void; count?: number }) {
  const Icon = active ? Eye : EyeOff
  return (
    <button
      onClick={onToggle}
      aria-pressed={active}
      className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
        active
          ? 'bg-slate-600/30 text-slate-200 border-slate-500/50'
          : 'bg-slate-800/60 text-slate-500 border-slate-700 hover:text-slate-300'
      }`}
    >
      <Icon size={12} />
      例外を含む{count !== undefined && count > 0 ? `（${count}）` : ''}
    </button>
  )
}
