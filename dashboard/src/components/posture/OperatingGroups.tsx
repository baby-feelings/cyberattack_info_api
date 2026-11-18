import { useState, type ReactNode } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'
import type { OperatingStatus } from '../../api/client'
import { POSTURE_TEXT } from './postureConfig'

const GROUP_TEXT = POSTURE_TEXT.groups

// 運用中と運用停止中を、2つの区画に分けて同時に表示する枠。
// 運用中は常に表示。運用停止中は折りたたみで、開いたときだけ描く（＝呼び出し側は、そのときだけ取得する）。
// 中身は、運用状態を受け取る関数 render が描く（アラート・設定の監査・外形監視など、画面ごとに差し替える）。
export function OperatingGroups({ render }: {
  render: (operating: Extract<OperatingStatus, 'active' | 'inactive'>) => ReactNode
}) {
  const [inactiveOpen, setInactiveOpen] = useState(false)
  const Chevron = inactiveOpen ? ChevronDown : ChevronRight

  return (
    <div className="flex flex-col gap-8">
      <section aria-label={GROUP_TEXT.active} className="flex flex-col gap-3">
        <h3 className="text-sm font-semibold text-white">{GROUP_TEXT.active}</h3>
        {render('active')}
      </section>

      <section aria-label={GROUP_TEXT.inactive} className="flex flex-col gap-3">
        <button
          type="button"
          onClick={() => setInactiveOpen((open) => !open)}
          aria-expanded={inactiveOpen}
          className="flex items-center gap-2 text-left text-sm font-semibold text-slate-300 hover:text-white"
        >
          <Chevron size={16} aria-hidden="true" />
          {GROUP_TEXT.inactive}
          <span className="text-[11px] font-normal text-slate-500">
            {inactiveOpen ? GROUP_TEXT.close : GROUP_TEXT.inactiveHint}
          </span>
        </button>
        {inactiveOpen && render('inactive')}
      </section>
    </div>
  )
}
