import { useState } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { PostureGroup } from './PostureGroup'
import { POSTURE_TEXT } from './postureConfig'

const GROUP_TEXT = POSTURE_TEXT.groups

// 「態勢」タブ。運用中と運用停止中を、2つの区画に分けて同時に表示する。
// 運用中は常に表示。運用停止中は折りたたみで、開いたときだけ取得する（運用中の確認に埋もれさせない）。
export function PosturePanel({ authToken }: { authToken: string }) {
  const [inactiveOpen, setInactiveOpen] = useState(false)
  const Chevron = inactiveOpen ? ChevronDown : ChevronRight

  return (
    <div className="flex flex-col gap-8">
      <section aria-label={GROUP_TEXT.active} className="flex flex-col gap-3">
        <h3 className="text-sm font-semibold text-white">{GROUP_TEXT.active}</h3>
        <PostureGroup authToken={authToken} operating="active" />
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
        {inactiveOpen && <PostureGroup authToken={authToken} operating="inactive" />}
      </section>
    </div>
  )
}
