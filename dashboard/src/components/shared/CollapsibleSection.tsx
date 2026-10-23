import { useState, type ReactNode } from 'react'

// 初期は畳んでおき、押すと開く領域（グラフなど、一覧より優先度の低い情報用）。
// 閉じている間は中身を描画しない（グラフが大きさ 0 で描かれて崩れるのを避けるため）
export function CollapsibleSection({ summary, children }: { summary: string; children: ReactNode }) {
  const [open, setOpen] = useState(false)
  return (
    <details
      onToggle={e => setOpen(e.currentTarget.open)}
      className="border-t border-slate-800 pt-3"
    >
      <summary className="cursor-pointer text-xs text-slate-500 hover:text-slate-300 select-none">
        {summary}
      </summary>
      {open && <div className="mt-3">{children}</div>}
    </details>
  )
}
