import { useState, type ReactNode } from 'react'

// 見出しを押して開閉できる領域（グラフなど）。最初は開いていて、不要なときだけ閉じられる。
// 閉じている間は中身を描画しない（開いたときに、グラフが大きさ 0 で描かれて崩れるのを避けるため）
export function CollapsibleSection({ summary, children }: { summary: string; children: ReactNode }) {
  const [open, setOpen] = useState(true)
  return (
    <details
      open={open}
      onToggle={e => setOpen(e.currentTarget.open)}
      className="border-b border-slate-800 pb-3"
    >
      <summary className="cursor-pointer text-xs text-slate-500 hover:text-slate-300 select-none">
        {summary}
      </summary>
      {open && <div className="mt-3">{children}</div>}
    </details>
  )
}
