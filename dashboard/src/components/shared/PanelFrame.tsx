import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'

// 画面の中に置くパネルの共通の殻（見出し行＋本文）。
// 以前は `FullScreenModal`（全画面を覆うモーダル）で表示していた4つの画面（依存パッケージ・言語・対応状況・
// Dependabot 運用状況）を、タブの中の小タブとして表示するために、同じ見出し行を、固定配置・閉じるボタンなしで描く
export function PanelFrame({
  label, title, icon: Icon, maxWidth = 'max-w-6xl', children,
}: {
  // 領域の名前（アクセシブルな名前）。title を省略すると、見出しにも使う
  label: string
  title?: string
  icon: LucideIcon
  maxWidth?: 'max-w-5xl' | 'max-w-6xl'
  children: ReactNode
}) {
  return (
    <section aria-label={label} className={`${maxWidth} w-full flex flex-col gap-5`}>
      <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-300 uppercase tracking-wider">
        <Icon size={16} className="text-slate-400" aria-hidden="true" />
        {title ?? label}
      </h3>
      {children}
    </section>
  )
}
