import type { ReactNode } from 'react'

// 左の一覧に並べる1アプリ分の表示内容
export interface RepoRailItem {
  // 選択キー（リポジトリの full_name）
  key: string
  // 表示名（owner を省いたリポジトリ名）
  label: string
  // 件数などのバッジ部分
  badge: ReactNode
  // 対応が必要な脆弱性が無いアプリは薄く表示する
  muted?: boolean
}

interface RepoRailProps {
  items: RepoRailItem[]
  // 選択中のアプリ（null = すべてのアプリ）
  selected: string | null
  onSelect: (key: string | null) => void
  // 先頭の「すべてのアプリ」行に出すバッジ
  allBadge: ReactNode
}

// DEPSCAN・CODESCAN 共通の「アプリ一覧」。広い画面では左に縦並び、狭い画面では横に並ぶチップになる。
// 運用中のアプリのうち、どのアプリに対応が必要かをひと目で見つけ、選んで絞り込むために使う
export function RepoRail({ items, selected, onSelect, allBadge }: RepoRailProps) {
  const base =
    'flex items-center justify-between gap-2 rounded-lg px-2.5 py-2 text-xs transition-colors '
    + 'whitespace-nowrap shrink-0 md:w-full border md:border-transparent'

  function cls(active: boolean, muted?: boolean) {
    if (active) return `${base} bg-slate-800 text-slate-100 border-violet-500/60 md:shadow-[inset_3px_0_0_#8b5cf6]`
    return `${base} border-slate-700 hover:bg-slate-800/60 ${muted ? 'text-slate-500' : 'text-slate-300'}`
  }

  return (
    <nav
      aria-label="アプリ一覧"
      className="flex md:flex-col gap-1.5 overflow-x-auto md:overflow-visible md:w-56 md:shrink-0 md:border-r md:border-slate-800 md:pr-3 pb-1 md:pb-0"
    >
      <button onClick={() => onSelect(null)} aria-pressed={selected === null} className={cls(selected === null)}>
        <span>すべてのアプリ</span>
        {allBadge}
      </button>
      {items.map(item => (
        <button
          key={item.key}
          onClick={() => onSelect(item.key)}
          aria-pressed={selected === item.key}
          title={item.key}
          className={cls(selected === item.key, item.muted)}
        >
          <span className="truncate md:max-w-[120px]">{item.label}</span>
          {item.badge}
        </button>
      ))}
    </nav>
  )
}
