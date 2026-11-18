import { useEffect, useRef } from 'react'

// 小タブの切り替え表示（役割: 切り替えのボタン列を描くだけ。中身・選択状態は持たない）
export interface SubTabItem {
  key: string
  label: string
}

export function SubTabBar({
  tabs, active, onSelect, idPrefix,
}: {
  tabs: SubTabItem[]
  active: string
  onSelect: (key: string) => void
  // 小タブとパネルを aria で関連付けるための接頭辞（親タブのキー）
  idPrefix: string
}) {
  const listRef = useRef<HTMLDivElement>(null)

  // 選択中の小タブが、横スクロールで見切れないよう、中央に寄せる（ページ自体は動かさない）
  useEffect(() => {
    const list = listRef.current
    const selected = list?.querySelector<HTMLElement>('[aria-selected="true"]')
    if (!list || !selected) return
    list.scrollLeft = selected.offsetLeft - (list.clientWidth - selected.offsetWidth) / 2
  }, [active])

  return (
    // ヘッダー（高さ h-14）の下に固定する。ページをスクロールした状態で別の画面へ切り替えても、小タブの画面内の位置が動かない
    <div
      ref={listRef}
      role="tablist"
      aria-label="小タブ"
      className="sticky top-14 z-10 flex flex-nowrap gap-x-1 overflow-x-auto border-b border-slate-800 bg-[#0a0e1a]/95 backdrop-blur-md [scrollbar-width:none] [&::-webkit-scrollbar]:hidden"
    >
      {tabs.map((tab) => {
        const isActive = tab.key === active
        return (
          <button
            key={tab.key}
            id={`subtab-${idPrefix}-${tab.key}`}
            role="tab"
            aria-selected={isActive}
            aria-controls={`subtabpanel-${idPrefix}`}
            onClick={() => onSelect(tab.key)}
            className={`shrink-0 px-4 py-3 text-base font-semibold whitespace-nowrap border-b-2 transition-colors ${
              isActive
                ? 'border-violet-500 text-white'
                : 'border-transparent text-slate-500 hover:text-slate-300'
            }`}
          >
            {tab.label}
          </button>
        )
      })}
    </div>
  )
}
