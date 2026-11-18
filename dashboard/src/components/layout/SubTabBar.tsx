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
  return (
    <div role="tablist" aria-label="小タブ" className="flex flex-wrap gap-1 border-b border-slate-800">
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
            className={`px-3 py-2 text-xs font-medium border-b-2 -mb-px transition-colors ${
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
