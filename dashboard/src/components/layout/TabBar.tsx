import { TAB_DEFINITIONS, type TabKey } from './tabs'

// 下部固定タブバー
export function TabBar({
  activeTab, onSelect,
}: {
  activeTab: TabKey
  onSelect: (key: TabKey) => void
}) {
  return (
    <nav className="fixed bottom-0 inset-x-0 z-20 border-t border-slate-800/60 bg-[#0a0e1a]/95 backdrop-blur-md">
      <div role="tablist" className="max-w-screen-xl mx-auto grid grid-cols-5">
        {TAB_DEFINITIONS.map((tab) => {
          const isActive = activeTab === tab.key
          return (
            <button
              key={tab.key}
              id={`tab-${tab.key}`}
              role="tab"
              aria-selected={isActive}
              aria-controls={`tabpanel-${tab.key}`}
              onClick={() => onSelect(tab.key)}
              className={`flex flex-col items-center justify-center gap-1 py-2.5 text-xs font-medium transition-colors ${
                isActive ? 'text-white' : 'text-slate-500 hover:text-slate-300'
              }`}
            >
              <span className={isActive ? 'opacity-100' : 'opacity-60'}>{tab.icon(20)}</span>
              <span>{tab.label}</span>
              <span
                className={`h-0.5 w-8 rounded-full transition-colors ${
                  isActive ? 'bg-violet-500' : 'bg-transparent'
                }`}
              />
            </button>
          )
        })}
      </div>
    </nav>
  )
}
