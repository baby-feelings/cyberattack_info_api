import type { TabDefinition } from './tabs'

// タブパネル（見出し＋本体）。aria 属性はタブバーのボタン（tab-<key>）と対応させる
export function TabPanel({ tab }: { tab: TabDefinition }) {
  return (
    <section
      id={`tabpanel-${tab.key}`}
      role="tabpanel"
      aria-labelledby={`tab-${tab.key}`}
      className="flex flex-col gap-4 sm:gap-6 lg:gap-8"
    >
      <div className={`flex items-center gap-3 pb-4 border-b ${tab.borderColor}`}>
        <div>{tab.icon(18)}</div>
        <div>
          <h2 className="text-base font-semibold text-white leading-tight">{tab.title}</h2>
          <p className="text-xs text-slate-500 leading-tight">{tab.subtitle}</p>
        </div>
      </div>
      {tab.panel}
    </section>
  )
}
