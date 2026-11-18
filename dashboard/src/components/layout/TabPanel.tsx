import type { TabDefinition } from './tabs'
import { LastFetched } from '../freshness/LastFetched'
import { SubTabBar } from './SubTabBar'

// タブパネル（見出し＋本体）。aria 属性はタブバーのボタン（tab-<key>）と対応させる。
// 小タブがあるタブは、小タブの切り替えを出し、見出し・最終取得・本体は選択中の小タブのものを使う
export function TabPanel({
  tab, subTabKey, onSubTabChange,
}: {
  tab: TabDefinition
  // 選択中の小タブ（未指定・不明な値は、先頭の小タブ）
  subTabKey?: string
  onSubTabChange?: (key: string) => void
}) {
  const subTabs = tab.subTabs
  const activeSub = subTabs?.find((sub) => sub.key === subTabKey) ?? subTabs?.[0]
  const title = activeSub?.title ?? tab.title
  const subtitle = activeSub?.subtitle ?? tab.subtitle
  const crawlerType = activeSub?.crawlerType ?? tab.crawlerType

  return (
    <section
      id={`tabpanel-${tab.key}`}
      role="tabpanel"
      aria-labelledby={`tab-${tab.key}`}
      className="flex flex-col gap-4 sm:gap-6 lg:gap-8"
    >
      <div className={`flex flex-wrap items-center gap-x-3 gap-y-2 pb-4 border-b ${tab.borderColor}`}>
        <div>{tab.icon(18)}</div>
        <div>
          <h2 className="text-base font-semibold text-white leading-tight">{title}</h2>
          <p className="text-xs text-slate-500 leading-tight">{subtitle}</p>
        </div>
        {/* データを最後に取得した日時（見出しの右。狭い画面では見出しの下に折り返す） */}
        <LastFetched crawlerType={crawlerType} />
      </div>
      {subTabs && activeSub ? (
        <>
          <SubTabBar
            tabs={subTabs.map(({ key, label }) => ({ key, label }))}
            active={activeSub.key}
            onSelect={(key) => onSubTabChange?.(key)}
            idPrefix={tab.key}
          />
          <div id={`subtabpanel-${tab.key}`} role="tabpanel" aria-label={activeSub.label}>
            {activeSub.panel}
          </div>
        </>
      ) : tab.panel}
    </section>
  )
}
