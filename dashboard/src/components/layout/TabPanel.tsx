import type { ReactNode } from 'react'
import type { PanelContent, PanelContext, TabDefinition } from './tabs'
import type { NavTarget } from '../overview/overviewConfig'
import { LastFetched } from '../freshness/LastFetched'
import { GithubLoginGate } from '../shared/GithubLoginGate'
import { SubTabBar } from './SubTabBar'

// 本体の定義（そのまま描ける中身、またはログイン後のセッションを受け取る関数）を、描ける形にする。
// 関数は、ログインのゲートの中（ctx がある）でだけ呼べる
function resolve(content: PanelContent, ctx: PanelContext | null): ReactNode {
  if (typeof content !== 'function') return content
  return ctx ? content(ctx) : null
}

// タブパネル（見出し＋本体）。aria 属性はタブバーのボタン（tab-<key>）と対応させる。
// 小タブがあるタブは、小タブの切り替えを出し、見出し・最終取得・本体は選択中の小タブのものを使う。
// login があるタブは、GitHub ログインのゲートで本体を包む（小タブすべてで1回のログインを共有する）
export function TabPanel({
  tab, subTabKey, onSubTabChange, onNavigate,
}: {
  tab: TabDefinition
  // 選択中の小タブ（未指定・不明な値は、先頭の小タブ）
  subTabKey?: string
  onSubTabChange?: (key: string) => void
  // 別のタブ・小タブへ移る（概要のカード用）
  onNavigate?: (target: NavTarget) => void
}) {
  const subTabs = tab.subTabs
  const activeSub = subTabs?.find((sub) => sub.key === subTabKey) ?? subTabs?.[0]
  const title = activeSub?.title ?? tab.title
  const subtitle = activeSub?.subtitle ?? tab.subtitle
  const crawlerType = activeSub?.crawlerType ?? tab.crawlerType

  const renderBody = (ctx: PanelContext | null): ReactNode => {
    if (!subTabs || !activeSub) return resolve(tab.panel, ctx)
    return (
      <>
        <div id={`subtabpanel-${tab.key}`} role="tabpanel" aria-label={activeSub.label}>
          {resolve(activeSub.panel, ctx)}
        </div>
      </>
    )
  }

  return (
    <section
      id={`tabpanel-${tab.key}`}
      role="tabpanel"
      aria-labelledby={`tab-${tab.key}`}
      // 切り替え直後（読み込み中）に中身が短くなっても、ページの高さが縮まないよう、画面の高さを下限にする。
      // 縮むと、スマホのブラウザがスクロール位置を補正して、画面が上下に動く（dvh は、アドレスバーの伸縮に追従する）
      className="flex flex-col gap-4 sm:gap-6 lg:gap-8 min-h-[100dvh]"
    >
      {/* 小タブは見出しの上に置く。見出し（題名の長さ・最終取得の行数）が小タブごとに違っても、押したボタンの位置が動かない */}
      {subTabs && activeSub && (
        <SubTabBar
          tabs={subTabs.map(({ key, label }) => ({ key, label }))}
          active={activeSub.key}
          onSelect={(key) => onSubTabChange?.(key)}
          idPrefix={tab.key}
        />
      )}
      <div className={`flex flex-wrap items-center gap-x-3 gap-y-2 pb-4 border-b ${tab.borderColor}`}>
        <div>{tab.icon(18)}</div>
        <div>
          <h2 className="text-base font-semibold text-white leading-tight">{title}</h2>
          <p className="text-xs text-slate-500 leading-tight">{subtitle}</p>
        </div>
        {/* データを最後に取得した日時（見出しの右。狭い画面では見出しの下に折り返す） */}
        <LastFetched crawlerType={crawlerType} />
      </div>
      {tab.login ? (
        <GithubLoginGate description={tab.login.description}>
          {(session, { logout }) => renderBody({ session, logout, navigate: (target) => onNavigate?.(target) })}
        </GithubLoginGate>
      ) : renderBody(null)}
    </section>
  )
}
