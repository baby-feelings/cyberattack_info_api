import type { TabDefinition } from './tabs'
import type { NavTarget } from '../overview/overviewConfig'

// URL のパラメータ名。Slack 通知・Issue のリンクを作るバックエンド（app/core/notifications/dashboard_links.py）と同じ値
export const DEEP_LINK_PARAM = { tab: 'tab', sub: 'sub' } as const

// URL（`?tab=dependencies&sub=sla`）から、開くタブと小タブを読む。
// 知らないタブは、リンク全体を無効にする（null）。知らない小タブは、無視してタブの先頭を開く
export function parseDeepLink(search: string, tabs: readonly TabDefinition[]): NavTarget | null {
  const params = new URLSearchParams(search)
  const tab = tabs.find((t) => t.key === params.get(DEEP_LINK_PARAM.tab))
  if (!tab) return null
  const sub = params.get(DEEP_LINK_PARAM.sub)
  const knownSub = tab.subTabs?.some((s) => s.key === sub) ? (sub ?? undefined) : undefined
  return { tab: tab.key, subTab: knownSub }
}
