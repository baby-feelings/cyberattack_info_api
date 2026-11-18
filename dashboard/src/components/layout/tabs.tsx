import type { ReactNode } from 'react'
import { Shield, Bug, ScanSearch, ShieldCheck, LayoutDashboard } from 'lucide-react'
import type { GithubSession } from '../../hooks/useGithubSession'
import { TAB_TEXT } from './tabsConfig'
import { OverviewPanel } from '../overview/OverviewPanel'
import { OVERVIEW_TEXT, type NavTarget } from '../overview/overviewConfig'
import { KevPanel } from '../KevPanel'
import { OsvPanel } from '../OsvPanel'
import { CodescanPanel } from '../CodescanPanel'
import { DepscanScanView } from '../DepscanScanView'
import { SlaPanel } from '../depscan/SlaPanel'
import { DependabotOpsPanel } from '../depscan/DependabotOpsPanel'
import { DependenciesPanel } from '../depscan/DependenciesPanel'
import { RuntimesPanel } from '../depscan/RuntimesPanel'
import { AlertsTab } from '../posture/AlertsTab'
import { AuditTab, SitesTab } from '../posture/SourceTabs'
import { ALERT_KIND_GROUPS } from '../posture/postureConfig'
import type { FetchedCrawlerType } from '../freshness/freshnessConfig'

// タブ種別
export type TabKey = 'overview' | 'public' | 'dependencies' | 'code' | 'ops'

// ログイン後に本体へ渡す文脈（セッションと、セッション失効時に呼ぶログアウト）
export interface PanelContext {
  session: GithubSession
  logout: () => void
  // 別のタブ・小タブへ移る（概要のカードから使う）
  navigate: (target: NavTarget) => void
}

// 本体の定義: そのまま描ける中身、または、ログイン後の文脈を受け取る関数（login のあるタブだけが使える）
export type PanelContent = ReactNode | ((ctx: PanelContext) => ReactNode)

// 1つの小タブ（タブの中の切り替え）。見出し（title・subtitle）と最終取得は、指定があればタブのものより優先する
export interface SubTabDefinition {
  key: string
  label: string
  panel: PanelContent
  crawlerType?: FetchedCrawlerType
  title?: string
  subtitle?: string
}

// 1つのタブの定義。タブバーのボタンと、タブパネルの見出し・本体を1か所で宣言する
// （以前は App.tsx にタブ数×約20行の同じ構造が並んでいた）。新しいタブはここに1件足す。
export interface TabDefinition {
  key: TabKey
  label: string
  // 見出しの「最終取得」に使う、クローラーの種別（バックエンドの crawler_logs.crawler_type）
  crawlerType: FetchedCrawlerType
  // タブバー用（20px）と見出し用（18px）で同じ色のアイコンを使う
  icon: (size: number) => ReactNode
  title: string
  subtitle: string
  borderColor: string
  // 小タブが無いタブだけが使う
  panel: PanelContent
  // GitHub ログインが要るタブ。本体を、ログインのゲートで包む（小タブすべてで、1回のログインを共有する）
  login?: { description: string }
  // 小タブ（あれば、先頭が初期表示）
  subTabs?: SubTabDefinition[]
}

export const TAB_DEFINITIONS: TabDefinition[] = [
  {
    key: 'overview',
    label: TAB_TEXT.overview.label,
    crawlerType: 'DEPSCAN',
    icon: (size) => <LayoutDashboard size={size} className="text-emerald-400" />,
    title: OVERVIEW_TEXT.heading,
    subtitle: OVERVIEW_TEXT.subtitle,
    borderColor: 'border-emerald-800/40',
    login: { description: OVERVIEW_TEXT.loginDescription },
    panel: ({ session, navigate }) => <OverviewPanel authToken={session.token} onNavigate={navigate} />,
  },
  {
    key: 'dependencies',
    label: TAB_TEXT.dependencies.label,
    crawlerType: 'DEPSCAN',
    icon: (size) => <Bug size={size} className="text-rose-400" />,
    title: TAB_TEXT.dependencies.title,
    subtitle: TAB_TEXT.dependencies.subtitle,
    borderColor: 'border-rose-800/40',
    panel: null,
    // GitHub ログイン後、本人所有リポジトリの結果を、小タブで表示する
    login: { description: TAB_TEXT.dependencies.login },
    subTabs: [
      {
        key: 'scan',
        label: TAB_TEXT.dependencies.scan.label,
        title: TAB_TEXT.dependencies.scan.title,
        subtitle: TAB_TEXT.dependencies.scan.subtitle,
        panel: ({ session, logout }) => <DepscanScanView session={session} onSessionExpired={logout} />,
      },
      { key: 'sla', label: TAB_TEXT.dependencies.sla.label, panel: ({ session }) => <SlaPanel authToken={session.token} /> },
      { key: 'depsops', label: TAB_TEXT.dependencies.depsops.label, panel: () => <DependabotOpsPanel /> },
      { key: 'deps', label: TAB_TEXT.dependencies.deps.label, panel: ({ session }) => <DependenciesPanel authToken={session.token} /> },
      { key: 'runtimes', label: TAB_TEXT.dependencies.runtimes.label, panel: ({ session }) => <RuntimesPanel authToken={session.token} /> },
      {
        key: 'alerts',
        label: TAB_TEXT.dependencies.alerts.label,
        crawlerType: 'GHALERT',
        title: TAB_TEXT.dependencies.alerts.title,
        subtitle: TAB_TEXT.dependencies.alerts.subtitle,
        panel: ({ session }) => <AlertsTab authToken={session.token} kinds={ALERT_KIND_GROUPS.dependencies} />,
      },
    ],
  },
  {
    key: 'code',
    label: TAB_TEXT.code.label,
    crawlerType: 'CODESCAN',
    icon: (size) => <ScanSearch size={size} className="text-cyan-400" />,
    title: TAB_TEXT.code.title,
    subtitle: TAB_TEXT.code.subtitle,
    borderColor: 'border-cyan-800/40',
    panel: null,
    login: { description: TAB_TEXT.code.login },
    subTabs: [
      {
        key: 'scan',
        label: TAB_TEXT.code.scan.label,
        crawlerType: 'CODESCAN',
        title: TAB_TEXT.code.scan.title,
        subtitle: TAB_TEXT.code.scan.subtitle,
        panel: ({ session }) => <CodescanPanel authToken={session.token} />,
      },
      {
        key: 'alerts',
        label: TAB_TEXT.code.alerts.label,
        crawlerType: 'GHALERT',
        title: TAB_TEXT.code.alerts.title,
        subtitle: TAB_TEXT.code.alerts.subtitle,
        panel: ({ session }) => <AlertsTab authToken={session.token} kinds={ALERT_KIND_GROUPS.code} />,
      },
      {
        key: 'audit',
        label: TAB_TEXT.code.audit.label,
        crawlerType: 'REPOAUDIT',
        title: TAB_TEXT.code.audit.title,
        subtitle: TAB_TEXT.code.audit.subtitle,
        panel: ({ session }) => <AuditTab authToken={session.token} />,
      },
    ],
  },
  {
    key: 'ops',
    label: TAB_TEXT.ops.label,
    crawlerType: 'EXTMON',
    icon: (size) => <ShieldCheck size={size} className="text-violet-400" />,
    title: TAB_TEXT.ops.title,
    subtitle: TAB_TEXT.ops.subtitle,
    borderColor: 'border-violet-800/40',
    login: { description: TAB_TEXT.ops.login },
    panel: ({ session }) => <SitesTab authToken={session.token} />,
  },
  {
    key: 'public',
    label: TAB_TEXT.public.label,
    // 見出しの最終取得は、選択中の小タブのものを使う
    crawlerType: 'KEV',
    icon: (size) => <Shield size={size} className="text-blue-400" />,
    title: TAB_TEXT.public.title,
    subtitle: TAB_TEXT.public.subtitle,
    borderColor: 'border-blue-800/40',
    panel: null,
    subTabs: [
      {
        key: 'kev',
        label: TAB_TEXT.public.kev.label,
        crawlerType: 'KEV',
        title: TAB_TEXT.public.kev.title,
        subtitle: TAB_TEXT.public.kev.subtitle,
        // KEV パネル（サマリー・チャート・一覧を内包。OSV と同じ構成）
        panel: <KevPanel />,
      },
      {
        key: 'osv',
        label: TAB_TEXT.public.osv.label,
        crawlerType: 'OSV',
        title: TAB_TEXT.public.osv.title,
        subtitle: TAB_TEXT.public.osv.subtitle,
        // OSV パネル（サマリーカード・チャート・一覧を内包）
        panel: <OsvPanel />,
      },
    ],
  },
]
