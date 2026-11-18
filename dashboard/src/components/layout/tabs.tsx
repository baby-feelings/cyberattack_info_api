import type { ReactNode } from 'react'
import { Shield, Bug, ScanSearch, ShieldCheck, LayoutDashboard } from 'lucide-react'
import type { GithubSession } from '../../hooks/useGithubSession'
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
    label: '概要',
    crawlerType: 'DEPSCAN',
    icon: (size) => <LayoutDashboard size={size} className="text-emerald-400" />,
    title: OVERVIEW_TEXT.heading,
    subtitle: OVERVIEW_TEXT.subtitle,
    borderColor: 'border-emerald-800/40',
    login: { description: OVERVIEW_TEXT.loginDescription },
    panel: ({ session, navigate }) => <OverviewPanel authToken={session.token} onNavigate={navigate} />,
  },
  {
    key: 'public',
    label: '公開情報',
    // 見出しの最終取得は、選択中の小タブのものを使う
    crawlerType: 'KEV',
    icon: (size) => <Shield size={size} className="text-blue-400" />,
    title: '公開情報 — 世界の公開された脆弱性',
    subtitle: 'CISA KEV（悪用が確認された脆弱性）と OSV（オープンソースの脆弱性）',
    borderColor: 'border-blue-800/40',
    panel: null,
    subTabs: [
      {
        key: 'kev',
        label: 'KEV',
        crawlerType: 'KEV',
        title: 'CISA KEV — Known Exploited Vulnerabilities',
        subtitle: '実際に悪用が確認された脆弱性（米 CISA 公式カタログ）',
        // KEV パネル（サマリー・チャート・一覧を内包。OSV と同じ構成）
        panel: <KevPanel />,
      },
      {
        key: 'osv',
        label: 'OSV',
        crawlerType: 'OSV',
        title: 'OSV — Open Source Vulnerabilities',
        subtitle: 'オープンソースライブラリの脆弱性（過去 6 ヶ月）',
        // OSV パネル（サマリーカード・チャート・一覧を内包）
        panel: <OsvPanel />,
      },
    ],
  },
  {
    key: 'dependencies',
    label: '依存ライブラリ',
    crawlerType: 'DEPSCAN',
    icon: (size) => <Bug size={size} className="text-rose-400" />,
    title: '依存ライブラリ — 脆弱性・対応状況・言語のサポート期限',
    subtitle: 'GitHub上の自作リポジトリの依存関係を OSV と照合し、悪意あるパッケージ・言語のサポート期限・対応状況・Dependabot も監視',
    borderColor: 'border-rose-800/40',
    panel: null,
    // GitHub ログイン後、本人所有リポジトリの結果を、小タブで表示する
    login: { description: 'ログインすると、あなた自身が所有する GitHub リポジトリの依存ライブラリ脆弱性を表示します' },
    subTabs: [
      {
        key: 'scan',
        label: '検知',
        title: 'DEPSCAN — 自作アプリの依存ライブラリ脆弱性',
        subtitle: 'GitHub上の自作リポジトリの依存関係を OSV と照合し、悪意あるパッケージ・言語のサポート期限・対応状況も監視',
        panel: ({ session, logout }) => <DepscanScanView session={session} onSessionExpired={logout} />,
      },
      { key: 'sla', label: '対応状況', panel: ({ session }) => <SlaPanel authToken={session.token} /> },
      { key: 'depsops', label: 'Dependabot運用', panel: () => <DependabotOpsPanel /> },
      { key: 'deps', label: '依存パッケージ', panel: ({ session }) => <DependenciesPanel authToken={session.token} /> },
      { key: 'runtimes', label: '言語・実行環境', panel: ({ session }) => <RuntimesPanel authToken={session.token} /> },
      {
        key: 'alerts',
        label: 'アラート',
        crawlerType: 'GHALERT',
        title: '依存ライブラリのアラート — Dependabot',
        subtitle: 'GitHub が検知した、依存ライブラリのセキュリティアラート',
        panel: ({ session }) => <AlertsTab authToken={session.token} kinds={ALERT_KIND_GROUPS.dependencies} />,
      },
    ],
  },
  {
    key: 'code',
    label: 'コードと設定',
    crawlerType: 'CODESCAN',
    icon: (size) => <ScanSearch size={size} className="text-cyan-400" />,
    title: 'コードと設定 — コードの診断・GitHub のアラート・リポジトリ設定の監査',
    subtitle: 'GitHub上の自作リポジトリのソースコード・設定を診断し、GitHub のセキュリティアラートとリポジトリ設定の監査も確認',
    borderColor: 'border-cyan-800/40',
    panel: null,
    login: { description: 'ログインすると、自アプリのコード・設定の診断結果と、GitHub のアラート・リポジトリ設定の監査を閲覧できます' },
    subTabs: [
      {
        key: 'scan',
        label: '検知',
        crawlerType: 'CODESCAN',
        title: 'CODESCAN — 自アプリのコード脆弱性診断',
        subtitle: 'GitHub上の自作リポジトリのソースコードを静的解析し、GitHub Actions・Firebase・Dockerの設定も診断',
        panel: ({ session }) => <CodescanPanel authToken={session.token} />,
      },
      {
        key: 'alerts',
        label: 'アラート',
        crawlerType: 'GHALERT',
        title: 'コードのアラート — コードスキャン・シークレット',
        subtitle: 'GitHub が検知した、コードの脆弱性と、漏えいしたシークレットのアラート',
        panel: ({ session }) => <AlertsTab authToken={session.token} kinds={ALERT_KIND_GROUPS.code} />,
      },
      {
        key: 'audit',
        label: '設定の監査',
        crawlerType: 'REPOAUDIT',
        title: 'リポジトリ設定の監査',
        subtitle: 'リポジトリ × 点検項目。項目を押すと、詳細と直し方が出ます',
        panel: ({ session }) => <AuditTab authToken={session.token} />,
      },
    ],
  },
  {
    key: 'ops',
    label: '運用',
    crawlerType: 'EXTMON',
    icon: (size) => <ShieldCheck size={size} className="text-violet-400" />,
    title: '運用 — 公開サイトの外形監視',
    subtitle: '公開サイトの TLS 証明書の期限・セキュリティヘッダー・露出ファイルなどを監視（本人所有のリポジトリ）',
    borderColor: 'border-violet-800/40',
    login: { description: 'ログインすると、自分のリポジトリの公開サイトの外形監視の結果を閲覧できます' },
    panel: ({ session }) => <SitesTab authToken={session.token} />,
  },
]
