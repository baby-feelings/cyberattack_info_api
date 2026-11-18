import type { ReactNode } from 'react'
import { Shield, Bug, ScanSearch, ShieldCheck } from 'lucide-react'
import { KevPanel } from '../KevPanel'
import { OsvPanel } from '../OsvPanel'
import { DepscanAuthGate } from '../DepscanAuthGate'
import { CodescanAuthGate } from '../CodescanAuthGate'
import { PostureAuthGate } from '../posture/PostureAuthGate'
import { POSTURE_TAB } from '../posture/postureConfig'
import type { FetchedCrawlerType } from '../freshness/freshnessConfig'

// タブ種別
export type TabKey = 'public' | 'depscan' | 'codescan' | 'posture'

// 1つのタブの定義。タブバーのボタンと、タブパネルの見出し・本体を1か所で宣言する
// （以前は App.tsx にタブ数×約20行の同じ構造が並んでいた）。新しいタブはここに1件足す。
// 1つの小タブ（タブの中の切り替え）。見出し（title・subtitle）と最終取得は、指定があればタブのものより優先する
export interface SubTabDefinition {
  key: string
  label: string
  panel: ReactNode
  crawlerType?: FetchedCrawlerType
  title?: string
  subtitle?: string
}

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
  panel: ReactNode
  // 小タブ（あれば、先頭が初期表示）
  subTabs?: SubTabDefinition[]
}

export const TAB_DEFINITIONS: TabDefinition[] = [
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
    key: 'depscan',
    label: 'DEPSCAN',
    crawlerType: 'DEPSCAN',
    icon: (size) => <Bug size={size} className="text-rose-400" />,
    title: 'DEPSCAN — 自作アプリの依存ライブラリ脆弱性',
    subtitle: 'GitHub上の自作リポジトリの依存関係を OSV と照合し、悪意あるパッケージ・言語のサポート期限・対応状況も監視',
    borderColor: 'border-rose-800/40',
    // GitHub ログイン後、本人所有リポジトリの DEPSCAN パネルを表示
    panel: <DepscanAuthGate />,
  },
  {
    key: 'codescan',
    label: 'CODESCAN',
    crawlerType: 'CODESCAN',
    icon: (size) => <ScanSearch size={size} className="text-cyan-400" />,
    title: 'CODESCAN — 自アプリのコード脆弱性診断',
    subtitle: 'GitHub上の自作リポジトリのソースコードを静的解析し、GitHub Actions・Firebase・Dockerの設定も診断',
    borderColor: 'border-cyan-800/40',
    // GitHub ログイン後、CODESCAN パネル（サマリー・一覧を内包）を表示
    panel: <CodescanAuthGate />,
  },
  {
    key: 'posture',
    label: POSTURE_TAB.label,
    // 見出しの「最終取得」は、アラートの取り込み。設定の監査・外形監視は、各セクションに出す
    crawlerType: 'GHALERT',
    icon: (size) => <ShieldCheck size={size} className="text-violet-400" />,
    title: POSTURE_TAB.title,
    subtitle: POSTURE_TAB.subtitle,
    borderColor: 'border-violet-800/40',
    // GitHub ログイン後、アラート・設定の監査・外形監視を表示
    panel: <PostureAuthGate />,
  },
]
