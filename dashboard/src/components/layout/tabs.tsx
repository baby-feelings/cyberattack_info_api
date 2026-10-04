import type { ReactNode } from 'react'
import { Shield, Package, FileWarning, Bug, ScanSearch } from 'lucide-react'
import { KevPanel } from '../KevPanel'
import { OsvPanel } from '../OsvPanel'
import { JvnPanel } from '../JvnPanel'
import { DepscanAuthGate } from '../DepscanAuthGate'
import { CodescanAuthGate } from '../CodescanAuthGate'

// タブ種別
export type TabKey = 'kev' | 'osv' | 'jvn' | 'depscan' | 'codescan'

// 1つのタブの定義。タブバーのボタンと、タブパネルの見出し・本体を1か所で宣言する
// （以前は App.tsx にタブ数×約20行の同じ構造が並んでいた）。新しいタブはここに1件足す。
export interface TabDefinition {
  key: TabKey
  label: string
  // タブバー用（20px）と見出し用（18px）で同じ色のアイコンを使う
  icon: (size: number) => ReactNode
  title: string
  subtitle: string
  borderColor: string
  panel: ReactNode
}

export const TAB_DEFINITIONS: TabDefinition[] = [
  {
    key: 'kev',
    label: 'KEV',
    icon: (size) => <Shield size={size} className="text-blue-400" />,
    title: 'CISA KEV — Known Exploited Vulnerabilities',
    subtitle: '実際に悪用が確認された脆弱性（米 CISA 公式カタログ）',
    borderColor: 'border-blue-800/40',
    // KEV パネル（サマリー・チャート・一覧を内包。OSV/JVN と同じ構成）
    panel: <KevPanel />,
  },
  {
    key: 'osv',
    label: 'OSV',
    icon: (size) => <Package size={size} className="text-emerald-400" />,
    title: 'OSV — Open Source Vulnerabilities',
    subtitle: 'オープンソースライブラリの脆弱性（過去 6 ヶ月）',
    borderColor: 'border-emerald-800/40',
    // OSV パネル（サマリーカード・チャート・一覧を内包）
    panel: <OsvPanel />,
  },
  {
    key: 'jvn',
    label: 'JVN',
    icon: (size) => <FileWarning size={size} className="text-amber-400" />,
    title: 'JVN — Japan Vulnerability Notes',
    subtitle: '日本国内の脆弱性情報（MyJVN / JVNDB 過去 6 ヶ月）',
    borderColor: 'border-amber-800/40',
    // JVN パネル（サマリーカード・チャート・一覧を内包）
    panel: <JvnPanel />,
  },
  {
    key: 'depscan',
    label: 'DEPSCAN',
    icon: (size) => <Bug size={size} className="text-rose-400" />,
    title: 'DEPSCAN — 自作アプリの依存ライブラリ脆弱性',
    subtitle: 'GitHub上の自作リポジトリの依存関係を OSV API とリアルタイム照合',
    borderColor: 'border-rose-800/40',
    // GitHub ログイン後、本人所有リポジトリの DEPSCAN パネルを表示
    panel: <DepscanAuthGate />,
  },
  {
    key: 'codescan',
    label: 'CODESCAN',
    icon: (size) => <ScanSearch size={size} className="text-cyan-400" />,
    title: 'CODESCAN — 自アプリのコード脆弱性診断',
    subtitle: 'GitHub上の自作リポジトリのソースコードを Semgrep + Gitleaks で静的解析',
    borderColor: 'border-cyan-800/40',
    // GitHub ログイン後、CODESCAN パネル（サマリー・一覧を内包）を表示
    panel: <CodescanAuthGate />,
  },
]
