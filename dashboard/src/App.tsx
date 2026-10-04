import { useState } from 'react'
import { ShieldAlert } from 'lucide-react'
import { HealthStatus } from './components/HealthStatus'
import { SettingsPanel } from './components/SettingsPanel'
import { HeaderMenu } from './components/layout/HeaderMenu'
import { TabBar } from './components/layout/TabBar'
import { TabPanel } from './components/layout/TabPanel'
import { TAB_DEFINITIONS, type TabKey } from './components/layout/tabs'

export default function App() {
  // GitHub OAuth コールバックからの復帰（?depscan_code=...）時は DEPSCAN タブを自動選択する
  const [activeTab, setActiveTab] = useState<TabKey>(() => (
    new URLSearchParams(window.location.search).has('depscan_code') ? 'depscan' : 'kev'
  ))
  const [settingsOpen, setSettingsOpen] = useState(false)
  const activeDefinition = TAB_DEFINITIONS.find((tab) => tab.key === activeTab)

  return (
    <div className="min-h-screen bg-[#0a0e1a] text-slate-100 flex flex-col items-center">

      {/* ヘッダー */}
      <header className="w-full sticky top-0 z-20 border-b border-slate-800/60 bg-[#0a0e1a]/90 backdrop-blur-md">
        <div className="max-w-screen-xl mx-auto px-4 sm:px-8 lg:px-12 h-14 flex items-center justify-between gap-4">

          <div className="flex items-center gap-2.5 min-w-0">
            <div className="shrink-0 bg-violet-600 rounded-lg p-1.5 shadow-lg shadow-violet-900/50">
              <ShieldAlert size={18} className="text-white" />
            </div>
            <div className="min-w-0">
              <p className="text-sm font-semibold text-white leading-tight truncate">
                サイバー攻撃情報ダッシュボード
              </p>
              <p className="text-[10px] text-slate-500 leading-tight hidden sm:block">
                CISA KEV / Open Source Vulnerabilities
              </p>
            </div>
          </div>

          <HeaderMenu onOpenSettings={() => setSettingsOpen(true)} />

        </div>
      </header>

      {settingsOpen && <SettingsPanel onClose={() => setSettingsOpen(false)} />}

      {/* メインコンテンツ（下部固定タブバーの高さ分、下に余白を確保） */}
      <main className="flex-1 max-w-screen-xl w-full px-4 sm:px-6 lg:px-12 py-6 sm:py-8 lg:py-10 pb-24 sm:pb-24 flex flex-col gap-6 sm:gap-8 lg:gap-10">

        {/* サーバー稼働状況（全タブ共通） */}
        <HealthStatus />

        {/* 選択中のタブのパネル（見出し＋本体） */}
        {activeDefinition && <TabPanel tab={activeDefinition} />}

      </main>

      {/* フッター（下部固定タブバーに隠れないよう下部余白を確保） */}
      <footer className="w-full border-t border-slate-800/60 pb-20">
        <div className="max-w-screen-xl mx-auto px-4 sm:px-8 lg:px-12 py-5 flex flex-col sm:flex-row items-center justify-between gap-1 text-xs text-slate-600">
          <span>データソース: CISA KEV / Open Source Vulnerabilities (OSV) / JVN (JVNDB) / DEPSCAN / CODESCAN</span>
          <span>KEV → OSV → JVN → DEPSCAN → CODESCAN: JST 04:05 一括自動更新</span>
        </div>
      </footer>

      {/* 下部固定タブバー */}
      <TabBar activeTab={activeTab} onSelect={setActiveTab} />

    </div>
  )
}
