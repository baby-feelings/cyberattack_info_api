import { useEffect, useState, useCallback } from 'react'
import { RefreshCw, ShieldAlert, Wifi, Shield, Package, FileWarning, Bug } from 'lucide-react'
import { fetchRecent, fetchStats, type VulnerabilityOut, type StatsResponse } from './api/client'
import { HealthStatus } from './components/HealthStatus'
import { StatsCards } from './components/StatsCards'
import { MonthlyTrend } from './components/MonthlyTrend'
import { VendorRanking } from './components/VendorRanking'
import { RecentCVEs } from './components/RecentCVEs'
import { OsvPanel } from './components/OsvPanel'
import { JvnPanel } from './components/JvnPanel'
import { DepscanPanel } from './components/DepscanPanel'

// セクション見出しコンポーネント
function SectionHeader({
  icon,
  title,
  subtitle,
  borderColor,
}: {
  icon: React.ReactNode
  title: string
  subtitle: string
  borderColor: string
}) {
  return (
    <div className={`flex items-center gap-3 pb-4 border-b ${borderColor}`}>
      <div>{icon}</div>
      <div>
        <h2 className="text-base font-semibold text-white leading-tight">{title}</h2>
        <p className="text-xs text-slate-500 leading-tight">{subtitle}</p>
      </div>
    </div>
  )
}

// タブ種別
type TabKey = 'kev' | 'osv' | 'jvn' | 'depscan'

const TABS: { key: TabKey; label: string; icon: React.ReactNode }[] = [
  { key: 'kev', label: 'KEV', icon: <Shield size={20} className="text-blue-400" /> },
  { key: 'osv', label: 'OSV', icon: <Package size={20} className="text-emerald-400" /> },
  { key: 'jvn', label: 'JVN', icon: <FileWarning size={20} className="text-amber-400" /> },
  { key: 'depscan', label: 'DEPSCAN', icon: <Bug size={20} className="text-rose-400" /> },
]

export default function App() {
  const [recent, setRecent] = useState<VulnerabilityOut[]>([])
  const [stats, setStats] = useState<StatsResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [refreshedAt, setRefreshedAt] = useState<Date | null>(null)
  const [activeTab, setActiveTab] = useState<TabKey>('kev')

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [recentData, statsData] = await Promise.all([fetchRecent(30), fetchStats()])
      setRecent(recentData)
      setStats(statsData)
      setRefreshedAt(new Date())
    } catch (e) {
      setError(e instanceof Error ? e.message : '不明なエラー')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

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

          <div className="flex items-center gap-2 shrink-0">
            {refreshedAt && (
              <div className="hidden md:flex items-center gap-1.5 text-xs text-slate-500">
                <Wifi size={11} className="text-emerald-500" />
                <span>{refreshedAt.toLocaleTimeString('ja-JP')}</span>
              </div>
            )}
            <button
              onClick={load}
              disabled={loading}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 active:bg-slate-600 text-xs font-medium text-slate-300 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
              <span>更新</span>
            </button>
          </div>

        </div>
      </header>

      {/* メインコンテンツ（下部固定タブバーの高さ分、下に余白を確保） */}
      <main className="flex-1 max-w-screen-xl w-full px-4 sm:px-6 lg:px-12 py-6 sm:py-8 lg:py-10 pb-24 sm:pb-24 flex flex-col gap-6 sm:gap-8 lg:gap-10">

        {/* エラーバナー */}
        {error && (
          <div className="flex items-start gap-3 bg-red-950/60 border border-red-800/60 text-red-300 rounded-xl px-4 py-3 text-sm">
            <span className="shrink-0 mt-0.5">⚠️</span>
            <span>データ取得エラー: {error}</span>
          </div>
        )}

        {/* ══ サーバー稼働状況（全タブ共通） ═══════════════════════════ */}
        <HealthStatus />

        {/* ══ CISA KEV タブ ══════════════════════════════════════════ */}
        {activeTab === 'kev' && (
          <section
            id="tabpanel-kev"
            role="tabpanel"
            aria-labelledby="tab-kev"
            className="flex flex-col gap-4 sm:gap-6 lg:gap-8"
          >
            <SectionHeader
              icon={<Shield size={18} className="text-blue-400" />}
              title="CISA KEV — Known Exploited Vulnerabilities"
              subtitle="実際に悪用が確認された脆弱性（米 CISA 公式カタログ）"
              borderColor="border-blue-800/40"
            />

            {/* CVE サマリーカード */}
            <StatsCards stats={stats} recent={recent} loading={loading} />

            {/* 月別トレンド */}
            <MonthlyTrend data={stats?.monthly_trend ?? []} loading={loading} />

            {/* ベンダーランキング + 直近 CVE */}
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-4 sm:gap-6 xl:gap-8">
              <VendorRanking data={stats?.top_vendors ?? []} loading={loading} />
              <RecentCVEs data={recent} loading={loading} />
            </div>
          </section>
        )}

        {/* ══ OSV タブ ═══════════════════════════════════════════════ */}
        {activeTab === 'osv' && (
          <section
            id="tabpanel-osv"
            role="tabpanel"
            aria-labelledby="tab-osv"
            className="flex flex-col gap-4 sm:gap-6 lg:gap-8"
          >
            <SectionHeader
              icon={<Package size={18} className="text-emerald-400" />}
              title="OSV — Open Source Vulnerabilities"
              subtitle="オープンソースライブラリの脆弱性（過去 6 ヶ月）"
              borderColor="border-emerald-800/40"
            />

            {/* OSV パネル（サマリーカード・チャート・一覧を内包） */}
            <OsvPanel />
          </section>
        )}

        {/* ══ JVN タブ ═══════════════════════════════════════════════ */}
        {activeTab === 'jvn' && (
          <section
            id="tabpanel-jvn"
            role="tabpanel"
            aria-labelledby="tab-jvn"
            className="flex flex-col gap-4 sm:gap-6 lg:gap-8"
          >
            <SectionHeader
              icon={<FileWarning size={18} className="text-amber-400" />}
              title="JVN — Japan Vulnerability Notes"
              subtitle="日本国内の脆弱性情報（MyJVN / JVNDB 過去 6 ヶ月）"
              borderColor="border-amber-800/40"
            />

            {/* JVN パネル（サマリーカード・チャート・一覧を内包） */}
            <JvnPanel />
          </section>
        )}

        {/* ══ DEPSCAN タブ ═══════════════════════════════════════════ */}
        {activeTab === 'depscan' && (
          <section
            id="tabpanel-depscan"
            role="tabpanel"
            aria-labelledby="tab-depscan"
            className="flex flex-col gap-4 sm:gap-6 lg:gap-8"
          >
            <SectionHeader
              icon={<Bug size={18} className="text-rose-400" />}
              title="DEPSCAN — 自作アプリの依存ライブラリ脆弱性"
              subtitle="GitHub上の自作リポジトリの依存関係を OSV API とリアルタイム照合"
              borderColor="border-rose-800/40"
            />

            {/* DEPSCAN パネル（サマリーカード・チャート・一覧を内包） */}
            <DepscanPanel />
          </section>
        )}

      </main>

      {/* フッター（下部固定タブバーに隠れないよう下部余白を確保） */}
      <footer className="w-full border-t border-slate-800/60 pb-20">
        <div className="max-w-screen-xl mx-auto px-4 sm:px-8 lg:px-12 py-5 flex flex-col sm:flex-row items-center justify-between gap-1 text-xs text-slate-600">
          <span>データソース: CISA KEV / Open Source Vulnerabilities (OSV) / JVN (JVNDB) / DEPSCAN</span>
          <span>KEV → OSV → JVN → DEPSCAN: JST 04:05 一括自動更新</span>
        </div>
      </footer>

      {/* 下部固定タブバー */}
      <nav className="fixed bottom-0 inset-x-0 z-20 border-t border-slate-800/60 bg-[#0a0e1a]/95 backdrop-blur-md">
        <div role="tablist" className="max-w-screen-xl mx-auto grid grid-cols-4">
          {TABS.map((tab) => {
            const isActive = activeTab === tab.key
            return (
              <button
                key={tab.key}
                id={`tab-${tab.key}`}
                role="tab"
                aria-selected={isActive}
                aria-controls={`tabpanel-${tab.key}`}
                onClick={() => setActiveTab(tab.key)}
                className={`flex flex-col items-center justify-center gap-1 py-2.5 text-xs font-medium transition-colors ${
                  isActive ? 'text-white' : 'text-slate-500 hover:text-slate-300'
                }`}
              >
                <span className={isActive ? 'opacity-100' : 'opacity-60'}>{tab.icon}</span>
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

    </div>
  )
}
