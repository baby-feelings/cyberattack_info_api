import { useEffect, useState, useCallback } from 'react'
import { RefreshCw, ShieldAlert, Wifi, Shield, Package } from 'lucide-react'
import { fetchRecent, fetchStats, type VulnerabilityOut, type StatsResponse } from './api/client'
import { HealthStatus } from './components/HealthStatus'
import { StatsCards } from './components/StatsCards'
import { MonthlyTrend } from './components/MonthlyTrend'
import { VendorRanking } from './components/VendorRanking'
import { RecentCVEs } from './components/RecentCVEs'
import { OsvPanel } from './components/OsvPanel'

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

export default function App() {
  const [recent, setRecent] = useState<VulnerabilityOut[]>([])
  const [stats, setStats] = useState<StatsResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [refreshedAt, setRefreshedAt] = useState<Date | null>(null)

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
                Cyberattack Info Dashboard
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

      {/* メインコンテンツ */}
      <main className="flex-1 max-w-screen-xl w-full px-4 sm:px-8 lg:px-12 py-8 flex flex-col gap-8">

        {/* エラーバナー */}
        {error && (
          <div className="flex items-start gap-3 bg-red-950/60 border border-red-800/60 text-red-300 rounded-xl px-4 py-3 text-sm">
            <span className="shrink-0 mt-0.5">⚠️</span>
            <span>データ取得エラー: {error}</span>
          </div>
        )}

        {/* ══ CISA KEV セクション ══════════════════════════════════════ */}
        <section className="flex flex-col gap-6">
          <SectionHeader
            icon={<Shield size={18} className="text-blue-400" />}
            title="CISA KEV — Known Exploited Vulnerabilities"
            subtitle="実際に悪用が確認された脆弱性（米 CISA 公式カタログ）"
            borderColor="border-blue-800/40"
          />

          {/* CVE サマリーカード */}
          <StatsCards stats={stats} recent={recent} loading={loading} />

          {/* ヘルス + 月別トレンド */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 lg:gap-8">
            <div className="lg:col-span-1">
              <HealthStatus />
            </div>
            <div className="lg:col-span-2">
              <MonthlyTrend data={stats?.monthly_trend ?? []} loading={loading} />
            </div>
          </div>

          {/* ベンダーランキング + 直近 CVE */}
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 xl:gap-8">
            <VendorRanking data={stats?.top_vendors ?? []} loading={loading} />
            <RecentCVEs data={recent} loading={loading} />
          </div>
        </section>

        {/* セクション区切り */}
        <div className="border-t border-slate-700/50" />

        {/* ══ OSV セクション ═══════════════════════════════════════════ */}
        <section className="flex flex-col gap-6">
          <SectionHeader
            icon={<Package size={18} className="text-emerald-400" />}
            title="OSV — Open Source Vulnerabilities"
            subtitle="オープンソースライブラリの脆弱性（直近 30 日）"
            borderColor="border-emerald-800/40"
          />

          {/* OSV パネル（サマリーカード・チャート・一覧を内包） */}
          <OsvPanel />
        </section>

      </main>

      {/* フッター */}
      <footer className="w-full border-t border-slate-800/60 mt-4">
        <div className="max-w-screen-xl mx-auto px-4 sm:px-8 lg:px-12 py-5 flex flex-col sm:flex-row items-center justify-between gap-1 text-xs text-slate-600">
          <span>データソース: CISA KEV / Open Source Vulnerabilities (OSV)</span>
          <span>KEV: JST 04:05 / OSV: JST 05:05 自動更新</span>
        </div>
      </footer>

    </div>
  )
}
