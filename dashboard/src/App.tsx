// ダッシュボードのメインコンポーネント
// 初回マウント時に API から全データを並列取得し、各ウィジェットへ渡す
import { useEffect, useState, useCallback } from 'react'
import { RefreshCw, ShieldAlert } from 'lucide-react'
import { fetchRecent, fetchStats, type VulnerabilityOut, type StatsResponse } from './api/client'
import { HealthStatus } from './components/HealthStatus'
import { StatsCards } from './components/StatsCards'
import { MonthlyTrend } from './components/MonthlyTrend'
import { VendorRanking } from './components/VendorRanking'
import { RecentCVEs } from './components/RecentCVEs'

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
      // 並列取得で高速化
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
    <div className="min-h-screen bg-slate-900 text-slate-100">
      {/* ヘッダー */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-sm sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="bg-violet-600 rounded-xl p-1.5">
              <ShieldAlert size={20} className="text-white" />
            </div>
            <div>
              <h1 className="text-base font-bold text-slate-100">Cyberattack Info Dashboard</h1>
              <p className="text-xs text-slate-500">CISA Known Exploited Vulnerabilities</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {refreshedAt && (
              <span className="text-xs text-slate-500 hidden sm:block">
                更新: {refreshedAt.toLocaleTimeString('ja-JP')}
              </span>
            )}
            <button
              onClick={load}
              disabled={loading}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 rounded-lg text-sm text-slate-300 transition-colors disabled:opacity-50"
            >
              <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
              <span className="hidden sm:inline">更新</span>
            </button>
          </div>
        </div>
      </header>

      {/* メインコンテンツ */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 py-6 space-y-5">
        {/* エラー表示 */}
        {error && (
          <div className="bg-red-900/40 border border-red-700 text-red-300 rounded-xl px-4 py-3 text-sm">
            ⚠️ データ取得エラー: {error}
          </div>
        )}

        {/* サマリーカード */}
        <StatsCards stats={stats} recent={recent} loading={loading} />

        {/* ヘルス + 月別トレンド */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
          <div className="lg:col-span-1">
            <HealthStatus />
          </div>
          <div className="lg:col-span-2">
            <MonthlyTrend data={stats?.monthly_trend ?? []} loading={loading} />
          </div>
        </div>

        {/* ベンダーランキング + 直近CVE */}
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
          <VendorRanking data={stats?.top_vendors ?? []} loading={loading} />
          <RecentCVEs data={recent} loading={loading} />
        </div>
      </main>

      {/* フッター */}
      <footer className="border-t border-slate-800 mt-8">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 py-4 flex items-center justify-between text-xs text-slate-600">
          <span>データソース: CISA Known Exploited Vulnerabilities Catalog</span>
          <span>毎日 JST 04:00 自動更新</span>
        </div>
      </footer>
    </div>
  )
}
