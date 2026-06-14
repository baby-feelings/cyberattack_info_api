// サーバー稼働状況カード
import { useEffect, useState } from 'react'
import { Activity, Database, Server, RefreshCw } from 'lucide-react'
import { fetchHealth, type HealthResponse } from '../api/client'

export function HealthStatus() {
  const [data, setData] = useState<HealthResponse | null>(null)
  const [error, setError] = useState(false)
  const [loading, setLoading] = useState(true)
  const [lastChecked, setLastChecked] = useState<Date | null>(null)

  async function load() {
    setLoading(true)
    try {
      const res = await fetchHealth()
      setData(res)
      setError(false)
    } catch {
      setError(true)
    } finally {
      setLoading(false)
      setLastChecked(new Date())
    }
  }

  useEffect(() => { load() }, [])

  const isOk = !error && data?.status === 'ok'

  return (
    <div className="bg-slate-800 rounded-2xl p-6 border border-slate-700">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Activity size={18} className="text-slate-400" />
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">サーバー稼働状況</h2>
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="text-slate-400 hover:text-slate-200 transition-colors disabled:opacity-50"
          title="更新"
        >
          <RefreshCw size={15} className={loading ? 'animate-spin' : ''} />
        </button>
      </div>

      <div className="flex items-center gap-3 mb-5">
        <span className={`w-3 h-3 rounded-full ${isOk ? 'bg-emerald-400 shadow-[0_0_8px_#34d399]' : 'bg-red-400 shadow-[0_0_8px_#f87171]'} ${loading ? 'animate-pulse' : ''}`} />
        <span className={`text-2xl font-bold ${isOk ? 'text-emerald-400' : 'text-red-400'}`}>
          {loading ? '確認中...' : error ? 'UNREACHABLE' : data?.status.toUpperCase()}
        </span>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="bg-slate-700/50 rounded-xl p-3 flex items-center gap-3">
          <Database size={16} className="text-slate-400 shrink-0" />
          <div>
            <p className="text-xs text-slate-400">DB 接続</p>
            <p className={`text-sm font-semibold ${data?.db_connected ? 'text-emerald-400' : 'text-red-400'}`}>
              {loading ? '—' : data?.db_connected ? '正常' : 'エラー'}
            </p>
          </div>
        </div>
        <div className="bg-slate-700/50 rounded-xl p-3 flex items-center gap-3">
          <Server size={16} className="text-slate-400 shrink-0" />
          <div>
            <p className="text-xs text-slate-400">環境</p>
            <p className="text-sm font-semibold text-slate-200">
              {loading ? '—' : data?.environment ?? '—'}
            </p>
          </div>
        </div>
      </div>

      {lastChecked && (
        <p className="text-xs text-slate-500 mt-3 text-right">
          最終確認: {lastChecked.toLocaleTimeString('ja-JP')}
        </p>
      )}
    </div>
  )
}
