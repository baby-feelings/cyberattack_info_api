import { useEffect, useState } from 'react'
import { Activity, Database, RefreshCw, CheckCircle, XCircle } from 'lucide-react'
import { fetchHealth, type HealthResponse } from '../api/client'

export function HealthStatus() {
  const [data, setData] = useState<HealthResponse | null>(null)
  const [error, setError] = useState(false)
  const [loading, setLoading] = useState(true)
  const [lastChecked, setLastChecked] = useState<Date | null>(null)

  async function load() {
    setLoading(true)
    try {
      setData(await fetchHealth())
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
  const isDbConnected = data?.db_connected ?? false

  return (
    <div className="h-full rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-lg flex flex-col gap-4">

      {/* ヘッダー */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Activity size={15} className="text-slate-400" />
          <span className="text-sm font-semibold text-slate-400 uppercase tracking-wider">サーバー稼働状況</span>
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="text-slate-500 hover:text-slate-300 transition-colors disabled:opacity-40 p-1 rounded"
          title="再確認"
        >
          <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
        </button>
      </div>

      {/* ステータス表示 */}
      <div className="flex items-center gap-3">
        <span
          className={`w-2.5 h-2.5 rounded-full shrink-0 ${
            loading ? 'bg-slate-600 animate-pulse' :
            isOk ? 'bg-emerald-400 shadow-[0_0_10px_#34d399]' :
            'bg-red-400 shadow-[0_0_10px_#f87171]'
          }`}
        />
        <span className={`text-2xl font-bold ${
          loading ? 'text-slate-600' :
          isOk ? 'text-emerald-400' : 'text-red-400'
        }`}>
          {loading ? '確認中...' : error ? 'UNREACHABLE' : data?.status.toUpperCase()}
        </span>
      </div>

      {/* 詳細項目（DB 接続） */}
      <div className="flex flex-col gap-2 flex-1">
        <div className="flex items-center justify-between rounded-xl bg-slate-800/60 px-3 py-2.5">
          <div className="flex items-center gap-2">
            <Database size={14} className="text-slate-500" />
            <span className="text-sm text-slate-400">DB 接続</span>
          </div>
          <div className="flex items-center gap-1.5">
            {!loading && (
              isDbConnected
                ? <CheckCircle size={14} className="text-emerald-400" />
                : <XCircle size={14} className="text-red-400" />
            )}
            <span className={`text-sm font-medium ${
              loading ? 'text-slate-600' :
              isDbConnected ? 'text-emerald-400' : 'text-red-400'
            }`}>
              {loading ? '—' : isDbConnected ? '正常' : 'エラー'}
            </span>
          </div>
        </div>
      </div>

      {/* 最終確認時刻 */}
      {lastChecked && (
        <p className="text-xs text-slate-600 text-right">
          最終確認: {lastChecked.toLocaleTimeString('ja-JP')}
        </p>
      )}
    </div>
  )
}
