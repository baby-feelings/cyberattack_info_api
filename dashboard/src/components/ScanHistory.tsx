import { useEffect, useState } from 'react'
import { History, Package, AlertTriangle, ChevronDown, ChevronUp, ExternalLink, RefreshCw } from 'lucide-react'
import { fetchScanHistory, type ScanResultOut } from '../api/client'

const SCAN_TYPE_LABEL: Record<string, string> = {
  requirements:   'requirements.txt',
  'package-json': 'package.json',
  packages:       'パッケージ',
}

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: 'text-red-400',
  HIGH:     'text-orange-400',
  MEDIUM:   'text-yellow-400',
  LOW:      'text-blue-400',
}

export function ScanHistory() {
  const [history, setHistory] = useState<ScanResultOut[]>([])
  const [loading, setLoading] = useState(true)
  const [expanded, setExpanded] = useState<number | null>(null)

  async function load() {
    setLoading(true)
    try {
      setHistory(await fetchScanHistory(10))
    } catch {
      // 取得失敗時は空のまま
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-lg flex flex-col gap-4">

      {/* ヘッダー */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <History size={15} className="text-slate-400" />
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            スキャン履歴
          </span>
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="text-slate-500 hover:text-slate-300 transition-colors disabled:opacity-40 p-1 rounded"
          title="再読み込み"
        >
          <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
        </button>
      </div>

      {/* ローディング */}
      {loading ? (
        <div className="space-y-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-12 bg-slate-800 rounded-xl animate-pulse" />
          ))}
        </div>

      /* 履歴なし */
      ) : history.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-2 py-10 text-slate-600">
          <Package size={24} />
          <p className="text-xs">スキャン履歴がありません</p>
        </div>

      /* 履歴一覧 */
      ) : (
        <div className="space-y-2">
          {history.map(item => {
            const isOpen = expanded === item.id
            const date = new Date(item.scanned_at)
            const hasFinding = item.total_findings > 0

            return (
              <div key={item.id} className="rounded-xl border border-slate-800 overflow-hidden">

                {/* 折りたたみヘッダー行 */}
                <button
                  onClick={() => setExpanded(isOpen ? null : item.id)}
                  className="w-full flex items-center justify-between px-3 py-2.5 hover:bg-slate-800/60 transition-colors text-left gap-2"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    {/* スキャン種別バッジ */}
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-violet-500/15 text-violet-400 font-medium shrink-0">
                      {SCAN_TYPE_LABEL[item.scan_type] ?? item.scan_type}
                    </span>
                    {/* パッケージ数 */}
                    <span className="text-xs text-slate-500 tabular-nums shrink-0">
                      {item.scanned_packages} pkg
                    </span>
                    {/* 検出件数 */}
                    {hasFinding ? (
                      <span className="flex items-center gap-0.5 text-xs text-red-400 font-semibold tabular-nums shrink-0">
                        <AlertTriangle size={10} />
                        {item.total_findings} 件
                      </span>
                    ) : (
                      <span className="text-xs text-emerald-500 tabular-nums shrink-0">0 件</span>
                    )}
                  </div>

                  <div className="flex items-center gap-1.5 shrink-0">
                    {/* 実行日時 */}
                    <span className="text-[10px] text-slate-600 tabular-nums">
                      {date.toLocaleDateString('ja-JP', { month: 'short', day: 'numeric' })}
                      {' '}
                      {date.toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' })}
                    </span>
                    {isOpen
                      ? <ChevronUp size={11} className="text-slate-500" />
                      : <ChevronDown size={11} className="text-slate-500" />}
                  </div>
                </button>

                {/* 展開: 検出された脆弱性の一覧 */}
                {isOpen && (
                  <div className="border-t border-slate-800">
                    {item.findings.length === 0 ? (
                      <p className="text-xs text-emerald-500 text-center py-3">脆弱性なし</p>
                    ) : (
                      <div className="max-h-64 overflow-y-auto divide-y divide-slate-800/60">
                        {item.findings.map((f, idx) => {
                          const isCve = f.vuln_id.startsWith('CVE-')
                          return (
                            <div key={idx} className="flex items-start gap-2 px-3 py-2">
                              {/* 深刻度 */}
                              <span className={`text-[10px] font-bold shrink-0 w-14 ${SEVERITY_COLOR[f.severity ?? ''] ?? 'text-slate-500'}`}>
                                {f.severity ?? 'N/A'}
                              </span>
                              {/* パッケージ名 */}
                              <span className="text-[10px] font-mono text-slate-400 shrink-0">
                                {f.package_name}
                              </span>
                              {/* CVE リンク */}
                              {isCve ? (
                                <a
                                  href={`https://nvd.nist.gov/vuln/detail/${f.vuln_id}`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="inline-flex items-center gap-0.5 text-[10px] font-mono text-violet-400 hover:text-violet-300 shrink-0"
                                >
                                  {f.vuln_id}
                                  <ExternalLink size={8} />
                                </a>
                              ) : (
                                <span className="text-[10px] font-mono text-slate-500 shrink-0">
                                  {f.vuln_id}
                                </span>
                              )}
                              {/* 概要（残りスペースを使用） */}
                              <span className="text-[10px] text-slate-600 truncate min-w-0">
                                {f.summary}
                              </span>
                            </div>
                          )
                        })}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
