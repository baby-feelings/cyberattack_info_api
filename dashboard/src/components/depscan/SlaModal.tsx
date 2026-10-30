import { useEffect, useState } from 'react'
import { X, Timer } from 'lucide-react'
import { fetchSlaReport, type OperatingStatus, type SlaReport } from '../../api/client'
import { TableLoadingSkeleton, EmptyState } from '../shared/VulnPanelParts'
import { OperatingFilter } from '../shared/OperatingFilter'

const TH = 'text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3'

// 取得結果。どの運用状態で取得したかを持ち、現在の条件と違えば「取得中」とみなす
interface Result {
  operating: OperatingStatus
  report: SlaReport | null
  failed: boolean
}

// 平均対応日数の表示（解決が0件のときは「—」）
function mttrText(mttr: number | null): string {
  return mttr === null ? '—' : `${mttr} 日`
}

// 期限超過が1件でもあれば目立たせる。0件は落ち着いた色にする
function Tile({ label, value, tone = 'neutral', hint }: {
  label: string; value: string; tone?: 'neutral' | 'danger'; hint?: string
}) {
  const cls = tone === 'danger'
    ? 'border-red-500/30 bg-red-500/10 text-red-300'
    : 'border-slate-800 bg-slate-900 text-slate-200'
  return (
    <div className={`rounded-xl border px-4 py-3 ${cls}`} title={hint}>
      <p className="text-[11px] text-slate-500">{label}</p>
      <p className="text-xl font-bold tabular-nums mt-0.5">{value}</p>
    </div>
  )
}

function OverdueBadge({ count }: { count: number }) {
  if (count === 0) return <span className="text-slate-600 tabular-nums">0</span>
  return <span className="text-red-400 font-semibold tabular-nums">{count}</span>
}

function SlaDialog({ onClose, authToken }: { onClose: () => void; authToken?: string }) {
  const [operating, setOperating] = useState<OperatingStatus>('active')
  const [result, setResult] = useState<Result | null>(null)

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  // 運用状態が変わるたびに取り直す。状態の更新は取得の完了時だけ行う
  // （条件の変更で古い取得が遅れて届いても、結果を捨てる）
  useEffect(() => {
    let cancelled = false
    fetchSlaReport(authToken, operating)
      .then(report => { if (!cancelled) setResult({ operating, report, failed: false }) })
      .catch(() => { if (!cancelled) setResult({ operating, report: null, failed: true }) })
    return () => { cancelled = true }
  }, [authToken, operating])

  const loading = result === null || result.operating !== operating
  const report = !loading && result ? result.report : null

  return (
    <div
      className="fixed inset-0 z-50 bg-slate-950 flex flex-col"
      role="dialog"
      aria-modal="true"
      aria-label="対応状況"
    >
      <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 shrink-0">
        <span className="flex items-center gap-2 text-sm font-semibold text-slate-300 uppercase tracking-wider">
          <Timer size={16} className="text-slate-400" />
          対応状況
        </span>
        <button
          onClick={onClose}
          aria-label="閉じる"
          className="text-slate-500 hover:text-slate-300 transition-colors p-1 rounded"
        >
          <X size={18} />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto px-6 py-5">
        <div className="max-w-6xl mx-auto flex flex-col gap-5">
          <p className="text-xs text-slate-500">
            検知から解決までの日数と、重要度ごとの対応期限（SLA）を超えている検知です。
            LOW・重要度不明は期限がありません。CISA KEV に掲載された検知は、重要度によらず期限が短くなります。
          </p>

          <div className="flex flex-wrap items-center gap-3">
            <OperatingFilter value={operating} onChange={setOperating} />
          </div>

          {loading ? (
            <TableLoadingSkeleton columnWidths={['w-40', 'w-24', 'w-24', 'w-32', 'flex-1']} />
          ) : report === null ? (
            <EmptyState icon={<Timer size={24} />} message="取得に失敗しました。時間をおいて再度お試しください" />
          ) : (
            <>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3" aria-label="対応状況の概要">
                <Tile
                  label="期限超過"
                  value={`${report.summary.overdue} 件`}
                  tone={report.summary.overdue > 0 ? 'danger' : 'neutral'}
                />
                <Tile label="未解決（期限あり）" value={`${report.summary.open_with_deadline} 件`} />
                <Tile label={`直近${report.mttr_window_days}日の解決`} value={`${report.summary.resolved} 件`} />
                <Tile
                  label="平均対応日数（MTTR）"
                  value={mttrText(report.summary.mttr_days)}
                  hint="検知から解決までの平均日数"
                />
              </div>

              <p className="text-xs text-slate-500" aria-label="対応期限">
                対応期限: CRITICAL {report.policy.critical_days}日 / HIGH {report.policy.high_days}日 /
                MEDIUM {report.policy.medium_days}日 / KEV掲載 {report.policy.kev_days}日
                {report.policy.excluded_osv_ids.length > 0 && (
                  <span>（除外中: {report.policy.excluded_osv_ids.length}件）</span>
                )}
              </p>

              {report.overdue.length === 0 ? (
                <EmptyState icon={<Timer size={24} />} message="期限を超えている検知はありません" />
              ) : (
                <div className="overflow-x-auto -mx-1 px-1">
                  <table aria-label="期限超過の検知一覧" className="w-full text-sm min-w-[760px]">
                    <thead>
                      <tr className="border-b border-slate-800">
                        <th className={`${TH} w-20`}>重要度</th>
                        <th className={`${TH} w-48`}>リポジトリ</th>
                        <th className={TH}>パッケージ</th>
                        <th className={`${TH} w-24`}>期限</th>
                        <th className={`${TH} w-28`}>超過</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {report.overdue.map(item => (
                        <tr key={`${item.repo_full_name}-${item.package_name}-${item.installed_version}-${item.osv_id}`}>
                          <td className="py-2.5 pr-3 text-xs text-slate-300">
                            {item.severity ?? '不明'}
                            {item.is_malicious && <span className="ml-1" title="悪意あるパッケージ">🛑</span>}
                            {item.is_kev && (
                              <span className="ml-1 px-1 rounded text-[9px] font-bold bg-red-500/20 text-red-400 border border-red-500/40">
                                KEV
                              </span>
                            )}
                          </td>
                          <td className="py-2.5 pr-3 text-xs text-slate-300 truncate max-w-[200px]">{item.repo_full_name}</td>
                          <td className="py-2.5 pr-3 text-xs text-slate-200">
                            {item.package_name}
                            <span className="text-slate-500 tabular-nums"> {item.installed_version}</span>
                            <p className="text-[10px] text-slate-600">{item.osv_id}</p>
                          </td>
                          <td className="py-2.5 pr-3 text-xs text-slate-400 tabular-nums">{item.deadline_days} 日</td>
                          <td className="py-2.5 text-xs text-red-400 font-semibold tabular-nums">{item.overdue_days} 日超過</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                <div className="overflow-x-auto">
                  <h3 className="text-xs font-semibold text-slate-500 mb-2">重要度別</h3>
                  <table aria-label="重要度別の対応状況" className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-slate-800">
                        <th className={TH}>重要度</th>
                        <th className={TH}>期限</th>
                        <th className={TH}>未解決</th>
                        <th className={TH}>超過</th>
                        <th className={TH}>平均対応</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {report.by_severity.map(s => (
                        <tr key={s.severity}>
                          <td className="py-2 pr-3 text-xs text-slate-300">{s.severity}</td>
                          <td className="py-2 pr-3 text-xs text-slate-400 tabular-nums">
                            {s.deadline_days === null ? '—' : `${s.deadline_days} 日`}
                          </td>
                          <td className="py-2 pr-3 text-xs text-slate-300 tabular-nums">{s.open}</td>
                          <td className="py-2 pr-3 text-xs"><OverdueBadge count={s.overdue} /></td>
                          <td className="py-2 text-xs text-slate-400 tabular-nums">{mttrText(s.mttr_days)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <div className="overflow-x-auto">
                  <h3 className="text-xs font-semibold text-slate-500 mb-2">リポジトリ別</h3>
                  <table aria-label="リポジトリ別の対応状況" className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-slate-800">
                        <th className={TH}>リポジトリ</th>
                        <th className={TH}>未解決</th>
                        <th className={TH}>超過</th>
                        <th className={TH}>平均対応</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {report.by_repo.map(r => (
                        <tr key={r.repo_full_name}>
                          <td className="py-2 pr-3 text-xs text-slate-300 truncate max-w-[220px]">{r.repo_full_name}</td>
                          <td className="py-2 pr-3 text-xs text-slate-300 tabular-nums">{r.open}</td>
                          <td className="py-2 pr-3 text-xs"><OverdueBadge count={r.overdue} /></td>
                          <td className="py-2 text-xs text-slate-400 tabular-nums">{mttrText(r.mttr_days)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

// 脆弱性への対応状況（期限超過・平均対応日数）を見る全画面モーダル。
// DEPSCAN タブ内のボタンから開く（依存パッケージ・言語・実行環境と同じ設計）。
// 開いたときにだけ内側を組み立てるため、閉じている間は取得しない。
export function SlaModal({
  open, onClose, authToken,
}: { open: boolean; onClose: () => void; authToken?: string }) {
  if (!open) return null
  return <SlaDialog onClose={onClose} authToken={authToken} />
}
