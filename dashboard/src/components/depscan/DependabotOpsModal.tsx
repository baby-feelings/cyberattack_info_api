import { useCallback, useEffect, useState } from 'react'
import { X, GitPullRequest, ExternalLink } from 'lucide-react'
import {
  fetchDepsOpsList, fetchAllDepsOpsEntries, type DependabotPrLogOut,
} from '../../api/client'
import { TableLoadingSkeleton, EmptyState, Pagination } from '../shared/VulnPanelParts'
import { DepsOpsRepoBarChart } from './DepsOpsRepoBarChart'
import { computeUnresolvedRepoStats, type RepoOpsStat } from './depsopsGrouping'

const PER_PAGE = 20

const ACTIONS: { key: 'ALL' | 'merged' | 'flagged'; label: string }[] = [
  { key: 'ALL', label: 'すべて' },
  { key: 'merged', label: '自動マージ' },
  { key: 'flagged', label: '要確認' },
]

function ActionBadge({ action }: { action: 'merged' | 'flagged' }) {
  return action === 'merged' ? (
    <span className="inline-block px-1.5 py-0.5 rounded text-xs font-medium bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
      自動マージ
    </span>
  ) : (
    <span className="inline-block px-1.5 py-0.5 rounded text-xs font-medium bg-amber-500/15 text-amber-400 border border-amber-500/30">
      要確認
    </span>
  )
}

// GitHub Dependabot alert のパッケージ名とPRタイトルのヒューリスティックな
// 照合結果（バックエンド側判定。あくまで参考情報）
function SecurityUpdateBadge({ isSecurityUpdate }: { isSecurityUpdate: boolean | null }) {
  if (isSecurityUpdate === null) {
    return <span className="text-[10px] text-slate-600">不明</span>
  }
  return isSecurityUpdate ? (
    <span className="inline-block px-1.5 py-0.5 rounded text-[10px] font-medium bg-red-500/15 text-red-400 border border-red-500/30 whitespace-nowrap">
      セキュリティ更新
    </span>
  ) : (
    <span className="text-[10px] text-slate-600 whitespace-nowrap">バージョン更新</span>
  )
}

// Dependabot PR 自動運用（DEPSOPS）の判定履歴を表示する全画面モーダル。
// DEPSCAN タブ内のボタンから開く（5つ目の固定タブにはしない設計判断。詳細はCLAUDE.md参照）。
export function DependabotOpsModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [action, setAction] = useState<'ALL' | 'merged' | 'flagged'>('ALL')
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [items, setItems] = useState<DependabotPrLogOut[]>([])
  const [loading, setLoading] = useState(false)
  const [repoStats, setRepoStats] = useState<RepoOpsStat[]>([])
  const [statsLoading, setStatsLoading] = useState(false)

  const loadTable = useCallback(async (act: typeof action, p: number) => {
    setLoading(true)
    try {
      const res = await fetchDepsOpsList({
        page: p, perPage: PER_PAGE, action: act === 'ALL' ? null : act,
      })
      setItems(res.data)
      setTotal(res.total)
    } catch {
      // エラーは握りつぶし（データなし状態として扱う）
    } finally {
      setLoading(false)
    }
  }, [])

  const loadStats = useCallback(async () => {
    setStatsLoading(true)
    try {
      const all = await fetchAllDepsOpsEntries()
      setRepoStats(computeUnresolvedRepoStats(all))
    } catch {
      // エラーは握りつぶし（データなし状態として扱う）
    } finally {
      setStatsLoading(false)
    }
  }, [])

  // 開いたときのみ取得する（閉じている間は取得しない）
  useEffect(() => {
    if (open) {
      loadTable(action, page)
    }
  }, [open, loadTable, action, page])

  useEffect(() => {
    if (open) {
      loadStats()
    }
  }, [open, loadStats])

  useEffect(() => {
    if (!open) return
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [open, onClose])

  function handleAction(act: typeof action) {
    setAction(act)
    setPage(1)
  }

  if (!open) return null

  const totalPages = Math.ceil(total / PER_PAGE)

  return (
    <div
      className="fixed inset-0 z-50 bg-slate-950 flex flex-col"
      role="dialog"
      aria-modal="true"
      aria-label="Dependabot 運用状況"
    >
      <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 shrink-0">
        <span className="flex items-center gap-2 text-sm font-semibold text-slate-300 uppercase tracking-wider">
          <GitPullRequest size={16} className="text-slate-400" />
          Dependabot 運用状況（DEPSOPS）
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
        <div className="max-w-5xl mx-auto flex flex-col gap-5">
          <DepsOpsRepoBarChart stats={repoStats} loading={statsLoading} />

          <div className="flex flex-wrap gap-1.5">
            {ACTIONS.map(a => (
              <button
                key={a.key}
                onClick={() => handleAction(a.key)}
                className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-colors ${
                  action === a.key
                    ? 'bg-violet-600 text-white shadow'
                    : 'bg-slate-800 text-slate-400 hover:text-slate-300 hover:bg-slate-700'
                }`}
              >
                {a.label}
              </button>
            ))}
          </div>

          {loading ? (
            <TableLoadingSkeleton columnWidths={['w-40', 'w-16', 'flex-1', 'w-24']} />
          ) : items.length === 0 ? (
            <EmptyState icon={<GitPullRequest size={24} />} message="該当する PR はありません" />
          ) : (
            <>
              <div className="overflow-x-auto -mx-1 px-1">
                <table className="w-full text-sm min-w-[720px]">
                  <thead>
                    <tr className="border-b border-slate-800">
                      <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-48">リポジトリ</th>
                      <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3">PR</th>
                      <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-28">判定</th>
                      <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-28">種別</th>
                      <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-24">日時</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {items.map(item => (
                      <tr key={`${item.repo_full_name}-${item.pr_number}-${item.processed_at}`}>
                        <td className="py-2.5 pr-3">
                          <p className="text-slate-300 text-xs truncate max-w-[220px]">{item.repo_full_name}</p>
                        </td>
                        <td className="py-2.5 pr-3">
                          <a
                            href={`https://github.com/${item.repo_full_name}/pull/${item.pr_number}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 text-violet-400 hover:text-violet-300 text-xs transition-colors"
                          >
                            #{item.pr_number} {item.title}
                            <ExternalLink size={9} />
                          </a>
                          {item.reason && (
                            <p className="text-[10px] text-slate-500 mt-0.5">{item.reason}</p>
                          )}
                        </td>
                        <td className="py-2.5 pr-3">
                          <ActionBadge action={item.action} />
                        </td>
                        <td className="py-2.5 pr-3">
                          <SecurityUpdateBadge isSecurityUpdate={item.is_security_update} />
                        </td>
                        <td className="py-2.5 text-xs text-slate-600 tabular-nums whitespace-nowrap">
                          {new Date(item.processed_at).toLocaleDateString('ja-JP', {
                            year: 'numeric', month: 'short', day: 'numeric',
                          })}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <Pagination page={page} totalPages={totalPages} total={total} onPageChange={setPage} />
            </>
          )}
        </div>
      </div>
    </div>
  )
}
