import { useCallback, useEffect, useState } from 'react'
import { GitPullRequest, ChevronDown, ChevronUp, ExternalLink } from 'lucide-react'
import {
  fetchDepsOpsList, type DependabotPrLogOut,
} from '../../api/client'
import { TableLoadingSkeleton, EmptyState, Pagination } from '../shared/VulnPanelParts'

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

// DEPSCAN タブ内に統合した Dependabot PR 自動運用（DEPSOPS）の判定履歴セクション。
// Slack 通知は実行時点のスナップショットのみで履歴を持たないため、
// 「要確認」PR がどのリポジトリ・どんな理由で自動マージされなかったかを
// 後から確認できるようにする（初期状態は折りたたみ。開いたときのみ取得する）。
export function DependabotOpsSection() {
  const [open, setOpen] = useState(false)
  const [action, setAction] = useState<'ALL' | 'merged' | 'flagged'>('ALL')
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [items, setItems] = useState<DependabotPrLogOut[]>([])
  const [loading, setLoading] = useState(false)

  const load = useCallback(async (act: typeof action, p: number) => {
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

  // 折りたたまれている間は取得しない（開いたとき・フィルタ/ページ変更時のみ取得する）
  useEffect(() => {
    if (open) {
      load(action, page)
    }
  }, [open, load, action, page])

  function handleAction(act: typeof action) {
    setAction(act)
    setPage(1)
  }

  const totalPages = Math.ceil(total / PER_PAGE)

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between gap-2 px-4 py-3 text-left hover:bg-slate-800/40 transition-colors"
      >
        <span className="flex items-center gap-2 text-sm font-semibold text-slate-400 uppercase tracking-wider">
          <GitPullRequest size={14} className="text-slate-400" />
          Dependabot 運用状況（DEPSOPS）
        </span>
        {open
          ? <ChevronUp size={14} className="text-slate-500" />
          : <ChevronDown size={14} className="text-slate-500" />}
      </button>

      {open && (
        <div className="px-4 pb-4 flex flex-col gap-3">
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
                <table className="w-full text-sm min-w-[640px]">
                  <thead>
                    <tr className="border-b border-slate-800">
                      <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-48">リポジトリ</th>
                      <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3">PR</th>
                      <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-28">判定</th>
                      <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-24">日時</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {items.map(item => (
                      <tr key={`${item.repo_full_name}-${item.pr_number}`}>
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

              <Pagination
                page={page}
                totalPages={totalPages}
                total={total}
                onPageChange={setPage}
              />
            </>
          )}
        </div>
      )}
    </div>
  )
}
