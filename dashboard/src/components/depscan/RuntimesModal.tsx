import { useEffect, useState } from 'react'
import { X, Cpu, AlertTriangle } from 'lucide-react'
import {
  fetchRuntimes, fetchRuntimeRepos, fetchRuntimeReleases,
  type OperatingStatus, type RepoRuntimeOut, type RepoRuntimeRepoStat,
  type RuntimeReleaseOut, type RuntimeState,
} from '../../api/client'
import { TableLoadingSkeleton, EmptyState } from '../shared/VulnPanelParts'
import { OperatingFilter } from '../shared/OperatingFilter'
import { RepoRail } from '../shared/RepoRail'
import { repoShortName } from '../shared/repoName'

const INPUT_CLS =
  'rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-violet-500'

const TH = 'text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3'

// 絞り込みに使う言語（バックエンドの識別子と表示名）
const RUNTIME_OPTIONS = [
  { value: 'python', label: 'Python' },
  { value: 'nodejs', label: 'Node.js' },
  { value: 'flutter', label: 'Flutter' },
  { value: 'dart', label: 'Dart' },
]

// 状態の表示（文言と色）。対応が急ぐものほど目立たせる
const STATE_BADGE: Record<RuntimeState, { label: string; cls: string }> = {
  eol: { label: 'サポート終了', cls: 'bg-red-500/15 text-red-400 border-red-500/30' },
  eol_soon: { label: '期限間近', cls: 'bg-orange-500/15 text-orange-400 border-orange-500/30' },
  update_available: { label: '更新あり', cls: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30' },
  latest: { label: '最新', cls: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30' },
  reference: { label: '参考（下限の指定）', cls: 'bg-slate-700/40 text-slate-400 border-slate-600' },
  unknown: { label: '不明', cls: 'bg-slate-700/40 text-slate-400 border-slate-600' },
}

// 表示に使う条件。変わるたびに取り直す
interface Filters {
  repo: string | null
  operating: OperatingStatus
  needsActionOnly: boolean
  runtime: string | null
}

// 初期表示は運用中のアプリすべて。何も操作しなくても、使っている言語・実行環境を一覧できる
const INITIAL_FILTERS: Filters = {
  repo: null, operating: 'active', needsActionOnly: false, runtime: null,
}

interface ListResult {
  // この結果を取得したときの条件。現在の条件と違えば「取得中」とみなす
  filters: Filters
  items: RepoRuntimeOut[]
  failed: boolean
}

function StateBadge({ state }: { state: RuntimeState }) {
  const { label, cls } = STATE_BADGE[state]
  return (
    <span className={`inline-block px-1.5 py-0.5 rounded text-xs font-medium border whitespace-nowrap ${cls}`}>
      {label}
    </span>
  )
}

// サポート終了日と、終了までの日数（過ぎていれば「終了済み」）。期限が定められていないものは「—」
function EolCell({ item }: { item: RepoRuntimeOut }) {
  if (!item.eol_date) return <span className="text-slate-600">—</span>
  const days = item.days_to_eol
  const note = days === null ? '' : days < 0 ? '（終了済み）' : `（あと ${days} 日）`
  return (
    <span className="tabular-nums">
      {item.eol_date}
      <span className="text-slate-500">{note}</span>
    </span>
  )
}

// 左のアプリ一覧に出すバッジ。対応が必要な数を目立たせ、無いアプリは検出した数を薄く出す
function RepoBadge({ stat }: { stat: RepoRuntimeRepoStat }) {
  if (stat.needs_action === 0) {
    return <span className="text-slate-500 tabular-nums" title="検出した言語・実行環境の数">{stat.total}</span>
  }
  return (
    <span
      className="px-1.5 rounded-full bg-orange-500/15 text-orange-400 font-semibold tabular-nums"
      title="対応が必要な数（サポート終了・期限間近・更新あり）"
    >
      {stat.needs_action}
    </span>
  )
}

// 言語ごとの推奨の版（サポート中で、公開から経った最新）。何に更新すればよいかの目安
function RecommendedStrip({ releases }: { releases: RuntimeReleaseOut[] }) {
  const recommended = releases.filter(r => r.recommended)
  if (recommended.length === 0) return null
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-400" aria-label="推奨の版">
      <span className="text-slate-500">推奨の版</span>
      {recommended.map(r => (
        <span key={r.runtime} className="tabular-nums">
          <span className="text-slate-300">{r.runtime_label} {r.cycle}</span>
          <span className="text-slate-500">（最新 {r.latest_version}）</span>
        </span>
      ))}
    </div>
  )
}

function RuntimesDialog({ onClose, authToken }: { onClose: () => void; authToken?: string }) {
  const [filters, setFilters] = useState<Filters>(INITIAL_FILTERS)
  const [list, setList] = useState<ListResult | null>(null)
  const [repoList, setRepoList] = useState<{ operating: OperatingStatus; repos: RepoRuntimeRepoStat[] } | null>(null)
  const [releases, setReleases] = useState<RuntimeReleaseOut[]>([])

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  // 一覧。条件が変わるたびに取り直す。状態の更新は取得の完了時だけ行う
  // （効果の中で同期的に更新しない。条件の変更で古い取得が遅れて届いても、結果を捨てる）
  useEffect(() => {
    let cancelled = false
    fetchRuntimes({
      repo: filters.repo, runtime: filters.runtime, needsAction: filters.needsActionOnly,
      operating: filters.operating, authToken,
    })
      .then(res => {
        if (!cancelled) setList({ filters, items: res.data, failed: false })
      })
      .catch(() => {
        if (!cancelled) setList({ filters, items: [], failed: true })
      })
    return () => { cancelled = true }
  }, [filters, authToken])

  // 左のアプリ一覧。運用状態を切り替えたときだけ取り直す
  useEffect(() => {
    let cancelled = false
    fetchRuntimeRepos(authToken, filters.operating)
      .then(res => {
        if (!cancelled) setRepoList({ operating: filters.operating, repos: res.repos })
      })
      .catch(() => {
        if (!cancelled) setRepoList({ operating: filters.operating, repos: [] })
      })
    return () => { cancelled = true }
  }, [authToken, filters.operating])

  // 推奨の版の表示。開いたときに1回だけ取得する（失敗しても、一覧の表示は妨げない）
  useEffect(() => {
    let cancelled = false
    fetchRuntimeReleases(authToken)
      .then(res => { if (!cancelled) setReleases(res.data) })
      .catch(() => { if (!cancelled) setReleases([]) })
    return () => { cancelled = true }
  }, [authToken])

  function update(patch: Partial<Filters>) {
    setFilters(f => ({ ...f, ...patch }))
  }

  function handleOperating(operating: OperatingStatus) {
    // 切り替え先に無いアプリを選んだままにしないよう、アプリの選択は外す
    update({ operating, repo: null })
  }

  const loading = list === null || list.filters !== filters
  const repos = repoList?.operating === filters.operating ? repoList.repos : []

  return (
    <div
      className="fixed inset-0 z-50 bg-slate-950 flex flex-col"
      role="dialog"
      aria-modal="true"
      aria-label="言語・実行環境"
    >
      <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 shrink-0">
        <span className="flex items-center gap-2 text-sm font-semibold text-slate-300 uppercase tracking-wider">
          <Cpu size={16} className="text-slate-400" />
          言語・実行環境
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
            各アプリが使っている Python・Node.js・Flutter・Dart の版と、サポート期限です。
            サポートが終わった版には、セキュリティ修正が提供されません。左でアプリを選ぶと、そのアプリの設定を見られます。
          </p>

          <RecommendedStrip releases={releases} />

          <div className="flex flex-wrap items-center gap-3">
            <OperatingFilter value={filters.operating} onChange={handleOperating} />
          </div>

          <div className="flex flex-col md:flex-row gap-4">
            <RepoRail
              selected={filters.repo}
              onSelect={repo => update({ repo })}
              allBadge={
                <span className="text-slate-500 tabular-nums">
                  {repos.reduce((n, r) => n + r.total, 0)}
                </span>
              }
              items={repos.map(r => ({
                key: r.repo_full_name,
                label: repoShortName(r.repo_full_name),
                muted: r.needs_action === 0,
                badge: <RepoBadge stat={r} />,
              }))}
            />

            <div className="flex-1 min-w-0 flex flex-col gap-4">
              <div className="flex flex-wrap items-end gap-3">
                <label className="flex flex-col gap-1 text-xs text-slate-400">
                  言語
                  <select
                    value={filters.runtime ?? ''}
                    onChange={e => update({ runtime: e.target.value || null })}
                    className={`${INPUT_CLS} w-32`}
                  >
                    <option value="">すべて</option>
                    {RUNTIME_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                </label>
                <button
                  type="button"
                  onClick={() => update({ needsActionOnly: !filters.needsActionOnly })}
                  aria-pressed={filters.needsActionOnly}
                  className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap border transition-colors ${
                    filters.needsActionOnly
                      ? 'bg-orange-500/15 text-orange-400 border-orange-500/30'
                      : 'bg-slate-800/60 text-slate-500 border-slate-700 hover:text-slate-300'
                  }`}
                >
                  <AlertTriangle size={12} />
                  更新が必要なものだけ
                </button>
              </div>

              {loading ? (
                <TableLoadingSkeleton columnWidths={['w-40', 'w-24', 'w-24', 'w-32', 'flex-1']} />
              ) : list.failed ? (
                <EmptyState icon={<Cpu size={24} />} message="取得に失敗しました。時間をおいて再度お試しください" />
              ) : list.items.length === 0 ? (
                <EmptyState
                  icon={<Cpu size={24} />}
                  message={filters.needsActionOnly
                    ? '更新が必要な言語・実行環境はありません'
                    : '該当する言語・実行環境はありません'}
                />
              ) : (
                <div className="overflow-x-auto -mx-1 px-1">
                  <table aria-label="言語・実行環境一覧" className="w-full text-sm min-w-[760px]">
                    <thead>
                      <tr className="border-b border-slate-800">
                        {!filters.repo && <th className={`${TH} w-48`}>アプリ</th>}
                        <th className={`${TH} w-24`}>言語</th>
                        <th className={`${TH} w-28`}>使っている版</th>
                        <th className={`${TH} w-36`}>状態</th>
                        <th className={`${TH} w-28`}>推奨の版</th>
                        <th className={`${TH} w-44`}>サポート終了</th>
                        <th className={TH}>設定ファイル</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {list.items.map(item => (
                        <tr key={`${item.repo_full_name}-${item.runtime}-${item.cycle}-${item.source_path}`}>
                          {!filters.repo && (
                            <td className="py-2.5 pr-3">
                              <p className="text-slate-300 text-xs truncate max-w-[200px]">{item.repo_full_name}</p>
                            </td>
                          )}
                          <td className="py-2.5 pr-3 text-xs text-slate-200">{item.runtime_label}</td>
                          <td className="py-2.5 pr-3 text-xs text-slate-300 tabular-nums">
                            {item.cycle}
                            {!item.pinned && <span className="text-slate-600">{' 以上'}</span>}
                            {item.latest_version && (
                              <p className="text-[10px] text-slate-500">最新 {item.latest_version}</p>
                            )}
                          </td>
                          <td className="py-2.5 pr-3"><StateBadge state={item.state} /></td>
                          <td className="py-2.5 pr-3 text-xs text-slate-300 tabular-nums">
                            {item.recommended_cycle ?? <span className="text-slate-600">—</span>}
                          </td>
                          <td className="py-2.5 pr-3 text-xs text-slate-400"><EolCell item={item} /></td>
                          <td className="py-2.5 text-xs text-slate-500 break-all">{item.source_path}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// 使っている言語・実行環境の版と、サポート期限から判定した状態を、アプリごとに閲覧する全画面モーダル。
// DEPSCAN タブ内のボタンから開く（依存パッケージ・Dependabot 運用状況と同じ設計。5つ目の固定タブにはしない）。
// 開いたときにだけ内側を組み立てるため、閉じている間は取得しない。
export function RuntimesModal({
  open, onClose, authToken,
}: { open: boolean; onClose: () => void; authToken?: string }) {
  if (!open) return null
  return <RuntimesDialog onClose={onClose} authToken={authToken} />
}
