import { useEffect, useState, type FormEvent } from 'react'
import { X, Search, Package, Bug } from 'lucide-react'
import {
  fetchRepoDependencies, fetchRepoDependencyRepos,
  type OperatingStatus, type RepoDependencyOut, type RepoDependencyRepoStat,
} from '../../api/client'
import { TableLoadingSkeleton, EmptyState, Pagination } from '../shared/VulnPanelParts'
import { OperatingFilter } from '../shared/OperatingFilter'
import { RepoRail } from '../shared/RepoRail'
import { repoShortName } from '../shared/repoName'

const PER_PAGE = 20

// 絞り込みに使うエコシステム（DEPSCAN が対応するもののうち、自作アプリで使うもの）
const ECOSYSTEMS = ['npm', 'PyPI', 'Pub']

const INPUT_CLS =
  'rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-violet-500'

const TH = 'text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3'

// 表示に使う条件。変わるたびに取り直す（入力欄の文字は「検索」で確定するまで含めない）
interface Filters {
  repo: string | null
  operating: OperatingStatus
  vulnerableOnly: boolean
  ecosystem: string | null
  packageName: string
  version: string
  page: number
}

// 初期表示は運用中のアプリすべて。何も入力しなくても、使っている依存を一覧できる
const INITIAL_FILTERS: Filters = {
  repo: null, operating: 'active', vulnerableOnly: false, ecosystem: null,
  packageName: '', version: '', page: 1,
}

interface ListResult {
  // この結果を取得したときの条件。現在の条件と違えば「取得中」とみなす
  filters: Filters
  items: RepoDependencyOut[]
  total: number
  failed: boolean
}

// 未解決の検知がある版は赤く目立たせる（対応が必要な版を一目で区別するため）
function OpenVulnBadge({ count }: { count: number | null }) {
  if (!count) {
    return <span className="text-[10px] text-slate-600">検知なし</span>
  }
  return (
    <span className="inline-block px-1.5 py-0.5 rounded text-xs font-medium bg-red-500/15 text-red-400 border border-red-500/30 whitespace-nowrap">
      未解決 {count} 件
    </span>
  )
}

// 左のアプリ一覧に出すバッジ。脆弱性のある依存の数を目立たせ、無いアプリは依存の総数を薄く出す
function RepoBadge({ stat }: { stat: RepoDependencyRepoStat }) {
  if (stat.vulnerable === 0) {
    return <span className="text-slate-500 tabular-nums" title="使っている依存の数">{stat.total}</span>
  }
  return (
    <span
      className="px-1.5 rounded-full bg-red-500/15 text-red-400 font-semibold tabular-nums"
      title="未解決の検知がある依存の数"
    >
      {stat.vulnerable}
    </span>
  )
}

function DependenciesDialog({ onClose, authToken }: { onClose: () => void; authToken?: string }) {
  const [filters, setFilters] = useState<Filters>(INITIAL_FILTERS)
  // 入力欄の文字（「検索」またはEnterで filters に確定する）
  const [packageText, setPackageText] = useState('')
  const [versionText, setVersionText] = useState('')
  const [list, setList] = useState<ListResult | null>(null)
  const [repoList, setRepoList] = useState<{ operating: OperatingStatus; repos: RepoDependencyRepoStat[] } | null>(null)

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  // 依存の一覧。条件が変わるたびに取り直す。状態の更新は取得の完了時だけ行う
  // （効果の中で同期的に更新しない。条件の変更で古い取得が遅れて届いても、結果を捨てる）
  useEffect(() => {
    let cancelled = false
    fetchRepoDependencies({
      page: filters.page, perPage: PER_PAGE, packageName: filters.packageName,
      version: filters.version, ecosystem: filters.ecosystem, repo: filters.repo,
      vulnerableOnly: filters.vulnerableOnly, operating: filters.operating, authToken,
    })
      .then(res => {
        if (!cancelled) setList({ filters, items: res.data, total: res.total, failed: false })
      })
      .catch(() => {
        if (!cancelled) setList({ filters, items: [], total: 0, failed: true })
      })
    return () => { cancelled = true }
  }, [filters, authToken])

  // 左のアプリ一覧。運用状態を切り替えたときだけ取り直す
  useEffect(() => {
    let cancelled = false
    fetchRepoDependencyRepos(authToken, filters.operating)
      .then(res => {
        if (!cancelled) setRepoList({ operating: filters.operating, repos: res.repos })
      })
      .catch(() => {
        if (!cancelled) setRepoList({ operating: filters.operating, repos: [] })
      })
    return () => { cancelled = true }
  }, [authToken, filters.operating])

  function update(patch: Partial<Filters>) {
    setFilters(f => ({ ...f, ...patch, page: 1 }))
  }

  function handleOperating(operating: OperatingStatus) {
    // 切り替え先に無いアプリを選んだままにしないよう、アプリの選択は外す
    update({ operating, repo: null })
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    update({ packageName: packageText, version: versionText })
  }

  const loading = list === null || list.filters !== filters
  const repos = repoList?.operating === filters.operating ? repoList.repos : []
  const totalPages = list ? Math.ceil(list.total / PER_PAGE) : 0

  return (
    <div
      className="fixed inset-0 z-50 bg-slate-950 flex flex-col"
      role="dialog"
      aria-modal="true"
      aria-label="依存パッケージ"
    >
      <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 shrink-0">
        <span className="flex items-center gap-2 text-sm font-semibold text-slate-300 uppercase tracking-wider">
          <Package size={16} className="text-slate-400" />
          依存パッケージ
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
            各アプリが使っている依存パッケージの一覧です。左でアプリを選ぶと、そのアプリが使っている依存を見られます。
            新しい脆弱性が公表されたときは、パッケージ名で検索して、影響を受けるアプリと版を確認できます。
          </p>

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
                muted: r.vulnerable === 0,
                badge: <RepoBadge stat={r} />,
              }))}
            />

            <div className="flex-1 min-w-0 flex flex-col gap-4">
              <form onSubmit={handleSubmit} className="flex flex-wrap items-end gap-3" role="search">
                <label className="flex flex-col gap-1 text-xs text-slate-400">
                  パッケージ名（部分一致）
                  <input
                    type="text"
                    value={packageText}
                    onChange={e => setPackageText(e.target.value)}
                    placeholder="例: undici"
                    className={`${INPUT_CLS} w-48`}
                  />
                </label>
                <label className="flex flex-col gap-1 text-xs text-slate-400">
                  バージョン（完全一致）
                  <input
                    type="text"
                    value={versionText}
                    onChange={e => setVersionText(e.target.value)}
                    placeholder="例: 8.11.2"
                    className={`${INPUT_CLS} w-32`}
                  />
                </label>
                <label className="flex flex-col gap-1 text-xs text-slate-400">
                  エコシステム
                  <select
                    value={filters.ecosystem ?? ''}
                    onChange={e => update({ ecosystem: e.target.value || null })}
                    className={`${INPUT_CLS} w-28`}
                  >
                    <option value="">すべて</option>
                    {ECOSYSTEMS.map(eco => <option key={eco} value={eco}>{eco}</option>)}
                  </select>
                </label>
                <button
                  type="submit"
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium whitespace-nowrap bg-violet-600 text-white hover:bg-violet-500 transition-colors"
                >
                  <Search size={14} />
                  検索
                </button>
                <button
                  type="button"
                  onClick={() => update({ vulnerableOnly: !filters.vulnerableOnly })}
                  aria-pressed={filters.vulnerableOnly}
                  className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap border transition-colors ${
                    filters.vulnerableOnly
                      ? 'bg-red-500/15 text-red-400 border-red-500/30'
                      : 'bg-slate-800/60 text-slate-500 border-slate-700 hover:text-slate-300'
                  }`}
                >
                  <Bug size={12} />
                  脆弱性ありのみ
                </button>
              </form>

              {loading ? (
                <TableLoadingSkeleton columnWidths={['w-48', 'w-40', 'w-24', 'w-24', 'flex-1']} />
              ) : list.failed ? (
                <EmptyState icon={<Package size={24} />} message="取得に失敗しました。時間をおいて再度お試しください" />
              ) : list.items.length === 0 ? (
                <EmptyState
                  icon={<Package size={24} />}
                  message={filters.vulnerableOnly
                    ? '未解決の検知がある依存パッケージはありません'
                    : '該当する依存パッケージはありません'}
                />
              ) : (
                <>
                  <Pagination
                    page={filters.page} totalPages={totalPages} total={list.total}
                    onPageChange={updater => setFilters(f => ({ ...f, page: updater(f.page) }))}
                    position="top"
                  />

                  <div className="overflow-x-auto -mx-1 px-1">
                    <table aria-label="依存パッケージ一覧" className="w-full text-sm min-w-[640px]">
                      <thead>
                        <tr className="border-b border-slate-800">
                          {!filters.repo && <th className={`${TH} w-52`}>アプリ</th>}
                          <th className={`${TH} w-48`}>パッケージ</th>
                          <th className={`${TH} w-28`}>バージョン</th>
                          <th className={`${TH} w-28`}>脆弱性</th>
                          <th className={TH}>ロックファイル</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60">
                        {list.items.map(item => (
                          <tr key={`${item.repo_full_name}-${item.ecosystem}-${item.package_name}-${item.version}-${item.manifest_path}`}>
                            {!filters.repo && (
                              <td className="py-2.5 pr-3">
                                <p className="text-slate-300 text-xs truncate max-w-[220px]">{item.repo_full_name}</p>
                              </td>
                            )}
                            <td className="py-2.5 pr-3">
                              <p className="text-slate-200 text-xs break-all">{item.package_name}</p>
                              <p className="text-[10px] text-slate-500">{item.ecosystem}</p>
                            </td>
                            <td className="py-2.5 pr-3 text-xs text-slate-300 tabular-nums">{item.version}</td>
                            <td className="py-2.5 pr-3"><OpenVulnBadge count={item.open_vulnerabilities} /></td>
                            <td className="py-2.5 text-xs text-slate-500 break-all">{item.manifest_path}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  <Pagination
                    page={filters.page} totalPages={totalPages} total={list.total}
                    onPageChange={updater => setFilters(f => ({ ...f, page: updater(f.page) }))}
                  />
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// 使っている依存パッケージを、アプリごとに閲覧し、パッケージ名・版で検索する全画面モーダル。
// DEPSCAN タブ内のボタンから開く（Dependabot 運用状況と同じ設計。5つ目の固定タブにはしない）。
// 開いたときにだけ内側を組み立てるため、閉じている間は取得しない。
export function DependenciesModal({
  open, onClose, authToken,
}: { open: boolean; onClose: () => void; authToken?: string }) {
  if (!open) return null
  return <DependenciesDialog onClose={onClose} authToken={authToken} />
}
