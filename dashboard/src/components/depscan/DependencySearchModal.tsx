import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { X, Search, Package } from 'lucide-react'
import { fetchRepoDependencies, type RepoDependencyOut } from '../../api/client'
import { TableLoadingSkeleton, EmptyState, Pagination } from '../shared/VulnPanelParts'

const PER_PAGE = 20

// 絞り込みに使うエコシステム（DEPSCAN が対応するもののうち、自作アプリで使うもの）
const ECOSYSTEMS = ['npm', 'PyPI', 'Pub']

const INPUT_CLS =
  'rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-violet-500'

const TH = 'text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3'

interface Query {
  packageName: string
  version: string
  ecosystem: string | null
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

// 使っている依存パッケージを横断検索する全画面モーダル。DEPSCAN タブ内のボタンから開く
// （Dependabot 運用状況と同じ設計。5つ目の固定タブにはしない）。
// 入力のたびには検索せず、「検索」ボタン（Enter）で確定する（キー入力ごとの API 呼び出しを避ける）。
export function DependencySearchModal({
  open, onClose, authToken,
}: { open: boolean; onClose: () => void; authToken?: string }) {
  const [packageName, setPackageName] = useState('')
  const [version, setVersion] = useState('')
  const [ecosystem, setEcosystem] = useState<string | null>(null)
  // 確定済みの検索条件。null の間は未検索（入力を促す表示にする）
  const [query, setQuery] = useState<Query | null>(null)
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [items, setItems] = useState<RepoDependencyOut[]>([])
  const [loading, setLoading] = useState(false)
  const [failed, setFailed] = useState(false)

  const load = useCallback(async (q: Query, p: number) => {
    setLoading(true)
    setFailed(false)
    try {
      const res = await fetchRepoDependencies({
        page: p, perPage: PER_PAGE, packageName: q.packageName, version: q.version,
        ecosystem: q.ecosystem, authToken,
      })
      setItems(res.data)
      setTotal(res.total)
    } catch {
      setItems([])
      setTotal(0)
      setFailed(true)
    } finally {
      setLoading(false)
    }
  }, [authToken])

  useEffect(() => {
    if (!open) return
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [open, onClose])

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    // 何も入力せずに全件を引くのは意味が薄いため、パッケージ名か版のどちらかを必須にする
    if (!packageName.trim() && !version.trim()) return
    const q = { packageName, version, ecosystem }
    setPage(1)
    setQuery(q)
    load(q, 1)
  }

  // ページ送りは、確定済みの検索条件のまま取り直す（入力欄を編集中でも検索条件は変わらない）
  // Pagination は setState 形式（更新関数を受け取る）で呼ぶ
  function handlePage(updater: (p: number) => number) {
    if (!query) return
    const next = updater(page)
    setPage(next)
    load(query, next)
  }

  if (!open) return null

  const totalPages = Math.ceil(total / PER_PAGE)
  const canSearch = packageName.trim() !== '' || version.trim() !== ''

  return (
    <div
      className="fixed inset-0 z-50 bg-slate-950 flex flex-col"
      role="dialog"
      aria-modal="true"
      aria-label="依存パッケージ検索"
    >
      <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 shrink-0">
        <span className="flex items-center gap-2 text-sm font-semibold text-slate-300 uppercase tracking-wider">
          <Package size={16} className="text-slate-400" />
          依存パッケージ検索
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
          <p className="text-xs text-slate-500">
            どのリポジトリが、どのパッケージのどの版を使っているかを検索します
            （新しい脆弱性の影響範囲の確認に使えます）。
          </p>

          <form onSubmit={handleSubmit} className="flex flex-wrap items-end gap-3" role="search">
            <label className="flex flex-col gap-1 text-xs text-slate-400">
              パッケージ名（部分一致）
              <input
                type="text"
                value={packageName}
                onChange={e => setPackageName(e.target.value)}
                placeholder="例: undici"
                className={`${INPUT_CLS} w-56`}
              />
            </label>
            <label className="flex flex-col gap-1 text-xs text-slate-400">
              バージョン（完全一致）
              <input
                type="text"
                value={version}
                onChange={e => setVersion(e.target.value)}
                placeholder="例: 8.11.2"
                className={`${INPUT_CLS} w-36`}
              />
            </label>
            <label className="flex flex-col gap-1 text-xs text-slate-400">
              エコシステム
              <select
                value={ecosystem ?? ''}
                onChange={e => setEcosystem(e.target.value || null)}
                className={`${INPUT_CLS} w-32`}
              >
                <option value="">すべて</option>
                {ECOSYSTEMS.map(eco => <option key={eco} value={eco}>{eco}</option>)}
              </select>
            </label>
            <button
              type="submit"
              disabled={!canSearch}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium bg-violet-600 text-white hover:bg-violet-500 transition-colors disabled:opacity-40 disabled:hover:bg-violet-600"
            >
              <Search size={14} />
              検索
            </button>
          </form>

          {query === null ? (
            <EmptyState icon={<Search size={24} />} message="パッケージ名かバージョンを入力して検索してください" />
          ) : loading ? (
            <TableLoadingSkeleton columnWidths={['w-48', 'w-40', 'w-24', 'w-24', 'flex-1']} />
          ) : failed ? (
            <EmptyState icon={<Package size={24} />} message="検索に失敗しました。時間をおいて再度お試しください" />
          ) : items.length === 0 ? (
            <EmptyState icon={<Package size={24} />} message="該当する依存パッケージはありません" />
          ) : (
            <>
              <Pagination page={page} totalPages={totalPages} total={total} onPageChange={handlePage} position="top" />

              <div className="overflow-x-auto -mx-1 px-1">
                <table aria-label="依存パッケージ検索結果" className="w-full text-sm min-w-[720px]">
                  <thead>
                    <tr className="border-b border-slate-800">
                      <th className={`${TH} w-52`}>リポジトリ</th>
                      <th className={`${TH} w-48`}>パッケージ</th>
                      <th className={`${TH} w-28`}>バージョン</th>
                      <th className={`${TH} w-28`}>脆弱性</th>
                      <th className={TH}>ロックファイル</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {items.map(item => (
                      <tr key={`${item.repo_full_name}-${item.ecosystem}-${item.package_name}-${item.version}-${item.manifest_path}`}>
                        <td className="py-2.5 pr-3">
                          <p className="text-slate-300 text-xs truncate max-w-[220px]">{item.repo_full_name}</p>
                        </td>
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

              <Pagination page={page} totalPages={totalPages} total={total} onPageChange={handlePage} />
            </>
          )}
        </div>
      </div>
    </div>
  )
}
