import type { FormEvent } from 'react'
import { Search, Bug } from 'lucide-react'
import type { RepoDependencyOut, RepoDependencyRepoStat } from '../../api/client'
import { DEPENDENCIES_TEXT as T, ECOSYSTEMS, INPUT_CLS, TH } from './dependenciesConfig'

// 未解決の検知がある版は赤く目立たせる（対応が必要な版を一目で区別するため）
export function OpenVulnBadge({ count }: { count: number | null }) {
  if (!count) {
    return <span className="text-[10px] text-slate-600">{T.noFinding}</span>
  }
  return (
    <span className="inline-block px-1.5 py-0.5 rounded text-xs font-medium bg-red-500/15 text-red-400 border border-red-500/30 whitespace-nowrap">
      {T.openFindings(count)}
    </span>
  )
}

// 左のアプリ一覧に出すバッジ。脆弱性のある依存の数を目立たせ、無いアプリは依存の総数を薄く出す
export function RepoBadge({ stat }: { stat: RepoDependencyRepoStat }) {
  if (stat.vulnerable === 0) {
    return <span className="text-slate-500 tabular-nums" title={T.repoTotalTitle}>{stat.total}</span>
  }
  return (
    <span
      className="px-1.5 rounded-full bg-red-500/15 text-red-400 font-semibold tabular-nums"
      title={T.repoVulnerableTitle}
    >
      {stat.vulnerable}
    </span>
  )
}

// 検索フォーム（パッケージ名・版・エコシステム・脆弱性ありのみ）。入力欄の文字は、検索で確定する
export function DependenciesSearchForm({
  packageText, onPackageText, versionText, onVersionText, ecosystem, onEcosystem,
  vulnerableOnly, onToggleVulnerable, onSubmit,
}: {
  packageText: string
  onPackageText: (value: string) => void
  versionText: string
  onVersionText: (value: string) => void
  ecosystem: string | null
  onEcosystem: (value: string | null) => void
  vulnerableOnly: boolean
  onToggleVulnerable: () => void
  onSubmit: (e: FormEvent) => void
}) {
  return (
    <form onSubmit={onSubmit} className="flex flex-wrap items-end gap-3" role="search">
      <label className="flex flex-col gap-1 text-xs text-slate-400">
        {T.packageName}
        <input
          type="text"
          value={packageText}
          onChange={e => onPackageText(e.target.value)}
          placeholder={T.packagePlaceholder}
          className={`${INPUT_CLS} w-48`}
        />
      </label>
      <label className="flex flex-col gap-1 text-xs text-slate-400">
        {T.version}
        <input
          type="text"
          value={versionText}
          onChange={e => onVersionText(e.target.value)}
          placeholder={T.versionPlaceholder}
          className={`${INPUT_CLS} w-32`}
        />
      </label>
      <label className="flex flex-col gap-1 text-xs text-slate-400">
        {T.ecosystem}
        <select
          value={ecosystem ?? ''}
          onChange={e => onEcosystem(e.target.value || null)}
          className={`${INPUT_CLS} w-28`}
        >
          <option value="">{T.all}</option>
          {ECOSYSTEMS.map(eco => <option key={eco} value={eco}>{eco}</option>)}
        </select>
      </label>
      <button
        type="submit"
        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium whitespace-nowrap bg-violet-600 text-white hover:bg-violet-500 transition-colors"
      >
        <Search size={14} />
        {T.search}
      </button>
      <button
        type="button"
        onClick={onToggleVulnerable}
        aria-pressed={vulnerableOnly}
        className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap border transition-colors ${
          vulnerableOnly
            ? 'bg-red-500/15 text-red-400 border-red-500/30'
            : 'bg-slate-800/60 text-slate-500 border-slate-700 hover:text-slate-300'
        }`}
      >
        <Bug size={12} />
        {T.vulnerableOnly}
      </button>
    </form>
  )
}

// 依存パッケージの表。アプリを1つ選んでいるときは、アプリの列を出さない
export function DependenciesTable({ items, showRepo }: { items: RepoDependencyOut[]; showRepo: boolean }) {
  return (
    <div className="overflow-x-auto -mx-1 px-1">
      <table aria-label={T.tableLabel} className="w-full text-sm min-w-[640px]">
        <thead>
          <tr className="border-b border-slate-800">
            {showRepo && <th className={`${TH} w-52`}>{T.columns.app}</th>}
            <th className={`${TH} w-48`}>{T.columns.package}</th>
            <th className={`${TH} w-28`}>{T.columns.version}</th>
            <th className={`${TH} w-28`}>{T.columns.vulnerability}</th>
            <th className={TH}>{T.columns.lockfile}</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/60">
          {items.map(item => (
            <tr key={`${item.repo_full_name}-${item.ecosystem}-${item.package_name}-${item.version}-${item.manifest_path}`}>
              {showRepo && (
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
  )
}
