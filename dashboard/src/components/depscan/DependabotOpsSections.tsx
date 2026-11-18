import { ExternalLink } from 'lucide-react'
import type { DependabotPrLogOut } from '../../api/client'
import { githubPullUrl } from '../shared/externalLinks'
import { ACTIONS, DEPSOPS_TEXT as T, TH, type ActionFilter } from './dependabotOpsConfig'

// 解決済みのPR（DEPSOPS外の要因で解消）は履歴ごと削除されるため、一覧に出るのは
// 自動マージ済みと要確認（未解決）のみ（app/depsops/runner.py の _record_pr_logs 参照）
function ActionBadge({ action }: { action: 'merged' | 'flagged' }) {
  if (action === 'merged') {
    return (
      <span className="inline-block px-1.5 py-0.5 rounded text-xs font-medium bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
        {T.merged}
      </span>
    )
  }
  return (
    <span className="inline-block px-1.5 py-0.5 rounded text-xs font-medium bg-amber-500/15 text-amber-400 border border-amber-500/30">
      {T.flagged}
    </span>
  )
}

// GitHub Dependabot alert のパッケージ名とPRタイトルのヒューリスティックな
// 照合結果（バックエンド側判定。あくまで参考情報）
function SecurityUpdateBadge({ isSecurityUpdate }: { isSecurityUpdate: boolean | null }) {
  if (isSecurityUpdate === null) {
    return <span className="text-[10px] text-slate-600">{T.unknown}</span>
  }
  return isSecurityUpdate ? (
    <span className="inline-block px-1.5 py-0.5 rounded text-[10px] font-medium bg-red-500/15 text-red-400 border border-red-500/30 whitespace-nowrap">
      {T.securityUpdate}
    </span>
  ) : (
    <span className="text-[10px] text-slate-600 whitespace-nowrap">{T.versionUpdate}</span>
  )
}

// Dependabot が PR 本文に埋め込む Compatibility score バッジ（GitHub提供の画像）。
// exact version bump のPRにのみ存在し、範囲指定の requirement 更新PR等には無い
function CompatibilityScoreBadge({ badgeUrl }: { badgeUrl: string | null }) {
  if (!badgeUrl) {
    return <span className="text-[10px] text-slate-600">—</span>
  }
  return <img src={badgeUrl} alt={T.scoreAlt} className="h-5 max-w-[160px]" loading="lazy" />
}

// 判定の絞り込みボタン（すべて・自動マージ・要確認）
export function ActionFilterButtons({
  action, onChange,
}: { action: ActionFilter; onChange: (action: ActionFilter) => void }) {
  return (
    <div role="group" aria-label={T.actionGroup} className="flex flex-wrap gap-1.5">
      {ACTIONS.map(a => (
        <button
          key={a.key}
          onClick={() => onChange(a.key)}
          aria-pressed={action === a.key}
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
  )
}

// PR 判定履歴の表
export function DependabotOpsTable({ items }: { items: DependabotPrLogOut[] }) {
  return (
    <div className="overflow-x-auto -mx-1 px-1">
      <table aria-label={T.tableLabel} className="w-full text-sm min-w-[860px]">
        <thead>
          <tr className="border-b border-slate-800">
            <th className={`${TH} w-48`}>{T.columns.repo}</th>
            <th className={`${TH} w-40`}>{T.columns.score}</th>
            <th className={TH}>{T.columns.pr}</th>
            <th className={`${TH} w-28`}>{T.columns.action}</th>
            <th className={`${TH} w-28`}>{T.columns.kind}</th>
            <th className={`${TH} w-24`}>{T.columns.date}</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/60">
          {items.map(item => (
            <tr key={`${item.repo_full_name}-${item.pr_number}-${item.processed_at}`}>
              <td className="py-2.5 pr-3">
                <p className="text-slate-300 text-xs truncate max-w-[220px]">{item.repo_full_name}</p>
              </td>
              <td className="py-2.5 pr-3">
                <CompatibilityScoreBadge badgeUrl={item.compatibility_badge_url} />
              </td>
              <td className="py-2.5 pr-3">
                <a
                  href={githubPullUrl(item.repo_full_name, item.pr_number)}
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
  )
}
