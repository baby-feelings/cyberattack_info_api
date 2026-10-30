import { useState } from 'react'
import { ExternalLink, ChevronDown, ChevronUp, CheckCircle2 } from 'lucide-react'
import { SeverityBadge } from '../shared/VulnPanelParts'
import { ExceptionControl, ExceptionTag } from '../shared/ExceptionControl'
import { githubRepoUrl, osvUrl } from '../shared/externalLinks'

import {
  SEVERITY_CLS, severityRank,
  groupFixedVersions, groupIsResolved, groupLatestDetectedAt,
  groupReachability,
  type FindingGroup,
} from './grouping'

const REACHABILITY_LABELS: Record<string, { label: string; cls: string }> = {
  reachable: { label: '到達可能', cls: 'bg-red-500/15 text-red-400 border-red-500/30' },
  unreachable: { label: '未使用の可能性', cls: 'bg-slate-700/40 text-slate-400 border-slate-600' },
  unknown: { label: '不明', cls: 'bg-slate-800 text-slate-500 border-slate-700' },
}

function ReachabilityBadge({ reachability }: { reachability: string | null }) {
  const info = REACHABILITY_LABELS[reachability ?? 'unknown'] ?? REACHABILITY_LABELS.unknown
  return (
    <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-medium border whitespace-nowrap ${info.cls}`}>
      {info.label}
    </span>
  )
}

// GitHub APIの"private"フィールドから自動取得した公開範囲（Issue #131）。
// publicの方が露出リスクが高いため目立たせ、privateは控えめに、
// 旧レコード（未取得でnull）は何も表示しない
function RepoVisibilityBadge({ visibility }: { visibility: 'public' | 'private' | null }) {
  if (visibility === null) return null
  return visibility === 'public' ? (
    <span className="inline-block px-1 py-0.5 rounded text-[9px] font-medium bg-amber-500/15 text-amber-400 border border-amber-500/30 whitespace-nowrap">
      Public
    </span>
  ) : (
    <span className="inline-block px-1 py-0.5 rounded text-[9px] font-medium bg-slate-700/40 text-slate-500 border border-slate-600 whitespace-nowrap">
      Private
    </span>
  )
}

// 優先度判定に寄与した要因の日本語ラベル（Issue #135）
const PRIORITY_REASON_LABELS: Record<string, string> = {
  kev_listed: 'KEV掲載',
  epss_high: 'EPSS高',
  reachable: '到達可能',
  public_repo: '公開リポジトリ',
  internet_facing_asset: 'ネット公開資産',
  production_asset: '本番資産',
  high_importance_asset: '重要度high',
  malicious_package: '悪意あるパッケージ',
}

// 悪意あるパッケージは脆弱性ではなくマルウェアで、対応が「更新」ではなく「削除と認証情報の再発行」に
// なるため、グループ行の重要度の横で最優先に目立たせる
function MaliciousBadge({ show }: { show: boolean }) {
  if (!show) return null
  return (
    <span
      title="脆弱性ではなくマルウェアです。該当バージョンを削除し、認証情報を再発行してください"
      className="inline-flex items-center px-1 py-0.5 rounded text-[9px] font-bold bg-fuchsia-500/20 text-fuchsia-300 border border-fuchsia-500/50 whitespace-nowrap"
    >
      🛑 悪意あり
    </span>
  )
}

// KEV掲載は最も緊急度が高いシグナルのため、グループ行に集約表示する際は
// これだけを別枠で目立たせる（他の理由は展開時のCVE単位の内訳で確認する）
function KevListedBadge({ show }: { show: boolean }) {
  if (!show) return null
  return (
    <span className="inline-flex items-center px-1 py-0.5 rounded text-[9px] font-bold bg-red-500/20 text-red-400 border border-red-500/40 whitespace-nowrap">
      KEV
    </span>
  )
}

function PriorityReasonBadges({ reasons }: { reasons: string[] }) {
  if (reasons.length === 0) return null
  return (
    <div className="flex flex-wrap gap-1 mt-1">
      {reasons.map(reason => (
        <span
          key={reason}
          className="inline-block px-1 py-0.5 rounded text-[9px] font-medium bg-violet-500/15 text-violet-400 border border-violet-500/30 whitespace-nowrap"
        >
          {PRIORITY_REASON_LABELS[reason] ?? reason}
        </span>
      ))}
    </div>
  )
}

// showRepo=false のときはリポジトリ列を隠す（左の一覧でアプリを選んでいて、リポジトリが自明なため）
// authToken: ログイン中のセッショントークン（例外の登録・解除に使う。無ければ操作できない）
// onExceptionChanged: 例外を登録・解除したとき（一覧と件数を読み直す）
interface DepscanGroupRowProps {
  group: FindingGroup
  showRepo?: boolean
  authToken?: string
  onExceptionChanged?: () => void
}

export function DepscanGroupRow({
  group, showRepo = true, authToken, onExceptionChanged,
}: DepscanGroupRowProps) {
  const [open, setOpen] = useState(false)
  const bestSeverity = group.findings
    .slice()
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))[0].severity
  const fixedVersions = groupFixedVersions(group)
  const reachability = groupReachability(group)
  const hasKevListed = group.findings.some(f => f.priority_reasons.includes('kev_listed'))
  const hasMalicious = group.findings.some(f => f.is_malicious)
  // 全件が例外（受容など）のグループは、一覧でも分かるようにする（件数からは外れている）
  const allExcepted = group.findings.every(f => f.exception)
  const latestDate = new Date(groupLatestDetectedAt(group)).toLocaleDateString('ja-JP', {
    year: 'numeric', month: 'short', day: 'numeric',
  })

  return (
    <>
      <tr
        aria-expanded={open}
        className="hover:bg-slate-800/40 transition-colors cursor-pointer"
        onClick={() => setOpen(o => !o)}
      >
        <td className="py-2.5 pr-3 w-20">
          <div className="flex items-center gap-1">
            <SeverityBadge severity={bestSeverity} classMap={SEVERITY_CLS} />
            <KevListedBadge show={hasKevListed} />
            <MaliciousBadge show={hasMalicious} />
            {allExcepted && group.findings[0].exception && (
              <ExceptionTag exception={group.findings[0].exception} />
            )}
          </div>
          <span className="block text-[10px] text-slate-600 mt-0.5 tabular-nums">
            計{group.findings.length}件
          </span>
        </td>

        {/* リポジトリ */}
        {showRepo && <td className="py-2.5 pr-3 w-52">
          <div className="flex items-center gap-1.5">
            <a
              href={githubRepoUrl(group.repo_full_name)}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-slate-300 hover:text-white text-xs transition-colors truncate max-w-[160px]"
              onClick={e => e.stopPropagation()}
            >
              {group.repo_full_name}
              <ExternalLink size={9} className="shrink-0" />
            </a>
            <RepoVisibilityBadge visibility={group.findings[0].repo_visibility} />
          </div>
          {groupIsResolved(group) && (
            <span className="inline-flex items-center gap-0.5 mt-0.5 text-[10px] text-emerald-500">
              <CheckCircle2 size={9} /> 解決済み
            </span>
          )}
        </td>}

        {/* パッケージ */}
        <td className="py-2.5 pr-3 w-40">
          <p className="text-slate-300 font-mono text-xs">{group.package_name}</p>
          <p className="text-slate-600 text-[10px] mt-0.5 font-mono">{group.installed_version}</p>
        </td>

        {/* 修正版 */}
        <td className="py-2.5 pr-3 w-32">
          {fixedVersions.length > 0 ? (
            <p className="text-emerald-500 text-[10px] font-mono">
              {fixedVersions[0]}
              {fixedVersions.length > 1 && ` +${fixedVersions.length - 1}`}
            </p>
          ) : (
            <span className="text-slate-700 text-xs">未提供</span>
          )}
        </td>

        {/* 到達可能性 */}
        <td className="py-2.5 pr-3 w-24">
          <ReachabilityBadge reachability={reachability} />
        </td>

        <td className="py-2.5 text-xs text-slate-600 tabular-nums whitespace-nowrap w-24">
          {latestDate}
        </td>

        <td className="py-2.5 pl-2 text-right w-5">
          {open
            ? <ChevronUp size={12} className="text-slate-500 ml-auto" />
            : <ChevronDown size={12} className="text-slate-500 ml-auto" />}
        </td>
      </tr>

      {/* 展開: 個々のCVE一覧 */}
      {open && (
        <tr className="bg-slate-800/30">
          <td colSpan={showRepo ? 7 : 6} className="px-4 py-3 text-xs text-slate-400">
            <p className="text-slate-500 mb-2">
              ロックファイル: <span className="font-mono text-slate-400">{group.findings[0].manifest_path}</span>
            </p>
            <div className="space-y-2.5">
              {group.findings
                .slice()
                .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
                .map(f => (
                  <div key={f.osv_id} className="flex flex-col gap-1 border-l-2 border-slate-700 pl-2.5">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={f.severity} classMap={SEVERITY_CLS} />
                      {f.cvss_score != null && (
                        <span className="text-[10px] text-slate-600 tabular-nums">{f.cvss_score.toFixed(1)}</span>
                      )}
                      <a
                        href={osvUrl(f.osv_id)}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-violet-400 hover:text-violet-300 font-mono text-[10px]"
                      >
                        {f.osv_id}
                        <ExternalLink size={8} />
                      </a>
                    </div>
                    <p className="leading-relaxed">{f.summary}</p>
                    <PriorityReasonBadges reasons={f.priority_reasons} />
                    {f.fixed_versions.length > 0 && (
                      <p className="flex flex-wrap items-center gap-1">
                        <span className="text-slate-500">修正版:</span>
                        {f.fixed_versions.map(v => (
                          <span key={v} className="text-emerald-500 font-mono text-[10px]">{v}</span>
                        ))}
                      </p>
                    )}
                    {f.exception_key && (
                      <ExceptionControl
                        kind="dependency"
                        repo={f.repo_full_name}
                        findingKey={f.exception_key}
                        exception={f.exception}
                        authToken={authToken}
                        onChanged={() => onExceptionChanged?.()}
                      />
                    )}
                  </div>
                ))}
            </div>
          </td>
        </tr>
      )}
    </>
  )
}
