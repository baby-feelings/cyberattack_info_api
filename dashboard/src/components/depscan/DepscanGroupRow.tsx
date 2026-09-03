import { useState } from 'react'
import { ExternalLink, ChevronDown, ChevronUp, CheckCircle2 } from 'lucide-react'
import { SeverityBadge } from '../shared/VulnPanelParts'
import {
  SEVERITY_CLS, severityRank,
  groupFixedVersions, groupSeverityCounts, groupIsResolved, groupLatestDetectedAt,
  type FindingGroup,
} from './grouping'

export function DepscanGroupRow({ group }: { group: FindingGroup }) {
  const [open, setOpen] = useState(false)
  const bestSeverity = group.findings
    .slice()
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))[0].severity
  const fixedVersions = groupFixedVersions(group)
  const severityCounts = groupSeverityCounts(group)
  const latestDate = new Date(groupLatestDetectedAt(group)).toLocaleDateString('ja-JP', {
    year: 'numeric', month: 'short', day: 'numeric',
  })

  return (
    <>
      <tr
        className="hover:bg-slate-800/40 transition-colors cursor-pointer"
        onClick={() => setOpen(o => !o)}
      >
        <td className="py-2.5 pr-3 w-20">
          <SeverityBadge severity={bestSeverity} classMap={SEVERITY_CLS} />
          <span className="block text-[10px] text-slate-600 mt-0.5 tabular-nums">
            計{group.findings.length}件
          </span>
        </td>

        {/* リポジトリ */}
        <td className="py-2.5 pr-3 w-52">
          <a
            href={`https://github.com/${group.repo_full_name}`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-slate-300 hover:text-white text-xs transition-colors truncate max-w-[200px]"
            onClick={e => e.stopPropagation()}
          >
            {group.repo_full_name}
            <ExternalLink size={9} className="shrink-0" />
          </a>
          {groupIsResolved(group) && (
            <span className="inline-flex items-center gap-0.5 mt-0.5 text-[10px] text-emerald-500">
              <CheckCircle2 size={9} /> 解決済み
            </span>
          )}
        </td>

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

        {/* 重大度内訳 */}
        <td className="py-2.5 pr-3">
          <div className="flex flex-wrap gap-1">
            {severityCounts.map(([sev, count]) => (
              <span
                key={sev}
                className={`px-1.5 py-0.5 rounded text-[10px] font-medium border ${
                  SEVERITY_CLS[sev] ?? 'bg-slate-800 text-slate-500 border-slate-700'
                }`}
              >
                {sev}×{count}
              </span>
            ))}
          </div>
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
          <td colSpan={7} className="px-4 py-3 text-xs text-slate-400">
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
                        href={`https://osv.dev/vulnerability/${f.osv_id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-violet-400 hover:text-violet-300 font-mono text-[10px]"
                      >
                        {f.osv_id}
                        <ExternalLink size={8} />
                      </a>
                    </div>
                    <p className="leading-relaxed">{f.summary}</p>
                    {f.fixed_versions.length > 0 && (
                      <p className="flex flex-wrap items-center gap-1">
                        <span className="text-slate-500">修正版:</span>
                        {f.fixed_versions.map(v => (
                          <span key={v} className="text-emerald-500 font-mono text-[10px]">{v}</span>
                        ))}
                      </p>
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
