import { useState } from 'react'
import { ExternalLink, ChevronDown, ChevronUp } from 'lucide-react'
import { type OsvVulnerabilityOut } from '../../api/client'
import { SeverityBadge } from '../shared/VulnPanelParts'

// エコシステムバッジの色
const ECO_COLOR: Record<string, string> = {
  PyPI:       'bg-sky-500/15 text-sky-400',
  npm:        'bg-red-500/15 text-red-400',
  Go:         'bg-cyan-500/15 text-cyan-400',
  Maven:      'bg-amber-500/15 text-amber-400',
  RubyGems:   'bg-rose-500/15 text-rose-400',
  NuGet:      'bg-violet-500/15 text-violet-400',
  'crates.io': 'bg-orange-500/15 text-orange-400',
  Packagist:  'bg-indigo-500/15 text-indigo-400',
  Hex:        'bg-emerald-500/15 text-emerald-400',
  Pub:        'bg-teal-500/15 text-teal-400',
}

function EcoBadge({ eco }: { eco: string }) {
  const cls = ECO_COLOR[eco] ?? 'bg-slate-700 text-slate-400'
  return (
    <span className={`inline-block px-1.5 py-0.5 rounded text-xs font-medium whitespace-nowrap ${cls}`}>
      {eco}
    </span>
  )
}

export function OsvRow({
  item, severityClassMap,
}: { item: OsvVulnerabilityOut; severityClassMap: Record<string, string> }) {
  const [open, setOpen] = useState(false)
  const cveAliases = item.aliases.filter(a => a.startsWith('CVE-'))
  const modifiedDate = new Date(item.modified).toLocaleDateString('ja-JP', {
    year: 'numeric', month: 'short', day: 'numeric',
  })

  return (
    <>
      <tr
        className="hover:bg-slate-800/40 transition-colors cursor-pointer"
        onClick={() => setOpen(o => !o)}
      >
        <td className="py-2.5 pr-3">
          <SeverityBadge severity={item.severity} classMap={severityClassMap} />
          {item.cvss_score != null && (
            <span className="block text-[10px] text-slate-600 mt-0.5 tabular-nums">
              {item.cvss_score.toFixed(1)}
            </span>
          )}
        </td>
        <td className="py-2.5 pr-3">
          {/* OSV ID */}
          <a
            href={`https://osv.dev/vulnerability/${item.osv_id}`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 font-mono text-violet-400 hover:text-violet-300 text-xs transition-colors"
            onClick={e => e.stopPropagation()}
          >
            {item.osv_id}
            <ExternalLink size={9} />
          </a>
          {/* CVE エイリアス */}
          {cveAliases.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-0.5">
              {cveAliases.slice(0, 2).map(cve => (
                <a
                  key={cve}
                  href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[10px] font-mono text-slate-500 hover:text-slate-300"
                  onClick={e => e.stopPropagation()}
                >
                  {cve}
                </a>
              ))}
            </div>
          )}
        </td>
        <td className="py-2.5 pr-3">
          <EcoBadge eco={item.ecosystem} />
        </td>
        <td className="py-2.5 pr-3">
          <p className="text-slate-300 font-mono text-xs">{item.package_name}</p>
          {item.fixed_versions.length > 0 && (
            <p className="text-emerald-500 text-[10px] mt-0.5">
              fix: {item.fixed_versions[0]}
            </p>
          )}
        </td>
        <td className="py-2.5 pr-3">
          <p className="text-slate-400 text-xs truncate max-w-[240px]">{item.summary}</p>
        </td>
        <td className="py-2.5 text-xs text-slate-600 tabular-nums whitespace-nowrap">
          {modifiedDate}
        </td>
        <td className="py-2.5 pl-2 text-right">
          {open
            ? <ChevronUp size={12} className="text-slate-500 ml-auto" />
            : <ChevronDown size={12} className="text-slate-500 ml-auto" />}
        </td>
      </tr>

      {/* 展開: 詳細・修正バージョン・参考リンク */}
      {open && (
        <tr className="bg-slate-800/30">
          <td colSpan={7} className="px-4 py-3 text-xs text-slate-400 space-y-2">
            {item.details && (
              <p className="leading-relaxed whitespace-pre-wrap">{item.details}</p>
            )}
            {item.fixed_versions.length > 0 && (
              <p className="flex flex-wrap items-center gap-1.5">
                <span className="text-slate-500">修正済みバージョン:</span>
                {item.fixed_versions.map(v => (
                  <span key={v} className="px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 text-[10px] font-mono">
                    {v}
                  </span>
                ))}
              </p>
            )}
            {item.aliases.length > 0 && (
              <p className="flex flex-wrap items-center gap-1.5">
                <span className="text-slate-500">エイリアス:</span>
                {item.aliases.map(a => (
                  <span key={a} className="text-[10px] font-mono text-slate-500">{a}</span>
                ))}
              </p>
            )}
            {item.references.length > 0 && (
              <div className="flex flex-wrap gap-2">
                {item.references.map(url => (
                  <a
                    key={url}
                    href={url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-violet-400 hover:text-violet-300 underline underline-offset-2 text-[10px] break-all"
                  >
                    {url}
                  </a>
                ))}
              </div>
            )}
          </td>
        </tr>
      )}
    </>
  )
}
