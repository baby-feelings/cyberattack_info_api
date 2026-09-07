import { useState } from 'react'
import { ExternalLink, ChevronDown, ChevronUp } from 'lucide-react'
import { type VulnerabilityOut } from '../../api/client'

// EPSSスコア（0.0〜1.0）の高さに応じた色分け（重要度バッジに準じた配色）
function epssColorClass(score: number): string {
  if (score >= 0.5) return 'text-red-400'
  if (score >= 0.1) return 'text-orange-400'
  if (score >= 0.01) return 'text-amber-400'
  return 'text-slate-500'
}

export function KevRow({ item }: { item: VulnerabilityOut }) {
  const [open, setOpen] = useState(false)
  const dateAdded = new Date(item.date_added).toLocaleDateString('ja-JP', {
    year: 'numeric', month: 'short', day: 'numeric',
  })

  return (
    <>
      <tr
        className="hover:bg-slate-800/40 transition-colors cursor-pointer"
        onClick={() => setOpen(o => !o)}
      >
        <td className="py-2.5 pr-3">
          <a
            href={`https://nvd.nist.gov/vuln/detail/${item.cve_id}`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 font-mono text-violet-400 hover:text-violet-300 text-xs transition-colors"
            onClick={e => e.stopPropagation()}
          >
            {item.cve_id}
            <ExternalLink size={9} />
          </a>
        </td>
        <td className="py-2.5 pr-3 text-xs tabular-nums whitespace-nowrap">
          {item.epss_score !== null ? (
            <span className={epssColorClass(item.epss_score)}>
              {(item.epss_score * 100).toFixed(1)}%
            </span>
          ) : (
            <span className="text-slate-700">—</span>
          )}
        </td>
        <td className="py-2.5 pr-3">
          <p className="text-slate-300 text-xs truncate max-w-[160px]">{item.vendor_project}</p>
        </td>
        <td className="py-2.5 pr-3">
          <p className="text-slate-300 text-xs truncate max-w-[160px]">{item.product}</p>
        </td>
        <td className="py-2.5 pr-3">
          <p className="text-slate-400 text-xs truncate max-w-[280px]">{item.vulnerability_name}</p>
        </td>
        <td className="py-2.5 text-xs text-slate-600 tabular-nums whitespace-nowrap">
          {dateAdded}
        </td>
        <td className="py-2.5 pl-2 text-right">
          {open
            ? <ChevronUp size={12} className="text-slate-500 ml-auto" />
            : <ChevronDown size={12} className="text-slate-500 ml-auto" />}
        </td>
      </tr>

      {/* 展開: 詳細説明・推奨対処・EPSS詳細 */}
      {open && (
        <tr className="bg-slate-800/30">
          <td colSpan={7} className="px-4 py-3 text-xs text-slate-400 space-y-2">
            <p className="leading-relaxed whitespace-pre-wrap">{item.description}</p>
            {item.required_action && (
              <p>
                <span className="text-slate-500">推奨対処:</span> {item.required_action}
              </p>
            )}
            {item.epss_score !== null && (
              <p>
                <span className="text-slate-500">EPSS（悪用確率）:</span>{' '}
                <span className={epssColorClass(item.epss_score)}>
                  {(item.epss_score * 100).toFixed(2)}%
                </span>
                {item.epss_percentile !== null && (
                  <> （パーセンタイル {(item.epss_percentile * 100).toFixed(1)}%）</>
                )}
                {item.epss_updated_at && (
                  <span className="text-slate-600">
                    {' '}· 更新: {new Date(item.epss_updated_at).toLocaleDateString('ja-JP')}
                  </span>
                )}
              </p>
            )}
          </td>
        </tr>
      )}
    </>
  )
}
