import { useState } from 'react'
import { ExternalLink, ChevronDown, ChevronUp } from 'lucide-react'
import { type JvnVulnerabilityOut } from '../../api/client'
import { SeverityBadge } from '../shared/VulnPanelParts'

export function JvnRow({
  item, severityClassMap,
}: { item: JvnVulnerabilityOut; severityClassMap: Record<string, string> }) {
  const [open, setOpen] = useState(false)
  const modifiedDate = new Date(item.date_last_modified).toLocaleDateString('ja-JP', {
    year: 'numeric', month: 'short', day: 'numeric',
  })
  // 最初の影響製品（代表表示）
  const firstProduct = item.affected_products[0]

  return (
    <>
      <tr
        className="hover:bg-slate-800/40 transition-colors cursor-pointer"
        onClick={() => setOpen(o => !o)}
      >
        {/* 深刻度 + CVSS */}
        <td className="py-2.5 pr-3 w-20">
          <SeverityBadge severity={item.severity} classMap={severityClassMap} />
          {item.cvss_score != null && (
            <span className="block text-[10px] text-slate-600 mt-0.5 tabular-nums">
              {item.cvss_score.toFixed(1)}
            </span>
          )}
        </td>

        {/* JVNDB ID */}
        <td className="py-2.5 pr-3 w-48">
          <a
            href={item.jvn_url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 font-mono text-amber-400 hover:text-amber-300 text-xs transition-colors"
            onClick={e => e.stopPropagation()}
          >
            {item.jvndb_id}
            <ExternalLink size={9} />
          </a>
          {/* 関連 CVE ID */}
          {item.cve_ids.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-0.5">
              {item.cve_ids.slice(0, 2).map(cve => (
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

        {/* タイトル */}
        <td className="py-2.5 pr-3">
          <p className="text-slate-300 text-xs line-clamp-2">{item.title}</p>
        </td>

        {/* 影響製品（代表） */}
        <td className="py-2.5 pr-3 w-44">
          {firstProduct ? (
            <p className="text-slate-400 text-xs truncate">
              <span className="text-slate-500">{firstProduct.vendor} / </span>
              {firstProduct.product}
            </p>
          ) : (
            <span className="text-slate-700 text-xs">—</span>
          )}
          {item.affected_products.length > 1 && (
            <p className="text-[10px] text-slate-600 mt-0.5">+{item.affected_products.length - 1} 製品</p>
          )}
        </td>

        {/* 更新日 */}
        <td className="py-2.5 text-xs text-slate-600 tabular-nums whitespace-nowrap w-24">
          {modifiedDate}
        </td>

        {/* 展開トグル */}
        <td className="py-2.5 pl-2 text-right w-5">
          {open
            ? <ChevronUp size={12} className="text-slate-500 ml-auto" />
            : <ChevronDown size={12} className="text-slate-500 ml-auto" />}
        </td>
      </tr>

      {/* 展開: 概要・影響製品全件・CVSS ベクター */}
      {open && (
        <tr className="bg-slate-800/30">
          <td colSpan={6} className="px-4 py-3 text-xs text-slate-400 space-y-2.5">
            {/* 概要 */}
            <p className="leading-relaxed whitespace-pre-wrap">{item.overview}</p>

            {/* CVSS ベクター */}
            {item.cvss_vector && (
              <p className="flex items-center gap-1.5">
                <span className="text-slate-500">CVSS ベクター:</span>
                <span className="font-mono text-slate-400 text-[10px] bg-slate-800 px-1.5 py-0.5 rounded">
                  {item.cvss_vector}
                </span>
              </p>
            )}

            {/* 関連 CVE (全件) */}
            {item.cve_ids.length > 0 && (
              <p className="flex flex-wrap items-center gap-1.5">
                <span className="text-slate-500">関連 CVE:</span>
                {item.cve_ids.map(cve => (
                  <a
                    key={cve}
                    href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[10px] font-mono text-violet-400 hover:text-violet-300"
                  >
                    {cve}
                  </a>
                ))}
              </p>
            )}

            {/* 影響製品（全件） */}
            {item.affected_products.length > 0 && (
              <div>
                <p className="text-slate-500 mb-1">影響製品:</p>
                <div className="flex flex-wrap gap-1.5">
                  {item.affected_products.map((p, i) => (
                    <span
                      key={i}
                      className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-[10px] text-slate-400"
                    >
                      {p.vendor} / {p.product}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* JVNDB リンク */}
            <a
              href={item.jvn_url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-amber-400 hover:text-amber-300 underline underline-offset-2 text-[10px]"
            >
              JVNDB で詳細を確認
              <ExternalLink size={9} />
            </a>
          </td>
        </tr>
      )}
    </>
  )
}
