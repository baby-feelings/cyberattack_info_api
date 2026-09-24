import { useState } from 'react'
import { ChevronDown, ChevronUp } from 'lucide-react'
import { type CodeFindingOut } from '../../api/client'
import { SeverityBadge } from '../shared/VulnPanelParts'

// 重要度バッジのスタイル（Semgrep の ERROR/WARNING/INFO 用）
const SEVERITY_CLS: Record<string, string> = {
  ERROR: 'bg-red-500/15 text-red-400 border-red-500/30',
  WARNING: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  INFO: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
}

// 重要度の表示ラベル。ERRORはシステムエラーと紛らわしいため日本語表記にする
const SEVERITY_LABELS: Record<string, string> = {
  ERROR: '重大',
  WARNING: '警告',
  INFO: '情報',
}

// 検知ツール種別を示す小さなバッジ（Semgrep / Gitleaks、Issue #219）
const TOOL_LABEL: Record<string, string> = {
  semgrep: 'Semgrep',
  gitleaks: 'Gitleaks',
}

function ToolBadge({ tool }: { tool: string }) {
  const isGitleaks = tool === 'gitleaks'
  return (
    <span
      className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-medium border ${
        isGitleaks
          ? 'bg-orange-500/15 text-orange-300 border-orange-500/30'
          : 'bg-slate-700/40 text-slate-400 border-slate-600/50'
      }`}
    >
      {TOOL_LABEL[tool] ?? tool}
    </span>
  )
}

// CVSS 7.0以上を視覚的に強調するバッジ（Issue #203 の要件）
function CvssBadge({ score }: { score: number | null }) {
  if (score == null) {
    return <span className="text-[10px] text-slate-600">未算出</span>
  }
  const isHigh = score >= 7.0
  return (
    <span
      className={`inline-block px-1.5 py-0.5 rounded text-[11px] font-mono font-semibold tabular-nums ${
        isHigh
          ? 'bg-red-600/20 text-red-300 border border-red-600/40'
          : 'text-slate-400'
      }`}
    >
      {score.toFixed(1)}
    </span>
  )
}

export function CodescanRow({ item }: { item: CodeFindingOut }) {
  const [open, setOpen] = useState(false)
  const detectedDate = new Date(item.detected_at).toLocaleDateString('ja-JP', {
    year: 'numeric', month: 'short', day: 'numeric',
  })

  return (
    <>
      <tr
        className="hover:bg-slate-800/40 transition-colors cursor-pointer"
        onClick={() => setOpen(o => !o)}
      >
        <td className="py-2.5 pr-3">
          <SeverityBadge severity={item.severity} classMap={SEVERITY_CLS} labels={SEVERITY_LABELS} />
        </td>
        <td className="py-2.5 pr-3">
          <CvssBadge score={item.cvss_score} />
        </td>
        <td className="py-2.5 pr-3">
          <p className="text-slate-300 font-mono text-xs">{item.repo_full_name}</p>
        </td>
        <td className="py-2.5 pr-3">
          <p className="text-slate-300 font-mono text-xs truncate max-w-[220px]">
            {item.file_path}:{item.line_start}
          </p>
        </td>
        <td className="py-2.5 pr-3">
          <div className="flex items-center gap-1.5">
            <ToolBadge tool={item.tool} />
            <p className="text-slate-500 font-mono text-[10px] truncate max-w-[180px]">
              {item.rule_id}
            </p>
          </div>
        </td>
        <td className="py-2.5 text-xs text-slate-600 tabular-nums whitespace-nowrap">
          {detectedDate}
        </td>
        <td className="py-2.5 pl-2 text-right">
          {open
            ? <ChevronUp size={12} className="text-slate-500 ml-auto" />
            : <ChevronDown size={12} className="text-slate-500 ml-auto" />}
        </td>
      </tr>

      {open && (
        <tr className="bg-slate-800/30">
          <td colSpan={7} className="px-4 py-3 text-xs text-slate-400 space-y-2">
            <p className="leading-relaxed whitespace-pre-wrap">{item.message}</p>
            {item.code_snippet && (
              <pre className="bg-slate-950 rounded p-2 overflow-x-auto text-[11px] text-slate-300">
                {item.code_snippet}
              </pre>
            )}
            {item.cwe_ids.length > 0 && (
              <p className="flex flex-wrap items-center gap-1.5">
                <span className="text-slate-500">CWE:</span>
                {item.cwe_ids.map(c => (
                  <span key={c} className="text-[10px] font-mono text-slate-500">{c}</span>
                ))}
              </p>
            )}
            {item.owasp_categories.length > 0 && (
              <p className="flex flex-wrap items-center gap-1.5">
                <span className="text-slate-500">OWASP:</span>
                {item.owasp_categories.map(o => (
                  <span key={o} className="text-[10px] font-mono text-slate-500">{o}</span>
                ))}
              </p>
            )}
            {item.cvss_vector && (
              <p className="text-[10px] font-mono text-slate-600">{item.cvss_vector}</p>
            )}
          </td>
        </tr>
      )}
    </>
  )
}
