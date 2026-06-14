import { useState } from 'react'
import {
  Scan, FileText, Package, AlertCircle, CheckCircle,
  Loader2, ExternalLink, ChevronDown, ChevronUp,
} from 'lucide-react'
import { scanRequirements, scanPackageJson, type ScanResponse, type VulnerabilityFinding } from '../api/client'

type TabType = 'requirements' | 'package-json'

// 深刻度ごとの表示スタイル
const SEVERITY_CLS: Record<string, string> = {
  CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/30',
  HIGH:     'bg-orange-500/15 text-orange-400 border-orange-500/30',
  MEDIUM:   'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  LOW:      'bg-blue-500/15 text-blue-400 border-blue-500/30',
}

// 深刻度の並び順（重大順）
const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

function SeverityBadge({ severity }: { severity: string | null }) {
  const cls = severity ? (SEVERITY_CLS[severity] ?? 'bg-slate-800 text-slate-400 border-slate-700')
    : 'bg-slate-800 text-slate-500 border-slate-700'
  return (
    <span className={`inline-block px-1.5 py-0.5 rounded border text-xs font-semibold whitespace-nowrap ${cls}`}>
      {severity ?? 'N/A'}
    </span>
  )
}

// 1件の検出結果行（クリックで詳細展開）
function FindingRow({ f }: { f: VulnerabilityFinding }) {
  const [open, setOpen] = useState(false)
  const isCve = f.vuln_id.startsWith('CVE-')

  return (
    <>
      <tr
        className="hover:bg-slate-800/40 transition-colors cursor-pointer"
        onClick={() => setOpen(o => !o)}
      >
        <td className="py-2.5 pr-3">
          <SeverityBadge severity={f.severity} />
        </td>
        <td className="py-2.5 pr-3">
          <p className="text-slate-300 font-mono text-sm">{f.package_name}</p>
          {f.package_version && (
            <p className="text-slate-600 text-xs">v{f.package_version}</p>
          )}
        </td>
        <td className="py-2.5 pr-3">
          {isCve ? (
            <a
              href={`https://nvd.nist.gov/vuln/detail/${f.vuln_id}`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 font-mono text-violet-400 hover:text-violet-300 text-sm transition-colors"
              onClick={e => e.stopPropagation()}
            >
              {f.vuln_id}
              <ExternalLink size={11} />
            </a>
          ) : (
            <span className="font-mono text-sm text-slate-400">{f.vuln_id}</span>
          )}
        </td>
        <td className="py-2.5 pr-3">
          <span className={`inline-block px-1.5 py-0.5 rounded text-xs font-medium ${
            f.source === 'OSV'
              ? 'bg-sky-500/15 text-sky-400'
              : 'bg-amber-500/15 text-amber-400'
          }`}>
            {f.source === 'CISA_KEV' ? 'KEV' : f.source}
          </span>
        </td>
        <td className="py-2.5 text-slate-400 text-sm">
          <p className="truncate max-w-[200px]">{f.summary}</p>
        </td>
        <td className="py-2.5 text-right pl-2">
          {open
            ? <ChevronUp size={14} className="text-slate-500 ml-auto" />
            : <ChevronDown size={14} className="text-slate-500 ml-auto" />}
        </td>
      </tr>

      {/* 展開: 詳細・修正バージョン・参考リンク */}
      {open && (
        <tr className="bg-slate-800/30">
          <td colSpan={6} className="px-4 py-3 text-sm text-slate-400 space-y-2">
            {f.details && <p className="leading-relaxed text-slate-400">{f.details}</p>}
            {f.fixed_versions.length > 0 && (
              <p className="flex flex-wrap items-center gap-1.5">
                <span className="text-slate-500">修正済みバージョン:</span>
                {f.fixed_versions.map(v => (
                  <span key={v} className="px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 text-xs font-mono">
                    {v}
                  </span>
                ))}
              </p>
            )}
            {f.references.length > 0 && (
              <div className="flex flex-wrap gap-2">
                {f.references.map(url => (
                  <a
                    key={url}
                    href={url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-violet-400 hover:text-violet-300 underline underline-offset-2 text-xs break-all"
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

// タブごとのプレースホルダー
const PLACEHOLDER: Record<TabType, string> = {
  requirements:   'fastapi==0.115.6\nhttpx==0.28.1\nsqlalchemy==2.0.36\npydantic==2.11.4',
  'package-json': '{\n  "dependencies": {\n    "react": "^18.3.1",\n    "vite": "^6.3.5"\n  }\n}',
}

export function ScanPanel() {
  const [tab, setTab] = useState<TabType>('requirements')
  const [text, setText] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<ScanResponse | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function handleScan() {
    if (!text.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const res = tab === 'requirements'
        ? await scanRequirements(text)
        : await scanPackageJson(text)
      // 深刻度の高い順にソート
      res.findings.sort((a, b) => {
        const ai = SEVERITY_ORDER.indexOf(a.severity ?? '')
        const bi = SEVERITY_ORDER.indexOf(b.severity ?? '')
        return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi)
      })
      setResult(res)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'スキャンエラーが発生しました')
    } finally {
      setLoading(false)
    }
  }

  function handleTabChange(next: TabType) {
    setTab(next)
    setResult(null)
    setError(null)
  }

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-lg flex flex-col gap-4">

      {/* ヘッダー */}
      <div className="flex items-center gap-2">
        <Scan size={15} className="text-slate-400" />
        <span className="text-sm font-semibold text-slate-400 uppercase tracking-wider">
          ライブラリ脆弱性スキャン
        </span>
      </div>

      {/* タブ切り替え */}
      <div className="flex gap-1 bg-slate-800/50 rounded-lg p-1 w-fit">
        {([
          { id: 'requirements' as TabType, label: 'requirements.txt', icon: FileText },
          { id: 'package-json' as TabType, label: 'package.json',     icon: Package  },
        ] as const).map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => handleTabChange(id)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
              tab === id
                ? 'bg-violet-600 text-white shadow'
                : 'text-slate-400 hover:text-slate-300'
            }`}
          >
            <Icon size={11} />
            {label}
          </button>
        ))}
      </div>

      {/* 入力エリア */}
      <textarea
        value={text}
        onChange={e => setText(e.target.value)}
        placeholder={PLACEHOLDER[tab]}
        rows={6}
        className="w-full bg-slate-800/60 border border-slate-700 rounded-xl px-3 py-2.5 text-sm font-mono text-slate-300 placeholder:text-slate-600 resize-y focus:outline-none focus:border-violet-500/60 transition-colors"
      />

      {/* スキャンボタン + 件数サマリー */}
      <div className="flex items-center gap-3">
        <button
          onClick={handleScan}
          disabled={loading || !text.trim()}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-violet-600 hover:bg-violet-500 active:bg-violet-700 text-sm font-semibold text-white transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
        >
          {loading
            ? <Loader2 size={14} className="animate-spin" />
            : <Scan size={14} />}
          {loading ? 'スキャン中...' : 'スキャン実行'}
        </button>
        {result && (
          <span className="text-sm text-slate-500 tabular-nums">
            {result.scanned_packages} パッケージ ・ 脆弱性{' '}
            <span className={result.total_findings > 0 ? 'text-red-400 font-semibold' : 'text-emerald-400'}>
              {result.total_findings}
            </span>{' '}件
          </span>
        )}
      </div>

      {/* エラー表示 */}
      {error && (
        <div className="flex items-center gap-2 bg-red-950/50 border border-red-800/60 text-red-300 rounded-xl px-3 py-2.5 text-sm">
          <AlertCircle size={14} className="shrink-0" />
          {error}
        </div>
      )}

      {/* 脆弱性なし */}
      {result && result.findings.length === 0 && (
        <div className="flex flex-col items-center justify-center gap-2 py-8 text-slate-600">
          <CheckCircle size={26} className="text-emerald-500" />
          <p className="text-sm">脆弱性は検出されませんでした</p>
        </div>
      )}

      {/* 検出結果テーブル */}
      {result && result.findings.length > 0 && (
        <div className="overflow-x-auto -mx-1 px-1">
          <table className="w-full text-sm min-w-[600px]">
            <thead>
              <tr className="border-b border-slate-800">
                <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-20">深刻度</th>
                <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-32">パッケージ</th>
                <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-36">CVE / ID</th>
                <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-12">ソース</th>
                <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2">概要</th>
                <th className="w-5" />
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {result.findings.map((f, i) => (
                <FindingRow key={`${f.package_name}-${f.vuln_id}-${i}`} f={f} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
