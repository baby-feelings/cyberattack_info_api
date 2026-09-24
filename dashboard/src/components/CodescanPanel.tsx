import { RefreshCw, ScanSearch } from 'lucide-react'
import {
  TableLoadingSkeleton, EmptyState, Pagination, SeverityFilterButtons,
} from './shared/VulnPanelParts'
import { CodescanRow } from './codescan/CodescanRow'
import { RepoBarChart } from './codescan/RepoBarChart'
import { useCodescanData } from './codescan/useCodescanData'

const SEVERITY_CLS: Record<string, string> = {
  ERROR: 'bg-red-500/15 text-red-400 border-red-500/30',
  WARNING: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  INFO: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
}

const SEVERITIES = ['ALL', 'ERROR', 'WARNING', 'INFO']

export function CodescanPanel() {
  const {
    severity, resolved, page, setPage,
    result, stats, loading,
    load, handleSev, handleResolvedToggle,
    totalPages, errorCount,
  } = useCodescanData()

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-lg flex flex-col gap-5">

      {/* ヘッダー */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ScanSearch size={16} className="text-slate-400" />
          <span className="text-sm font-semibold text-slate-400 uppercase tracking-wider">
            CODESCAN（Semgrep 静的解析）
          </span>
        </div>
        <div className="flex items-center gap-3">
          {!loading && stats && stats.total > 0 && (
            <div className="flex items-center gap-2 text-xs tabular-nums">
              {errorCount > 0 && (
                <span className="px-2 py-0.5 rounded-full bg-red-500/15 text-red-400 font-semibold">
                  ERROR {errorCount}
                </span>
              )}
              <span className="text-slate-500">未解決 {stats.total} 件</span>
            </div>
          )}
          <button
            onClick={() => load(severity, resolved, page)}
            disabled={loading}
            className="text-slate-500 hover:text-slate-300 transition-colors disabled:opacity-40 p-1 rounded"
            title="再読み込み"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {/* 注記: CVSSはベストエフォート推定であることを明記（Issue #203の要件） */}
      <p className="text-[11px] text-slate-600 leading-relaxed">
        CVSSスコアはSemgrepの検知結果（重要度・CWE）からのベストエフォート推定値であり、
        正式なCVSS評価に代わるものではありません。7.0以上は赤バッジで強調表示します。
      </p>

      {/* リポジトリ別統計（棒グラフ、DEPSCANと同じ構成） */}
      <RepoBarChart stats={stats} loading={loading} />

      {/* 重要度フィルター + 解決状態フィルター */}
      <div className="flex flex-wrap items-center gap-3">
        <SeverityFilterButtons
          severities={SEVERITIES}
          active={severity}
          onSelect={handleSev}
          classMap={SEVERITY_CLS}
        />
        <div className="flex items-center gap-1 bg-slate-800/60 border border-slate-700 rounded-lg px-2.5 py-1.5">
          <span className="text-[10px] text-slate-500 whitespace-nowrap">状態:</span>
          {([
            { label: '未解決', value: false as boolean | null },
            { label: '解決済み', value: true as boolean | null },
            { label: '全件', value: null as boolean | null },
          ]).map(opt => (
            <button
              key={opt.label}
              onClick={() => handleResolvedToggle(opt.value)}
              className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${
                resolved === opt.value
                  ? 'bg-rose-600 text-white'
                  : 'text-slate-400 hover:text-slate-300'
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>
      </div>

      {/* ローディング */}
      {loading ? (
        <TableLoadingSkeleton columnWidths={['w-16', 'w-12', 'w-32', 'w-40', 'flex-1']} />

      /* データなし */
      ) : result && result.total === 0 ? (
        <EmptyState icon={<ScanSearch size={28} />} message="該当するコード脆弱性はありません" />

      /* テーブル */
      ) : result && (
        <>
          <div className="overflow-x-auto -mx-1 px-1">
            <table className="w-full text-sm min-w-[700px]">
              <thead>
                <tr className="border-b border-slate-800">
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-20">重要度</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-16">CVSS</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-40">リポジトリ</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3">ファイル:行</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3">ルール</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-24">検知日</th>
                  <th className="w-5" />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {result.data.map((item, i) => (
                  <CodescanRow
                    key={`${item.repo_full_name}-${item.file_path}-${item.rule_id}-${item.line_start}-${i}`}
                    item={item}
                  />
                ))}
              </tbody>
            </table>
          </div>

          <Pagination page={page} totalPages={totalPages} total={result.total} onPageChange={setPage} />
        </>
      )}
    </div>
  )
}
