import { FileWarning, RefreshCw, Search, X } from 'lucide-react'
import {
  SeverityPieChart, MonthlyBarChart,
  TableLoadingSkeleton, EmptyState, Pagination,
  SeverityFilterButtons, SearchBox, SortSelector,
} from './shared/VulnPanelParts'
import { JvnRow } from './jvn/JvnRow'
import { useJvnData, JVN_PERIODS } from './jvn/useJvnData'
import { PeriodFilter } from './shared/PeriodFilter'
import { StatBand } from './shared/StatBand'
import { WatchKeywords } from './shared/WatchKeywords'
import { CollapsibleSection } from './shared/CollapsibleSection'

// JVN の重要度は High / Medium / Low（OSV とは異なる）
const SEVERITY_CLS: Record<string, string> = {
  High:   'bg-orange-500/15 text-orange-400 border-orange-500/30',
  Medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  Low:    'bg-blue-500/15 text-blue-400 border-blue-500/30',
}

const SEVERITY_COLORS: Record<string, string> = {
  High:   '#f97316',
  Medium: '#eab308',
  Low:    '#3b82f6',
  'N/A':  '#475569',
}

const SEVERITIES = ['ALL', 'High', 'Medium', 'Low']
export function JvnPanel() {
  const {
    severity, search, sortBy, period, page, setPage,
    result, stats, loading, statsLoading,
    load, handleSev, handleSearch, handleSortBy, handlePeriod,
    totalPages, highCount,
    keywords, keywordCounts, addKeyword, removeKeyword,
  } = useJvnData()

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-lg flex flex-col gap-5">

      {/* ヘッダー */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <FileWarning size={16} className="text-slate-400" />
          <span className="text-sm font-semibold text-slate-400 uppercase tracking-wider">
            JVN 脆弱性（直近 {period} 日）
          </span>
        </div>
        <button
          onClick={() => load(severity, search, page, sortBy, period)}
          disabled={loading || statsLoading}
          className="text-slate-500 hover:text-slate-300 transition-colors disabled:opacity-40 p-1 rounded"
          title="再読み込み"
        >
          <RefreshCw size={13} className={loading || statsLoading ? 'animate-spin' : ''} />
        </button>
      </div>

      {/* 期間の切り替え */}
      <div className="flex flex-wrap items-center gap-3">
        <PeriodFilter value={period} options={JVN_PERIODS} onChange={v => handlePeriod(v ?? 30)} />
      </div>

      {/* 期間内の件数と、そのうち対応が必要な（High）件数 */}
      <StatBand
        loading={statsLoading && !stats}
        items={[
          { value: stats?.total ?? null, label: `件が直近${period}日に更新`, tone: 'sky' },
          { value: stats ? highCount : null, label: '件は High', tone: 'red' },
        ]}
      />

      {/* 自分が使っている製品名ごとの該当件数。押すと、その語で絞り込む */}
      <WatchKeywords
        keywords={keywords}
        counts={keywordCounts}
        active={search}
        total={stats?.total ?? null}
        onSelect={kw => handleSearch(kw ?? '')}
        onAdd={addKeyword}
        onRemove={removeKeyword}
      />

      {/* 重要度フィルター + 検索 + ソート */}
      <div className="flex flex-wrap items-center gap-3">
        <SeverityFilterButtons
          severities={SEVERITIES}
          active={severity}
          onSelect={handleSev}
          classMap={SEVERITY_CLS}
        />

        <SearchBox
          value={search}
          onChange={handleSearch}
          onClear={() => handleSearch('')}
          placeholder="JVNDB ID・タイトル・概要"
          searchIcon={<Search size={11} className="text-slate-500 shrink-0" />}
          clearIcon={<X size={10} />}
        />

        <SortSelector
          sortBy={sortBy}
          onChange={handleSortBy}
          activeClass="bg-amber-500 text-white"
        />
      </div>

      {/* ローディング */}
      {loading ? (
        <TableLoadingSkeleton columnWidths={['w-16', 'w-36', 'flex-1', 'w-28']} />

      /* データなし */
      ) : result && result.total === 0 ? (
        <EmptyState icon={<FileWarning size={28} />} message="該当する JVN 脆弱性はありません" />

      /* テーブル */
      ) : result && (
        <>
          <Pagination page={page} totalPages={totalPages} total={result.total} onPageChange={setPage} position="top" />

          <div className="overflow-x-auto -mx-1 px-1">
            <table aria-label="JVN 脆弱性一覧" className="w-full text-sm min-w-[700px]">
              <thead>
                <tr className="border-b border-slate-800">
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-20">深刻度</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-48">JVNDB ID</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3">タイトル</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-44">影響製品</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-24">更新日</th>
                  <th className="w-5" />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {result.data.map((item, i) => (
                  <JvnRow
                    key={`${item.jvndb_id}-${i}`}
                    item={item}
                    severityClassMap={SEVERITY_CLS}
                  />
                ))}
              </tbody>
            </table>
          </div>

          <Pagination page={page} totalPages={totalPages} total={result.total} onPageChange={setPage} />
        </>
      )}

      {/* グラフ（重要度別・月別トレンド）。一覧より優先度が低いため、初期は畳んでおく */}
      <CollapsibleSection summary="グラフ（重要度別・月別）を開く">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <SeverityPieChart
            icon={<FileWarning size={13} className="text-slate-400" />}
            data={stats?.severities ?? []}
            colorMap={SEVERITY_COLORS}
            loading={statsLoading}
          />
          <MonthlyBarChart
            icon={<FileWarning size={13} className="text-slate-400" />}
            title="月別 JVN 更新トレンド"
            data={stats?.monthly_trend ?? []}
            barColor="#f59e0b"
            height={210}
            loading={statsLoading}
          />
        </div>
      </CollapsibleSection>
    </div>
  )
}
