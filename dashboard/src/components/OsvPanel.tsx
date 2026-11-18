import { Shield, Search, X, BarChart2 } from 'lucide-react'
import {
  SeverityPieChart, MonthlyBarChart,
  TableLoadingSkeleton, EmptyState, Pagination,
  SeverityFilterButtons, SearchBox, SortSelector,
} from './shared/VulnPanelParts'
import { EcosystemBarChart } from './osv/EcosystemBarChart'
import { useOsvData, OSV_PERIODS } from './osv/useOsvData'
import { PeriodFilter } from './shared/PeriodFilter'
import { StatBand } from './shared/StatBand'
import { WatchKeywords } from './shared/WatchKeywords'
import { CollapsibleSection } from './shared/CollapsibleSection'
import { OSV_TEXT as T, SEVERITIES, SEVERITY_CLS, SEVERITY_COLORS } from './osv/osvPanelConfig'
import { EcosystemFilter, OsvHeader, OsvTable } from './osv/OsvSections'

export function OsvPanel() {
  const {
    ecosystem, severity, search, sortBy, period, page, setPage,
    result, stats, trend, loading, statsLoading,
    load, handleEco, handleSev, handleSearch, clearSearch, handleSortBy, handlePeriod,
    totalPages, critCount, highCount,
    keywords, keywordCounts, addKeyword, removeKeyword,
  } = useOsvData()

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-lg flex flex-col gap-5">
      <OsvHeader
        period={period} busy={loading || statsLoading}
        onReload={() => load(ecosystem, severity, search, page, sortBy, period)}
      />

      {/* グラフ。最初は表示し、見出しを押すと閉じられる */}
      <CollapsibleSection summary={T.charts}>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <SeverityPieChart
            icon={<Shield size={13} className="text-slate-400" />}
            data={stats?.severities ?? []}
            colorMap={SEVERITY_COLORS}
            loading={statsLoading}
          />
          <EcosystemBarChart stats={stats} loading={statsLoading} />
          <MonthlyBarChart
            icon={<BarChart2 size={13} className="text-slate-400" />}
            title={T.monthlyTitle}
            data={trend?.monthly_trend ?? []}
            barColor="#7c3aed"
            height={160}
            loading={trend === null && statsLoading}
          />
        </div>
      </CollapsibleSection>

      {/* 期間の切り替え */}
      <div className="flex flex-wrap items-center gap-3">
        <PeriodFilter value={period} options={OSV_PERIODS} onChange={v => handlePeriod(v ?? 30)} />
      </div>

      {/* 期間内の件数と、そのうち対応が必要な（CRITICAL・HIGH）件数 */}
      <StatBand
        loading={statsLoading && !stats}
        items={[
          { value: stats?.total ?? null, label: T.updatedInPeriod(period), tone: 'sky' },
          { value: stats ? critCount + highCount : null, label: T.criticalHigh, tone: 'red' },
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

      <EcosystemFilter ecosystem={ecosystem} stats={stats} onSelect={handleEco} />

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
          onClear={clearSearch}
          placeholder={T.searchPlaceholder}
          searchIcon={<Search size={11} className="text-slate-500 shrink-0" />}
          clearIcon={<X size={10} />}
        />
        <SortSelector
          sortBy={sortBy}
          onChange={handleSortBy}
          activeClass="bg-violet-600 text-white"
        />
      </div>

      {loading ? (
        <TableLoadingSkeleton columnWidths={['w-16', 'w-28', 'w-16', 'flex-1']} />
      ) : result && result.total === 0 ? (
        <EmptyState icon={<Shield size={28} />} message={T.empty} />
      ) : result && (
        <>
          <Pagination page={page} totalPages={totalPages} total={result.total} onPageChange={setPage} position="top" />
          <OsvTable result={result} sortBy={sortBy} />
          <Pagination page={page} totalPages={totalPages} total={result.total} onPageChange={setPage} />
        </>
      )}
    </div>
  )
}
