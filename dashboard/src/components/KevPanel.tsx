import { Shield, Search, X, BarChart2 } from 'lucide-react'
import {
  MonthlyBarChart,
  TableLoadingSkeleton, EmptyState, Pagination, SearchBox,
} from './shared/VulnPanelParts'
import { VendorBarChart } from './kev/VendorBarChart'
import { useKevData, KEV_PERIODS } from './kev/useKevData'
import { recentMonths } from './kev/trend'
import { PeriodFilter } from './shared/PeriodFilter'
import { StatBand } from './shared/StatBand'
import { WatchKeywords } from './shared/WatchKeywords'
import { CollapsibleSection } from './shared/CollapsibleSection'
import { KEV_TEXT as T } from './kev/kevPanelConfig'
import { KevHeader, KevTable } from './kev/KevSections'

export function KevPanel() {
  const {
    search, period, page, setPage,
    rows, total, totalPages, stats, loading, statsLoading,
    periodTotal, epssHigh,
    keywords, keywordCounts, addKeyword, removeKeyword,
    load, handleSearch, handlePeriod,
  } = useKevData()

  const periodLabel = T.periodLabel(period)

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-lg flex flex-col gap-5">
      <KevHeader busy={loading || statsLoading} onReload={() => load(search, page, period)} />

      {/* グラフ。最初は表示し、見出しを押すと閉じられる */}
      <CollapsibleSection summary={T.charts}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <VendorBarChart stats={stats} loading={statsLoading} />
          <MonthlyBarChart
            icon={<BarChart2 size={13} className="text-slate-400" />}
            title={T.monthlyTitle}
            data={recentMonths(stats?.monthly_trend ?? [])}
            barColor="#7c3aed"
            height={160}
            loading={statsLoading}
          />
        </div>
      </CollapsibleSection>

      {/* 期間の切り替え + 検索 */}
      <div className="flex flex-wrap items-center gap-3">
        <PeriodFilter value={period} options={KEV_PERIODS} onChange={handlePeriod} />
        <SearchBox
          value={search}
          onChange={handleSearch}
          onClear={() => handleSearch('')}
          placeholder={T.searchPlaceholder}
          searchIcon={<Search size={11} className="text-slate-500 shrink-0" />}
          clearIcon={<X size={10} />}
        />
      </div>

      {/* 期間内の追加件数と、そのうち悪用されやすい（EPSS 10%以上）件数 */}
      <StatBand
        loading={periodTotal === null && (loading || statsLoading)}
        items={[
          { value: periodTotal, label: T.addedInPeriod(periodLabel), tone: 'sky' },
          { value: epssHigh, label: T.epssHigh, tone: 'red' },
        ]}
      />

      {/* 自分が使っている製品名ごとの該当件数。押すと、その語で絞り込む */}
      <WatchKeywords
        keywords={keywords}
        counts={keywordCounts}
        active={search}
        total={periodTotal}
        onSelect={kw => handleSearch(kw ?? '')}
        onAdd={addKeyword}
        onRemove={removeKeyword}
      />

      {loading ? (
        <TableLoadingSkeleton columnWidths={['w-28', 'w-28', 'w-28', 'flex-1']} />
      ) : total === 0 ? (
        <EmptyState icon={<Shield size={28} />} message={T.empty} />
      ) : total !== null && (
        <>
          <Pagination page={page} totalPages={totalPages} total={total} onPageChange={setPage} position="top" />
          <KevTable rows={rows} />
          <Pagination page={page} totalPages={totalPages} total={total} onPageChange={setPage} />
        </>
      )}
    </div>
  )
}
