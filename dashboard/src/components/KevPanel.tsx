import { Fragment } from 'react'
import { Shield, RefreshCw, Search, X, BarChart2 } from 'lucide-react'
import {
  MonthlyBarChart,
  TableLoadingSkeleton, EmptyState, Pagination, SearchBox,
} from './shared/VulnPanelParts'
import { KevRow } from './kev/KevRow'
import { VendorBarChart } from './kev/VendorBarChart'
import { useKevData, KEV_PERIODS } from './kev/useKevData'
import { PeriodFilter } from './shared/PeriodFilter'
import { StatBand } from './shared/StatBand'
import { WatchKeywords } from './shared/WatchKeywords'
import { CollapsibleSection } from './shared/CollapsibleSection'

// 追加日ごとの区切り行の表示（例: 2026年10月20日）
function formatDay(date: string): string {
  return new Date(date).toLocaleDateString('ja-JP', { year: 'numeric', month: 'long', day: 'numeric' })
}

export function KevPanel() {
  const {
    search, period, page, setPage,
    rows, total, totalPages, stats, loading, statsLoading,
    periodTotal, epssHigh,
    keywords, keywordCounts, addKeyword, removeKeyword,
    load, handleSearch, handlePeriod,
  } = useKevData()

  const periodLabel = period === null ? '登録済み' : `直近${period}日に追加`

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-lg flex flex-col gap-5">

      {/* ヘッダー */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield size={16} className="text-slate-400" />
          <span className="text-sm font-semibold text-slate-400 uppercase tracking-wider">
            CISA KEV — 悪用が確認された脆弱性
          </span>
        </div>
        <button
          onClick={() => load(search, page, period)}
          disabled={loading || statsLoading}
          className="text-slate-500 hover:text-slate-300 transition-colors disabled:opacity-40 p-1 rounded"
          title="再読み込み"
        >
          <RefreshCw size={13} className={loading || statsLoading ? 'animate-spin' : ''} />
        </button>
      </div>

      {/* 期間の切り替え + 検索 */}
      <div className="flex flex-wrap items-center gap-3">
        <PeriodFilter value={period} options={KEV_PERIODS} onChange={handlePeriod} />
        <SearchBox
          value={search}
          onChange={handleSearch}
          onClear={() => handleSearch('')}
          placeholder="ベンダー名・製品名"
          searchIcon={<Search size={11} className="text-slate-500 shrink-0" />}
          clearIcon={<X size={10} />}
        />
      </div>

      {/* 期間内の追加件数と、そのうち悪用されやすい（EPSS 10%以上）件数 */}
      <StatBand
        loading={periodTotal === null && (loading || statsLoading)}
        items={[
          { value: periodTotal, label: `件が${periodLabel}`, tone: 'sky' },
          { value: epssHigh, label: '件は悪用されやすい（EPSS 10%以上）', tone: 'red' },
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

      {/* ローディング */}
      {loading ? (
        <TableLoadingSkeleton columnWidths={['w-28', 'w-28', 'w-28', 'flex-1']} />

      /* データなし */
      ) : total === 0 ? (
        <EmptyState icon={<Shield size={28} />} message="該当する CVE はありません" />

      /* テーブル（追加日の新しい順。日ごとに区切る） */
      ) : total !== null && (
        <>
          <Pagination page={page} totalPages={totalPages} total={total} onPageChange={setPage} position="top" />

          <div className="overflow-x-auto -mx-1 px-1">
            <table aria-label="KEV 脆弱性一覧" className="w-full text-sm min-w-[700px]">
              <thead>
                <tr className="border-b border-slate-800">
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-36">CVE ID</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-28">EPSS</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-40">ベンダー</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-40">製品</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3">脆弱性名</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-24">追加日</th>
                  <th className="w-5" />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {rows.map((item, i) => (
                  <Fragment key={item.cve_id}>
                    {(i === 0 || rows[i - 1].date_added !== item.date_added) && (
                      <tr aria-label={`${formatDay(item.date_added)}に追加`}>
                        <td colSpan={7} className="bg-slate-950/50 px-2 py-1 text-[11px] font-semibold text-slate-500">
                          {formatDay(item.date_added)}
                        </td>
                      </tr>
                    )}
                    <KevRow item={item} />
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>

          <Pagination page={page} totalPages={totalPages} total={total} onPageChange={setPage} />
        </>
      )}

      {/* グラフ（ベンダー別・月別トレンド）。一覧より優先度が低いため、初期は畳んでおく */}
      <CollapsibleSection summary="グラフ（ベンダー別・月別トレンド）を開く">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <VendorBarChart stats={stats} loading={statsLoading} />
          <MonthlyBarChart
            icon={<BarChart2 size={13} className="text-slate-400" />}
            title="月別 CVE 追加数トレンド"
            data={stats?.monthly_trend ?? []}
            barColor="#7c3aed"
            height={160}
            loading={statsLoading}
          />
        </div>
      </CollapsibleSection>
    </div>
  )
}
