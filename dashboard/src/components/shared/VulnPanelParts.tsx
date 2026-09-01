import type { ReactNode } from 'react'
import {
  PieChart, Pie, Cell, Tooltip as ReTooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
} from 'recharts'

// OsvPanel・JvnPanel で共有する、脆弱性一覧パネルの汎用パーツ群。
// 深刻度の値・配色・件数などドメイン固有の情報は呼び出し側から props で渡す。

// ── 深刻度バッジ ──────────────────────────────────────────────

export function SeverityBadge({
  severity, classMap,
}: {
  severity: string | null
  classMap: Record<string, string>
}) {
  const cls = severity
    ? (classMap[severity] ?? 'bg-slate-800 text-slate-400 border-slate-700')
    : 'bg-slate-800 text-slate-500 border-slate-700'
  return (
    <span className={`inline-block px-1.5 py-0.5 rounded border text-xs font-semibold whitespace-nowrap ${cls}`}>
      {severity ?? 'N/A'}
    </span>
  )
}

// ── チャートカードの外枠（アイコン・タイトル・ローディング/空状態） ──

export function ChartCard({
  icon, title, loading, isEmpty, height, children, footer,
}: {
  icon: ReactNode
  title: string
  loading: boolean
  isEmpty: boolean
  height: number
  children: ReactNode
  /** 高さ固定領域の外側（下）に表示する任意コンテンツ（例: 凡例）。ローディング/空の間は表示しない */
  footer?: ReactNode
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 flex flex-col gap-3">
      <div className="flex items-center gap-2">
        {icon}
        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">{title}</span>
      </div>
      <div style={{ height }}>
        {loading || isEmpty ? (
          <div className="h-full flex items-center justify-center text-xs text-slate-600">
            {loading ? '読み込み中...' : 'データなし'}
          </div>
        ) : children}
      </div>
      {!loading && !isEmpty && footer}
    </div>
  )
}

// ── 重要度別円グラフ ──────────────────────────────────────────

export function SeverityPieChart({
  icon, data, colorMap, loading,
}: {
  icon: ReactNode
  data: { severity: string; count: number }[]
  colorMap: Record<string, string>
  loading: boolean
}) {
  const chartData = data
    .filter(s => s.severity !== 'N/A' && s.count > 0)
    .map(s => ({ name: s.severity, value: s.count }))

  const legend = (
    <div className="flex flex-wrap gap-2">
      {chartData.map(d => (
        <span key={d.name} className="flex items-center gap-1 text-[11px] text-slate-400">
          <span
            className="inline-block w-2 h-2 rounded-full"
            style={{ background: colorMap[d.name] ?? '#475569' }}
          />
          {d.name} <span className="text-slate-600">{d.value}</span>
        </span>
      ))}
    </div>
  )

  return (
    <ChartCard
      icon={icon}
      title="重要度別分布"
      loading={loading}
      isEmpty={chartData.length === 0}
      height={210}
      footer={legend}
    >
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={chartData}
            cx="50%"
            cy="50%"
            innerRadius={55}
            outerRadius={85}
            paddingAngle={2}
            dataKey="value"
          >
            {chartData.map((entry) => (
              <Cell key={entry.name} fill={colorMap[entry.name] ?? '#475569'} />
            ))}
          </Pie>
          <ReTooltip
            contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }}
            formatter={(value, name) => [String(value) + ' 件', String(name)]}
          />
        </PieChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}

// ── 月別トレンド棒グラフ ──────────────────────────────────────

export function MonthlyBarChart({
  icon, title, data, barColor, height = 160,
  loading,
}: {
  icon: ReactNode
  title: string
  data: { year_month: string; count: number }[]
  barColor: string
  height?: number
  loading: boolean
}) {
  return (
    <ChartCard icon={icon} title={title} loading={loading} isEmpty={data.length === 0} height={height}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
          <XAxis
            dataKey="year_month"
            tick={{ fill: '#475569', fontSize: 10 }}
            tickLine={false}
            axisLine={false}
            interval="preserveStartEnd"
          />
          <YAxis
            tick={{ fill: '#475569', fontSize: 10 }}
            tickLine={false}
            axisLine={false}
            allowDecimals={false}
          />
          <ReTooltip
            contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }}
            formatter={(value) => [String(value) + ' 件', '件数']}
          />
          <Bar dataKey="count" fill={barColor} radius={[3, 3, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}

// ── ローディングスケルトン（テーブル用） ────────────────────────

export function TableLoadingSkeleton({ columnWidths }: { columnWidths: string[] }) {
  return (
    <div className="space-y-2 py-4">
      {Array.from({ length: 5 }).map((_, i) => (
        <div key={i} className="flex items-center gap-3 py-2">
          {columnWidths.map((w, j) => (
            <div key={j} className={`h-4 bg-slate-800 rounded animate-pulse ${w}`} />
          ))}
        </div>
      ))}
    </div>
  )
}

// ── データなし状態 ────────────────────────────────────────────

export function EmptyState({ icon, message }: { icon: ReactNode; message: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-12 text-slate-600">
      {icon}
      <p className="text-sm">{message}</p>
      <p className="text-xs text-slate-700">クローラーがデータを取得すると表示されます</p>
    </div>
  )
}

// ── ページネーション ──────────────────────────────────────────

export function Pagination({
  page, totalPages, total, onPageChange,
}: {
  page: number
  totalPages: number
  total: number
  onPageChange: (updater: (p: number) => number) => void
}) {
  if (totalPages <= 1) return null
  return (
    <div className="flex items-center justify-between pt-2 border-t border-slate-800">
      <button
        onClick={() => onPageChange(p => Math.max(1, p - 1))}
        disabled={page === 1}
        className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-sm text-slate-300 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
      >
        ← 前へ
      </button>
      <span className="text-sm text-slate-600 tabular-nums">
        {page} / {totalPages}
        <span className="ml-2 text-slate-700">（{total} 件）</span>
      </span>
      <button
        onClick={() => onPageChange(p => Math.min(totalPages, p + 1))}
        disabled={page === totalPages}
        className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-sm text-slate-300 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
      >
        次へ →
      </button>
    </div>
  )
}

// ── 重要度フィルターボタン列 ────────────────────────────────────

export function SeverityFilterButtons({
  severities, active, onSelect, classMap, activeAllClass = 'bg-slate-700 text-white',
}: {
  severities: string[]
  active: string | null
  onSelect: (sev: string) => void
  classMap: Record<string, string>
  activeAllClass?: string
}) {
  return (
    <div className="flex gap-1">
      {severities.map(sev => {
        const isActive = (sev === 'ALL' && active === null) || sev === active
        const cls = isActive
          ? sev === 'ALL'
            ? activeAllClass
            : (classMap[sev] ?? activeAllClass) + ' border'
          : 'bg-slate-800/50 text-slate-500 hover:text-slate-300'
        return (
          <button
            key={sev}
            onClick={() => onSelect(sev)}
            className={`px-2 py-1 rounded text-xs font-medium transition-colors ${cls}`}
          >
            {sev}
          </button>
        )
      })}
    </div>
  )
}

// ── キーワード検索ボックス ────────────────────────────────────

export function SearchBox({
  value, onChange, onClear, placeholder, searchIcon, clearIcon,
}: {
  value: string
  onChange: (value: string) => void
  onClear: () => void
  placeholder: string
  searchIcon: ReactNode
  clearIcon: ReactNode
}) {
  return (
    <div className="flex items-center gap-1.5 bg-slate-800/60 border border-slate-700 rounded-lg px-2.5 py-1.5 flex-1 min-w-[160px]">
      {searchIcon}
      <input
        type="text"
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        className="bg-transparent text-xs text-slate-300 placeholder:text-slate-600 outline-none w-full"
      />
      {value && (
        <button onClick={onClear} className="text-slate-500 hover:text-slate-300">
          {clearIcon}
        </button>
      )}
    </div>
  )
}

// ── ソートセレクター（更新日 / CVSS） ──────────────────────────

export function SortSelector({
  sortBy, onChange, activeClass,
}: {
  sortBy: 'modified' | 'cvss'
  onChange: (sort: 'modified' | 'cvss') => void
  activeClass: string
}) {
  return (
    <div className="flex items-center gap-1 bg-slate-800/60 border border-slate-700 rounded-lg px-2.5 py-1.5">
      <span className="text-[10px] text-slate-500 whitespace-nowrap">ソート:</span>
      <button
        onClick={() => onChange('modified')}
        className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${
          sortBy === 'modified' ? activeClass : 'text-slate-400 hover:text-slate-300'
        }`}
      >
        更新日
      </button>
      <button
        onClick={() => onChange('cvss')}
        className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${
          sortBy === 'cvss' ? activeClass : 'text-slate-400 hover:text-slate-300'
        }`}
      >
        CVSS
      </button>
    </div>
  )
}
