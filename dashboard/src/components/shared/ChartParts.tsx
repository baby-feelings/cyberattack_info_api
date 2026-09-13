import type { ReactNode } from 'react'
import {
  PieChart, Pie, Cell, Tooltip as ReTooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
} from 'recharts'

// OsvPanel・JvnPanel で共有する、脆弱性一覧パネルのチャート系パーツ群
// （チャートカードの外枠・重要度別円グラフ・月別トレンド棒グラフ）。
// 深刻度の値・配色などドメイン固有の情報は呼び出し側から props で渡す。

// ── チャートカードの外枠（アイコン・タイトル・ローディング/空状態） ──

export function ChartCard({
  icon, title, description, loading, isEmpty, height, children, footer,
}: {
  icon: ReactNode
  title: string
  /** タイトル下に表示する小さな補足説明（誤解されやすい集計の前提等を明記する用途） */
  description?: string
  loading: boolean
  isEmpty: boolean
  height: number
  children: ReactNode
  /** 高さ固定領域の外側（下）に表示する任意コンテンツ（例: 凡例）。ローディング/空の間は表示しない */
  footer?: ReactNode
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 flex flex-col gap-3">
      <div className="flex flex-col gap-0.5">
        <div className="flex items-center gap-2">
          {icon}
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">{title}</span>
        </div>
        {description && (
          <p className="text-[10px] text-slate-600 leading-snug">{description}</p>
        )}
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

// Recharts の Tooltip formatter は jsdom 上でホバーをシミュレートしてもテストから
// 呼び出されないため、名前付き関数として切り出しテストから直接呼び出す
// （表示内容は不変。dashboard/CLAUDE.md の VendorBarChart と同じパターン）。
export function formatSeverityPieTooltipValue(value: unknown, name: unknown): [string, string] {
  return [String(value) + ' 件', String(name)]
}

export function formatMonthlyBarTooltipValue(value: unknown): [string, string] {
  return [String(value) + ' 件', '件数']
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
            formatter={formatSeverityPieTooltipValue}
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
            formatter={formatMonthlyBarTooltipValue}
          />
          <Bar dataKey="count" fill={barColor} radius={[3, 3, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
