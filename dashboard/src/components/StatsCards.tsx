// サマリー統計カード（合計件数・直近30日・最新追加日）
import { Shield, TrendingUp, Calendar } from 'lucide-react'
import type { StatsResponse, VulnerabilityOut } from '../api/client'

interface Props {
  stats: StatsResponse | null
  recent: VulnerabilityOut[]
  loading: boolean
}

export function StatsCards({ stats, recent, loading }: Props) {
  // 直近30日の中で最も新しい追加日
  const latestDate = recent.length > 0
    ? recent.reduce((a, b) => a.date_added > b.date_added ? a : b).date_added
    : null

  const cards = [
    {
      icon: <Shield size={20} className="text-violet-400" />,
      label: '登録済み CVE 総数',
      value: loading ? '—' : stats?.total_vulnerabilities.toLocaleString() ?? '—',
      sub: 'CISA KEV カタログ',
      color: 'text-violet-400',
    },
    {
      icon: <TrendingUp size={20} className="text-sky-400" />,
      label: '直近 30 日の新規 CVE',
      value: loading ? '—' : recent.length.toLocaleString(),
      sub: '実際に悪用された脆弱性',
      color: 'text-sky-400',
    },
    {
      icon: <Calendar size={20} className="text-amber-400" />,
      label: '最新追加日',
      value: loading ? '—' : latestDate ?? '—',
      sub: '直近30日以内',
      color: 'text-amber-400',
    },
  ]

  return (
    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
      {cards.map((card) => (
        <div key={card.label} className="bg-slate-800 rounded-2xl p-5 border border-slate-700">
          <div className="flex items-center gap-2 mb-3">
            {card.icon}
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">{card.label}</span>
          </div>
          <p className={`text-3xl font-bold ${card.color} mb-1`}>{card.value}</p>
          <p className="text-xs text-slate-500">{card.sub}</p>
        </div>
      ))}
    </div>
  )
}
