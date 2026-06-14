import { Shield, TrendingUp, Calendar } from 'lucide-react'
import type { StatsResponse, VulnerabilityOut } from '../api/client'

interface Props {
  stats: StatsResponse | null
  recent: VulnerabilityOut[]
  loading: boolean
}

export function StatsCards({ stats, recent, loading }: Props) {
  const latestDate = recent.length > 0
    ? recent.reduce((a, b) => a.date_added > b.date_added ? a : b).date_added
    : null

  const cards = [
    {
      icon: Shield,
      iconColor: 'text-violet-400',
      iconBg: 'bg-violet-500/10',
      accent: 'from-violet-500/20 to-transparent',
      borderColor: 'border-violet-500/20',
      label: '登録済み CVE 総数',
      value: loading ? '—' : (stats?.total_vulnerabilities.toLocaleString() ?? '—'),
      sub: 'CISA KEV カタログ収録',
    },
    {
      icon: TrendingUp,
      iconColor: 'text-sky-400',
      iconBg: 'bg-sky-500/10',
      accent: 'from-sky-500/20 to-transparent',
      borderColor: 'border-sky-500/20',
      label: '直近 30 日の新規 CVE',
      value: loading ? '—' : recent.length.toLocaleString(),
      sub: '実際に悪用が確認された脆弱性',
    },
    {
      icon: Calendar,
      iconColor: 'text-amber-400',
      iconBg: 'bg-amber-500/10',
      accent: 'from-amber-500/20 to-transparent',
      borderColor: 'border-amber-500/20',
      label: '最終追加日',
      value: loading ? '—' : (latestDate ?? 'なし'),
      sub: '直近 30 日以内の最新',
    },
  ]

  return (
    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
      {cards.map(({ icon: Icon, iconColor, iconBg, accent, borderColor, label, value, sub }) => (
        <div
          key={label}
          className={`relative overflow-hidden rounded-2xl border ${borderColor} bg-slate-900 p-5 shadow-lg`}
        >
          {/* 背景グラデーション装飾 */}
          <div className={`absolute inset-0 bg-gradient-to-br ${accent} pointer-events-none`} />

          <div className="relative">
            <div className="flex items-center gap-2 mb-4">
              <span className={`inline-flex p-2 rounded-lg ${iconBg}`}>
                <Icon size={15} className={iconColor} />
              </span>
              <span className="text-xs font-medium text-slate-400">{label}</span>
            </div>
            <p className={`text-3xl font-bold tracking-tight ${loading ? 'text-slate-600 animate-pulse' : 'text-white'} mb-1`}>
              {value}
            </p>
            <p className="text-xs text-slate-500">{sub}</p>
          </div>
        </div>
      ))}
    </div>
  )
}
