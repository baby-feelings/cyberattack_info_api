// 帯に並べる1つの数字（件数と、その意味を表すラベル）
export interface StatItem {
  // null のときは表示しない（取得できない数字を 0 と誤解させないため）
  value: number | null
  label: string
  tone?: 'sky' | 'red'
}

const TONE_CLS: Record<NonNullable<StatItem['tone']>, string> = {
  sky: 'text-sky-400',
  red: 'text-red-400',
}

// KEV・OSV・JVN 共通の件数の帯。期間内に何件あり、そのうち注目すべきものが何件かを、大きく見せる
export function StatBand({ items, loading }: { items: StatItem[]; loading: boolean }) {
  if (loading) {
    return <div role="status" aria-label="集計中" className="h-12 w-72 rounded-lg bg-slate-800/60 animate-pulse" />
  }
  return (
    <div role="group" aria-label="件数の集計" className="flex flex-wrap items-end gap-x-8 gap-y-2">
      {items.filter(item => item.value !== null).map(item => (
        <div key={item.label} className="flex items-end gap-2">
          <span className={`text-4xl font-bold leading-none tabular-nums ${TONE_CLS[item.tone ?? 'sky']}`}>
            {item.value}
          </span>
          <span className="text-sm text-slate-300">{item.label}</span>
        </div>
      ))}
    </div>
  )
}
