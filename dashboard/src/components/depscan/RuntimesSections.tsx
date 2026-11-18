import type { RepoRuntimeOut, RepoRuntimeRepoStat, RuntimeReleaseOut, RuntimeState } from '../../api/client'
import { RECOMMEND_MIN_AGE_DAYS, STATE_BADGE } from './runtimesConfig'
import { isNewerCycle } from './runtimeCycles'

export function StateBadge({ state }: { state: RuntimeState }) {
  const { label, cls } = STATE_BADGE[state]
  return (
    <span className={`inline-block px-1.5 py-0.5 rounded text-xs font-medium border whitespace-nowrap ${cls}`}>
      {label}
    </span>
  )
}

// サポート終了日と、終了までの日数（過ぎていれば「終了済み」）。期限が定められていないものは「—」
export function EolCell({ item }: { item: RepoRuntimeOut }) {
  if (!item.eol_date) return <span className="text-slate-600">—</span>
  const days = item.days_to_eol
  const note = days === null ? '' : days < 0 ? '（終了済み）' : `（あと ${days} 日）`
  return (
    <span className="tabular-nums">
      {item.eol_date}
      <span className="text-slate-500">{note}</span>
    </span>
  )
}

// 左のアプリ一覧に出すバッジ。対応が必要な数を目立たせ、無いアプリは検出した数を薄く出す
export function RepoBadge({ stat }: { stat: RepoRuntimeRepoStat }) {
  if (stat.needs_action === 0) {
    return <span className="text-slate-500 tabular-nums" title="検出した言語・実行環境の数">{stat.total}</span>
  }
  return (
    <span
      className="px-1.5 rounded-full bg-orange-500/15 text-orange-400 font-semibold tabular-nums"
      title="対応が必要な数（サポート終了・期限間近・更新あり）"
    >
      {stat.needs_action}
    </span>
  )
}

// 言語ごとの推奨の版（サポート中で、公開から経った最新）。何に更新すればよいかの目安
export function RecommendedStrip({ releases }: { releases: RuntimeReleaseOut[] }) {
  const recommended = releases.filter(r => r.recommended)
  if (recommended.length === 0) return null
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-400" aria-label="推奨の版">
      <span className="text-slate-500">推奨の版</span>
      {recommended.map(r => (
        <span key={r.runtime} className="tabular-nums">
          <span className="text-slate-300">{r.runtime_label} {r.cycle}</span>
          <span className="text-slate-500">（最新 {r.latest_version}）</span>
        </span>
      ))}
    </div>
  )
}

// 言語ごとに、推奨より新しい系列（公開直後で、まだ推奨にならないもの）。Slack の「新しい版が
// 公開されました」の通知と、「推奨の版」を、取り違えないために併記する
export function NewerSeriesNote({ releases }: { releases: RuntimeReleaseOut[] }) {
  const newer = releases
    .filter(r => r.recommended)
    .flatMap(rec => {
      const candidates = releases.filter(r =>
        r.runtime === rec.runtime && !r.is_eol && (r.is_lts || r.runtime !== 'nodejs')
        && isNewerCycle(r.cycle, rec.cycle))
      const latest = candidates.reduce<RuntimeReleaseOut | null>(
        (best, r) => (best === null || isNewerCycle(r.cycle, best.cycle) ? r : best), null)
      return latest ? [latest] : []
    })
  if (newer.length === 0) return null
  return (
    <div className="space-y-0.5 text-xs text-slate-500" aria-label="公開済みの新しい系列">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 tabular-nums">
        <span>新しい系列</span>
        {newer.map(r => (
          <span key={r.runtime}>
            <span className="text-slate-400">{r.runtime_label} {r.cycle}</span>
            <span>（最新 {r.latest_version}）</span>
          </span>
        ))}
      </div>
      <p className="text-[11px]">
        公開から{RECOMMEND_MIN_AGE_DAYS}日たつまで、推奨にしません（公開直後は、ライブラリの対応が追いつかないため）。
        Slack の「新しい版が公開されました」は、この新しい系列の通知です。
      </p>
    </div>
  )
}
