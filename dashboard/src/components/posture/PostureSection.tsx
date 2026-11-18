import { useId, type ReactNode } from 'react'
import { LastFetched } from '../freshness/LastFetched'
import type { FetchedCrawlerType } from '../freshness/freshnessConfig'
import { POSTURE_TEXT } from './postureConfig'
import type { Source } from './usePostureData'

// 態勢タブの1つのセクションの枠。見出し・最終取得・読み込み中・失敗（原因と再試行）を、ここで1か所に持つ。
// 本体は、取得できたときだけ、`children(値)` で描く。
export function PostureSection<T>({ title, crawlerType, source, onRetry, children }: {
  title: string
  // 「最終取得」に使う、クローラーの種別
  crawlerType: FetchedCrawlerType
  source: Source<T>
  onRetry: () => void
  children: (value: T) => ReactNode
}) {
  const headingId = useId()
  return (
    <section aria-labelledby={headingId} className="rounded-2xl border border-slate-800 bg-slate-900 p-4 flex flex-col gap-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <h3 id={headingId} className="text-sm font-semibold text-slate-200">{title}</h3>
        <LastFetched crawlerType={crawlerType} />
      </div>

      {source.status === 'loading' && (
        <div role="status" aria-label={POSTURE_TEXT.loading} className="h-24 rounded-lg bg-slate-800/60 animate-pulse" />
      )}

      {source.status === 'error' && (
        <div role="alert" className="flex flex-wrap items-center gap-3 rounded-lg border border-red-900 bg-red-950/40 px-3 py-2 text-sm text-red-300">
          <span>{POSTURE_TEXT.loadFailed}: {source.message}</span>
          <button
            onClick={onRetry}
            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
          >
            {POSTURE_TEXT.retry}
          </button>
        </div>
      )}

      {source.status === 'ready' && children(source.value)}
    </section>
  )
}
