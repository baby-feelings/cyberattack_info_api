import type { CrawlerLogOut } from '../../api/crawlerLogs'
import { formatAbsolute, formatRelative } from './freshness'
import { FRESHNESS_STYLE, FRESHNESS_TEXT, type FetchedCrawlerType } from './freshnessConfig'
import { useCrawlFreshness } from './useCrawlFreshness'

// 実行の内訳（新規・更新の件数）。どちらも 0 のときは「変化なし」
function runSummary(log: CrawlerLogOut): string {
  const parts = [
    log.inserted > 0 ? FRESHNESS_TEXT.inserted(log.inserted) : null,
    log.updated > 0 ? FRESHNESS_TEXT.updated(log.updated) : null,
  ].filter((part): part is string => part !== null)
  return parts.length > 0 ? parts.join('・') : FRESHNESS_TEXT.noChange
}

// タブの見出しに添える「最終取得」。データを最後に取得した時刻と、遅れ・失敗を示す。
// 状態は点の色だけでなく文言でも示す（色の違いが分からなくても読み取れるようにする）。
export function LastFetched({ crawlerType }: { crawlerType: FetchedCrawlerType }) {
  const { state, latest, lastSuccess, now } = useCrawlFreshness(crawlerType)
  const style = FRESHNESS_STYLE[state]

  // 1行目: 状態と相対時間。2行目: 正確な日時と、実行の内訳
  let headline: string
  let detail: string | null = null
  if (state === 'unknown' || !lastSuccess) {
    headline = FRESHNESS_TEXT.unknown
  } else if (state === 'failed') {
    headline = FRESHNESS_TEXT.failed
    detail = `${FRESHNESS_TEXT.lastSuccess} ${formatRelative(lastSuccess.finished_at, now)}（${formatAbsolute(lastSuccess.finished_at)}）`
  } else {
    headline = `${FRESHNESS_TEXT.label} ${formatRelative(lastSuccess.finished_at, now)}`
    detail = `${formatAbsolute(lastSuccess.finished_at)} · ${runSummary(lastSuccess)}`
    if (state === 'stale') headline = `${headline}（${FRESHNESS_TEXT.stale}）`
  }

  return (
    <div
      data-testid="last-fetched"
      data-state={state}
      className="flex items-start gap-2 sm:ml-auto sm:text-right"
    >
      <span aria-hidden="true" className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${style.dot}`} />
      <div className="leading-tight">
        <p className={`text-xs font-medium ${style.text}`}>
          {lastSuccess ? (
            <time dateTime={(state === 'failed' ? latest : lastSuccess)?.finished_at}>{headline}</time>
          ) : headline}
        </p>
        {detail && <p className="mt-0.5 text-xs tabular-nums text-slate-500">{detail}</p>}
      </div>
    </div>
  )
}
