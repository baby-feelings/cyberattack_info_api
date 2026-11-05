import { useEffect, useState } from 'react'
import { fetchCrawlerLogs, type CrawlerLogOut } from '../../api/crawlerLogs'
import { classifyFreshness, pickLatestRuns } from './freshness'
import {
  LOG_LOOKBACK, REFETCH_MS, TICK_MS, type FetchedCrawlerType, type FreshnessState,
} from './freshnessConfig'

export interface CrawlFreshness {
  state: FreshnessState
  // 直近の実行と、最後に成功した実行（実行記録が無い・取得に失敗したときは null）
  latest: CrawlerLogOut | null
  lastSuccess: CrawlerLogOut | null
  // 相対時間の計算に使う現在時刻（一定間隔で更新する）
  now: Date
}

// 指定したクローラーの実行履歴から、「最終取得」の状態を求める。
// 実行履歴は一定間隔で取り直し、相対時間の表示は、それより短い間隔で更新する。
export function useCrawlFreshness(crawlerType: FetchedCrawlerType): CrawlFreshness {
  const [logs, setLogs] = useState<CrawlerLogOut[]>([])
  const [now, setNow] = useState(() => new Date())

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const result = await fetchCrawlerLogs({ crawlerType, limit: LOG_LOOKBACK })
        if (!cancelled) {
          setLogs(result)
          // 基準時刻も取得時点に更新する（古い時刻のままだと、経過時間を実際より短く表示してしまう）
          setNow(new Date())
        }
      } catch {
        // 取得に失敗しても画面を壊さない（前回の結果を残し、無ければ「確認できません」を表示する）
      }
    }
    load()
    const refetch = setInterval(load, REFETCH_MS)
    return () => {
      cancelled = true
      clearInterval(refetch)
    }
  }, [crawlerType])

  useEffect(() => {
    const tick = setInterval(() => setNow(new Date()), TICK_MS)
    return () => clearInterval(tick)
  }, [])

  const runs = pickLatestRuns(logs)
  return { state: classifyFreshness(runs, now), ...runs, now }
}
