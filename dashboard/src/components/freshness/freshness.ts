// 「最終取得」の判定と、日時の整形。表示から切り離した純粋な関数で、時刻を引数で受け取る（テストしやすくする）。
import type { CrawlerLogOut } from '../../api/crawlerLogs'
import { DISPLAY_LOCALE, STALE_AFTER_HOURS, type FreshnessState } from './freshnessConfig'

const MS_PER_HOUR = 3_600_000

// タイムゾーンの指定（Z・+09:00 など）で終わっているか
const HAS_TIME_ZONE = /(Z|[+-]\d{2}:?\d{2})$/i

// API の日時を Date にする。API の日時は UTC で、開発用の SQLite はタイムゾーンを付けずに返すため、
// 指定が無いときは UTC として読む（そのまま読むと、ブラウザが現地時間とみなして、数時間ずれる）
export function parseApiDate(value: string): Date {
  return new Date(HAS_TIME_ZONE.test(value) ? value : `${value}Z`)
}

// 実行履歴（新しい順）から、直近の実行と、最後に成功した実行を取り出す
export function pickLatestRuns(logs: CrawlerLogOut[]): {
  latest: CrawlerLogOut | null
  lastSuccess: CrawlerLogOut | null
} {
  return {
    latest: logs[0] ?? null,
    lastSuccess: logs.find((log) => log.status === 'success') ?? null,
  }
}

// 取得状況の状態を決める。直近の実行の失敗を最優先し、次に、成功からの経過時間を見る
export function classifyFreshness(
  runs: { latest: CrawlerLogOut | null; lastSuccess: CrawlerLogOut | null },
  now: Date,
  staleAfterHours: number = STALE_AFTER_HOURS,
): FreshnessState {
  if (!runs.latest) return 'unknown'
  if (runs.latest.status !== 'success') return 'failed'
  if (!runs.lastSuccess) return 'unknown'
  const elapsedHours = (now.getTime() - parseApiDate(runs.lastSuccess.finished_at).getTime()) / MS_PER_HOUR
  return elapsedHours > staleAfterHours ? 'stale' : 'fresh'
}

// 相対時間の単位。大きい単位から並べ、経過時間が最初に1以上になる単位で表示する
const RELATIVE_UNITS: { unit: Intl.RelativeTimeFormatUnit; ms: number }[] = [
  { unit: 'day', ms: 24 * MS_PER_HOUR },
  { unit: 'hour', ms: MS_PER_HOUR },
  { unit: 'minute', ms: 60_000 },
]

// 「3 時間前」のような相対時間。文言は Intl が作る（手書きの日本語を持たない）。
// 経過時間を24時間ごとに数えるため、暦の日を指す「昨日」ではなく「1 日前」の形（numeric: 'always'）にする。
// 1分に満たないときだけ、Intl の自然な表現（「1 分以内」）を使う。
export function formatRelative(date: string, now: Date): string {
  const elapsed = now.getTime() - parseApiDate(date).getTime()
  const match = RELATIVE_UNITS.find(({ ms }) => elapsed >= ms)
  if (!match) {
    return new Intl.RelativeTimeFormat(DISPLAY_LOCALE, { numeric: 'auto' }).format(0, 'minute')
  }
  return new Intl.RelativeTimeFormat(DISPLAY_LOCALE, { numeric: 'always' })
    .format(-Math.floor(elapsed / match.ms), match.unit)
}

// 「11/05 13:00」のような、正確な日時（閲覧者のタイムゾーン）
export function formatAbsolute(date: string): string {
  return parseApiDate(date).toLocaleString(DISPLAY_LOCALE, {
    month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
  })
}
