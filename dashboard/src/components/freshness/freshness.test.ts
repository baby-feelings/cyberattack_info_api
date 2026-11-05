import { describe, expect, it } from 'vitest'
import type { CrawlerLogOut } from '../../api/crawlerLogs'
import {
  classifyFreshness, formatAbsolute, formatRelative, parseApiDate, pickLatestRuns,
} from './freshness'
import { STALE_AFTER_HOURS } from './freshnessConfig'

const NOW = new Date('2026-11-05T12:00:00Z')

// 現在時刻の hours 時間前に終わった実行
function log(status: string, hoursAgo: number, id = 1): CrawlerLogOut {
  const finished = new Date(NOW.getTime() - hoursAgo * 3_600_000).toISOString()
  return {
    id, crawler_type: 'KEV', status, started_at: finished, finished_at: finished,
    duration_seconds: 1, inserted: 0, updated: 0, deleted: 0, error_message: null,
  }
}

describe('parseApiDate', () => {
  it('reads a value with a time zone as it is', () => {
    expect(parseApiDate('2026-11-05T03:00:00Z').toISOString()).toBe('2026-11-05T03:00:00.000Z')
    expect(parseApiDate('2026-11-05T12:00:00+09:00').toISOString()).toBe('2026-11-05T03:00:00.000Z')
    expect(parseApiDate('2026-11-05T03:00:00.123456+00:00').getTime())
      .toBe(new Date('2026-11-05T03:00:00.123Z').getTime())
  })

  it('reads a value without a time zone (dev SQLite) as UTC, not as local time', () => {
    expect(parseApiDate('2026-11-05T03:00:00').toISOString()).toBe('2026-11-05T03:00:00.000Z')
    expect(parseApiDate('2026-11-05T03:00:00.426213').toISOString()).toBe('2026-11-05T03:00:00.426Z')
  })
})

describe('pickLatestRuns', () => {
  it('takes the newest run and the newest success from a newest-first list', () => {
    const logs = [log('error', 1, 3), log('error', 2, 2), log('success', 30, 1)]
    const { latest, lastSuccess } = pickLatestRuns(logs)
    expect(latest?.id).toBe(3)
    expect(lastSuccess?.id).toBe(1)
  })

  it('returns nulls for an empty list and null success when none succeeded', () => {
    expect(pickLatestRuns([])).toEqual({ latest: null, lastSuccess: null })
    expect(pickLatestRuns([log('error', 1)]).lastSuccess).toBeNull()
  })
})

describe('classifyFreshness', () => {
  const runsOf = (...logs: CrawlerLogOut[]) => pickLatestRuns(logs)

  it('is unknown when there are no runs', () => {
    expect(classifyFreshness(runsOf(), NOW)).toBe('unknown')
  })

  it('is fresh within the allowed hours and stale after them', () => {
    expect(classifyFreshness(runsOf(log('success', 3)), NOW)).toBe('fresh')
    expect(classifyFreshness(runsOf(log('success', STALE_AFTER_HOURS)), NOW)).toBe('fresh')
    expect(classifyFreshness(runsOf(log('success', STALE_AFTER_HOURS + 0.1)), NOW)).toBe('stale')
  })

  it('is failed when the latest run failed, even if an older run succeeded recently', () => {
    expect(classifyFreshness(runsOf(log('error', 1), log('success', 2)), NOW)).toBe('failed')
  })

  it('is failed when the only runs so far failed', () => {
    expect(classifyFreshness(runsOf(log('error', 1)), NOW)).toBe('failed')
  })

  it('uses a custom threshold when given', () => {
    expect(classifyFreshness(runsOf(log('success', 5)), NOW, 4)).toBe('stale')
    expect(classifyFreshness(runsOf(log('success', 5)), NOW, 6)).toBe('fresh')
  })
})

describe('formatRelative', () => {
  const ago = (hours: number) => new Date(NOW.getTime() - hours * 3_600_000).toISOString()

  it('uses the largest whole unit (minutes, hours, days)', () => {
    expect(formatRelative(ago(0.5), NOW)).toContain('30')
    expect(formatRelative(ago(0.5), NOW)).toContain('分')
    expect(formatRelative(ago(3), NOW)).toContain('3')
    expect(formatRelative(ago(3), NOW)).toContain('時間')
    expect(formatRelative(ago(50), NOW)).toContain('2')
    expect(formatRelative(ago(50), NOW)).toContain('日')
  })

  it('counts 24-hour blocks, never "yesterday" (a calendar-day claim)', () => {
    expect(formatRelative(ago(47), NOW)).not.toContain('昨日')
    expect(formatRelative(ago(47), NOW)).toContain('1')
  })

  it('has a natural expression for less than a minute', () => {
    const text = formatRelative(NOW.toISOString(), NOW)
    expect(text).not.toBe('')
    expect(text).not.toContain('-')
  })
})

describe('formatAbsolute', () => {
  it('shows month, day and time in the viewer time zone from a UTC value', () => {
    const text = formatAbsolute('2026-11-05T03:05:00Z')
    expect(text).toMatch(/11\/05 \d{2}:05/)
  })
})
