import { describe, it, expect } from 'vitest'
import { recentMonths, TREND_MONTHS } from './trend'

const MONTHS = Array.from({ length: 13 }, (_, i) => ({
  year_month: `2025-${String(i + 1).padStart(2, '0')}`,
  count: i,
}))

describe('recentMonths', () => {
  it('keeps only the newest 6 months by default, in the original order', () => {
    const result = recentMonths(MONTHS)
    expect(result.length).toBe(TREND_MONTHS)
    expect(result[0].year_month).toBe('2025-08')
    expect(result[result.length - 1].year_month).toBe('2025-13')
  })

  it('returns everything when there are fewer months than requested', () => {
    expect(recentMonths(MONTHS.slice(0, 3))).toEqual(MONTHS.slice(0, 3))
  })

  it('accepts a different number of months, and 0 returns nothing', () => {
    expect(recentMonths(MONTHS, 2).map(m => m.count)).toEqual([11, 12])
    expect(recentMonths(MONTHS, 0)).toEqual([])
  })

  it('returns an empty list for no data', () => {
    expect(recentMonths([])).toEqual([])
  })
})
