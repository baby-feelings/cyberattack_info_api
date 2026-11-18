import { describe, expect, it } from 'vitest'
import { OverviewMetric } from './OverviewMetric'

const target = { tab: 'ops' as const }

describe('OverviewMetric', () => {
  it('treats null as unknown, not as zero', () => {
    const m = new OverviewMetric({ id: 'a', label: 'a', value: null, target })
    expect(m.state).toBe('unknown')
    expect(m.display()).toBe('不明')
  })
  it('is ok at 0 and warn above 0 for counts', () => {
    expect(new OverviewMetric({ id: 'a', label: 'a', value: 0, target }).state).toBe('ok')
    const warn = new OverviewMetric({ id: 'a', label: 'a', value: 3, target })
    expect(warn.state).toBe('warn')
    expect(warn.display()).toBe('3 件')
  })
  it('is ok only at 100 for percentages', () => {
    expect(new OverviewMetric({ id: 'a', label: 'a', value: 100, unit: 'percent', target }).state).toBe('ok')
    const m = new OverviewMetric({ id: 'a', label: 'a', value: 81, unit: 'percent', target })
    expect(m.state).toBe('warn')
    expect(m.display()).toBe('81%')
  })
})
