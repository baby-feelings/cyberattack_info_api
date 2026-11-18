import { describe, expect, it, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { useOverviewData } from './useOverviewData'
import * as client from '../../api/client'

vi.mock('../../api/client', () => ({
  fetchDepscanStats: vi.fn(), fetchSlaReport: vi.fn(), fetchRuntimes: vi.fn(), fetchGithubAlerts: vi.fn(),
  fetchCodescanStats: vi.fn(), fetchRepoAudit: vi.fn(), fetchSiteMonitor: vi.fn(),
}))

const mocked = vi.mocked(client)

beforeEach(() => {
  mocked.fetchDepscanStats.mockResolvedValue({ total: 3, repos: [], severities: [] })
  mocked.fetchSlaReport.mockResolvedValue({ summary: { overdue: 1 } } as never)
  mocked.fetchRuntimes.mockResolvedValue({ total: 3, data: [{ state: 'eol' }, { state: 'latest' }, { state: 'eol_soon' }] } as never)
  mocked.fetchGithubAlerts.mockResolvedValue({
    total: 3, unavailable: [], data: [{ kind: 'dependabot' }, { kind: 'code' }, { kind: 'secret' }],
  } as never)
  mocked.fetchCodescanStats.mockResolvedValue({ total: 5, excepted_total: 0, repos: [], severities: [] })
  mocked.fetchRepoAudit.mockResolvedValue({ total: 2, repos_with_issues: 0, data: [{ score: 80 }, { score: 100 }, { score: null }] } as never)
  mocked.fetchSiteMonitor.mockResolvedValue({ total: 1, sites_with_issues: 7, data: [] })
})

const valueOf = (metrics: { id: string; value: number | null }[], id: string) => metrics.find((m) => m.id === id)?.value

describe('useOverviewData', () => {
  it('collects each metric from its source', async () => {
    const { result } = renderHook(() => useOverviewData('tok'))
    await waitFor(() => expect(result.current.loading).toBe(false))
    const m = result.current.metrics
    expect(valueOf(m, 'dep-open')).toBe(3)
    expect(valueOf(m, 'dep-overdue')).toBe(1)
    expect(valueOf(m, 'dep-eol')).toBe(2)
    expect(valueOf(m, 'dep-alerts')).toBe(1)
    expect(valueOf(m, 'code-alerts')).toBe(2)
    expect(valueOf(m, 'code-open')).toBe(5)
    expect(valueOf(m, 'code-audit')).toBe(90)
    expect(valueOf(m, 'ops-sites')).toBe(7)
  })

  it('marks only the failed metric as unknown', async () => {
    mocked.fetchSlaReport.mockRejectedValue(new Error('boom'))
    const { result } = renderHook(() => useOverviewData('tok'))
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(valueOf(result.current.metrics, 'dep-overdue')).toBeNull()
    expect(valueOf(result.current.metrics, 'dep-open')).toBe(3)
  })
})
