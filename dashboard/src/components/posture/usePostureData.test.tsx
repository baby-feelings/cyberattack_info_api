import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor, act } from '@testing-library/react'
import { fetchGithubAlerts, fetchRepoAudit, fetchSiteMonitor } from '../../api/client'
import { AlertList } from './model/AlertList'
import { AuditMatrix } from './model/AuditMatrix'
import { SiteCheck } from './model/SiteCheck'
import { usePostureData } from './usePostureData'

vi.mock('../../api/client', async () => {
  const actual = await vi.importActual<typeof import('../../api/client')>('../../api/client')
  return { ...actual, fetchRepoAudit: vi.fn(), fetchGithubAlerts: vi.fn(), fetchSiteMonitor: vi.fn() }
})

const audit = vi.mocked(fetchRepoAudit)
const alerts = vi.mocked(fetchGithubAlerts)
const sites = vi.mocked(fetchSiteMonitor)

beforeEach(() => {
  vi.resetAllMocks()
  audit.mockResolvedValue({ total: 0, repos_with_issues: 0, data: [] })
  alerts.mockResolvedValue({ total: 0, data: [], unavailable: [] })
  sites.mockResolvedValue({ total: 0, sites_with_issues: 0, data: [] })
})

describe('usePostureData', () => {
  it('loads the three sources and turns them into model objects', async () => {
    const { result } = renderHook(() => usePostureData('tok', 'active'))

    expect(result.current.audit.status).toBe('loading')
    await waitFor(() => {
      expect(result.current.audit.status).toBe('ready')
      expect(result.current.alerts.status).toBe('ready')
      expect(result.current.sites.status).toBe('ready')
    })
    if (result.current.audit.status === 'ready') expect(result.current.audit.value).toBeInstanceOf(AuditMatrix)
    if (result.current.alerts.status === 'ready') expect(result.current.alerts.value).toBeInstanceOf(AlertList)
    if (result.current.sites.status === 'ready') {
      expect(result.current.sites.value.every((s) => s instanceof SiteCheck)).toBe(true)
    }
  })

  it('passes the session token and the operating status to every request', async () => {
    renderHook(() => usePostureData('tok', 'inactive'))

    await waitFor(() => expect(audit).toHaveBeenCalled())
    expect(audit).toHaveBeenCalledWith({ operating: 'inactive', authToken: 'tok' })
    expect(alerts).toHaveBeenCalledWith({ operating: 'inactive', authToken: 'tok' })
    expect(sites).toHaveBeenCalledWith({ operating: 'inactive', authToken: 'tok' })
  })

  it('keeps the other sources when one of them fails', async () => {
    alerts.mockRejectedValue(new Error('API error 500: /api/github-alerts'))
    const { result } = renderHook(() => usePostureData('tok', 'active'))

    await waitFor(() => expect(result.current.alerts.status).toBe('error'))
    expect(result.current.alerts).toEqual({ status: 'error', message: 'API error 500: /api/github-alerts' })
    await waitFor(() => expect(result.current.audit.status).toBe('ready'))
    expect(result.current.sites.status).toBe('ready')
  })

  it('reloads only the requested source', async () => {
    const { result } = renderHook(() => usePostureData('tok', 'active'))
    await waitFor(() => expect(result.current.alerts.status).toBe('ready'))

    act(() => result.current.reload('alerts'))

    await waitFor(() => expect(alerts).toHaveBeenCalledTimes(2))
    expect(audit).toHaveBeenCalledTimes(1)
    expect(sites).toHaveBeenCalledTimes(1)
  })

  it('reloads all three sources when the operating status changes', async () => {
    const { result, rerender } = renderHook(
      ({ operating }) => usePostureData('tok', operating), { initialProps: { operating: 'active' as const } },
    )
    await waitFor(() => expect(result.current.audit.status).toBe('ready'))

    rerender({ operating: 'all' as never })

    await waitFor(() => expect(audit).toHaveBeenCalledTimes(2))
    expect(alerts).toHaveBeenCalledTimes(2)
    expect(sites).toHaveBeenCalledTimes(2)
    expect(audit).toHaveBeenLastCalledWith({ operating: 'all', authToken: 'tok' })
  })
})
