import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { fetchGithubAlerts, fetchRepoAudit, fetchSiteMonitor } from '../../api/client'
import { PosturePanel } from './PosturePanel'
import { POSTURE_TEXT } from './postureConfig'

vi.mock('../../api/client', async () => {
  const actual = await vi.importActual<typeof import('../../api/client')>('../../api/client')
  return { ...actual, fetchRepoAudit: vi.fn(), fetchGithubAlerts: vi.fn(), fetchSiteMonitor: vi.fn() }
})
vi.mock('../freshness/LastFetched', () => ({ LastFetched: () => null }))

const audit = vi.mocked(fetchRepoAudit)
const alerts = vi.mocked(fetchGithubAlerts)
const sites = vi.mocked(fetchSiteMonitor)

beforeEach(() => {
  vi.resetAllMocks()
  audit.mockResolvedValue({
    total: 1, repos_with_issues: 1,
    data: [{
      repo_full_name: 'owner/beta', score: 50, issues: 1, changes: [], audited_at: '2026-11-18T00:00:00Z',
      checks: [{ key: 'k', label: '項目K', status: 'ng', weight: 1, detail: '', fix: '' }],
    }],
  })
  alerts.mockResolvedValue({ total: 0, data: [], unavailable: [] })
  sites.mockResolvedValue({ total: 0, sites_with_issues: 0, data: [] })
})

describe('PosturePanel', () => {
  it('shows the three sections and the summary once loaded', async () => {
    render(<PosturePanel authToken="tok" />)

    await waitFor(() => expect(screen.getByRole('table', { name: POSTURE_TEXT.audit.title })).toBeInTheDocument())
    expect(screen.getByText(POSTURE_TEXT.alerts.empty)).toBeInTheDocument()
    expect(screen.getByText(POSTURE_TEXT.sites.empty)).toBeInTheDocument()
    expect(screen.getByRole('group', { name: '件数の集計' })).toHaveTextContent(`50${POSTURE_TEXT.summary.auditRate}`)
  })

  it('starts with the active apps, and asks the API again when the operating filter changes', async () => {
    const user = userEvent.setup()
    render(<PosturePanel authToken="tok" />)
    await waitFor(() => expect(audit).toHaveBeenCalledWith({ operating: 'active', authToken: 'tok' }))

    await user.click(screen.getByRole('button', { name: 'すべて' }))

    await waitFor(() => expect(audit).toHaveBeenLastCalledWith({ operating: 'all', authToken: 'tok' }))
    expect(alerts).toHaveBeenLastCalledWith({ operating: 'all', authToken: 'tok' })
    expect(sites).toHaveBeenLastCalledWith({ operating: 'all', authToken: 'tok' })
  })

  it('still shows the other sections when one source fails, and retries only that one', async () => {
    const user = userEvent.setup()
    alerts.mockRejectedValueOnce(new Error('API error 500: /api/github-alerts'))
    render(<PosturePanel authToken="tok" />)

    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(POSTURE_TEXT.loadFailed))
    expect(screen.getByRole('table', { name: POSTURE_TEXT.audit.title })).toBeInTheDocument()
    // 取得できなかった元は、集計の帯の下に、名前で示す（0 件とは、区別する）
    expect(screen.getByText(`${POSTURE_TEXT.summary.unknownPrefix} ${POSTURE_TEXT.sources.alerts}`)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: POSTURE_TEXT.retry }))

    await waitFor(() => expect(screen.getByText(POSTURE_TEXT.alerts.empty)).toBeInTheDocument())
    expect(alerts).toHaveBeenCalledTimes(2)
    expect(audit).toHaveBeenCalledTimes(1)
  })
})
