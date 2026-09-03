import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { DepscanPanel } from './DepscanPanel'
import {
  fetchAllDepscanFindings, fetchDepscanStats, fetchCrawlerLogs,
  type DependencyFindingOut, type DepscanStatsResponse,
} from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    fetchAllDepscanFindings: vi.fn(),
    fetchDepscanStats: vi.fn(),
    fetchCrawlerLogs: vi.fn(),
  }
})

const mockedFindings = vi.mocked(fetchAllDepscanFindings)
const mockedStats = vi.mocked(fetchDepscanStats)
const mockedLogs = vi.mocked(fetchCrawlerLogs)

function finding(overrides: Partial<DependencyFindingOut> = {}): DependencyFindingOut {
  return {
    repo_full_name: 'baby-feelings/baby_grow',
    ecosystem: 'PyPI',
    package_name: 'cryptography',
    installed_version: '3.4.7',
    osv_id: 'GHSA-1',
    severity: 'HIGH',
    cvss_score: 7.5,
    summary: 'vuln',
    fixed_versions: ['3.4.8'],
    manifest_path: 'requirements.txt',
    detected_at: '2026-06-01T00:00:00Z',
    resolved_at: null,
    ...overrides,
  }
}

const EMPTY_STATS: DepscanStatsResponse = { total: 0, repos: [], severities: [] }

describe('DepscanPanel', () => {
  beforeEach(() => {
    mockedLogs.mockResolvedValue([{
      id: 1, crawler_type: 'DEPSCAN', status: 'success',
      started_at: '2026-06-01T00:00:00Z', finished_at: '2026-06-01T00:01:00Z',
      duration_seconds: 60, inserted: 0, updated: 0, deleted: 0, error_message: null,
    }])
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.resetAllMocks()
  })

  it('shows the empty state when there are no findings', async () => {
    mockedFindings.mockResolvedValue([])
    mockedStats.mockResolvedValue(EMPTY_STATS)

    render(<DepscanPanel />)
    await waitFor(() => expect(screen.getByText('該当する依存ライブラリ脆弱性はありません')).toBeInTheDocument())
  })

  it('groups findings by package and renders a row per group', async () => {
    mockedFindings.mockResolvedValue([
      finding({ osv_id: 'GHSA-1' }),
      finding({ osv_id: 'GHSA-2' }), // same repo/package/version -> merges into the same group
      finding({ package_name: 'requests', osv_id: 'GHSA-3' }),
    ])
    mockedStats.mockResolvedValue({
      total: 3,
      repos: [{ repo_full_name: 'baby-feelings/baby_grow', count: 3 }],
      severities: [{ severity: 'HIGH', count: 3 }],
    })

    render(<DepscanPanel />)
    await waitFor(() => expect(screen.getByText('cryptography')).toBeInTheDocument())
    expect(screen.getByText('requests')).toBeInTheDocument()
    expect(screen.getByText(/3 件（2 パッケージ）/)).toBeInTheDocument()
  })

  it('only shows the owner filter when findings span more than one owner', async () => {
    mockedFindings.mockResolvedValue([finding()])
    mockedStats.mockResolvedValue({
      total: 1,
      repos: [{ repo_full_name: 'baby-feelings/baby_grow', count: 1 }],
      severities: [],
    })

    render(<DepscanPanel />)
    await waitFor(() => expect(screen.getByText('cryptography')).toBeInTheDocument())
    expect(screen.queryByText('baby-feelings')).not.toBeInTheDocument()
  })

  it('shows an owner filter button set when multiple owners are present', async () => {
    mockedFindings.mockResolvedValue([finding()])
    mockedStats.mockResolvedValue({
      total: 2,
      repos: [
        { repo_full_name: 'baby-feelings/baby_grow', count: 1 },
        { repo_full_name: 'octocat/hello-world', count: 1 },
      ],
      severities: [],
    })

    render(<DepscanPanel />)
    await waitFor(() => expect(screen.getByText('baby-feelings')).toBeInTheDocument())
    expect(screen.getByText('octocat')).toBeInTheDocument()
  })

  it('reloads with the selected owner when an owner filter button is clicked', async () => {
    mockedFindings.mockResolvedValue([finding()])
    mockedStats.mockResolvedValue({
      total: 2,
      repos: [
        { repo_full_name: 'baby-feelings/baby_grow', count: 1 },
        { repo_full_name: 'octocat/hello-world', count: 1 },
      ],
      severities: [],
    })
    const user = userEvent.setup()

    render(<DepscanPanel />)
    await waitFor(() => expect(screen.getByText('octocat')).toBeInTheDocument())

    await user.click(screen.getByText('octocat'))
    await waitFor(() => expect(mockedFindings).toHaveBeenLastCalledWith(
      expect.objectContaining({ owner: 'octocat' }),
    ))
  })

  it('reloads including resolved findings when the toggle is clicked', async () => {
    mockedFindings.mockResolvedValue([])
    mockedStats.mockResolvedValue(EMPTY_STATS)
    const user = userEvent.setup()

    render(<DepscanPanel />)
    await waitFor(() => expect(mockedFindings).toHaveBeenCalledTimes(1))
    expect(mockedFindings).toHaveBeenLastCalledWith(expect.objectContaining({ resolved: false }))

    await user.click(screen.getByText('解決済みを含む'))
    await waitFor(() => expect(mockedFindings).toHaveBeenCalledTimes(2))
    expect(mockedFindings).toHaveBeenLastCalledWith(expect.objectContaining({ resolved: null }))
  })

  it('reloads with the selected severity when a severity filter is clicked', async () => {
    mockedFindings.mockResolvedValue([])
    mockedStats.mockResolvedValue(EMPTY_STATS)
    const user = userEvent.setup()

    render(<DepscanPanel />)
    await waitFor(() => expect(mockedFindings).toHaveBeenCalledTimes(1))
    expect(mockedFindings).toHaveBeenLastCalledWith(
      expect.objectContaining({ severity: null }),
    )

    await user.click(screen.getByText('CRITICAL'))
    await waitFor(() => expect(mockedFindings).toHaveBeenCalledTimes(2))
    expect(mockedFindings).toHaveBeenLastCalledWith(
      expect.objectContaining({ severity: 'CRITICAL' }),
    )
  })

  it('passes the authToken through to the API calls when provided', async () => {
    mockedFindings.mockResolvedValue([])
    mockedStats.mockResolvedValue(EMPTY_STATS)

    render(<DepscanPanel authToken="session-tok" />)
    await waitFor(() => expect(mockedFindings).toHaveBeenCalledTimes(1))
    expect(mockedFindings).toHaveBeenCalledWith(expect.objectContaining({ authToken: 'session-tok' }))
    expect(mockedStats).toHaveBeenCalledWith('session-tok')
  })

  it('shows a "new data available" banner once the crawl log id changes, and clears it on refresh', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    mockedFindings.mockResolvedValue([])
    mockedStats.mockResolvedValue(EMPTY_STATS)

    render(<DepscanPanel />)
    await waitFor(() => expect(mockedLogs).toHaveBeenCalledTimes(1))

    mockedLogs.mockResolvedValue([{
      id: 2, crawler_type: 'DEPSCAN', status: 'success',
      started_at: '2026-06-02T00:00:00Z', finished_at: '2026-06-02T00:01:00Z',
      duration_seconds: 60, inserted: 1, updated: 0, deleted: 0, error_message: null,
    }])

    await vi.advanceTimersByTimeAsync(120000)
    await waitFor(() => expect(screen.getByText('新しいデータがあります')).toBeInTheDocument())

    vi.useRealTimers()
    const user = userEvent.setup()
    await user.click(screen.getByText('更新'))
    await waitFor(() => expect(screen.queryByText('新しいデータがあります')).not.toBeInTheDocument())
  })
})
