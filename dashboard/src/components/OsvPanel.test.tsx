import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { OsvPanel } from './OsvPanel'
import {
  fetchOsvList, fetchOsvStats,
  type OsvVulnerabilityOut, type OsvListResponse, type OsvStatsResponse,
} from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    fetchOsvList: vi.fn(),
    fetchOsvStats: vi.fn(),
  }
})

const mockedList = vi.mocked(fetchOsvList)
const mockedStats = vi.mocked(fetchOsvStats)

function item(overrides: Partial<OsvVulnerabilityOut> = {}): OsvVulnerabilityOut {
  return {
    osv_id: 'GHSA-xxxx-xxxx-xxxx',
    ecosystem: 'PyPI',
    package_name: 'cryptography',
    aliases: ['CVE-2026-12345'],
    summary: 'DNS name constraints bypass',
    details: 'Full details here',
    severity: 'HIGH',
    cvss_score: 7.5,
    affected_versions: ['<46.0.6'],
    fixed_versions: ['46.0.6'],
    references: ['https://example.com/advisory'],
    published: '2026-06-01T00:00:00Z',
    modified: '2026-06-15T00:00:00Z',
    ...overrides,
  }
}

const EMPTY_LIST: OsvListResponse = { total: 0, page: 1, per_page: 30, data: [] }
const EMPTY_STATS: OsvStatsResponse = { total: 0, ecosystems: [], severities: [], monthly_trend: [] }

describe('OsvPanel', () => {
  afterEach(() => {
    vi.resetAllMocks()
  })

  it('shows the empty state when there are no results', async () => {
    mockedList.mockResolvedValue(EMPTY_LIST)
    mockedStats.mockResolvedValue(EMPTY_STATS)

    render(<OsvPanel />)
    await waitFor(() => expect(screen.getByText('該当する OSV 脆弱性はありません')).toBeInTheDocument())
  })

  it('renders a row per result and expands details on click', async () => {
    mockedList.mockResolvedValue({ total: 1, page: 1, per_page: 30, data: [item()] })
    mockedStats.mockResolvedValue({
      total: 1, ecosystems: [{ ecosystem: 'PyPI', count: 1 }],
      severities: [{ severity: 'HIGH', count: 1 }], monthly_trend: [],
    })
    const user = userEvent.setup()

    render(<OsvPanel />)
    await waitFor(() => expect(screen.getByText('cryptography')).toBeInTheDocument())
    expect(screen.queryByText('Full details here')).not.toBeInTheDocument()

    await user.click(screen.getByText('cryptography'))
    expect(screen.getByText('Full details here')).toBeInTheDocument()
    // CVE-2026-12345 は折りたたみ時のエイリアス表示と展開後のエイリアス一覧の両方に出る
    expect(screen.getAllByText('CVE-2026-12345').length).toBeGreaterThanOrEqual(1)
  })

  it('requests the selected ecosystem when a filter button is clicked', async () => {
    mockedList.mockResolvedValue(EMPTY_LIST)
    mockedStats.mockResolvedValue(EMPTY_STATS)
    const user = userEvent.setup()

    render(<OsvPanel />)
    await waitFor(() => expect(mockedList).toHaveBeenCalledTimes(1))
    expect(mockedList).toHaveBeenLastCalledWith(expect.objectContaining({ ecosystem: null }))

    await user.click(screen.getByText('PyPI'))
    await waitFor(() => expect(mockedList).toHaveBeenCalledTimes(2))
    expect(mockedList).toHaveBeenLastCalledWith(expect.objectContaining({ ecosystem: 'PyPI' }))
  })

  it('requests the selected severity when a severity filter is clicked', async () => {
    mockedList.mockResolvedValue(EMPTY_LIST)
    mockedStats.mockResolvedValue(EMPTY_STATS)
    const user = userEvent.setup()

    render(<OsvPanel />)
    await waitFor(() => expect(mockedList).toHaveBeenCalledTimes(1))

    await user.click(screen.getByText('CRITICAL'))
    await waitFor(() => expect(mockedList).toHaveBeenLastCalledWith(
      expect.objectContaining({ severity: 'CRITICAL' }),
    ))
  })

  it('searches by keyword and clears the search', async () => {
    mockedList.mockResolvedValue(EMPTY_LIST)
    mockedStats.mockResolvedValue(EMPTY_STATS)
    const user = userEvent.setup()

    render(<OsvPanel />)
    await waitFor(() => expect(mockedList).toHaveBeenCalledTimes(1))

    await user.type(screen.getByPlaceholderText('OSV ID・パッケージ名・概要'), 'django')
    await waitFor(() => expect(mockedList).toHaveBeenLastCalledWith(
      expect.objectContaining({ search: 'django' }),
    ))

    const clearButton = screen.getByPlaceholderText('OSV ID・パッケージ名・概要').parentElement!.querySelector('button')!
    await user.click(clearButton)
    await waitFor(() => expect(mockedList).toHaveBeenLastCalledWith(
      expect.objectContaining({ search: '' }),
    ))
  })

  it('switches sort order when the CVSS sort button is clicked', async () => {
    mockedList.mockResolvedValue(EMPTY_LIST)
    mockedStats.mockResolvedValue(EMPTY_STATS)
    const user = userEvent.setup()

    render(<OsvPanel />)
    await waitFor(() => expect(mockedList).toHaveBeenCalledTimes(1))
    expect(mockedList).toHaveBeenLastCalledWith(expect.objectContaining({ sortBy: 'modified' }))

    await user.click(screen.getByText('CVSS'))
    await waitFor(() => expect(mockedList).toHaveBeenLastCalledWith(
      expect.objectContaining({ sortBy: 'cvss' }),
    ))
  })

  it('re-fetches when the refresh button is clicked', async () => {
    mockedList.mockResolvedValue(EMPTY_LIST)
    mockedStats.mockResolvedValue(EMPTY_STATS)
    const user = userEvent.setup()

    render(<OsvPanel />)
    await waitFor(() => expect(mockedList).toHaveBeenCalledTimes(1))

    await user.click(screen.getByTitle('再読み込み'))
    await waitFor(() => expect(mockedList).toHaveBeenCalledTimes(2))
  })

  it('shows CRIT/HIGH counts and the ecosystem chart once stats load', async () => {
    mockedList.mockResolvedValue({ total: 2, page: 1, per_page: 30, data: [item()] })
    mockedStats.mockResolvedValue({
      total: 2,
      ecosystems: [{ ecosystem: 'PyPI', count: 2 }],
      severities: [{ severity: 'CRITICAL', count: 1 }, { severity: 'HIGH', count: 1 }],
      monthly_trend: [{ year_month: '2026-06', count: 2 }],
    })

    render(<OsvPanel />)
    await waitFor(() => expect(screen.getByText(/CRIT 1/)).toBeInTheDocument())
    expect(screen.getByText(/HIGH 1/)).toBeInTheDocument()
    expect(screen.getByText('エコシステム別件数')).toBeInTheDocument()
  })
})
