import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { KevPanel } from './KevPanel'
import {
  fetchVulnerabilities, fetchStats, fetchRecent,
  type VulnerabilityOut, type VulnerabilityListResponse, type StatsResponse,
} from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    fetchVulnerabilities: vi.fn(),
    fetchStats: vi.fn(),
    fetchRecent: vi.fn(),
  }
})

const mockedList = vi.mocked(fetchVulnerabilities)
const mockedStats = vi.mocked(fetchStats)
const mockedRecent = vi.mocked(fetchRecent)

function item(overrides: Partial<VulnerabilityOut> = {}): VulnerabilityOut {
  return {
    cve_id: 'CVE-2021-44228',
    vendor_project: 'Apache',
    product: 'Log4j',
    vulnerability_name: 'Apache Log4j2 Remote Code Execution Vulnerability',
    description: 'Apache Log4j2 <=2.14.1 JNDI features...',
    required_action: 'Apply the vendor patch immediately.',
    date_added: '2021-12-10',
    ...overrides,
  }
}

const EMPTY_LIST: VulnerabilityListResponse = { total: 0, page: 1, per_page: 30, data: [] }
const EMPTY_STATS: StatsResponse = { total_vulnerabilities: 0, top_vendors: [], monthly_trend: [] }

describe('KevPanel', () => {
  afterEach(() => {
    vi.resetAllMocks()
  })

  it('shows the empty state when there are no results', async () => {
    mockedList.mockResolvedValue(EMPTY_LIST)
    mockedStats.mockResolvedValue(EMPTY_STATS)
    mockedRecent.mockResolvedValue([])

    render(<KevPanel />)
    await waitFor(() => expect(screen.getByText('該当する CVE はありません')).toBeInTheDocument())
  })

  it('renders a row and expands to show description and required action', async () => {
    mockedList.mockResolvedValue({ total: 1, page: 1, per_page: 30, data: [item()] })
    mockedStats.mockResolvedValue({
      total_vulnerabilities: 1,
      top_vendors: [{ vendor_project: 'Apache', count: 1 }],
      monthly_trend: [],
    })
    mockedRecent.mockResolvedValue([item()])
    const user = userEvent.setup()

    render(<KevPanel />)
    await waitFor(() => expect(screen.getByText('Apache')).toBeInTheDocument())
    expect(screen.queryByText(/JNDI features/)).not.toBeInTheDocument()

    await user.click(screen.getByText('Apache'))
    expect(screen.getByText(/JNDI features/)).toBeInTheDocument()
    expect(screen.getByText(/Apply the vendor patch/)).toBeInTheDocument()
  })

  it('does not show a required-action line when none is provided', async () => {
    mockedList.mockResolvedValue({
      total: 1, page: 1, per_page: 30, data: [item({ required_action: null })],
    })
    mockedStats.mockResolvedValue(EMPTY_STATS)
    mockedRecent.mockResolvedValue([])
    const user = userEvent.setup()

    render(<KevPanel />)
    await waitFor(() => expect(screen.getByText('Apache')).toBeInTheDocument())
    await user.click(screen.getByText('Apache'))
    expect(screen.queryByText('推奨対処:')).not.toBeInTheDocument()
  })

  it('searches by keyword and clears it', async () => {
    mockedList.mockResolvedValue(EMPTY_LIST)
    mockedStats.mockResolvedValue(EMPTY_STATS)
    mockedRecent.mockResolvedValue([])
    const user = userEvent.setup()

    render(<KevPanel />)
    await waitFor(() => expect(mockedList).toHaveBeenCalledTimes(1))

    await user.type(screen.getByPlaceholderText('ベンダー名・製品名'), 'Microsoft')
    await waitFor(() => expect(mockedList).toHaveBeenLastCalledWith(
      expect.objectContaining({ search: 'Microsoft' }),
    ))

    const clearButton = screen.getByPlaceholderText('ベンダー名・製品名').parentElement!.querySelector('button')!
    await user.click(clearButton)
    await waitFor(() => expect(mockedList).toHaveBeenLastCalledWith(
      expect.objectContaining({ search: '' }),
    ))
  })

  it('re-fetches when the refresh button is clicked', async () => {
    mockedList.mockResolvedValue(EMPTY_LIST)
    mockedStats.mockResolvedValue(EMPTY_STATS)
    mockedRecent.mockResolvedValue([])
    const user = userEvent.setup()

    render(<KevPanel />)
    await waitFor(() => expect(mockedList).toHaveBeenCalledTimes(1))

    await user.click(screen.getByTitle('再読み込み'))
    await waitFor(() => expect(mockedList).toHaveBeenCalledTimes(2))
  })

  it('shows the total count and recent-30-day count once stats load', async () => {
    mockedList.mockResolvedValue({ total: 1, page: 1, per_page: 30, data: [item()] })
    mockedStats.mockResolvedValue({
      total_vulnerabilities: 1619,
      top_vendors: [{ vendor_project: 'Microsoft', count: 312 }],
      monthly_trend: [{ year_month: '2026-06', count: 8 }],
    })
    mockedRecent.mockResolvedValue([item(), item({ cve_id: 'CVE-2021-99999' })])

    render(<KevPanel />)
    await waitFor(() => expect(screen.getByText(/直近30日 2/)).toBeInTheDocument())
    expect(screen.getByText(/1619 件/)).toBeInTheDocument()
    expect(screen.getByText('ベンダー別件数 TOP8')).toBeInTheDocument()
  })

  it('paginates using the totals returned from the list response', async () => {
    mockedList.mockResolvedValue({
      total: 60, page: 1, per_page: 30, data: [item()],
    })
    mockedStats.mockResolvedValue(EMPTY_STATS)
    mockedRecent.mockResolvedValue([])

    render(<KevPanel />)
    await waitFor(() => expect(screen.getByText(/60 件/)).toBeInTheDocument())
    expect(screen.getByText('1 / 2')).toBeInTheDocument()
  })
})
