import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { JvnPanel } from './JvnPanel'
import {
  fetchJvnList, fetchJvnStats,
  type JvnVulnerabilityOut, type JvnListResponse, type JvnStatsResponse,
} from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    fetchJvnList: vi.fn(),
    fetchJvnStats: vi.fn(),
  }
})

const mockedList = vi.mocked(fetchJvnList)
const mockedStats = vi.mocked(fetchJvnStats)

function item(overrides: Partial<JvnVulnerabilityOut> = {}): JvnVulnerabilityOut {
  return {
    jvndb_id: 'JVNDB-2026-020172',
    title: 'CISA ICS Advisory（2026年06月16日）',
    overview: 'Overview text here',
    cve_ids: ['CVE-2026-12345'],
    severity: 'High',
    cvss_score: 9.8,
    cvss_vector: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    affected_products: [
      { vendor: 'Acme', product: 'Widget', cpe: 'cpe:/a:acme:widget' },
      { vendor: 'Acme', product: 'Gadget', cpe: 'cpe:/a:acme:gadget' },
    ],
    references: [],
    jvn_url: 'https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-020172.html',
    date_published: '2026-06-18T11:35:05+09:00',
    date_last_modified: '2026-06-18T11:35:05+09:00',
    ...overrides,
  }
}

const EMPTY_LIST: JvnListResponse = { total: 0, page: 1, per_page: 30, data: [] }
const EMPTY_STATS: JvnStatsResponse = { total: 0, severities: [], monthly_trend: [] }

describe('JvnPanel', () => {
  afterEach(() => {
    vi.resetAllMocks()
  })

  it('shows the empty state when there are no results', async () => {
    mockedList.mockResolvedValue(EMPTY_LIST)
    mockedStats.mockResolvedValue(EMPTY_STATS)

    render(<JvnPanel />)
    await waitFor(() => expect(screen.getByText('該当する JVN 脆弱性はありません')).toBeInTheDocument())
  })

  it('renders a row and expands to show overview and all affected products', async () => {
    mockedList.mockResolvedValue({ total: 1, page: 1, per_page: 30, data: [item()] })
    mockedStats.mockResolvedValue({
      total: 1, severities: [{ severity: 'High', count: 1 }], monthly_trend: [],
    })
    const user = userEvent.setup()

    render(<JvnPanel />)
    await waitFor(() => expect(screen.getByText('JVNDB-2026-020172')).toBeInTheDocument())
    expect(screen.getByText('+1 製品')).toBeInTheDocument()
    expect(screen.queryByText('Overview text here')).not.toBeInTheDocument()

    await user.click(screen.getByText(/CISA ICS Advisory/))
    expect(screen.getByText('Overview text here')).toBeInTheDocument()
    expect(screen.getByText('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBeInTheDocument()
    expect(screen.getByText('Acme / Gadget')).toBeInTheDocument()
  })

  it('shows a placeholder when there is no affected product listed', async () => {
    mockedList.mockResolvedValue({
      total: 1, page: 1, per_page: 30, data: [item({ affected_products: [] })],
    })
    mockedStats.mockResolvedValue(EMPTY_STATS)

    render(<JvnPanel />)
    await waitFor(() => expect(screen.getByText('—')).toBeInTheDocument())
  })

  it('requests the selected severity when a filter is clicked', async () => {
    mockedList.mockResolvedValue(EMPTY_LIST)
    mockedStats.mockResolvedValue(EMPTY_STATS)
    const user = userEvent.setup()

    render(<JvnPanel />)
    await waitFor(() => expect(mockedList).toHaveBeenCalledTimes(1))
    expect(mockedList).toHaveBeenLastCalledWith(expect.objectContaining({ severity: null }))

    await user.click(screen.getByText('High'))
    await waitFor(() => expect(mockedList).toHaveBeenLastCalledWith(
      expect.objectContaining({ severity: 'High' }),
    ))
  })

  it('searches by keyword and clears it', async () => {
    mockedList.mockResolvedValue(EMPTY_LIST)
    mockedStats.mockResolvedValue(EMPTY_STATS)
    const user = userEvent.setup()

    render(<JvnPanel />)
    await waitFor(() => expect(mockedList).toHaveBeenCalledTimes(1))

    await user.type(screen.getByPlaceholderText('JVNDB ID・タイトル・概要'), 'Apache')
    await waitFor(() => expect(mockedList).toHaveBeenLastCalledWith(
      expect.objectContaining({ search: 'Apache' }),
    ))

    const clearButton = screen.getByPlaceholderText('JVNDB ID・タイトル・概要').parentElement!.querySelector('button')!
    await user.click(clearButton)
    await waitFor(() => expect(mockedList).toHaveBeenLastCalledWith(
      expect.objectContaining({ search: '' }),
    ))
  })

  it('switches sort order when CVSS is selected', async () => {
    mockedList.mockResolvedValue(EMPTY_LIST)
    mockedStats.mockResolvedValue(EMPTY_STATS)
    const user = userEvent.setup()

    render(<JvnPanel />)
    await waitFor(() => expect(mockedList).toHaveBeenCalledTimes(1))

    await user.click(screen.getByText('CVSS'))
    await waitFor(() => expect(mockedList).toHaveBeenLastCalledWith(
      expect.objectContaining({ sortBy: 'cvss' }),
    ))
  })

  it('re-fetches when the refresh button is clicked', async () => {
    mockedList.mockResolvedValue(EMPTY_LIST)
    mockedStats.mockResolvedValue(EMPTY_STATS)
    const user = userEvent.setup()

    render(<JvnPanel />)
    await waitFor(() => expect(mockedList).toHaveBeenCalledTimes(1))

    await user.click(screen.getByTitle('再読み込み'))
    await waitFor(() => expect(mockedList).toHaveBeenCalledTimes(2))
  })

  it('shows HIGH/MED counts once stats load', async () => {
    mockedList.mockResolvedValue({ total: 2, page: 1, per_page: 30, data: [item()] })
    mockedStats.mockResolvedValue({
      total: 2,
      severities: [{ severity: 'High', count: 1 }, { severity: 'Medium', count: 1 }],
      monthly_trend: [{ year_month: '2026-06', count: 2 }],
    })

    render(<JvnPanel />)
    await waitFor(() => expect(screen.getByText(/HIGH 1/)).toBeInTheDocument())
    expect(screen.getByText(/MED 1/)).toBeInTheDocument()
  })
})
