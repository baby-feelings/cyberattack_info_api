import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
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

  it('shows the period count and how many are High in the summary band', async () => {
    mockedList.mockResolvedValue({ total: 2, page: 1, per_page: 30, data: [item()] })
    mockedStats.mockResolvedValue({
      total: 5,
      severities: [{ severity: 'High', count: 2 }, { severity: 'Medium', count: 3 }],
      monthly_trend: [{ year_month: '2026-06', count: 5 }],
    })

    render(<JvnPanel />)
    const band = await screen.findByRole('group', { name: '件数の集計' })
    expect(within(band).getByText('5')).toBeInTheDocument()
    expect(within(band).getByText('件が直近30日に更新')).toBeInTheDocument()
    expect(within(band).getByText('2')).toBeInTheDocument()
    expect(within(band).getByText('件は High')).toBeInTheDocument()
  })

  it('defaults to the last 30 days and passes the selected period to the list and stats', async () => {
    mockedList.mockResolvedValue(EMPTY_LIST)
    mockedStats.mockResolvedValue(EMPTY_STATS)
    const user = userEvent.setup()

    render(<JvnPanel />)
    await waitFor(() => expect(mockedList).toHaveBeenCalledWith(expect.objectContaining({ days: 30 })))
    expect(mockedStats).toHaveBeenCalledWith(30)

    await user.click(screen.getByRole('button', { name: '90日' }))
    await waitFor(() => expect(mockedList).toHaveBeenLastCalledWith(
      expect.objectContaining({ days: 90, page: 1 }),
    ))
    expect(mockedStats).toHaveBeenLastCalledWith(90)
    expect(screen.getByText(/JVN 脆弱性（直近 90 日）/)).toBeInTheDocument()
  })

  it('shows the charts at first and closes them when the heading is clicked', async () => {
    mockedList.mockResolvedValue({ total: 1, page: 1, per_page: 30, data: [item()] })
    mockedStats.mockResolvedValue({
      total: 2,
      severities: [{ severity: 'High', count: 2 }],
      monthly_trend: [{ year_month: '2026-06', count: 2 }],
    })
    const user = userEvent.setup()

    render(<JvnPanel />)
    await screen.findByRole('group', { name: '件数の集計' })
    expect(await screen.findByText('月別 JVN 更新トレンド（6ヶ月）')).toBeInTheDocument()

    await user.click(screen.getByText('グラフ（重要度別・月別）'))
    expect(screen.queryByText('月別 JVN 更新トレンド（6ヶ月）')).not.toBeInTheDocument()
  })

  it('counts hits per watched keyword within the period', async () => {
    localStorage.setItem('watch_keywords', JSON.stringify(['Cisco']))
    mockedList.mockImplementation(async params => (
      params.perPage === 1
        ? { total: 6, page: 1, per_page: 1, data: [] }
        : { total: 1, page: 1, per_page: 30, data: [item()] }
    ))
    mockedStats.mockResolvedValue(EMPTY_STATS)

    render(<JvnPanel />)
    const group = await screen.findByRole('group', { name: '自分のスタックのキーワード' })
    expect(await within(group).findByText('6')).toBeInTheDocument()
    expect(mockedList).toHaveBeenCalledWith(expect.objectContaining({ search: 'Cisco', days: 30, perPage: 1 }))
    localStorage.clear()
  })

  it('always loads a 6-month stats for the monthly trend, whatever period is selected', async () => {
    mockedList.mockResolvedValue(EMPTY_LIST)
    mockedStats.mockResolvedValue(EMPTY_STATS)
    const user = userEvent.setup()

    render(<JvnPanel />)
    // 件数の帯は選んだ期間（30日）、月別トレンドは 180日分（月が2つしか出なくならないように）
    await waitFor(() => expect(mockedStats).toHaveBeenCalledWith(30))
    await waitFor(() => expect(mockedStats).toHaveBeenCalledWith(180))
    const trendCalls = () => mockedStats.mock.calls.filter(c => c[0] === 180).length
    expect(trendCalls()).toBe(1)

    // 期間を切り替えても、6ヶ月分は取り直さない
    await user.click(screen.getByRole('button', { name: '90日' }))
    await waitFor(() => expect(mockedStats).toHaveBeenCalledWith(90))
    expect(trendCalls()).toBe(1)

    // 手動の再読み込みでは、6ヶ月分も取り直す
    await user.click(screen.getByTitle('再読み込み'))
    await waitFor(() => expect(trendCalls()).toBe(2))
  })
})
