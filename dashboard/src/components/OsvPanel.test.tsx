import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
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

  it('shows the details as formatted markdown, not as raw "###" / "**" / "|" text (Issue #365)', async () => {
    const details = '### Summary\n\nEvery wheel bundles **OpenJPEG**.\n\n| Pillow | status |\n|---|---|\n| 11.1.0 | affected |'
    mockedList.mockResolvedValue({ total: 1, page: 1, per_page: 30, data: [item({ details })] })
    mockedStats.mockResolvedValue({
      total: 1, ecosystems: [{ ecosystem: 'PyPI', count: 1 }],
      severities: [{ severity: 'HIGH', count: 1 }], monthly_trend: [],
    })
    const user = userEvent.setup()

    render(<OsvPanel />)
    await user.click(await screen.findByText('cryptography'))

    expect(screen.getByRole('heading', { name: 'Summary' })).toBeInTheDocument()
    expect(screen.getByText('OpenJPEG').tagName).toBe('STRONG')
    // 一覧の表とは別に、詳細の中に表（Pillow / status の列）が出る
    expect(screen.getByRole('columnheader', { name: 'Pillow' })).toBeInTheDocument()
    expect(screen.getByRole('cell', { name: 'affected' })).toBeInTheDocument()
    expect(screen.queryByText(/###/)).not.toBeInTheDocument()
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

    await user.click(screen.getAllByText('ALL')[0])
    await waitFor(() => expect(mockedList).toHaveBeenCalledTimes(3))
    expect(mockedList).toHaveBeenLastCalledWith(expect.objectContaining({ ecosystem: null }))
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

    await user.click(screen.getAllByText('ALL')[1])
    await waitFor(() => expect(mockedList).toHaveBeenLastCalledWith(
      expect.objectContaining({ severity: null }),
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

  it('shows the period count and how many are CRITICAL or HIGH in the summary band', async () => {
    mockedList.mockResolvedValue({ total: 2, page: 1, per_page: 30, data: [item()] })
    mockedStats.mockResolvedValue({
      total: 7,
      ecosystems: [{ ecosystem: 'PyPI', count: 7 }],
      severities: [{ severity: 'CRITICAL', count: 1 }, { severity: 'HIGH', count: 2 }, { severity: 'LOW', count: 4 }],
      monthly_trend: [{ year_month: '2026-06', count: 7 }],
    })

    render(<OsvPanel />)
    const band = await screen.findByRole('group', { name: '件数の集計' })
    expect(within(band).getByText('7')).toBeInTheDocument()
    expect(within(band).getByText('件が直近30日に更新')).toBeInTheDocument()
    // CRITICAL 1 + HIGH 2
    expect(within(band).getByText('3')).toBeInTheDocument()
    expect(within(band).getByText('件は CRITICAL・HIGH')).toBeInTheDocument()
  })

  it('defaults to the last 30 days and passes the selected period to the list and stats', async () => {
    mockedList.mockResolvedValue(EMPTY_LIST)
    mockedStats.mockResolvedValue(EMPTY_STATS)
    const user = userEvent.setup()

    render(<OsvPanel />)
    await waitFor(() => expect(mockedList).toHaveBeenCalledWith(expect.objectContaining({ days: 30 })))
    expect(mockedStats).toHaveBeenCalledWith(30)

    await user.click(screen.getByRole('button', { name: '180日' }))
    await waitFor(() => expect(mockedList).toHaveBeenLastCalledWith(
      expect.objectContaining({ days: 180, page: 1 }),
    ))
    expect(mockedStats).toHaveBeenLastCalledWith(180)
    expect(screen.getByText(/OSV 脆弱性（直近 180 日）/)).toBeInTheDocument()
  })

  it('shows the charts at first and closes them when the heading is clicked', async () => {
    mockedList.mockResolvedValue({ total: 1, page: 1, per_page: 30, data: [item()] })
    mockedStats.mockResolvedValue({
      total: 2,
      ecosystems: [{ ecosystem: 'PyPI', count: 2 }],
      severities: [{ severity: 'HIGH', count: 2 }],
      monthly_trend: [{ year_month: '2026-06', count: 2 }],
    })
    const user = userEvent.setup()

    render(<OsvPanel />)
    await screen.findByRole('group', { name: '件数の集計' })
    expect(await screen.findByText('エコシステム別件数')).toBeInTheDocument()

    await user.click(screen.getByText('グラフ（重要度別・エコシステム別・月別）'))
    expect(screen.queryByText('エコシステム別件数')).not.toBeInTheDocument()
  })

  it('counts hits per watched keyword within the period, and filters by it when clicked', async () => {
    localStorage.setItem('watch_keywords', JSON.stringify(['requests']))
    mockedList.mockImplementation(async params => (
      params.perPage === 1
        ? { total: 4, page: 1, per_page: 1, data: [] }
        : { total: 1, page: 1, per_page: 30, data: [item()] }
    ))
    mockedStats.mockResolvedValue(EMPTY_STATS)
    const user = userEvent.setup()

    render(<OsvPanel />)
    const group = await screen.findByRole('group', { name: '自分のスタックのキーワード' })
    expect(await within(group).findByText('4')).toBeInTheDocument()
    expect(mockedList).toHaveBeenCalledWith(expect.objectContaining({ search: 'requests', days: 30, perPage: 1 }))

    await user.click(within(group).getByRole('button', { name: /^requests\d+$/ }))
    await waitFor(() => expect(mockedList).toHaveBeenLastCalledWith(
      expect.objectContaining({ search: 'requests', perPage: 30 }),
    ))
    localStorage.clear()
  })

  it('always loads a 6-month stats for the monthly trend, whatever period is selected', async () => {
    mockedList.mockResolvedValue(EMPTY_LIST)
    mockedStats.mockResolvedValue(EMPTY_STATS)
    const user = userEvent.setup()

    render(<OsvPanel />)
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
