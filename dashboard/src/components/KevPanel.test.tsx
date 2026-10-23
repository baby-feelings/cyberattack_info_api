import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
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
    epss_score: null,
    epss_percentile: null,
    epss_updated_at: null,
    ...overrides,
  }
}

const EMPTY_LIST: VulnerabilityListResponse = { total: 0, page: 1, per_page: 30, data: [] }
const EMPTY_STATS: StatsResponse = { total_vulnerabilities: 0, top_vendors: [], monthly_trend: [] }

describe('KevPanel', () => {
  afterEach(() => {
    vi.resetAllMocks()
    localStorage.clear()
  })

  it('shows the empty state when there are no results', async () => {
    mockedList.mockResolvedValue(EMPTY_LIST)
    mockedStats.mockResolvedValue(EMPTY_STATS)
    mockedRecent.mockResolvedValue([])

    render(<KevPanel />)
    await waitFor(() => expect(screen.getByText('該当する CVE はありません')).toBeInTheDocument())
  })

  it('shows the last 30 days by default, without calling the paged list API', async () => {
    mockedStats.mockResolvedValue(EMPTY_STATS)
    mockedRecent.mockResolvedValue([item()])

    render(<KevPanel />)
    await waitFor(() => expect(screen.getByText('Apache')).toBeInTheDocument())
    expect(mockedRecent).toHaveBeenCalledWith(30)
    expect(mockedList).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: '30日' })).toHaveAttribute('aria-pressed', 'true')
  })

  it('renders a row and expands to show description and required action', async () => {
    mockedStats.mockResolvedValue(EMPTY_STATS)
    mockedRecent.mockResolvedValue([item()])
    const user = userEvent.setup()

    render(<KevPanel />)
    await waitFor(() => expect(screen.getByText('Apache')).toBeInTheDocument())
    expect(screen.queryByText(/JNDI features/)).not.toBeInTheDocument()

    await user.click(screen.getByText('Apache'))
    expect(screen.getByText(/JNDI features/)).toBeInTheDocument()
    expect(screen.getByText(/Apply the vendor patch/)).toBeInTheDocument()
  })

  it('shows the EPSS score in the row and expanded detail when present', async () => {
    mockedStats.mockResolvedValue(EMPTY_STATS)
    mockedRecent.mockResolvedValue([
      item({ epss_score: 0.123, epss_percentile: 0.456, epss_updated_at: '2026-06-20T00:00:00Z' }),
    ])
    const user = userEvent.setup()

    render(<KevPanel />)
    await waitFor(() => expect(screen.getByText('12.3%')).toBeInTheDocument())

    await user.click(screen.getByText('Apache'))
    expect(screen.getByText(/12.30%/)).toBeInTheDocument()
    expect(screen.getByText(/パーセンタイル 45.6%/)).toBeInTheDocument()
  })

  it('shows a placeholder dash when the EPSS score is not yet available', async () => {
    mockedStats.mockResolvedValue(EMPTY_STATS)
    mockedRecent.mockResolvedValue([item()])

    render(<KevPanel />)
    await waitFor(() => expect(screen.getByText('—')).toBeInTheDocument())
  })

  it('does not show a required-action line when none is provided', async () => {
    mockedStats.mockResolvedValue(EMPTY_STATS)
    mockedRecent.mockResolvedValue([item({ required_action: null })])
    const user = userEvent.setup()

    render(<KevPanel />)
    await waitFor(() => expect(screen.getByText('Apache')).toBeInTheDocument())
    await user.click(screen.getByText('Apache'))
    expect(screen.queryByText('推奨対処:')).not.toBeInTheDocument()
  })

  it('narrows the recent list by keyword on the client, and clears it', async () => {
    mockedStats.mockResolvedValue(EMPTY_STATS)
    mockedRecent.mockResolvedValue([
      item(),
      item({ cve_id: 'CVE-2026-1', vendor_project: 'Microsoft', product: 'Windows' }),
    ])
    const user = userEvent.setup()

    render(<KevPanel />)
    await waitFor(() => expect(screen.getByText('Microsoft')).toBeInTheDocument())

    await user.type(screen.getByPlaceholderText('ベンダー名・製品名'), 'micro')
    expect(screen.queryByText('Apache')).not.toBeInTheDocument()
    expect(screen.getByText('Microsoft')).toBeInTheDocument()
    // 期間内の一覧は取得済みのため、検索のたびに取り直さない
    expect(mockedRecent).toHaveBeenCalledTimes(1)

    await user.click(screen.getByLabelText('検索をクリア'))
    expect(screen.getByText('Apache')).toBeInTheDocument()
  })

  it('re-fetches when the refresh button is clicked', async () => {
    mockedStats.mockResolvedValue(EMPTY_STATS)
    mockedRecent.mockResolvedValue([])
    const user = userEvent.setup()

    render(<KevPanel />)
    await waitFor(() => expect(mockedRecent).toHaveBeenCalledTimes(1))

    await user.click(screen.getByTitle('再読み込み'))
    await waitFor(() => expect(mockedRecent).toHaveBeenCalledTimes(2))
  })

  it('shows how many were added in the period and how many have a high EPSS', async () => {
    mockedStats.mockResolvedValue(EMPTY_STATS)
    mockedRecent.mockResolvedValue([
      item({ epss_score: 0.5 }),
      item({ cve_id: 'CVE-2', epss_score: 0.05 }),
      item({ cve_id: 'CVE-3', epss_score: null }),
    ])

    render(<KevPanel />)
    await waitFor(() => expect(screen.getByText('件が直近30日に追加')).toBeInTheDocument())
    // 3 件追加、うち EPSS 10%以上は 1 件
    const band = screen.getByRole('group', { name: '件数の集計' })
    expect(within(band).getByText('3')).toBeInTheDocument()
    expect(within(band).getByText('件は悪用されやすい（EPSS 10%以上）')).toBeInTheDocument()
    expect(within(band).getByText('1')).toBeInTheDocument()
  })

  it('switches the period, fetching that many days', async () => {
    mockedStats.mockResolvedValue(EMPTY_STATS)
    mockedRecent.mockResolvedValue([item()])
    const user = userEvent.setup()

    render(<KevPanel />)
    await waitFor(() => expect(mockedRecent).toHaveBeenCalledWith(30))

    await user.click(screen.getByRole('button', { name: '7日' }))
    await waitFor(() => expect(mockedRecent).toHaveBeenLastCalledWith(7))
    expect(await screen.findByText('件が直近7日に追加')).toBeInTheDocument()
  })

  it('uses the paged list API for "all", with the EPSS-high total from min_epss', async () => {
    mockedStats.mockResolvedValue({ total_vulnerabilities: 1619, top_vendors: [], monthly_trend: [] })
    mockedRecent.mockResolvedValue([])
    mockedList.mockImplementation(async params => (
      params.minEpss !== undefined
        ? { total: 88, page: 1, per_page: 1, data: [] }
        : { total: 60, page: 1, per_page: 30, data: [item()] }
    ))
    const user = userEvent.setup()

    render(<KevPanel />)
    await waitFor(() => expect(mockedRecent).toHaveBeenCalled())
    await user.click(screen.getByRole('button', { name: 'すべて', pressed: false }))

    await waitFor(() => expect(screen.getByText('件が登録済み')).toBeInTheDocument())
    const band = screen.getByRole('group', { name: '件数の集計' })
    expect(within(band).getByText('1619')).toBeInTheDocument()
    expect(within(band).getByText('88')).toBeInTheDocument()
    expect(mockedList).toHaveBeenCalledWith(expect.objectContaining({ minEpss: 0.1, perPage: 1 }))
    // ページネーションは上部・下部の両方に表示されるため、件数表示は2箇所になる
    expect(screen.getAllByText(/60 件/).length).toBe(2)
    expect(screen.getAllByText('1 / 2').length).toBe(2)
  })

  it('searches through the API for "all" and sends the keyword', async () => {
    mockedStats.mockResolvedValue(EMPTY_STATS)
    mockedRecent.mockResolvedValue([])
    mockedList.mockResolvedValue(EMPTY_LIST)
    const user = userEvent.setup()

    render(<KevPanel />)
    await waitFor(() => expect(mockedRecent).toHaveBeenCalled())
    await user.click(screen.getByRole('button', { name: 'すべて', pressed: false }))
    await waitFor(() => expect(mockedList).toHaveBeenCalled())

    await user.type(screen.getByPlaceholderText('ベンダー名・製品名'), 'Cisco')
    await waitFor(() => expect(mockedList).toHaveBeenCalledWith(
      expect.objectContaining({ search: 'Cisco' }),
    ))
  })

  it('paginates the recent list on the client', async () => {
    mockedStats.mockResolvedValue(EMPTY_STATS)
    mockedRecent.mockResolvedValue(
      Array.from({ length: 31 }, (_, i) => item({ cve_id: `CVE-2026-${i}` })),
    )

    render(<KevPanel />)
    await waitFor(() => expect(screen.getAllByText(/31 件/).length).toBe(2))
    expect(screen.getAllByText('1 / 2').length).toBe(2)
  })

  it('separates the list by the day each entry was added', async () => {
    mockedStats.mockResolvedValue(EMPTY_STATS)
    mockedRecent.mockResolvedValue([
      item({ cve_id: 'A', date_added: '2026-10-20' }),
      item({ cve_id: 'B', date_added: '2026-10-20' }),
      item({ cve_id: 'C', date_added: '2026-10-14' }),
    ])

    render(<KevPanel />)
    await waitFor(() => expect(screen.getByRole('row', { name: '2026年10月20日に追加' })).toBeInTheDocument())
    expect(screen.getByRole('row', { name: '2026年10月14日に追加' })).toBeInTheDocument()
    // 同じ日の2件に対して、区切りは1つだけ
    expect(screen.getAllByRole('row', { name: /に追加$/ }).length).toBe(2)
  })

  it('keeps the charts folded until opened', async () => {
    mockedStats.mockResolvedValue({
      total_vulnerabilities: 1619,
      top_vendors: [{ vendor_project: 'Microsoft', count: 312 }],
      monthly_trend: [{ year_month: '2026-06', count: 8 }],
    })
    mockedRecent.mockResolvedValue([item()])
    const user = userEvent.setup()

    render(<KevPanel />)
    await waitFor(() => expect(screen.getByText('Apache')).toBeInTheDocument())
    expect(screen.queryByText('ベンダー別件数 TOP8')).not.toBeInTheDocument()

    await user.click(screen.getByText('グラフ（ベンダー別・月別トレンド）を開く'))
    expect(await screen.findByText('ベンダー別件数 TOP8')).toBeInTheDocument()
  })

  describe('watch keywords', () => {
    it('adds a keyword, shows its hit count, and filters the list when clicked', async () => {
      mockedStats.mockResolvedValue(EMPTY_STATS)
      mockedRecent.mockResolvedValue([
        item(),
        item({ cve_id: 'CVE-2', vendor_project: 'Apache', product: 'Struts' }),
        item({ cve_id: 'CVE-3', vendor_project: 'Microsoft', product: 'Windows' }),
      ])
      const user = userEvent.setup()

      render(<KevPanel />)
      await waitFor(() => expect(screen.getByText('Microsoft')).toBeInTheDocument())

      await user.type(screen.getByLabelText('キーワードを追加'), 'apache{Enter}')
      const group = screen.getByRole('group', { name: '自分のスタックのキーワード' })
      // 大文字小文字を区別せず、取得済みの期間内の一覧から数える（2 件）
      expect(await within(group).findByText('2')).toBeInTheDocument()
      expect(JSON.parse(localStorage.getItem('watch_keywords') ?? '[]')).toEqual(['apache'])

      await user.click(within(group).getByRole('button', { name: /^apache\d+$/ }))
      expect(screen.queryByText('Microsoft')).not.toBeInTheDocument()
      expect(screen.getAllByText('Apache').length).toBe(2)

      await user.click(within(group).getByRole('button', { name: /^すべて/ }))
      expect(screen.getByText('Microsoft')).toBeInTheDocument()
    })

    it('shows a green zero for a keyword with no hits', async () => {
      localStorage.setItem('watch_keywords', JSON.stringify(['nginx']))
      mockedStats.mockResolvedValue(EMPTY_STATS)
      mockedRecent.mockResolvedValue([item()])

      render(<KevPanel />)
      const group = await screen.findByRole('group', { name: '自分のスタックのキーワード' })
      expect(await within(group).findByText('0')).toHaveClass('text-emerald-400')
    })

    it('removes a keyword', async () => {
      localStorage.setItem('watch_keywords', JSON.stringify(['nginx']))
      mockedStats.mockResolvedValue(EMPTY_STATS)
      mockedRecent.mockResolvedValue([item()])
      const user = userEvent.setup()

      render(<KevPanel />)
      await user.click(await screen.findByRole('button', { name: 'nginxを削除' }))
      expect(screen.queryByRole('button', { name: /^nginx/ })).not.toBeInTheDocument()
      expect(localStorage.getItem('watch_keywords')).toBe('[]')
    })

    it('explains how to use the keywords when none are registered', async () => {
      mockedStats.mockResolvedValue(EMPTY_STATS)
      mockedRecent.mockResolvedValue([item()])

      render(<KevPanel />)
      expect(await screen.findByText(/使っている製品名（例: Python・nginx）を追加すると/)).toBeInTheDocument()
    })
  })
})
