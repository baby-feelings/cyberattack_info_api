import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { DepscanPanel } from './DepscanPanel'
import {
  fetchAllDepscanFindings, fetchDepscanStats, fetchCrawlerLogs,
  fetchDepsOpsList, fetchDepsOpsStats,
  type DependencyFindingOut, type DepscanStatsResponse,
} from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    fetchAllDepscanFindings: vi.fn(),
    fetchDepscanStats: vi.fn(),
    fetchCrawlerLogs: vi.fn(),
    fetchDepsOpsList: vi.fn(),
    fetchDepsOpsStats: vi.fn(),
  }
})

const mockedFindings = vi.mocked(fetchAllDepscanFindings)
const mockedStats = vi.mocked(fetchDepscanStats)
const mockedLogs = vi.mocked(fetchCrawlerLogs)
const mockedDepsOpsList = vi.mocked(fetchDepsOpsList)
const mockedDepsOpsStats = vi.mocked(fetchDepsOpsStats)

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
    reachability: null,
    repo_visibility: null,
    priority_reasons: [],
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
    mockedDepsOpsList.mockResolvedValue({ total: 0, page: 1, per_page: 20, data: [] })
    mockedDepsOpsStats.mockResolvedValue({ repos: [] })
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.resetAllMocks()
  })

  it('does not crash when fetching the latest crawl log id fails', async () => {
    mockedFindings.mockResolvedValue([])
    mockedStats.mockResolvedValue(EMPTY_STATS)
    mockedLogs.mockRejectedValue(new Error('network error'))

    render(<DepscanPanel />)
    await waitFor(() => expect(screen.getByText('該当する依存ライブラリ脆弱性はありません')).toBeInTheDocument())
  })

  it('shows the empty state when there are no findings', async () => {
    mockedFindings.mockResolvedValue([])
    mockedStats.mockResolvedValue(EMPTY_STATS)

    render(<DepscanPanel />)
    await waitFor(() => expect(screen.getByText('該当する依存ライブラリ脆弱性はありません')).toBeInTheDocument())
  })

  it('opens the Dependabot ops modal when its button is clicked, and closes it', async () => {
    mockedFindings.mockResolvedValue([])
    mockedStats.mockResolvedValue(EMPTY_STATS)

    render(<DepscanPanel />)
    await waitFor(() => expect(screen.getByText('該当する依存ライブラリ脆弱性はありません')).toBeInTheDocument())

    await userEvent.click(screen.getByText('Dependabot運用状況'))
    await waitFor(() => {
      expect(screen.getByText('Dependabot 運用状況（DEPSOPS）')).toBeInTheDocument()
    })

    await userEvent.click(screen.getByLabelText('閉じる'))
    await waitFor(() => {
      expect(screen.queryByText('Dependabot 運用状況（DEPSOPS）')).not.toBeInTheDocument()
    })
  })

  it('opens the dependency search modal when its button is clicked, and closes it', async () => {
    mockedFindings.mockResolvedValue([])
    mockedStats.mockResolvedValue(EMPTY_STATS)

    render(<DepscanPanel />)
    await waitFor(() => expect(screen.getByText('該当する依存ライブラリ脆弱性はありません')).toBeInTheDocument())

    await userEvent.click(screen.getByRole('button', { name: '依存パッケージ検索' }))
    expect(screen.getByRole('dialog', { name: '依存パッケージ検索' })).toBeInTheDocument()

    await userEvent.click(screen.getByLabelText('閉じる'))
    expect(screen.queryByRole('dialog', { name: '依存パッケージ検索' })).not.toBeInTheDocument()
  })

  it('reloads the data when the manual refresh button is clicked', async () => {
    mockedFindings.mockResolvedValue([])
    mockedStats.mockResolvedValue(EMPTY_STATS)

    render(<DepscanPanel />)
    await waitFor(() => expect(mockedFindings).toHaveBeenCalledTimes(1))

    await userEvent.click(screen.getByTitle('再読み込み'))
    await waitFor(() => expect(mockedFindings).toHaveBeenCalledTimes(2))
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
    // 帯: 対応が必要な件数（CRITICAL・HIGH の合計）と、未解決の総件数
    expect(screen.getByText('件が対応必要（CRITICAL・HIGH）')).toBeInTheDocument()
    expect(screen.getByText('未解決 3 件のうち')).toBeInTheDocument()
  })

  it('shows how many findings need action in the summary band', async () => {
    mockedFindings.mockResolvedValue([finding({ severity: 'CRITICAL' })])
    mockedStats.mockResolvedValue({
      total: 1,
      repos: [{ repo_full_name: 'baby-feelings/baby_grow', count: 1 }],
      severities: [{ severity: 'CRITICAL', count: 1 }],
    })

    render(<DepscanPanel />)
    await waitFor(() => expect(screen.getByText('件が対応必要（CRITICAL・HIGH）')).toBeInTheDocument())
  })

  it('shows a calm message when nothing needs action', async () => {
    mockedFindings.mockResolvedValue([finding({ severity: 'LOW' })])
    mockedStats.mockResolvedValue({
      total: 1,
      repos: [{ repo_full_name: 'baby-feelings/baby_grow', count: 1 }],
      severities: [{ severity: 'LOW', count: 1 }],
    })

    render(<DepscanPanel />)
    await waitFor(() => expect(screen.getByText('対応が必要な脆弱性はありません')).toBeInTheDocument())
  })

  it('lists apps in the left rail, urgent ones first, and filters the table when one is selected', async () => {
    mockedFindings.mockResolvedValue([
      finding({ repo_full_name: 'baby-feelings/quiet', package_name: 'lodash', severity: 'LOW', osv_id: 'A' }),
      finding({ repo_full_name: 'baby-feelings/urgent', package_name: 'vite', severity: 'CRITICAL', osv_id: 'B' }),
    ])
    mockedStats.mockResolvedValue({
      total: 2,
      repos: [
        { repo_full_name: 'baby-feelings/quiet', count: 1 },
        { repo_full_name: 'baby-feelings/urgent', count: 1 },
      ],
      severities: [{ severity: 'CRITICAL', count: 1 }, { severity: 'LOW', count: 1 }],
    })

    render(<DepscanPanel />)
    const rail = await screen.findByRole('navigation', { name: 'アプリ一覧' })
    const names = within(rail).getAllByRole('button').map(b => b.textContent)
    // 先頭は「すべてのアプリ」、その次が要対応のあるアプリ
    expect(names[0]).toContain('すべてのアプリ')
    expect(names[1]).toContain('urgent')
    expect(names[2]).toContain('quiet')
    expect(screen.getByText('lodash')).toBeInTheDocument()

    await userEvent.click(within(rail).getByRole('button', { name: /urgent/ }))
    expect(screen.getByText('vite')).toBeInTheDocument()
    expect(screen.queryByText('lodash')).not.toBeInTheDocument()
    // アプリを選ぶと、リポジトリ列は不要になる
    expect(screen.queryByRole('columnheader', { name: 'リポジトリ' })).not.toBeInTheDocument()

    await userEvent.click(within(rail).getByRole('button', { name: /すべてのアプリ/ }))
    expect(screen.getByText('lodash')).toBeInTheDocument()
  })

  it('shows the charts at first and closes them when the heading is clicked', async () => {
    mockedFindings.mockResolvedValue([finding()])
    mockedStats.mockResolvedValue({
      total: 1,
      repos: [{ repo_full_name: 'baby-feelings/baby_grow', count: 1 }],
      severities: [{ severity: 'HIGH', count: 1 }],
    })

    render(<DepscanPanel />)
    await screen.findByText('cryptography')
    expect(await screen.findByText('リポジトリ別件数（未解決）')).toBeInTheDocument()

    await userEvent.click(screen.getByText('グラフ（重要度別・リポジトリ別）'))
    expect(screen.queryByText('リポジトリ別件数（未解決）')).not.toBeInTheDocument()
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
    expect(mockedStats).toHaveBeenCalledWith('session-tok', 'active')
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

  it('shows only running apps by default, and switches to stopped / all', async () => {
    mockedFindings.mockResolvedValue([])
    mockedStats.mockResolvedValue(EMPTY_STATS)

    render(<DepscanPanel />)
    await waitFor(() =>
      expect(mockedFindings).toHaveBeenCalledWith(expect.objectContaining({ operating: 'active' })),
    )
    expect(mockedStats).toHaveBeenCalledWith(undefined, 'active')
    expect(screen.getByRole('button', { name: '運用中' })).toHaveAttribute('aria-pressed', 'true')

    await userEvent.click(screen.getByRole('button', { name: '運用停止中' }))
    await waitFor(() =>
      expect(mockedFindings).toHaveBeenLastCalledWith(
        expect.objectContaining({ operating: 'inactive' }),
      ),
    )
    expect(mockedStats).toHaveBeenLastCalledWith(undefined, 'inactive')

    await userEvent.click(screen.getByRole('button', { name: 'すべて' }))
    await waitFor(() =>
      expect(mockedFindings).toHaveBeenLastCalledWith(expect.objectContaining({ operating: 'all' })),
    )
    expect(mockedStats).toHaveBeenLastCalledWith(undefined, 'all')
  })
})
