import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CodescanPanel } from './CodescanPanel'
import {
  fetchCodescanList, fetchCodescanStats,
  type CodeFindingOut, type CodescanListResponse, type CodescanStatsResponse,
} from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    fetchCodescanList: vi.fn(),
    fetchCodescanStats: vi.fn(),
  }
})

const mockedList = vi.mocked(fetchCodescanList)
const mockedStats = vi.mocked(fetchCodescanStats)

function item(overrides: Partial<CodeFindingOut> = {}): CodeFindingOut {
  return {
    repo_full_name: 'baby-feelings/baby_grow',
    file_path: 'app/main.py',
    line_start: 10,
    line_end: 10,
    rule_id: 'python.lang.security.audit.hardcoded-password',
    message: 'Hardcoded password detected',
    severity: 'ERROR',
    cwe_ids: ['CWE-798'],
    owasp_categories: [],
    code_snippet: 'PASSWORD = "hunter2"',
    cvss_score: 7.4,
    cvss_vector: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    tool: 'semgrep',
    detected_at: '2026-06-15T00:00:00Z',
    resolved_at: null,
    ...overrides,
  }
}

const EMPTY_LIST: CodescanListResponse = { total: 0, page: 1, per_page: 30, data: [] }
const EMPTY_STATS: CodescanStatsResponse = { total: 0, repos: [], severities: [] }

describe('CodescanPanel', () => {
  afterEach(() => {
    vi.resetAllMocks()
  })

  it('shows the empty state when there are no results', async () => {
    mockedList.mockResolvedValue(EMPTY_LIST)
    mockedStats.mockResolvedValue(EMPTY_STATS)

    render(<CodescanPanel />)
    await waitFor(() =>
      expect(screen.getByText('該当するコード脆弱性はありません')).toBeInTheDocument(),
    )
  })

  it('renders a row per finding and expands details on click', async () => {
    mockedList.mockResolvedValue({ total: 1, page: 1, per_page: 30, data: [item()] })
    mockedStats.mockResolvedValue({
      total: 1,
      repos: [{ repo_full_name: 'baby-feelings/baby_grow', count: 1 }],
      severities: [{ severity: 'ERROR', count: 1 }],
    })
    const user = userEvent.setup()

    render(<CodescanPanel />)
    await waitFor(() => expect(screen.getByText('app/main.py:10')).toBeInTheDocument())
    expect(screen.queryByText('Hardcoded password detected')).not.toBeInTheDocument()

    await user.click(screen.getByText('app/main.py:10'))
    expect(screen.getByText('Hardcoded password detected')).toBeInTheDocument()
  })

  it('highlights CVSS scores of 7.0 or higher', async () => {
    mockedList.mockResolvedValue({ total: 1, page: 1, per_page: 30, data: [item({ cvss_score: 9.1 })] })
    mockedStats.mockResolvedValue(EMPTY_STATS)

    render(<CodescanPanel />)
    await waitFor(() => expect(screen.getByText('9.1')).toBeInTheDocument())
    expect(screen.getByText('9.1').className).toContain('bg-red-600')
  })

  it('shows "未算出" when CVSS score is null', async () => {
    mockedList.mockResolvedValue({ total: 1, page: 1, per_page: 30, data: [item({ cvss_score: null })] })
    mockedStats.mockResolvedValue(EMPTY_STATS)

    render(<CodescanPanel />)
    await waitFor(() => expect(screen.getByText('未算出')).toBeInTheDocument())
  })

  it('requests the selected severity when a filter button is clicked', async () => {
    mockedList.mockResolvedValue(EMPTY_LIST)
    mockedStats.mockResolvedValue(EMPTY_STATS)
    const user = userEvent.setup()

    render(<CodescanPanel />)
    await waitFor(() => expect(mockedList).toHaveBeenCalled())

    await user.click(screen.getByRole('button', { name: '重大' }))
    await waitFor(() =>
      expect(mockedList).toHaveBeenLastCalledWith(
        expect.objectContaining({ severity: 'ERROR' }),
      ),
    )
  })

  it('requests resolved findings when the resolved toggle is clicked', async () => {
    mockedList.mockResolvedValue(EMPTY_LIST)
    mockedStats.mockResolvedValue(EMPTY_STATS)
    const user = userEvent.setup()

    render(<CodescanPanel />)
    await waitFor(() => expect(mockedList).toHaveBeenCalled())

    await user.click(screen.getByRole('button', { name: '解決済み' }))
    await waitFor(() =>
      expect(mockedList).toHaveBeenLastCalledWith(
        expect.objectContaining({ resolved: true }),
      ),
    )
  })

  it('defaults to showing only unresolved findings', async () => {
    mockedList.mockResolvedValue(EMPTY_LIST)
    mockedStats.mockResolvedValue(EMPTY_STATS)

    render(<CodescanPanel />)
    await waitFor(() =>
      expect(mockedList).toHaveBeenCalledWith(expect.objectContaining({ resolved: false })),
    )
  })

  it('shows a tool badge distinguishing semgrep and gitleaks findings', async () => {
    mockedList.mockResolvedValue({
      total: 1, page: 1, per_page: 30, data: [item({ tool: 'gitleaks', rule_id: 'gitleaks:aws-access-token' })],
    })
    mockedStats.mockResolvedValue(EMPTY_STATS)

    render(<CodescanPanel />)
    await waitFor(() => expect(screen.getByText('Gitleaks')).toBeInTheDocument())
  })

  it('shows a Zizmor badge for GitHub Actions workflow findings', async () => {
    mockedList.mockResolvedValue({
      total: 1, page: 1, per_page: 30,
      data: [item({ tool: 'zizmor', rule_id: 'zizmor:unpinned-uses', file_path: '.github/workflows/ci.yml' })],
    })
    mockedStats.mockResolvedValue(EMPTY_STATS)

    render(<CodescanPanel />)
    await waitFor(() => expect(screen.getByText('Zizmor')).toBeInTheDocument())
    expect(screen.getByText('zizmor:unpinned-uses')).toBeInTheDocument()
  })

  it('shows an infrastructure-config badge for Firebase and Docker findings', async () => {
    mockedList.mockResolvedValue({
      total: 1, page: 1, per_page: 30,
      data: [item({ tool: 'iac', rule_id: 'iac:firebase-open-write', file_path: 'firestore.rules' })],
    })
    mockedStats.mockResolvedValue(EMPTY_STATS)

    render(<CodescanPanel />)
    await waitFor(() => expect(screen.getByText('インフラ設定')).toBeInTheDocument())
    expect(screen.getByText('iac:firebase-open-write')).toBeInTheDocument()
  })

  it('shows an unknown tool by its name', async () => {
    mockedList.mockResolvedValue({
      total: 1, page: 1, per_page: 30, data: [item({ tool: 'newtool', rule_id: 'newtool:rule' })],
    })
    mockedStats.mockResolvedValue(EMPTY_STATS)

    render(<CodescanPanel />)
    await waitFor(() => expect(screen.getByText('newtool')).toBeInTheDocument())
  })

  it('reloads the current filters when the reload button is clicked', async () => {
    mockedList.mockResolvedValue({ total: 1, page: 1, per_page: 30, data: [item()] })
    mockedStats.mockResolvedValue({
      total: 1,
      repos: [{ repo_full_name: 'baby-feelings/baby_grow', count: 1 }],
      severities: [{ severity: 'ERROR', count: 1 }],
    })
    const user = userEvent.setup()

    render(<CodescanPanel />)
    await waitFor(() => expect(mockedList).toHaveBeenCalledTimes(1))

    await user.click(screen.getByTitle('再読み込み'))
    await waitFor(() => expect(mockedList).toHaveBeenCalledTimes(2))
  })

  it('passes authToken through to fetchCodescanList/fetchCodescanStats (Bearer auth, Issue #219)', async () => {
    mockedList.mockResolvedValue(EMPTY_LIST)
    mockedStats.mockResolvedValue(EMPTY_STATS)

    render(<CodescanPanel authToken="tok-abc" />)
    await waitFor(() =>
      expect(mockedList).toHaveBeenCalledWith(expect.objectContaining({ authToken: 'tok-abc' })),
    )
    expect(mockedStats).toHaveBeenCalledWith('tok-abc', 'active')
  })

  it('shows only running apps by default, and switches to stopped / all', async () => {
    mockedList.mockResolvedValue(EMPTY_LIST)
    mockedStats.mockResolvedValue(EMPTY_STATS)

    render(<CodescanPanel />)
    await waitFor(() =>
      expect(mockedList).toHaveBeenCalledWith(expect.objectContaining({ operating: 'active' })),
    )
    expect(mockedStats).toHaveBeenCalledWith(undefined, 'active')
    expect(screen.getByRole('button', { name: '運用中' })).toHaveAttribute('aria-pressed', 'true')

    await userEvent.click(screen.getByRole('button', { name: '運用停止中' }))
    await waitFor(() =>
      expect(mockedList).toHaveBeenLastCalledWith(
        expect.objectContaining({ operating: 'inactive', page: 1 }),
      ),
    )
    expect(mockedStats).toHaveBeenLastCalledWith(undefined, 'inactive')

    await userEvent.click(screen.getByRole('button', { name: 'すべて' }))
    await waitFor(() =>
      expect(mockedList).toHaveBeenLastCalledWith(expect.objectContaining({ operating: 'all' })),
    )
    expect(mockedStats).toHaveBeenLastCalledWith(undefined, 'all')
  })

  it('shows how many critical findings need action in the summary band', async () => {
    mockedList.mockResolvedValue({ total: 1, page: 1, per_page: 30, data: [item()] })
    mockedStats.mockResolvedValue({
      total: 3,
      repos: [{ repo_full_name: 'baby-feelings/baby_grow', count: 3 }],
      severities: [{ severity: 'ERROR', count: 2 }, { severity: 'INFO', count: 1 }],
    })

    render(<CodescanPanel />)
    await waitFor(() => expect(screen.getByText('件が対応必要（重大）')).toBeInTheDocument())
    expect(screen.getByText('未解決 3 件のうち')).toBeInTheDocument()
  })

  it('narrows the list to one app through the left rail, and back to all apps', async () => {
    mockedList.mockResolvedValue({ total: 1, page: 1, per_page: 30, data: [item()] })
    mockedStats.mockResolvedValue({
      total: 3,
      repos: [
        { repo_full_name: 'baby-feelings/baby_grow', count: 2 },
        { repo_full_name: 'baby-feelings/todo-app', count: 1 },
      ],
      severities: [{ severity: 'ERROR', count: 3 }],
    })

    render(<CodescanPanel />)
    const rail = await screen.findByRole('navigation', { name: 'アプリ一覧' })
    await waitFor(() =>
      expect(mockedList).toHaveBeenCalledWith(expect.objectContaining({ repo: null })),
    )

    await userEvent.click(within(rail).getByRole('button', { name: /todo-app/ }))
    await waitFor(() =>
      expect(mockedList).toHaveBeenLastCalledWith(
        expect.objectContaining({ repo: 'baby-feelings/todo-app', page: 1 }),
      ),
    )
    // アプリを選ぶと、リポジトリ列は不要になる
    expect(screen.queryByRole('columnheader', { name: 'リポジトリ' })).not.toBeInTheDocument()

    await userEvent.click(within(rail).getByRole('button', { name: /すべてのアプリ/ }))
    await waitFor(() =>
      expect(mockedList).toHaveBeenLastCalledWith(expect.objectContaining({ repo: null })),
    )
  })

  it('clears the selected app when the operating filter changes', async () => {
    mockedList.mockResolvedValue({ total: 1, page: 1, per_page: 30, data: [item()] })
    mockedStats.mockResolvedValue({
      total: 1,
      repos: [{ repo_full_name: 'baby-feelings/baby_grow', count: 1 }],
      severities: [{ severity: 'ERROR', count: 1 }],
    })

    render(<CodescanPanel />)
    const rail = await screen.findByRole('navigation', { name: 'アプリ一覧' })
    await userEvent.click(within(rail).getByRole('button', { name: /baby_grow/ }))
    await waitFor(() =>
      expect(mockedList).toHaveBeenLastCalledWith(expect.objectContaining({ repo: 'baby-feelings/baby_grow' })),
    )

    await userEvent.click(screen.getByRole('button', { name: '運用停止中' }))
    await waitFor(() =>
      expect(mockedList).toHaveBeenLastCalledWith(
        expect.objectContaining({ operating: 'inactive', repo: null }),
      ),
    )
  })

  it('shows the repo chart at first and closes it when the heading is clicked', async () => {
    mockedList.mockResolvedValue({ total: 1, page: 1, per_page: 30, data: [item()] })
    mockedStats.mockResolvedValue({
      total: 1,
      repos: [{ repo_full_name: 'baby-feelings/baby_grow', count: 1 }],
      severities: [{ severity: 'ERROR', count: 1 }],
    })

    render(<CodescanPanel />)
    expect(await screen.findByText('リポジトリ別件数（未解決）')).toBeInTheDocument()

    await userEvent.click(screen.getByText('グラフ（リポジトリ別）'))
    expect(screen.queryByText('リポジトリ別件数（未解決）')).not.toBeInTheDocument()
  })
})
