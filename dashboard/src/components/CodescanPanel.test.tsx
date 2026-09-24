import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
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

    await user.click(screen.getByRole('button', { name: 'ERROR' }))
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
})
