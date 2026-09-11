import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { DependabotOpsModal } from './DependabotOpsModal'
import {
  fetchDepsOpsList, fetchAllDepsOpsEntries,
  type DependabotPrLogOut, type DepsOpsListResponse,
} from '../../api/client'

vi.mock('../../api/client', async () => {
  const actual = await vi.importActual<typeof import('../../api/client')>('../../api/client')
  return { ...actual, fetchDepsOpsList: vi.fn(), fetchAllDepsOpsEntries: vi.fn() }
})

const mockedList = vi.mocked(fetchDepsOpsList)
const mockedAll = vi.mocked(fetchAllDepsOpsEntries)

function item(overrides: Partial<DependabotPrLogOut> = {}): DependabotPrLogOut {
  return {
    repo_full_name: 'baby-feelings/baby_grow',
    pr_number: 42,
    title: 'Bump lucide-react from 1.18.0 to 1.37.0',
    action: 'merged',
    reason: null,
    is_security_update: null,
    compatibility_badge_url: null,
    processed_at: '2026-06-01T00:00:00Z',
    ...overrides,
  }
}

function listResponse(data: DependabotPrLogOut[], total?: number): DepsOpsListResponse {
  return { total: total ?? data.length, page: 1, per_page: 20, data }
}

afterEach(() => {
  vi.clearAllMocks()
})

describe('DependabotOpsModal', () => {
  it('renders nothing when closed', () => {
    mockedList.mockResolvedValue(listResponse([]))
    mockedAll.mockResolvedValue([])
    render(<DependabotOpsModal open={false} onClose={vi.fn()} />)
    expect(screen.queryByText('Dependabot 運用状況（DEPSOPS）')).not.toBeInTheDocument()
    expect(mockedList).not.toHaveBeenCalled()
  })

  it('fetches and shows PR entries once opened', async () => {
    mockedList.mockResolvedValue(listResponse([item()]))
    mockedAll.mockResolvedValue([item()])
    render(<DependabotOpsModal open onClose={vi.fn()} />)

    await waitFor(() => {
      expect(screen.getByText(/Bump lucide-react/)).toBeInTheDocument()
    })
    expect(mockedList).toHaveBeenCalledWith(expect.objectContaining({ action: null }))
  })

  it('shows the empty state when there are no matching PRs', async () => {
    mockedList.mockResolvedValue(listResponse([]))
    mockedAll.mockResolvedValue([])
    render(<DependabotOpsModal open onClose={vi.fn()} />)

    await waitFor(() => {
      expect(screen.getByText('該当する PR はありません')).toBeInTheDocument()
    })
  })

  it('shows the flagged reason and re-fetches when filtering by action', async () => {
    mockedList.mockResolvedValue(listResponse([
      item({ pr_number: 7, action: 'flagged', reason: 'メジャーバージョンアップ' }),
    ]))
    mockedAll.mockResolvedValue([])
    render(<DependabotOpsModal open onClose={vi.fn()} />)
    await waitFor(() => expect(screen.getByText('メジャーバージョンアップ')).toBeInTheDocument())

    mockedList.mockClear()
    await userEvent.click(screen.getByRole('button', { name: '要確認' }))

    await waitFor(() => {
      expect(mockedList).toHaveBeenCalledWith(
        expect.objectContaining({ action: 'flagged', page: 1 }),
      )
    })
  })

  it('shows a badge for the security-update classification of each PR', async () => {
    mockedList.mockResolvedValue(listResponse([
      item({ pr_number: 1, is_security_update: true }),
      item({ pr_number: 2, is_security_update: false }),
      item({ pr_number: 3, is_security_update: null }),
    ]))
    mockedAll.mockResolvedValue([])
    render(<DependabotOpsModal open onClose={vi.fn()} />)

    await waitFor(() => expect(screen.getByText('セキュリティ更新')).toBeInTheDocument())
    expect(screen.getByText('バージョン更新')).toBeInTheDocument()
    expect(screen.getByText('不明')).toBeInTheDocument()
  })

  it('renders the compatibility score badge image when a URL is present', async () => {
    mockedList.mockResolvedValue(listResponse([
      item({
        pr_number: 1,
        compatibility_badge_url: 'https://dependabot-badges.githubapp.com/badges/x',
      }),
    ]))
    mockedAll.mockResolvedValue([])
    render(<DependabotOpsModal open onClose={vi.fn()} />)

    await waitFor(() => {
      expect(screen.getByAltText('Dependabot compatibility score')).toHaveAttribute(
        'src', 'https://dependabot-badges.githubapp.com/badges/x',
      )
    })
  })

  it('shows a placeholder when no compatibility score badge is available', async () => {
    mockedList.mockResolvedValue(listResponse([item({ pr_number: 1 })]))
    mockedAll.mockResolvedValue([])
    render(<DependabotOpsModal open onClose={vi.fn()} />)

    await waitFor(() => expect(screen.getByText(/Bump lucide-react/)).toBeInTheDocument())
    expect(screen.queryByAltText('Dependabot compatibility score')).not.toBeInTheDocument()
  })

  it('calls onClose when the close button is clicked', async () => {
    mockedList.mockResolvedValue(listResponse([]))
    mockedAll.mockResolvedValue([])
    const onClose = vi.fn()
    render(<DependabotOpsModal open onClose={onClose} />)
    await waitFor(() => expect(mockedList).toHaveBeenCalled())

    await userEvent.click(screen.getByLabelText('閉じる'))
    expect(onClose).toHaveBeenCalledOnce()
  })

  it('calls onClose when Escape is pressed', async () => {
    mockedList.mockResolvedValue(listResponse([]))
    mockedAll.mockResolvedValue([])
    const onClose = vi.fn()
    render(<DependabotOpsModal open onClose={onClose} />)
    await waitFor(() => expect(mockedList).toHaveBeenCalled())

    await userEvent.keyboard('{Escape}')
    expect(onClose).toHaveBeenCalledOnce()
  })

  it('renders the unresolved repo chart from all fetched entries', async () => {
    mockedList.mockResolvedValue(listResponse([item()]))
    mockedAll.mockResolvedValue([
      item({ repo_full_name: 'u/r1', pr_number: 1, action: 'flagged' }),
    ])
    render(<DependabotOpsModal open onClose={vi.fn()} />)

    await waitFor(() => {
      expect(screen.getByText('リポジトリ別 要確認PR件数（未解決）')).toBeInTheDocument()
    })
    expect(mockedAll).toHaveBeenCalled()
  })

  it('shows a neutral "resolved" badge for PRs closed outside DEPSOPS', async () => {
    mockedList.mockResolvedValue(listResponse([
      item({ pr_number: 1, action: 'closed', reason: 'Dependabotの自動クローズ等で解消済み' }),
    ]))
    mockedAll.mockResolvedValue([])
    render(<DependabotOpsModal open onClose={vi.fn()} />)

    // "解消済み" はフィルターボタンとバッジの両方に表示されるため getAllByText で確認する
    await waitFor(() => expect(screen.getAllByText('解消済み').length).toBeGreaterThan(1))
    expect(screen.getByText('Dependabotの自動クローズ等で解消済み')).toBeInTheDocument()
  })
})
