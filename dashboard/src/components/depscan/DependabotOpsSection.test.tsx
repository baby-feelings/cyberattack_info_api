import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { DependabotOpsSection } from './DependabotOpsSection'
import { fetchDepsOpsList, type DependabotPrLogOut, type DepsOpsListResponse } from '../../api/client'

vi.mock('../../api/client', async () => {
  const actual = await vi.importActual<typeof import('../../api/client')>('../../api/client')
  return { ...actual, fetchDepsOpsList: vi.fn() }
})

const mockedFetch = vi.mocked(fetchDepsOpsList)

function item(overrides: Partial<DependabotPrLogOut> = {}): DependabotPrLogOut {
  return {
    repo_full_name: 'baby-feelings/baby_grow',
    pr_number: 42,
    title: 'Bump lucide-react from 1.18.0 to 1.37.0',
    action: 'merged',
    reason: null,
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

describe('DependabotOpsSection', () => {
  it('starts collapsed and does not fetch until expanded', () => {
    render(<DependabotOpsSection />)
    expect(screen.getByText('Dependabot 運用状況（DEPSOPS）')).toBeInTheDocument()
    expect(mockedFetch).not.toHaveBeenCalled()
  })

  it('fetches and shows PR entries once expanded', async () => {
    mockedFetch.mockResolvedValue(listResponse([item()]))
    render(<DependabotOpsSection />)

    await userEvent.click(screen.getByText('Dependabot 運用状況（DEPSOPS）'))

    await waitFor(() => {
      expect(screen.getByText(/Bump lucide-react/)).toBeInTheDocument()
    })
    expect(mockedFetch).toHaveBeenCalledWith(
      expect.objectContaining({ action: null }),
    )
  })

  it('shows the empty state when there are no matching PRs', async () => {
    mockedFetch.mockResolvedValue(listResponse([]))
    render(<DependabotOpsSection />)

    await userEvent.click(screen.getByText('Dependabot 運用状況（DEPSOPS）'))

    await waitFor(() => {
      expect(screen.getByText('該当する PR はありません')).toBeInTheDocument()
    })
  })

  it('shows the flagged reason and re-fetches when filtering by action', async () => {
    mockedFetch.mockResolvedValue(listResponse([
      item({ pr_number: 7, action: 'flagged', reason: 'メジャーバージョンアップ' }),
    ]))
    render(<DependabotOpsSection />)
    await userEvent.click(screen.getByText('Dependabot 運用状況（DEPSOPS）'))
    await waitFor(() => expect(screen.getByText('メジャーバージョンアップ')).toBeInTheDocument())

    mockedFetch.mockClear()
    await userEvent.click(screen.getByRole('button', { name: '要確認' }))

    await waitFor(() => {
      expect(mockedFetch).toHaveBeenCalledWith(
        expect.objectContaining({ action: 'flagged', page: 1 }),
      )
    })
  })
})
