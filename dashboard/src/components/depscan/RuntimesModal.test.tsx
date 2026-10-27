import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { RuntimesModal } from './RuntimesModal'
import {
  fetchRuntimes, fetchRuntimeRepos, fetchRuntimeReleases,
  type RepoRuntimeOut, type RepoRuntimeRepoStat, type RuntimeReleaseOut,
} from '../../api/client'

vi.mock('../../api/client', async () => {
  const actual = await vi.importActual<typeof import('../../api/client')>('../../api/client')
  return {
    ...actual,
    fetchRuntimes: vi.fn(), fetchRuntimeRepos: vi.fn(), fetchRuntimeReleases: vi.fn(),
  }
})

const mockedList = vi.mocked(fetchRuntimes)
const mockedRepos = vi.mocked(fetchRuntimeRepos)
const mockedReleases = vi.mocked(fetchRuntimeReleases)

function runtime(overrides: Partial<RepoRuntimeOut> = {}): RepoRuntimeOut {
  return {
    repo_full_name: 'baby-feelings/app-one',
    runtime: 'python',
    runtime_label: 'Python',
    cycle: '3.13',
    source_path: '.github/workflows/ci.yml',
    pinned: true,
    state: 'update_available',
    latest_version: '3.13.17',
    recommended_cycle: '3.14',
    recommended_version: '3.14.10',
    eol_date: '2029-10-31',
    days_to_eol: 1100,
    ...overrides,
  }
}

const REPOS: RepoRuntimeRepoStat[] = [
  { repo_full_name: 'baby-feelings/app-one', total: 5, needs_action: 2 },
  { repo_full_name: 'baby-feelings/app-two', total: 3, needs_action: 0 },
]

const RELEASES: RuntimeReleaseOut[] = [
  {
    runtime: 'python', runtime_label: 'Python', cycle: '3.14', latest_version: '3.14.10',
    release_date: '2025-10-07', eol_date: '2030-10-31', is_eol: false, is_lts: false, recommended: true,
  },
  {
    runtime: 'python', runtime_label: 'Python', cycle: '3.15', latest_version: '3.15.2',
    release_date: '2026-10-09', eol_date: '2031-10-31', is_eol: false, is_lts: false, recommended: false,
  },
  {
    runtime: 'nodejs', runtime_label: 'Node.js', cycle: '24', latest_version: '24.22.1',
    release_date: '2025-05-06', eol_date: '2028-04-30', is_eol: false, is_lts: true, recommended: true,
  },
]

beforeEach(() => {
  mockedList.mockResolvedValue({ total: 1, data: [runtime()] })
  mockedRepos.mockResolvedValue({ repos: REPOS })
  mockedReleases.mockResolvedValue({ data: RELEASES })
})

afterEach(() => {
  vi.clearAllMocks()
})

// 取得が終わって一覧が表示されるまで待つ
async function renderOpen(authToken?: string) {
  render(<RuntimesModal open onClose={vi.fn()} authToken={authToken} />)
  await waitFor(() => expect(screen.getByRole('table', { name: '言語・実行環境一覧' })).toBeInTheDocument())
}

describe('RuntimesModal', () => {
  it('renders nothing and does not fetch while closed', () => {
    render(<RuntimesModal open={false} onClose={vi.fn()} />)
    expect(screen.queryByRole('dialog', { name: '言語・実行環境' })).not.toBeInTheDocument()
    expect(mockedList).not.toHaveBeenCalled()
    expect(mockedRepos).not.toHaveBeenCalled()
    expect(mockedReleases).not.toHaveBeenCalled()
  })

  it('lists the runtimes as soon as it opens, without any input', async () => {
    await renderOpen('session-token')

    // 初期表示は運用中のアプリすべて。入力が無くても一覧が出る
    expect(mockedList).toHaveBeenCalledWith({
      repo: null, runtime: null, needsAction: false, operating: 'active', authToken: 'session-token',
    })
    expect(mockedRepos).toHaveBeenCalledWith('session-token', 'active')
    expect(mockedReleases).toHaveBeenCalledWith('session-token')
    expect(screen.getByText('.github/workflows/ci.yml')).toBeInTheDocument()
  })

  it('shows the state, the recommended version and the support end date', async () => {
    await renderOpen()
    const table = screen.getByRole('table', { name: '言語・実行環境一覧' })
    const row = within(table).getAllByRole('row')[1]

    expect(within(row).getByText('更新あり')).toBeInTheDocument()
    expect(row).toHaveTextContent('3.13')
    expect(row).toHaveTextContent('最新 3.13.17')
    expect(row).toHaveTextContent('3.14')
    expect(row).toHaveTextContent('2029-10-31')
    expect(row).toHaveTextContent('あと 1100 日')
  })

  it('shows an ended version as ended, with the end-of-life badge', async () => {
    mockedList.mockResolvedValue({
      total: 1,
      data: [runtime({ cycle: '3.10', state: 'eol', eol_date: '2026-10-01', days_to_eol: -26 })],
    })
    await renderOpen()
    // 「サポート終了」は列見出しにもあるため、行の中のバッジを見る
    const row = within(screen.getByRole('table', { name: '言語・実行環境一覧' })).getAllByRole('row')[1]
    expect(within(row).getByText('サポート終了')).toBeInTheDocument()
    expect(within(row).getByText('（終了済み）')).toBeInTheDocument()
  })

  it('shows a dash for versions without a support end date (Flutter / Dart)', async () => {
    mockedList.mockResolvedValue({
      total: 1,
      data: [runtime({
        runtime: 'flutter', runtime_label: 'Flutter', cycle: '3.47', state: 'latest',
        eol_date: null, days_to_eol: null, recommended_cycle: '3.47',
      })],
    })
    await renderOpen()
    const table = screen.getByRole('table', { name: '言語・実行環境一覧' })
    expect(within(table).getByText('最新')).toBeInTheDocument()
    expect(within(table).getAllByText('—').length).toBeGreaterThan(0)
  })

  it('marks a lower-bound specification (not pinned) as reference only', async () => {
    mockedList.mockResolvedValue({
      total: 1,
      data: [runtime({
        runtime: 'nodejs', runtime_label: 'Node.js', cycle: '22', pinned: false, state: 'reference',
        source_path: 'functions/package.json',
      })],
    })
    await renderOpen()
    expect(screen.getByText('参考（下限の指定）')).toBeInTheDocument()
    expect(screen.getByText('以上')).toBeInTheDocument()
  })

  it('shows the recommended version of each language', async () => {
    await renderOpen()
    const strip = await screen.findByLabelText('推奨の版')
    await waitFor(() => expect(strip).toHaveTextContent('Python 3.14'))
    expect(strip).toHaveTextContent('最新 3.14.10')
    expect(strip).toHaveTextContent('Node.js 24')
    // 推奨ではない系列（公開直後の 3.15）は出さない
    expect(strip).not.toHaveTextContent('3.15')
  })

  it('still lists the runtimes when the recommended versions cannot be fetched', async () => {
    mockedReleases.mockRejectedValue(new Error('boom'))
    await renderOpen()
    expect(screen.getByText('.github/workflows/ci.yml')).toBeInTheDocument()
    expect(screen.queryByLabelText('推奨の版')).not.toBeInTheDocument()
  })

  it('shows the apps on the left, with the number that need action', async () => {
    await renderOpen()
    const rail = await screen.findByRole('navigation', { name: 'アプリ一覧' })
    await waitFor(() => expect(within(rail).getByText('app-one')).toBeInTheDocument())

    // 対応が必要な数はバッジ、無いアプリは検出した数を薄く表示する
    expect(within(rail).getByTitle(/対応が必要な数/)).toHaveTextContent('2')
    expect(within(rail).getByText('3')).toBeInTheDocument()
    expect(within(rail).getByRole('button', { name: /すべてのアプリ/ })).toHaveTextContent('8')
  })

  it('narrows to the selected app and hides the app column', async () => {
    mockedList.mockResolvedValueOnce({
      total: 2, data: [runtime(), runtime({ repo_full_name: 'baby-feelings/app-two' })],
    })
    await renderOpen()
    expect(screen.getByRole('columnheader', { name: 'アプリ' })).toBeInTheDocument()

    mockedList.mockResolvedValue({ total: 1, data: [runtime({ source_path: 'Dockerfile' })] })
    const rail = await screen.findByRole('navigation', { name: 'アプリ一覧' })
    await waitFor(() => expect(within(rail).getByText('app-one')).toBeInTheDocument())
    await userEvent.click(within(rail).getByRole('button', { name: /app-one/ }))

    await waitFor(() => expect(screen.getByText('Dockerfile')).toBeInTheDocument())
    expect(mockedList).toHaveBeenLastCalledWith(expect.objectContaining({ repo: 'baby-feelings/app-one' }))
    expect(screen.queryByRole('columnheader', { name: 'アプリ' })).not.toBeInTheDocument()
  })

  it('toggles "needs action only"', async () => {
    await renderOpen()
    const toggle = screen.getByRole('button', { name: '更新が必要なものだけ' })
    expect(toggle).toHaveAttribute('aria-pressed', 'false')

    await userEvent.click(toggle)

    await waitFor(() => expect(mockedList).toHaveBeenLastCalledWith(
      expect.objectContaining({ needsAction: true }),
    ))
    expect(screen.getByRole('button', { name: '更新が必要なものだけ' })).toHaveAttribute('aria-pressed', 'true')
  })

  it('filters by language', async () => {
    await renderOpen()
    await userEvent.selectOptions(screen.getByLabelText('言語'), 'nodejs')
    await waitFor(() => expect(mockedList).toHaveBeenLastCalledWith(
      expect.objectContaining({ runtime: 'nodejs' }),
    ))
  })

  it('switches the operating status and refetches both the apps and the list', async () => {
    await renderOpen()

    await userEvent.click(screen.getByRole('button', { name: '運用停止中' }))

    await waitFor(() => expect(mockedRepos).toHaveBeenLastCalledWith(undefined, 'inactive'))
    await waitFor(() => expect(mockedList).toHaveBeenLastCalledWith(
      expect.objectContaining({ operating: 'inactive', repo: null }),
    ))
  })

  it('shows the empty state, with a message specific to the needs-action filter', async () => {
    mockedList.mockResolvedValue({ total: 0, data: [] })
    render(<RuntimesModal open onClose={vi.fn()} />)
    expect(await screen.findByText('該当する言語・実行環境はありません')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: '更新が必要なものだけ' }))
    expect(await screen.findByText('更新が必要な言語・実行環境はありません')).toBeInTheDocument()
  })

  it('shows an error message when fetching fails', async () => {
    mockedList.mockRejectedValue(new Error('boom'))
    render(<RuntimesModal open onClose={vi.fn()} />)
    expect(await screen.findByText(/取得に失敗しました/)).toBeInTheDocument()
  })

  it('closes with the close button and the Escape key', async () => {
    const onClose = vi.fn()
    render(<RuntimesModal open onClose={onClose} />)
    await userEvent.click(screen.getByRole('button', { name: '閉じる' }))
    expect(onClose).toHaveBeenCalledTimes(1)
    await userEvent.keyboard('{Escape}')
    expect(onClose).toHaveBeenCalledTimes(2)
  })
})
