import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { DependenciesModal } from './DependenciesModal'
import {
  fetchRepoDependencies, fetchRepoDependencyRepos,
  type RepoDependencyOut, type RepoDependencyListResponse, type RepoDependencyRepoStat,
} from '../../api/client'

vi.mock('../../api/client', async () => {
  const actual = await vi.importActual<typeof import('../../api/client')>('../../api/client')
  return { ...actual, fetchRepoDependencies: vi.fn(), fetchRepoDependencyRepos: vi.fn() }
})

const mockedList = vi.mocked(fetchRepoDependencies)
const mockedRepos = vi.mocked(fetchRepoDependencyRepos)

function dep(overrides: Partial<RepoDependencyOut> = {}): RepoDependencyOut {
  return {
    repo_full_name: 'baby-feelings/app-one',
    ecosystem: 'npm',
    package_name: 'undici',
    version: '8.11.2',
    manifest_path: 'package-lock.json',
    scanned_at: '2026-10-27T00:00:00Z',
    purl: 'pkg:npm/undici@8.11.2',
    open_vulnerabilities: 0,
    ...overrides,
  }
}

function listResponse(data: RepoDependencyOut[], total?: number): RepoDependencyListResponse {
  return { total: total ?? data.length, page: 1, per_page: 20, data }
}

const REPOS: RepoDependencyRepoStat[] = [
  { repo_full_name: 'baby-feelings/app-one', total: 120, vulnerable: 3 },
  { repo_full_name: 'baby-feelings/app-two', total: 80, vulnerable: 0 },
]

beforeEach(() => {
  mockedList.mockResolvedValue(listResponse([dep()]))
  mockedRepos.mockResolvedValue({ repos: REPOS })
})

afterEach(() => {
  vi.clearAllMocks()
})

// 取得が終わって一覧が表示されるまで待つ
async function renderOpen(authToken?: string) {
  render(<DependenciesModal open onClose={vi.fn()} authToken={authToken} />)
  await waitFor(() => expect(screen.getByRole('table', { name: '依存パッケージ一覧' })).toBeInTheDocument())
}

describe('DependenciesModal', () => {
  it('renders nothing and does not fetch while closed', () => {
    render(<DependenciesModal open={false} onClose={vi.fn()} />)
    expect(screen.queryByRole('dialog', { name: '依存パッケージ' })).not.toBeInTheDocument()
    expect(mockedList).not.toHaveBeenCalled()
    expect(mockedRepos).not.toHaveBeenCalled()
  })

  it('lists the dependencies as soon as it opens, without any input', async () => {
    await renderOpen('session-token')

    // 初期表示は運用中のアプリすべて。入力が無くても一覧が出る
    expect(mockedList).toHaveBeenCalledWith({
      page: 1, perPage: 20, packageName: '', version: '', ecosystem: null, repo: null,
      vulnerableOnly: false, operating: 'active', authToken: 'session-token',
    })
    expect(mockedRepos).toHaveBeenCalledWith('session-token', 'active')
    expect(screen.getByText('undici')).toBeInTheDocument()
  })

  it('shows the apps on the left, with the number of vulnerable dependencies', async () => {
    await renderOpen()
    const rail = await screen.findByRole('navigation', { name: 'アプリ一覧' })
    await waitFor(() => expect(within(rail).getByText('app-one')).toBeInTheDocument())

    // 脆弱性のある依存の数は赤いバッジ、無いアプリは依存の総数を薄く表示する
    expect(within(rail).getByTitle('未解決の検知がある依存の数')).toHaveTextContent('3')
    expect(within(rail).getByText('80')).toBeInTheDocument()
    // 「すべてのアプリ」には、依存の総数
    expect(within(rail).getByRole('button', { name: /すべてのアプリ/ })).toHaveTextContent('200')
  })

  it('narrows to the selected app and hides the app column', async () => {
    mockedList.mockResolvedValueOnce(listResponse([dep(), dep({ repo_full_name: 'baby-feelings/app-two' })]))
    await renderOpen()
    expect(screen.getByRole('columnheader', { name: 'アプリ' })).toBeInTheDocument()

    mockedList.mockResolvedValue(listResponse([dep({ package_name: 'axios' })]))
    const rail = await screen.findByRole('navigation', { name: 'アプリ一覧' })
    await waitFor(() => expect(within(rail).getByText('app-one')).toBeInTheDocument())
    await userEvent.click(within(rail).getByRole('button', { name: /app-one/ }))

    await waitFor(() => expect(screen.getByText('axios')).toBeInTheDocument())
    expect(mockedList).toHaveBeenLastCalledWith(expect.objectContaining({
      repo: 'baby-feelings/app-one', page: 1,
    }))
    // アプリを選ぶと、アプリ列は不要になる
    expect(screen.queryByRole('columnheader', { name: 'アプリ' })).not.toBeInTheDocument()
  })

  it('toggles "vulnerable only"', async () => {
    await renderOpen()
    const toggle = screen.getByRole('button', { name: '脆弱性ありのみ' })
    expect(toggle).toHaveAttribute('aria-pressed', 'false')

    await userEvent.click(toggle)

    await waitFor(() => expect(mockedList).toHaveBeenLastCalledWith(
      expect.objectContaining({ vulnerableOnly: true }),
    ))
    expect(screen.getByRole('button', { name: '脆弱性ありのみ' })).toHaveAttribute('aria-pressed', 'true')
  })

  it('switches the operating status and refetches both the apps and the list', async () => {
    await renderOpen()

    await userEvent.click(screen.getByRole('button', { name: '運用停止中' }))

    await waitFor(() => expect(mockedRepos).toHaveBeenLastCalledWith(undefined, 'inactive'))
    await waitFor(() => expect(mockedList).toHaveBeenLastCalledWith(
      expect.objectContaining({ operating: 'inactive', repo: null }),
    ))
  })

  it('searches with the entered conditions only when submitted', async () => {
    await renderOpen()
    mockedList.mockClear()

    await userEvent.type(screen.getByLabelText('パッケージ名（部分一致）'), 'undici')
    await userEvent.type(screen.getByLabelText('バージョン（完全一致）'), '8.11.2')
    // 入力しただけでは取り直さない
    expect(mockedList).not.toHaveBeenCalled()

    await userEvent.selectOptions(screen.getByLabelText('エコシステム'), 'npm')
    await userEvent.click(screen.getByRole('button', { name: '検索' }))

    await waitFor(() => expect(mockedList).toHaveBeenLastCalledWith(expect.objectContaining({
      packageName: 'undici', version: '8.11.2', ecosystem: 'npm',
    })))
  })

  it('submits with Enter', async () => {
    await renderOpen()
    await userEvent.type(screen.getByLabelText('パッケージ名（部分一致）'), 'axios{Enter}')
    await waitFor(() => expect(mockedList).toHaveBeenLastCalledWith(
      expect.objectContaining({ packageName: 'axios' }),
    ))
  })

  it('shows open vulnerabilities as a red badge and "検知なし" otherwise', async () => {
    mockedList.mockResolvedValue(listResponse([
      dep({ open_vulnerabilities: 2 }),
      dep({ package_name: 'axios', open_vulnerabilities: 0 }),
    ]))
    await renderOpen()
    expect(screen.getByText('未解決 2 件')).toBeInTheDocument()
    expect(screen.getByText('検知なし')).toBeInTheDocument()
  })

  it('fetches the next page with the committed conditions, not the half-typed ones', async () => {
    mockedList.mockResolvedValue(listResponse([dep()], 45))
    await renderOpen()

    // 入力欄を書き換えても、「検索」を押すまでは条件に含めない
    await userEvent.type(screen.getByLabelText('パッケージ名（部分一致）'), 'axios')
    await userEvent.click(screen.getAllByRole('button', { name: '次へ →' })[0])

    await waitFor(() => expect(mockedList).toHaveBeenLastCalledWith(
      expect.objectContaining({ page: 2, packageName: '' }),
    ))
  })

  it('shows the empty state, with a message specific to "vulnerable only"', async () => {
    mockedList.mockResolvedValue(listResponse([]))
    render(<DependenciesModal open onClose={vi.fn()} />)
    await waitFor(() => expect(screen.getByText('該当する依存パッケージはありません')).toBeInTheDocument())

    await userEvent.click(screen.getByRole('button', { name: '脆弱性ありのみ' }))
    await waitFor(() => expect(screen.getByText('未解決の検知がある依存パッケージはありません')).toBeInTheDocument())
  })

  it('shows an error state when fetching fails', async () => {
    mockedList.mockRejectedValue(new Error('boom'))
    render(<DependenciesModal open onClose={vi.fn()} />)
    await waitFor(() => expect(screen.getByText(/取得に失敗しました/)).toBeInTheDocument())
  })

  it('still shows the list when the app list fails to load', async () => {
    mockedRepos.mockRejectedValue(new Error('boom'))
    await renderOpen()
    expect(screen.getByText('undici')).toBeInTheDocument()
  })

  it('closes with the close button and with Escape', async () => {
    const onClose = vi.fn()
    render(<DependenciesModal open onClose={onClose} />)

    await userEvent.click(screen.getByLabelText('閉じる'))
    expect(onClose).toHaveBeenCalledTimes(1)

    await userEvent.keyboard('{Escape}')
    expect(onClose).toHaveBeenCalledTimes(2)
  })
})
