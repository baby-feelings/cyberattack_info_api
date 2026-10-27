import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { DependencySearchModal } from './DependencySearchModal'
import {
  fetchRepoDependencies, type RepoDependencyOut, type RepoDependencyListResponse,
} from '../../api/client'

vi.mock('../../api/client', async () => {
  const actual = await vi.importActual<typeof import('../../api/client')>('../../api/client')
  return { ...actual, fetchRepoDependencies: vi.fn() }
})

const mockedFetch = vi.mocked(fetchRepoDependencies)

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

function response(data: RepoDependencyOut[], total?: number): RepoDependencyListResponse {
  return { total: total ?? data.length, page: 1, per_page: 20, data }
}

afterEach(() => {
  vi.clearAllMocks()
})

describe('DependencySearchModal', () => {
  it('renders nothing when closed', () => {
    render(<DependencySearchModal open={false} onClose={vi.fn()} />)
    expect(screen.queryByRole('dialog', { name: '依存パッケージ検索' })).not.toBeInTheDocument()
    expect(mockedFetch).not.toHaveBeenCalled()
  })

  it('asks for input and does not fetch until a search is submitted', () => {
    render(<DependencySearchModal open onClose={vi.fn()} />)
    expect(screen.getByText('パッケージ名かバージョンを入力して検索してください')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '検索' })).toBeDisabled()
    expect(mockedFetch).not.toHaveBeenCalled()
  })

  it('searches with the entered conditions and the session token', async () => {
    mockedFetch.mockResolvedValue(response([
      dep({ open_vulnerabilities: 2 }),
      dep({ repo_full_name: 'baby-feelings/app-two', version: '8.12.3', open_vulnerabilities: 0 }),
    ]))
    render(<DependencySearchModal open onClose={vi.fn()} authToken="session-token" />)

    await userEvent.type(screen.getByLabelText('パッケージ名（部分一致）'), 'undici')
    await userEvent.type(screen.getByLabelText('バージョン（完全一致）'), '8.11.2')
    await userEvent.selectOptions(screen.getByLabelText('エコシステム'), 'npm')
    await userEvent.click(screen.getByRole('button', { name: '検索' }))

    await waitFor(() => expect(screen.getByRole('table', { name: '依存パッケージ検索結果' })).toBeInTheDocument())
    expect(mockedFetch).toHaveBeenCalledWith({
      page: 1, perPage: 20, packageName: 'undici', version: '8.11.2', ecosystem: 'npm',
      authToken: 'session-token',
    })
    // 未解決の検知がある版は件数つきのバッジ、無い版は「検知なし」
    expect(screen.getByText('未解決 2 件')).toBeInTheDocument()
    expect(screen.getByText('検知なし')).toBeInTheDocument()
    expect(screen.getByText('baby-feelings/app-two')).toBeInTheDocument()
  })

  it('submits with Enter and passes null for "all ecosystems"', async () => {
    mockedFetch.mockResolvedValue(response([dep()]))
    render(<DependencySearchModal open onClose={vi.fn()} />)

    await userEvent.type(screen.getByLabelText('パッケージ名（部分一致）'), 'undici{Enter}')

    await waitFor(() => expect(mockedFetch).toHaveBeenCalledTimes(1))
    expect(mockedFetch).toHaveBeenCalledWith(expect.objectContaining({ ecosystem: null }))
  })

  it('fetches the next page with the same conditions when paging', async () => {
    mockedFetch.mockResolvedValue(response([dep()], 45))
    render(<DependencySearchModal open onClose={vi.fn()} />)

    await userEvent.type(screen.getByLabelText('パッケージ名（部分一致）'), 'undici')
    await userEvent.click(screen.getByRole('button', { name: '検索' }))
    await waitFor(() => expect(screen.getByRole('table', { name: '依存パッケージ検索結果' })).toBeInTheDocument())

    // 入力欄を書き換えても、ページ送りは検索を確定したときの条件で行う
    await userEvent.clear(screen.getByLabelText('パッケージ名（部分一致）'))
    await userEvent.type(screen.getByLabelText('パッケージ名（部分一致）'), 'axios')
    await userEvent.click(screen.getAllByRole('button', { name: '次へ →' })[0])

    await waitFor(() => expect(mockedFetch).toHaveBeenCalledTimes(2))
    expect(mockedFetch).toHaveBeenLastCalledWith(
      expect.objectContaining({ page: 2, packageName: 'undici' }),
    )
  })

  it('shows the empty state when nothing matches', async () => {
    mockedFetch.mockResolvedValue(response([]))
    render(<DependencySearchModal open onClose={vi.fn()} />)

    await userEvent.type(screen.getByLabelText('パッケージ名（部分一致）'), 'nothing')
    await userEvent.click(screen.getByRole('button', { name: '検索' }))

    await waitFor(() => expect(screen.getByText('該当する依存パッケージはありません')).toBeInTheDocument())
  })

  it('shows an error state when the search fails', async () => {
    mockedFetch.mockRejectedValue(new Error('boom'))
    render(<DependencySearchModal open onClose={vi.fn()} />)

    await userEvent.type(screen.getByLabelText('パッケージ名（部分一致）'), 'undici')
    await userEvent.click(screen.getByRole('button', { name: '検索' }))

    await waitFor(() => expect(screen.getByText(/検索に失敗しました/)).toBeInTheDocument())
  })

  it('closes with the close button and with Escape', async () => {
    const onClose = vi.fn()
    render(<DependencySearchModal open onClose={onClose} />)

    await userEvent.click(screen.getByLabelText('閉じる'))
    expect(onClose).toHaveBeenCalledTimes(1)

    await userEvent.keyboard('{Escape}')
    expect(onClose).toHaveBeenCalledTimes(2)
  })
})
