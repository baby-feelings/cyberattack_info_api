import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { OAuthConnectionsSection } from './OAuthConnectionsSection'
import * as authApi from '../api/auth'
import { UnauthorizedError } from '../api/shared'

vi.mock('../api/auth', async () => {
  const actual = await vi.importActual<typeof import('../api/auth')>('../api/auth')
  return {
    ...actual,
    listOAuthConnections: vi.fn(),
    disconnectOAuthClient: vi.fn(),
  }
})

const CONN: authApi.OAuthConnection = {
  client_id: 'client-1111', client_name: 'Claude Code',
  connected_at: '2026-10-10T00:00:00+00:00', last_refreshed_at: '2026-10-12T00:00:00+00:00',
  last_used_at: '2026-10-12T09:00:00+00:00', expires_at: '2026-11-11T00:00:00+00:00',
}

const mockList = vi.mocked(authApi.listOAuthConnections)
const mockDisconnect = vi.mocked(authApi.disconnectOAuthClient)

beforeEach(() => {
  mockList.mockReset()
  mockDisconnect.mockReset()
})
afterEach(() => vi.restoreAllMocks())

describe('OAuthConnectionsSection', () => {
  it('接続が1件も無くても、推奨の接続方法と登録コマンドを表示する（一覧は出さない）', async () => {
    mockList.mockResolvedValue([])
    render(<OAuthConnectionsSection authToken="t" />)
    await waitFor(() => expect(mockList).toHaveBeenCalledWith('t'))
    expect(screen.getByRole('heading', { name: 'OAuth で接続（推奨）' })).toBeInTheDocument()
    expect(screen.getByLabelText('OAuth の登録コマンド')).toHaveTextContent(
      /^claude mcp add --scope user --transport http cyberattack-info .+\/mcp$/,
    )
    expect(screen.queryByRole('list', { name: 'OAuthで接続中のアプリ' })).not.toBeInTheDocument()
    expect(screen.queryByText('接続中のアプリ')).not.toBeInTheDocument()
  })

  it('登録コマンドにトークンを含めない（OAuth は貼り付け不要）', async () => {
    mockList.mockResolvedValue([])
    render(<OAuthConnectionsSection authToken="secret-session-token" />)
    await waitFor(() => expect(mockList).toHaveBeenCalled())
    expect(screen.getByLabelText('OAuth の登録コマンド')).not.toHaveTextContent(/Bearer|secret-session-token/)
  })

  it('未使用の接続は自動で解除される旨を表示する', async () => {
    mockList.mockResolvedValue([{ ...CONN, last_used_at: null }])
    render(<OAuthConnectionsSection authToken="t" />)
    expect(await screen.findByText(/7日後に自動で解除されます/)).toBeInTheDocument()
  })

  it('接続中のアプリを、名前・接続日・最終使用・許可の期限つきで表示する', async () => {
    mockList.mockResolvedValue([CONN])
    render(<OAuthConnectionsSection authToken="t" />)
    expect(await screen.findByText('Claude Code')).toBeInTheDocument()
    expect(screen.getByText(/接続 2026-10-10/)).toBeInTheDocument()
    expect(screen.getByText(/最終使用 2026-10-12/)).toBeInTheDocument()
    expect(screen.getByText(/許可の期限 2026-11-11/)).toBeInTheDocument()
  })

  it('一度も使われていない接続は「未使用」と表示する', async () => {
    mockList.mockResolvedValue([{ ...CONN, last_used_at: null }])
    render(<OAuthConnectionsSection authToken="t" />)
    expect(await screen.findByText(/未使用/)).toBeInTheDocument()
  })

  it('アプリ名は HTML として解釈せず、テキストとして表示する（自己申告のため）', async () => {
    const name = '<img src=x onerror=alert(1)>'
    mockList.mockResolvedValue([{ ...CONN, client_name: name }])
    const { container } = render(<OAuthConnectionsSection authToken="t" />)
    expect(await screen.findByText(name)).toBeInTheDocument()
    expect(container.querySelector('img')).toBeNull()
  })

  it('接続解除: 確認のうえ解除し、一覧を取り直す', async () => {
    mockList.mockResolvedValueOnce([CONN]).mockResolvedValueOnce([])
    mockDisconnect.mockResolvedValue()
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    render(<OAuthConnectionsSection authToken="t" />)

    await userEvent.click(await screen.findByRole('button', { name: 'Claude Code の接続を解除する' }))

    expect(mockDisconnect).toHaveBeenCalledWith('t', 'client-1111')
    await waitFor(() => expect(screen.queryByText('Claude Code')).not.toBeInTheDocument())
  })

  it('確認でキャンセルしたら解除しない', async () => {
    mockList.mockResolvedValue([CONN])
    vi.spyOn(window, 'confirm').mockReturnValue(false)
    render(<OAuthConnectionsSection authToken="t" />)

    await userEvent.click(await screen.findByRole('button', { name: 'Claude Code の接続を解除する' }))

    expect(mockDisconnect).not.toHaveBeenCalled()
  })

  it('解除に失敗したらエラーを表示し、接続は一覧に残る', async () => {
    mockList.mockResolvedValue([CONN])
    mockDisconnect.mockRejectedValue(new Error('boom'))
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    render(<OAuthConnectionsSection authToken="t" />)

    await userEvent.click(await screen.findByRole('button', { name: 'Claude Code の接続を解除する' }))

    expect(await screen.findByText('接続の解除に失敗しました')).toBeInTheDocument()
    expect(screen.getByText('Claude Code')).toBeInTheDocument()
  })

  it('一覧の取得に失敗したらエラーを表示する', async () => {
    mockList.mockRejectedValue(new Error('boom'))
    render(<OAuthConnectionsSection authToken="t" />)
    expect(await screen.findByText('OAuth 接続の取得に失敗しました')).toBeInTheDocument()
  })

  it('セッション切れ（401）なら再ログインを促す', async () => {
    mockList.mockRejectedValue(new UnauthorizedError('expired'))
    render(<OAuthConnectionsSection authToken="t" />)
    expect(await screen.findByText(/再ログインしてください/)).toBeInTheDocument()
  })
})
