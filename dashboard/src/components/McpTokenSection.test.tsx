import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { McpTokenSection } from './McpTokenSection'
import * as authApi from '../api/auth'
import { UnauthorizedError } from '../api/shared'

vi.mock('../api/auth', async () => {
  const actual = await vi.importActual<typeof import('../api/auth')>('../api/auth')
  return {
    ...actual,
    issueMcpToken: vi.fn(),
    listMcpTokens: vi.fn(),
    revokeMcpToken: vi.fn(),
  }
})

const ISSUED: authApi.McpTokenResponse = {
  id: 'tok-1111-aaaa', token: 'mcp-abc', username: 'octocat',
  created_at: '2026-10-10T00:00:00+00:00', expires_at: '2026-11-08T00:00:00+00:00',
  revoked_at: null, last_used_at: null, status: 'active',
}
const ACTIVE: authApi.McpTokenInfo = {
  id: 'tok-2222-bbbb', created_at: '2026-10-01T00:00:00+00:00',
  expires_at: '2026-11-01T00:00:00+00:00', revoked_at: null,
  last_used_at: '2026-10-05T12:00:00+00:00', status: 'active',
}
const REVOKED: authApi.McpTokenInfo = {
  ...ACTIVE, id: 'tok-3333-cccc', revoked_at: '2026-10-02T00:00:00+00:00', status: 'revoked',
  last_used_at: null,
}

describe('McpTokenSection', () => {
  beforeEach(() => {
    vi.mocked(authApi.listMcpTokens).mockResolvedValue([])
    vi.mocked(authApi.issueMcpToken).mockResolvedValue(ISSUED)
    vi.mocked(authApi.revokeMcpToken).mockResolvedValue()
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.resetAllMocks()
  })

  it('does not show a token command before issuing', async () => {
    render(<McpTokenSection authToken="tok" />)
    await waitFor(() => expect(authApi.listMcpTokens).toHaveBeenCalledWith('tok'))
    expect(screen.getByRole('button', { name: 'MCPトークンを発行' })).toBeInTheDocument()
    expect(screen.queryByLabelText('Claude Code に登録するコマンド')).not.toBeInTheDocument()
  })

  it('issues a token with the default 30 days and shows the command and expiry', async () => {
    const user = userEvent.setup()
    render(<McpTokenSection authToken="tok" />)

    await user.click(screen.getByRole('button', { name: 'MCPトークンを発行' }))

    expect(authApi.issueMcpToken).toHaveBeenCalledWith('tok', 30)
    const command = await screen.findByLabelText('Claude Code に登録するコマンド')
    expect((command as HTMLTextAreaElement).value).toContain('claude mcp add --transport http')
    expect((command as HTMLTextAreaElement).value).toContain('Authorization: Bearer mcp-abc')
    expect(screen.getByText('有効期限: 2026-11-08')).toBeInTheDocument()
    // 発行後に一覧を取り直す
    expect(authApi.listMcpTokens).toHaveBeenCalledTimes(2)
  })

  it('issues with the selected expiry', async () => {
    const user = userEvent.setup()
    render(<McpTokenSection authToken="tok" />)

    await user.selectOptions(screen.getByLabelText('有効期限'), '90')
    await user.click(screen.getByRole('button', { name: 'MCPトークンを発行' }))

    expect(authApi.issueMcpToken).toHaveBeenCalledWith('tok', 90)
  })

  it('lists issued tokens with status, expiry and last use', async () => {
    vi.mocked(authApi.listMcpTokens).mockResolvedValue([ACTIVE, REVOKED])
    render(<McpTokenSection authToken="tok" />)

    const list = await screen.findByRole('list', { name: '発行済みのMCPトークン' })
    const items = within(list).getAllByRole('listitem')
    expect(items).toHaveLength(2)
    expect(items[0]).toHaveTextContent('有効')
    expect(items[0]).toHaveTextContent('期限 2026-11-01')
    expect(items[0]).toHaveTextContent('最終使用 2026-10-05')
    expect(items[1]).toHaveTextContent('失効済み')
    expect(items[1]).toHaveTextContent('未使用')
    // 失効ボタンは有効なトークンにだけ出る
    expect(within(list).getAllByRole('button', { name: /を失効する/ })).toHaveLength(1)
  })

  it('revokes a token after confirmation and refreshes the list', async () => {
    const user = userEvent.setup()
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    vi.mocked(authApi.listMcpTokens)
      .mockResolvedValueOnce([ACTIVE])
      .mockResolvedValueOnce([{ ...ACTIVE, status: 'revoked', revoked_at: '2026-10-10T00:00:00+00:00' }])
    render(<McpTokenSection authToken="tok" />)

    await user.click(await screen.findByRole('button', { name: /を失効する/ }))

    expect(authApi.revokeMcpToken).toHaveBeenCalledWith('tok', 'tok-2222-bbbb')
    expect(await screen.findByText('失効済み')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /を失効する/ })).not.toBeInTheDocument()
  })

  it('does nothing when the revoke confirmation is cancelled', async () => {
    const user = userEvent.setup()
    vi.spyOn(window, 'confirm').mockReturnValue(false)
    vi.mocked(authApi.listMcpTokens).mockResolvedValue([ACTIVE])
    render(<McpTokenSection authToken="tok" />)

    await user.click(await screen.findByRole('button', { name: /を失効する/ }))

    expect(authApi.revokeMcpToken).not.toHaveBeenCalled()
  })

  it('hides the displayed command when that very token is revoked', async () => {
    const user = userEvent.setup()
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    vi.mocked(authApi.listMcpTokens).mockResolvedValue([{ ...ISSUED }])
    render(<McpTokenSection authToken="tok" />)
    await user.click(screen.getByRole('button', { name: 'MCPトークンを発行' }))
    await screen.findByLabelText('Claude Code に登録するコマンド')

    await user.click(screen.getByRole('button', { name: /を失効する/ }))

    await waitFor(() =>
      expect(screen.queryByLabelText('Claude Code に登録するコマンド')).not.toBeInTheDocument())
  })

  it('shows an error when revoking fails', async () => {
    const user = userEvent.setup()
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    vi.mocked(authApi.listMcpTokens).mockResolvedValue([ACTIVE])
    vi.mocked(authApi.revokeMcpToken).mockRejectedValue(new Error('500'))
    render(<McpTokenSection authToken="tok" />)

    await user.click(await screen.findByRole('button', { name: /を失効する/ }))

    expect(await screen.findByText('トークンの失効に失敗しました')).toBeInTheDocument()
  })

  it('copies the command to the clipboard', async () => {
    const user = userEvent.setup()
    const writeText = vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValue()
    render(<McpTokenSection authToken="tok" />)
    await user.click(screen.getByRole('button', { name: 'MCPトークンを発行' }))
    await screen.findByLabelText('Claude Code に登録するコマンド')

    await user.click(screen.getByRole('button', { name: 'コピー' }))

    expect(writeText).toHaveBeenCalledWith(expect.stringContaining('Bearer mcp-abc'))
    expect(await screen.findByText('コピーしました')).toBeInTheDocument()
  })

  it('shows an error when copying fails', async () => {
    const user = userEvent.setup()
    vi.spyOn(navigator.clipboard, 'writeText').mockRejectedValue(new Error('denied'))
    render(<McpTokenSection authToken="tok" />)
    await user.click(screen.getByRole('button', { name: 'MCPトークンを発行' }))
    await screen.findByLabelText('Claude Code に登録するコマンド')

    await user.click(screen.getByRole('button', { name: 'コピー' }))

    expect(await screen.findByText(/コピーに失敗しました/)).toBeInTheDocument()
  })

  it('shows a re-login message when the session has expired while issuing', async () => {
    const user = userEvent.setup()
    vi.mocked(authApi.issueMcpToken).mockRejectedValue(new UnauthorizedError('expired'))
    render(<McpTokenSection authToken="tok" />)

    await user.click(screen.getByRole('button', { name: 'MCPトークンを発行' }))

    expect(await screen.findByText(/再ログインしてください/)).toBeInTheDocument()
    expect(screen.queryByLabelText('Claude Code に登録するコマンド')).not.toBeInTheDocument()
  })

  it('shows the server explanation when the active token limit is reached', async () => {
    const user = userEvent.setup()
    vi.mocked(authApi.issueMcpToken).mockRejectedValue(
      new Error('有効なMCPトークンが上限（10個）に達しています。'))
    render(<McpTokenSection authToken="tok" />)

    await user.click(screen.getByRole('button', { name: 'MCPトークンを発行' }))

    expect(await screen.findByText(/上限（10個）に達しています/)).toBeInTheDocument()
  })

  it('shows a generic error when issuing fails', async () => {
    const user = userEvent.setup()
    vi.mocked(authApi.issueMcpToken).mockRejectedValue(new Error('MCP token error 500'))
    render(<McpTokenSection authToken="tok" />)

    await user.click(screen.getByRole('button', { name: 'MCPトークンを発行' }))

    expect(await screen.findByText('トークンの発行に失敗しました')).toBeInTheDocument()
  })

  it('shows an error when the token list cannot be loaded', async () => {
    vi.mocked(authApi.listMcpTokens).mockRejectedValue(new Error('500'))
    render(<McpTokenSection authToken="tok" />)

    expect(await screen.findByText('トークン一覧の取得に失敗しました')).toBeInTheDocument()
  })

  it('asks to re-login when the session expired while loading the list', async () => {
    vi.mocked(authApi.listMcpTokens).mockRejectedValue(new UnauthorizedError('expired'))
    render(<McpTokenSection authToken="tok" />)

    expect(await screen.findByText(/再ログインしてください/)).toBeInTheDocument()
  })
})
