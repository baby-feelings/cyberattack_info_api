import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { McpTokenSection } from './McpTokenSection'
import * as authApi from '../api/auth'
import { UnauthorizedError } from '../api/shared'

vi.mock('../api/auth', async () => {
  const actual = await vi.importActual<typeof import('../api/auth')>('../api/auth')
  return { ...actual, issueMcpToken: vi.fn() }
})

const ISSUED = { token: 'mcp-abc', username: 'octocat', expires_at: '2026-11-08T00:00:00+00:00' }

describe('McpTokenSection', () => {
  beforeEach(() => {
    vi.mocked(authApi.issueMcpToken).mockResolvedValue(ISSUED)
  })

  afterEach(() => {
    vi.resetAllMocks()
  })

  it('does not show a token before issuing', () => {
    render(<McpTokenSection authToken="tok" />)
    expect(screen.getByRole('button', { name: 'MCPトークンを発行' })).toBeInTheDocument()
    expect(screen.queryByLabelText('Claude Code に登録するコマンド')).not.toBeInTheDocument()
  })

  it('issues a token with the session token and shows the command and expiry', async () => {
    const user = userEvent.setup()
    render(<McpTokenSection authToken="tok" />)

    await user.click(screen.getByRole('button', { name: 'MCPトークンを発行' }))

    expect(authApi.issueMcpToken).toHaveBeenCalledWith('tok')
    const command = await screen.findByLabelText('Claude Code に登録するコマンド')
    expect((command as HTMLTextAreaElement).value).toContain('claude mcp add --transport http')
    expect((command as HTMLTextAreaElement).value).toContain('Authorization: Bearer mcp-abc')
    expect(screen.getByText('有効期限: 2026-11-08')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'トークンを再発行' })).toBeInTheDocument()
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

  it('shows a re-login message when the session has expired', async () => {
    const user = userEvent.setup()
    vi.mocked(authApi.issueMcpToken).mockRejectedValue(new UnauthorizedError('expired'))
    render(<McpTokenSection authToken="tok" />)

    await user.click(screen.getByRole('button', { name: 'MCPトークンを発行' }))

    expect(await screen.findByText(/再ログインしてください/)).toBeInTheDocument()
    expect(screen.queryByLabelText('Claude Code に登録するコマンド')).not.toBeInTheDocument()
  })

  it('shows a generic error when issuing fails', async () => {
    const user = userEvent.setup()
    vi.mocked(authApi.issueMcpToken).mockRejectedValue(new Error('500'))
    render(<McpTokenSection authToken="tok" />)

    await user.click(screen.getByRole('button', { name: 'MCPトークンを発行' }))

    await waitFor(() => expect(screen.getByText('トークンの発行に失敗しました')).toBeInTheDocument())
  })
})
