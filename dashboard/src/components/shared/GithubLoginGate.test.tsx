import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { GithubLoginGate } from './GithubLoginGate'
import { githubLoginUrl } from '../../api/client'

vi.mock('../../api/client', async () => {
  const actual = await vi.importActual<typeof import('../../api/client')>('../../api/client')
  return {
    ...actual,
    githubLoginUrl: vi.fn(() => 'http://localhost:8000/auth/github/login'),
    // セッション延長は実サーバーへ送らない（CodescanAuthGate のテストと同じ）
    refreshSession: vi.fn(),
  }
})

describe('GithubLoginGate', () => {
  beforeEach(() => {
    localStorage.clear()
    window.history.pushState({}, '', '/')
  })

  afterEach(() => {
    vi.resetAllMocks()
  })

  it('shows the login link and the given description when there is no session', async () => {
    render(
      <GithubLoginGate description="ログインすると、自分のリポジトリの結果を閲覧できます">
        {() => <div data-testid="content" />}
      </GithubLoginGate>,
    )

    await waitFor(() => expect(screen.getByText('GitHubでログイン')).toBeInTheDocument())
    expect(screen.getByText('GitHubでログイン').closest('a')).toHaveAttribute(
      'href', 'http://localhost:8000/auth/github/login',
    )
    expect(screen.getByText('ログインすると、自分のリポジトリの結果を閲覧できます')).toBeInTheDocument()
    expect(githubLoginUrl).toHaveBeenCalled()
    expect(screen.queryByTestId('content')).not.toBeInTheDocument()
  })

  it('renders the children with the session, and shows who is logged in', async () => {
    localStorage.setItem('depscan_session_token', 'tok-abc')
    localStorage.setItem('depscan_session_user', 'octocat')

    render(
      <GithubLoginGate description="説明">
        {(session) => <div data-testid="content">token {session.token}</div>}
      </GithubLoginGate>,
    )

    await waitFor(() => expect(screen.getByTestId('content')).toHaveTextContent('token tok-abc'))
    expect(screen.getByText('octocat', { selector: 'span.text-slate-300' })).toBeInTheDocument()
  })

  it('logs out only after the user confirms, and goes back to the login link', async () => {
    localStorage.setItem('depscan_session_token', 'tok-abc')
    localStorage.setItem('depscan_session_user', 'octocat')
    const user = userEvent.setup()

    render(<GithubLoginGate description="説明">{() => <div data-testid="content" />}</GithubLoginGate>)
    await waitFor(() => expect(screen.getByTestId('content')).toBeInTheDocument())

    // 確認で「いいえ」なら、ログインしたまま
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValueOnce(false)
    await user.click(screen.getByRole('button', { name: /ログアウト/ }))
    expect(confirmSpy).toHaveBeenCalled()
    expect(screen.getByTestId('content')).toBeInTheDocument()

    // 「はい」ならログアウトし、ログインの案内に戻る
    confirmSpy.mockReturnValueOnce(true)
    await user.click(screen.getByRole('button', { name: /ログアウト/ }))
    await waitFor(() => expect(screen.getByText('GitHubでログイン')).toBeInTheDocument())
    expect(localStorage.getItem('depscan_session_token')).toBeNull()
  })
})
