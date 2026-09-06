import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { DepscanAuthGate } from './DepscanAuthGate'
import { fetchScanStatus, logout, UnauthorizedError, githubLoginUrl } from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    fetchScanStatus: vi.fn(),
    logout: vi.fn().mockResolvedValue(undefined),
    githubLoginUrl: vi.fn(() => 'https://cyberattack-info-api.onrender.com/auth/github/login'),
  }
})

vi.mock('./DepscanPanel', () => ({
  DepscanPanel: () => <div data-testid="depscan-panel">panel</div>,
}))

const mockedFetchScanStatus = vi.mocked(fetchScanStatus)
const mockedLogout = vi.mocked(logout)

function setUrl(search: string) {
  window.history.pushState({}, '', `/${search}`)
}

describe('DepscanAuthGate', () => {
  beforeEach(() => {
    localStorage.clear()
    setUrl('')
    mockedLogout.mockResolvedValue(undefined)
    vi.useFakeTimers({ shouldAdvanceTime: true })
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.resetAllMocks()
  })

  it('shows the login button when there is no session', async () => {
    render(<DepscanAuthGate />)
    await waitFor(() => expect(screen.getByText('GitHubでログイン')).toBeInTheDocument())
    expect(screen.getByText('GitHubでログイン').closest('a')).toHaveAttribute(
      'href', 'https://cyberattack-info-api.onrender.com/auth/github/login',
    )
    expect(githubLoginUrl).toHaveBeenCalled()
  })

  it('restores the displayed username from localStorage and shows the scanning state', async () => {
    localStorage.setItem('depscan_session_user', 'octocat')
    mockedFetchScanStatus.mockResolvedValue({ username: 'octocat', status: 'running' })

    render(<DepscanAuthGate />)
    await waitFor(() => expect(screen.getByText(/ログイン中/)).toBeInTheDocument())
    expect(screen.getByText('octocat', { selector: 'span.text-slate-300' })).toBeInTheDocument()
    expect(screen.getByText(/スキャン中です/)).toBeInTheDocument()
  })

  it('consumes the OAuth callback username from the URL, stores it, and strips the URL', async () => {
    // セッションJWT自体はHttpOnly Cookieで渡されるため、URLにはユーザー名のみ載る
    setUrl('?depscan_user=newuser&other=1')
    mockedFetchScanStatus.mockResolvedValue({ username: 'newuser', status: 'done' })

    render(<DepscanAuthGate />)

    await waitFor(() => expect(screen.getByTestId('depscan-panel')).toBeInTheDocument())
    expect(localStorage.getItem('depscan_session_user')).toBe('newuser')
    expect(window.location.search).not.toContain('depscan_user')
    expect(window.location.search).toContain('other=1')
  })

  it('shows the DepscanPanel once the scan is done', async () => {
    localStorage.setItem('depscan_session_user', 'octocat')
    mockedFetchScanStatus.mockResolvedValue({ username: 'octocat', status: 'done' })

    render(<DepscanAuthGate />)
    await waitFor(() => expect(screen.getByTestId('depscan-panel')).toBeInTheDocument())
  })

  it('shows an error banner but still renders the panel when the scan errored', async () => {
    localStorage.setItem('depscan_session_user', 'octocat')
    mockedFetchScanStatus.mockResolvedValue({
      username: 'octocat', status: 'error', error_message: 'GitHub API down',
    })

    render(<DepscanAuthGate />)
    await waitFor(() => expect(screen.getByText(/GitHub API down/)).toBeInTheDocument())
    expect(screen.getByTestId('depscan-panel')).toBeInTheDocument()
  })

  it('logs out automatically on UnauthorizedError without a confirm dialog', async () => {
    localStorage.setItem('depscan_session_user', 'octocat')
    mockedFetchScanStatus.mockRejectedValue(new UnauthorizedError('expired'))
    const confirmSpy = vi.spyOn(window, 'confirm')

    render(<DepscanAuthGate />)
    await waitFor(() => expect(screen.getByText('GitHubでログイン')).toBeInTheDocument())
    expect(localStorage.getItem('depscan_session_user')).toBeNull()
    expect(confirmSpy).not.toHaveBeenCalled()
    // 自動ログアウトはサーバーへのlogout呼び出しを伴わない（Cookie自体はまだ有効期限内の
    // 可能性があるため。明示的なログアウトボタンでのみサーバー側Cookieを削除する）
    expect(mockedLogout).not.toHaveBeenCalled()
  })

  it('does not log out on a transient network error and retries polling', async () => {
    localStorage.setItem('depscan_session_user', 'octocat')
    mockedFetchScanStatus
      .mockRejectedValueOnce(new Error('network blip'))
      .mockResolvedValueOnce({ username: 'octocat', status: 'done' })

    render(<DepscanAuthGate />)
    await waitFor(() => expect(mockedFetchScanStatus).toHaveBeenCalledTimes(1))
    expect(localStorage.getItem('depscan_session_user')).toBe('octocat')

    await vi.advanceTimersByTimeAsync(4000)
    await waitFor(() => expect(screen.getByTestId('depscan-panel')).toBeInTheDocument())
  })

  it('logs out only after confirming when the logout button is clicked, and clears the server cookie', async () => {
    vi.useRealTimers()
    localStorage.setItem('depscan_session_user', 'octocat')
    mockedFetchScanStatus.mockResolvedValue({ username: 'octocat', status: 'done' })
    const user = userEvent.setup()

    render(<DepscanAuthGate />)
    await waitFor(() => expect(screen.getByText('ログアウト')).toBeInTheDocument())

    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValueOnce(false)
    await user.click(screen.getByText('ログアウト'))
    expect(confirmSpy).toHaveBeenCalled()
    expect(screen.getByText('ログアウト')).toBeInTheDocument() // still logged in
    expect(mockedLogout).not.toHaveBeenCalled()

    confirmSpy.mockReturnValueOnce(true)
    await user.click(screen.getByText('ログアウト'))
    await waitFor(() => expect(screen.getByText('GitHubでログイン')).toBeInTheDocument())
    expect(localStorage.getItem('depscan_session_user')).toBeNull()
    expect(mockedLogout).toHaveBeenCalledTimes(1)
  })
})
