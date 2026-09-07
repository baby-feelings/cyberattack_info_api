import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { DepscanAuthGate } from './DepscanAuthGate'
import { fetchScanStatus, exchangeAuthCode, UnauthorizedError, githubLoginUrl } from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    fetchScanStatus: vi.fn(),
    exchangeAuthCode: vi.fn(),
    githubLoginUrl: vi.fn(() => 'https://cyberattack-info-api.onrender.com/auth/github/login'),
  }
})

vi.mock('./DepscanPanel', () => ({
  DepscanPanel: ({ authToken }: { authToken?: string }) => (
    <div data-testid="depscan-panel">panel for {authToken}</div>
  ),
}))

const mockedFetchScanStatus = vi.mocked(fetchScanStatus)
const mockedExchangeAuthCode = vi.mocked(exchangeAuthCode)

function setUrl(search: string) {
  window.history.pushState({}, '', `/${search}`)
}

describe('DepscanAuthGate', () => {
  beforeEach(() => {
    localStorage.clear()
    setUrl('')
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

  it('restores a session from localStorage and shows the scanning state', async () => {
    localStorage.setItem('depscan_session_token', 'tok-abc')
    localStorage.setItem('depscan_session_user', 'octocat')
    mockedFetchScanStatus.mockResolvedValue({ username: 'octocat', status: 'running' })

    render(<DepscanAuthGate />)
    await waitFor(() => expect(screen.getByText(/ログイン中/)).toBeInTheDocument())
    expect(screen.getByText('octocat', { selector: 'span.text-slate-300' })).toBeInTheDocument()
    expect(screen.getByText(/スキャン中です/)).toBeInTheDocument()
  })

  it('exchanges the OAuth callback code from the URL for a session, and strips the URL', async () => {
    setUrl('?depscan_code=code-123&other=1')
    mockedExchangeAuthCode.mockResolvedValue({ token: 'new-token', username: 'newuser' })
    mockedFetchScanStatus.mockResolvedValue({ username: 'newuser', status: 'done' })

    render(<DepscanAuthGate />)

    await waitFor(() => expect(screen.getByTestId('depscan-panel')).toBeInTheDocument())
    expect(mockedExchangeAuthCode).toHaveBeenCalledWith('code-123')
    expect(localStorage.getItem('depscan_session_token')).toBe('new-token')
    expect(localStorage.getItem('depscan_session_user')).toBe('newuser')
    expect(window.location.search).not.toContain('depscan_code')
    expect(window.location.search).toContain('other=1')
  })

  it('shows the login screen when the exchange code is invalid or expired', async () => {
    setUrl('?depscan_code=bad-code')
    mockedExchangeAuthCode.mockRejectedValue(new Error('Exchange error 400'))

    render(<DepscanAuthGate />)

    await waitFor(() => expect(screen.getByText('GitHubでログイン')).toBeInTheDocument())
    expect(localStorage.getItem('depscan_session_token')).toBeNull()
  })

  it('shows the DepscanPanel once the scan is done', async () => {
    localStorage.setItem('depscan_session_token', 'tok-abc')
    localStorage.setItem('depscan_session_user', 'octocat')
    mockedFetchScanStatus.mockResolvedValue({ username: 'octocat', status: 'done' })

    render(<DepscanAuthGate />)
    await waitFor(() => expect(screen.getByTestId('depscan-panel')).toBeInTheDocument())
    expect(screen.getByTestId('depscan-panel')).toHaveTextContent('panel for tok-abc')
  })

  it('shows an error banner but still renders the panel when the scan errored', async () => {
    localStorage.setItem('depscan_session_token', 'tok-abc')
    localStorage.setItem('depscan_session_user', 'octocat')
    mockedFetchScanStatus.mockResolvedValue({
      username: 'octocat', status: 'error', error_message: 'GitHub API down',
    })

    render(<DepscanAuthGate />)
    await waitFor(() => expect(screen.getByText(/GitHub API down/)).toBeInTheDocument())
    expect(screen.getByTestId('depscan-panel')).toBeInTheDocument()
  })

  it('logs out automatically on UnauthorizedError without a confirm dialog', async () => {
    localStorage.setItem('depscan_session_token', 'expired-token')
    localStorage.setItem('depscan_session_user', 'octocat')
    mockedFetchScanStatus.mockRejectedValue(new UnauthorizedError('expired'))
    const confirmSpy = vi.spyOn(window, 'confirm')

    render(<DepscanAuthGate />)
    await waitFor(() => expect(screen.getByText('GitHubでログイン')).toBeInTheDocument())
    expect(localStorage.getItem('depscan_session_token')).toBeNull()
    expect(confirmSpy).not.toHaveBeenCalled()
  })

  it('does not log out on a transient network error and retries polling', async () => {
    localStorage.setItem('depscan_session_token', 'tok-abc')
    localStorage.setItem('depscan_session_user', 'octocat')
    mockedFetchScanStatus
      .mockRejectedValueOnce(new Error('network blip'))
      .mockResolvedValueOnce({ username: 'octocat', status: 'done' })

    render(<DepscanAuthGate />)
    await waitFor(() => expect(mockedFetchScanStatus).toHaveBeenCalledTimes(1))
    expect(localStorage.getItem('depscan_session_token')).toBe('tok-abc')

    await vi.advanceTimersByTimeAsync(4000)
    await waitFor(() => expect(screen.getByTestId('depscan-panel')).toBeInTheDocument())
  })

  it('logs out only after confirming when the logout button is clicked', async () => {
    vi.useRealTimers()
    localStorage.setItem('depscan_session_token', 'tok-abc')
    localStorage.setItem('depscan_session_user', 'octocat')
    mockedFetchScanStatus.mockResolvedValue({ username: 'octocat', status: 'done' })
    const user = userEvent.setup()

    render(<DepscanAuthGate />)
    await waitFor(() => expect(screen.getByText('ログアウト')).toBeInTheDocument())

    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValueOnce(false)
    await user.click(screen.getByText('ログアウト'))
    expect(confirmSpy).toHaveBeenCalled()
    expect(screen.getByText('ログアウト')).toBeInTheDocument() // still logged in

    confirmSpy.mockReturnValueOnce(true)
    await user.click(screen.getByText('ログアウト'))
    await waitFor(() => expect(screen.getByText('GitHubでログイン')).toBeInTheDocument())
    expect(localStorage.getItem('depscan_session_token')).toBeNull()
  })
})
