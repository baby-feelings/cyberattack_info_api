import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor, act } from '@testing-library/react'
import { useGithubSession } from './useGithubSession'
import { exchangeAuthCode, refreshSession, UnauthorizedError } from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    exchangeAuthCode: vi.fn(),
    refreshSession: vi.fn(),
  }
})

const mockedExchangeAuthCode = vi.mocked(exchangeAuthCode)
const mockedRefreshSession = vi.mocked(refreshSession)

function setUrl(search: string) {
  window.history.pushState({}, '', `/${search}`)
}

describe('useGithubSession', () => {
  beforeEach(() => {
    localStorage.clear()
    setUrl('')
  })

  afterEach(() => {
    vi.resetAllMocks()
  })

  it('reports checked=true and no session once the initial check completes', async () => {
    const { result } = renderHook(() => useGithubSession())
    await waitFor(() => expect(result.current.checked).toBe(true))
    expect(result.current.session).toBeNull()
  })

  it('restores a session from localStorage (shared depscan_session_* keys)', async () => {
    localStorage.setItem('depscan_session_token', 'tok-abc')
    localStorage.setItem('depscan_session_user', 'octocat')

    const { result } = renderHook(() => useGithubSession())
    await waitFor(() => expect(result.current.checked).toBe(true))
    expect(result.current.session).toEqual({ token: 'tok-abc', username: 'octocat' })
  })

  it('exchanges the OAuth callback code, stores the session, and strips the URL', async () => {
    setUrl('?depscan_code=code-123&other=1')
    mockedExchangeAuthCode.mockResolvedValue({ token: 'new-token', username: 'newuser' })

    const { result } = renderHook(() => useGithubSession())
    await waitFor(() => expect(result.current.session).toEqual({
      token: 'new-token', username: 'newuser',
    }))
    expect(mockedExchangeAuthCode).toHaveBeenCalledWith('code-123')
    expect(localStorage.getItem('depscan_session_token')).toBe('new-token')
    expect(localStorage.getItem('depscan_session_user')).toBe('newuser')
    expect(window.location.search).not.toContain('depscan_code')
    expect(window.location.search).toContain('other=1')
  })

  it('stays logged out when the exchange code is invalid or expired', async () => {
    setUrl('?depscan_code=bad-code')
    mockedExchangeAuthCode.mockRejectedValue(new Error('Exchange error 400'))

    const { result } = renderHook(() => useGithubSession())
    await waitFor(() => expect(result.current.checked).toBe(true))
    expect(result.current.session).toBeNull()
    expect(localStorage.getItem('depscan_session_token')).toBeNull()
  })

  it('handleLogout clears the session, localStorage, and calls onLogout', async () => {
    localStorage.setItem('depscan_session_token', 'tok-abc')
    localStorage.setItem('depscan_session_user', 'octocat')
    const onLogout = vi.fn()

    const { result } = renderHook(() => useGithubSession(onLogout))
    await waitFor(() => expect(result.current.session).not.toBeNull())

    act(() => result.current.handleLogout())

    expect(result.current.session).toBeNull()
    expect(localStorage.getItem('depscan_session_token')).toBeNull()
    expect(onLogout).toHaveBeenCalledOnce()
  })

  it('handleLogoutClick only logs out after confirmation', async () => {
    localStorage.setItem('depscan_session_token', 'tok-abc')
    localStorage.setItem('depscan_session_user', 'octocat')

    const { result } = renderHook(() => useGithubSession())
    await waitFor(() => expect(result.current.session).not.toBeNull())

    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValueOnce(false)
    act(() => result.current.handleLogoutClick())
    expect(confirmSpy).toHaveBeenCalled()
    expect(result.current.session).not.toBeNull()

    confirmSpy.mockReturnValueOnce(true)
    act(() => result.current.handleLogoutClick())
    expect(result.current.session).toBeNull()
  })

  describe('session refresh (sliding expiry, Issue #337)', () => {
    function storeSessionInStorage() {
      localStorage.setItem('depscan_session_token', 'old-token')
      localStorage.setItem('depscan_session_user', 'octocat')
    }

    it('extends the stored session on load and saves the new token', async () => {
      storeSessionInStorage()
      mockedRefreshSession.mockResolvedValue({ token: 'new-token', username: 'octocat' })

      const { result } = renderHook(() => useGithubSession())
      await waitFor(() => expect(result.current.session?.token).toBe('new-token'))
      expect(mockedRefreshSession).toHaveBeenCalledWith('old-token')
      expect(localStorage.getItem('depscan_session_token')).toBe('new-token')
    })

    it('shows the login screen when the stored session can no longer be extended (401)', async () => {
      storeSessionInStorage()
      mockedRefreshSession.mockRejectedValue(new UnauthorizedError('expired'))

      const { result } = renderHook(() => useGithubSession())
      await waitFor(() => expect(result.current.checked).toBe(true))
      expect(result.current.session).toBeNull()
      expect(localStorage.getItem('depscan_session_token')).toBeNull()
    })

    it('keeps the session when the refresh fails for a non-auth reason (offline etc.)', async () => {
      storeSessionInStorage()
      mockedRefreshSession.mockRejectedValue(new Error('network down'))

      const { result } = renderHook(() => useGithubSession())
      await waitFor(() => expect(result.current.checked).toBe(true))
      expect(mockedRefreshSession).toHaveBeenCalled()
      expect(result.current.session).toEqual({ token: 'old-token', username: 'octocat' })
      expect(localStorage.getItem('depscan_session_token')).toBe('old-token')
    })

    it('shares one refresh request between hook instances opened at the same time', async () => {
      storeSessionInStorage()
      mockedRefreshSession.mockResolvedValue({ token: 'new-token', username: 'octocat' })

      const first = renderHook(() => useGithubSession())
      const second = renderHook(() => useGithubSession())
      await waitFor(() => expect(first.result.current.checked).toBe(true))
      await waitFor(() => expect(second.result.current.checked).toBe(true))
      expect(mockedRefreshSession).toHaveBeenCalledTimes(1)
      expect(second.result.current.session?.token).toBe('new-token')
    })

    it('logs out and calls onLogout when a later refresh (tab return) gets 401', async () => {
      vi.useFakeTimers({ toFake: ['Date'] })
      try {
        storeSessionInStorage()
        mockedRefreshSession.mockResolvedValueOnce({ token: 'tok-1', username: 'octocat' })
        const onLogout = vi.fn()
        const { result } = renderHook(() => useGithubSession(onLogout))
        await waitFor(() => expect(result.current.session?.token).toBe('tok-1'))

        mockedRefreshSession.mockRejectedValue(new UnauthorizedError('expired'))
        vi.setSystemTime(Date.now() + 2 * 60 * 60 * 1000)
        act(() => { document.dispatchEvent(new Event('visibilitychange')) })
        await waitFor(() => expect(result.current.session).toBeNull())
        expect(onLogout).toHaveBeenCalled()
        expect(localStorage.getItem('depscan_session_token')).toBeNull()
      } finally {
        vi.useRealTimers()
      }
    })

    it('does not call refresh when there is no session', async () => {
      const { result } = renderHook(() => useGithubSession())
      await waitFor(() => expect(result.current.checked).toBe(true))
      expect(mockedRefreshSession).not.toHaveBeenCalled()
    })

    it('refreshes again when the tab becomes visible after the minimum interval', async () => {
      vi.useFakeTimers({ toFake: ['Date'] })
      try {
        storeSessionInStorage()
        mockedRefreshSession.mockResolvedValue({ token: 'tok-1', username: 'octocat' })
        const { result } = renderHook(() => useGithubSession())
        await waitFor(() => expect(result.current.session?.token).toBe('tok-1'))
        expect(mockedRefreshSession).toHaveBeenCalledTimes(1)

        // 1時間未満では、タブに戻っても再度は呼ばない
        vi.setSystemTime(Date.now() + 30 * 60 * 1000)
        act(() => { document.dispatchEvent(new Event('visibilitychange')) })
        expect(mockedRefreshSession).toHaveBeenCalledTimes(1)

        // 1時間以上経っていれば、現在のトークンで再度延長する
        mockedRefreshSession.mockResolvedValue({ token: 'tok-2', username: 'octocat' })
        vi.setSystemTime(Date.now() + 60 * 60 * 1000)
        act(() => { document.dispatchEvent(new Event('visibilitychange')) })
        await waitFor(() => expect(result.current.session?.token).toBe('tok-2'))
        expect(mockedRefreshSession).toHaveBeenLastCalledWith('tok-1')
      } finally {
        vi.useRealTimers()
      }
    })
  })
})
