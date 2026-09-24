import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor, act } from '@testing-library/react'
import { useGithubSession } from './useGithubSession'
import { exchangeAuthCode } from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    exchangeAuthCode: vi.fn(),
  }
})

const mockedExchangeAuthCode = vi.mocked(exchangeAuthCode)

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
})
