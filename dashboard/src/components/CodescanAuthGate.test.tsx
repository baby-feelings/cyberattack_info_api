import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CodescanAuthGate } from './CodescanAuthGate'
import { githubLoginUrl } from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    githubLoginUrl: vi.fn(() => 'https://cyberattack-info-api.onrender.com/auth/github/login'),
  }
})

vi.mock('./CodescanPanel', () => ({
  CodescanPanel: ({ authToken }: { authToken?: string }) => (
    <div data-testid="codescan-panel">panel for {authToken}</div>
  ),
}))

function setUrl(search: string) {
  window.history.pushState({}, '', `/${search}`)
}

describe('CodescanAuthGate', () => {
  beforeEach(() => {
    localStorage.clear()
    setUrl('')
  })

  afterEach(() => {
    vi.resetAllMocks()
  })

  it('shows the login button when there is no session', async () => {
    render(<CodescanAuthGate />)
    await waitFor(() => expect(screen.getByText('GitHubでログイン')).toBeInTheDocument())
    expect(screen.getByText('GitHubでログイン').closest('a')).toHaveAttribute(
      'href', 'https://cyberattack-info-api.onrender.com/auth/github/login',
    )
    expect(githubLoginUrl).toHaveBeenCalled()
  })

  it('shows the CodescanPanel immediately once a session exists (no scan-progress UI)', async () => {
    localStorage.setItem('depscan_session_token', 'tok-abc')
    localStorage.setItem('depscan_session_user', 'octocat')

    render(<CodescanAuthGate />)
    await waitFor(() => expect(screen.getByTestId('codescan-panel')).toBeInTheDocument())
    expect(screen.getByTestId('codescan-panel')).toHaveTextContent('panel for tok-abc')
    expect(screen.getByText('octocat', { selector: 'span.text-slate-300' })).toBeInTheDocument()
  })

  it('shares the session with DEPSCAN via the same localStorage keys', async () => {
    // depscan_session_token/depscan_session_user はDEPSCANと共通のキー名
    // （useGithubSession経由）。どちらのタブでログインしても両方閲覧できることの根拠。
    localStorage.setItem('depscan_session_token', 'shared-token')
    localStorage.setItem('depscan_session_user', 'shared-user')

    render(<CodescanAuthGate />)
    await waitFor(() => expect(screen.getByTestId('codescan-panel')).toHaveTextContent(
      'panel for shared-token',
    ))
  })

  it('logs out only after confirming when the logout button is clicked', async () => {
    localStorage.setItem('depscan_session_token', 'tok-abc')
    localStorage.setItem('depscan_session_user', 'octocat')
    const user = userEvent.setup()

    render(<CodescanAuthGate />)
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
