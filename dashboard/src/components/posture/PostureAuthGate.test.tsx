import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { PostureAuthGate } from './PostureAuthGate'
import { POSTURE_TEXT } from './postureConfig'

vi.mock('../../api/client', async () => {
  const actual = await vi.importActual<typeof import('../../api/client')>('../../api/client')
  return {
    ...actual,
    githubLoginUrl: vi.fn(() => 'http://localhost:8000/auth/github/login'),
    refreshSession: vi.fn(),
  }
})

vi.mock('./PosturePanel', () => ({
  PosturePanel: ({ authToken }: { authToken: string }) => <div data-testid="posture-panel">panel for {authToken}</div>,
}))

describe('PostureAuthGate', () => {
  beforeEach(() => {
    localStorage.clear()
    window.history.pushState({}, '', '/')
  })

  afterEach(() => {
    vi.resetAllMocks()
  })

  it('asks for the GitHub login, and says what the login shows', async () => {
    render(<PostureAuthGate />)
    await waitFor(() => expect(screen.getByText('GitHubでログイン')).toBeInTheDocument())
    expect(screen.getByText(POSTURE_TEXT.loginDescription)).toBeInTheDocument()
  })

  it('shows the panel with the session token once logged in', async () => {
    localStorage.setItem('depscan_session_token', 'tok-abc')
    localStorage.setItem('depscan_session_user', 'octocat')

    render(<PostureAuthGate />)

    await waitFor(() => expect(screen.getByTestId('posture-panel')).toHaveTextContent('panel for tok-abc'))
  })
})
