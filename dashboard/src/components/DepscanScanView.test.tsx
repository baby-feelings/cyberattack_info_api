import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { DepscanScanView } from './DepscanScanView'
import { fetchScanStatus, UnauthorizedError } from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return { ...actual, fetchScanStatus: vi.fn() }
})

vi.mock('./DepscanPanel', () => ({
  DepscanPanel: ({ authToken }: { authToken?: string }) => (
    <div data-testid="depscan-panel">panel for {authToken}</div>
  ),
}))

const mockedFetchScanStatus = vi.mocked(fetchScanStatus)
const SESSION = { token: 'tok-abc', username: 'octocat' }

describe('DepscanScanView', () => {
  beforeEach(() => { vi.useFakeTimers({ shouldAdvanceTime: true }) })
  afterEach(() => {
    vi.useRealTimers()
    vi.resetAllMocks()
  })

  it('shows the scanning state while the scan is running', async () => {
    mockedFetchScanStatus.mockResolvedValue({ username: 'octocat', status: 'running' })
    render(<DepscanScanView session={SESSION} onSessionExpired={vi.fn()} />)
    await waitFor(() => expect(screen.getByText(/スキャン中です/)).toBeInTheDocument())
    expect(screen.queryByTestId('depscan-panel')).not.toBeInTheDocument()
  })

  it('shows the DepscanPanel once the scan is done', async () => {
    mockedFetchScanStatus.mockResolvedValue({ username: 'octocat', status: 'done' })
    render(<DepscanScanView session={SESSION} onSessionExpired={vi.fn()} />)
    await waitFor(() => expect(screen.getByTestId('depscan-panel')).toBeInTheDocument())
    expect(screen.getByTestId('depscan-panel')).toHaveTextContent('panel for tok-abc')
  })

  it('shows an error banner but still renders the panel when the scan errored', async () => {
    mockedFetchScanStatus.mockResolvedValue({
      username: 'octocat', status: 'error', error_message: 'GitHub API down',
    })
    render(<DepscanScanView session={SESSION} onSessionExpired={vi.fn()} />)
    await waitFor(() => expect(screen.getByText(/GitHub API down/)).toBeInTheDocument())
    expect(screen.getByTestId('depscan-panel')).toBeInTheDocument()
  })

  it('reports an expired session (401) to the caller', async () => {
    mockedFetchScanStatus.mockRejectedValue(new UnauthorizedError('expired'))
    const onSessionExpired = vi.fn()
    render(<DepscanScanView session={SESSION} onSessionExpired={onSessionExpired} />)
    await waitFor(() => expect(onSessionExpired).toHaveBeenCalledTimes(1))
  })

  it('does not report a transient network error, and retries polling', async () => {
    mockedFetchScanStatus
      .mockRejectedValueOnce(new Error('network blip'))
      .mockResolvedValueOnce({ username: 'octocat', status: 'done' })
    const onSessionExpired = vi.fn()
    render(<DepscanScanView session={SESSION} onSessionExpired={onSessionExpired} />)
    await waitFor(() => expect(mockedFetchScanStatus).toHaveBeenCalledTimes(1))
    expect(onSessionExpired).not.toHaveBeenCalled()

    await vi.advanceTimersByTimeAsync(4000)
    await waitFor(() => expect(screen.getByTestId('depscan-panel')).toBeInTheDocument())
  })
})
