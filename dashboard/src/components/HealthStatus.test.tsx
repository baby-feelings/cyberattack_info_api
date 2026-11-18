import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { HealthStatus } from './HealthStatus'
import { fetchHealth } from '../api/client'

vi.mock('../api/client', () => ({
  fetchHealth: vi.fn(),
}))

const mockedFetchHealth = vi.mocked(fetchHealth)

describe('HealthStatus', () => {
  afterEach(() => {
    vi.resetAllMocks()
  })

  it('shows OK status and the DB connection on success, without an environment row', async () => {
    mockedFetchHealth.mockResolvedValueOnce({
      status: 'ok', environment: 'production', db_connected: true,
    })
    render(<HealthStatus />)

    await waitFor(() => expect(screen.getByText('OK')).toBeInTheDocument())
    expect(screen.getByText('正常')).toBeInTheDocument()
    // 実行環境の行は表示しない（本番では常に同じ値で、情報にならないため）
    expect(screen.queryByText('実行環境')).not.toBeInTheDocument()
    expect(screen.queryByText('本番環境')).not.toBeInTheDocument()
  })

  it('shows UNREACHABLE when the health check fails', async () => {
    mockedFetchHealth.mockRejectedValueOnce(new Error('network error'))
    render(<HealthStatus />)

    await waitFor(() => expect(screen.getByText('UNREACHABLE')).toBeInTheDocument())
    expect(screen.getByText('エラー')).toBeInTheDocument()
  })

  it('re-fetches when the refresh button is clicked', async () => {
    mockedFetchHealth.mockResolvedValue({
      status: 'ok', environment: 'development', db_connected: true,
    })
    render(<HealthStatus />)
    await waitFor(() => expect(mockedFetchHealth).toHaveBeenCalledTimes(1))

    fireEvent.click(screen.getByTitle('再確認'))
    await waitFor(() => expect(mockedFetchHealth).toHaveBeenCalledTimes(2))
  })

  it('shows a degraded status as its raw uppercased value, not UNREACHABLE', async () => {
    mockedFetchHealth.mockResolvedValueOnce({
      status: 'degraded', environment: 'production', db_connected: false,
    })
    render(<HealthStatus />)

    await waitFor(() => expect(screen.getByText('DEGRADED')).toBeInTheDocument())
  })
})
