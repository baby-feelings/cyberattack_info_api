import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, render, screen, waitFor } from '@testing-library/react'
import type { CrawlerLogOut } from '../../api/crawlerLogs'
import { fetchCrawlerLogs } from '../../api/crawlerLogs'
import { LastFetched } from './LastFetched'
import { LOG_LOOKBACK, REFETCH_MS, TICK_MS } from './freshnessConfig'

vi.mock('../../api/crawlerLogs', () => ({ fetchCrawlerLogs: vi.fn() }))
const mockedFetch = vi.mocked(fetchCrawlerLogs)

const NOW = new Date('2026-11-05T12:00:00Z')

function log(
  status: string, hoursAgo: number, counts: { inserted?: number; updated?: number } = {},
): CrawlerLogOut {
  const finished = new Date(NOW.getTime() - hoursAgo * 3_600_000).toISOString()
  return {
    id: 1, crawler_type: 'KEV', status, started_at: finished, finished_at: finished,
    duration_seconds: 1, inserted: counts.inserted ?? 0, updated: counts.updated ?? 0, deleted: 0,
    error_message: null,
  }
}

describe('LastFetched', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] })
    vi.setSystemTime(NOW)
    mockedFetch.mockReset()
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  async function renderFor(logs: CrawlerLogOut[]) {
    mockedFetch.mockResolvedValue(logs)
    render(<LastFetched crawlerType="KEV" />)
    await waitFor(() => expect(mockedFetch).toHaveBeenCalled())
  }

  it('asks for the recent runs of the given crawler type', async () => {
    await renderFor([])
    expect(mockedFetch).toHaveBeenCalledWith({ crawlerType: 'KEV', limit: LOG_LOOKBACK })
  })

  it('shows a fresh state with the relative time, exact time and what changed', async () => {
    await renderFor([log('success', 3, { inserted: 1 })])
    const box = await screen.findByTestId('last-fetched')
    await waitFor(() => expect(box).toHaveAttribute('data-state', 'fresh'))
    expect(box).toHaveTextContent('最終取得')
    expect(box).toHaveTextContent('3')
    expect(box).toHaveTextContent('新規 1 件')
    expect(box.querySelector('time')).toHaveAttribute('datetime', log('success', 3).finished_at)
  })

  it('shows both new and updated counts, or "no change" when nothing changed', async () => {
    await renderFor([log('success', 1, { inserted: 5, updated: 15 })])
    await waitFor(() => expect(screen.getByTestId('last-fetched')).toHaveTextContent('新規 5 件・更新 15 件'))
  })

  it('says there was no change when nothing was added or updated', async () => {
    await renderFor([log('success', 1)])
    await waitFor(() => expect(screen.getByTestId('last-fetched')).toHaveTextContent('変化なし'))
  })

  it('warns in words when the data is late', async () => {
    await renderFor([log('success', 40, { inserted: 5 })])
    const box = await screen.findByTestId('last-fetched')
    await waitFor(() => expect(box).toHaveAttribute('data-state', 'stale'))
    expect(box).toHaveTextContent('更新が遅れています')
  })

  it('shows the failure and the last success when the latest run failed', async () => {
    await renderFor([log('error', 1), log('success', 26)])
    const box = await screen.findByTestId('last-fetched')
    await waitFor(() => expect(box).toHaveAttribute('data-state', 'failed'))
    expect(box).toHaveTextContent('直近の実行が失敗')
    expect(box).toHaveTextContent('最終成功')
  })

  it('shows "unable to confirm" when there are no runs', async () => {
    await renderFor([])
    const box = await screen.findByTestId('last-fetched')
    expect(box).toHaveAttribute('data-state', 'unknown')
    expect(box).toHaveTextContent('取得状況を確認できません')
    expect(box.querySelector('time')).toBeNull()
  })

  it('keeps the page working when the request fails', async () => {
    mockedFetch.mockRejectedValue(new Error('network'))
    render(<LastFetched crawlerType="KEV" />)
    await waitFor(() => expect(mockedFetch).toHaveBeenCalled())
    expect(screen.getByTestId('last-fetched')).toHaveAttribute('data-state', 'unknown')
  })

  it('updates the relative time as time passes, and refetches on an interval', async () => {
    await renderFor([log('success', 0.9)])
    const box = await screen.findByTestId('last-fetched')
    await waitFor(() => expect(box).toHaveTextContent('分'))

    // 1分に1回、相対時間を更新する（54分前 → 約1時間前）
    await act(async () => {
      vi.setSystemTime(new Date(NOW.getTime() + 10 * 60_000))
      vi.advanceTimersByTime(TICK_MS)
    })
    await waitFor(() => expect(box).toHaveTextContent('時間'))

    // 実行履歴は、一定間隔で取り直す
    const before = mockedFetch.mock.calls.length
    await act(async () => { vi.advanceTimersByTime(REFETCH_MS) })
    expect(mockedFetch.mock.calls.length).toBeGreaterThan(before)
  })

  it('measures elapsed time from the moment the runs were fetched, not from when it mounted', async () => {
    // 画面を開いてから、履歴が返るまでに時間が経つ（1分）。基準時刻が古いままだと、経過が短く出る
    let resolve: (logs: CrawlerLogOut[]) => void = () => {}
    mockedFetch.mockReturnValue(new Promise((r) => { resolve = r }))
    render(<LastFetched crawlerType="KEV" />)
    const finished = new Date(NOW.getTime() + 60_000 - 3 * 3_600_000).toISOString()
    await act(async () => {
      vi.setSystemTime(new Date(NOW.getTime() + 60_000))
      resolve([{ ...log('success', 3), finished_at: finished }])
    })
    // 取得時点で、ちょうど3時間経過している（開き始めの時刻で数えると2時間台になる）
    await waitFor(() => expect(screen.getByTestId('last-fetched')).toHaveTextContent('3 時間前'))
  })

  it('stops its timers and ignores a late response after unmount', async () => {
    let resolve: (logs: CrawlerLogOut[]) => void = () => {}
    mockedFetch.mockReturnValue(new Promise((r) => { resolve = r }))
    const { unmount } = render(<LastFetched crawlerType="KEV" />)
    unmount()
    await act(async () => { resolve([log('success', 1)]) })
    expect(screen.queryByTestId('last-fetched')).toBeNull()
  })
})
