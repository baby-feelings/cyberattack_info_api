import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { PostureSection } from './PostureSection'
import { failed, loading, ready } from './testFixtures'

vi.mock('../freshness/LastFetched', () => ({ LastFetched: () => null }))

function renderSection(source: Parameters<typeof PostureSection<string>>[0]['source'], onRetry = vi.fn()) {
  render(
    <PostureSection title="外形監視" crawlerType="EXTMON" source={source} onRetry={onRetry}>
      {(value) => <p>{value}</p>}
    </PostureSection>,
  )
  return onRetry
}

describe('PostureSection reload button', () => {
  it('is shown on a loaded section and reloads when pressed', async () => {
    const onRetry = renderSection(ready('本文'))

    await userEvent.click(screen.getByRole('button', { name: '外形監視を再読み込み' }))

    expect(onRetry).toHaveBeenCalledTimes(1)
  })

  it('is disabled while the section is loading', () => {
    renderSection(loading())

    expect(screen.getByRole('button', { name: '外形監視を再読み込み' })).toBeDisabled()
  })

  it('stays available after a failure (next to the retry button)', () => {
    renderSection(failed())

    expect(screen.getByRole('button', { name: '外形監視を再読み込み' })).toBeEnabled()
  })
})
