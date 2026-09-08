import { describe, it, expect } from 'vitest'
import { computeUnresolvedRepoStats } from './depsopsGrouping'
import type { DependabotPrLogOut } from '../../api/client'

function entry(overrides: Partial<DependabotPrLogOut> = {}): DependabotPrLogOut {
  return {
    repo_full_name: 'baby-feelings/baby_grow',
    pr_number: 1,
    title: 'Bump lucide-react from 1.18.0 to 1.37.0',
    action: 'flagged',
    reason: 'メジャーバージョンアップ',
    processed_at: '2026-06-01T00:00:00Z',
    ...overrides,
  }
}

describe('computeUnresolvedRepoStats', () => {
  it('counts flagged PRs per repo', () => {
    const stats = computeUnresolvedRepoStats([
      entry({ repo_full_name: 'u/r1', pr_number: 1 }),
      entry({ repo_full_name: 'u/r1', pr_number: 2 }),
      entry({ repo_full_name: 'u/r2', pr_number: 1 }),
    ])
    expect(stats).toEqual([
      { repo_full_name: 'u/r1', count: 2 },
      { repo_full_name: 'u/r2', count: 1 },
    ])
  })

  it('excludes merged PRs', () => {
    const stats = computeUnresolvedRepoStats([
      entry({ repo_full_name: 'u/r1', pr_number: 1, action: 'merged' }),
    ])
    expect(stats).toEqual([])
  })

  it('deduplicates repeated daily entries for the same PR, keeping only the latest', () => {
    // 同じPRが複数日「要確認」のままだと、DEPSOPSは実行ごとに行を積み増す。
    // 最新の状態だけを見て重複カウントしないこと。
    const stats = computeUnresolvedRepoStats([
      entry({ pr_number: 1, processed_at: '2026-06-01T00:00:00Z' }),
      entry({ pr_number: 1, processed_at: '2026-06-02T00:00:00Z' }),
      entry({ pr_number: 1, processed_at: '2026-06-03T00:00:00Z' }),
    ])
    expect(stats).toEqual([{ repo_full_name: 'baby-feelings/baby_grow', count: 1 }])
  })

  it('does not count a PR whose latest status is merged even if it was flagged earlier', () => {
    const stats = computeUnresolvedRepoStats([
      entry({ pr_number: 1, action: 'flagged', processed_at: '2026-06-01T00:00:00Z' }),
      entry({ pr_number: 1, action: 'merged', processed_at: '2026-06-02T00:00:00Z' }),
    ])
    expect(stats).toEqual([])
  })

  it('sorts by count descending', () => {
    const stats = computeUnresolvedRepoStats([
      entry({ repo_full_name: 'u/small', pr_number: 1 }),
      entry({ repo_full_name: 'u/big', pr_number: 1 }),
      entry({ repo_full_name: 'u/big', pr_number: 2 }),
    ])
    expect(stats.map(s => s.repo_full_name)).toEqual(['u/big', 'u/small'])
  })

  it('returns an empty array for no entries', () => {
    expect(computeUnresolvedRepoStats([])).toEqual([])
  })
})
