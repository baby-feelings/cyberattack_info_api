import { describe, it, expect } from 'vitest'
import { summarizeRepos } from './repoSummary'
import type { DependencyFindingOut } from '../../api/client'

function f(repo: string, severity: string | null, resolved = false): DependencyFindingOut {
  return {
    repo_full_name: repo, severity, resolved_at: resolved ? '2026-10-01T00:00:00Z' : null,
  } as DependencyFindingOut
}

describe('summarizeRepos', () => {
  it('counts only unresolved CRITICAL and HIGH as needing action', () => {
    const [s] = summarizeRepos([
      f('o/a', 'CRITICAL'), f('o/a', 'HIGH'), f('o/a', 'HIGH', true), f('o/a', 'LOW'), f('o/a', null),
    ])
    expect(s).toEqual({ repo: 'o/a', crit: 1, high: 1, total: 5 })
  })

  it('puts apps needing action first, then by total, then by name', () => {
    const repos = summarizeRepos([
      f('o/quiet-big', 'LOW'), f('o/quiet-big', 'LOW'), f('o/quiet-big', 'LOW'),
      f('o/urgent', 'HIGH'),
      f('o/b-small', 'LOW'), f('o/a-small', 'LOW'),
    ]).map(r => r.repo)
    expect(repos).toEqual(['o/urgent', 'o/quiet-big', 'o/a-small', 'o/b-small'])
  })

  it('returns an empty list for no findings', () => {
    expect(summarizeRepos([])).toEqual([])
  })
})
