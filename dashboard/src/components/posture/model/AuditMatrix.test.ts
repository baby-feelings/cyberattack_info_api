import { describe, it, expect } from 'vitest'
import type { AuditCheckOut, RepoAuditOut, RepoAuditResponse } from '../../../api/client'
import { AuditMatrix } from './AuditMatrix'
import { RepoAudit } from './RepoAudit'

const check = (key: string, label: string, status = 'ok'): AuditCheckOut =>
  ({ key, label, status, weight: 1, detail: '', fix: '' })

const audit = (repo: string, score: number | null, issues: number, checks: AuditCheckOut[]): RepoAudit =>
  new RepoAudit({ repo_full_name: repo, score, issues, checks, changes: [], audited_at: '2026-11-18T00:00:00Z' })

const matrix = () => new AuditMatrix([
  audit('owner/alpha', 100, 0, [check('a', '項目A'), check('b', '項目B')]),
  audit('owner/Beta', 50, 1, [check('b', '項目B', 'ng'), check('c', '項目C')]),
  audit('owner/gamma', null, 0, [check('a', '項目A', 'unavailable')]),
])

describe('AuditMatrix', () => {
  it('derives the columns from the checks of all repositories, in order of first appearance', () => {
    expect(matrix().columns()).toEqual([
      { key: 'a', label: '項目A' }, { key: 'b', label: '項目B' }, { key: 'c', label: '項目C' },
    ])
  })

  it('has no columns and no rows when empty', () => {
    expect(new AuditMatrix([]).columns()).toEqual([])
    expect(new AuditMatrix([]).rows()).toEqual([])
  })

  it('returns every repository by default, and only those with issues on request', () => {
    expect(matrix().rows().map((r) => r.repo)).toEqual(['owner/alpha', 'owner/Beta', 'owner/gamma'])
    expect(matrix().rows({ onlyIssues: true }).map((r) => r.repo)).toEqual(['owner/Beta'])
  })

  it('searches the repository name case-insensitively by partial match', () => {
    expect(matrix().rows({ query: 'BETA' }).map((r) => r.repo)).toEqual(['owner/Beta'])
    expect(matrix().rows({ query: 'owner/' })).toHaveLength(3)
    expect(matrix().rows({ query: 'zzz' })).toEqual([])
  })

  it('averages only the repositories that could be audited, rounded', () => {
    expect(matrix().averageScore()).toBe(75)
    expect(new AuditMatrix([audit('o/a', 100, 0, []), audit('o/b', 51, 1, [])]).averageScore()).toBe(76)
  })

  it('has no average when no repository could be audited', () => {
    expect(new AuditMatrix([audit('o/a', null, 0, [])]).averageScore()).toBeNull()
    expect(new AuditMatrix([]).averageScore()).toBeNull()
  })

  it('is built from an API response', () => {
    const data: RepoAuditOut[] = [
      { repo_full_name: 'o/a', score: 10, issues: 1, checks: [check('a', '項目A', 'ng')], changes: [], audited_at: '' },
    ]
    const response: RepoAuditResponse = { total: 1, repos_with_issues: 1, data }
    expect(AuditMatrix.fromResponse(response).rows().map((r) => r.repo)).toEqual(['o/a'])
  })
})
