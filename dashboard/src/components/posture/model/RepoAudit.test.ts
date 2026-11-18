import { describe, it, expect } from 'vitest'
import type { RepoAuditOut } from '../../../api/client'
import { RepoAudit } from './RepoAudit'

const raw: RepoAuditOut = {
  repo_full_name: 'owner/app', score: 80, issues: 1, changes: [], audited_at: '2026-11-18T00:00:00Z',
  checks: [
    { key: 'secret_scanning', label: 'シークレットスキャン', status: 'ok', weight: 3, detail: '有効', fix: '' },
    { key: 'branch_protection', label: 'ブランチ保護', status: 'ng', weight: 5, detail: '無効', fix: '設定で有効にする' },
  ],
}

describe('RepoAudit', () => {
  it('exposes the repository, score and issue count', () => {
    const audit = new RepoAudit(raw)
    expect(audit.repo).toBe('owner/app')
    expect(audit.score).toBe(80)
    expect(audit.issues).toBe(1)
  })

  it('finds a check by key, keeping the label and fix text that the API returned', () => {
    const check = new RepoAudit(raw).checkOf('branch_protection')
    expect(check?.label).toBe('ブランチ保護')
    expect(check?.status.kind).toBe('ng')
    expect(check?.fix).toBe('設定で有効にする')
  })

  it('returns undefined for a check the repository does not have', () => {
    expect(new RepoAudit(raw).checkOf('missing')).toBeUndefined()
  })

  it('reads an unknown status string as unavailable', () => {
    const odd = { ...raw, checks: [{ ...raw.checks[0], status: 'foo' }] }
    expect(new RepoAudit(odd).checkOf('secret_scanning')?.status.kind).toBe('unavailable')
  })
})
