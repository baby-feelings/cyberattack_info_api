import { describe, it, expect } from 'vitest'
import { AuditStatus } from './AuditStatus'

describe('AuditStatus', () => {
  it.each(['ok', 'ng', 'unavailable', 'not_enforceable'] as const)('reads the known status %s as is', (raw) => {
    expect(AuditStatus.from(raw).kind).toBe(raw)
  })

  it('treats an unknown or empty status as unavailable, never throws', () => {
    expect(AuditStatus.from('foo').kind).toBe('unavailable')
    expect(AuditStatus.from('').kind).toBe('unavailable')
  })

  it('counts only ok and ng toward the score', () => {
    expect(AuditStatus.from('ok').isScored()).toBe(true)
    expect(AuditStatus.from('ng').isScored()).toBe(true)
    expect(AuditStatus.from('unavailable').isScored()).toBe(false)
    expect(AuditStatus.from('not_enforceable').isScored()).toBe(false)
    expect(AuditStatus.from('foo').isScored()).toBe(false)
  })
})
