import { describe, it, expect } from 'vitest'
import type { GithubAlertOut } from '../../../api/client'
import { ALERT_SEVERITY_RANK } from '../postureConfig'
import { GithubAlert } from './GithubAlert'

const raw = (over: Partial<GithubAlertOut> = {}): GithubAlertOut => ({
  kind: 'code', repo_full_name: 'owner/app', number: 1, severity: 'HIGH', title: 'XSS',
  html_url: 'https://github.com/owner/app/security/code-scanning/1', detail: {},
  detected_at: '2026-11-18T00:00:00Z', resolved_at: null, ...over,
})

describe('GithubAlert', () => {
  it('links only to http(s) URLs', () => {
    expect(new GithubAlert(raw()).safeUrl()).toBe('https://github.com/owner/app/security/code-scanning/1')
    expect(new GithubAlert(raw({ html_url: 'javascript:alert(1)' })).safeUrl()).toBeNull()
    expect(new GithubAlert(raw({ html_url: 'data:text/html,x' })).safeUrl()).toBeNull()
    expect(new GithubAlert(raw({ html_url: '' })).safeUrl()).toBeNull()
  })

  it('ranks severities by the configured order, and an unknown or missing severity last', () => {
    const rank = (severity: string | null) => new GithubAlert(raw({ severity })).severityRank()
    expect(rank('CRITICAL')).toBe(ALERT_SEVERITY_RANK.CRITICAL)
    expect(rank('CRITICAL')).toBeLessThan(rank('HIGH'))
    expect(rank('LOW')).toBeLessThan(rank('WHATEVER'))
    expect(rank(null)).toBe(rank('WHATEVER'))
  })

  it('reads the detecting tool only when detail.tool is a string', () => {
    expect(new GithubAlert(raw({ detail: { tool: 'CodeQL' } })).tool()).toBe('CodeQL')
    expect(new GithubAlert(raw({ detail: { tool: 3 } })).tool()).toBeNull()
    expect(new GithubAlert(raw({ detail: {} })).tool()).toBeNull()
  })

  it('exposes the repository, title, number and kind', () => {
    const alert = new GithubAlert(raw({ kind: 'secret', title: 'AWS key', number: 7 }))
    expect(alert.repo).toBe('owner/app')
    expect(alert.title).toBe('AWS key')
    expect(alert.number).toBe(7)
    expect(alert.kind.kind).toBe('secret')
  })
})
