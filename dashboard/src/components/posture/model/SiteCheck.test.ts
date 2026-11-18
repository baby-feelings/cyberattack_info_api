import { describe, it, expect } from 'vitest'
import type { SiteCheckOut, SiteFindingOut } from '../../../api/client'
import { SiteCheck } from './SiteCheck'

const finding = (severity: string): SiteFindingOut => ({ rule: 'r', severity, message: 'm' })
const raw = (findings: SiteFindingOut[], over: Partial<SiteCheckOut> = {}): SiteCheckOut => ({
  url: 'https://x.example', source: 'homepage', repo_full_name: 'owner/app', tls_days_left: 30,
  issues: findings.filter((f) => f.severity !== 'INFO').length, findings, checked_at: '2026-11-18T00:00:00Z', ...over,
})

describe('SiteCheck', () => {
  it('reports the worst severity of the findings as the API gave them', () => {
    expect(new SiteCheck(raw([finding('WARNING'), finding('ERROR')])).worstSeverity()).toBe('ERROR')
    expect(new SiteCheck(raw([finding('INFO'), finding('WARNING')])).worstSeverity()).toBe('WARNING')
  })

  it('has no worst severity when there are only INFO findings or none', () => {
    expect(new SiteCheck(raw([finding('INFO')])).worstSeverity()).toBeNull()
    expect(new SiteCheck(raw([])).worstSeverity()).toBeNull()
  })

  it('keeps the issue count, TLS days and a missing repository', () => {
    const site = new SiteCheck(raw([finding('ERROR')], { tls_days_left: null, repo_full_name: null }))
    expect(site.issues).toBe(1)
    expect(site.tlsDaysLeft).toBeNull()
    expect(site.repo).toBeNull()
    expect(site.url).toBe('https://x.example')
  })
})
