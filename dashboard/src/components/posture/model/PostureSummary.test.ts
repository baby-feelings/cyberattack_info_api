import { describe, it, expect } from 'vitest'
import { AlertList } from './AlertList'
import { AuditMatrix } from './AuditMatrix'
import { PostureSummary } from './PostureSummary'
import { RepoAudit } from './RepoAudit'
import { SiteCheck } from './SiteCheck'

const alerts = AlertList.fromResponse({
  total: 2,
  data: [1, 2].map((n) => ({
    kind: 'code', repo_full_name: 'o/a', number: n, severity: 'HIGH', title: 't', html_url: 'https://x',
    detail: {}, detected_at: '', resolved_at: null,
  })),
  unavailable: [],
})
const audit = new AuditMatrix([
  new RepoAudit({ repo_full_name: 'o/a', score: 80, issues: 1, checks: [], changes: [], audited_at: '' }),
])
const sites = [1, 2].map((issues) => new SiteCheck({
  url: `https://s${issues}.example`, source: 'homepage', repo_full_name: null, tls_days_left: 9, issues,
  findings: [], checked_at: '',
}))

describe('PostureSummary', () => {
  it('summarizes the three sources', () => {
    const summary = new PostureSummary({ alerts, audit, sites })
    expect(summary.openAlerts()).toBe(2)
    expect(summary.auditRate()).toBe(80)
    expect(summary.siteIssues()).toBe(3)
  })

  it('reports a source that could not be fetched as null, which is not the same as 0', () => {
    const summary = new PostureSummary({ alerts: null, audit: null, sites: null })
    expect(summary.openAlerts()).toBeNull()
    expect(summary.auditRate()).toBeNull()
    expect(summary.siteIssues()).toBeNull()
  })

  it('names the sources that could not be fetched, in a fixed order', () => {
    expect(new PostureSummary({ alerts: null, audit, sites: null }).unknownSources()).toEqual(['alerts', 'sites'])
    expect(new PostureSummary({ alerts, audit: null, sites }).unknownSources()).toEqual(['audit'])
    expect(new PostureSummary({ alerts, audit, sites }).unknownSources()).toEqual([])
  })

  it('reports 0 when a source was fetched and is empty', () => {
    const summary = new PostureSummary({
      alerts: AlertList.fromResponse({ total: 0, data: [], unavailable: [] }), audit: new AuditMatrix([]), sites: [],
    })
    expect(summary.openAlerts()).toBe(0)
    expect(summary.siteIssues()).toBe(0)
    expect(summary.auditRate()).toBeNull()   // 点検できたリポジトリが無い＝達成率は出せない
  })
})
