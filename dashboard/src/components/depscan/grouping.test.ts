import { describe, it, expect } from 'vitest'
import type { DependencyFindingOut } from '../../api/client'
import {
  severityRank, ownerOf, groupFindings, groupBestSeverityRank,
  groupLatestDetectedAt, groupIsResolved, groupFixedVersions, groupSeverityCounts,
  SEVERITY_CLS, SEVERITY_COLORS,
} from './grouping'

function makeFinding(overrides: Partial<DependencyFindingOut> = {}): DependencyFindingOut {
  return {
    repo_full_name: 'baby-feelings/baby_grow',
    ecosystem: 'PyPI',
    package_name: 'cryptography',
    installed_version: '3.4.7',
    osv_id: 'GHSA-test-0001',
    severity: 'HIGH',
    cvss_score: 7.5,
    summary: 'Test vulnerability',
    fixed_versions: ['3.4.8'],
    manifest_path: 'requirements.txt',
    detected_at: '2026-06-01T00:00:00Z',
    resolved_at: null,
    ...overrides,
  }
}

describe('severityRank', () => {
  it('orders CRITICAL < HIGH < MEDIUM < LOW', () => {
    expect(severityRank('CRITICAL')).toBeLessThan(severityRank('HIGH'))
    expect(severityRank('HIGH')).toBeLessThan(severityRank('MEDIUM'))
    expect(severityRank('MEDIUM')).toBeLessThan(severityRank('LOW'))
  })

  it('ranks null/unknown severities last', () => {
    expect(severityRank(null)).toBeGreaterThan(severityRank('LOW'))
    expect(severityRank('UNKNOWN')).toBeGreaterThan(severityRank('LOW'))
  })
})

describe('ownerOf', () => {
  it('extracts the owner segment from "owner/repo"', () => {
    expect(ownerOf('baby-feelings/baby_grow')).toBe('baby-feelings')
  })

  it('returns the input unchanged when there is no slash', () => {
    expect(ownerOf('no-slash')).toBe('no-slash')
  })
})

describe('groupFindings', () => {
  it('groups findings by repo+package+version', () => {
    const findings = [
      makeFinding({ osv_id: 'GHSA-1' }),
      makeFinding({ osv_id: 'GHSA-2' }),
      makeFinding({ package_name: 'requests', osv_id: 'GHSA-3' }),
    ]
    const groups = groupFindings(findings)
    expect(groups).toHaveLength(2)
    const cryptoGroup = groups.find(g => g.package_name === 'cryptography')
    expect(cryptoGroup?.findings).toHaveLength(2)
  })

  it('returns an empty array for empty input', () => {
    expect(groupFindings([])).toEqual([])
  })
})

describe('groupBestSeverityRank', () => {
  it('returns the rank of the most severe finding in the group', () => {
    const group = groupFindings([
      makeFinding({ osv_id: 'GHSA-1', severity: 'LOW' }),
      makeFinding({ osv_id: 'GHSA-2', severity: 'CRITICAL' }),
    ])[0]
    expect(groupBestSeverityRank(group)).toBe(severityRank('CRITICAL'))
  })
})

describe('groupLatestDetectedAt', () => {
  it('returns the latest detected_at among findings', () => {
    const group = groupFindings([
      makeFinding({ osv_id: 'GHSA-1', detected_at: '2026-01-01T00:00:00Z' }),
      makeFinding({ osv_id: 'GHSA-2', detected_at: '2026-06-01T00:00:00Z' }),
    ])[0]
    expect(groupLatestDetectedAt(group)).toBe('2026-06-01T00:00:00Z')
  })
})

describe('groupIsResolved', () => {
  it('is true only when every finding in the group is resolved', () => {
    const resolvedGroup = groupFindings([
      makeFinding({ osv_id: 'GHSA-1', resolved_at: '2026-06-02T00:00:00Z' }),
    ])[0]
    expect(groupIsResolved(resolvedGroup)).toBe(true)

    const mixedGroup = groupFindings([
      makeFinding({ osv_id: 'GHSA-1', resolved_at: '2026-06-02T00:00:00Z' }),
      makeFinding({ osv_id: 'GHSA-2', resolved_at: null }),
    ])[0]
    expect(groupIsResolved(mixedGroup)).toBe(false)
  })
})

describe('groupFixedVersions', () => {
  it('collects and sorts unique fixed versions across findings', () => {
    const group = groupFindings([
      makeFinding({ osv_id: 'GHSA-1', fixed_versions: ['3.4.8', '3.5.0'] }),
      makeFinding({ osv_id: 'GHSA-2', fixed_versions: ['3.4.8'] }),
    ])[0]
    expect(groupFixedVersions(group)).toEqual(['3.4.8', '3.5.0'])
  })

  it('returns an empty array when no fixed versions are provided', () => {
    const group = groupFindings([makeFinding({ fixed_versions: [] })])[0]
    expect(groupFixedVersions(group)).toEqual([])
  })
})

describe('groupSeverityCounts', () => {
  it('counts findings per severity, sorted by severity rank', () => {
    const group = groupFindings([
      makeFinding({ osv_id: 'GHSA-1', severity: 'LOW' }),
      makeFinding({ osv_id: 'GHSA-2', severity: 'CRITICAL' }),
      makeFinding({ osv_id: 'GHSA-3', severity: 'CRITICAL' }),
    ])[0]
    expect(groupSeverityCounts(group)).toEqual([
      ['CRITICAL', 2],
      ['LOW', 1],
    ])
  })

  it('treats a null severity as the "N/A" bucket', () => {
    const group = groupFindings([makeFinding({ severity: null })])[0]
    expect(groupSeverityCounts(group)).toEqual([['N/A', 1]])
  })
})

describe('style maps', () => {
  it('define a class/color for every known severity', () => {
    for (const sev of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
      expect(SEVERITY_CLS[sev]).toBeTruthy()
      expect(SEVERITY_COLORS[sev]).toBeTruthy()
    }
    expect(SEVERITY_COLORS['N/A']).toBeTruthy()
  })
})
