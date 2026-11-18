import { describe, it, expect } from 'vitest'
import type { GithubAlertListResponse, GithubAlertOut } from '../../../api/client'
import { AlertList } from './AlertList'

const alert = (over: Partial<GithubAlertOut>): GithubAlertOut => ({
  kind: 'code', repo_full_name: 'owner/a', number: 1, severity: 'HIGH', title: 't', html_url: 'https://x',
  detail: {}, detected_at: '2026-11-18T00:00:00Z', resolved_at: null, ...over,
})

const response = (): GithubAlertListResponse => ({
  total: 4,
  data: [
    alert({ number: 1, kind: 'code', severity: 'LOW', repo_full_name: 'owner/b' }),
    alert({ number: 2, kind: 'secret', severity: 'CRITICAL', repo_full_name: 'owner/b' }),
    alert({ number: 3, kind: 'code', severity: 'CRITICAL', repo_full_name: 'owner/a' }),
    alert({ number: 4, kind: 'dependabot', severity: null, repo_full_name: 'owner/a' }),
  ],
  unavailable: [{ kind: 'secret', repo_full_name: 'owner/web', reason: 'HTTP 404' }],
})

describe('AlertList', () => {
  it('counts the alerts and keeps the unavailable sources with their reasons', () => {
    const list = AlertList.fromResponse(response())
    expect(list.count()).toBe(4)
    expect(list.unavailable).toEqual([{ kind: 'secret', repo_full_name: 'owner/web', reason: 'HTTP 404' }])
  })

  it('sorts by severity rank, then by repository name; a missing severity comes last', () => {
    const order = AlertList.fromResponse(response()).sorted().map((a) => a.number)
    expect(order).toEqual([3, 2, 1, 4])
  })

  it('filters by kind and by severity, without changing the original list', () => {
    const list = AlertList.fromResponse(response())
    expect(list.filter({ kind: 'code' }).count()).toBe(2)
    expect(list.filter({ severity: 'CRITICAL' }).count()).toBe(2)
    expect(list.filter({ kind: 'code', severity: 'CRITICAL' }).sorted().map((a) => a.number)).toEqual([3])
    expect(list.filter({ kind: null, severity: null }).count()).toBe(4)
    expect(list.count()).toBe(4)
  })

  it('counts the alerts by kind', () => {
    expect(AlertList.fromResponse(response()).countsByKind()).toEqual({ code: 2, secret: 1, dependabot: 1 })
  })

  it('is empty without alerts', () => {
    const list = AlertList.fromResponse({ total: 0, data: [], unavailable: [] })
    expect(list.count()).toBe(0)
    expect(list.sorted()).toEqual([])
    expect(list.countsByKind()).toEqual({})
  })
})
