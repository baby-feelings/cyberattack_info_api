import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { fetchGithubAlerts, fetchRepoAudit, fetchSiteMonitor } from './posture'

// 成功レスポンス（`json()` だけを使う最小のモック）
function jsonResponse(body: unknown) {
  return { ok: true, status: 200, json: () => Promise.resolve(body) } as Response
}

describe('api/posture', () => {
  let fetchMock: ReturnType<typeof vi.fn>

  beforeEach(() => {
    fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  // 呼び出した URL（ベース URL を除いた、パスとクエリ）を返す
  function calledPath(): string {
    const [url] = fetchMock.mock.calls[0] as [string]
    return url.replace(/^https?:\/\/[^/]+/, '')
  }

  describe('fetchRepoAudit', () => {
    it('sends only_issues and operating when given', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, repos_with_issues: 0, data: [] }))
      await fetchRepoAudit({ onlyIssues: true, operating: 'active' })
      expect(calledPath()).toBe('/api/repo-audit?only_issues=true&operating=active')
    })

    it('omits the query when nothing is given, and omits operating=all', async () => {
      fetchMock.mockResolvedValue(jsonResponse({ total: 0, repos_with_issues: 0, data: [] }))
      await fetchRepoAudit({})
      expect(calledPath()).toBe('/api/repo-audit')
      fetchMock.mockClear()
      await fetchRepoAudit({ operating: 'all' })
      expect(calledPath()).toBe('/api/repo-audit')
    })

    it('sends the session token as a Bearer header instead of the API key', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, repos_with_issues: 0, data: [] }))
      await fetchRepoAudit({ authToken: 'session-token' })
      const [, init] = fetchMock.mock.calls[0] as [string, RequestInit]
      expect(init.headers).toEqual({ Authorization: 'Bearer session-token' })
    })
  })

  describe('fetchGithubAlerts', () => {
    it('sends kind and operating, and omits resolved unless it is true', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, data: [], unavailable: [] }))
      await fetchGithubAlerts({ kind: 'code', resolved: false, operating: 'inactive' })
      expect(calledPath()).toBe('/api/github-alerts?kind=code&operating=inactive')
    })

    it('sends repo and resolved=true when given', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, data: [], unavailable: [] }))
      await fetchGithubAlerts({ repo: 'owner/app', resolved: true })
      expect(calledPath()).toBe('/api/github-alerts?repo=owner%2Fapp&resolved=true')
    })
  })

  describe('fetchSiteMonitor', () => {
    it('sends only_issues and operating when given', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, sites_with_issues: 0, data: [] }))
      await fetchSiteMonitor({ onlyIssues: true, operating: 'active' })
      expect(calledPath()).toBe('/api/site-monitor?only_issues=true&operating=active')
    })

    it('throws when the API responds with an error status', async () => {
      fetchMock.mockResolvedValueOnce({ ok: false, status: 500 } as Response)
      await expect(fetchSiteMonitor({})).rejects.toThrow('API error 500')
    })
  })
})
