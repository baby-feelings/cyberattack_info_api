import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  githubLoginUrl, fetchScanStatus, exchangeAuthCode,
  fetchNotificationSettings, putNotificationSettings, deleteNotificationSettings, issueMcpToken,
  listMcpTokens, revokeMcpToken,
} from './auth'
import { UnauthorizedError } from './shared'

const BASE_URL = 'https://cyberattack-info-api.onrender.com'

function jsonResponse(body: unknown, init: { ok?: boolean; status?: number } = {}) {
  return {
    ok: init.ok ?? true,
    status: init.status ?? 200,
    json: () => Promise.resolve(body),
  } as Response
}

describe('api/auth', () => {
  let fetchMock: ReturnType<typeof vi.fn>

  beforeEach(() => {
    fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  describe('githubLoginUrl', () => {
    it('points at the backend /auth/github/login endpoint', () => {
      expect(githubLoginUrl()).toBe(`${BASE_URL}/auth/github/login`)
    })
  })

  describe('fetchScanStatus', () => {
    it('sends the Bearer token and returns the parsed status', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ username: 'octocat', status: 'done' }))
      const result = await fetchScanStatus('tok-123')
      expect(result.status).toBe('done')
      const [url, opts] = fetchMock.mock.calls[0]
      expect(url).toBe(`${BASE_URL}/auth/scan-status`)
      expect(opts.headers).toEqual({ Authorization: 'Bearer tok-123' })
    })

    it('throws UnauthorizedError specifically on 401', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 401 }))
      await expect(fetchScanStatus('bad-token')).rejects.toBeInstanceOf(UnauthorizedError)
    })

    it('throws a generic Error on other failures (not UnauthorizedError)', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 500 }))
      await expect(fetchScanStatus('tok')).rejects.toThrow('Scan status error 500')
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 500 }))
      await expect(fetchScanStatus('tok')).rejects.not.toBeInstanceOf(UnauthorizedError)
    })
  })

  describe('exchangeAuthCode', () => {
    it('POSTs the code as JSON and returns the token/username', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ token: 'tok-abc', username: 'octocat' }))
      const result = await exchangeAuthCode('code-123')
      expect(result).toEqual({ token: 'tok-abc', username: 'octocat' })
      const [url, opts] = fetchMock.mock.calls[0]
      expect(url).toBe(`${BASE_URL}/auth/exchange`)
      expect(opts.method).toBe('POST')
      expect(JSON.parse(opts.body)).toEqual({ code: 'code-123' })
    })

    it('throws when the code is invalid, expired, or already used', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 400 }))
      await expect(exchangeAuthCode('bad-code')).rejects.toThrow('Exchange error 400')
    })
  })

  describe('fetchNotificationSettings', () => {
    it('sends the Bearer token and returns the parsed settings', async () => {
      fetchMock.mockResolvedValueOnce(
        jsonResponse({ slack_webhook_url: 'https://hooks.slack.com/x', notifications_enabled: true }),
      )
      const result = await fetchNotificationSettings('tok-123')
      expect(result.slack_webhook_url).toBe('https://hooks.slack.com/x')
      const [url, opts] = fetchMock.mock.calls[0]
      expect(url).toBe(`${BASE_URL}/auth/notification-settings`)
      expect(opts.headers).toEqual({ Authorization: 'Bearer tok-123' })
    })

    it('throws UnauthorizedError specifically on 401', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 401 }))
      await expect(fetchNotificationSettings('bad-token')).rejects.toBeInstanceOf(UnauthorizedError)
    })
  })

  describe('putNotificationSettings', () => {
    it('PUTs the webhook URL as JSON and returns the saved settings', async () => {
      fetchMock.mockResolvedValueOnce(
        jsonResponse({ slack_webhook_url: 'https://hooks.slack.com/x', notifications_enabled: true }),
      )
      const result = await putNotificationSettings('tok-123', 'https://hooks.slack.com/x')
      expect(result.slack_webhook_url).toBe('https://hooks.slack.com/x')
      const [url, opts] = fetchMock.mock.calls[0]
      expect(url).toBe(`${BASE_URL}/auth/notification-settings`)
      expect(opts.method).toBe('PUT')
      expect(opts.headers.Authorization).toBe('Bearer tok-123')
      expect(JSON.parse(opts.body)).toEqual({ slack_webhook_url: 'https://hooks.slack.com/x' })
    })

    it('surfaces the server error detail message on failure', async () => {
      fetchMock.mockResolvedValueOnce(
        jsonResponse({ detail: 'Invalid Slack webhook URL' }, { ok: false, status: 400 }),
      )
      await expect(putNotificationSettings('tok', 'https://evil.example.com')).rejects.toThrow(
        'Invalid Slack webhook URL',
      )
    })

    it('throws UnauthorizedError specifically on 401', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 401 }))
      await expect(
        putNotificationSettings('bad-token', 'https://hooks.slack.com/x'),
      ).rejects.toBeInstanceOf(UnauthorizedError)
    })
  })

  describe('deleteNotificationSettings', () => {
    it('DELETEs and returns the cleared settings', async () => {
      fetchMock.mockResolvedValueOnce(
        jsonResponse({ slack_webhook_url: null, notifications_enabled: true }),
      )
      const result = await deleteNotificationSettings('tok-123')
      expect(result.slack_webhook_url).toBeNull()
      const [url, opts] = fetchMock.mock.calls[0]
      expect(url).toBe(`${BASE_URL}/auth/notification-settings`)
      expect(opts.method).toBe('DELETE')
    })

    it('throws UnauthorizedError specifically on 401', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 401 }))
      await expect(deleteNotificationSettings('bad-token')).rejects.toBeInstanceOf(UnauthorizedError)
    })
  })

  describe('issueMcpToken', () => {
    it('POSTs the selected days with the session token and returns the issued token', async () => {
      fetchMock.mockResolvedValueOnce(
        jsonResponse({ token: 'mcp-1', username: 'octocat', id: 't1', expires_at: '2026-10-17T00:00:00+00:00' }),
      )
      const result = await issueMcpToken('tok-123', 7)
      expect(result.token).toBe('mcp-1')
      const [url, opts] = fetchMock.mock.calls[0]
      expect(url).toBe(`${BASE_URL}/auth/mcp-token`)
      expect(opts.method).toBe('POST')
      expect(opts.headers.Authorization).toBe('Bearer tok-123')
      expect(JSON.parse(opts.body)).toEqual({ days: 7 })
    })

    it('defaults to 30 days', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ token: 'm' }))
      await issueMcpToken('tok')
      expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ days: 30 })
    })

    it('throws UnauthorizedError on 401', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 401 }))
      await expect(issueMcpToken('bad')).rejects.toBeInstanceOf(UnauthorizedError)
    })

    it('passes the server explanation through on 409 (limit reached)', async () => {
      fetchMock.mockResolvedValueOnce(
        jsonResponse({ detail: '上限に達しています' }, { ok: false, status: 409 }),
      )
      await expect(issueMcpToken('tok')).rejects.toThrow('上限に達しています')
    })

    it('falls back to a status message on 409 without a body', async () => {
      fetchMock.mockResolvedValueOnce({
        ok: false, status: 409, json: () => Promise.reject(new Error('no body')),
      } as Response)
      await expect(issueMcpToken('tok')).rejects.toThrow('MCP token error 409')
    })

    it('does not leak server details on other failures', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ detail: 'boom' }, { ok: false, status: 500 }))
      await expect(issueMcpToken('tok')).rejects.toThrow('MCP token error 500')
    })
  })

  describe('listMcpTokens', () => {
    it('GETs the token list with the session token', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ tokens: [{ id: 't1', status: 'active' }] }))
      const result = await listMcpTokens('tok-123')
      expect(result).toEqual([{ id: 't1', status: 'active' }])
      const [url, opts] = fetchMock.mock.calls[0]
      expect(url).toBe(`${BASE_URL}/auth/mcp-tokens`)
      expect(opts.headers.Authorization).toBe('Bearer tok-123')
    })

    it('throws UnauthorizedError on 401 and a generic error otherwise', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 401 }))
      await expect(listMcpTokens('bad')).rejects.toBeInstanceOf(UnauthorizedError)
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 500 }))
      await expect(listMcpTokens('tok')).rejects.toThrow('MCP token list error 500')
    })
  })

  describe('revokeMcpToken', () => {
    it('DELETEs the token by id with the session token', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ id: 't 1', revoked: true }))
      await revokeMcpToken('tok-123', 't 1')
      const [url, opts] = fetchMock.mock.calls[0]
      expect(url).toBe(`${BASE_URL}/auth/mcp-tokens/t%201`)
      expect(opts.method).toBe('DELETE')
      expect(opts.headers.Authorization).toBe('Bearer tok-123')
    })

    it('throws UnauthorizedError on 401 and a generic error otherwise', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 401 }))
      await expect(revokeMcpToken('bad', 't1')).rejects.toBeInstanceOf(UnauthorizedError)
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 404 }))
      await expect(revokeMcpToken('tok', 't1')).rejects.toThrow('MCP token revoke error 404')
    })
  })
})
