import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  fetchNotificationSettings, putNotificationSettings, deleteNotificationSettings,
} from './notifications'
import { BASE_URL, jsonResponse } from '../../test/http'
import { UnauthorizedError } from '../shared'

describe('api/auth/notifications', () => {
  let fetchMock: ReturnType<typeof vi.fn>

  beforeEach(() => {
    fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
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

})
