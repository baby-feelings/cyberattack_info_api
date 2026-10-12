import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { listOAuthConnections, disconnectOAuthClient } from './oauthConnections'
import { BASE_URL, jsonResponse } from '../../test/http'
import { UnauthorizedError } from '../shared'

describe('api/auth/oauthConnections', () => {
  let fetchMock: ReturnType<typeof vi.fn>

  beforeEach(() => {
    fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  describe('listOAuthConnections', () => {
    it('GETs the connections with the session token and unwraps them', async () => {
      const connections = [{ client_id: 'c1', client_name: 'Claude Code' }]
      fetchMock.mockResolvedValueOnce(jsonResponse({ connections }))
      const result = await listOAuthConnections('tok-123')
      const [url, opts] = fetchMock.mock.calls[0]
      expect(url).toBe(`${BASE_URL}/auth/oauth-connections`)
      expect(opts.headers.Authorization).toBe('Bearer tok-123')
      expect(result).toEqual(connections)
    })

    it('throws UnauthorizedError on 401 and a generic error otherwise', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 401 }))
      await expect(listOAuthConnections('bad')).rejects.toBeInstanceOf(UnauthorizedError)
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 500 }))
      await expect(listOAuthConnections('tok')).rejects.toThrow('OAuth connections error 500')
    })
  })

  describe('disconnectOAuthClient', () => {
    it('DELETEs the client by (encoded) id with the session token', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ client_id: 'c 1', disconnected: true }))
      await disconnectOAuthClient('tok-123', 'c 1')
      const [url, opts] = fetchMock.mock.calls[0]
      expect(url).toBe(`${BASE_URL}/auth/oauth-connections/c%201`)
      expect(opts.method).toBe('DELETE')
      expect(opts.headers.Authorization).toBe('Bearer tok-123')
    })

    it('throws UnauthorizedError on 401 and a generic error otherwise', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 401 }))
      await expect(disconnectOAuthClient('bad', 'c1')).rejects.toBeInstanceOf(UnauthorizedError)
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 404 }))
      await expect(disconnectOAuthClient('tok', 'c1')).rejects.toThrow('OAuth disconnect error 404')
    })
  })
})
