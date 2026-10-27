// API クライアントのテスト用: fetch のレスポンスの組み立て。

export const BASE_URL = 'http://localhost:8000'

export function jsonResponse(body: unknown, init: { ok?: boolean; status?: number } = {}) {
  return {
    ok: init.ok ?? true,
    status: init.status ?? 200,
    json: () => Promise.resolve(body),
  } as Response
}
