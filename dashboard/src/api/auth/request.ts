// ログイン中ユーザー（セッショントークン）として本番 API を呼ぶ共通処理。
//
// 認証が必要な呼び出しは、どれも「Bearer ヘッダーを付ける → 401 なら UnauthorizedError →
// それ以外の失敗は Error」という同じ形をしていたため、ここに1か所で持つ（DRY）。
// 呼び出し側は、成功時のレスポンスの扱いと、エラーメッセージの接頭辞（errorLabel）だけを決める。

import { BASE_URL, UnauthorizedError } from '../shared'

export interface AuthorizedRequestOptions {
  method?: string
  // JSON として送る本文（指定すると Content-Type: application/json も付く）
  body?: unknown
  // サーバーの説明文（`detail`）をそのままエラーメッセージにするステータス。
  // 'any' なら失敗はすべて。ユーザーが対処できる失敗（上限超過・登録できない Webhook 等）だけに使う
  // （それ以外は、内部の詳細を画面に出さないため固定文言にする）
  explain?: 'any' | readonly number[]
}

export async function authorizedFetch(
  path: string, authToken: string, errorLabel: string, options: AuthorizedRequestOptions = {},
): Promise<Response> {
  const headers: Record<string, string> = { Authorization: `Bearer ${authToken}` }
  const init: RequestInit = { headers }
  if (options.method) init.method = options.method
  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json'
    init.body = JSON.stringify(options.body)
  }

  const res = await fetch(`${BASE_URL}${path}`, init)
  if (res.status === 401) throw new UnauthorizedError('Session token is invalid or expired')
  if (!res.ok) {
    const explain = options.explain
    if (explain === 'any' || (explain !== undefined && explain.includes(res.status))) {
      const body = await res.json().catch(() => null)
      throw new Error(body?.detail || `${errorLabel} ${res.status}`)
    }
    throw new Error(`${errorLabel} ${res.status}`)
  }
  return res
}
