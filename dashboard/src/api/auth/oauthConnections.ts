// OAuth（MCP）で接続中のクライアントの一覧と解除。

import { authorizedFetch } from './request'

// OAuth（MCP）で接続中のクライアント（Claude Code 等）。クライアント名は登録時の自己申告（未確認）
export interface OAuthConnection {
  client_id: string
  client_name: string
  connected_at: string | null
  last_refreshed_at: string | null
  last_used_at: string | null
  expires_at: string | null
}

// 自分が OAuth で許可したクライアントの一覧（他のユーザーのものは含まれない）
export async function listOAuthConnections(authToken: string): Promise<OAuthConnection[]> {
  const res = await authorizedFetch('/auth/oauth-connections', authToken, 'OAuth connections error')
  return (await res.json()).connections
}

// 接続を解除する（そのクライアントへの許可をすべて取り消す。以後は再認可が必要）
export async function disconnectOAuthClient(authToken: string, clientId: string): Promise<void> {
  await authorizedFetch(
    `/auth/oauth-connections/${encodeURIComponent(clientId)}`, authToken, 'OAuth disconnect error',
    { method: 'DELETE' },
  )
}
