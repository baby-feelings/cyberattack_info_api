// MCPアクセストークンの発行・一覧・失効（貼り付け方式。OAuth 非対応のクライアント向け）。

import { authorizedFetch } from './request'

export type McpTokenStatus = 'active' | 'revoked' | 'expired'

// 台帳の1件（トークン本体は含まない）
export interface McpTokenInfo {
  id: string
  created_at: string | null
  expires_at: string
  revoked_at: string | null
  last_used_at: string | null
  status: McpTokenStatus
}

// 発行直後の応答だけにトークン本体が含まれる（再表示できない）
export interface McpTokenResponse extends McpTokenInfo {
  token: string
  username: string
}

// 選べる有効期限（日）。サーバー側の許可値（7/30/90）と一致させる
export const MCP_TOKEN_DAYS = [7, 30, 90] as const
export type McpTokenDays = (typeof MCP_TOKEN_DAYS)[number]

// ログイン中ユーザー本人専用のMCPトークンを発行する。このトークンで参照できる
// DEPSCAN/CODESCANは、発行したユーザー本人が所有するリポジトリのみに限られる。
// 有効なトークンが上限（10個）に達していると409。上限超過はユーザーが対処できる（不要な
// トークンを失効する）ため、サーバーの説明文をそのまま投げる
export async function issueMcpToken(
  authToken: string, days: McpTokenDays = 30,
): Promise<McpTokenResponse> {
  const res = await authorizedFetch('/auth/mcp-token', authToken, 'MCP token error', {
    method: 'POST',
    body: { days },
    explain: [409],
  })
  return res.json()
}

// 自分のMCPトークンの一覧（新しい順）
export async function listMcpTokens(authToken: string): Promise<McpTokenInfo[]> {
  const res = await authorizedFetch('/auth/mcp-tokens', authToken, 'MCP token list error')
  return (await res.json()).tokens
}

// 自分のMCPトークンを個別に失効する（以後そのトークンでのMCP接続は401になる）
export async function revokeMcpToken(authToken: string, tokenId: string): Promise<void> {
  await authorizedFetch(
    `/auth/mcp-tokens/${encodeURIComponent(tokenId)}`, authToken, 'MCP token revoke error',
    { method: 'DELETE' },
  )
}
