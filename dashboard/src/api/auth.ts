// DEPSCAN ダッシュボード用 GitHub ログイン（Issue #107）関連の API クライアント。

import { BASE_URL, UnauthorizedError } from './shared'

export interface ScanStatusResponse {
  username: string
  status: 'not_started' | 'running' | 'done' | 'error'
  repos_scanned?: number
  started_at?: string
  finished_at?: string | null
  error_message?: string | null
}

// GitHub OAuth 認可画面へのリダイレクト先 URL（そのまま <a href> に指定する）
export function githubLoginUrl(): string {
  return `${BASE_URL}/auth/github/login`
}

// ログイン中ユーザーのオンデマンドスキャン進捗を取得する
export async function fetchScanStatus(authToken: string): Promise<ScanStatusResponse> {
  const res = await fetch(`${BASE_URL}/auth/scan-status`, {
    headers: { Authorization: `Bearer ${authToken}` },
  })
  if (res.status === 401) throw new UnauthorizedError('Session token is invalid or expired')
  if (!res.ok) throw new Error(`Scan status error ${res.status}`)
  return res.json()
}

export interface ExchangeResponse {
  token: string
  username: string
}

// OAuthコールバックのリダイレクトURLに載る、数十秒で失効し一度しか使えない
// 交換コードをセッションJWTと交換する（RFC 9700対策：JWT自体はURLに載らない）
export async function exchangeAuthCode(code: string): Promise<ExchangeResponse> {
  const res = await fetch(`${BASE_URL}/auth/exchange`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  })
  if (!res.ok) throw new Error(`Exchange error ${res.status}`)
  return res.json()
}

// ── Slack Webhook 通知登録（Issue #227） ─────────────────────────

export interface NotificationSettings {
  slack_webhook_url: string | null
  notifications_enabled: boolean
}

export async function fetchNotificationSettings(authToken: string): Promise<NotificationSettings> {
  const res = await fetch(`${BASE_URL}/auth/notification-settings`, {
    headers: { Authorization: `Bearer ${authToken}` },
  })
  if (res.status === 401) throw new UnauthorizedError('Session token is invalid or expired')
  if (!res.ok) throw new Error(`Notification settings error ${res.status}`)
  return res.json()
}

// Webhook登録は必ずテスト送信を伴うため、URL形式不備・送信失敗はメッセージ付きの
// エラーとして呼び出し側（設定画面）へ伝える
export async function putNotificationSettings(
  authToken: string, slackWebhookUrl: string,
): Promise<NotificationSettings> {
  const res = await fetch(`${BASE_URL}/auth/notification-settings`, {
    method: 'PUT',
    headers: { Authorization: `Bearer ${authToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ slack_webhook_url: slackWebhookUrl }),
  })
  if (res.status === 401) throw new UnauthorizedError('Session token is invalid or expired')
  if (!res.ok) {
    const body = await res.json().catch(() => null)
    throw new Error(body?.detail || `Notification settings error ${res.status}`)
  }
  return res.json()
}

export async function deleteNotificationSettings(authToken: string): Promise<NotificationSettings> {
  const res = await fetch(`${BASE_URL}/auth/notification-settings`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${authToken}` },
  })
  if (res.status === 401) throw new UnauthorizedError('Session token is invalid or expired')
  if (!res.ok) throw new Error(`Notification settings error ${res.status}`)
  return res.json()
}

// ── MCPアクセストークンの発行・一覧・失効 ──────────────────────────

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
// 有効なトークンが上限（10個）に達していると409（サーバーの説明文をそのまま投げる）
export async function issueMcpToken(
  authToken: string, days: McpTokenDays = 30,
): Promise<McpTokenResponse> {
  const res = await fetch(`${BASE_URL}/auth/mcp-token`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${authToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ days }),
  })
  if (res.status === 401) throw new UnauthorizedError('Session token is invalid or expired')
  if (res.status === 409) {
    // 上限超過はユーザーが対処できる（不要なトークンを失効する）ため、説明文をそのまま伝える
    const body = await res.json().catch(() => null)
    throw new Error(body?.detail || `MCP token error ${res.status}`)
  }
  if (!res.ok) throw new Error(`MCP token error ${res.status}`)
  return res.json()
}

// 自分のMCPトークンの一覧（新しい順）
export async function listMcpTokens(authToken: string): Promise<McpTokenInfo[]> {
  const res = await fetch(`${BASE_URL}/auth/mcp-tokens`, {
    headers: { Authorization: `Bearer ${authToken}` },
  })
  if (res.status === 401) throw new UnauthorizedError('Session token is invalid or expired')
  if (!res.ok) throw new Error(`MCP token list error ${res.status}`)
  return (await res.json()).tokens
}

// 自分のMCPトークンを個別に失効する（以後そのトークンでのMCP接続は401になる）
export async function revokeMcpToken(authToken: string, tokenId: string): Promise<void> {
  const res = await fetch(`${BASE_URL}/auth/mcp-tokens/${encodeURIComponent(tokenId)}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${authToken}` },
  })
  if (res.status === 401) throw new UnauthorizedError('Session token is invalid or expired')
  if (!res.ok) throw new Error(`MCP token revoke error ${res.status}`)
}
