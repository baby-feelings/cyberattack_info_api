// GitHub ログイン（Issue #107）とセッション: ログイン URL・交換コードの交換・セッションの延長・
// オンデマンドスキャンの進捗。

import { BASE_URL } from '../shared'
import { authorizedFetch } from './request'

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
  const res = await authorizedFetch('/auth/scan-status', authToken, 'Scan status error')
  return res.json()
}

export interface ExchangeResponse {
  token: string
  username: string
}

// OAuthコールバックのリダイレクトURLに載る、数十秒で失効し一度しか使えない
// 交換コードをセッションJWTと交換する（RFC 9700対策：JWT自体はURLに載らない）。
// まだログインしていない（セッションが無い）状態で呼ぶため、Bearer は付けない
export async function exchangeAuthCode(code: string): Promise<ExchangeResponse> {
  const res = await fetch(`${BASE_URL}/auth/exchange`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  })
  if (!res.ok) throw new Error(`Exchange error ${res.status}`)
  return res.json()
}

// セッションJWTの有効期間を延長した新しいJWTに交換する（スライディング更新、Issue #337）。
// 期限切れ・無効・ログインから上限日数を超えた場合は 401（UnauthorizedError）になる
export async function refreshSession(authToken: string): Promise<ExchangeResponse> {
  const res = await authorizedFetch('/auth/refresh', authToken, 'Session refresh error', {
    method: 'POST',
  })
  return res.json()
}
