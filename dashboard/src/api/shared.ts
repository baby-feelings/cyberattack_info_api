// API クライアント共通部分: BASE_URL・認証ヘッダー付与・共通型・共通エラー型。
// KEV/OSV/JVN/DEPSCAN/DEPSOPS の各ドメインモジュール（kev.ts 等）から利用する。

export const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'https://cyberattack-info-api.onrender.com'
// このダッシュボードはブラウザに配信される公開資産のため、/admin/* も保護する
// 管理者用キーではなく、読み取り専用エンドポイント（KEV/OSV/JVN/crawler-logs）にしか
// 通用しない PUBLIC_API_KEY を埋め込む（バックエンド側は require_public_api_key で受理）。
export const API_KEY = import.meta.env.VITE_PUBLIC_API_KEY || ''

// セッショントークンが無効・期限切れの場合（401）を、それ以外のエラー
// （ネットワーク瞬断・サーバー一時エラー等）と区別するための専用エラー型。
// 呼び出し側は Unauthorized のみをログアウトのトリガーとして扱うべきで、
// それ以外の一時的なエラーでユーザーを毎回ログアウトさせてはならない。
export class UnauthorizedError extends Error {}

// authToken 指定時は X-API-KEY の代わりに、GitHub ログインのセッションJWTを
// Authorization: Bearer ヘッダーで送る（DEPSCAN のログインユーザー向けエンドポイント用。
// サーバー側で本人所有リポジトリに強制的に絞り込まれる）。
//
// クロスサイトCookie（バックエンドがRender・フロントエンドがVercelで異なるドメイン）は
// SafariのITP（Intelligent Tracking Prevention）により既定でブロックされ、iOSのPWAを
// 含むSafari系ブラウザでログインできない不具合が実際に発生したため、Bearerトークンを
// クライアント側（localStorage）で保持する方式にしている。
export async function apiFetch<T>(path: string, authToken?: string): Promise<T> {
  const headers: Record<string, string> = authToken
    ? { Authorization: `Bearer ${authToken}` }
    : { 'X-API-KEY': API_KEY }
  const res = await fetch(`${BASE_URL}${path}`, { headers })
  if (authToken && res.status === 401) {
    throw new UnauthorizedError('Session token is invalid or expired')
  }
  if (!res.ok) throw new Error(`API error ${res.status}: ${path}`)
  return res.json() as Promise<T>
}

// KEV/OSV/JVN 共通の月別統計エントリ
export interface MonthlyStat {
  year_month: string
  count: number
}
