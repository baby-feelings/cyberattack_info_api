import { useCallback, useEffect, useRef, useState } from 'react'
import { exchangeAuthCode, refreshSession, UnauthorizedError } from '../api/client'

// localStorage のキー名は DEPSCAN 導入時から変更しない。DEPSCAN/CODESCAN の
// 両タブがこのフックを通じて同じキーを参照することで、「どちらのタブで
// ログインしても両方閲覧可能」というセッション共有要件が自然に満たされる
// （Issue #219）。
const STORAGE_TOKEN_KEY = 'depscan_session_token'
const STORAGE_USER_KEY = 'depscan_session_user'

// セッションを延長する最小の間隔。開いている間に何度もタブを切り替えても、API は1時間に1回だけ呼ぶ
const REFRESH_MIN_INTERVAL_MS = 60 * 60 * 1000
// 起動時の延長を待つ上限。サーバーが遅くても、画面の表示（ログイン状態の確認）を長く止めない
const INITIAL_REFRESH_TIMEOUT_MS = 3000

export interface GithubSession {
  token: string
  username: string
}

// 延長の結果: 新しいセッション / 'expired'（延長できない＝再ログインが必要）/ null（一時的な失敗）
type RenewResult = GithubSession | 'expired' | null

// 同じトークンでの延長を1回にまとめる。このフックは DEPSCAN・CODESCAN・設定の各画面が
// それぞれ使うため、同時に開くと同じ延長リクエストが重複するのを防ぐ
const inflightRenewals = new Map<string, Promise<RenewResult>>()

// セッションJWTの有効期間を延長する（スライディング更新、Issue #337）。
// 数時間・数日開かなかっただけでログインが切れないようにする。
// 401（期限切れ・ログインから上限日数超過）のときだけ 'expired' を返す。
// ネットワーク瞬断・サーバー一時エラーは null（現在のセッションを維持してよい）
function renewSession(current: GithubSession): Promise<RenewResult> {
  const pending = inflightRenewals.get(current.token)
  if (pending) return pending

  const request = (async (): Promise<RenewResult> => {
    try {
      const { token, username } = await refreshSession(current.token)
      return { token, username }
    } catch (e) {
      return e instanceof UnauthorizedError ? 'expired' : null
    }
  })().finally(() => inflightRenewals.delete(current.token))
  inflightRenewals.set(current.token, request)
  return request
}

// promise の完了、または ms ミリ秒の経過（null）のどちらか早いほうを返す
function resultWithin(promise: Promise<RenewResult>, ms: number): Promise<RenewResult> {
  return new Promise(resolve => {
    const timer = setTimeout(() => resolve(null), ms)
    void promise.then(result => {
      clearTimeout(timer)
      resolve(result)
    })
  })
}

function readStoredSession(): GithubSession | null {
  try {
    const token = localStorage.getItem(STORAGE_TOKEN_KEY)
    const username = localStorage.getItem(STORAGE_USER_KEY)
    return token && username ? { token, username } : null
  } catch {
    return null
  }
}

function storeSession(session: GithubSession): void {
  try {
    localStorage.setItem(STORAGE_TOKEN_KEY, session.token)
    localStorage.setItem(STORAGE_USER_KEY, session.username)
  } catch {
    // localStorageが使えない環境（プライベートモード等）ではセッションを保持しないだけで動作は継続する
  }
}

function clearStoredSession(): void {
  try {
    localStorage.removeItem(STORAGE_TOKEN_KEY)
    localStorage.removeItem(STORAGE_USER_KEY)
  } catch {
    // 上記と同様、失敗しても無視してよい
  }
}

// OAuthコールバックのリダイレクト先（/?depscan_code=...）から交換コードを読み取り、
// URLからは取り除く（リロード時の再送信を防ぐ）。コードは数十秒で失効し一度しか
// 使えないため、URLに残っていても実害は小さいが、念のため即座に取り除く。
function consumeCallbackCode(): string | null {
  const params = new URLSearchParams(window.location.search)
  const code = params.get('depscan_code')
  if (!code) return null

  params.delete('depscan_code')
  const newSearch = params.toString()
  const newUrl = window.location.pathname + (newSearch ? `?${newSearch}` : '') + window.location.hash
  window.history.replaceState({}, '', newUrl)

  return code
}

// GitHub ログインのセッション状態管理（DEPSCAN/CODESCAN 共通）。
//
// 元々 DepscanAuthGate.tsx に混在していた「セッション管理（ログイン状態・
// トークン・OAuthコールバック処理）」を、「DEPSCAN固有のオンデマンドスキャン
// 進捗ポーリングUI」から分離してここに切り出した（Separation of Concerns）。
// DepscanAuthGate・CodescanAuthGate の双方がこのフックを使う。
//
// @param onLogout ログアウト完了後（トークン失効時の自動ログアウト含む）に呼ばれる
//   任意のコールバック。DepscanAuthGate はこれを使ってスキャン進捗状態もクリアする
//   （CodescanAuthGate にはスキャン進捗の概念が無いため省略してよい）。
export function useGithubSession(onLogout?: () => void) {
  const [session, setSession] = useState<GithubSession | null>(null)
  const [checked, setChecked] = useState(false)
  // 直近にセッションを発行・延長した時刻（延長の頻度を抑えるため）
  const lastRefreshAt = useRef(0)

  // 初回マウント時のみ: OAuthコールバックからの復帰（交換コードをセッションJWTと
  // 交換する）、または localStorage の既存セッションを読み込む。
  // 既存セッションは、画面を表示する（session を確定し checked にする）前に延長しておく。
  // 表示後に新しいトークンへ差し替えると、各パネルが再取得（ちらつき・二重呼び出し）になるため
  useEffect(() => {
    async function init() {
      const code = consumeCallbackCode()
      if (code) {
        try {
          const { token, username } = await exchangeAuthCode(code)
          storeSession({ token, username })
          setSession({ token, username })
          // 発行したばかりのトークンなので、延長は不要
          lastRefreshAt.current = Date.now()
        } catch {
          // コード期限切れ・二重使用等は未ログイン状態のまま（ログイン画面を再表示）
        }
      } else {
        const restored = readStoredSession()
        if (restored) {
          lastRefreshAt.current = Date.now()
          const renewed = await resultWithin(renewSession(restored), INITIAL_REFRESH_TIMEOUT_MS)
          if (renewed === 'expired') {
            clearStoredSession()
          } else {
            if (renewed) storeSession(renewed)
            setSession(renewed ?? restored)
          }
        }
      }
      setChecked(true)
    }
    void init()
  }, [])

  // トークン失効時の自動ログアウト等、内部的な処理から呼ぶ（確認ダイアログなし）
  const handleLogout = useCallback(() => {
    clearStoredSession()
    setSession(null)
    onLogout?.()
  }, [onLogout])

  // タブに戻ったとき（前回の延長から1時間以上経っていれば）に、使用中のセッションを延長する。
  // 延長できなければログアウト扱いにし、一時的な失敗なら現在のセッションを維持する
  useEffect(() => {
    if (!session) return
    const maybeRefresh = () => {
      if (document.visibilityState !== 'visible') return
      if (Date.now() - lastRefreshAt.current < REFRESH_MIN_INTERVAL_MS) return
      lastRefreshAt.current = Date.now()
      void renewSession(session).then(renewed => {
        if (renewed === 'expired') {
          handleLogout()
        } else if (renewed) {
          storeSession(renewed)
          setSession(renewed)
        }
      })
    }
    document.addEventListener('visibilitychange', maybeRefresh)
    return () => document.removeEventListener('visibilitychange', maybeRefresh)
  }, [session, handleLogout])

  // ログアウトボタン押下時のみ呼ぶ（誤クリック防止の確認ダイアログを挟む）
  const handleLogoutClick = useCallback(() => {
    if (window.confirm('ログアウトしますか？')) {
      handleLogout()
    }
  }, [handleLogout])

  return { session, checked, handleLogout, handleLogoutClick }
}
