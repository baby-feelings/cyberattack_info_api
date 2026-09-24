import { useCallback, useEffect, useState } from 'react'
import { exchangeAuthCode } from '../api/client'

// localStorage のキー名は DEPSCAN 導入時から変更しない。DEPSCAN/CODESCAN の
// 両タブがこのフックを通じて同じキーを参照することで、「どちらのタブで
// ログインしても両方閲覧可能」というセッション共有要件が自然に満たされる
// （Issue #219）。
const STORAGE_TOKEN_KEY = 'depscan_session_token'
const STORAGE_USER_KEY = 'depscan_session_user'

export interface GithubSession {
  token: string
  username: string
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

  // 初回マウント時のみ: OAuthコールバックからの復帰（交換コードをセッションJWTと
  // 交換する）、または localStorage の既存セッションを読み込む
  useEffect(() => {
    async function init() {
      const code = consumeCallbackCode()
      if (code) {
        try {
          const { token, username } = await exchangeAuthCode(code)
          storeSession({ token, username })
          setSession({ token, username })
        } catch {
          // コード期限切れ・二重使用等は未ログイン状態のまま（ログイン画面を再表示）
        }
      } else {
        const restored = readStoredSession()
        if (restored) setSession(restored)
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

  // ログアウトボタン押下時のみ呼ぶ（誤クリック防止の確認ダイアログを挟む）
  const handleLogoutClick = useCallback(() => {
    if (window.confirm('ログアウトしますか？')) {
      handleLogout()
    }
  }, [handleLogout])

  return { session, checked, handleLogout, handleLogoutClick }
}
