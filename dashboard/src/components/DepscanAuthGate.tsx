import { useCallback, useEffect, useState } from 'react'
import { LogIn, LogOut, Loader2, AlertTriangle } from 'lucide-react'
import {
  githubLoginUrl, fetchScanStatus, exchangeAuthCode, UnauthorizedError,
  type ScanStatusResponse,
} from '../api/client'
import { DepscanPanel } from './DepscanPanel'

const STORAGE_TOKEN_KEY = 'depscan_session_token'
const STORAGE_USER_KEY = 'depscan_session_user'
const POLL_INTERVAL_MS = 4000

interface Session {
  token: string
  username: string
}

function readStoredSession(): Session | null {
  try {
    const token = localStorage.getItem(STORAGE_TOKEN_KEY)
    const username = localStorage.getItem(STORAGE_USER_KEY)
    return token && username ? { token, username } : null
  } catch {
    return null
  }
}

function storeSession(session: Session): void {
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

export function DepscanAuthGate() {
  const [session, setSession] = useState<Session | null>(null)
  const [checked, setChecked] = useState(false)
  const [scanStatus, setScanStatus] = useState<ScanStatusResponse | null>(null)

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
    setScanStatus(null)
  }, [])

  // ログアウトボタン押下時のみ呼ぶ（誤クリック防止の確認ダイアログを挟む）
  function handleLogoutClick() {
    if (window.confirm('ログアウトしますか？')) {
      handleLogout()
    }
  }

  // ログイン中は、オンデマンドスキャンが完了する（またはエラーになる）まで進捗をポーリングする
  useEffect(() => {
    if (!session) return
    let cancelled = false
    let timer: ReturnType<typeof setTimeout>

    async function tick() {
      try {
        const status = await fetchScanStatus(session!.token)
        if (cancelled) return
        setScanStatus(status)
        if (status.status === 'not_started' || status.status === 'running') {
          timer = setTimeout(tick, POLL_INTERVAL_MS)
        }
      } catch (e) {
        if (cancelled) return
        if (e instanceof UnauthorizedError) {
          // セッショントークン失効時のみログアウト扱いにする
          handleLogout()
          return
        }
        // ネットワーク瞬断・サーバー一時エラー等はログアウトせず、次回ポーリングで再試行する
        timer = setTimeout(tick, POLL_INTERVAL_MS)
      }
    }
    tick()

    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [session, handleLogout])

  if (!checked) return null

  if (!session) {
    return (
      <div className="rounded-2xl border border-slate-800 bg-slate-900 p-10 shadow-lg flex flex-col items-center gap-4 text-center">
        <LogIn size={32} className="text-slate-400" />
        <div>
          <p className="text-sm font-semibold text-white">GitHubアカウントでログインしてください</p>
          <p className="text-xs text-slate-500 mt-1">
            ログインすると、あなた自身が所有する GitHub リポジトリの依存ライブラリ脆弱性を表示します
          </p>
        </div>
        <a
          href={githubLoginUrl()}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-sm font-medium text-white transition-colors"
        >
          <LogIn size={16} />
          GitHubでログイン
        </a>
      </div>
    )
  }

  const isScanning = scanStatus === null
    || scanStatus.status === 'not_started'
    || scanStatus.status === 'running'

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between text-xs text-slate-500">
        <span>
          ログイン中: <span className="text-slate-300 font-medium">{session.username}</span>
        </span>
        <button
          onClick={handleLogoutClick}
          className="flex items-center gap-1 text-slate-500 hover:text-slate-300 transition-colors"
        >
          <LogOut size={12} />
          ログアウト
        </button>
      </div>

      {scanStatus?.status === 'error' && (
        <div className="flex items-center gap-2 text-xs text-red-400 bg-red-950/40 border border-red-800/50 rounded-lg px-3 py-2">
          <AlertTriangle size={13} className="shrink-0" />
          <span>スキャン中にエラーが発生しました: {scanStatus.error_message ?? '不明なエラー'}</span>
        </div>
      )}

      {isScanning ? (
        <div className="rounded-2xl border border-slate-800 bg-slate-900 p-10 shadow-lg flex flex-col items-center gap-3 text-center">
          <Loader2 size={24} className="text-violet-400 animate-spin" />
          <p className="text-sm text-slate-400">
            {session.username} のリポジトリをスキャン中です…しばらくお待ちください
          </p>
        </div>
      ) : (
        <DepscanPanel authToken={session.token} />
      )}
    </div>
  )
}
