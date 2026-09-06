import { useCallback, useEffect, useState } from 'react'
import { LogIn, LogOut, Loader2, AlertTriangle } from 'lucide-react'
import {
  githubLoginUrl, fetchScanStatus, logout as apiLogout, UnauthorizedError,
  type ScanStatusResponse,
} from '../api/client'
import { DepscanPanel } from './DepscanPanel'

// セッション本体（JWT）は HttpOnly Cookie で保持されブラウザJSからは読めないため、
// ここではUI即時表示用にユーザー名（非機微情報）だけをlocalStorageに保持する。
// ログイン状態の正とするのは常にサーバー側（fetchScanStatusが401を返すか否か）
const STORAGE_USER_KEY = 'depscan_session_user'
const POLL_INTERVAL_MS = 4000

function readStoredUsername(): string | null {
  try {
    return localStorage.getItem(STORAGE_USER_KEY)
  } catch {
    return null
  }
}

function storeUsername(username: string): void {
  try {
    localStorage.setItem(STORAGE_USER_KEY, username)
  } catch {
    // localStorageが使えない環境（プライベートモード等）では保持しないだけで動作は継続する
  }
}

function clearStoredUsername(): void {
  try {
    localStorage.removeItem(STORAGE_USER_KEY)
  } catch {
    // 上記と同様、失敗しても無視してよい
  }
}

// OAuthコールバックのリダイレクト先（/?depscan_user=...）からユーザー名を読み取り、
// URLからは取り除く（リロード時の再送信を防ぐ。セッションJWT自体はURLに載らない）
function consumeCallbackUsername(): string | null {
  const params = new URLSearchParams(window.location.search)
  const username = params.get('depscan_user')
  if (!username) return null

  params.delete('depscan_user')
  const newSearch = params.toString()
  const newUrl = window.location.pathname + (newSearch ? `?${newSearch}` : '') + window.location.hash
  window.history.replaceState({}, '', newUrl)

  return username
}

export function DepscanAuthGate() {
  const [username, setUsername] = useState<string | null>(null)
  const [checked, setChecked] = useState(false)
  const [scanStatus, setScanStatus] = useState<ScanStatusResponse | null>(null)

  // 初回マウント時のみ: OAuthコールバックからの復帰、または localStorage の既存表示名を読み込む
  // （実際のログイン有効性はポーリング側の fetchScanStatus が判定する）
  useEffect(() => {
    const restored = consumeCallbackUsername() ?? readStoredUsername()
    if (restored) {
      storeUsername(restored)
      setUsername(restored)
    }
    setChecked(true)
  }, [])

  // セッション失効時の自動ログアウト等、内部的な処理から呼ぶ（確認ダイアログなし）
  const handleLogout = useCallback(() => {
    clearStoredUsername()
    setUsername(null)
    setScanStatus(null)
  }, [])

  // ログアウトボタン押下時のみ呼ぶ（誤クリック防止の確認ダイアログを挟む）
  function handleLogoutClick() {
    if (window.confirm('ログアウトしますか？')) {
      void apiLogout().catch(() => {
        // サーバー側の削除に失敗してもローカルの表示はログアウト状態にする
      })
      handleLogout()
    }
  }

  // ログイン中は、オンデマンドスキャンが完了する（またはエラーになる）まで進捗をポーリングする
  useEffect(() => {
    if (!username) return
    let cancelled = false
    let timer: ReturnType<typeof setTimeout>

    async function tick() {
      try {
        const status = await fetchScanStatus()
        if (cancelled) return
        setScanStatus(status)
        if (status.status === 'not_started' || status.status === 'running') {
          timer = setTimeout(tick, POLL_INTERVAL_MS)
        }
      } catch (e) {
        if (cancelled) return
        if (e instanceof UnauthorizedError) {
          // セッションCookie失効時のみログアウト扱いにする
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
  }, [username, handleLogout])

  if (!checked) return null

  if (!username) {
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
          ログイン中: <span className="text-slate-300 font-medium">{username}</span>
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
            {username} のリポジトリをスキャン中です…しばらくお待ちください
          </p>
        </div>
      ) : (
        <DepscanPanel />
      )}
    </div>
  )
}
