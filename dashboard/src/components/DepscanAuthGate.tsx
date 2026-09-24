import { useEffect, useState } from 'react'
import { LogIn, LogOut, Loader2, AlertTriangle } from 'lucide-react'
import { fetchScanStatus, UnauthorizedError, githubLoginUrl, type ScanStatusResponse } from '../api/client'
import { useGithubSession } from '../hooks/useGithubSession'
import { DepscanPanel } from './DepscanPanel'

const POLL_INTERVAL_MS = 4000

export function DepscanAuthGate() {
  const [scanStatus, setScanStatus] = useState<ScanStatusResponse | null>(null)

  // セッション管理（ログイン状態・トークン・OAuthコールバック処理）は
  // DEPSCAN/CODESCAN 共通の useGithubSession に切り出してある（Issue #219）。
  // ログアウト時にはスキャン進捗表示もクリアする（DEPSCAN固有の関心事）
  const { session, checked, handleLogout, handleLogoutClick } = useGithubSession(
    () => setScanStatus(null),
  )

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
