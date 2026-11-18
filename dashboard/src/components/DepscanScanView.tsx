import { useEffect, useState } from 'react'
import { Loader2, AlertTriangle } from 'lucide-react'
import { fetchScanStatus, UnauthorizedError, type ScanStatusResponse } from '../api/client'
import type { GithubSession } from '../hooks/useGithubSession'
import { DepscanPanel } from './DepscanPanel'

const POLL_INTERVAL_MS = 4000

// DEPSCAN の検知画面。ログイン後、オンデマンドスキャンが完了する（またはエラーになる）まで、進捗をポーリングし、
// 完了後に DepscanPanel を表示する。ログイン・ログアウトは、呼び出し側（GitHub ログインのゲート）の役割。
// セッション失効（401）のときだけ、onSessionExpired を呼ぶ（呼び出し側がログアウト扱いにする）
export function DepscanScanView({ session, onSessionExpired }: {
  session: GithubSession
  onSessionExpired: () => void
}) {
  const [scanStatus, setScanStatus] = useState<ScanStatusResponse | null>(null)

  useEffect(() => {
    let cancelled = false
    let timer: ReturnType<typeof setTimeout>

    async function tick() {
      try {
        const status = await fetchScanStatus(session.token)
        if (cancelled) return
        setScanStatus(status)
        if (status.status === 'not_started' || status.status === 'running') {
          timer = setTimeout(tick, POLL_INTERVAL_MS)
        }
      } catch (e) {
        if (cancelled) return
        if (e instanceof UnauthorizedError) {
          // セッショントークン失効時のみ、ログアウト扱いにする
          onSessionExpired()
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
  }, [session.token, onSessionExpired])

  const isScanning = scanStatus === null
    || scanStatus.status === 'not_started'
    || scanStatus.status === 'running'

  return (
    <div className="flex flex-col gap-3">
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
