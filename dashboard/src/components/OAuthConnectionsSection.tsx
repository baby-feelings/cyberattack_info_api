import { useCallback, useEffect, useState } from 'react'
import { disconnectOAuthClient, listOAuthConnections, type OAuthConnection } from '../api/auth'
import { UnauthorizedError } from '../api/shared'

// ISO 8601 文字列の日付部分（YYYY-MM-DD）
const dateOf = (iso: string) => iso.slice(0, 10)

// OAuth 接続欄: Claude Code などを OAuth（MCP 標準の認可フロー）で接続すると表示される。
// クライアント名は登録時の自己申告（未確認）のため、React のテキストとして出す（HTML として解釈しない）。
// 「接続解除」でそのクライアントへの許可（リフレッシュトークンと発行済みトークン）をすべて取り消す。
// 接続が1件も無いときは何も表示しない（OAuth を使っていない間は画面を増やさない）。
export function OAuthConnectionsSection({ authToken }: { authToken: string }) {
  const [connections, setConnections] = useState<OAuthConnection[]>([])
  const [error, setError] = useState<string | null>(null)

  const reload = useCallback(async () => {
    try {
      setConnections(await listOAuthConnections(authToken))
    } catch (err) {
      setError(
        err instanceof UnauthorizedError
          ? 'ログインの有効期限が切れました。再ログインしてください'
          : 'OAuth 接続の取得に失敗しました',
      )
    }
  }, [authToken])

  useEffect(() => {
    // 非同期の取得完了後にstateを更新する（effect内で同期的にsetStateしない）
    const timer = setTimeout(() => { void reload() }, 0)
    return () => clearTimeout(timer)
  }, [reload])

  async function handleDisconnect(conn: OAuthConnection) {
    if (!window.confirm(
      `「${conn.client_name}」との接続を解除しますか？以後は再度の認可が必要になります。`,
    )) return
    setError(null)
    try {
      await disconnectOAuthClient(authToken, conn.client_id)
      await reload()
    } catch {
      setError('接続の解除に失敗しました')
    }
  }

  if (connections.length === 0 && !error) return null

  return (
    <div className="pt-5 border-t border-slate-800 space-y-3">
      <div>
        <h3 className="text-sm font-medium text-slate-200 mb-1">OAuth で接続中のアプリ</h3>
        <p className="text-xs text-slate-500 leading-relaxed">
          OAuth で許可したアプリ（Claude Code など）です。アプリ名は登録時の自己申告で、確認されたものではありません。
          心当たりがない接続は解除してください。
        </p>
      </div>

      {error && <p className="text-xs text-rose-400">{error}</p>}

      {connections.length > 0 && (
        <ul className="space-y-1.5" aria-label="OAuthで接続中のアプリ">
          {connections.map((c) => (
            <li
              key={c.client_id}
              className="flex items-center justify-between gap-2 px-3 py-2 rounded-lg bg-slate-800/60 border border-slate-800"
            >
              <div className="min-w-0 text-xs leading-relaxed">
                <div className="text-slate-200 truncate">{c.client_name}</div>
                <div className="text-slate-500">
                  {c.connected_at ? `接続 ${dateOf(c.connected_at)}` : ''}
                  {' '}・{c.last_used_at ? `最終使用 ${dateOf(c.last_used_at)}` : '未使用'}
                  {c.expires_at ? ` ・許可の期限 ${dateOf(c.expires_at)}` : ''}
                </div>
              </div>
              <button
                onClick={() => void handleDisconnect(c)}
                aria-label={`${c.client_name} の接続を解除する`}
                className="shrink-0 px-2.5 py-1 rounded-md border border-slate-700 hover:border-rose-500/60 hover:text-rose-400 text-slate-400 text-xs transition-colors"
              >
                接続解除
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
