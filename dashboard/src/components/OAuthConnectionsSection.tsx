import { useCallback, useEffect, useState } from 'react'
import { disconnectOAuthClient, listOAuthConnections, type OAuthConnection } from '../api/auth'
import { BASE_URL, UnauthorizedError } from '../api/shared'

// ISO 8601 文字列の日付部分（YYYY-MM-DD）
const dateOf = (iso: string) => iso.slice(0, 10)

// Claude Code に OAuth で登録するコマンド（トークンの貼り付けは不要。初回の接続時にブラウザで認可する）。
// 全プロジェクトで使えるよう user スコープで登録する。
const ADD_COMMAND = `claude mcp add --scope user --transport http cyberattack-info ${BASE_URL}/mcp`

// 接続だけして一度も使われない接続を、サーバーが自動で解除するまでの日数（app/mcp_server/oauth_cleanup.py）
const UNUSED_DAYS = 7

// OAuth 欄（推奨の接続方法）: Claude Code などを OAuth（MCP 標準の認可フロー）で接続する手順と、
// 接続中のアプリの一覧・解除。MCPトークン欄（OAuth 非対応のクライアント向け）より先に表示する。
// クライアント名は登録時の自己申告（未確認）のため、React のテキストとして出す（HTML として解釈しない）。
// 「接続解除」でそのクライアントへの許可（リフレッシュトークンと発行済みトークン）をすべて取り消す。
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

  return (
    <div className="pt-5 border-t border-slate-800 space-y-3">
      <div>
        <h3 className="text-sm font-medium text-slate-200 mb-1">OAuth で接続（推奨）</h3>
        <p className="text-xs text-slate-500 leading-relaxed">
          AIエージェント（Claude Code など）を、トークンの貼り付けなしで接続できます。
          次のコマンドで登録し、初回の接続時にブラウザで許可してください。
          アクセス権は自動で更新されます。
        </p>
      </div>

      <code
        aria-label="OAuth の登録コマンド"
        className="block px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-xs text-slate-200 font-mono break-all select-all"
      >
        {ADD_COMMAND}
      </code>

      {error && <p className="text-xs text-rose-400">{error}</p>}

      {connections.length > 0 && (
        <div>
          <h4 className="text-xs text-slate-500 mb-1">接続中のアプリ</h4>
          <p className="text-xs text-slate-500 leading-relaxed mb-1.5">
            アプリ名は登録時の自己申告で、確認されたものではありません。
            心当たりがない接続は解除してください。
            接続後に一度も使われない接続は、{UNUSED_DAYS}日後に自動で解除されます。
          </p>
          <ul className="space-y-1.5" aria-label="OAuthで接続中のアプリ">
            {connections.map((c) => (
              <li
                key={c.client_id}
                className="flex items-center justify-between gap-2 px-3 py-2 rounded-lg bg-slate-800/60 border border-slate-800"
              >
                <div className="min-w-0 text-xs leading-relaxed">
                  <div className="text-slate-200 break-words">{c.client_name}</div>
                  <div className="text-slate-500">
                    {c.connected_at ? `接続 ${dateOf(c.connected_at)}` : ''}
                    {' '}・
                    {c.last_used_at
                      ? `最終使用 ${dateOf(c.last_used_at)}`
                      : <span className="text-amber-400/90">未使用</span>}
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
        </div>
      )}
    </div>
  )
}
