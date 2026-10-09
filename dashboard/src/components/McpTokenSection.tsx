import { useCallback, useEffect, useState } from 'react'
import {
  issueMcpToken, listMcpTokens, revokeMcpToken, MCP_TOKEN_DAYS,
  type McpTokenDays, type McpTokenInfo, type McpTokenResponse,
} from '../api/auth'
import { BASE_URL, UnauthorizedError } from '../api/shared'

const STATUS_LABEL: Record<McpTokenInfo['status'], string> = {
  active: '有効', revoked: '失効済み', expired: '期限切れ',
}

// ISO 8601 文字列の日付部分（YYYY-MM-DD）
const dateOf = (iso: string) => iso.slice(0, 10)

// MCPトークン欄: AIエージェント（Claude Code等）からリモートMCPサーバー（/mcp）へ
// 接続するための、ログイン中ユーザー専用トークンを発行・一覧・失効する。
// トークン本体は発行時の1回だけ表示し（サーバーは保存しない）、自分が所有するリポジトリの
// DEPSCAN/CODESCANだけが見える。漏えいが疑われるトークンは一覧から個別に失効できる。
export function McpTokenSection({ authToken }: { authToken: string }) {
  const [days, setDays] = useState<McpTokenDays>(30)
  const [issued, setIssued] = useState<McpTokenResponse | null>(null)
  const [tokens, setTokens] = useState<McpTokenInfo[]>([])
  const [issuing, setIssuing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const reload = useCallback(async () => {
    try {
      setTokens(await listMcpTokens(authToken))
    } catch (err) {
      setError(
        err instanceof UnauthorizedError
          ? 'ログインの有効期限が切れました。再ログインしてください'
          : 'トークン一覧の取得に失敗しました',
      )
    }
  }, [authToken])

  useEffect(() => {
    // 非同期の取得完了後にstateを更新する（effect内で同期的にsetStateしない）
    const timer = setTimeout(() => { void reload() }, 0)
    return () => clearTimeout(timer)
  }, [reload])

  async function handleIssue() {
    setIssuing(true)
    setError(null)
    setCopied(false)
    try {
      setIssued(await issueMcpToken(authToken, days))
      await reload()
    } catch (err) {
      setError(
        err instanceof UnauthorizedError
          ? 'ログインの有効期限が切れました。再ログインしてください'
          // 上限超過（409）などは、サーバーの説明文をそのまま表示する
          : err instanceof Error && !err.message.startsWith('MCP token error')
            ? err.message
            : 'トークンの発行に失敗しました',
      )
    } finally {
      setIssuing(false)
    }
  }

  async function handleRevoke(token: McpTokenInfo) {
    if (!window.confirm('このトークンを失効しますか？以後このトークンでは接続できなくなります。')) return
    setError(null)
    try {
      await revokeMcpToken(authToken, token.id)
      // 表示中のコマンドが失効したトークンのものなら、誤って使わないよう消す
      if (issued?.id === token.id) setIssued(null)
      await reload()
    } catch {
      setError('トークンの失効に失敗しました')
    }
  }

  // Claude Code に登録するコマンド（トークンは Authorization ヘッダーで渡す）
  const command = issued
    ? `claude mcp add --transport http cyberattack-info ${BASE_URL}/mcp `
      + `--header "Authorization: Bearer ${issued.token}"`
    : ''

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(command)
      setCopied(true)
    } catch {
      setError('コピーに失敗しました。手動で選択してコピーしてください')
    }
  }

  return (
    <div className="space-y-3">
      <div>
        <h3 className="text-sm font-medium text-slate-200 mb-1">MCPトークン</h3>
        <p className="text-xs text-slate-500 leading-relaxed">
          AIエージェントからこのAPIをMCPサーバーとして使うためのトークンです。
          このトークンで参照できるDEPSCAN・CODESCANは、あなたが所有するリポジトリのみです。
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <label className="text-xs text-slate-500" htmlFor="mcp-token-days">有効期限</label>
        <select
          id="mcp-token-days"
          value={days}
          onChange={(e) => setDays(Number(e.target.value) as McpTokenDays)}
          className="px-2 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-xs text-slate-200 focus:outline-none focus:border-violet-500"
        >
          {MCP_TOKEN_DAYS.map((d) => <option key={d} value={d}>{d}日</option>)}
        </select>
        <button
          onClick={handleIssue}
          disabled={issuing}
          className="px-4 py-2 rounded-lg border border-slate-700 hover:border-violet-500/60 hover:text-violet-300 disabled:opacity-40 text-slate-300 text-sm font-medium transition-colors"
        >
          {issuing ? '発行中...' : 'MCPトークンを発行'}
        </button>
      </div>

      {error && <p className="text-xs text-rose-400">{error}</p>}

      {issued && (
        <div className="space-y-2">
          <label className="block text-xs text-slate-500" htmlFor="mcp-command">
            Claude Code に登録するコマンド
          </label>
          <textarea
            id="mcp-command"
            readOnly
            rows={4}
            value={command}
            onFocus={(e) => e.currentTarget.select()}
            className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-xs text-slate-200 font-mono resize-none focus:outline-none focus:border-violet-500"
          />
          <div className="flex items-center gap-3">
            <button
              onClick={handleCopy}
              className="px-3 py-1.5 rounded-lg bg-violet-600 hover:bg-violet-500 text-white text-xs font-medium transition-colors"
            >
              {copied ? 'コピーしました' : 'コピー'}
            </button>
            <span className="text-xs text-slate-500">
              有効期限: {dateOf(issued.expires_at)}
            </span>
          </div>
          <p className="text-xs text-amber-400/90 leading-relaxed">
            このトークンは再表示できません。他の人に共有しないでください
            （共有すると、その人があなたのリポジトリの検知結果を見られます）。
          </p>
        </div>
      )}

      {tokens.length > 0 && (
        <div>
          <h4 className="text-xs text-slate-500 mb-1.5">発行済みのトークン</h4>
          <ul className="space-y-1.5" aria-label="発行済みのMCPトークン">
            {tokens.map((t) => (
              <li
                key={t.id}
                className="flex items-center justify-between gap-2 px-3 py-2 rounded-lg bg-slate-800/60 border border-slate-800"
              >
                <div className="min-w-0 text-xs leading-relaxed">
                  <span className={t.status === 'active' ? 'text-emerald-400' : 'text-slate-500'}>
                    {STATUS_LABEL[t.status]}
                  </span>
                  <span className="text-slate-500">
                    {' '}・期限 {dateOf(t.expires_at)}
                    {' '}・{t.last_used_at ? `最終使用 ${dateOf(t.last_used_at)}` : '未使用'}
                  </span>
                </div>
                {t.status === 'active' && (
                  <button
                    onClick={() => void handleRevoke(t)}
                    aria-label={`トークン ${t.id.slice(0, 8)} を失効する`}
                    className="shrink-0 px-2.5 py-1 rounded-md border border-slate-700 hover:border-rose-500/60 hover:text-rose-400 text-slate-400 text-xs transition-colors"
                  >
                    失効
                  </button>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
