import { useState } from 'react'
import { issueMcpToken, type McpTokenResponse } from '../api/auth'
import { BASE_URL, UnauthorizedError } from '../api/shared'

// MCPトークン発行欄: AIエージェント（Claude Code等）からリモートMCPサーバー（/mcp）へ
// 接続するための、ログイン中ユーザー専用トークンを発行する。トークンは発行時の1回だけ
// 表示し（サーバーは保存しない）、自分が所有するリポジトリのDEPSCAN/CODESCANだけが見える。
export function McpTokenSection({ authToken }: { authToken: string }) {
  const [issued, setIssued] = useState<McpTokenResponse | null>(null)
  const [issuing, setIssuing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  async function handleIssue() {
    setIssuing(true)
    setError(null)
    setCopied(false)
    try {
      setIssued(await issueMcpToken(authToken))
    } catch (err) {
      setError(
        err instanceof UnauthorizedError
          ? 'ログインの有効期限が切れました。再ログインしてください'
          : 'トークンの発行に失敗しました',
      )
    } finally {
      setIssuing(false)
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

      <button
        onClick={handleIssue}
        disabled={issuing}
        className="px-4 py-2 rounded-lg border border-slate-700 hover:border-violet-500/60 hover:text-violet-300 disabled:opacity-40 text-slate-300 text-sm font-medium transition-colors"
      >
        {issuing ? '発行中...' : issued ? 'トークンを再発行' : 'MCPトークンを発行'}
      </button>

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
              有効期限: {issued.expires_at.slice(0, 10)}
            </span>
          </div>
          <p className="text-xs text-amber-400/90 leading-relaxed">
            このトークンは再表示できません。他の人に共有しないでください
            （共有すると、その人があなたのリポジトリの検知結果を見られます）。
          </p>
        </div>
      )}
    </div>
  )
}
