import { MCP_TOKEN_DAYS, type McpTokenDays } from '../api/auth'
import { MCP_TOKEN_TEXT as T } from './mcpToken/mcpTokenConfig'
import { IssuedCommand, TokenList } from './mcpToken/McpTokenParts'
import { useMcpTokens } from './mcpToken/useMcpTokens'

// MCPトークン欄: AIエージェント（Claude Code等）からリモートMCPサーバー（/mcp）へ
// 接続するための、ログイン中ユーザー専用トークンを発行・一覧・失効する。
// トークン本体は発行時の1回だけ表示し（サーバーは保存しない）、自分が所有するリポジトリの
// DEPSCAN/CODESCANだけが見える。漏えいが疑われるトークンは一覧から個別に失効できる。
export function McpTokenSection({ authToken }: { authToken: string }) {
  const t = useMcpTokens(authToken)

  return (
    <div className="space-y-3">
      <div>
        <h3 className="text-sm font-medium text-slate-200 mb-1">{T.title}</h3>
        <p className="text-xs text-slate-500 leading-relaxed">{T.description}</p>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <label className="text-xs text-slate-500" htmlFor="mcp-token-days">{T.expiry}</label>
        <select
          id="mcp-token-days"
          value={t.days}
          onChange={(e) => t.setDays(Number(e.target.value) as McpTokenDays)}
          className="px-2 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-xs text-slate-200 focus:outline-none focus:border-violet-500"
        >
          {MCP_TOKEN_DAYS.map((d) => <option key={d} value={d}>{T.days(d)}</option>)}
        </select>
        <button
          onClick={t.handleIssue}
          disabled={t.issuing}
          className="px-4 py-2 rounded-lg border border-slate-700 hover:border-violet-500/60 hover:text-violet-300 disabled:opacity-40 text-slate-300 text-sm font-medium transition-colors"
        >
          {t.issuing ? T.issuing : T.issue}
        </button>
      </div>

      {t.error && <p className="text-xs text-rose-400">{t.error}</p>}

      {t.issued && (
        <IssuedCommand issued={t.issued} command={t.command} copied={t.copied} onCopy={t.handleCopy} />
      )}

      {t.hasTokens && (
        <TokenList
          tokens={t.visibleTokens} inactiveCount={t.inactiveCount}
          showInactive={t.showInactive} onToggleInactive={t.toggleInactive}
          onRevoke={(token) => void t.handleRevoke(token)}
        />
      )}
    </div>
  )
}
