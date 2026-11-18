import type { McpTokenInfo, McpTokenResponse } from '../../api/auth'
import { MCP_TOKEN_TEXT as T, STATUS_LABEL, dateOf } from './mcpTokenConfig'

// 発行直後に1回だけ出す、Claude Code に登録するコマンド（再表示はできない）
export function IssuedCommand({
  issued, command, copied, onCopy,
}: { issued: McpTokenResponse; command: string; copied: boolean; onCopy: () => void }) {
  return (
    <div className="space-y-2">
      <label className="block text-xs text-slate-500" htmlFor="mcp-command">{T.commandLabel}</label>
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
          onClick={onCopy}
          className="px-3 py-1.5 rounded-lg bg-violet-600 hover:bg-violet-500 text-white text-xs font-medium transition-colors"
        >
          {copied ? T.copied : T.copy}
        </button>
        <span className="text-xs text-slate-500">{T.expiresAt(dateOf(issued.expires_at))}</span>
      </div>
      <p className="text-xs text-amber-400/90 leading-relaxed">{T.warning}</p>
    </div>
  )
}

// 発行済みのトークンの一覧（有効なものだけ失効できる）
export function TokenList({
  tokens, inactiveCount, showInactive, onToggleInactive, onRevoke,
}: {
  tokens: McpTokenInfo[]
  inactiveCount: number
  showInactive: boolean
  onToggleInactive: () => void
  onRevoke: (token: McpTokenInfo) => void
}) {
  return (
    <div>
      <div className="flex items-center justify-between mb-1.5">
        <h4 className="text-xs text-slate-500">{T.issuedHeading}</h4>
        {inactiveCount > 0 && (
          <button
            onClick={onToggleInactive}
            aria-pressed={showInactive}
            className="text-xs text-slate-500 hover:text-slate-300 transition-colors"
          >
            {showInactive ? T.hideInactive : T.showInactive(inactiveCount)}
          </button>
        )}
      </div>
      <ul className="space-y-1.5" aria-label={T.listLabel}>
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
                {' '}・{T.expiryOf(dateOf(t.expires_at))}
                {' '}・{t.last_used_at ? T.lastUsed(dateOf(t.last_used_at)) : T.unused}
              </span>
            </div>
            {t.status === 'active' && (
              <button
                onClick={() => onRevoke(t)}
                aria-label={T.revokeLabel(t.id.slice(0, 8))}
                className="shrink-0 px-2.5 py-1 rounded-md border border-slate-700 hover:border-rose-500/60 hover:text-rose-400 text-slate-400 text-xs transition-colors"
              >
                {T.revoke}
              </button>
            )}
          </li>
        ))}
      </ul>
    </div>
  )
}
