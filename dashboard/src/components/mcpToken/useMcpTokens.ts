import { useCallback, useEffect, useState } from 'react'
import {
  issueMcpToken, listMcpTokens, revokeMcpToken,
  type McpTokenDays, type McpTokenInfo, type McpTokenResponse,
} from '../../api/auth'
import { BASE_URL, UnauthorizedError } from '../../api/shared'
import { MCP_TOKEN_TEXT as T } from './mcpTokenConfig'

// MCPトークンの発行・一覧・失効の状態と操作（画面は、これを読んで描くだけ）
export function useMcpTokens(authToken: string) {
  const [days, setDays] = useState<McpTokenDays>(30)
  const [issued, setIssued] = useState<McpTokenResponse | null>(null)
  const [tokens, setTokens] = useState<McpTokenInfo[]>([])
  const [issuing, setIssuing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  // 失効済み・期限切れは一覧が長くなるため、標準では隠す（有効なトークンだけを見せる）
  const [showInactive, setShowInactive] = useState(false)
  const inactiveCount = tokens.filter((t) => t.status !== 'active').length
  const visibleTokens = showInactive ? tokens : tokens.filter((t) => t.status === 'active')

  const reload = useCallback(async () => {
    try {
      setTokens(await listMcpTokens(authToken))
    } catch (err) {
      setError(err instanceof UnauthorizedError ? T.errors.sessionExpired : T.errors.listFailed)
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
          ? T.errors.sessionExpired
          // 上限超過（409）などは、サーバーの説明文をそのまま表示する
          : err instanceof Error && !err.message.startsWith('MCP token error')
            ? err.message
            : T.errors.issueFailed,
      )
    } finally {
      setIssuing(false)
    }
  }

  async function handleRevoke(token: McpTokenInfo) {
    if (!window.confirm(T.confirmRevoke)) return
    setError(null)
    try {
      await revokeMcpToken(authToken, token.id)
      // 表示中のコマンドが失効したトークンのものなら、誤って使わないよう消す
      if (issued?.id === token.id) setIssued(null)
      await reload()
    } catch {
      setError(T.errors.revokeFailed)
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
      setError(T.errors.copyFailed)
    }
  }

  return {
    days, setDays, issued, issuing, error, copied, command,
    showInactive, toggleInactive: () => setShowInactive((v) => !v),
    inactiveCount, visibleTokens, hasTokens: tokens.length > 0,
    handleIssue, handleRevoke, handleCopy,
  }
}
