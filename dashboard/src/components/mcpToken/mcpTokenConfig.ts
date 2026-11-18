import type { McpTokenInfo } from '../../api/auth'

// MCPトークン欄の、文言・表示名（画面は、これを読んで描くだけ）
export const STATUS_LABEL: Record<McpTokenInfo['status'], string> = {
  active: '有効', revoked: '失効済み', expired: '期限切れ',
}

// ISO 8601 文字列の日付部分（YYYY-MM-DD）
export const dateOf = (iso: string) => iso.slice(0, 10)

export const MCP_TOKEN_TEXT = {
  title: 'MCPトークン（OAuth 非対応のクライアント向け）',
  description:
    'OAuth に対応していないクライアントやスクリプトから、このAPIをMCPサーバーとして使うための'
    + 'トークンです。OAuth で接続できる場合は、上の OAuth を使ってください。'
    + 'このトークンで参照できるDEPSCAN・CODESCANは、あなたが所有するリポジトリのみです。'
    + 'Slack通知を登録すると、期限の3日前にお知らせします。',
  expiry: '有効期限',
  days: (d: number) => `${d}日`,
  issue: 'MCPトークンを発行',
  issuing: '発行中...',
  commandLabel: 'Claude Code に登録するコマンド',
  copy: 'コピー',
  copied: 'コピーしました',
  expiresAt: (date: string) => `有効期限: ${date}`,
  warning:
    'このトークンは再表示できません。他の人に共有しないでください'
    + '（共有すると、その人があなたのリポジトリの検知結果を見られます）。',
  issuedHeading: '発行済みのトークン',
  hideInactive: '失効済み・期限切れを隠す',
  showInactive: (count: number) => `失効済み・期限切れを表示（${count}件）`,
  listLabel: '発行済みのMCPトークン',
  expiryOf: (date: string) => `期限 ${date}`,
  lastUsed: (date: string) => `最終使用 ${date}`,
  unused: '未使用',
  revoke: '失効',
  revokeLabel: (shortId: string) => `トークン ${shortId} を失効する`,
  confirmRevoke: 'このトークンを失効しますか？以後このトークンでは接続できなくなります。',
  errors: {
    sessionExpired: 'ログインの有効期限が切れました。再ログインしてください',
    listFailed: 'トークン一覧の取得に失敗しました',
    issueFailed: 'トークンの発行に失敗しました',
    revokeFailed: 'トークンの失効に失敗しました',
    copyFailed: 'コピーに失敗しました。手動で選択してコピーしてください',
  },
} as const
