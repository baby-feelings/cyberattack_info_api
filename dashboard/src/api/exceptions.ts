// 検知の例外（受容・誤検知・影響なし。Issue #403）関連の API クライアント。
//
// 登録・解除は、ログイン中のユーザー（セッショントークン）として行う。サーバーは、
// 本人所有のリポジトリの検知だけを受け付ける。

import { authorizedFetch } from './auth/request'

export type ExceptionStatus = 'accepted' | 'false_positive' | 'not_affected'

// 検知の一覧（DEPSCAN・CODESCAN）に埋め込まれる、有効な例外の要約
export interface FindingExceptionSummary {
  id: number
  status: ExceptionStatus
  reason: string
  expires_at: string | null
  approver: string
}

export interface ExceptionInput {
  kind: 'dependency' | 'code'
  repo_full_name: string
  // 検知の同一性キー（一覧の `exception_key`）
  finding_key: string
  status: ExceptionStatus
  reason: string
  // 期限（ISO 8601）。受容は必須
  expires_at: string | null
}

export const EXCEPTION_STATUS_LABELS: Record<ExceptionStatus, string> = {
  accepted: '受容',
  false_positive: '誤検知',
  not_affected: '影響なし',
}

const PATH = '/api/exceptions'
const LABEL = 'Exception error'

// 理由・期限の入力ミス（422）・対象の検知が無い（404）・他人のリポジトリ（403）は、
// サーバーの説明文をそのまま画面に出す（利用者が直せるため）
const EXPLAINED = [403, 404, 422] as const

export async function createException(authToken: string, input: ExceptionInput): Promise<void> {
  await authorizedFetch(PATH, authToken, LABEL, { method: 'POST', body: input, explain: EXPLAINED })
}

export async function revokeException(authToken: string, id: number): Promise<void> {
  await authorizedFetch(`${PATH}/${id}`, authToken, LABEL, { method: 'DELETE', explain: EXPLAINED })
}
