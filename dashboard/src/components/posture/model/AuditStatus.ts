// 設定の監査の、点検項目の状態。API の文字列を、安全に読み取る値オブジェクト。

// API（`/api/repo-audit`）が返す状態の値
export type AuditStatusKind = 'ok' | 'ng' | 'unavailable' | 'not_enforceable'

const KNOWN_KINDS: readonly AuditStatusKind[] = ['ok', 'ng', 'unavailable', 'not_enforceable']

// スコアに数える状態（バックエンドの `_SCORED` と同じ）。取得不可・強制できないは、数えない
const SCORED_KINDS: readonly AuditStatusKind[] = ['ok', 'ng']

export class AuditStatus {
  readonly kind: AuditStatusKind

  private constructor(kind: AuditStatusKind) {
    this.kind = kind
  }

  // 未知の値・空文字は、「取得不可」として扱う（画面を壊さない）
  static from(raw: string): AuditStatus {
    const known = KNOWN_KINDS.find((kind) => kind === raw)
    return new AuditStatus(known ?? 'unavailable')
  }

  isScored(): boolean {
    return SCORED_KINDS.includes(this.kind)
  }
}
