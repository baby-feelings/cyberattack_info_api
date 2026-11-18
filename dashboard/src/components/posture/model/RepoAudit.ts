import type { RepoAuditOut } from '../../../api/client'
import { AuditCheck } from './AuditCheck'

// 1リポジトリの、設定の監査の結果。
export class RepoAudit {
  readonly repo: string
  // 点検できた項目の達成率（0〜100）。点検できなかったリポジトリは null
  readonly score: number | null
  // 不合格（ng）の項目数
  readonly issues: number
  readonly auditedAt: string
  readonly checks: readonly AuditCheck[]
  private readonly byKey: ReadonlyMap<string, AuditCheck>

  constructor(raw: RepoAuditOut) {
    this.repo = raw.repo_full_name
    this.score = raw.score
    this.issues = raw.issues
    this.auditedAt = raw.audited_at
    this.checks = raw.checks.map((check) => new AuditCheck(check))
    this.byKey = new Map(this.checks.map((check) => [check.key, check]))
  }

  // このリポジトリに、その項目が無ければ undefined（他のリポジトリにだけある項目）
  checkOf(key: string): AuditCheck | undefined {
    return this.byKey.get(key)
  }
}
