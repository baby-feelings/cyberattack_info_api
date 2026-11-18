import type { RepoAuditResponse } from '../../../api/client'
import { RepoAudit } from './RepoAudit'

export interface MatrixColumn {
  key: string
  label: string
}

export interface RowOptions {
  // リポジトリ名の部分一致（大文字小文字を区別しない）
  query?: string
  // 不合格（ng）の項目があるリポジトリだけ
  onlyIssues?: boolean
}

// 「リポジトリ × 点検項目」の表。列は、全リポジトリの点検項目から導く（項目名を、画面に持たない）。
export class AuditMatrix {
  private readonly audits: readonly RepoAudit[]

  constructor(audits: readonly RepoAudit[]) {
    this.audits = audits
  }

  static fromResponse(response: RepoAuditResponse): AuditMatrix {
    return new AuditMatrix(response.data.map((raw) => new RepoAudit(raw)))
  }

  // 全リポジトリの項目の和集合。初めて現れた順。項目名（label）は、API の値
  columns(): MatrixColumn[] {
    const seen = new Map<string, MatrixColumn>()
    for (const audit of this.audits) {
      for (const check of audit.checks) {
        if (!seen.has(check.key)) seen.set(check.key, { key: check.key, label: check.label })
      }
    }
    return [...seen.values()]
  }

  rows(options: RowOptions = {}): RepoAudit[] {
    const query = options.query?.trim().toLowerCase()
    return this.audits.filter((audit) => (
      (!options.onlyIssues || audit.issues > 0)
      && (!query || audit.repo.toLowerCase().includes(query))
    ))
  }

  // 点検できたリポジトリの、達成率の平均（四捨五入）。点検できたものが無ければ null
  averageScore(): number | null {
    const scores = this.audits.map((audit) => audit.score).filter((score): score is number => score !== null)
    if (scores.length === 0) return null
    return Math.round(scores.reduce((sum, score) => sum + score, 0) / scores.length)
  }
}
