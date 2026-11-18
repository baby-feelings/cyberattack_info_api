import type { AuditCheckOut } from '../../../api/client'
import { AuditStatus } from './AuditStatus'

// 点検項目1件。項目名（label）・詳細・直し方は、API が返す値をそのまま持つ（画面に項目名を持たない）。
export class AuditCheck {
  readonly key: string
  readonly label: string
  readonly status: AuditStatus
  readonly weight: number
  readonly detail: string
  readonly fix: string

  constructor(raw: AuditCheckOut) {
    this.key = raw.key
    this.label = raw.label
    this.status = AuditStatus.from(raw.status)
    this.weight = raw.weight
    this.detail = raw.detail
    this.fix = raw.fix
  }
}
