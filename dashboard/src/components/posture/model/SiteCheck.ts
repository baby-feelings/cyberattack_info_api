import type { SiteCheckOut, SiteFindingOut } from '../../../api/client'

// 問題として数える重要度（重い順）。API（`app/external_monitor/probes.py`）の値と同じ。INFO は問題に含めない
export type SiteSeverity = 'ERROR' | 'WARNING'
const SEVERITY_ORDER: readonly SiteSeverity[] = ['ERROR', 'WARNING']

// 公開サイトの外形監視の結果1件。判定のしきい値は、API の指摘（findings）に従い、ここでは、再計算しない。
export class SiteCheck {
  readonly url: string
  readonly source: string
  // リポジトリに紐づかないサイト（設定で指定した監視対象）は null
  readonly repo: string | null
  readonly tlsDaysLeft: number | null
  // 問題（ERROR・WARNING）の数。API が数えた値
  readonly issues: number
  readonly findings: readonly SiteFindingOut[]
  readonly checkedAt: string

  constructor(raw: SiteCheckOut) {
    this.url = raw.url
    this.source = raw.source
    this.repo = raw.repo_full_name
    this.tlsDaysLeft = raw.tls_days_left
    this.issues = raw.issues
    this.findings = raw.findings
    this.checkedAt = raw.checked_at
  }

  // 指摘のうち、いちばん重いもの。ERROR・WARNING が無ければ（INFO だけ・指摘なし）null
  worstSeverity(): SiteSeverity | null {
    return SEVERITY_ORDER.find((severity) => this.findings.some((f) => f.severity === severity)) ?? null
  }
}
