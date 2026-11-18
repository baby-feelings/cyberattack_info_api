import type { GithubAlertOut } from '../../../api/client'
import { safeHttpUrl } from '../../shared/safeUrl'
import { ALERT_SEVERITY_RANK, ALERT_UNKNOWN_SEVERITY_RANK } from '../postureConfig'
import { AlertKind } from './AlertKind'

// GitHub のセキュリティアラート1件。シークレットの値は、API が返さないため、持たない。
export class GithubAlert {
  readonly kind: AlertKind
  readonly repo: string
  readonly number: number
  readonly title: string
  readonly severity: string | null
  readonly detectedAt: string
  readonly resolvedAt: string | null
  private readonly htmlUrl: string
  private readonly detail: Readonly<Record<string, unknown>>

  constructor(raw: GithubAlertOut) {
    this.kind = AlertKind.of(raw.kind)
    this.repo = raw.repo_full_name
    this.number = raw.number
    this.title = raw.title
    this.severity = raw.severity
    this.detectedAt = raw.detected_at
    this.resolvedAt = raw.resolved_at
    this.htmlUrl = raw.html_url
    this.detail = raw.detail
  }

  // リンクにしてよい URL（http・https のみ）。それ以外は null
  safeUrl(): string | null {
    return safeHttpUrl(this.htmlUrl) ?? null
  }

  // 並べ替え用の順位（小さいほど重大）。未知・未設定の重要度は、最後
  severityRank(): number {
    const severity = this.severity?.toUpperCase()
    const entry = Object.entries(ALERT_SEVERITY_RANK).find(([known]) => known === severity)
    return entry ? entry[1] : ALERT_UNKNOWN_SEVERITY_RANK
  }

  // 検知したツールの名前（code scanning のとき、API が `detail.tool` に入れる）。文字列でなければ null
  tool(): string | null {
    const tool = this.detail.tool
    return typeof tool === 'string' ? tool : null
  }
}
