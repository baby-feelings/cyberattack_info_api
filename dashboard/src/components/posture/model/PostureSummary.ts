import type { AlertList } from './AlertList'
import type { AuditMatrix } from './AuditMatrix'
import type { SiteCheck } from './SiteCheck'

export interface PostureSources {
  alerts: AlertList | null
  audit: AuditMatrix | null
  sites: readonly SiteCheck[] | null
}

// 見出しの数値。3つの取得元を束ねる。取得できなかった元（null）は、0 と区別して、null を返す
// （「0件」と「不明」を、同じに見せない）。
export class PostureSummary {
  private readonly alerts: AlertList | null
  private readonly audit: AuditMatrix | null
  private readonly sites: readonly SiteCheck[] | null

  constructor(sources: PostureSources) {
    this.alerts = sources.alerts
    this.audit = sources.audit
    this.sites = sources.sites
  }

  // 未対応（未解決）のアラートの件数
  openAlerts(): number | null {
    return this.alerts ? this.alerts.count() : null
  }

  // 設定の達成率の平均（0〜100）。点検できたリポジトリが無ければ null
  auditRate(): number | null {
    return this.audit ? this.audit.averageScore() : null
  }

  // 外形監視の、問題（ERROR・WARNING）の合計
  siteIssues(): number | null {
    return this.sites ? this.sites.reduce((sum, site) => sum + site.issues, 0) : null
  }
}
