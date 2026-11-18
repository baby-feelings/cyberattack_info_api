import type { GithubAlertListResponse, UnavailableSource } from '../../../api/client'
import { GithubAlert } from './GithubAlert'

export interface AlertFilter {
  kind?: string | null
  severity?: string | null
}

// アラートの集合。絞り込み・並べ替え・集計を、自分で行う（呼び出し側は、結果を描くだけ）。不変
export class AlertList {
  private readonly alerts: readonly GithubAlert[]
  // 取得できなかった項目（機能が無効・権限不足）。絞り込みの影響を受けない
  readonly unavailable: readonly UnavailableSource[]

  constructor(alerts: readonly GithubAlert[], unavailable: readonly UnavailableSource[]) {
    this.alerts = alerts
    this.unavailable = unavailable
  }

  static fromResponse(response: GithubAlertListResponse): AlertList {
    return new AlertList(response.data.map((raw) => new GithubAlert(raw)), response.unavailable)
  }

  // 元の集合は変えず、絞り込んだ新しい集合を返す
  filter(options: AlertFilter): AlertList {
    const severity = options.severity?.toUpperCase()
    const kept = this.alerts.filter((alert) => (
      (!options.kind || alert.kind.kind === options.kind)
      && (!severity || alert.severity?.toUpperCase() === severity)
    ))
    return new AlertList(kept, this.unavailable)
  }

  // 指定した種別のアラートと、取得できなかった項目だけに絞った新しい集合を返す（画面ごとに、扱う種別を分けるため）
  onlyKinds(kinds: readonly string[]): AlertList {
    return new AlertList(
      this.alerts.filter((alert) => kinds.includes(alert.kind.kind)),
      this.unavailable.filter((u) => kinds.includes(u.kind)),
    )
  }

  // 重要度の順位（重大なものが先）、次にリポジトリ名、次に番号
  sorted(): GithubAlert[] {
    return [...this.alerts].sort((a, b) => (
      a.severityRank() - b.severityRank()
      || a.repo.localeCompare(b.repo)
      || a.number - b.number
    ))
  }

  count(): number {
    return this.alerts.length
  }

  countsByKind(): Record<string, number> {
    const counts: Record<string, number> = {}
    for (const alert of this.alerts) counts[alert.kind.kind] = (counts[alert.kind.kind] ?? 0) + 1
    return counts
  }
}
