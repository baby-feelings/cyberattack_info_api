import { OVERVIEW_TEXT, PERCENT_OK_AT, type MetricState, type MetricUnit, type NavTarget } from './overviewConfig'

// 概要の1つの指標（値と、その状態）。不変。value が null は「取得できなかった」で、0 とは区別する
export class OverviewMetric {
  readonly id: string
  readonly label: string
  readonly value: number | null
  readonly unit: MetricUnit
  readonly target: NavTarget

  constructor(init: { id: string; label: string; value: number | null; unit?: MetricUnit; target: NavTarget }) {
    this.id = init.id
    this.label = init.label
    this.value = init.value
    this.unit = init.unit ?? 'count'
    this.target = init.target
  }

  get state(): MetricState {
    if (this.value === null) return 'unknown'
    const healthy = this.unit === 'percent' ? this.value >= PERCENT_OK_AT : this.value === 0
    return healthy ? 'ok' : 'warn'
  }

  // 画面に出す値（例: 「3 件」「81%」「不明」）
  display(): string {
    if (this.value === null) return OVERVIEW_TEXT.unknown
    return this.unit === 'percent'
      ? `${this.value}${OVERVIEW_TEXT.unitPercent}`
      : `${this.value} ${OVERVIEW_TEXT.unitCount}`
  }
}
