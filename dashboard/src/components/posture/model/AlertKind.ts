import { ALERT_FALLBACK_ICON, ALERT_KIND_VIEW, type AlertIconName, type AlertKindView } from '../postureConfig'

// アラートの種類（secret / dependabot / code）。表示名とアイコンは、設定（postureConfig）から引く。
// 未知の種類は、値をそのまま表示名にして、画面を壊さない。
export class AlertKind {
  readonly kind: string
  private readonly view: AlertKindView | undefined

  private constructor(kind: string) {
    this.kind = kind
    // `Object.entries` で探す（`'constructor'` などの、オブジェクトの組み込みの名前を、種類と取り違えない）
    this.view = Object.entries(ALERT_KIND_VIEW).find(([known]) => known === kind)?.[1]
  }

  static of(kind: string): AlertKind {
    return new AlertKind(kind)
  }

  label(): string {
    return this.view?.label ?? this.kind
  }

  icon(): AlertIconName {
    return this.view?.icon ?? ALERT_FALLBACK_ICON
  }
}
