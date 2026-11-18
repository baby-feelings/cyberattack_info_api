import { describe, it, expect } from 'vitest'
import { ALERT_KIND_VIEW } from '../postureConfig'
import { AlertKind } from './AlertKind'

describe('AlertKind', () => {
  it.each(['secret', 'dependabot', 'code'] as const)('takes the label and icon of %s from the config', (kind) => {
    const alertKind = AlertKind.of(kind)
    expect(alertKind.kind).toBe(kind)
    expect(alertKind.label()).toBe(ALERT_KIND_VIEW[kind].label)
    expect(alertKind.icon()).toBe(ALERT_KIND_VIEW[kind].icon)
  })

  it('shows an unknown kind by its own value, and gives it the fallback icon', () => {
    const alertKind = AlertKind.of('new-kind')
    expect(alertKind.label()).toBe('new-kind')
    expect(alertKind.icon()).toBe('ShieldAlert')
  })
})
