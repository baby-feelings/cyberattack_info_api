import { describe, expect, it } from 'vitest'
import { parseDeepLink } from './deepLink'
import { TAB_DEFINITIONS } from './tabs'

describe('parseDeepLink', () => {
  it('reads the tab and sub-tab', () => {
    expect(parseDeepLink('?tab=dependencies&sub=sla', TAB_DEFINITIONS)).toEqual({ tab: 'dependencies', subTab: 'sla' })
  })
  it('opens the tab alone when there is no sub-tab, or the sub-tab is unknown', () => {
    expect(parseDeepLink('?tab=ops', TAB_DEFINITIONS)).toEqual({ tab: 'ops', subTab: undefined })
    expect(parseDeepLink('?tab=code&sub=nope', TAB_DEFINITIONS)).toEqual({ tab: 'code', subTab: undefined })
  })
  it('ignores an unknown or missing tab', () => {
    expect(parseDeepLink('?tab=nope&sub=sla', TAB_DEFINITIONS)).toBeNull()
    expect(parseDeepLink('', TAB_DEFINITIONS)).toBeNull()
  })
})
