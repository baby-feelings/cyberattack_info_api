import { describe, expect, it } from 'vitest'
import {
  CRAWL_INTERVAL_HOURS, FRESHNESS_STYLE, FRESHNESS_TEXT, STALE_AFTER_HOURS, STALE_GRACE_HOURS,
  numberFromEnv, SCREEN_FETCH_SOURCE,
} from './freshnessConfig'

describe('numberFromEnv', () => {
  it('uses a positive number from the environment', () => {
    expect(numberFromEnv('12', 24)).toBe(12)
    expect(numberFromEnv('1.5', 24)).toBe(1.5)
  })

  it('falls back for unset, empty, non-numeric, zero and negative values', () => {
    for (const raw of [undefined, '', 'abc', '0', '-3', 'Infinity', 'NaN']) {
      expect(numberFromEnv(raw, 24)).toBe(24)
    }
  })
})

describe('freshness settings', () => {
  it('adds the grace period to the crawl interval', () => {
    expect(STALE_AFTER_HOURS).toBe(CRAWL_INTERVAL_HOURS + STALE_GRACE_HOURS)
    expect(STALE_AFTER_HOURS).toBeGreaterThan(CRAWL_INTERVAL_HOURS)
  })

  it('has a style for every state and text that tells states apart without colour', () => {
    expect(Object.keys(FRESHNESS_STYLE).sort()).toEqual(['failed', 'fresh', 'stale', 'unknown'])
    expect(FRESHNESS_TEXT.stale).not.toBe(FRESHNESS_TEXT.failed)
    expect(FRESHNESS_TEXT.inserted(3)).toContain('3')
    expect(FRESHNESS_TEXT.updated(2)).toContain('2')
  })

  it('pulses only for the abnormal states, and only when motion is allowed', () => {
    expect(FRESHNESS_STYLE.fresh.dot).not.toContain('animate-pulse')
    expect(FRESHNESS_STYLE.stale.dot).toContain('motion-safe:animate-pulse')
    expect(FRESHNESS_STYLE.failed.dot).toContain('motion-safe:animate-pulse')
  })
})

describe('SCREEN_FETCH_SOURCE', () => {
  it('maps each modal screen to the crawler whose data it shows', () => {
    expect(SCREEN_FETCH_SOURCE).toEqual({
      dependencies: 'DEPSCAN', sla: 'DEPSCAN', depsops: 'DEPSOPS', runtimes: 'RUNTIME',
    })
  })
})
