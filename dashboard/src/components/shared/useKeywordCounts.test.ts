import { describe, it, expect, vi } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { useKeywordCounts } from './useKeywordCounts'

describe('useKeywordCounts', () => {
  it('fetches a count for each keyword', async () => {
    const countFor = vi.fn(async (k: string) => k.length)
    const keywords = ['abc', 'de']
    const { result } = renderHook(() => useKeywordCounts(keywords, countFor))
    await waitFor(() => expect(result.current).toEqual({ abc: 3, de: 2 }))
  })

  it('leaves a keyword undefined when its count fails, without affecting the others', async () => {
    const countFor = vi.fn(async (k: string) => {
      if (k === 'bad') throw new Error('boom')
      return 1
    })
    const keywords = ['ok', 'bad']
    const { result } = renderHook(() => useKeywordCounts(keywords, countFor))
    await waitFor(() => expect(result.current.ok).toBe(1))
    expect(result.current.bad).toBeUndefined()
  })

  it('drops the old counts and refetches when the condition (countFor) changes', async () => {
    const keywords = ['k']
    const { result, rerender } = renderHook(
      ({ fn }) => useKeywordCounts(keywords, fn),
      { initialProps: { fn: async () => 1 } },
    )
    await waitFor(() => expect(result.current.k).toBe(1))

    rerender({ fn: async () => 2 })
    // 条件が変わった直後は、古い件数を見せない
    expect(result.current.k).toBeUndefined()
    await waitFor(() => expect(result.current.k).toBe(2))
  })

  it('ignores a slow response that arrives after the condition changed', async () => {
    const keywords = ['k']
    let resolveSlow: (n: number) => void = () => {}
    const slow = () => new Promise<number>(r => { resolveSlow = r })
    const { result, rerender } = renderHook(
      ({ fn }) => useKeywordCounts(keywords, fn),
      { initialProps: { fn: slow } },
    )
    rerender({ fn: async () => 5 })
    await waitFor(() => expect(result.current.k).toBe(5))

    resolveSlow(99)
    await new Promise(r => setTimeout(r, 10))
    expect(result.current.k).toBe(5)
  })
})
