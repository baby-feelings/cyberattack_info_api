import { describe, it, expect, beforeEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useWatchKeywords, MAX_KEYWORDS, MAX_KEYWORD_LENGTH } from './useWatchKeywords'

const KEY = 'watch_keywords'

describe('useWatchKeywords', () => {
  beforeEach(() => localStorage.clear())

  it('starts empty', () => {
    const { result } = renderHook(() => useWatchKeywords())
    expect(result.current.keywords).toEqual([])
  })

  it('adds a trimmed keyword and saves it in the browser', () => {
    const { result } = renderHook(() => useWatchKeywords())
    let error: string | null = 'unset'
    act(() => { error = result.current.add('  Python ') })
    expect(error).toBeNull()
    expect(result.current.keywords).toEqual(['Python'])
    expect(JSON.parse(localStorage.getItem(KEY) ?? '[]')).toEqual(['Python'])
  })

  it('restores saved keywords', () => {
    localStorage.setItem(KEY, JSON.stringify(['nginx', 'Redis']))
    const { result } = renderHook(() => useWatchKeywords())
    expect(result.current.keywords).toEqual(['nginx', 'Redis'])
  })

  it('rejects an empty keyword, a duplicate (ignoring case) and an over-long one', () => {
    const { result } = renderHook(() => useWatchKeywords())
    act(() => { result.current.add('Python') })
    let errors: (string | null)[] = []
    act(() => {
      errors = [
        result.current.add('   '),
        result.current.add('python'),
        result.current.add('x'.repeat(MAX_KEYWORD_LENGTH + 1)),
      ]
    })
    expect(errors.every(e => e !== null)).toBe(true)
    expect(result.current.keywords).toEqual(['Python'])
  })

  it('rejects keywords beyond the maximum', () => {
    localStorage.setItem(KEY, JSON.stringify(Array.from({ length: MAX_KEYWORDS }, (_, i) => `k${i}`)))
    const { result } = renderHook(() => useWatchKeywords())
    let error: string | null = null
    act(() => { error = result.current.add('one-more') })
    expect(error).toContain(`${MAX_KEYWORDS}個`)
    expect(result.current.keywords.length).toBe(MAX_KEYWORDS)
  })

  it('removes a keyword', () => {
    localStorage.setItem(KEY, JSON.stringify(['a', 'b']))
    const { result } = renderHook(() => useWatchKeywords())
    act(() => { result.current.remove('a') })
    expect(result.current.keywords).toEqual(['b'])
    expect(JSON.parse(localStorage.getItem(KEY) ?? '[]')).toEqual(['b'])
  })

  it('ignores corrupted saved data', () => {
    localStorage.setItem(KEY, '{not json')
    expect(renderHook(() => useWatchKeywords()).result.current.keywords).toEqual([])
    localStorage.setItem(KEY, JSON.stringify({ a: 1 }))
    expect(renderHook(() => useWatchKeywords()).result.current.keywords).toEqual([])
    localStorage.setItem(KEY, JSON.stringify(['ok', 3, '', null]))
    expect(renderHook(() => useWatchKeywords()).result.current.keywords).toEqual(['ok'])
  })
})
