import { describe, expect, it } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import { useFindingFilters } from './useFindingFilters'

describe('useFindingFilters', () => {
  it('starts with active-only, no severity, no excepted, page 1', () => {
    const { result } = renderHook(() => useFindingFilters())
    expect(result.current).toMatchObject({ severity: null, showExcepted: false, operating: 'active', selectedRepo: null, page: 1 })
  })

  it('maps ALL to no severity, and returns to page 1 when a filter changes', () => {
    const { result } = renderHook(() => useFindingFilters())
    act(() => result.current.setPage(3))
    act(() => result.current.handleSev('HIGH'))
    expect(result.current).toMatchObject({ severity: 'HIGH', page: 1 })
    act(() => result.current.handleSev('ALL'))
    expect(result.current.severity).toBeNull()
  })

  it('keeps the selected repo on an operating change unless asked to reset it', () => {
    const keep = renderHook(() => useFindingFilters())
    act(() => keep.result.current.handleRepo('o/r'))
    act(() => keep.result.current.handleOperating('inactive'))
    expect(keep.result.current.selectedRepo).toBe('o/r')

    const reset = renderHook(() => useFindingFilters({ resetRepoOnOperating: true }))
    act(() => reset.result.current.handleRepo('o/r'))
    act(() => reset.result.current.handleOperating('inactive'))
    expect(reset.result.current.selectedRepo).toBeNull()
  })

  it('toggles excepted and resets the page', () => {
    const { result } = renderHook(() => useFindingFilters())
    act(() => result.current.setPage(2))
    act(() => result.current.toggleShowExcepted())
    expect(result.current).toMatchObject({ showExcepted: true, page: 1 })
  })
})
