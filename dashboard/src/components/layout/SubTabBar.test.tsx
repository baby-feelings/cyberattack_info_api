import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { SubTabBar } from './SubTabBar'

const TABS = [
  { key: 'a', label: 'エー' },
  { key: 'b', label: 'ビー' },
  { key: 'c', label: 'シー' },
]

describe('SubTabBar', () => {
  it('renders one tab per item and marks only the active one as selected', () => {
    render(<SubTabBar tabs={TABS} active="b" onSelect={vi.fn()} idPrefix="x" />)
    expect(screen.getAllByRole('tab')).toHaveLength(3)
    expect(screen.getByRole('tab', { name: 'ビー' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('tab', { name: 'エー' })).toHaveAttribute('aria-selected', 'false')
  })

  it('calls onSelect with the key of the clicked tab', () => {
    const onSelect = vi.fn()
    render(<SubTabBar tabs={TABS} active="a" onSelect={onSelect} idPrefix="x" />)
    fireEvent.click(screen.getByRole('tab', { name: 'シー' }))
    expect(onSelect).toHaveBeenCalledWith('c')
  })

  it('links each tab to the panel through aria-controls', () => {
    render(<SubTabBar tabs={TABS} active="a" onSelect={vi.fn()} idPrefix="pub" />)
    expect(screen.getByRole('tab', { name: 'エー' })).toHaveAttribute('aria-controls', 'subtabpanel-pub')
  })
})
