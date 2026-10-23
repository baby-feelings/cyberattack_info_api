import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { StatBand } from './StatBand'

describe('StatBand', () => {
  it('shows each number with its label', () => {
    render(<StatBand loading={false} items={[
      { value: 33, label: '件が追加', tone: 'sky' },
      { value: 9, label: '件は悪用されやすい', tone: 'red' },
    ]} />)
    expect(screen.getByText('33')).toBeInTheDocument()
    expect(screen.getByText('件が追加')).toBeInTheDocument()
    expect(screen.getByText('9')).toHaveClass('text-red-400')
  })

  it('shows zero as a number', () => {
    render(<StatBand loading={false} items={[{ value: 0, label: '件' }]} />)
    expect(screen.getByText('0')).toBeInTheDocument()
  })

  it('hides a number that could not be obtained, instead of showing 0', () => {
    render(<StatBand loading={false} items={[
      { value: 5, label: '件が追加' },
      { value: null, label: '件は悪用されやすい' },
    ]} />)
    expect(screen.queryByText('件は悪用されやすい')).not.toBeInTheDocument()
  })

  it('shows a placeholder while loading', () => {
    render(<StatBand loading items={[{ value: 5, label: '件が追加' }]} />)
    expect(screen.getByRole('status', { name: '集計中' })).toBeInTheDocument()
    expect(screen.queryByText('件が追加')).not.toBeInTheDocument()
  })
})
