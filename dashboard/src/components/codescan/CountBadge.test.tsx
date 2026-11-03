import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { CountBadge } from './CountBadge'

describe('CountBadge', () => {
  it('shows only the count when there are no excepted findings', () => {
    render(<CountBadge count={3} excepted={0} />)
    expect(screen.getByText('3')).toBeInTheDocument()
    expect(screen.queryByText(/^\+/)).not.toBeInTheDocument()
  })

  it('shows the excepted count beside the count', () => {
    render(<CountBadge count={2} excepted={7} />)
    expect(screen.getByText('2')).toBeInTheDocument()
    expect(screen.getByText('+7')).toHaveAttribute('title', '例外（受容・影響なし など）')
  })

  it('shows the muted style for the all-apps badge', () => {
    render(<CountBadge count={2} excepted={0} muted />)
    expect(screen.getByText('2').className).toContain('text-slate-500')
  })
})
