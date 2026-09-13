import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SeverityBadge } from './Badge'

const CLASS_MAP = {
  CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/30',
  HIGH: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
}

describe('SeverityBadge', () => {
  it('renders the severity text with its mapped class', () => {
    render(<SeverityBadge severity="CRITICAL" classMap={CLASS_MAP} />)
    const badge = screen.getByText('CRITICAL')
    expect(badge.className).toContain('text-red-400')
  })

  it('falls back to a generic class for an unmapped severity', () => {
    render(<SeverityBadge severity="LOW" classMap={CLASS_MAP} />)
    const badge = screen.getByText('LOW')
    expect(badge.className).toContain('bg-slate-800')
  })

  it('renders "N/A" for a null severity', () => {
    render(<SeverityBadge severity={null} classMap={CLASS_MAP} />)
    expect(screen.getByText('N/A')).toBeInTheDocument()
  })
})
