import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { PeriodFilter } from './PeriodFilter'

const OPTIONS = [
  { value: 7, label: '7日' },
  { value: 30, label: '30日' },
  { value: null, label: 'すべて' },
]

describe('PeriodFilter', () => {
  it('marks the selected period', () => {
    render(<PeriodFilter value={30} options={OPTIONS} onChange={() => {}} />)
    expect(screen.getByRole('button', { name: '30日' })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByRole('button', { name: '7日' })).toHaveAttribute('aria-pressed', 'false')
  })

  it('treats null as the "all" option', () => {
    render(<PeriodFilter value={null} options={OPTIONS} onChange={() => {}} />)
    expect(screen.getByRole('button', { name: 'すべて' })).toHaveAttribute('aria-pressed', 'true')
  })

  it('reports the chosen value', async () => {
    const onChange = vi.fn()
    render(<PeriodFilter value={30} options={OPTIONS} onChange={onChange} />)
    await userEvent.click(screen.getByRole('button', { name: '7日' }))
    expect(onChange).toHaveBeenCalledWith(7)
    await userEvent.click(screen.getByRole('button', { name: 'すべて' }))
    expect(onChange).toHaveBeenLastCalledWith(null)
  })
})
