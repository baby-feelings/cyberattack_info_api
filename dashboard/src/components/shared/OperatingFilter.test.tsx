import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { OperatingFilter } from './OperatingFilter'

describe('OperatingFilter', () => {
  it('shows the three options with the portfolio wording and marks the current one', () => {
    render(<OperatingFilter value="active" onChange={vi.fn()} />)
    expect(screen.getByRole('group', { name: '運用状態フィルター' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '運用中' })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByRole('button', { name: '運用停止中' })).toHaveAttribute('aria-pressed', 'false')
    expect(screen.getByRole('button', { name: 'すべて' })).toHaveAttribute('aria-pressed', 'false')
  })

  it('calls onChange with the selected status', async () => {
    const onChange = vi.fn()
    render(<OperatingFilter value="active" onChange={onChange} />)
    await userEvent.click(screen.getByRole('button', { name: '運用停止中' }))
    expect(onChange).toHaveBeenLastCalledWith('inactive')
    await userEvent.click(screen.getByRole('button', { name: 'すべて' }))
    expect(onChange).toHaveBeenLastCalledWith('all')
  })
})
