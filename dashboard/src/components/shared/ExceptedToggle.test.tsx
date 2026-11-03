import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ExceptedToggle } from './ExceptedToggle'

describe('ExceptedToggle', () => {
  it('reflects the state with aria-pressed and calls onToggle on click', async () => {
    const onToggle = vi.fn()
    const user = userEvent.setup()
    const { rerender } = render(<ExceptedToggle active={false} onToggle={onToggle} />)

    const button = screen.getByRole('button', { name: '例外を含む' })
    expect(button).toHaveAttribute('aria-pressed', 'false')
    await user.click(button)
    expect(onToggle).toHaveBeenCalledTimes(1)

    rerender(<ExceptedToggle active onToggle={onToggle} />)
    expect(screen.getByRole('button', { name: '例外を含む' })).toHaveAttribute('aria-pressed', 'true')
  })

  it('shows the count only when it is positive', () => {
    const { rerender } = render(<ExceptedToggle active={false} onToggle={() => {}} count={4} />)
    expect(screen.getByRole('button', { name: '例外を含む（4）' })).toBeInTheDocument()

    rerender(<ExceptedToggle active={false} onToggle={() => {}} count={0} />)
    expect(screen.getByRole('button', { name: '例外を含む' })).toBeInTheDocument()
  })
})
