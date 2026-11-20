import { describe, it, expect, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { ReloadButton } from './ReloadButton'

describe('ReloadButton', () => {
  it('calls onReload when clicked', () => {
    const onReload = vi.fn()
    render(<ReloadButton onReload={onReload} busy={false} />)

    fireEvent.click(screen.getByRole('button', { name: '再読み込み' }))

    expect(onReload).toHaveBeenCalledTimes(1)
  })

  it('is disabled and spins while busy, so it cannot be pressed twice', () => {
    const onReload = vi.fn()
    const { container } = render(<ReloadButton onReload={onReload} busy />)

    const button = screen.getByRole('button', { name: '再読み込み' })
    expect(button).toBeDisabled()
    fireEvent.click(button)
    expect(onReload).not.toHaveBeenCalled()
    expect(container.querySelector('svg')).toHaveClass('animate-spin')
  })

  it('uses the given label as its accessible name', () => {
    render(<ReloadButton onReload={() => {}} busy={false} label="対応状況を再読み込み" />)

    expect(screen.getByRole('button', { name: '対応状況を再読み込み' })).toBeInTheDocument()
  })
})
