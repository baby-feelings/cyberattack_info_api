import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Timer } from 'lucide-react'
import { FullScreenModal } from './FullScreenModal'

describe('FullScreenModal', () => {
  it('renders an accessible dialog with the title and the children', () => {
    render(
      <FullScreenModal label="対応状況" icon={Timer} onClose={() => {}}>
        <p>本文</p>
      </FullScreenModal>,
    )
    const dialog = screen.getByRole('dialog', { name: '対応状況' })
    expect(dialog).toHaveAttribute('aria-modal', 'true')
    // 見出しは、title を省略すると label と同じ
    expect(dialog).toHaveTextContent('対応状況')
    expect(screen.getByText('本文')).toBeInTheDocument()
  })

  it('shows a separate title when given', () => {
    render(
      <FullScreenModal label="Dependabot 運用状況" title="Dependabot 運用状況（DEPSOPS）" icon={Timer} onClose={() => {}}>
        <p>x</p>
      </FullScreenModal>,
    )
    expect(screen.getByText('Dependabot 運用状況（DEPSOPS）')).toBeInTheDocument()
  })

  it('closes with the close button and with Escape', async () => {
    const onClose = vi.fn()
    const user = userEvent.setup()
    render(
      <FullScreenModal label="x" icon={Timer} onClose={onClose}>
        <p>x</p>
      </FullScreenModal>,
    )

    await user.click(screen.getByRole('button', { name: '閉じる' }))
    expect(onClose).toHaveBeenCalledTimes(1)

    await user.keyboard('{Escape}')
    expect(onClose).toHaveBeenCalledTimes(2)
  })

  it('stops listening for Escape once unmounted', async () => {
    const onClose = vi.fn()
    const user = userEvent.setup()
    const { unmount } = render(
      <FullScreenModal label="x" icon={Timer} onClose={onClose}>
        <p>x</p>
      </FullScreenModal>,
    )
    unmount()
    await user.keyboard('{Escape}')
    expect(onClose).not.toHaveBeenCalled()
  })

  it('uses the narrower width only when asked', () => {
    const { container, rerender } = render(
      <FullScreenModal label="x" icon={Timer} onClose={() => {}}>
        <p>x</p>
      </FullScreenModal>,
    )
    expect(container.querySelector('.max-w-6xl')).not.toBeNull()
    rerender(
      <FullScreenModal label="x" icon={Timer} maxWidth="max-w-5xl" onClose={() => {}}>
        <p>x</p>
      </FullScreenModal>,
    )
    expect(container.querySelector('.max-w-5xl')).not.toBeNull()
  })
})
