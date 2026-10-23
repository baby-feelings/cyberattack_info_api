import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { WatchKeywords } from './WatchKeywords'

function setup(overrides: Partial<Parameters<typeof WatchKeywords>[0]> = {}) {
  const props = {
    keywords: ['Python', 'nginx'],
    counts: { Python: 3, nginx: 0 } as Record<string, number | undefined>,
    active: '',
    total: 33,
    onSelect: vi.fn(),
    onAdd: vi.fn(() => null as string | null),
    onRemove: vi.fn(),
    ...overrides,
  }
  render(<WatchKeywords {...props} />)
  return props
}

describe('WatchKeywords', () => {
  it('shows a count for each keyword: red when there are hits, green for zero', () => {
    setup()
    expect(screen.getByText('3')).toHaveClass('text-red-400')
    expect(screen.getByText('0')).toHaveClass('text-emerald-400')
    expect(screen.getByText('33')).toBeInTheDocument()
  })

  it('shows a dash for a count that is not available yet (not a misleading 0)', () => {
    setup({ counts: {} })
    expect(screen.getAllByText('—').length).toBe(2)
  })

  it('selects a keyword, and clears the selection with "all"', async () => {
    const props = setup()
    await userEvent.click(screen.getByRole('button', { name: /^Python\d/ }))
    expect(props.onSelect).toHaveBeenCalledWith('Python')
    await userEvent.click(screen.getByRole('button', { name: /^すべて/ }))
    expect(props.onSelect).toHaveBeenLastCalledWith(null)
  })

  it('marks the keyword matching the current search as selected, ignoring case', () => {
    setup({ active: ' python ' })
    expect(screen.getByRole('button', { name: /^Python\d/ })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByRole('button', { name: /^すべて/ })).toHaveAttribute('aria-pressed', 'false')
  })

  it('removes a keyword', async () => {
    const props = setup()
    await userEvent.click(screen.getByRole('button', { name: 'nginxを削除' }))
    expect(props.onRemove).toHaveBeenCalledWith('nginx')
  })

  it('adds a keyword with Enter and clears the input', async () => {
    const props = setup()
    const input = screen.getByLabelText('キーワードを追加')
    await userEvent.type(input, 'Redis{Enter}')
    expect(props.onAdd).toHaveBeenCalledWith('Redis')
    expect(input).toHaveValue('')
  })

  it('shows the reason and keeps the input when adding fails', async () => {
    setup({ onAdd: vi.fn(() => 'すでに登録されています') })
    const input = screen.getByLabelText('キーワードを追加')
    await userEvent.type(input, 'Python{Enter}')
    expect(screen.getByRole('alert')).toHaveTextContent('すでに登録されています')
    expect(input).toHaveValue('Python')
  })

  it('explains how to use it when there are no keywords', () => {
    setup({ keywords: [], counts: {} })
    expect(screen.getByText(/使っている製品名（例: Python・nginx）を追加すると/)).toBeInTheDocument()
  })
})
