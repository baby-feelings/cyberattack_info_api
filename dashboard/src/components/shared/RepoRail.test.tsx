import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { RepoRail } from './RepoRail'
import { repoShortName } from './repoName'

describe('repoShortName', () => {
  it('drops the owner part', () => {
    expect(repoShortName('baby-feelings/todo-app')).toBe('todo-app')
  })
  it('returns the input when there is no owner', () => {
    expect(repoShortName('todo-app')).toBe('todo-app')
  })
})

describe('RepoRail', () => {
  const items = [
    { key: 'o/a', label: 'a', badge: <span>3</span> },
    { key: 'o/b', label: 'b', badge: <span>0</span>, muted: true },
  ]

  it('marks the selected app and calls onSelect with its key', async () => {
    const onSelect = vi.fn()
    render(<RepoRail items={items} selected="o/a" onSelect={onSelect} allBadge={<span>3</span>} />)
    expect(screen.getByRole('button', { name: /^a/ })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByRole('button', { name: /^b/ })).toHaveAttribute('aria-pressed', 'false')

    await userEvent.click(screen.getByRole('button', { name: /^b/ }))
    expect(onSelect).toHaveBeenCalledWith('o/b')
  })

  it('selects every app with null', async () => {
    const onSelect = vi.fn()
    render(<RepoRail items={items} selected="o/a" onSelect={onSelect} allBadge={<span>3</span>} />)
    await userEvent.click(screen.getByRole('button', { name: /すべてのアプリ/ }))
    expect(onSelect).toHaveBeenCalledWith(null)
  })

  it('treats "all" as selected when nothing is selected', () => {
    render(<RepoRail items={items} selected={null} onSelect={() => {}} allBadge={<span>3</span>} />)
    expect(screen.getByRole('button', { name: /すべてのアプリ/ })).toHaveAttribute('aria-pressed', 'true')
  })
})
