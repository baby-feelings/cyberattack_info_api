import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CollapsibleSection } from './CollapsibleSection'

describe('CollapsibleSection', () => {
  it('shows its children at first', () => {
    render(<CollapsibleSection summary="グラフ"><p>中身</p></CollapsibleSection>)
    expect(screen.getByText('中身')).toBeInTheDocument()
  })

  it('closes when the heading is clicked, and opens again on the next click', async () => {
    render(<CollapsibleSection summary="グラフ"><p>中身</p></CollapsibleSection>)

    await userEvent.click(screen.getByText('グラフ'))
    expect(screen.queryByText('中身')).not.toBeInTheDocument()

    await userEvent.click(screen.getByText('グラフ'))
    expect(await screen.findByText('中身')).toBeInTheDocument()
  })
})
