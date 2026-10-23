import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CollapsibleSection } from './CollapsibleSection'

describe('CollapsibleSection', () => {
  it('does not render its children until opened', async () => {
    render(<CollapsibleSection summary="開く"><p>中身</p></CollapsibleSection>)
    expect(screen.queryByText('中身')).not.toBeInTheDocument()

    await userEvent.click(screen.getByText('開く'))
    expect(await screen.findByText('中身')).toBeInTheDocument()
  })
})
