import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { OperatingGroups } from './OperatingGroups'
import { POSTURE_TEXT } from './postureConfig'

const GROUPS = POSTURE_TEXT.groups

describe('OperatingGroups', () => {
  it('always renders the active group, and does not render the inactive one while it is closed', () => {
    const renderGroup = vi.fn((operating: string) => <p>{`group:${operating}`}</p>)
    render(<OperatingGroups render={renderGroup} />)

    expect(screen.getByText('group:active')).toBeInTheDocument()
    expect(screen.queryByText('group:inactive')).not.toBeInTheDocument()
    expect(renderGroup).not.toHaveBeenCalledWith('inactive')
    expect(screen.getByRole('button', { name: new RegExp(GROUPS.inactive) })).toHaveAttribute('aria-expanded', 'false')
  })

  it('renders the inactive group when opened, and removes it again when closed', async () => {
    const user = userEvent.setup()
    render(<OperatingGroups render={(operating) => <p>{`group:${operating}`}</p>} />)
    const toggle = screen.getByRole('button', { name: new RegExp(GROUPS.inactive) })

    await user.click(toggle)
    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByText('group:inactive')).toBeInTheDocument()
    expect(screen.getByText('group:active')).toBeInTheDocument()

    await user.click(toggle)
    expect(screen.queryByText('group:inactive')).not.toBeInTheDocument()
    expect(screen.getByText('group:active')).toBeInTheDocument()
  })
})
