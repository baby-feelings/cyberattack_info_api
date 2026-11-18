import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Timer } from 'lucide-react'
import { PanelFrame } from './PanelFrame'

describe('PanelFrame', () => {
  it('renders a labelled region with the heading and the children, and is not a dialog', () => {
    render(
      <PanelFrame label="対応状況" icon={Timer}>
        <p>本文</p>
      </PanelFrame>,
    )
    expect(screen.getByRole('region', { name: '対応状況' })).toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '対応状況' })).toBeInTheDocument()
    expect(screen.getByText('本文')).toBeInTheDocument()
  })

  it('shows a separate title when given', () => {
    render(
      <PanelFrame label="Dependabot 運用状況" title="Dependabot 運用状況（DEPSOPS）" icon={Timer}>
        <p>x</p>
      </PanelFrame>,
    )
    expect(screen.getByRole('heading', { name: 'Dependabot 運用状況（DEPSOPS）' })).toBeInTheDocument()
  })
})
