import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import App from './App'

vi.mock('./components/HealthStatus', () => ({
  HealthStatus: () => <div data-testid="health-status" />,
}))
vi.mock('./components/KevPanel', () => ({
  KevPanel: () => <div data-testid="kev-panel" />,
}))
vi.mock('./components/OsvPanel', () => ({
  OsvPanel: () => <div data-testid="osv-panel" />,
}))
vi.mock('./components/JvnPanel', () => ({
  JvnPanel: () => <div data-testid="jvn-panel" />,
}))
vi.mock('./components/DepscanAuthGate', () => ({
  DepscanAuthGate: () => <div data-testid="depscan-auth-gate" />,
}))

function setUrl(search: string) {
  window.history.pushState({}, '', `/${search}`)
}

describe('App', () => {
  afterEach(() => {
    setUrl('')
  })

  it('defaults to the KEV tab', () => {
    render(<App />)
    expect(screen.getByTestId('kev-panel')).toBeInTheDocument()
    expect(screen.queryByTestId('osv-panel')).not.toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /KEV/ })).toHaveAttribute('aria-selected', 'true')
  })

  it('auto-selects the DEPSCAN tab when returning from an OAuth callback', () => {
    setUrl('?depscan_code=abc123')
    render(<App />)
    expect(screen.getByTestId('depscan-auth-gate')).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /DEPSCAN/ })).toHaveAttribute('aria-selected', 'true')
  })

  it('switches panels when a different tab is clicked', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.click(screen.getByRole('tab', { name: /OSV/ }))
    expect(screen.getByTestId('osv-panel')).toBeInTheDocument()
    expect(screen.queryByTestId('kev-panel')).not.toBeInTheDocument()

    await user.click(screen.getByRole('tab', { name: /JVN/ }))
    expect(screen.getByTestId('jvn-panel')).toBeInTheDocument()

    await user.click(screen.getByRole('tab', { name: /DEPSCAN/ }))
    expect(screen.getByTestId('depscan-auth-gate')).toBeInTheDocument()
  })

  it('always renders HealthStatus regardless of the active tab', async () => {
    const user = userEvent.setup()
    render(<App />)
    expect(screen.getByTestId('health-status')).toBeInTheDocument()

    await user.click(screen.getByRole('tab', { name: /OSV/ }))
    expect(screen.getByTestId('health-status')).toBeInTheDocument()
  })
})
