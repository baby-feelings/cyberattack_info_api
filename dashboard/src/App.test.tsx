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
vi.mock('./components/shared/GithubLoginGate', () => ({
  GithubLoginGate: ({ children }: { children: (s: unknown, c: unknown) => unknown }) => (
    <div data-testid="login-gate">{children({ token: 'tok', username: 'octocat' }, { logout: vi.fn() }) as never}</div>
  ),
}))
vi.mock('./components/DepscanScanView', () => ({
  DepscanScanView: () => <div data-testid="depscan-auth-gate" />,
}))
vi.mock('./components/CodescanPanel', () => ({
  CodescanPanel: () => <div data-testid="codescan-panel" />,
}))
vi.mock('./components/posture/SourceTabs', () => ({
  AuditTab: () => <div data-testid="audit-tab" />,
  SitesTab: () => <div data-testid="sites-tab" />,
}))
vi.mock('./components/posture/AlertsTab', () => ({
  AlertsTab: () => <div data-testid="alerts-tab" />,
}))
vi.mock('./components/SettingsPanel', () => ({
  SettingsPanel: ({ onClose }: { onClose: () => void }) => (
    <div data-testid="settings-panel">
      <button onClick={onClose}>close-settings</button>
    </div>
  ),
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
    expect(screen.getByRole('tab', { name: /依存ライブラリ/ })).toHaveAttribute('aria-selected', 'true')
  })

  it('switches panels when a different tab is clicked', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.click(screen.getByRole('tab', { name: /OSV/ }))
    expect(screen.getByTestId('osv-panel')).toBeInTheDocument()
    expect(screen.queryByTestId('kev-panel')).not.toBeInTheDocument()

    await user.click(screen.getByRole('tab', { name: /依存ライブラリ/ }))
    expect(screen.getByTestId('depscan-auth-gate')).toBeInTheDocument()

    await user.click(screen.getByRole('tab', { name: /コードと設定/ }))
    expect(screen.getByTestId('codescan-panel')).toBeInTheDocument()

    await user.click(screen.getByRole('tab', { name: /^運用$/ }))
    expect(screen.getByTestId('sites-tab')).toBeInTheDocument()
  })

  it('always renders HealthStatus regardless of the active tab', async () => {
    const user = userEvent.setup()
    render(<App />)
    expect(screen.getByTestId('health-status')).toBeInTheDocument()

    await user.click(screen.getByRole('tab', { name: /OSV/ }))
    expect(screen.getByTestId('health-status')).toBeInTheDocument()
  })

  it('opens the settings panel from the hamburger menu', async () => {
    const user = userEvent.setup()
    render(<App />)
    expect(screen.queryByTestId('settings-panel')).not.toBeInTheDocument()

    await user.click(screen.getByLabelText('メニュー'))
    await user.click(screen.getByText('設定'))
    expect(screen.getByTestId('settings-panel')).toBeInTheDocument()

    await user.click(screen.getByText('close-settings'))
    expect(screen.queryByTestId('settings-panel')).not.toBeInTheDocument()
  })
})
