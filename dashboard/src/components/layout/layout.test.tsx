import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { HeaderMenu } from './HeaderMenu'
import { TabBar } from './TabBar'
import { TabPanel } from './TabPanel'
import { TAB_DEFINITIONS } from './tabs'
import { fetchCrawlerLogs } from '../../api/crawlerLogs'

// 「最終取得」の実行履歴の取得は、ダミーへ差し替える
vi.mock('../../api/crawlerLogs', () => ({ fetchCrawlerLogs: vi.fn().mockResolvedValue([]) }))
// 重いパネル本体は軽量なダミーへ差し替える（レイアウトだけを検証する）
vi.mock('../KevPanel', () => ({ KevPanel: () => <div>kev-panel</div> }))
vi.mock('../OsvPanel', () => ({ OsvPanel: () => <div>osv-panel</div> }))
// ログインのゲートは、ログイン済みの状態を装う（小タブの切り替えだけを検証する）
vi.mock('../shared/GithubLoginGate', () => ({
  GithubLoginGate: ({ children }: { children: (s: unknown, c: unknown) => unknown }) => (
    <div data-testid="login-gate">{children({ token: 'tok', username: 'octocat' }, { logout: vi.fn() }) as never}</div>
  ),
}))
vi.mock('../DepscanScanView', () => ({ DepscanScanView: () => <div>depscan-scan-view</div> }))
vi.mock('../depscan/SlaPanel', () => ({ SlaPanel: ({ authToken }: { authToken: string }) => <div>sla-panel {authToken}</div> }))
vi.mock('../depscan/DependabotOpsPanel', () => ({ DependabotOpsPanel: () => <div>depsops-panel</div> }))
vi.mock('../depscan/DependenciesPanel', () => ({ DependenciesPanel: () => <div>deps-panel</div> }))
vi.mock('../depscan/RuntimesPanel', () => ({ RuntimesPanel: () => <div>runtimes-panel</div> }))
vi.mock('../posture/AlertsTab', () => ({
  AlertsTab: ({ kinds }: { kinds: string[] }) => <div>alerts-tab {kinds.join(',')}</div>,
}))
vi.mock('../CodescanPanel', () => ({ CodescanPanel: () => <div>codescan-panel</div> }))
vi.mock('../posture/SourceTabs', () => ({
  AuditTab: () => <div>audit-tab</div>,
  SitesTab: () => <div>sites-tab</div>,
}))

describe('TAB_DEFINITIONS', () => {
  it('defines the five tabs in display order with unique keys', () => {
    expect(TAB_DEFINITIONS.map((t) => t.key)).toEqual(['overview', 'public', 'dependencies', 'code', 'ops'])
    expect(new Set(TAB_DEFINITIONS.map((t) => t.key)).size).toBe(5)
  })

  it('declares the crawler whose last fetch each tab shows', () => {
    expect(TAB_DEFINITIONS.map((t) => t.crawlerType)).toEqual(['DEPSCAN', 'KEV', 'DEPSCAN', 'CODESCAN', 'EXTMON'])
  })

  it('puts the logged-in tabs behind a GitHub login, and the public tab in front of none', () => {
    expect(TAB_DEFINITIONS.filter((t) => t.login).map((t) => t.key)).toEqual(['overview', 'dependencies', 'code', 'ops'])
  })
})

describe('TabBar', () => {
  it('renders one tab per definition and marks only the active one as selected', () => {
    render(<TabBar activeTab="dependencies" onSelect={vi.fn()} />)
    const tabs = screen.getAllByRole('tab')
    expect(tabs).toHaveLength(5)
    expect(screen.getByRole('tab', { name: /依存ライブラリ/ })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('tab', { name: /公開情報/ })).toHaveAttribute('aria-selected', 'false')
  })

  it('splits the width evenly, with one column per tab', () => {
    render(<TabBar activeTab="public" onSelect={vi.fn()} />)
    // 列数を固定値にすると、タブを増減したときに、右側が空く（JVN の廃止で実際に起きた）
    expect(screen.getByRole('tablist')).toHaveStyle(
      `grid-template-columns: repeat(${TAB_DEFINITIONS.length}, minmax(0, 1fr))`,
    )
  })

  it('links each tab to its panel via aria-controls and calls onSelect with the key', () => {
    const onSelect = vi.fn()
    render(<TabBar activeTab="public" onSelect={onSelect} />)
    const depscan = screen.getByRole('tab', { name: /依存ライブラリ/ })
    expect(depscan).toHaveAttribute('id', 'tab-dependencies')
    expect(depscan).toHaveAttribute('aria-controls', 'tabpanel-dependencies')
    fireEvent.click(depscan)
    expect(onSelect).toHaveBeenCalledWith('dependencies')
  })
})

describe('TabPanel', () => {
  it('shows the last fetch of the crawler the tab declares, next to the heading', async () => {
    const tab = TAB_DEFINITIONS.find((t) => t.key === 'dependencies')!
    render(<TabPanel tab={tab} />)
    expect(await screen.findByTestId('last-fetched')).toBeInTheDocument()
    expect(fetchCrawlerLogs).toHaveBeenCalledWith(expect.objectContaining({ crawlerType: 'DEPSCAN' }))
  })

  describe('with sub tabs (the public tab)', () => {
    const publicTab = () => TAB_DEFINITIONS.find((t) => t.key === 'public')!

    it('shows the first sub tab by default, with its own heading and crawler', async () => {
      render(<TabPanel tab={publicTab()} />)
      expect(screen.getAllByRole('tab').map((t) => t.textContent)).toEqual(['KEV', 'OSV'])
      expect(screen.getByRole('tab', { name: 'KEV' })).toHaveAttribute('aria-selected', 'true')
      expect(screen.getByText('kev-panel')).toBeInTheDocument()
      expect(screen.getByRole('heading', { name: /CISA KEV/ })).toBeInTheDocument()
      expect(await screen.findByTestId('last-fetched')).toBeInTheDocument()
      expect(fetchCrawlerLogs).toHaveBeenCalledWith(expect.objectContaining({ crawlerType: 'KEV' }))
    })

    it('shows the selected sub tab, and reports the key when another one is clicked', () => {
      const onSubTabChange = vi.fn()
      const { rerender } = render(<TabPanel tab={publicTab()} onSubTabChange={onSubTabChange} />)
      fireEvent.click(screen.getByRole('tab', { name: 'OSV' }))
      expect(onSubTabChange).toHaveBeenCalledWith('osv')

      rerender(<TabPanel tab={publicTab()} subTabKey="osv" onSubTabChange={onSubTabChange} />)
      expect(screen.getByText('osv-panel')).toBeInTheDocument()
      expect(screen.queryByText('kev-panel')).not.toBeInTheDocument()
      expect(screen.getByRole('heading', { name: /OSV — Open Source/ })).toBeInTheDocument()
    })

    it('falls back to the first sub tab for an unknown key', () => {
      render(<TabPanel tab={publicTab()} subTabKey="nope" />)
      expect(screen.getByText('kev-panel')).toBeInTheDocument()
    })
  })

  it('renders heading, subtitle and body with aria wiring back to the tab', () => {
    const tab = TAB_DEFINITIONS.find((t) => t.key === 'dependencies')!
    render(<TabPanel tab={tab} />)
    // 外側（タブ）のパネルが先頭。小タブの中身のパネルが、その中に入る
    const panel = screen.getAllByRole('tabpanel')[0]
    expect(panel).toHaveAttribute('id', 'tabpanel-dependencies')
    expect(panel).toHaveAttribute('aria-labelledby', 'tab-dependencies')
    expect(screen.getByRole('heading', { name: /DEPSCAN/ })).toBeInTheDocument()
    expect(screen.getByText(/OSV と照合し、悪意あるパッケージ/)).toBeInTheDocument()
    expect(screen.getByText('depscan-scan-view')).toBeInTheDocument()
  })

  describe('the code and settings tab', () => {
    const tab = () => TAB_DEFINITIONS.find((t) => t.key === 'code')!

    it('has three sub tabs, and each one shows its own heading and last fetch', () => {
      const { rerender } = render(<TabPanel tab={tab()} />)
      expect(screen.getAllByRole('tab').map((t) => t.textContent)).toEqual(['検知', 'アラート', '設定の監査'])
      expect(screen.getByText('codescan-panel')).toBeInTheDocument()

      rerender(<TabPanel tab={tab()} subTabKey="audit" />)
      expect(screen.getByText('audit-tab')).toBeInTheDocument()
      expect(screen.getByRole('heading', { name: /リポジトリ設定の監査/ })).toBeInTheDocument()
    })

    it('shows only code and secret alerts in the alerts sub tab', () => {
      render(<TabPanel tab={tab()} subTabKey="alerts" />)
      expect(screen.getByText('alerts-tab code,secret')).toBeInTheDocument()
    })
  })

  it('shows the external monitoring directly in the ops tab (no sub tabs)', () => {
    const ops = TAB_DEFINITIONS.find((t) => t.key === 'ops')!
    render(<TabPanel tab={ops} />)
    expect(screen.getByText('sites-tab')).toBeInTheDocument()
    expect(screen.queryByRole('tablist', { name: '小タブ' })).not.toBeInTheDocument()
  })

  describe('the dependencies tab (behind the GitHub login gate)', () => {
    const tab = () => TAB_DEFINITIONS.find((t) => t.key === 'dependencies')!

    it('has the six sub tabs in order, inside one login gate', () => {
      render(<TabPanel tab={tab()} />)
      expect(screen.getAllByTestId('login-gate')).toHaveLength(1)
      expect(screen.getAllByRole('tab').map((t) => t.textContent)).toEqual([
        '検知', '対応状況', 'Dependabot運用', '依存パッケージ', '言語・実行環境', 'アラート',
      ])
    })

    it('passes the session token to a sub tab, and only the dependabot alerts to the alerts tab', () => {
      const { rerender } = render(<TabPanel tab={tab()} subTabKey="sla" />)
      expect(screen.getByText('sla-panel tok')).toBeInTheDocument()

      rerender(<TabPanel tab={tab()} subTabKey="alerts" />)
      expect(screen.getByText('alerts-tab dependabot')).toBeInTheDocument()
    })
  })
})

describe('HeaderMenu', () => {
  it('opens the menu and calls onOpenSettings, closing the menu', () => {
    const onOpenSettings = vi.fn()
    render(<HeaderMenu onOpenSettings={onOpenSettings} />)
    const toggle = screen.getByRole('button', { name: 'メニュー' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')

    fireEvent.click(toggle)
    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    fireEvent.click(screen.getByRole('button', { name: '設定' }))

    expect(onOpenSettings).toHaveBeenCalledTimes(1)
    expect(screen.queryByRole('button', { name: '設定' })).not.toBeInTheDocument()
  })

  it('closes on Escape and on an outside pointer down', () => {
    render(<HeaderMenu onOpenSettings={vi.fn()} />)
    const toggle = screen.getByRole('button', { name: 'メニュー' })

    fireEvent.click(toggle)
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')

    fireEvent.click(toggle)
    fireEvent.pointerDown(document.body)
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
  })
})
