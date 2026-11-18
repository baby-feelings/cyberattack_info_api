import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { HeaderMenu } from './HeaderMenu'
import { TabBar } from './TabBar'
import { TabPanel } from './TabPanel'
import { TAB_DEFINITIONS } from './tabs'
import { POSTURE_TAB } from '../posture/postureConfig'
import { fetchCrawlerLogs } from '../../api/crawlerLogs'

// 「最終取得」の実行履歴の取得は、ダミーへ差し替える
vi.mock('../../api/crawlerLogs', () => ({ fetchCrawlerLogs: vi.fn().mockResolvedValue([]) }))
// 重いパネル本体は軽量なダミーへ差し替える（レイアウトだけを検証する）
vi.mock('../KevPanel', () => ({ KevPanel: () => <div>kev-panel</div> }))
vi.mock('../OsvPanel', () => ({ OsvPanel: () => <div>osv-panel</div> }))
vi.mock('../DepscanAuthGate', () => ({ DepscanAuthGate: () => <div>depscan-gate</div> }))
vi.mock('../CodescanAuthGate', () => ({ CodescanAuthGate: () => <div>codescan-gate</div> }))
vi.mock('../posture/PostureAuthGate', () => ({ PostureAuthGate: () => <div>posture-gate</div> }))

describe('TAB_DEFINITIONS', () => {
  it('defines the four tabs in display order with unique keys', () => {
    expect(TAB_DEFINITIONS.map((t) => t.key)).toEqual(['public', 'depscan', 'codescan', 'posture'])
    expect(new Set(TAB_DEFINITIONS.map((t) => t.key)).size).toBe(4)
  })

  it('declares the crawler whose last fetch each tab shows', () => {
    expect(TAB_DEFINITIONS.map((t) => t.crawlerType)).toEqual(['KEV', 'DEPSCAN', 'CODESCAN', 'GHALERT'])
  })

  it('takes the label, title and subtitle of the posture tab from the posture config', () => {
    const tab = TAB_DEFINITIONS.find((t) => t.key === 'posture')!
    expect(tab.label).toBe(POSTURE_TAB.label)
    expect(tab.title).toBe(POSTURE_TAB.title)
    expect(tab.subtitle).toBe(POSTURE_TAB.subtitle)
  })
})

describe('TabBar', () => {
  it('renders one tab per definition and marks only the active one as selected', () => {
    render(<TabBar activeTab="depscan" onSelect={vi.fn()} />)
    const tabs = screen.getAllByRole('tab')
    expect(tabs).toHaveLength(4)
    expect(screen.getByRole('tab', { name: /DEPSCAN/ })).toHaveAttribute('aria-selected', 'true')
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
    const depscan = screen.getByRole('tab', { name: /DEPSCAN/ })
    expect(depscan).toHaveAttribute('id', 'tab-depscan')
    expect(depscan).toHaveAttribute('aria-controls', 'tabpanel-depscan')
    fireEvent.click(depscan)
    expect(onSelect).toHaveBeenCalledWith('depscan')
  })
})

describe('TabPanel', () => {
  it('shows the last fetch of the crawler the tab declares, next to the heading', async () => {
    const tab = TAB_DEFINITIONS.find((t) => t.key === 'depscan')!
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
    const tab = TAB_DEFINITIONS.find((t) => t.key === 'depscan')!
    render(<TabPanel tab={tab} />)
    const panel = screen.getByRole('tabpanel')
    expect(panel).toHaveAttribute('id', 'tabpanel-depscan')
    expect(panel).toHaveAttribute('aria-labelledby', 'tab-depscan')
    expect(screen.getByRole('heading', { name: /DEPSCAN/ })).toBeInTheDocument()
    expect(screen.getByText(/OSV と照合し、悪意あるパッケージ/)).toBeInTheDocument()
    expect(screen.getByText('depscan-gate')).toBeInTheDocument()
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
