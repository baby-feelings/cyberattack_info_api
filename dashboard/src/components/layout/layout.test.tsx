import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { HeaderMenu } from './HeaderMenu'
import { TabBar } from './TabBar'
import { TabPanel } from './TabPanel'
import { TAB_DEFINITIONS } from './tabs'

// 重いパネル本体は軽量なダミーへ差し替える（レイアウトだけを検証する）
vi.mock('../KevPanel', () => ({ KevPanel: () => <div>kev-panel</div> }))
vi.mock('../OsvPanel', () => ({ OsvPanel: () => <div>osv-panel</div> }))
vi.mock('../JvnPanel', () => ({ JvnPanel: () => <div>jvn-panel</div> }))
vi.mock('../DepscanAuthGate', () => ({ DepscanAuthGate: () => <div>depscan-gate</div> }))
vi.mock('../CodescanAuthGate', () => ({ CodescanAuthGate: () => <div>codescan-gate</div> }))

describe('TAB_DEFINITIONS', () => {
  it('defines the five tabs in display order with unique keys', () => {
    expect(TAB_DEFINITIONS.map((t) => t.key)).toEqual(['kev', 'osv', 'jvn', 'depscan', 'codescan'])
    expect(new Set(TAB_DEFINITIONS.map((t) => t.key)).size).toBe(5)
  })
})

describe('TabBar', () => {
  it('renders one tab per definition and marks only the active one as selected', () => {
    render(<TabBar activeTab="osv" onSelect={vi.fn()} />)
    const tabs = screen.getAllByRole('tab')
    expect(tabs).toHaveLength(5)
    expect(screen.getByRole('tab', { name: /OSV/ })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('tab', { name: /KEV/ })).toHaveAttribute('aria-selected', 'false')
  })

  it('links each tab to its panel via aria-controls and calls onSelect with the key', () => {
    const onSelect = vi.fn()
    render(<TabBar activeTab="kev" onSelect={onSelect} />)
    const jvn = screen.getByRole('tab', { name: /JVN/ })
    expect(jvn).toHaveAttribute('id', 'tab-jvn')
    expect(jvn).toHaveAttribute('aria-controls', 'tabpanel-jvn')
    fireEvent.click(jvn)
    expect(onSelect).toHaveBeenCalledWith('jvn')
  })
})

describe('TabPanel', () => {
  it('renders heading, subtitle and body with aria wiring back to the tab', () => {
    const tab = TAB_DEFINITIONS.find((t) => t.key === 'depscan')!
    render(<TabPanel tab={tab} />)
    const panel = screen.getByRole('tabpanel')
    expect(panel).toHaveAttribute('id', 'tabpanel-depscan')
    expect(panel).toHaveAttribute('aria-labelledby', 'tab-depscan')
    expect(screen.getByRole('heading', { name: /DEPSCAN/ })).toBeInTheDocument()
    expect(screen.getByText(/OSV API とリアルタイム照合/)).toBeInTheDocument()
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
