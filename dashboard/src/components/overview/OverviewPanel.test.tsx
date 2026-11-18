import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { OverviewPanel } from './OverviewPanel'
import { OverviewMetric } from './OverviewMetric'
import { OVERVIEW_METRICS } from './overviewConfig'
import * as data from './useOverviewData'

vi.mock('./useOverviewData')

function setMetrics(values: Record<string, number | null>, loading = false) {
  vi.mocked(data.useOverviewData).mockReturnValue({
    loading,
    metrics: OVERVIEW_METRICS.map((d) => new OverviewMetric({ ...d, value: d.id in values ? values[d.id] : 0 })),
  })
}

describe('OverviewPanel', () => {
  it('shows counts and 不明 for a metric that could not be fetched', () => {
    setMetrics({ 'dep-open': 3, 'dep-overdue': null, 'code-audit': 81 })
    render(<OverviewPanel authToken="t" onNavigate={vi.fn()} />)
    expect(screen.getByRole('button', { name: /未解決の脆弱性/ })).toHaveTextContent('3 件')
    expect(screen.getByRole('button', { name: /対応期限を超過/ })).toHaveTextContent('不明')
    expect(screen.getByRole('button', { name: /リポジトリ設定の達成率/ })).toHaveTextContent('81%')
  })

  it('navigates to the tab and sub-tab of the pressed card', () => {
    setMetrics({})
    const onNavigate = vi.fn()
    render(<OverviewPanel authToken="t" onNavigate={onNavigate} />)
    fireEvent.click(screen.getByRole('button', { name: /対応期限を超過/ }))
    expect(onNavigate).toHaveBeenCalledWith({ tab: 'dependencies', subTab: 'sla' })
  })

  it('shows a loading state', () => {
    setMetrics({}, true)
    render(<OverviewPanel authToken="t" onNavigate={vi.fn()} />)
    expect(screen.getByRole('status', { name: '集計中' })).toBeInTheDocument()
  })
})
