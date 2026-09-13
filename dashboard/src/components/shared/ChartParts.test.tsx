import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import {
  ChartCard, SeverityPieChart, MonthlyBarChart,
  formatSeverityPieTooltipValue, formatMonthlyBarTooltipValue,
} from './ChartParts'

describe('tooltip formatters', () => {
  it('formatSeverityPieTooltipValue appends the unit and stringifies the name', () => {
    expect(formatSeverityPieTooltipValue(3, 'CRITICAL')).toEqual(['3 件', 'CRITICAL'])
  })

  it('formatMonthlyBarTooltipValue appends the unit and a fixed label', () => {
    expect(formatMonthlyBarTooltipValue(12)).toEqual(['12 件', '件数'])
  })
})

describe('ChartCard', () => {
  it('shows the loading label while loading', () => {
    render(
      <ChartCard icon={<span />} title="Test Chart" loading isEmpty={false} height={100}>
        <div>content</div>
      </ChartCard>,
    )
    expect(screen.getByText('読み込み中...')).toBeInTheDocument()
    expect(screen.queryByText('content')).not.toBeInTheDocument()
  })

  it('shows the empty label when not loading and empty', () => {
    render(
      <ChartCard icon={<span />} title="Test Chart" loading={false} isEmpty height={100}>
        <div>content</div>
      </ChartCard>,
    )
    expect(screen.getByText('データなし')).toBeInTheDocument()
  })

  it('renders a description when provided', () => {
    render(
      <ChartCard icon={<span />} title="Test Chart" description="補足説明" loading={false} isEmpty height={100}>
        <div>content</div>
      </ChartCard>,
    )
    expect(screen.getByText('補足説明')).toBeInTheDocument()
  })

  it('renders children and footer once loaded with data', () => {
    render(
      <ChartCard
        icon={<span />}
        title="Test Chart"
        loading={false}
        isEmpty={false}
        height={100}
        footer={<span>legend</span>}
      >
        <div>content</div>
      </ChartCard>,
    )
    expect(screen.getByText('content')).toBeInTheDocument()
    expect(screen.getByText('legend')).toBeInTheDocument()
  })

  it('hides the footer while loading', () => {
    render(
      <ChartCard icon={<span />} title="Test Chart" loading isEmpty={false} height={100} footer={<span>legend</span>}>
        <div>content</div>
      </ChartCard>,
    )
    expect(screen.queryByText('legend')).not.toBeInTheDocument()
  })
})

describe('SeverityPieChart', () => {
  it('reports empty when all counts are zero or N/A', () => {
    render(
      <SeverityPieChart
        icon={<span />}
        data={[{ severity: 'N/A', count: 5 }, { severity: 'LOW', count: 0 }]}
        colorMap={{}}
        loading={false}
      />,
    )
    expect(screen.getByText('データなし')).toBeInTheDocument()
  })

  it('renders a legend entry per non-zero severity', () => {
    render(
      <SeverityPieChart
        icon={<span />}
        data={[{ severity: 'CRITICAL', count: 3 }, { severity: 'HIGH', count: 2 }]}
        colorMap={{ CRITICAL: '#ef4444', HIGH: '#f97316' }}
        loading={false}
      />,
    )
    expect(screen.getByText('CRITICAL')).toBeInTheDocument()
    expect(screen.getByText('3')).toBeInTheDocument()
    expect(screen.getByText('HIGH')).toBeInTheDocument()
  })

  it('shows the loading state', () => {
    render(
      <SeverityPieChart icon={<span />} data={[]} colorMap={{}} loading />,
    )
    expect(screen.getByText('読み込み中...')).toBeInTheDocument()
  })

  it('falls back to a default color for a severity missing from colorMap', () => {
    render(
      <SeverityPieChart
        icon={<span />}
        data={[{ severity: 'UNKNOWN', count: 1 }]}
        colorMap={{}}
        loading={false}
      />,
    )
    expect(screen.getByText('UNKNOWN')).toBeInTheDocument()
  })
})

describe('MonthlyBarChart', () => {
  it('shows empty state for an empty dataset', () => {
    render(
      <MonthlyBarChart icon={<span />} title="Monthly" data={[]} barColor="#7c3aed" loading={false} />,
    )
    expect(screen.getByText('データなし')).toBeInTheDocument()
  })

  it('renders the given title', () => {
    render(
      <MonthlyBarChart
        icon={<span />}
        title="月別トレンド"
        data={[{ year_month: '2026-06', count: 5 }]}
        barColor="#7c3aed"
        loading={false}
      />,
    )
    expect(screen.getByText('月別トレンド')).toBeInTheDocument()
  })

  it('accepts a custom height', () => {
    render(
      <MonthlyBarChart
        icon={<span />}
        title="月別トレンド"
        data={[{ year_month: '2026-06', count: 5 }]}
        barColor="#7c3aed"
        height={220}
        loading={false}
      />,
    )
    expect(screen.getByText('月別トレンド')).toBeInTheDocument()
  })
})
