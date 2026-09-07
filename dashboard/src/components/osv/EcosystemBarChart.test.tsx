import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { EcosystemBarChart, formatEcosystemTooltipValue } from './EcosystemBarChart'
import type { OsvStatsResponse } from '../../api/client'

const STATS: OsvStatsResponse = {
  total: 3,
  ecosystems: [
    { ecosystem: 'PyPI', count: 2 },
    { ecosystem: 'npm', count: 1 },
  ],
  severities: [],
  monthly_trend: [],
}

describe('EcosystemBarChart', () => {
  it('shows the loading state', () => {
    render(<EcosystemBarChart stats={null} loading />)
    expect(screen.getByText('読み込み中...')).toBeInTheDocument()
  })

  it('shows the empty state when there are no ecosystem stats', () => {
    render(
      <EcosystemBarChart
        stats={{ total: 0, ecosystems: [], severities: [], monthly_trend: [] }}
        loading={false}
      />,
    )
    expect(screen.getByText('データなし')).toBeInTheDocument()
  })

  it('renders the chart title once data is available', () => {
    render(<EcosystemBarChart stats={STATS} loading={false} />)
    expect(screen.getByText('エコシステム別件数')).toBeInTheDocument()
    expect(screen.queryByText('データなし')).not.toBeInTheDocument()
  })
})

describe('formatEcosystemTooltipValue', () => {
  it('appends the unit and label to the raw count', () => {
    expect(formatEcosystemTooltipValue(7)).toEqual(['7 件', '件数'])
  })
})
