import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { VendorBarChart, formatVendorTooltipValue } from './VendorBarChart'
import type { StatsResponse } from '../../api/client'

const STATS: StatsResponse = {
  total_vulnerabilities: 3,
  top_vendors: [
    { vendor_project: 'Microsoft', count: 2 },
    { vendor_project: 'Apple', count: 1 },
  ],
  monthly_trend: [],
}

describe('VendorBarChart', () => {
  it('shows the loading state', () => {
    render(<VendorBarChart stats={null} loading />)
    expect(screen.getByText('読み込み中...')).toBeInTheDocument()
  })

  it('shows the empty state when there are no vendor stats', () => {
    render(<VendorBarChart stats={{ total_vulnerabilities: 0, top_vendors: [], monthly_trend: [] }} loading={false} />)
    expect(screen.getByText('データなし')).toBeInTheDocument()
  })

  it('renders the chart title once data is available', () => {
    render(<VendorBarChart stats={STATS} loading={false} />)
    expect(screen.getByText('ベンダー別件数 TOP8')).toBeInTheDocument()
    expect(screen.queryByText('データなし')).not.toBeInTheDocument()
  })
})

describe('formatVendorTooltipValue', () => {
  it('appends the unit and label to the raw count', () => {
    expect(formatVendorTooltipValue(5)).toEqual(['5 件', '件数'])
  })
})
