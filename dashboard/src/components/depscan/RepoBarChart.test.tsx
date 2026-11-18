import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { RepoBarChart } from './RepoBarChart'
import type { DepscanStatsResponse } from '../../api/client'

const STATS: DepscanStatsResponse = {
  total: 3,
  repos: [
    { repo_full_name: 'baby-feelings/baby_grow', count: 2 },
    { repo_full_name: 'baby-feelings/baby_immunity', count: 1 },
  ],
  severities: [],
}

describe('RepoBarChart', () => {
  it('shows the loading state', () => {
    render(<RepoBarChart stats={null} loading />)
    expect(screen.getByText('読み込み中...')).toBeInTheDocument()
  })

  it('shows the empty state when there are no repo stats', () => {
    render(<RepoBarChart stats={{ total: 0, repos: [], severities: [] }} loading={false} />)
    expect(screen.getByText('データなし')).toBeInTheDocument()
  })

  it('renders the chart title once data is available', () => {
    render(<RepoBarChart stats={STATS} loading={false} />)
    expect(screen.getByText('リポジトリ別件数（未解決）')).toBeInTheDocument()
    expect(screen.queryByText('データなし')).not.toBeInTheDocument()
  })
})
