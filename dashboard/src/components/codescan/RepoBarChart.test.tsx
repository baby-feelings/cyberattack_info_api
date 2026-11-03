import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { RepoBarChart, formatRepoTooltipValue } from './RepoBarChart'
import type { CodescanStatsResponse } from '../../api/codescan'

const STATS: CodescanStatsResponse = {
  total: 3,
  excepted_total: 0,
  repos: [
    { repo_full_name: 'baby-feelings/baby_grow', count: 2, excepted_count: 0 },
    { repo_full_name: 'baby-feelings/cyberattack_info_api', count: 1, excepted_count: 0 },
  ],
  severities: [],
}

describe('RepoBarChart', () => {
  it('shows the loading state', () => {
    render(<RepoBarChart stats={null} loading />)
    expect(screen.getByText('読み込み中...')).toBeInTheDocument()
  })

  it('shows the empty state when there are no repo stats', () => {
    render(<RepoBarChart stats={{ total: 0, excepted_total: 0, repos: [], severities: [] }} loading={false} />)
    expect(screen.getByText('データなし')).toBeInTheDocument()
  })

  it('keeps repos that only have excepted findings in the chart', () => {
    // 例外だけのリポジトリ（対応が必要は0件）も、グラフのデータに含める（下の一覧と食い違わないため）
    const stats: CodescanStatsResponse = {
      total: 0,
      excepted_total: 2,
      repos: [{ repo_full_name: 'baby-feelings/other', count: 0, excepted_count: 2 }],
      severities: [],
    }
    render(<RepoBarChart stats={stats} loading={false} />)
    expect(screen.queryByText('データなし')).not.toBeInTheDocument()
  })

  it('renders the chart title once data is available', () => {
    render(<RepoBarChart stats={STATS} loading={false} />)
    expect(screen.getByText('リポジトリ別件数（未解決）')).toBeInTheDocument()
    expect(screen.queryByText('データなし')).not.toBeInTheDocument()
  })
})

describe('formatRepoTooltipValue', () => {
  it('appends the unit and the series name to the raw count', () => {
    expect(formatRepoTooltipValue(4, '対応が必要')).toEqual(['4 件', '対応が必要'])
  })
})
