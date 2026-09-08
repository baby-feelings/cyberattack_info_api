import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { DepsOpsRepoBarChart, formatDepsOpsRepoTooltipValue } from './DepsOpsRepoBarChart'
import type { RepoOpsStat } from './depsopsGrouping'

const STATS: RepoOpsStat[] = [
  { repo_full_name: 'baby-feelings/baby_grow', count: 2 },
  { repo_full_name: 'baby-feelings/baby_immunity', count: 1 },
]

describe('DepsOpsRepoBarChart', () => {
  it('shows the loading state', () => {
    render(<DepsOpsRepoBarChart stats={[]} loading />)
    expect(screen.getByText('読み込み中...')).toBeInTheDocument()
  })

  it('shows the empty state when there are no repo stats', () => {
    render(<DepsOpsRepoBarChart stats={[]} loading={false} />)
    expect(screen.getByText('データなし')).toBeInTheDocument()
  })

  it('renders the chart title once data is available', () => {
    render(<DepsOpsRepoBarChart stats={STATS} loading={false} />)
    expect(screen.getByText('リポジトリ別件数（未解決）')).toBeInTheDocument()
    expect(screen.queryByText('データなし')).not.toBeInTheDocument()
  })
})

describe('formatDepsOpsRepoTooltipValue', () => {
  it('appends the unit and label to the raw count', () => {
    expect(formatDepsOpsRepoTooltipValue(3)).toEqual(['3 件', '件数'])
  })
})
