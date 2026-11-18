import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { RepoBarChart, formatRepoTooltipValue } from './RepoBarChart'

const DATA = [
  { repo_full_name: 'baby-feelings/a', count: 3, excepted_count: 1 },
  { repo_full_name: 'baby-feelings/b', count: 1 },
]

describe('shared RepoBarChart', () => {
  it('shows the title and optional description', () => {
    render(<RepoBarChart data={DATA} loading={false} title="題名" description="補足" />)
    expect(screen.getByText('題名')).toBeInTheDocument()
    expect(screen.getByText('補足')).toBeInTheDocument()
  })

  it('shows the empty state when there is no data', () => {
    render(<RepoBarChart data={[]} loading={false} title="題名" />)
    expect(screen.queryByRole('img')).not.toBeInTheDocument()
  })

  it('formats the tooltip with the unit and series name', () => {
    expect(formatRepoTooltipValue(4, '対応が必要')).toEqual(['4 件', '対応が必要'])
  })
})
